"""Verified Team Vault key rotation and exposure resolution."""
from __future__ import annotations

import base64
import inspect
import secrets
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlencode

from . import crypto
from .grant_processor import Approval
from .roster_pins import decode_b64
from .team_vault_client import (
    TeamVaultClient,
    VaultStateError,
    current_identity,
    identity_encryption_public,
    identity_signing_seed,
)


class RotationService:
    """Rotate a vault once, preserving ciphertext and rewrapping only item keys."""

    def __init__(self, vaults: TeamVaultClient, items: Any, *, strict_verification: bool = False) -> None:
        self._vaults = vaults
        self._items = items
        self._strict = strict_verification

    async def rotate(
        self, vault_id: str, *, approval: Approval | None = None, retry_once: bool = True
    ) -> dict[str, Any]:
        try:
            return await self._rotate_once(vault_id, approval=approval)
        except Exception as exc:
            if not retry_once or getattr(exc, "code", None) not in {"item_set_changed", "version_conflict"}:
                raise
        return await self._rotate_once(vault_id, approval=approval)

    async def _rotate_once(self, vault_id: str, *, approval: Approval | None) -> dict[str, Any]:
        vault = await self._vaults.get_vault(vault_id)
        old_key = self._vaults.open_my_grant(vault)
        identity = current_identity(self._vaults._identity_store)
        old_version = int(vault["current_version"])
        old_record = self._version(vault, old_version)
        new_key = secrets.token_bytes(32)
        new_public = crypto.x25519_public(new_key)
        new_version = old_version + 1
        previous_hash = decode_b64(old_record["record_hash"], "version.record_hash")
        version_signature = crypto.sign(
            identity_signing_seed(identity),
            crypto.version_message(vault_id, str(vault["scope"]), new_version, new_public, previous_hash, str(identity.identity_id)),
        )
        grants = await self._recipient_grants(vault, new_version, new_public, new_key, identity, approval)
        escrow_grants = self._escrow_grants(vault, new_version, new_public, new_key, identity)
        metadata = await self._all_item_metadata(vault_id)
        item_rewraps = [
            self._rewrap_item(vault, item, old_key, new_key, new_public, identity)
            for item in metadata
            if not item.get("deleted", False)
        ]
        return await self._vaults._signed(
            "POST", f"/api/v1/vaults/{vault_id}/rotate",
            {
                "expected_version": old_version,
                "version": {
                    "version": new_version,
                    "public_key": base64.b64encode(new_public).decode(),
                    "prev_hash": base64.b64encode(previous_hash).decode(),
                    "signature": base64.b64encode(version_signature).decode(),
                },
                "grants": grants,
                "escrow_grants": escrow_grants,
                "item_rewraps": item_rewraps,
            },
        )

    async def list_exposures(
        self, vault_id: str, *, status: str = "open", cursor: str | None = None, limit: int = 50
    ) -> dict[str, Any]:
        if status not in {"open", "resolved", "all"} or not 1 <= limit <= 200:
            raise ValueError("invalid exposure list options")
        query = urlencode({"status": status, "limit": limit, **({"cursor": cursor} if cursor else {})})
        return await self._vaults._signed("GET", f"/api/v1/vaults/{vault_id}/exposures?{query}")

    async def resolve_exposure(
        self, vault_id: str, exposure_id: str, *, resolution: str, note: str = ""
    ) -> dict[str, Any]:
        if resolution not in {"rotated", "accepted_risk", "not_deployed"} or len(note) > 500:
            raise ValueError("invalid exposure resolution")
        return await self._vaults._signed(
            "POST", f"/api/v1/vaults/{vault_id}/exposures/{exposure_id}/resolve",
            {"resolution": resolution, "note": note},
        )

    async def _all_item_metadata(self, vault_id: str) -> list[dict[str, Any]]:
        cursor: str | None = None
        seen: set[str] = set()
        result: list[dict[str, Any]] = []
        while True:
            response = await self._items.list_items(vault_id, cursor=cursor, limit=500)
            data = response.get("data", [])
            if not isinstance(data, list):
                raise VaultStateError("rotation item list has an invalid shape")
            result.extend(dict(item) for item in data if isinstance(item, Mapping))
            meta = response.get("meta", {})
            next_cursor = meta.get("next_cursor") if isinstance(meta, Mapping) else None
            if next_cursor is None:
                return result
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen:
                raise VaultStateError("rotation item list cursor is invalid")
            seen.add(next_cursor)
            cursor = next_cursor

    async def _recipient_grants(
        self, vault: Mapping[str, Any], version: int, public_key: bytes, vault_key: bytes,
        identity: Any, approval: Approval | None,
    ) -> list[dict[str, Any]]:
        grants: list[dict[str, Any]] = []
        own_id = str(identity.identity_id)
        own = {"identity_id": own_id, "user_id": identity.user_id, "enc_public_key": base64.b64encode(identity_encryption_public(identity)).decode(), "fingerprint": identity.fingerprint, "grantable": True}
        recipients: list[Mapping[str, Any]] = [own]
        for entry in vault.get("roster", []):
            if not isinstance(entry, Mapping) or str(entry.get("role")) not in {"member", "admin", "owner"}:
                continue
            recipient = entry.get("identity")
            if not isinstance(recipient, Mapping) or recipient.get("grantable") is not True:
                continue
            if str(recipient.get("identity_id")) == own_id:
                continue
            status = str(entry.get("status", ""))
            changed = status == "identity_changed"
            # A roster recipient awaiting approval is never grantable merely
            # because local strict verification is disabled.  A caller may
            # compare the safety number and create the signed server approval
            # below; until then it is excluded from the rotation entirely.
            needs_check = changed or status == "awaiting_approval"
            if needs_check:
                fingerprint = self._vaults._pins.verify_identity(recipient)
                if approval is None:
                    continue
                accepted = approval(entry, crypto.safety_number(fingerprint), changed)
                if inspect.isawaitable(accepted):
                    accepted = await accepted
                if accepted is not True:
                    continue
                self._vaults._pins.observe(recipient, confirm_changed=changed)
                await self._approve_recipient(vault, entry, fingerprint, identity)
            else:
                self._vaults._pins.observe(recipient)
            recipients.append(recipient)
        for recipient in recipients:
            fingerprint_value = recipient["fingerprint"]
            fingerprint = bytes.fromhex(fingerprint_value) if isinstance(fingerprint_value, str) else bytes(fingerprint_value)
            sealed = crypto.seal(vault_key, decode_b64(recipient["enc_public_key"], "recipient.enc_public_key"))
            message = crypto.grant_message(
                str(vault["vault_id"]), str(vault["scope"]), version, public_key, int(recipient["user_id"]),
                str(recipient["identity_id"]), fingerprint, sealed, str(identity.identity_id),
            )
            grants.append({"recipient_user_id": int(recipient["user_id"]), "recipient_identity_id": str(recipient["identity_id"]), "sealed_private_key": base64.b64encode(sealed).decode(), "signature": base64.b64encode(crypto.sign(identity_signing_seed(identity), message)).decode()})
        return grants

    async def _approve_recipient(
        self, vault: Mapping[str, Any], entry: Mapping[str, Any], fingerprint: bytes, identity: Any,
    ) -> None:
        recipient = entry["identity"]
        signature = crypto.sign(
            identity_signing_seed(identity),
            crypto.recipient_approval_message(
                str(vault["vault_id"]), int(entry["user_id"]), str(recipient["identity_id"]),
                fingerprint, str(identity.identity_id),
            ),
        )
        await self._vaults._signed(
            "POST", f"/api/v1/vaults/{vault['vault_id']}/recipients/{entry['user_id']}/approve",
            {
                "identity_id": recipient["identity_id"],
                "fingerprint": fingerprint.hex(),
                "approval_signature": base64.b64encode(signature).decode(),
            },
        )

    def _escrow_grants(self, vault: Mapping[str, Any], version: int, public_key: bytes, vault_key: bytes, identity: Any) -> list[dict[str, Any]]:
        grants: list[dict[str, Any]] = []
        identities = vault.get("identities", {})
        owner_ids = {str(entry.get("identity", {}).get("identity_id")) for entry in vault.get("roster", []) if isinstance(entry, Mapping) and entry.get("role") == "owner"}
        if vault.get("kind") == "personal":
            owner_ids.add(str(identity.identity_id))
        for escrow in vault.get("escrow", []):
            if not isinstance(escrow, Mapping) or str(escrow.get("owner_identity_id")) not in owner_ids:
                continue
            owner = identities.get(str(escrow["owner_identity_id"])) if isinstance(identities, Mapping) else None
            if not isinstance(owner, Mapping):
                raise VaultStateError("trusted escrow owner identity is missing")
            enc_key = decode_b64(escrow["enc_public_key"], "escrow.enc_public_key")
            if not crypto.verify(decode_b64(owner["sig_public_key"], "owner.sig_public_key"), crypto.escrow_message(str(vault["vault_id"]), str(escrow["escrow_id"]), enc_key, str(escrow["label"]), str(escrow["owner_identity_id"])), decode_b64(escrow["signature"], "escrow.signature")):
                raise VaultStateError("escrow signature is invalid")
            sealed = crypto.seal(vault_key, enc_key)
            message = crypto.grant_message(str(vault["vault_id"]), str(vault["scope"]), version, public_key, 0, str(escrow["escrow_id"]), crypto.sha256(enc_key), sealed, str(identity.identity_id))
            grants.append({"escrow_id": str(escrow["escrow_id"]), "sealed_private_key": base64.b64encode(sealed).decode(), "signature": base64.b64encode(crypto.sign(identity_signing_seed(identity), message)).decode()})
        return grants

    def _rewrap_item(self, vault: Mapping[str, Any], item: Mapping[str, Any], old_key: bytes, new_key: bytes, new_public: bytes, identity: Any) -> dict[str, Any]:
        old_record = self._version(vault, int(item["key_version"]))
        wrapped = decode_b64(item["wrapped_item_key"], "item.wrapped_item_key")
        item_key = crypto.open_sealed(wrapped, decode_b64(old_record["public_key"], "version.public_key"), old_key)
        new_wrapped = crypto.seal(item_key, new_public)
        ciphertext_hash = decode_b64(item["ciphertext_sha256"], "item.ciphertext_sha256")
        message = crypto.item_wrap_message_from_hash(str(vault["vault_id"]), str(item["item_id"]), int(item["revision"]), int(vault["current_version"]) + 1, new_wrapped, ciphertext_hash, str(identity.identity_id))
        return {"item_id": str(item["item_id"]), "revision": int(item["revision"]), "wrapped_item_key": base64.b64encode(new_wrapped).decode(), "wrap_signature": base64.b64encode(crypto.sign(identity_signing_seed(identity), message)).decode()}

    @staticmethod
    def _version(vault: Mapping[str, Any], number: int) -> Mapping[str, Any]:
        for record in vault.get("versions", []):
            if int(record.get("version", 0)) == number:
                return record
        raise VaultStateError("vault version is missing")
