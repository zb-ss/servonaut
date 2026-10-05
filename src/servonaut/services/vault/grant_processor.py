"""Batch native-vault grants for eligible Team Vault roster members."""
from __future__ import annotations

import base64
import inspect
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from . import crypto
from .roster_pins import IdentityPinChangedError
from .team_vault_client import (
    TeamVaultClient,
    current_identity,
    identity_encryption_public,
    identity_signing_seed,
)


Approval = Callable[[Mapping[str, Any], str, bool], bool | Awaitable[bool]]


class GrantProcessor:
    """Prepare grants without prompting or hiding any recipient decision.

    The optional ``approval`` callback is supplied by a CLI/TUI caller.  The
    service reports when it needs consent and never treats a web approval as a
    local safety-number check while strict verification is enabled.
    """

    def __init__(self, vaults: TeamVaultClient, *, strict_verification: bool = False) -> None:
        self._vaults = vaults
        self._strict = strict_verification

    async def process_auto_grants(
        self,
        vault: Mapping[str, Any],
        *,
        approval: Approval | None = None,
    ) -> dict[str, Any]:
        self._vaults.verify_vault(vault)
        vault_key = self._vaults.open_my_grant(vault)
        identity = current_identity(self._vaults._identity_store)
        version = int(vault["current_version"])
        version_record = next(item for item in vault["versions"] if int(item["version"]) == version)
        version_key = base64.b64decode(version_record["public_key"], validate=True)
        grants: list[dict[str, Any]] = []
        pending: list[dict[str, Any]] = []
        for entry in vault.get("roster", []):
            if not isinstance(entry, Mapping):
                continue
            status = str(entry.get("status", ""))
            if status in {"granted", "awaiting_identity", "not_eligible", "awaiting_confirmation", "identity_compromised"}:
                continue
            recipient = entry.get("identity")
            if not isinstance(recipient, Mapping) or recipient.get("grantable") is not True:
                continue
            is_changed = status == "identity_changed"
            needs_approval = status in {"awaiting_approval", "identity_changed"}
            web_approval = isinstance(entry.get("approval"), Mapping) and entry["approval"].get("via") == "web"
            try:
                fingerprint = self._vaults._pins.observe(recipient, confirm_changed=False)
            except IdentityPinChangedError:
                is_changed = True
                needs_approval = True
                fingerprint = self._vaults._pins.verify_identity(recipient)
            needs_local_check = is_changed or (needs_approval and (self._strict or not web_approval))
            if needs_local_check:
                if approval is None:
                    pending.append(self._pending(entry, fingerprint, is_changed))
                    continue
                accepted = approval(entry, crypto.safety_number(fingerprint), is_changed)
                if inspect.isawaitable(accepted):
                    accepted = await accepted
                if not accepted:
                    pending.append(self._pending(entry, fingerprint, is_changed))
                    continue
                self._vaults._pins.observe(recipient, confirm_changed=is_changed)
                if needs_approval:
                    await self._approve(vault, entry, fingerprint, identity)
            grants.append(
                self._grant(vault, version, version_key, vault_key, recipient, fingerprint, identity)
            )
        if not grants:
            return {"accepted": [], "skipped": [], "pending_confirmation": pending}
        result = await self._vaults._signed(
            "POST", f"/api/v1/vaults/{vault['vault_id']}/grants", {"version": version, "grants": grants}
        )
        result["pending_confirmation"] = pending
        return result

    async def _approve(
        self, vault: Mapping[str, Any], entry: Mapping[str, Any], fingerprint: bytes, identity: Any
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

    @staticmethod
    def _pending(entry: Mapping[str, Any], fingerprint: bytes, changed: bool) -> dict[str, Any]:
        return {
            "user_id": int(entry["user_id"]),
            "identity_id": entry["identity"]["identity_id"],
            "safety_number": crypto.safety_number(fingerprint),
            "identity_changed": changed,
        }

    @staticmethod
    def _grant(
        vault: Mapping[str, Any], version: int, version_key: bytes, vault_key: bytes,
        recipient: Mapping[str, Any], fingerprint: bytes, identity: Any,
    ) -> dict[str, Any]:
        recipient_key = base64.b64decode(recipient["enc_public_key"], validate=True)
        sealed = crypto.seal(vault_key, recipient_key)
        recipient_id = str(recipient["identity_id"])
        message = crypto.grant_message(
            str(vault["vault_id"]), str(vault["scope"]), version, version_key,
            int(recipient["user_id"]), recipient_id, fingerprint, sealed, str(identity.identity_id),
        )
        return {
            "recipient_user_id": int(recipient["user_id"]),
            "recipient_identity_id": recipient_id,
            "sealed_private_key": base64.b64encode(sealed).decode(),
            "signature": base64.b64encode(crypto.sign(identity_signing_seed(identity), message)).decode(),
        }
