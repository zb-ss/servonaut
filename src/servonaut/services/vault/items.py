"""Encrypted Team Vault item reads and writes."""
from __future__ import annotations

import base64
import inspect
import json
import secrets
from urllib.parse import urlencode
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from . import crypto
from .roster_pins import decode_b64
from .team_vault_client import (
    TeamVaultClient,
    VaultStateError,
    _uuid,
    _positive_int,
    current_identity,
    identity_signing_seed,
)


_ITEM_TYPES = {"ssh_key", "secret", "connection_extra", "break_glass", "host_pins"}
_SSH_TYPES = {"ssh_key", "break_glass"}


class VaultItemService:
    """Use verified vault state to read and mutate encrypted item records."""

    def __init__(self, api: Any, vaults: TeamVaultClient) -> None:
        self._api = api
        self._vaults = vaults

    async def _signed(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return await self._api.request_signed(
            method, path, json=dict(payload or {}), device=self._vaults._signer()
        )

    async def list_items(
        self,
        vault_id: str,
        *,
        cursor: str | None = None,
        limit: int = 200,
        include_deleted: bool = False,
        updated_since: str | None = None,
    ) -> dict[str, Any]:
        _uuid(vault_id, "vault_id")
        if not 1 <= limit <= 500:
            raise ValueError("item list limit must be between 1 and 500")
        query: dict[str, str | int] = {"limit": limit, "include_deleted": int(include_deleted)}
        if cursor is not None:
            query["cursor"] = cursor
        if updated_since is not None:
            query["updated_since"] = updated_since
        return await self._signed("GET", f"/api/v1/vaults/{vault_id}/items?{urlencode(query)}")

    async def get_item(self, vault_id: str, item_id: str) -> dict[str, Any]:
        _uuid(vault_id, "vault_id")
        _uuid(item_id, "item_id")
        item = await self._signed("GET", f"/api/v1/vaults/{vault_id}/items/{item_id}")
        _positive_int(item.get("revision"), "item.revision")
        return item

    def read_item(self, vault: Mapping[str, Any], item: Mapping[str, Any]) -> dict[str, Any]:
        """Verify the current trust rule and decrypt a complete item response."""
        self._vaults.verify_vault(vault)
        vault_key = self._vaults.open_my_grant(vault)
        item_id = str(item["item_id"])
        revision = _positive_int(item.get("revision"), "item.revision")
        key_version = _positive_int(item.get("key_version"), "item.key_version")
        item_type = str(item["type"])
        if item_type not in _ITEM_TYPES:
            raise VaultStateError("unsupported vault item type")
        ciphertext = decode_b64(item["ciphertext"], "item.ciphertext")
        if crypto.sha256(ciphertext) != decode_b64(item["ciphertext_sha256"], "item.ciphertext_sha256"):
            raise VaultStateError("item ciphertext hash does not match")
        wrapped_key = decode_b64(item["wrapped_item_key"], "item.wrapped_item_key")
        version = self._version(vault, key_version)
        self._verify_item_trust(vault, item, ciphertext, wrapped_key, version)
        item_key = crypto.open_sealed(
            wrapped_key, decode_b64(version["public_key"], "version.public_key"), vault_key
        )
        plaintext = crypto.decrypt_item(
            item_key,
            decode_b64(item["nonce"], "item.nonce"),
            ciphertext,
            crypto.item_aad(str(vault["vault_id"]), item_id, item_type, revision),
        )
        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultStateError("item plaintext is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise VaultStateError("item plaintext must be an object")
        self._validate_payload(item_type, payload, item.get("public_fingerprint"))
        self._vaults._state.record_item_revision(item_id, revision)
        return payload

    async def write_item(
        self,
        vault_id: str,
        item_id: str,
        item_type: str,
        payload: Mapping[str, Any],
        *,
        expected_revision: int,
        retry_stale_once: bool = True,
        retry_confirmation: Callable[[], bool | Awaitable[bool]] | None = None,
    ) -> dict[str, Any]:
        """Encrypt a fresh item key on every write, retrying one stale conflict."""
        _uuid(vault_id, "vault_id")
        _uuid(item_id, "item_id")
        if isinstance(expected_revision, bool) or not isinstance(expected_revision, int) or expected_revision < 0:
            raise ValueError("expected_revision must not be negative")
        try:
            return await self._write_once(
                vault_id, item_id, item_type, payload, expected_revision=expected_revision
            )
        except Exception as exc:
            if not retry_stale_once or getattr(exc, "code", None) not in {"revision_conflict", "key_version_stale"}:
                raise
        if retry_confirmation is None:
            raise VaultStateError("item changed remotely; review it before retrying the write")
        confirmed = retry_confirmation()
        if inspect.isawaitable(confirmed):
            confirmed = await confirmed
        if confirmed is not True:
            raise VaultStateError("item write retry was not confirmed")
        vault = await self._vaults.get_vault(vault_id)
        latest = await self.get_item(vault_id, item_id) if expected_revision else {"revision": 0}
        return await self._write_once(
            vault_id,
            item_id,
            item_type,
            payload,
            expected_revision=_positive_int(latest.get("revision"), "item.revision"),
            vault=vault,
        )

    async def _write_once(
        self,
        vault_id: str,
        item_id: str,
        item_type: str,
        payload: Mapping[str, Any],
        *,
        expected_revision: int,
        vault: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if item_type not in _ITEM_TYPES:
            raise ValueError("unsupported vault item type")
        self._validate_payload(item_type, payload, payload.get("public_fingerprint"))
        vault = await self._vaults.get_vault(vault_id) if vault is None else vault
        vault_key = self._vaults.open_my_grant(vault)
        identity = current_identity(self._vaults._identity_store)
        revision = expected_revision + 1
        key_version = _positive_int(vault.get("current_version"), "vault.current_version")
        version = self._version(vault, key_version)
        plaintext = json.dumps(dict(payload), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        item_key = secrets.token_bytes(32)
        nonce, ciphertext = crypto.encrypt_item(
            item_key, plaintext, crypto.item_aad(vault_id, item_id, item_type, revision)
        )
        wrapped_key = crypto.seal(item_key, decode_b64(version["public_key"], "version.public_key"))
        fingerprint = payload.get("public_fingerprint")
        identity_id = str(identity.identity_id)
        content_signature = crypto.sign(
            identity_signing_seed(identity),
            crypto.item_content_message(vault_id, item_id, item_type, revision, nonce, ciphertext, fingerprint, identity_id),
        )
        wrap_signature = crypto.sign(
            identity_signing_seed(identity),
            crypto.item_wrap_message(vault_id, item_id, revision, key_version, wrapped_key, ciphertext, identity_id),
        )
        body = {
            "type": item_type,
            "expected_revision": expected_revision,
            "revision": revision,
            "key_version": key_version,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "public_fingerprint": fingerprint,
            "author_identity_id": identity_id,
            "content_signature": base64.b64encode(content_signature).decode(),
            "wrapped_item_key": base64.b64encode(wrapped_key).decode(),
            # A fresh write's wrapper is the same current identity that
            # created its content.  The server must retain this signed
            # linkage so later reads can apply the current-admin wrap rule.
            "wrapper_identity_id": identity_id,
            "wrap_signature": base64.b64encode(wrap_signature).decode(),
        }
        return await self._signed("PUT", f"/api/v1/vaults/{vault_id}/items/{item_id}", body)

    async def delete_item(self, vault_id: str, item_id: str, revision: int) -> dict[str, Any]:
        _uuid(vault_id, "vault_id")
        _uuid(item_id, "item_id")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            raise ValueError("delete revision must be positive")
        identity = current_identity(self._vaults._identity_store)
        next_revision = revision + 1
        signature = crypto.sign(
            identity_signing_seed(identity),
            crypto.item_tombstone_message(vault_id, item_id, next_revision, str(identity.identity_id)),
        )
        return await self._signed(
            "DELETE",
            f"/api/v1/vaults/{vault_id}/items/{item_id}",
            {"revision": next_revision, "deleter_identity_id": str(identity.identity_id), "signature": base64.b64encode(signature).decode()},
        )

    def _version(self, vault: Mapping[str, Any], number: int) -> Mapping[str, Any]:
        for version in vault.get("versions", []):
            if int(version.get("version", 0)) == number:
                return version
        raise VaultStateError("item references a missing vault version")

    def _verify_item_trust(
        self, vault: Mapping[str, Any], item: Mapping[str, Any], ciphertext: bytes,
        wrapped_key: bytes, version: Mapping[str, Any],
    ) -> None:
        if vault.get("kind") == "personal":
            self._verify_personal_item_trust(vault, item, ciphertext, wrapped_key)
            return
        identities = vault.get("identities", {})
        roster = vault.get("roster", [])
        roles = {int(entry["user_id"]): str(entry.get("role", "viewer")) for entry in roster if isinstance(entry, Mapping)}
        by_identity = {str(identity_id): identity for identity_id, identity in identities.items() if isinstance(identity, Mapping)}
        author_id = str(item["author_identity_id"])
        author = by_identity.get(author_id)
        author_ok = False
        if author is not None and roles.get(int(author["user_id"]), "viewer") in {"member", "admin", "owner"}:
            author_ok = crypto.verify(
                decode_b64(author["sig_public_key"], "author.sig_public_key"),
                crypto.item_content_message(
                    str(vault["vault_id"]), str(item["item_id"]), str(item["type"]), int(item["revision"]),
                    decode_b64(item["nonce"], "item.nonce"), ciphertext, item.get("public_fingerprint"), author_id,
                ),
                decode_b64(item["content_signature"], "item.content_signature"),
            )
        wrapper_id = str(item["wrapper_identity_id"])
        wrapper = by_identity.get(wrapper_id)
        wrapper_ok = False
        if wrapper is not None and roles.get(int(wrapper["user_id"]), "viewer") in {"admin", "owner"}:
            wrapper_ok = int(item["key_version"]) == int(vault["current_version"]) and crypto.verify(
                decode_b64(wrapper["sig_public_key"], "wrapper.sig_public_key"),
                crypto.item_wrap_message(
                    str(vault["vault_id"]), str(item["item_id"]), int(item["revision"]), int(item["key_version"]),
                    wrapped_key, ciphertext, wrapper_id,
                ),
                decode_b64(item["wrap_signature"], "item.wrap_signature"),
            )
        if not author_ok and not wrapper_ok:
            raise VaultStateError("item has no trusted content or current admin wrap signature")

    def _verify_personal_item_trust(
        self, vault: Mapping[str, Any], item: Mapping[str, Any], ciphertext: bytes,
        wrapped_key: bytes,
    ) -> None:
        """Verify sparse personal-vault items against local custody only.

        Personal responses intentionally omit roster and identity maps.  Their
        owner and scope must nevertheless match the unlocked identity already
        used to verify the vault chain; no signing key supplied by the server
        is accepted for either item signature.
        """
        identity = current_identity(self._vaults._identity_store)
        identity_id = str(identity.identity_id)
        user_id = getattr(identity, "user_id", None)
        owner_user_id = vault.get("owner_user_id")
        if (
            isinstance(user_id, bool) or not isinstance(user_id, int) or user_id < 1
            or isinstance(owner_user_id, bool) or owner_user_id != user_id
            or vault.get("scope") != f"user:{user_id}"
        ):
            raise VaultStateError("personal vault ownership does not match local identity")
        signing_key = crypto.public_from_seed(identity_signing_seed(identity))
        author_id = str(item["author_identity_id"])
        author_ok = author_id == identity_id and crypto.verify(
            signing_key,
            crypto.item_content_message(
                str(vault["vault_id"]), str(item["item_id"]), str(item["type"]), int(item["revision"]),
                decode_b64(item["nonce"], "item.nonce"), ciphertext, item.get("public_fingerprint"), author_id,
            ),
            decode_b64(item["content_signature"], "item.content_signature"),
        )
        wrapper_id = str(item["wrapper_identity_id"])
        wrapper_ok = (
            wrapper_id == identity_id
            and int(item["key_version"]) == int(vault["current_version"])
            and crypto.verify(
                signing_key,
                crypto.item_wrap_message(
                    str(vault["vault_id"]), str(item["item_id"]), int(item["revision"]), int(item["key_version"]),
                    wrapped_key, ciphertext, wrapper_id,
                ),
                decode_b64(item["wrap_signature"], "item.wrap_signature"),
            )
        )
        if not author_ok and not wrapper_ok:
            raise VaultStateError("item has no trusted content or current admin wrap signature")

    @staticmethod
    def _validate_payload(item_type: str, payload: Mapping[str, Any], fingerprint: Any) -> None:
        if not isinstance(payload.get("name"), str) or not 1 <= len(payload["name"]) <= 200:
            raise ValueError("vault item name must contain 1 to 200 characters")
        if not isinstance(payload.get("notes", ""), str) or len(payload.get("notes", "")) > 4000:
            raise ValueError("vault item notes must contain at most 4000 characters")
        if item_type in _SSH_TYPES:
            if not isinstance(fingerprint, str) or not fingerprint.startswith("SHA256:"):
                raise ValueError("SSH vault items require their public key fingerprint")
            if not isinstance(payload.get("public_key"), str) or not isinstance(payload.get("private_key_openssh"), str):
                raise ValueError("SSH vault items require an OpenSSH public and private key")
            public_key = payload["public_key"]
            private_key = payload["private_key_openssh"]
            actual_fingerprint = crypto.ssh_public_fingerprint(public_key)
            derived_public_key = crypto.openssh_public_key_from_private(private_key.encode("utf-8"))
            if actual_fingerprint != fingerprint or crypto.ssh_public_fingerprint(derived_public_key) != fingerprint:
                raise ValueError("SSH public key, private key, and fingerprint must match")
            if payload.get("key_type") != public_key.split()[0]:
                raise ValueError("SSH item key_type must match the OpenSSH public key")
        elif fingerprint is not None:
            raise ValueError("only SSH vault items may carry a public fingerprint")
