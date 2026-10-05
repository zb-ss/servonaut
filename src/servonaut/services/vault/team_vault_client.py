"""Verified, signed client for Team Vault state.

The HTTP transport signs requests; this layer verifies the untrusted server's
identity, version-chain and grant records before exposing a vault key.
"""
from __future__ import annotations

import base64
import secrets
import uuid
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlencode

from . import crypto
from .errors import NO_LOCAL_IDENTITY, VaultUserError
from .roster_pins import RosterPins, decode_b64


class VaultStateError(crypto.IntegrityError):
    """Raised when a remote vault cannot be safely used."""


class VaultIdentityMissingError(VaultStateError, VaultUserError):
    """No unlocked local identity: a state error that also tells the user what to do."""


def _uuid(value: str, field: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(f"{field} must be a canonical UUID") from exc
    if str(parsed) != value:
        raise ValueError(f"{field} must be a lowercase canonical UUID")
    return value


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise VaultStateError(f"{field} must be a positive integer")
    return value


def _value(identity: Any, name: str) -> Any:
    if isinstance(identity, Mapping):
        return identity[name]
    return getattr(identity, name)


def current_identity(store: Any) -> Any:
    """Read unlocked local identity material from the identity-store boundary."""
    for name in ("current_identity", "identity", "current"):
        candidate = getattr(store, name, None)
        if callable(candidate):
            return candidate()
        if candidate is not None:
            return candidate
    raise VaultIdentityMissingError(NO_LOCAL_IDENTITY)


def identity_signing_seed(identity: Any) -> bytes:
    return bytes(_value(identity, "signing_seed"))


def identity_encryption_secret(identity: Any) -> bytes:
    return bytes(_value(identity, "encryption_secret_key"))


def identity_encryption_public(identity: Any) -> bytes:
    return crypto.x25519_public(identity_encryption_secret(identity))


def identity_fingerprint(identity: Any) -> bytes:
    value = _value(identity, "fingerprint")
    return bytes.fromhex(value) if isinstance(value, str) else bytes(value)


class TeamVaultClient:
    """Fetch, create and verify native vaults without making UI decisions."""

    def __init__(self, api: Any, identity_store: Any, pins: RosterPins, state: Any) -> None:
        self._api = api
        self._identity_store = identity_store
        self._pins = pins
        self._state = state

    def _signer(self) -> Any:
        return self._identity_store.signer()

    async def _signed(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return await self._api.request_signed(
            method, path, json=dict(payload or {}), device=self._signer()
        )

    async def list_vaults(self) -> list[dict[str, Any]]:
        cursor: str | None = None
        seen: set[str] = set()
        vaults: list[dict[str, Any]] = []
        while True:
            path = "/api/v1/vaults" if cursor is None else f"/api/v1/vaults?{urlencode({'cursor': cursor})}"
            response = await self._signed("GET", path)
            data = response.get("data", [])
            if not isinstance(data, list):
                raise VaultStateError("vault list has an invalid response shape")
            vaults.extend(dict(vault) for vault in data if isinstance(vault, Mapping))
            meta = response.get("meta", {})
            next_cursor = meta.get("next_cursor") if isinstance(meta, Mapping) else None
            if next_cursor is None:
                return vaults
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen:
                raise VaultStateError("vault list cursor is invalid")
            seen.add(next_cursor)
            cursor = next_cursor

    async def get_vault(
        self, vault_id: str, *, confirm_changed_identities: bool = False
    ) -> dict[str, Any]:
        _uuid(vault_id, "vault_id")
        vault = await self._signed("GET", f"/api/v1/vaults/{vault_id}")
        self.verify_vault(vault, confirm_changed_identities=confirm_changed_identities)
        return vault

    def verify_vault(
        self, vault: Mapping[str, Any], *, confirm_changed_identities: bool = False
    ) -> tuple[int, bytes]:
        """Verify all referenced identities and the complete version chain."""
        vault_id = str(vault.get("vault_id", ""))
        scope = str(vault.get("scope", ""))
        versions = vault.get("versions")
        identities = vault.get("identities", {})
        if not vault_id or not scope or not isinstance(versions, list) or not isinstance(identities, Mapping):
            raise VaultStateError("vault is missing its verifiable state")
        active_identity_ids = {
            str(entry.get("identity", {}).get("identity_id"))
            for entry in vault.get("roster", [])
            if isinstance(entry, Mapping) and isinstance(entry.get("identity"), Mapping)
        }
        local_identity = getattr(self._identity_store, "identity", None)
        if local_identity is not None:
            active_identity_ids.add(str(_value(local_identity, "identity_id")))
        signing_keys: dict[str, bytes] = {}
        for identity_id, identity in identities.items():
            if not isinstance(identity, Mapping):
                raise VaultStateError("vault identity has an invalid shape")
            self._pins.verify_identity(identity)
            is_active = str(identity_id) in active_identity_ids
            if is_active and identity.get("grantable") is True:
                self._pins.observe(identity, confirm_changed=confirm_changed_identities)
            elif not self._pins.is_pinned(identity):
                if not is_active:
                    raise VaultStateError("historical vault identity was never pinned")
                # A current member whose identity is not grantable yet
                # (unconfirmed) or any more (compromised) is neither pinned
                # nor trusted to sign the chain, but must not block the vault
                # for everyone else.
                continue
            signing_keys[str(identity_id)] = decode_b64(identity["sig_public_key"], "sig_public_key")
        if vault.get("kind") == "personal" and local_identity is not None:
            # Personal responses deliberately omit their roster and identity
            # map.  The unlocked local identity is the only safe trust anchor
            # available for its current signed chain; a reset whose historical
            # signing key is unavailable fails closed rather than trusting a
            # key supplied by the server.
            signing_keys.setdefault(
                str(_value(local_identity, "identity_id")),
                crypto.public_from_seed(identity_signing_seed(local_identity)),
            )
        records: list[dict[str, Any]] = []
        for wire in versions:
            if not isinstance(wire, Mapping):
                raise VaultStateError("vault version has an invalid shape")
            records.append(
                {
                    "vault_id": vault_id,
                    "scope": scope,
                    "version": _positive_int(wire["version"], "version.version"),
                    "public_key": decode_b64(wire["public_key"], "version.public_key"),
                    "prev_hash": decode_b64(wire["prev_hash"], "version.prev_hash"),
                    "record_hash": decode_b64(wire["record_hash"], "version.record_hash"),
                    "creator_identity_id": str(wire["creator_identity_id"]),
                    "signature": decode_b64(wire["signature"], "version.signature"),
                }
            )
        previous = self._state.load().get("vault_heads", {}).get(vault_id)
        highest = None
        if isinstance(previous, Mapping):
            highest = (_positive_int(previous["version"], "stored vault version"), bytes.fromhex(str(previous["record_hash"])))
        head = crypto.verify_version_chain(records, signing_keys, highest)
        if _positive_int(vault.get("current_version"), "vault.current_version") != head[0]:
            raise VaultStateError("vault current version does not match its signed chain")
        self._state.record_vault_head(vault_id, head[0], head[1].hex())
        return head

    def open_my_grant(self, vault: Mapping[str, Any], identity: Any | None = None) -> bytes:
        """Verify and decrypt this client's grant for the current vault version."""
        identity = current_identity(self._identity_store) if identity is None else identity
        # Bind the grant to the same complete, verified vault state used by
        # item reads.  In particular, personal-vault responses omit identity
        # maps, so their local signer anchor is established only here from
        # custody, never from a server-supplied public key.
        self.verify_vault(vault)
        grant = vault.get("my_grant")
        versions = vault.get("versions")
        identities = vault.get("identities", {})
        if not isinstance(grant, Mapping) or not isinstance(versions, list) or not isinstance(identities, Mapping):
            raise VaultStateError("vault does not contain a usable local grant")
        version_number = _positive_int(grant.get("version"), "grant.version")
        version = next(
            (
                item for item in versions
                if isinstance(item, Mapping)
                and _positive_int(item.get("version"), "version.version") == version_number
            ),
            None,
        )
        if not isinstance(version, Mapping):
            raise VaultStateError("grant references an unknown vault version")
        granter_id = str(grant["granter_identity_id"])
        granter = identities.get(granter_id)
        if vault.get("kind") == "personal":
            local_identity = current_identity(self._identity_store)
            if granter_id != str(_value(local_identity, "identity_id")):
                raise VaultStateError("personal vault grant signer is not the local identity")
            granter_key = crypto.public_from_seed(identity_signing_seed(local_identity))
        else:
            if not isinstance(granter, Mapping):
                raise VaultStateError("grant signer identity is missing")
            if not self._pins.is_pinned(granter):
                raise VaultStateError("grant signer identity is not pinned")
            granter_key = decode_b64(granter["sig_public_key"], "granter.sig_public_key")
        sealed = decode_b64(grant["sealed_private_key"], "grant.sealed_private_key")
        version_key = decode_b64(version["public_key"], "version.public_key")
        message = crypto.grant_message(
            str(vault["vault_id"]), str(vault["scope"]), version_number, version_key,
            int(_value(identity, "user_id")), str(_value(identity, "identity_id")),
            identity_fingerprint(identity), sealed, granter_id,
        )
        if not crypto.verify(
            granter_key,
            message,
            decode_b64(grant["signature"], "grant.signature"),
        ):
            raise VaultStateError("vault grant signature is invalid")
        return crypto.open_grant(
            sealed, identity_encryption_public(identity), identity_encryption_secret(identity), version_key
        )

    async def create_personal(self, name: str, identity: Any | None = None) -> dict[str, Any]:
        identity = current_identity(self._identity_store) if identity is None else identity
        return await self._create("/api/v1/vault/personal", name, None, identity)

    async def create_team(
        self,
        team_slug: str,
        team_id: str,
        name: str,
        *,
        grant_policy: str = "auto",
        identity: Any | None = None,
    ) -> dict[str, Any]:
        if grant_policy not in {"auto", "approval"}:
            raise ValueError("grant_policy must be auto or approval")
        identity = current_identity(self._identity_store) if identity is None else identity
        return await self._create(
            f"/api/v1/teams/{team_slug}/vaults", name, grant_policy, identity,
            scope=f"team:{team_id}",
        )

    async def _create(
        self,
        path: str,
        name: str,
        grant_policy: str | None,
        identity: Any,
        *,
        scope: str | None = None,
    ) -> dict[str, Any]:
        vault_id = str(uuid.uuid4())
        vault_secret = secrets.token_bytes(32)
        vault_public = crypto.x25519_public(vault_secret)
        scope = scope or f"user:{int(_value(identity, 'user_id'))}"
        version_message = crypto.version_message(
            vault_id, scope, 1, vault_public, crypto.ZERO_HASH, str(_value(identity, "identity_id"))
        )
        version = {
            "version": 1,
            "public_key": base64.b64encode(vault_public).decode(),
            "prev_hash": base64.b64encode(crypto.ZERO_HASH).decode(),
            "signature": base64.b64encode(crypto.sign(identity_signing_seed(identity), version_message)).decode(),
        }
        sealed = crypto.seal(vault_secret, identity_encryption_public(identity))
        grant_message = crypto.grant_message(
            vault_id, scope, 1, vault_public, int(_value(identity, "user_id")),
            str(_value(identity, "identity_id")), identity_fingerprint(identity), sealed,
            str(_value(identity, "identity_id")),
        )
        grant = {
            "recipient_user_id": int(_value(identity, "user_id")),
            "recipient_identity_id": str(_value(identity, "identity_id")),
            "sealed_private_key": base64.b64encode(sealed).decode(),
            "signature": base64.b64encode(crypto.sign(identity_signing_seed(identity), grant_message)).decode(),
        }
        payload: dict[str, Any] = {"vault_id": vault_id, "name": name, "version": version, "grants": [grant]}
        if grant_policy is not None:
            payload["grant_policy"] = grant_policy
        return await self._signed("POST", path, payload)
