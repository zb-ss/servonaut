"""Signed credential-binding construction and verification."""
from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from typing import Any

from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from . import crypto
from .roster_pins import decode_b64
from .team_vault_client import TeamVaultClient, VaultStateError, _positive_int, current_identity, identity_signing_seed


class VaultBindingService:
    """Bind native vault SSH items only to verified, pinned destinations."""

    def __init__(self, api: Any, vaults: TeamVaultClient) -> None:
        self._api = api
        self._vaults = vaults

    def build_binding(
        self,
        *,
        scope: str,
        target: str,
        hostname: str,
        port: int,
        login_user: str,
        vault_id: str,
        vault_item_id: str,
        public_fingerprint: str,
        host_keys: Sequence[str],
        binding_revision: int,
    ) -> dict[str, Any]:
        """Build a signed native-vault binding after strict local validation."""
        self._validate_host_keys(host_keys)
        if not 1 <= port <= 65535 or binding_revision < 1:
            raise ValueError("binding port or revision is invalid")
        identity = current_identity(self._vaults._identity_store)
        message = crypto.binding_message(
            scope, target, hostname, port, login_user, vault_id, vault_item_id,
            public_fingerprint, host_keys, binding_revision, str(identity.identity_id),
        )
        return {
            "source": "servonaut_vault",
            "vault_id": vault_id,
            "vault_item_id": vault_item_id,
            "login_user": login_user,
            "public_fingerprint": public_fingerprint,
            "host_keys": list(host_keys),
            "hostname": hostname,
            "port": port,
            "binding_revision": binding_revision,
            "binder_identity_id": str(identity.identity_id),
            "signature": base64.b64encode(crypto.sign(identity_signing_seed(identity), message)).decode(),
        }

    def verify_binding(
        self,
        binding: Mapping[str, Any],
        vault: Mapping[str, Any],
        *,
        target: str,
        hostname: str,
        port: int,
    ) -> dict[str, Any]:
        """Verify a binding's target, destination and current admin signature."""
        self._vaults.verify_vault(vault)
        if binding.get("source") != "servonaut_vault" or binding.get("valid") is not True:
            raise VaultStateError("credential binding is not a usable native-vault binding")
        binding_port = binding.get("port")
        if isinstance(binding_port, bool) or not isinstance(binding_port, int) or binding.get("hostname") != hostname or binding_port != port:
            raise VaultStateError("credential binding destination no longer matches the server")
        scope = str(vault["scope"])
        if not target or not str(binding.get("vault_id", "")) == str(vault["vault_id"]):
            raise VaultStateError("credential binding targets the wrong vault")
        host_keys = binding.get("host_keys")
        if not isinstance(host_keys, list):
            raise VaultStateError("credential binding host pins are malformed")
        self._validate_host_keys(host_keys)
        binder_id = str(binding.get("binder_identity_id", ""))
        identities = vault.get("identities", {})
        binder = identities.get(binder_id) if isinstance(identities, Mapping) else None
        local_identity = current_identity(self._vaults._identity_store)
        if vault.get("kind") == "personal":
            # Personal vault responses intentionally omit their identity map.
            # A binding can consequently only be accepted when it was signed
            # by the unlocked personal-vault identity.
            if binder_id != str(local_identity.identity_id):
                raise VaultStateError("personal credential binding signer is not the local vault owner")
            binder_signing_key = crypto.public_from_seed(identity_signing_seed(local_identity))
        else:
            if not isinstance(binder, Mapping):
                raise VaultStateError("credential binding signer identity is absent")
            self._vaults._pins.observe(binder)
            binder_signing_key = decode_b64(binder["sig_public_key"], "binder.sig_public_key")
        if vault.get("kind") == "team":
            roles = {
                int(entry["user_id"]): str(entry.get("role", "viewer"))
                for entry in vault.get("roster", []) if isinstance(entry, Mapping)
            }
            if roles.get(int(binder["user_id"]), "viewer") not in {"owner", "admin"}:
                raise VaultStateError("credential binding signer is not a current team admin")
        message = crypto.binding_message(
            scope, target, hostname, port, str(binding["login_user"]), str(binding["vault_id"]),
            str(binding["vault_item_id"]), str(binding["public_fingerprint"]), host_keys,
            _positive_int(binding.get("binding_revision"), "binding.binding_revision"), binder_id,
        )
        if not crypto.verify(
            binder_signing_key, message,
            decode_b64(binding["signature"], "binding.signature"),
        ):
            raise VaultStateError("credential binding signature is invalid")
        return dict(binding)

    async def put_team_binding(self, team_slug: str, server_id: str, binding: Mapping[str, Any]) -> dict[str, Any]:
        return await self._api.request_signed(
            "PUT", f"/api/v1/teams/{team_slug}/servers/{server_id}/credential-binding",
            json=dict(binding), device=self._vaults._signer(),
        )

    async def put_personal_binding(
        self, provider: str, instance_id: str, binding: Mapping[str, Any]
    ) -> dict[str, Any]:
        return await self._api.request_signed(
            "PUT", f"/api/v1/me/instances/{provider}/{instance_id}/credential-binding",
            json=dict(binding), device=self._vaults._signer(),
        )

    @staticmethod
    def _validate_host_keys(host_keys: Sequence[str]) -> None:
        if len(host_keys) > 8:
            raise ValueError("a credential binding supports at most eight host keys")
        for host_key in host_keys:
            if not isinstance(host_key, str) or len(host_key.split()) != 2:
                raise ValueError("host pins must be OpenSSH public keys without comments")
            try:
                load_ssh_public_key(host_key.encode("ascii"))
            except (ValueError, UnicodeEncodeError) as exc:
                raise ValueError("host pin is not a valid OpenSSH public key") from exc
