"""Bitwarden Password Manager SSH config + per-instance ref client.

Wire contract locked with servonaut.dev on 2026-05-24. Two address spaces:

- Personal (Solo + Teams tiers): ``/api/v1/me/...`` — applies to instances the
  user owns directly via list_instances (AWS / OVH / Hetzner).
- Team (Teams tier, admin/owner role for writes): ``/api/v1/teams/{slug}/...``
  — applies to instances explicitly shared by an owner as ``SharedServer`` rows.

Resolution order (callers walk in this exact priority):

    1. Personal — :meth:`get_personal_instance_ref`
    2. Team    — :meth:`get_team_server_ref` (added in C2, see ``team_service``)
    3. Local ``~/.ssh`` fallback

Locked field names (additive-evolution from here, never renamed):

- Body field is **``ssh_credential_ref``** (NOT ``ref``). The server accepts
  ``ref`` as a backward-compat alias for one release; we never use it.
- ``ssh_verified_at`` is **NULL whenever ``ssh_verify_status`` ≠ ``"verified"``**.
  Callers must render it as "—" / "never" for non-verified statuses to avoid
  showing a stale timestamp next to a failed status.

Tier gates surfaced by the server:

- Free tier on any ``/me/{ssh,secrets}-config`` or ``/me/instances/...`` → 402
- Member-not-admin on team-side writes → 403 (see ``team_service``)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .interfaces import BwSshConfigServiceInterface

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient

logger = logging.getLogger(__name__)

# Provider identifier in the locked wire contract.
BITWARDEN_PM_PROVIDER = "bitwarden_pm"

# Verify-report status enum. Server NULLs ``ssh_verified_at`` on anything
# other than ``verified``.
STATUS_VERIFIED = "verified"
STATUS_NOT_FOUND = "not_found"
STATUS_AUTH_FAILED = "auth_failed"
VALID_VERIFY_STATUSES = frozenset({STATUS_VERIFIED, STATUS_NOT_FOUND, STATUS_AUTH_FAILED})


class BwSshConfigService(BwSshConfigServiceInterface):
    """Client for personal SSH config + per-instance ref endpoints.

    Team-side equivalents live on :class:`TeamService` because they share the
    team-slug routing concern; this service is personal-scope only.
    """

    def __init__(self, api_client: "APIClient") -> None:
        self._api = api_client

    # ------------------------------------------------------------------
    # Personal SSH config (vault wiring)
    # ------------------------------------------------------------------

    async def get_personal_config(self) -> Optional[Dict[str, Any]]:
        """Return the user's personal BW SSH config, or ``None`` if not configured.

        Shape on 200::

            {"provider": "bitwarden_pm",
             "config": {"vault_url": "...", "default_collection_id": "..."?},
             "updated_at": "..."}

        404 → user has not configured personal BW yet — caller should treat
        this as "fall back to local ``~/.ssh``".
        """
        from servonaut.services.api_client import APIError  # local import — avoid cycle
        try:
            return await self._api.get("/api/v1/me/ssh-config")
        except APIError as exc:
            if exc.status == 404:
                return None
            raise

    async def put_personal_config(
        self,
        vault_url: str,
        default_collection_id: Optional[str] = None,
        provider: str = BITWARDEN_PM_PROVIDER,
    ) -> Dict[str, Any]:
        config: Dict[str, Any] = {"vault_url": vault_url}
        if default_collection_id:
            config["default_collection_id"] = default_collection_id
        return await self._api.put(
            "/api/v1/me/ssh-config",
            json={"provider": provider, "config": config},
        )

    # ------------------------------------------------------------------
    # Personal per-instance SSH refs
    # ------------------------------------------------------------------

    async def list_personal_instances(self) -> List[Dict[str, Any]]:
        """Roll-up of every personal instance with a stored SSH ref.

        Shape on 200::

            {"instances": [
                {"provider", "instance_id", "ssh_credential_provider",
                 "ssh_verify_status", "ssh_verified_at", "updated_at"},
                ...
            ]}

        Returns the unwrapped list. Tolerates a bare-array fallback shape
        for forward-compat.
        """
        result = await self._api.get("/api/v1/me/instances")
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("instances", [])
        return []

    async def put_personal_instance_ref(
        self,
        provider: str,
        instance_id: str,
        ssh_credential_ref: Dict[str, Any],
        ssh_credential_provider: str = BITWARDEN_PM_PROVIDER,
    ) -> Dict[str, Any]:
        """Store/replace the SSH credential ref for a personal instance.

        ``ssh_credential_ref`` shape::

            {"item_id": "uuid",
             "collection_id": "uuid"?,
             "vault_url": "https://..."?}

        Callers must validate ``provider`` and ``instance_id`` via
        :mod:`servonaut.utils.validation` BEFORE calling this — server-side
        regexes return 404 / 400 which are slower to surface as user-facing
        errors than a local ``ValidationError``.
        """
        path = f"/api/v1/me/instances/{provider}/{instance_id}/ssh-ref"
        return await self._api.put(
            path,
            json={
                "ssh_credential_provider": ssh_credential_provider,
                "ssh_credential_ref": ssh_credential_ref,
            },
        )

    async def delete_personal_instance_ref(
        self, provider: str, instance_id: str
    ) -> bool:
        """Remove the stored SSH ref. Returns True on delete, False if absent."""
        from servonaut.services.api_client import APIError  # local import — avoid cycle
        path = f"/api/v1/me/instances/{provider}/{instance_id}/ssh-ref"
        try:
            result = await self._api.delete(path)
        except APIError as exc:
            if exc.status == 404:
                return False
            raise
        return bool(result.get("deleted", True)) if isinstance(result, dict) else True

    async def get_personal_instance_ref(
        self, provider: str, instance_id: str
    ) -> Optional[Dict[str, Any]]:
        """GET /api/v1/me/instances/{provider}/{instance_id}/ssh-ref.

        Returns ``{"ssh_credential_provider": ..., "ssh_credential_ref": {...}}``
        on 200, or ``None`` on 404 (no ref stored yet).

        Used by :class:`SshRefResolver` as the first tier of the resolution
        chain — if the user has stored a BW item ref for this instance, this
        method returns it; otherwise falls through to team and local tiers.
        """
        from servonaut.services.api_client import APIError  # local import — avoid cycle
        path = f"/api/v1/me/instances/{provider}/{instance_id}/ssh-ref"
        try:
            return await self._api.get(path)
        except APIError as exc:
            if exc.status == 404:
                return None
            raise

    async def get_personal_instance_verify_status(
        self, provider: str, instance_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get the last verify status for a personal instance, or None if no ref.

        Shape on 200::

            {"provider", "instance_id", "ssh_verify_status",
             "ssh_verified_at", "checked_by_client", "updated_at"}

        ``ssh_verified_at`` is NULL whenever ``ssh_verify_status`` ≠ ``verified``
        (server-enforced contract).
        """
        from servonaut.services.api_client import APIError  # local import — avoid cycle
        path = f"/api/v1/me/instances/{provider}/{instance_id}/ssh-verify-status"
        try:
            return await self._api.get(path)
        except APIError as exc:
            if exc.status == 404:
                return None
            raise

    async def report_personal_instance_verify(
        self,
        provider: str,
        instance_id: str,
        status: str,
        checked_by_client: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Submit a verify probe result for a personal instance.

        ``status`` must be one of :data:`VALID_VERIFY_STATUSES`.
        ``checked_by_client`` should be ``"servonaut-cli/<version>"`` so the
        audit row tells future-us which CLI version did the probe.
        """
        if status not in VALID_VERIFY_STATUSES:
            allowed = ", ".join(sorted(VALID_VERIFY_STATUSES))
            raise ValueError(f"status must be one of {{{allowed}}}, got {status!r}")
        body: Dict[str, Any] = {"status": status}
        if checked_by_client:
            body["checked_by_client"] = checked_by_client
        path = f"/api/v1/me/instances/{provider}/{instance_id}/ssh-verify-report"
        return await self._api.post(path, json=body)
