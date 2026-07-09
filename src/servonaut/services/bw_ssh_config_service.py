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

import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

try:  # POSIX-only; Windows falls back to lock-less (atomic replace still holds)
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platform
    fcntl = None  # type: ignore[assignment]

from .interfaces import BwSshConfigServiceInterface

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient

logger = logging.getLogger(__name__)

# Local mirror of successfully saved per-instance refs. Holds only opaque
# pointers (item/collection UUIDs, vault URL) — never key material. Used as a
# read fallback when the server does not expose GET on the ssh-ref route
# (405), so verify/resolution keep working on the device that saved the ref.
DEFAULT_REFS_CACHE_PATH = Path.home() / ".servonaut" / "bw_ssh_refs.json"

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

    def __init__(
        self,
        api_client: "APIClient",
        refs_cache_path: Optional[Path] = None,
    ) -> None:
        self._api = api_client
        self._refs_cache_path = refs_cache_path or DEFAULT_REFS_CACHE_PATH

    # ------------------------------------------------------------------
    # Local ref cache (fallback for servers without GET on the ssh-ref route)
    # ------------------------------------------------------------------

    @staticmethod
    def _cache_key(provider: str, instance_id: str) -> str:
        return f"{provider}/{instance_id}"

    def _load_ref_cache(self) -> Dict[str, Any]:
        try:
            data = json.loads(self._refs_cache_path.read_text())
            return data if isinstance(data, dict) else {}
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as exc:
            logger.debug("ref cache unreadable: %s", exc)
            return {}

    def _write_ref_cache(self, cache: Dict[str, Any]) -> None:
        """Atomically replace the mirror file (write-to-temp + ``os.replace``).

        The mirror is shared by up to three long-running processes (TUI, MCP
        server, relay listener), and against 405-only servers it is the ONLY
        source of the full ref on this device — so a truncate-in-place write
        is not acceptable: a concurrent reader would see a partial file
        (``_load_ref_cache`` treats a JSON parse error as an empty cache) and
        a crash mid-write would empty the mirror permanently. ``mkstemp``
        creates the temp file 0600 from birth (no umask window — contents are
        opaque pointers, never keys, but the instance→vault-item mapping is
        still not for other local users), the payload is flushed + fsynced,
        and ``os.replace`` publishes it atomically so readers only ever see a
        complete file.
        """
        self._refs_cache_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=self._refs_cache_path.name + ".",
            suffix=".tmp",
            dir=str(self._refs_cache_path.parent),
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(json.dumps(cache, indent=2).encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self._refs_cache_path)
        except OSError:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _mutate_ref_cache(
        self, mutate: Callable[[Dict[str, Any]], bool]
    ) -> None:
        """Locked read-modify-write of the mirror file.

        ``mutate`` receives the loaded cache dict, changes it in place, and
        returns whether anything changed (False skips the rewrite). An
        exclusive ``flock`` on a sidecar lock file serialises the RMW across
        processes so concurrent saves/deletes from the TUI, MCP server, and
        relay listener cannot drop each other's entries (last-writer-wins on
        the whole dict). On platforms without ``fcntl`` the RMW is
        best-effort unlocked, but readers are still safe thanks to the
        atomic-replace write.

        Failures stay debug-logged, mirroring the historical behaviour: the
        mirror is a resilience layer, never a hard dependency.
        """
        try:
            self._refs_cache_path.parent.mkdir(parents=True, exist_ok=True)
            lock_path = self._refs_cache_path.with_name(
                self._refs_cache_path.name + ".lock"
            )
            lock_fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                if fcntl is not None:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX)
                cache = self._load_ref_cache()
                if mutate(cache):
                    self._write_ref_cache(cache)
            finally:
                # Closing the fd releases the flock.
                os.close(lock_fd)
        except OSError as exc:
            logger.debug("ref cache update failed: %s", exc)

    def _cache_store(self, provider: str, instance_id: str, row: Dict[str, Any]) -> None:
        key = self._cache_key(provider, instance_id)

        def _mutate(cache: Dict[str, Any]) -> bool:
            cache[key] = row
            return True

        self._mutate_ref_cache(_mutate)

    def _cache_remove(self, provider: str, instance_id: str) -> None:
        key = self._cache_key(provider, instance_id)

        def _mutate(cache: Dict[str, Any]) -> bool:
            return cache.pop(key, None) is not None

        self._mutate_ref_cache(_mutate)

    def _cache_lookup(self, provider: str, instance_id: str) -> Optional[Dict[str, Any]]:
        row = self._load_ref_cache().get(self._cache_key(provider, instance_id))
        return row if isinstance(row, dict) else None

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
        result = await self._api.put(
            path,
            json={
                "ssh_credential_provider": ssh_credential_provider,
                "ssh_credential_ref": ssh_credential_ref,
            },
        )
        # Mirror the saved ref locally so reads keep working against servers
        # that expose only PUT/DELETE on this route (see get_personal_instance_ref).
        # File IO runs in a thread — these async methods execute on the TUI /
        # MCP event loop, where a slow disk must not stall other handlers.
        await asyncio.to_thread(
            self._cache_store,
            provider,
            instance_id,
            {
                "ssh_credential_provider": ssh_credential_provider,
                "ssh_credential_ref": dict(ssh_credential_ref),
            },
        )
        return result

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
                await asyncio.to_thread(self._cache_remove, provider, instance_id)
                return False
            raise
        await asyncio.to_thread(self._cache_remove, provider, instance_id)
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

        Resilience: some server versions expose only PUT/DELETE on this route
        and answer GET with 405. Headless surfaces (the MCP server, the relay
        listener) may also hit 401 when no interactive login session exists.
        In both cases fall back to (1) the local ref cache written on every
        successful save — full ref, so resolution keeps working on the device
        that saved it — then (2) the ``/me/instances`` roll-up, which proves a
        ref exists but carries no ``item_id`` (``ssh_credential_ref`` is
        ``None`` in that partial row). The 401 fallback leaks nothing: the
        mirror holds only opaque pointers, and the Bitwarden vault unlock is
        still required to obtain actual key material.

        The 401 fallback is a DELIBERATE offline-resilience decision, with two
        accepted consequences: (a) an expired login session keeps resolving
        refs the same device saved while entitled — acceptable because the
        entitlement gate is enforced server-side at save time (tier lapse on
        these routes surfaces as 402, which is NOT in the fallback set and
        propagates), and the user's own vault unlock still gates key material;
        (b) the 404 stale-mirror cleanup cannot run while requests return 401,
        so a ref deleted server-side keeps resolving on this device until the
        next authenticated read.

        404 stays authoritative-none: the server says no ref is stored, so any
        stale local mirror entry is dropped.
        """
        from servonaut.services.api_client import APIError  # local import — avoid cycle
        path = f"/api/v1/me/instances/{provider}/{instance_id}/ssh-ref"
        try:
            return await self._api.get(path)
        except APIError as exc:
            if exc.status == 404:
                # Server is authoritative: no ref stored — drop any stale mirror.
                await asyncio.to_thread(self._cache_remove, provider, instance_id)
                return None
            if exc.status in (401, 405):
                logger.debug(
                    "GET on ssh-ref route unavailable (status=%s); "
                    "using local-cache/list fallback",
                    exc.status,
                )
                return await self._ref_from_fallbacks(provider, instance_id)
            raise

    async def _ref_from_fallbacks(
        self, provider: str, instance_id: str
    ) -> Optional[Dict[str, Any]]:
        """Local-cache → list-roll-up fallback for servers without ssh-ref GET.

        The roll-up call is guarded: on a headless/unauthenticated surface it
        would fail exactly like the ssh-ref GET did (e.g. 401), so an
        ``APIError`` here is treated as an empty roll-up rather than a hard
        failure — the local mirror already had its chance above.
        """
        from servonaut.services.api_client import APIError  # local import — avoid cycle
        cached = await asyncio.to_thread(self._cache_lookup, provider, instance_id)
        if cached is not None:
            return cached
        try:
            rows = await self.list_personal_instances()
        except APIError as exc:
            logger.debug(
                "list_personal_instances unavailable during ref fallback "
                "(status=%s); treating as empty",
                exc.status,
            )
            rows = []
        for row in rows:
            if (
                str(row.get("provider", "")) == provider
                and str(row.get("instance_id", "")) == instance_id
            ):
                return {
                    "ssh_credential_provider": row.get("ssh_credential_provider"),
                    "ssh_credential_ref": None,
                }
        return None

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
