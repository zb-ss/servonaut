"""SSH ref resolution chain: personal BW ref → team BW ref → local ~/.ssh.

Resolution order (matches the locked wire contract in bw_ssh_config_service):

    1. Personal — ``BwSshConfigService.get_personal_instance_ref()``
    2. Team     — ``TeamService.get_team_server_ssh_ref()`` (only when
                  ``teams_supplier`` is set and the instance is a shared server)
    3. Local    — ``SSHService.get_key_path()`` / ``discover_key()``
    4. None     — if nothing matched

Any tier that raises an ``APIError`` (e.g. 403 Forbidden) is logged at
WARNING and skipped; the chain continues to the next tier.  A 404 from a
tier means "no ref stored" (not a failure) and also advances the chain.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, List, Literal, Optional

logger = logging.getLogger(__name__)

ResolutionSource = Literal["personal", "team", "local"]

_KNOWN_PROVIDERS = frozenset({"aws", "ovh", "hetzner"})


@dataclass(frozen=True)
class ResolvedSshRef:
    """Result of :meth:`SshRefResolver.resolve`.

    Exactly one of (``item_id`` / ``local_key_path``) is populated,
    depending on ``source``.
    """

    source: ResolutionSource
    """Which tier produced this ref."""

    item_id: Optional[str]
    """Bitwarden item UUID.  Set when ``source`` is ``'personal'`` or ``'team'``."""

    vault_url: Optional[str]
    """Bitwarden vault URL from the ref payload.  May be ``None`` even for BW
    sources when the personal/global default is used."""

    collection_id: Optional[str]
    """Bitwarden collection UUID from the ref payload.  Optional."""

    local_key_path: Optional[str]
    """Absolute path to an ``~/.ssh`` key file.  Set only when ``source`` is
    ``'local'``."""

    team_slug: Optional[str]
    """Team slug.  Set only when ``source`` is ``'team'``."""

    server_id: Optional[str]
    """SharedServer row id used to fetch the team ref.  Set only when
    ``source`` is ``'team'``."""


class SshRefResolver:
    """Walk personal → team → local to resolve an SSH credential for an instance.

    The resolver is *defensive by design*: API errors from any tier are caught,
    logged at WARNING, and the chain continues.  Only a 404 (no ref stored) is
    treated as "tier has nothing" and silently advances to the next.

    Args:
        bw_ssh_config_service: :class:`BwSshConfigService` instance (personal tier).
        team_service: :class:`TeamService` instance (team tier).
        ssh_service: :class:`SSHService` instance (local fallback).
        teams_supplier: Zero-arg callable that returns the list of teams the
            caller belongs to (used to iterate the team tier).  When ``None``
            the team tier is entirely skipped.
    """

    def __init__(
        self,
        bw_ssh_config_service: object,
        team_service: object,
        ssh_service: object,
        teams_supplier: Optional[Callable[[], List[dict]]] = None,
    ) -> None:
        self._bw = bw_ssh_config_service
        self._team_svc = team_service
        self._ssh_svc = ssh_service
        self._teams_supplier = teams_supplier

    async def resolve(self, instance: dict) -> Optional[ResolvedSshRef]:
        """Resolve an SSH credential for *instance*.

        Args:
            instance: Servonaut instance dict with at minimum ``'id'``.  The
                ``'provider'`` key is used for the personal tier; when absent
                it defaults to ``'aws'`` and is lowercased, matching the ref
                editor's save keying and the MCP resolution path.  Custom
                servers (provider outside ``{aws, ovh, hetzner}``) skip the
                personal tier gracefully.

        Returns:
            :class:`ResolvedSshRef` from the first tier that matches, or
            ``None`` if no tier could resolve a credential.
        """
        # --- Tier 1: personal BW ref ---
        ref = await self._try_personal(instance)
        if ref is not None:
            return ref

        # --- Tier 2: team BW ref ---
        ref = await self._try_team(instance)
        if ref is not None:
            return ref

        # --- Tier 3: local ~/.ssh fallback ---
        ref = self._try_local(instance)
        if ref is not None:
            return ref

        return None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _try_personal(self, instance: dict) -> Optional[ResolvedSshRef]:
        """Attempt resolution via the personal BW ref endpoint.

        Provider keying matches the ref-editor save path and the MCP
        resolution path exactly: a missing ``'provider'`` key defaults to
        ``'aws'`` (AWS instance dicts carry no provider key) and the value is
        lowercased (OVH dicts carry ``'OVH'``). Diverging here silently
        skipped the personal tier for AWS/OVH instances on the connect
        surfaces while MCP tools resolved the same saved ref.

        Skips silently when:
        - the normalized ``provider`` is not in ``{aws, ovh, hetzner}``
          (custom servers).
        - ``provider`` or ``instance_id`` fail client-side validation.
        - The API returns 404 (no ref stored).

        Logs a WARNING and skips when the API returns any other error.
        """
        from servonaut.utils.validation import (
            validate_provider,
            validate_instance_id,
            ValidationError,
        )
        from servonaut.services.api_client import APIError

        # Same keying convention as ssh_ref_editor's save path and
        # ServonautTools._resolve_connection_with_vault: default 'aws',
        # lowercase.
        provider = str(instance.get("provider", "aws") or "aws").lower()
        instance_id = instance.get("id") or instance.get("instance_id")

        # Custom servers / unknown providers don't have personal BW refs.
        if provider not in _KNOWN_PROVIDERS:
            return None

        # Client-side validation mirrors server-side regexes — invalid values
        # would silently 404 at the server; fail fast and skip the tier.
        try:
            validate_provider(provider)
            validate_instance_id(str(instance_id or ""))
        except ValidationError as exc:
            logger.debug(
                "Personal tier skipped for %r/%r: %s", provider, instance_id, exc
            )
            return None

        try:
            payload = await self._bw.get_personal_instance_ref(provider, str(instance_id))
        except APIError as exc:
            logger.warning(
                "Personal BW ref lookup failed for %s/%s (status=%s): %s",
                provider,
                instance_id,
                exc.status,
                exc.message,
            )
            return None
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Unexpected error in personal BW ref lookup for %s/%s: %s",
                provider,
                instance_id,
                exc,
            )
            return None

        if payload is None:
            # 404 → no ref stored; advance to next tier
            return None

        cred_ref = payload.get("ssh_credential_ref") or {}
        return ResolvedSshRef(
            source="personal",
            item_id=cred_ref.get("item_id"),
            vault_url=cred_ref.get("vault_url"),
            collection_id=cred_ref.get("collection_id"),
            local_key_path=None,
            team_slug=None,
            server_id=None,
        )

    async def _try_team(self, instance: dict) -> Optional[ResolvedSshRef]:
        """Attempt resolution via team BW ref endpoints.

        Only attempted when ``teams_supplier`` is set and the instance carries
        ``is_shared=True`` plus ``team_slug``.  Iterates all teams and returns
        the first hit.
        """
        from servonaut.services.api_client import APIError

        if self._teams_supplier is None:
            return None

        is_shared = instance.get("is_shared") is True
        if not is_shared:
            return None

        team_slug = instance.get("team_slug")
        if not team_slug:
            return None

        server_id = instance.get("shared_server_id") or instance.get("id")
        if not server_id:
            return None

        try:
            teams: List[dict] = self._teams_supplier()
        except Exception as exc:  # noqa: BLE001
            logger.warning("teams_supplier() raised: %s", exc)
            return None

        for team in teams:
            slug = team.get("slug") or team.get("name")
            if slug != team_slug:
                continue
            try:
                payload = await self._team_svc.get_team_server_ssh_ref(slug, str(server_id))
            except APIError as exc:
                logger.warning(
                    "Team BW ref lookup failed for %s/servers/%s (status=%s): %s",
                    slug,
                    server_id,
                    exc.status,
                    exc.message,
                )
                continue
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Unexpected error in team BW ref lookup for %s/%s: %s",
                    slug,
                    server_id,
                    exc,
                )
                continue

            if payload is None:
                continue

            cred_ref = payload.get("ssh_credential_ref") or {}
            return ResolvedSshRef(
                source="team",
                item_id=cred_ref.get("item_id"),
                vault_url=cred_ref.get("vault_url"),
                collection_id=cred_ref.get("collection_id"),
                local_key_path=None,
                team_slug=slug,
                server_id=str(server_id),
            )

        return None

    def _try_local(self, instance: dict) -> Optional[ResolvedSshRef]:
        """Attempt resolution via local ``~/.ssh`` discovery.

        Resolution order:

        1. ``instance['ssh_key']`` — when present and pointing at an existing
           path on disk.  Custom servers (and Hetzner instances) carry the
           key path directly on the instance dict; the AWS-style
           ``get_key_path`` / ``discover_key`` lookups can't find these
           because ``instance['key_name']`` for a custom server is itself
           the full path, not an AWS key-pair name.
        2. ``get_key_path(instance_id)`` — checks ``instance_keys`` map then
           ``config.default_key``.
        3. ``discover_key(key_name)`` — globs ``~/.ssh`` for AWS key-pair
           naming patterns.
        """
        from pathlib import Path

        direct = instance.get("ssh_key")
        if direct:
            try:
                expanded = Path(str(direct)).expanduser()
                if expanded.exists():
                    return ResolvedSshRef(
                        source="local",
                        item_id=None,
                        vault_url=None,
                        collection_id=None,
                        local_key_path=str(expanded),
                        team_slug=None,
                        server_id=None,
                    )
            except (OSError, ValueError) as exc:
                logger.debug("instance['ssh_key']=%r not usable: %s", direct, exc)

        instance_id = str(instance.get("id") or "")
        key_path: Optional[str] = None

        if instance_id:
            try:
                key_path = self._ssh_svc.get_key_path(instance_id)
            except Exception as exc:  # noqa: BLE001
                logger.debug("get_key_path(%r) raised: %s", instance_id, exc)

        if not key_path:
            key_name = instance.get("key_name")
            if key_name:
                try:
                    key_path = self._ssh_svc.discover_key(key_name)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("discover_key(%r) raised: %s", key_name, exc)

        if not key_path:
            return None

        return ResolvedSshRef(
            source="local",
            item_id=None,
            vault_url=None,
            collection_id=None,
            local_key_path=key_path,
            team_slug=None,
            server_id=None,
        )
