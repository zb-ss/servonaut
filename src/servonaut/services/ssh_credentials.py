"""Servonaut Vault keys for every SSH path.

Each surface resolves a server's local connection (host, login, key file,
bastion) in its own way. :func:`resolve_with_vault` puts the server's vault
credential on top of that: when the vault runtime holds an SSH certificate or
a verified native binding for the server, the connection uses the lease's
private agent, public identity file, pinned host keys and login instead of any
local key. A server whose row names a native binding fails closed when no
lease can be produced; every other server keeps its local connection.

A long-running app shares one :class:`VaultLeaseCache`, so a server's lease
(one private agent holding the key) is reused while the key is still loaded,
instead of starting an agent for every command. Headless one-shot callers pass
no cache and close the lease when they are done.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any, Optional

from servonaut.services.shared_servers import row_team_label, team_key_fallback, team_key_target

logger = logging.getLogger(__name__)

#: Binding source of a native Servonaut Vault key.
VAULT_SOURCE = "servonaut_vault"

#: A cached lease is given up this long before its key leaves the agent.
_EXPIRY_MARGIN_SECONDS = 30.0
#: How long a lease whose key has no agent lifetime is reused.
_DEFAULT_REUSE_SECONDS = 300.0


class VaultCredentialError(RuntimeError):
    """A server's vault credential is configured but cannot be used.

    Raised instead of falling back to a local key: a vault binding is an
    authenticated instruction, so an integrity or unlock failure must stop
    the connection rather than quietly try something else.
    """


def requires_vault(instance: Mapping[str, Any]) -> bool:
    """Whether the row itself names a native vault binding (team servers)."""
    binding = instance.get("credential_binding")
    return isinstance(binding, Mapping) and binding.get("source") == VAULT_SOURCE


def lease_key(instance: Mapping[str, Any]) -> tuple[str, ...]:
    """The cache key of a server: its team or provider, account and id."""
    if instance.get("is_shared") is True:
        return ("shared", str(instance.get("team_slug") or ""), str(instance.get("id") or ""))
    return (
        str(instance.get("provider") or "aws").lower(),
        str(instance.get("account") or ""),
        str(instance.get("id") or instance.get("name") or ""),
    )


class VaultLeaseCache:
    """Reuse a server's vault lease while its key is still loaded in the private agent.

    The vault runtime owns every lease and closes them all when the app
    stops, so the cache never closes one itself; it only stops handing out a
    lease that is about to expire or whose agent has gone.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._entries: dict[tuple[str, ...], tuple[Any, float]] = {}

    def get(self, key: tuple[str, ...]) -> Any:
        entry = self._entries.get(key)
        if entry is None:
            return None
        lease, expires_at = entry
        agent = getattr(lease, "identity_agent", None)
        if self._clock() >= expires_at or not isinstance(agent, str) or not Path(agent).exists():
            self._entries.pop(key, None)
            return None
        return lease

    def put(self, key: tuple[str, ...], lease: Any, ttl_seconds: Optional[float]) -> None:
        reuse = (
            float(ttl_seconds) - _EXPIRY_MARGIN_SECONDS
            if isinstance(ttl_seconds, (int, float)) and not isinstance(ttl_seconds, bool) and ttl_seconds > 0
            else _DEFAULT_REUSE_SECONDS
        )
        if reuse > 0:
            self._entries[key] = (lease, self._clock() + reuse)

    def forget(self, instance: Mapping[str, Any]) -> None:
        """Stop reusing a server's lease (its binding changed)."""
        self._entries.pop(lease_key(instance), None)

    def clear(self) -> None:
        self._entries.clear()


def _check_lease(lease: Any) -> None:
    for name, what in (
        ("identity_agent", "its private identity agent"),
        ("identity_file", "its public identity file"),
        ("known_hosts_path", "its strict host-key file"),
    ):
        value = getattr(lease, name, None)
        if not isinstance(value, str) or not value:
            raise VaultCredentialError(f"The vault SSH credential is missing {what}.")


async def vault_lease(
    instance: Mapping[str, Any],
    vault_runtime: Any,
    *,
    cache: Optional[VaultLeaseCache] = None,
) -> Any:
    """The vault lease for *instance*, or None when it has no vault credential.

    Raises:
        VaultCredentialError: the server has a vault credential that cannot
            be used (locked vault, changed address, tampered binding…).
    """
    native = requires_vault(instance)
    if vault_runtime is None or not callable(getattr(vault_runtime, "resolve_ssh", None)):
        if native:
            raise VaultCredentialError(
                "This server uses a Servonaut Vault key, but the vault is not available here."
            )
        return None
    key = lease_key(instance)
    if cache is not None:
        cached = cache.get(key)
        if cached is not None:
            return cached
    try:
        lease = await vault_runtime.resolve_ssh(instance)
    except Exception as exc:  # noqa: BLE001 - every failure fails closed
        from servonaut.services.vault.errors import vault_failure_reason

        raise VaultCredentialError(
            f"The configured Vault SSH credential could not be used ({vault_failure_reason(exc)})."
        ) from exc
    if lease is None:
        if native:
            raise VaultCredentialError("This server's Servonaut Vault key is unavailable.")
        return None
    _check_lease(lease)
    if cache is not None:
        cache.put(key, lease, getattr(vault_runtime, "agent_key_ttl_seconds", None))
    return lease


def lease_destination(lease: Any, host: Any, port: Any) -> tuple[Any, Any]:
    """``(host, port)`` where *lease*'s pinned host keys point, else *host* and *port*."""
    target_host = getattr(lease, "target_host", None) if lease is not None else None
    target_port = getattr(lease, "target_port", None) if lease is not None else None
    if not isinstance(target_host, str) or not target_host:
        target_host = host
    if isinstance(target_port, bool) or not isinstance(target_port, int) or not 1 <= target_port <= 65535:
        target_port = port
    return target_host, target_port


def apply_vault_lease(
    conn: Mapping[str, Any],
    lease: Any,
    *,
    instance: Mapping[str, Any],
    connection_service: Any,
) -> dict[str, Any]:
    """*conn* with the lease's agent, identity, host pins and login in place of a local key."""
    applied = dict(conn)
    proxy_args = list(applied.get("proxy_args") or [])
    profile = applied.get("profile")
    if profile is None and connection_service is not None:
        try:
            profile = connection_service.resolve_profile(instance)
        except Exception:  # noqa: BLE001 - a row without rules keeps its proxy args
            profile = None
    if profile is not None and connection_service is not None:
        proxy_args = connection_service.get_proxy_args(
            profile, identity_agent=getattr(lease, "identity_agent", None)
        )
    applied.update(
        {
            "username": getattr(lease, "login_user", None) or applied.get("username"),
            # The lease is the only private-key source: a local key file left
            # here would be offered before the agent's key.
            "key_path": None,
            "identity_agent": lease.identity_agent,
            "identity_file": lease.identity_file,
            "certificate_path": getattr(lease, "certificate_path", None),
            "known_hosts_path": lease.known_hosts_path,
            "proxy_args": proxy_args,
            # Connect exactly where the pinned host keys point.
            "host": getattr(lease, "target_host", None) or applied.get("host"),
            "port": getattr(lease, "target_port", None) or applied.get("port"),
            "key_source": f"vault_{getattr(lease, 'source', 'vault')}",
        }
    )
    return applied


async def resolve_with_vault(
    conn: Mapping[str, Any],
    instance: Mapping[str, Any],
    *,
    vault_runtime: Any,
    connection_service: Any,
    cache: Optional[VaultLeaseCache] = None,
    team_rows: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """*conn* unchanged, or with the server's vault credential applied.

    A server of the user's own without a vault credential or a local key
    for its key pair connects with a team's vault key or SSH certificate
    when a team in *team_rows* shares the same server (see
    ``shared_servers.team_key_fallback``), or when *instance* was marked
    with such a team row (``shared_servers.with_team_key``). It then goes
    where the team's key points, by the team row's connection rule, and
    ``key_team`` names the team. When the team's key cannot be used here
    (no vault identity yet, a grant still pending), the user's own SSH
    setup applies as before: an agent or ssh's default keys may hold the
    server's key.

    Raises:
        VaultCredentialError: see :func:`vault_lease` (the server's own
            vault credential).
    """
    lease = await vault_lease(instance, vault_runtime, cache=cache)
    if lease is not None:
        return apply_vault_lease(conn, lease, instance=instance, connection_service=connection_service)
    team = team_key_target(instance) or team_key_fallback(instance, team_rows, conn.get("key_path"))
    if team is None:
        return dict(conn)
    try:
        lease = await vault_lease(team, vault_runtime, cache=cache)
    except VaultCredentialError as exc:
        logger.warning("Not using the team's key for %s here: %s", instance.get("name") or instance.get("id"), exc)
        return dict(conn)
    if lease is None:
        return dict(conn)
    # The team's route: its connection rule and options, not the user's own row's.
    profile, extra_options = None, []
    if connection_service is not None:
        try:
            profile = connection_service.resolve_profile(team)
            extra_options = list(connection_service.get_extra_options(team, profile) or [])
        except Exception:  # noqa: BLE001 - a row without rules keeps none
            profile, extra_options = None, []
    applied = apply_vault_lease(
        {**conn, "profile": profile, "proxy_args": [], "extra_options": extra_options}, lease,
        instance=team, connection_service=connection_service,
    )
    applied["key_team"] = row_team_label(team)
    return applied


def ssh_identity_kwargs(conn: Mapping[str, Any]) -> dict[str, Any]:
    """Keyword arguments for the ssh/scp command builders from a resolved *conn*."""
    return {
        "identity_agent": conn.get("identity_agent"),
        "identity_file": conn.get("identity_file"),
        "certificate_file": conn.get("certificate_path"),
        "known_hosts_file": conn.get("known_hosts_path"),
    }
