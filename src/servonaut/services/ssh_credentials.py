"""Servonaut Vault keys for every SSH path.

Each surface resolves a server's local connection (host, login, key file,
bastion) in its own way. :func:`resolve_with_vault` puts the server's vault
credential on top of that: when the vault runtime holds an SSH certificate or
a verified native binding for the server, the connection uses the lease's
private agent, public identity file, pinned host keys and login instead of any
local key. A server whose row names a native binding fails closed when no
lease can be produced; every other server keeps its local connection.

A bastion (jump host) that is itself one of the fleet's servers and has a
vault key gets its own lease too (:func:`bastion_lease`): the hop then logs in
with the bastion's key and checks its signed host-key pins. A bastion the user
lists as their own without a vault key uses a team's key for the same server,
unless the user set a key of their own for the hop. Without either the hop
uses the user's own SSH setup.

A long-running app shares one :class:`VaultLeaseCache`, so a server's lease
(one private agent holding the key) is reused while the key is still loaded,
instead of starting an agent for every command. Headless one-shot callers pass
no cache and close the lease when they are done.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any, Optional

from servonaut.services.shared_servers import (
    has_team_access,
    is_shared_row,
    row_team_label,
    team_key_fallback,
    team_key_target,
    team_twin,
)

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


def _is_private_address(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False  # a DNS name names one host wherever it is used
    return address.is_private or address.is_loopback or address.is_link_local


def _row_address(row: Mapping[str, Any]) -> tuple[str, int]:
    """The address and port this machine dials for *row* directly, as a bastion is dialled.

    A cloud server's public address only: the same private address exists in
    many networks. A custom server's host is what the user connects to, so it
    counts whatever it is. A team's shared server's host counts unless it is
    a private address: the team's network is not necessarily the user's.
    """
    if is_shared_row(row):
        host = row.get("hostname") or row.get("public_ip")
        if _is_private_address(str(host or "").strip()):
            host = None
    elif row.get("is_custom") is True:
        host = row.get("host") or row.get("public_ip")
    else:
        host = row.get("public_ip")
    port = row.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        port = 22
    return str(host or "").strip().casefold(), port


def bastion_row(profile: Any, rows: Iterable[Mapping[str, Any]]) -> Optional[Mapping[str, Any]]:
    """The server row that is *profile*'s bastion, or None.

    The bastion is the one row the profile dials: same address and port,
    else (a bastion named by its server name) the one row of that name. The
    user's own rows are searched first, both ways, then a team's shared rows.
    Several matches find none: guessing could lease the wrong server's key.
    """
    host = str(getattr(profile, "bastion_host", None) or "").strip().casefold()
    if not host:
        return None
    try:
        port = int(getattr(profile, "ssh_port", 22) or 22)
    except (TypeError, ValueError):
        port = 22
    rows = [row for row in rows if isinstance(row, Mapping)]
    own = [row for row in rows if not is_shared_row(row)]
    shared = [row for row in rows if is_shared_row(row)]
    for group in (own, shared):
        by_address = [row for row in group if _row_address(row) == (host, port)]
        if not by_address:
            by_address = [row for row in group if str(row.get("name") or "").strip().casefold() == host]
        if len(by_address) == 1:
            return by_address[0]
        if by_address:
            return None
    return None


def _is_untrusted(exc: BaseException) -> bool:
    """Whether *exc* (or what it wraps) says the bastion's vault key must not be trusted.

    A binding, signature or pin that does not verify, or a bound address
    that changed. Anything else (a locked or missing identity, an agent that
    cannot start, an unreachable service) only means the key cannot be used
    here.
    """
    from servonaut.services.vault.ca_pins import CaPinMismatchError
    from servonaut.services.vault.crypto import IntegrityError
    from servonaut.services.vault.team_vault_client import VaultIdentityMissingError

    seen: set[int] = set()
    current: Optional[BaseException] = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, (IntegrityError, CaPinMismatchError)) and not isinstance(
            current, VaultIdentityMissingError,
        ):
            return True
        current = current.__cause__ or current.__context__
    return False


async def bastion_lease(
    profile: Any,
    rows: Iterable[Mapping[str, Any]],
    *,
    vault_runtime: Any,
    connection_service: Any,
    cache: Optional[VaultLeaseCache] = None,
) -> Any:
    """The vault lease of *profile*'s bastion, or None to keep the user's own hop setup.

    A bastion the user lists as their own (from their own cloud account)
    without a vault key of their own hops with a team's key for the same
    server (:func:`shared_servers.team_twin`), unless the profile names a
    ``bastion_key``: a key the user set for the hop is never replaced.

    None when the profile has no bastion, the vault is locked, no single
    server is the bastion (:func:`bastion_row`), the bastion has no vault
    key, the key cannot be used here (the vault service cannot be reached,
    no private agent can start, Windows), or the bastion is itself reached
    through a bastion or a proxy command (its binding pins an address only
    reachable that way).

    Raises:
        VaultCredentialError: the bastion's vault key must not be trusted (a
            binding, signature or pin that does not verify, a changed
            address): as for a target, the connection stops rather than
            trust the hop.
    """
    from servonaut.utils.platform_utils import get_os

    if profile is None or getattr(profile, "proxy_command", None) or not getattr(profile, "bastion_host", None):
        return None
    if vault_runtime is None or getattr(vault_runtime, "is_unlocked", False) is not True:
        return None
    if get_os() == "windows":
        # OpenSSH on Windows runs no hop that could use the key (see
        # ConnectionService.get_proxy_args): never start an agent for it.
        return None
    rows = [row for row in rows if isinstance(row, Mapping)]
    row = bastion_row(profile, rows)
    if row is None:
        return None
    name = str(row.get("name") or row.get("id") or profile.bastion_host)
    if _behind_proxy(row, name, connection_service):
        return None
    lease = await _bastion_row_lease(row, name, vault_runtime, cache)
    if lease is not None or is_shared_row(row) or getattr(profile, "bastion_key", None):
        return lease
    team = team_twin(row, rows)
    if team is None or _behind_proxy(team, name, connection_service):
        return None
    lease = await _bastion_row_lease(team, name, vault_runtime, cache)
    if lease is not None:
        logger.info("The hop to the bastion %s uses the key of the team %s", name, row_team_label(team))
    return lease


def bastion_hop_hint(profile: Any, rows: Iterable[Mapping[str, Any]], vault_runtime: Any) -> Optional[str]:
    """What to do when *profile*'s bastion hop has no key here, but a team's could log it in.

    A team that shares the bastion with its vault key or SSH certificate (the
    team's row, or the one the user's own row of it falls back to, see
    :func:`bastion_lease`) needs an unlocked Servonaut Vault identity on this
    computer. Without one the hop quietly offers the user's own keys, and a
    bastion that accepts only the team's refuses them all. None when the
    vault is ready, the profile names a ``bastion_key``, no team key applies,
    or this computer cannot hop with a vault key at all (Windows).
    """
    from servonaut.utils.platform_utils import get_os

    if (
        profile is None or getattr(profile, "proxy_command", None) or getattr(profile, "bastion_key", None)
        or not getattr(profile, "bastion_host", None)
        or getattr(vault_runtime, "is_unlocked", False) is True or get_os() == "windows"
    ):
        return None
    rows = [row for row in rows if isinstance(row, Mapping)]
    row = bastion_row(profile, rows)
    if row is None:
        return None
    if is_shared_row(row):
        team = dict(row) if has_team_access(row) else None
    else:
        team = team_twin(row, rows)
    if team is None:
        return None
    label = row_team_label(team)
    who = f"Team {label}" if label else "A team"
    return (
        f"{who} shares the bastion {profile.bastion_host} with its own key, which needs this computer's "
        "Servonaut Vault identity: set it up with `servonaut vault setup` (or unlock it). "
        "Until then the hop uses your own SSH setup."
    )


def _behind_proxy(row: Mapping[str, Any], name: str, connection_service: Any) -> bool:
    """Whether a connection rule routes the bastion's server *row* through a bastion or proxy itself."""
    if connection_service is None:
        return False
    try:
        own_profile = connection_service.resolve_profile(dict(row))
    except Exception:  # noqa: BLE001 - a row without rules is reached directly
        return False
    if own_profile is not None and (
        getattr(own_profile, "bastion_host", None) or getattr(own_profile, "proxy_command", None)
    ):
        logger.info("Not using the vault key of the bastion %s: a connection rule routes it through a proxy too", name)
        return True
    return False


async def _bastion_row_lease(
    row: Mapping[str, Any], name: str, vault_runtime: Any, cache: Optional[VaultLeaseCache],
) -> Any:
    """The vault lease of the bastion's server *row* (:func:`bastion_lease`), or None."""
    try:
        return await vault_lease(row, vault_runtime, cache=cache)
    except VaultCredentialError as exc:
        if _is_untrusted(exc):
            raise VaultCredentialError(f"The bastion {name}: {exc}") from exc
        logger.warning("The vault key of the bastion %s cannot be used here: %s", name, exc)
        return None


def apply_vault_lease(
    conn: Mapping[str, Any],
    lease: Any,
    *,
    instance: Mapping[str, Any],
    connection_service: Any,
    hop: Any = None,
) -> dict[str, Any]:
    """*conn* with the lease's agent, identity, host pins and login in place of a local key.

    *hop* is the bastion's own vault lease, if any (:func:`bastion_lease`).
    """
    applied = dict(conn)
    proxy_args = list(applied.get("proxy_args") or [])
    profile = _route_profile(applied, instance, connection_service)
    if profile is not None and connection_service is not None:
        proxy_args = connection_service.get_proxy_args(profile, hop=hop)
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


def _route_profile(conn: Mapping[str, Any], instance: Mapping[str, Any], connection_service: Any) -> Any:
    """The connection rule's profile *conn* routes *instance* by."""
    profile = conn.get("profile")
    if profile is None and connection_service is not None:
        try:
            profile = connection_service.resolve_profile(instance)
        except Exception:  # noqa: BLE001 - a row without rules keeps its proxy args
            profile = None
    return profile


async def resolve_with_vault(
    conn: Mapping[str, Any],
    instance: Mapping[str, Any],
    *,
    vault_runtime: Any,
    connection_service: Any,
    cache: Optional[VaultLeaseCache] = None,
    team_rows: Iterable[Mapping[str, Any]] = (),
    rows: Optional[Iterable[Mapping[str, Any]]] = None,
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

    The hop to a bastion that is one of *rows* (the fleet; *team_rows*
    when not given) and has a vault key uses that key (:func:`bastion_lease`).

    Raises:
        VaultCredentialError: see :func:`vault_lease` (the server's own
            vault credential) and :func:`bastion_lease`.
    """
    team_rows = list(team_rows)
    fleet = list(rows) if rows is not None else team_rows

    async def hop_for(profile: Any) -> Any:
        return await bastion_lease(
            profile, fleet, vault_runtime=vault_runtime, connection_service=connection_service, cache=cache,
        )

    lease = await vault_lease(instance, vault_runtime, cache=cache)
    if lease is not None:
        profile = _route_profile(conn, instance, connection_service)
        return apply_vault_lease(
            conn, lease, instance=instance, connection_service=connection_service, hop=await hop_for(profile),
        )
    team = team_key_target(instance) or team_key_fallback(instance, team_rows, conn.get("key_path"))
    if team is None:
        return await _with_hop(conn, instance, connection_service, hop_for)
    try:
        lease = await vault_lease(team, vault_runtime, cache=cache)
    except VaultCredentialError as exc:
        logger.warning("Not using the team's key for %s here: %s", instance.get("name") or instance.get("id"), exc)
        return await _with_hop(conn, instance, connection_service, hop_for)
    if lease is None:
        return await _with_hop(conn, instance, connection_service, hop_for)
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
        instance=team, connection_service=connection_service, hop=await hop_for(profile),
    )
    applied["key_team"] = row_team_label(team)
    return applied


async def _with_hop(conn: Mapping[str, Any], instance: Mapping[str, Any], connection_service: Any, hop_for: Any) -> dict[str, Any]:
    """*conn* for a server without a vault key: its hop uses the bastion's vault key if it has one."""
    applied = dict(conn)
    profile = _route_profile(applied, instance, connection_service)
    if profile is None or connection_service is None:
        return applied
    hop = await hop_for(profile)
    if hop is not None:
        applied["proxy_args"] = connection_service.get_proxy_args(profile, hop=hop)
    return applied


def ssh_identity_kwargs(conn: Mapping[str, Any]) -> dict[str, Any]:
    """Keyword arguments for the ssh/scp command builders from a resolved *conn*."""
    return {
        "identity_agent": conn.get("identity_agent"),
        "identity_file": conn.get("identity_file"),
        "certificate_file": conn.get("certificate_path"),
        "known_hosts_file": conn.get("known_hosts_path"),
    }
