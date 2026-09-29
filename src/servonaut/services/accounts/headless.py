"""Provider accounts for the surfaces without an instance list.

The MCP tools, the AI chat tools, the relay runner and the CLI commands read
servers and resolve server references through here, so each of them sees
every account of every provider and applies the same reference rules as the
TUI (see :mod:`servonaut.utils.instance_resolver`).

- :class:`CachedFleet` reads every account's cached servers from disk, for
  one-shot CLI commands that must never wait on a provider API.
- :class:`InstanceDirectory` finds a server for a tool call, refreshing
  provider inventories only while nothing has matched yet.
- :func:`resolve_provider_target` tells which account a provider-level call
  (start, stop, reboot, delete) acts in.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional

from servonaut.config.accounts import AWS, HETZNER, OVH, PROVIDER_TITLES, AccountRef
from servonaut.services.accounts.fleet import ACCOUNT_KEY, tag_rows
from servonaut.services.accounts.registry import AccountRegistry, UnknownAccountError
from servonaut.utils.instance_resolver import (
    CUSTOM_QUALIFIER,
    AmbiguousInstanceError,
    match_instances,
    resolve_unique,
)

logger = logging.getLogger(__name__)

PROVIDERS = (AWS, HETZNER, OVH)
# Custom servers are listed after AWS and before the other clouds, as in the
# TUI instance list.
_LOOKUP_ORDER = (AWS, CUSTOM_QUALIFIER, OVH, HETZNER)


def build_account_registry(config_manager: Any) -> AccountRegistry:
    """The account registry for a headless surface, from the saved config."""
    return AccountRegistry(config_manager.get(), config_manager=config_manager)


def account_labels(registry: Optional[AccountRegistry]) -> Dict[str, List[str]]:
    """Usable account labels per provider, primary first.

    Labels only: never account ids, profile names or credentials.
    """
    if registry is None:
        return {}
    return {provider: [ref.label for ref in registry.accounts(provider)] for provider in PROVIDERS}


def row_account_key(row: Mapping[str, Any]) -> str:
    """The lower-cased account label a server row is tagged with ("" if none)."""
    return str(row.get(ACCOUNT_KEY) or "").lower()


def unknown_account_error(registry: Optional[AccountRegistry], label: str) -> UnknownAccountError:
    """The error for a label that names no account, listing the ones that exist."""
    known = [ref.label for p in PROVIDERS for ref in (registry.accounts(p) if registry else [])]
    listing = f" Accounts: {', '.join(known)}" if known else ""
    return UnknownAccountError(f"No account named {label!r}.{listing}")


def qualifier_provider(registry: Optional[AccountRegistry], reference: str) -> Optional[str]:
    """The provider an ``<account>/...`` reference is qualified with, if any.

    ``"custom"`` for ``custom/<name>``; None for a bare reference or one
    whose prefix names no account (an OVH Public Cloud id also has a
    ``/`` in it).
    """
    label, sep, rest = (reference or "").strip().partition("/")
    if not (sep and label and rest):
        return None
    if label.lower() == CUSTOM_QUALIFIER:
        return CUSTOM_QUALIFIER
    if registry is None:
        return None
    ref = registry.find_account(label)
    return ref.provider if ref is not None else None


def _rows(value: Any) -> List[dict]:
    """*value* as a list of server rows (anything else reads as no rows)."""
    if not isinstance(value, (list, tuple)):
        return []
    return [row for row in value if isinstance(row, dict)]


# ---------------------------------------------------------------------------
# Cached rows (CLI)
# ---------------------------------------------------------------------------


class CachedFleet:
    """Every account's cached servers plus the custom servers, from disk.

    For one-shot CLI commands: nothing is fetched from a provider API, so a
    command never waits on a slow or failing provider to find a server.
    """

    def __init__(
        self,
        custom_server_service: Any,
        *,
        aws: Any = None,
        ovh: Any = None,
        hetzner: Any = None,
    ) -> None:
        """Args: one inventory per provider (``get_cached_instances()``), None when unused."""
        self._custom = custom_server_service
        self._inventories = {AWS: aws, OVH: ovh, HETZNER: hetzner}

    @classmethod
    def from_registry(cls, registry: AccountRegistry, custom_server_service: Any) -> "CachedFleet":
        return cls(
            custom_server_service,
            aws=registry.fleet(AWS),
            ovh=registry.fleet(OVH),
            hetzner=registry.fleet(HETZNER),
        )

    @classmethod
    def from_config(
        cls, config: Any, custom_server_service: Any, config_manager: Any = None,
    ) -> "CachedFleet":
        registry = AccountRegistry(config, config_manager=config_manager)
        return cls.from_registry(registry, custom_server_service)

    def instances(self) -> List[dict]:
        """AWS, custom, OVH, then Hetzner servers (the instance list's order)."""
        rows: List[dict] = []
        aws = self._inventories[AWS]
        if aws is not None:
            # No try/except: the cache layer already absorbs a missing or
            # corrupt file, so anything raised here is a bug that must
            # surface loudly.
            rows.extend(aws.get_cached_instances())
        try:
            rows.extend(self._custom.list_as_instances())
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not load custom server instances: %s", exc)
        for provider in (OVH, HETZNER):
            inventory = self._inventories[provider]
            if inventory is None:
                continue
            try:
                rows.extend(inventory.get_cached_instances())
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "Could not load %s cached instances: %s", PROVIDER_TITLES[provider], exc,
                )
        return rows

    def matches(self, reference: str) -> List[dict]:
        """Every server *reference* could mean."""
        return match_instances(reference, self.instances())

    def resolve(self, reference: str) -> Optional[dict]:
        """The one server *reference* names, or None.

        Raises:
            AmbiguousInstanceError: The reference names several servers.
        """
        return resolve_unique(reference, self.instances())


# ---------------------------------------------------------------------------
# Live lookups (MCP tools, AI chat tools, relay)
# ---------------------------------------------------------------------------


class InstanceDirectory:
    """Finds servers across every provider account and the custom servers."""

    def __init__(
        self,
        custom_server_service: Any,
        inventories: Callable[[], Mapping[str, Any]],
        accounts: Callable[[], Optional[AccountRegistry]] = lambda: None,
    ) -> None:
        """Build the directory.

        Args:
            custom_server_service: Source of the custom servers.
            inventories: Returns ``{"aws": ..., "ovh": ..., "hetzner": ...}``,
                each an inventory with ``fetch_instances_cached()`` and
                ``get_cached_instances()`` (a provider's account fleet, or its
                single service), None when the provider is unused. Called on
                every lookup, so rebound accounts take effect at once.
            accounts: Returns the account registry (None on surfaces without
                one); it tells which provider an ``<account>/...`` reference
                is qualified with.
        """
        self._custom = custom_server_service
        self._inventories = inventories
        self._accounts = accounts

    def custom_rows(self) -> List[dict]:
        return _rows(self._custom.list_as_instances())

    async def provider_rows(self, provider: str) -> List[dict]:
        """Every account's servers of *provider*, refreshed when stale."""
        if provider == CUSTOM_QUALIFIER:
            return self.custom_rows()
        inventory = self._inventories().get(provider)
        if inventory is None:
            return []
        return _rows(await inventory.fetch_instances_cached())

    def cached_provider_rows(self, provider: str) -> List[dict]:
        """Every account's cached servers of *provider*, without any API call."""
        if provider == CUSTOM_QUALIFIER:
            return self.custom_rows()
        inventory = self._inventories().get(provider)
        if inventory is None:
            return []
        try:
            return _rows(inventory.get_cached_instances())
        except Exception as exc:  # noqa: BLE001 - a broken cache hides no one
            logger.warning("Reading the %s cache failed: %s", provider, exc)
            return []

    async def all_instances(self) -> List[dict]:
        """AWS, custom, OVH, then Hetzner servers, refreshed when stale."""
        rows: List[dict] = []
        for provider in _LOOKUP_ORDER:
            rows.extend(await self.provider_rows(provider))
        return rows

    async def find(self, reference: str) -> Optional[dict]:
        """The server *reference* names, or None (see the resolver's rules).

        A degraded provider must not delay unrelated lookups: an explicit
        ``custom-*`` id resolves locally first, an ``<account>/...``
        reference only consults that account's provider, and once a name
        has matched, the remaining providers are checked in their cached
        rows instead of being fetched.

        Raises:
            AmbiguousInstanceError: The reference names several servers.
        """
        needle = (reference or "").strip()
        if not needle:
            return None
        custom = self.custom_rows()
        if needle.lower().startswith("custom-"):
            match = resolve_unique(needle, custom)
            if match is not None:
                return match

        qualified = qualifier_provider(self._accounts(), needle)
        if qualified == CUSTOM_QUALIFIER:
            return resolve_unique(needle, custom)
        if qualified is not None:
            # Custom servers are local and free to check: one literally named
            # "prod/web-1" must be reported next to account prod's web-1.
            return resolve_unique(needle, await self.provider_rows(qualified) + custom)

        rows: List[dict] = []
        matched = False
        for provider in _LOOKUP_ORDER:
            if provider == CUSTOM_QUALIFIER:
                batch = custom
            elif matched:
                batch = self.cached_provider_rows(provider)
            else:
                batch = await self.provider_rows(provider)
            rows.extend(batch)
            matched = matched or bool(match_instances(needle, batch))
        return resolve_unique(needle, rows)


async def fetch_provider_rows(
    registry: AccountRegistry, provider: str, account: str = "", *,
    force_refresh: bool = False,
) -> List[dict]:
    """Every account's servers of *provider*, or only *account*'s.

    One account's rows are tagged exactly like the fleet's, and only that
    account is read.

    Raises:
        UnknownAccountError: *account* names no account of *provider*, or
            the provider has no usable account.
    """
    fleet = registry.fleet(provider)
    if fleet is None:
        registry.account(provider)  # raises: the provider is not configured
    if not account:
        return await fleet.fetch_instances_cached(force_refresh=force_refresh)
    binding = fleet.binding(registry.account(provider, account).label)
    rows = await binding.service.fetch_instances_cached(force_refresh=force_refresh)
    return tag_rows(rows or [], binding.ref, qualified=fleet.multi)


# ---------------------------------------------------------------------------
# Provider-level calls
# ---------------------------------------------------------------------------


class TargetNotFoundError(LookupError):
    """A server reference no account of a multi-account provider lists.

    With several accounts, acting in the default one would be a guess: the
    server may be in an account whose inventory could not be read.
    """

    def __init__(self, provider: str, reference: str, labels: List[str]):
        self.provider = provider
        self.reference = reference
        self.labels = list(labels)
        title = PROVIDER_TITLES.get(provider, provider)
        super().__init__(
            f"No {title} server {reference!r} in any account ({', '.join(self.labels)})."
        )


@dataclass(frozen=True)
class ProviderTarget:
    """A server named for a provider API call, and the account it is in."""

    account: AccountRef
    # The reference without its account qualifier.
    reference: str
    # The cached row the reference names, when one does.
    row: Optional[dict] = None

    @property
    def native_id(self) -> str:
        """The provider id to call the API with (the row's id when known)."""
        if self.row is not None and self.row.get("id"):
            return str(self.row["id"])
        return self.reference


async def _target_rows(fleet: Any) -> List[dict]:
    """The rows a lifecycle target is looked up in.

    A single account keeps the cached rows, as before. With several
    accounts the inventory is read through its cache (fresh caches as they
    are, missing or stale ones fetched): a cache a mutation invalidated, or
    one never written, must not make a server of that account unknown.
    """
    if fleet is None:
        return []
    if not fleet.multi:
        return _rows(fleet.get_cached_instances())
    try:
        return _rows(await fleet.fetch_instances_cached())
    except Exception as exc:  # noqa: BLE001 - every account failed: use caches
        logger.warning("Refreshing the %s inventory failed: %s", fleet.provider, exc)
        return _rows(fleet.get_cached_instances())


async def resolve_provider_target(
    registry: AccountRegistry,
    provider: str,
    reference: str,
    account: str = "",
) -> ProviderTarget:
    """Which account a start/stop/reboot/delete of *reference* acts in.

    The account is, in order: *account*; the ``<account>/`` qualifier of
    *reference*; the account whose inventory lists the server. An exact id
    always wins before a qualifier is parsed (OVH Public Cloud ids contain
    ``/``). With one account, only cached rows are read and an unlisted
    reference goes to that account, as before; with several, the inventory
    is refreshed where its cache is missing or stale, and a reference no
    account lists is refused rather than sent to the default account.

    Raises:
        UnknownAccountError: *account* or the qualifier names no account of
            *provider*, or they name different accounts.
        AmbiguousInstanceError: The reference matches several servers.
        TargetNotFoundError: Several accounts, none of which lists the
            reference, and none was named.
    """
    title = PROVIDER_TITLES.get(provider, provider)
    wanted = registry.account(provider, account) if account else None
    fleet = registry.fleet(provider)
    every_row = await _target_rows(fleet)

    def in_scope(rows: List[dict]) -> List[dict]:
        if wanted is None:
            return rows
        return [row for row in rows if row_account_key(row) == wanted.key]

    needle = (reference or "").strip()
    lower = needle.lower()
    matches = [r for r in in_scope(every_row) if str(r.get("id") or "").lower() == lower]
    if not matches:
        label, sep, rest = needle.partition("/")
        if sep and label and rest:
            if label.lower() == CUSTOM_QUALIFIER:
                raise UnknownAccountError(
                    f"{needle!r} names a custom server, which has no {title} account"
                )
            ref = registry.find_account(label)
            if ref is not None and ref.provider != provider:
                raise UnknownAccountError(
                    f"{ref.label!r} is a {PROVIDER_TITLES.get(ref.provider, ref.provider)} "
                    f"account, not a {title} account"
                )
            if ref is not None:
                if wanted is not None and wanted.key != ref.key:
                    raise UnknownAccountError(
                        f"{needle!r} is in account {ref.label!r}, not {wanted.label!r}"
                    )
                wanted = ref
                needle, lower = rest, rest.lower()
        scoped = in_scope(every_row)
        matches = [r for r in scoped if str(r.get("id") or "").lower() == lower]
        if not matches:
            matches = [r for r in scoped if str(r.get("name") or "").lower() == lower]

    if len(matches) > 1:
        raise AmbiguousInstanceError(reference, matches)
    row = matches[0] if matches else None
    if wanted is None and row is not None:
        wanted = registry.account(provider, row.get(ACCOUNT_KEY) or None)
    if wanted is None:
        if registry.is_multi(provider):
            raise TargetNotFoundError(
                provider, reference, [ref.label for ref in registry.accounts(provider)],
            )
        wanted = registry.account(provider)
    return ProviderTarget(wanted, needle, row)
