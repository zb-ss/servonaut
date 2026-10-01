"""Provider accounts for the surfaces without an instance list.

The MCP tools, the AI chat tools, the relay runner and the CLI commands read
servers and resolve server references through here, so each of them sees
every account of every provider and applies the same reference rules as the
TUI (see :mod:`servonaut.utils.instance_resolver`).

- :class:`CachedFleet` reads every account's cached servers from disk, for
  one-shot CLI commands that must not wait on a provider API; only an
  account that was never listed on this machine is read, once.
- :class:`InstanceDirectory` finds a server for a tool call, refreshing
  provider inventories only while nothing has matched yet.
- :func:`resolve_provider_target` tells which account a provider-level call
  (start, stop, reboot, delete) acts in.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from servonaut.config.accounts import AWS, HETZNER, OVH, PROVIDER_TITLES, AccountRef
from servonaut.services.accounts.fleet import ACCOUNT_KEY, AccountFleet, tag_rows
from servonaut.services.accounts.registry import (
    AccountRegistry,
    AccountUnavailableError,
    UnknownAccountError,
)
from servonaut.utils.instance_resolver import (
    CUSTOM_QUALIFIER,
    AmbiguousInstanceError,
    match_instances,
    resolve_unique,
)

logger = logging.getLogger(__name__)

PROVIDERS = (AWS, HETZNER, OVH)
# Seconds a CLI lookup allows, past its listing budget, for the listings to
# be cancelled and their outcome written (a safety net; it is normally
# instant).
_WIND_DOWN_SECONDS = 2.0
# What a CLI note calls one account of each provider (default "account").
_ACCOUNT_NOUNS = {HETZNER: "project"}
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


def usable_providers(registry: Optional[AccountRegistry]) -> List[str]:
    """The providers a relay advertises, sorted.

    A provider counts with at least one usable account, or with object
    storage of its own: a project can have S3 keys and no usable compute
    credentials. The TUI and the headless relay both answer through here.
    """
    if registry is None:
        return []
    return sorted(
        provider for provider in PROVIDERS
        if registry.accounts(provider) or _has_object_storage(registry, provider)
    )


def _has_object_storage(registry: AccountRegistry, provider: str) -> bool:
    try:
        return registry.object_storage(provider) is not None
    except UnknownAccountError:
        return False


def row_account_key(row: Mapping[str, Any]) -> str:
    """The lower-cased account label a server row is tagged with ("" if none)."""
    return str(row.get(ACCOUNT_KEY) or "").lower()


def unknown_account_error(registry: Optional[AccountRegistry], label: str) -> UnknownAccountError:
    """The error for a label that names no account, listing the ones that exist."""
    known = [ref.label for p in PROVIDERS for ref in (registry.accounts(p) if registry else [])]
    listing = f" Accounts: {', '.join(known)}" if known else ""
    return UnknownAccountError(f"No account named {label!r}.{listing}")


def qualifier_account(
    registry: Optional[AccountRegistry], reference: str,
) -> Optional[AccountRef]:
    """The account an ``<account>/...`` reference is qualified with, if any.

    Includes an account that cannot connect, so the caller can say why
    (:func:`usable_account`) instead of reading the reference as a name.
    None for a bare reference, ``custom/...``, or a prefix that names no
    account (an OVH Public Cloud id also has a ``/`` in it).
    """
    label, sep, rest = (reference or "").strip().partition("/")
    if not (sep and label and rest) or registry is None:
        return None
    if label.lower() == CUSTOM_QUALIFIER:
        return None
    return registry.find_account(label, include_unavailable=True)


def usable_account(registry: AccountRegistry, ref: AccountRef) -> AccountRef:
    """*ref* when it can connect.

    Raises:
        AccountUnavailableError: It cannot; the registry says why.
    """
    return registry.account(ref.provider, ref.label)


def check_qualifier(registry: Optional[AccountRegistry], reference: str) -> None:
    """Refuse a reference qualified with an account that cannot connect.

    Raises:
        AccountUnavailableError: The ``<account>/`` prefix names such an
            account. Its servers are not listed, so the reference would
            otherwise match nothing, or only a custom server of that name.
    """
    ref = qualifier_account(registry, reference)
    if ref is not None:
        usable_account(registry, ref)


def check_configured_reference(config: Any, reference: str) -> None:
    """:func:`check_qualifier` for a CLI command that holds only the config.

    Nothing is built for a reference without an ``<account>/`` prefix.

    Raises:
        AccountUnavailableError: See :func:`check_qualifier`.
    """
    if "/" in (reference or ""):
        check_qualifier(AccountRegistry(config), reference)


def qualifier_provider(registry: Optional[AccountRegistry], reference: str) -> Optional[str]:
    """The provider an ``<account>/...`` reference is qualified with, if any.

    ``"custom"`` for ``custom/<name>``; None for a bare reference or one
    whose prefix names no account (an OVH Public Cloud id also has a
    ``/`` in it). An account that cannot connect counts: see
    :func:`check_qualifier`.
    """
    label, sep, rest = (reference or "").strip().partition("/")
    if sep and label and rest and label.lower() == CUSTOM_QUALIFIER:
        return CUSTOM_QUALIFIER
    ref = qualifier_account(registry, reference)
    return ref.provider if ref is not None else None


def with_ovh_login(row: dict, config: Any) -> dict:
    """*row*, and for an OVH server a copy carrying its account's login.

    The CLI reads ``username`` and ``ssh_key`` from the row, as custom and
    Hetzner rows carry them. An OVH server takes both from the account it
    belongs to, the same way the TUI and the MCP tools connect to it. A
    username already on the row is kept.
    """
    if not row.get("is_ovh"):
        return row
    from servonaut.services.connection_service import ConnectionService

    login = ConnectionService.for_config(config).resolve_ovh_connection(row)
    enriched = dict(row)
    enriched["username"] = row.get("username") or login["username"]
    if login["key_path"] and not row.get("ssh_key"):
        enriched["ssh_key"] = login["key_path"]
    return enriched


def _rows(value: Any) -> List[dict]:
    """*value* as a list of server rows (anything else reads as no rows)."""
    if not isinstance(value, (list, tuple)):
        return []
    return [row for row in value if isinstance(row, dict)]


# ---------------------------------------------------------------------------
# Cached rows (CLI)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CheckedRows:
    """The rows a CLI command resolves a reference against, and its notes."""

    rows: List[dict]
    # One line per account whose servers could not be checked, and why.
    notes: List[str]


class CachedFleet:
    """Every account's cached servers plus the custom servers, from disk.

    For one-shot CLI commands: a command does not wait on a slow or failing
    provider to find a server. :meth:`checked_rows` reads an account only
    when it was never listed on this machine.
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
        self._registry: Optional[AccountRegistry] = None

    @classmethod
    def from_registry(cls, registry: AccountRegistry, custom_server_service: Any) -> "CachedFleet":
        fleet = cls(
            custom_server_service,
            aws=registry.fleet(AWS),
            ovh=registry.fleet(OVH),
            hetzner=registry.fleet(HETZNER),
        )
        fleet._registry = registry
        return fleet

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

    def matches(self, reference: str, rows: Optional[List[dict]] = None) -> List[dict]:
        """Every server *reference* could mean, among *rows* (default: :meth:`instances`).

        Raises:
            AccountUnavailableError: See :func:`check_qualifier`.
        """
        check_qualifier(self._registry, reference)
        return match_instances(reference, self.instances() if rows is None else rows)

    def resolve(self, reference: str, rows: Optional[List[dict]] = None) -> Optional[dict]:
        """The one server *reference* names among *rows* (default: :meth:`instances`).

        Raises:
            AmbiguousInstanceError: The reference names several servers.
            AccountUnavailableError: See :func:`check_qualifier`.
        """
        check_qualifier(self._registry, reference)
        return resolve_unique(reference, self.instances() if rows is None else rows)

    async def checked_rows(self, reference: str) -> CheckedRows:
        """The rows to resolve *reference* against in a CLI command.

        The cached rows (:meth:`instances`), plus the servers of every
        account that was never listed on this machine (it has no cache at
        all; a single account of its provider as much as one of several),
        read once through its normal cached fetch. That writes its cache, so
        later commands stay offline, and a name no longer passes as unique
        because another server of that name was never listed. A listing too
        incomplete to be saved as the cache is remembered for the cache's
        TTL instead, its servers counting as checked; a failed one for
        ``account_retry_seconds`` (see :mod:`.listing_record`). The account
        is not read again meanwhile. The listings run together, within
        ``account_check_timeout_seconds``.

        Nothing is read for an id a cached row has or a ``custom/...``
        reference; ``<account>/...`` reads only that account. Nor is an
        account nothing is set up for on this machine (AWS without
        credentials, checked offline); it gets a note only when the
        reference points at it (``<account>/...`` or an EC2 instance id).
        An account that cannot be read, or cannot connect, never breaks the
        command: it gets a note that its servers were not checked.
        """
        rows = self.instances()
        needle = (reference or "").strip()
        if not needle or _names_cached_id(needle, rows) or _is_custom_reference(needle):
            return CheckedRows(rows, [])
        only = qualifier_account(self._registry, needle)
        notes: List[str] = []
        listings: List[Tuple[Any, bool]] = []
        for provider in PROVIDERS:
            inventory = self._inventories[provider]
            for binding in _never_listed(inventory, only):
                if _has_credentials(binding.service):
                    listings.append((binding, inventory.multi))
                elif only is not None or _names_instance_id(provider, needle):
                    notes.append(_not_checked(
                        binding.ref, "has no credentials on this machine", needle,
                    ))
        fetched: List[dict] = []
        for read, note in await _checked_listings(
            listings, needle, self._check_seconds(), self._retry_seconds(),
        ):
            fetched.extend(read)
            if note:
                notes.append(note)
        if fetched:
            # The reads wrote their caches: list again, in the instance list's
            # order, so candidates show the same way on every run. Rows a read
            # did not keep (an incomplete listing) come last.
            rows = self.instances()
            known = {_row_key(row) for row in rows}
            rows.extend(row for row in fetched if _row_key(row) not in known)
        if only is None:
            notes.extend(self._unavailable_notes(needle))
        return CheckedRows(rows, notes)

    def _check_seconds(self) -> float:
        """How long the never-listed accounts may take in all (config)."""
        return _seconds_setting(self._registry, "account_check_timeout_seconds")

    def _retry_seconds(self) -> float:
        """How long a failed listing is left alone before it is tried again (config)."""
        return _seconds_setting(self._registry, "account_retry_seconds")

    def _unavailable_notes(self, reference: str) -> List[str]:
        """A note for every configured account that cannot connect."""
        registry = self._registry
        if registry is None:
            return []
        notes = []
        for provider in PROVIDERS:
            for ref in registry.configured_accounts(provider):
                reason = registry.unavailable_reason(ref)
                if reason:
                    reason = reason.strip().rstrip(".")
                    notes.append(_not_checked(ref, f"is not available ({reason})", reference))
        return notes


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
        # The last read of each account that had no cached servers, by
        # (provider, account key): see checked_provider_rows.
        self._account_reads: Dict[Tuple[str, str], _AccountRead] = {}

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

    async def _rows_or_cache(self, provider: str) -> List[dict]:
        """:meth:`provider_rows`, or the cached rows when the provider fails.

        A lookup must not fail because one provider cannot be reached: the
        server asked for may well be another provider's.
        """
        try:
            return await self.provider_rows(provider)
        except Exception as exc:  # noqa: BLE001 - an unreachable provider hides no one
            logger.warning(
                "Refreshing the %s inventory failed: %s",
                PROVIDER_TITLES.get(provider, provider), exc,
            )
            return self.cached_provider_rows(provider)

    async def checked_provider_rows(self, provider: str) -> List[dict]:
        """*provider*'s servers for telling whether a name is unique.

        Cached rows, without an API call. With several accounts, an account
        with no cached servers at all (typically it was never listed) is
        read, so a server of it cannot be missed; a single account keeps its
        cached rows only, as before accounts existed. The read is shared by
        the lookups that follow: a successful one while that account's cache
        is fresh (an account without servers is not asked again on every
        lookup), a failed one for a short while before it is retried. An
        account that cannot be read is logged and counts as having no
        servers: it never breaks the lookup of another provider's server. A
        stale cache is used as it is.
        """
        rows = self.cached_provider_rows(provider)
        inventory = self._inventories().get(provider)
        if inventory is None:
            return rows
        self._forget_reads(provider, inventory)
        known = {str(row.get("id") or "") for row in rows}
        for binding in _unlisted_accounts(inventory, rows):
            for row in await self._read(provider, inventory, binding):
                row_id = str(row.get("id") or "")
                if not row_id or row_id not in known:
                    rows.append(row)
                    known.add(row_id)
        return rows

    def _retry_seconds(self) -> float:
        """The configured wait before a failed account read is retried."""
        from servonaut.config.schema import AppConfig

        config = getattr(self._accounts(), "config", None)
        value = getattr(config, "account_retry_seconds", AppConfig.account_retry_seconds)
        return max(0.0, float(value))

    def _forget_reads(self, provider: str, inventory: Any) -> None:
        """Drop reads made for accounts that were rebuilt since."""
        for slot, read in list(self._account_reads.items()):
            if slot[0] == provider and read.inventory is not inventory:
                del self._account_reads[slot]

    async def _read(self, provider: str, inventory: Any, binding: Any) -> List[dict]:
        """One account's servers from a read that concurrent lookups share.

        A failed read counts as no servers; it is logged once.
        """
        slot = (provider, binding.ref.key)
        read = self._account_reads.get(slot)
        if read is None or not read.answers_for(inventory):
            future = asyncio.ensure_future(_read_account(binding, inventory.multi))
            read = _AccountRead(inventory, binding, future, self._retry_seconds())
            future.add_done_callback(partial(_read_done, provider, read))
            self._account_reads[slot] = read
        try:
            # Shielded: a cancelled lookup must not cancel a read others share.
            return await asyncio.shield(read.future)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - logged by _read_done
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
        rows instead of being fetched. With several accounts, an account
        with no cached servers at all is still read (see
        :meth:`checked_provider_rows`): a name must never pass as unique
        because another server of that name was never listed.

        Raises:
            AmbiguousInstanceError: The reference names several servers.
            AccountUnavailableError: It is qualified with an account that
                cannot connect (see :func:`check_qualifier`).
        """
        needle = (reference or "").strip()
        if not needle:
            return None
        custom = self.custom_rows()
        if needle.lower().startswith("custom-"):
            match = resolve_unique(needle, custom)
            if match is not None:
                return match

        registry = self._accounts()
        qualified = qualifier_provider(registry, needle)
        if qualified == CUSTOM_QUALIFIER:
            return resolve_unique(needle, custom)
        if qualified is not None:
            check_qualifier(registry, needle)
            # Custom servers are local and free to check: one literally named
            # "prod/web-1" must be reported next to account prod's web-1.
            return resolve_unique(needle, await self._rows_or_cache(qualified) + custom)

        rows: List[dict] = []
        matched = False
        for provider in _LOOKUP_ORDER:
            if provider == CUSTOM_QUALIFIER:
                batch = custom
            elif matched:
                batch = await self.checked_provider_rows(provider)
            else:
                batch = await self._rows_or_cache(provider)
            rows.extend(batch)
            matched = matched or bool(match_instances(needle, batch))
        return resolve_unique(needle, rows)


@dataclass
class _AccountRead:
    """A read of one account that had no cached servers."""

    # The fleet it was made for: rebuilding the accounts makes a new one.
    inventory: Any
    binding: Any
    future: asyncio.Future
    # How long a failed read is reused before the account is asked again
    # (config ``account_retry_seconds``), so an unreachable provider slows
    # at most one lookup per window.
    retry_seconds: float
    # Monotonic time after which a failed read is retried.
    retry_at: float = 0.0

    def answers_for(self, inventory: Any) -> bool:
        """Whether this read still stands for the account in *inventory*.

        A read in flight does; a successful one while the account's cache
        is fresh; a failed one until its retry time.
        """
        if self.inventory is not inventory or self.future.cancelled():
            return False
        if not self.future.done():
            return True
        if self.future.exception() is not None:
            return time.monotonic() < self.retry_at
        return _cache_fresh(self.binding.service)


def _cache_fresh(service: Any) -> bool:
    check = getattr(service, "is_cache_fresh", None)
    if check is None:
        return False
    try:
        return bool(check())
    except Exception:  # noqa: BLE001 - an unreadable cache is not fresh
        return False


def _unlisted_accounts(inventory: Any, rows: List[dict]) -> List[Any]:
    """The bindings of *inventory*'s accounts that have no cached rows.

    Only a provider with several accounts is read this way: one account's
    servers are looked up in its cache alone, as they always were.
    """
    if not isinstance(inventory, AccountFleet) or not inventory.multi:
        return []
    listed = {row_account_key(row) for row in rows}
    return [binding for binding in inventory.bindings if binding.ref.key not in listed]


async def _read_account(binding: Any, qualified: bool) -> List[dict]:
    """One account's servers, tagged as its fleet tags them."""
    fetched = await binding.service.fetch_instances_cached()
    return tag_rows(_rows(fetched), binding.ref, qualified=qualified)


def _names_cached_id(reference: str, rows: List[dict]) -> bool:
    """True when *reference* is the exact id of a cached row (ids always win)."""
    wanted = reference.lower()
    return any(str(row.get("id") or "").lower() == wanted for row in rows)


def _is_custom_reference(reference: str) -> bool:
    label, sep, rest = reference.partition("/")
    return bool(sep and rest) and label.lower() == CUSTOM_QUALIFIER


def _row_key(row: Mapping[str, Any]) -> Tuple[str, str]:
    """A row's provider and id: ids are unique within one provider."""
    if row.get("is_custom"):
        provider = CUSTOM_QUALIFIER
    elif row.get("is_ovh"):
        provider = OVH
    elif row.get("is_hetzner"):
        provider = HETZNER
    else:
        provider = AWS
    return provider, str(row.get("id") or "")


def _never_listed(inventory: Any, only: Optional[AccountRef]) -> List[Any]:
    """*inventory*'s accounts with no cache at all (of *only* alone, if set)."""
    if not isinstance(inventory, AccountFleet):
        return []
    return [
        binding for binding in inventory.bindings
        if (only is None or (binding.ref.provider, binding.ref.key) == (only.provider, only.key))
        and not _has_cache(binding.service)
    ]


def _has_cache(service: Any) -> bool:
    """Whether *service*'s account was listed here; True when it cannot tell (read nothing).

    The cache layer absorbs a missing or corrupt file (that counts as never
    listed), so anything raised here is a bug that must surface.
    """
    check = getattr(service, "has_cached_instances", None)
    return not callable(check) or bool(check())


def _has_credentials(service: Any) -> bool:
    """False for an account nothing is set up for here (AWS without credentials).

    It holds no server this machine could connect to, so there is nothing to
    check, and reading it would only fail on every command. The check is
    offline (see ``AWSService.has_credentials``).
    """
    check = getattr(service, "has_credentials", None)
    return not callable(check) or bool(check())


def _names_instance_id(provider: str, reference: str) -> bool:
    """Whether *reference* is an id of *provider*'s shape (EC2 ids only)."""
    if provider != AWS:
        return False
    from servonaut.services.aws_service import is_instance_id

    return is_instance_id(reference)


class _DaemonExecutor(ThreadPoolExecutor):
    """Runs each call in a daemon thread of its own; never waits for one.

    asyncio takes only a ThreadPoolExecutor as a loop's default executor, so
    this one is of that type, but :meth:`submit` starts a daemon thread
    instead of a pool worker (pool workers are joined when the interpreter
    exits) and :meth:`shutdown` returns at once. A call that is abandoned
    therefore never holds up the command.
    """

    def submit(self, fn, /, *args, **kwargs):  # noqa: D102 - see the class
        future: Future = Future()

        def run() -> None:
            if not future.set_running_or_notify_cancel():
                return
            try:
                result = fn(*args, **kwargs)
            except BaseException as exc:  # noqa: BLE001 - handed to the waiter
                future.set_exception(exc)
            else:
                future.set_result(result)

        threading.Thread(target=run, name="servonaut-listing", daemon=True).start()
        return future

    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
        return None


async def _checked_listings(
    listings: List[Tuple[Any, bool]], reference: str, seconds: float, retry_seconds: float,
) -> List[Tuple[List[dict], Optional[str]]]:
    """:func:`_checked_listing` of every ``(binding, qualified)``, together, in *seconds*.

    The listings run on an event loop of their own, in a daemon thread, whose
    blocking calls (the provider SDKs) run in daemon threads too: a listing
    abandoned when the time is up keeps no thread the command waits for,
    either now or when the process exits.
    """
    if not listings:
        return []
    if seconds <= 0:
        # No time allowed at all (config): list nothing.
        return [
            ([], _not_checked(binding.ref, "was not listed (no time allowed)", reference))
            for binding, _ in listings
        ]
    done: Future = Future()

    def run() -> None:
        loop = asyncio.new_event_loop()
        loop.set_default_executor(_DaemonExecutor())
        try:
            done.set_result(loop.run_until_complete(
                _listings_within(listings, reference, seconds, retry_seconds),
            ))
        except BaseException as exc:  # noqa: BLE001 - handed to the waiter
            done.set_exception(exc)
        finally:
            loop.close()

    threading.Thread(target=run, name="servonaut-listings", daemon=True).start()
    try:
        # The listings end themselves after *seconds*; the margin covers
        # cancelling them and writing what was learned.
        return await asyncio.wait_for(asyncio.wrap_future(done), seconds + _WIND_DOWN_SECONDS)
    except asyncio.TimeoutError:
        return [
            ([], _not_checked(binding.ref, f"could not be listed (timed out after {seconds:g} s)",
                              reference))
            for binding, _ in listings
        ]


async def _listings_within(
    listings: List[Tuple[Any, bool]], reference: str, seconds: float, retry_seconds: float,
) -> List[Tuple[List[dict], Optional[str]]]:
    """The listings of :func:`_checked_listings`, on its own loop.

    Each account's listing starts requests only in the first half of
    *seconds* and gives each one the second half to answer (the services'
    ``limit_listing_time``), so what it listed by then comes back as a
    partial listing. A listing still running when the time is up is
    abandoned: its account gets a note, and the timeout is remembered like
    any failure: the next commands do not wait for it again until
    *retry_seconds* have passed.
    """
    from servonaut.services.accounts.listing_record import TIMEOUT

    request_seconds = seconds / 2
    for binding, _ in listings:
        limit = getattr(binding.service, "limit_listing_time", None)
        if callable(limit):
            limit(request_seconds, seconds - request_seconds)
    tasks = [
        asyncio.ensure_future(_checked_listing(binding, qualified, reference, retry_seconds))
        for binding, qualified in listings
    ]
    _, pending = await asyncio.wait(tasks, timeout=seconds)
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    results = []
    for task, (binding, _) in zip(tasks, listings):
        if task in pending:
            detail = f"timed out after {seconds:g} s"
            record = _listing_record(binding.service)
            if record is not None:
                record.save(TIMEOUT, detail, [], keep_seconds=retry_seconds)
            results.append(([], _not_checked(
                binding.ref, f"could not be listed ({detail})", reference,
            )))
        else:
            results.append(task.result())
    return results


async def _checked_listing(
    binding: Any, qualified: bool, reference: str, retry_seconds: float,
) -> Tuple[List[dict], Optional[str]]:
    """A never-listed account's servers for a lookup, and the note to print, if any.

    A complete listing writes the account's cache. Otherwise the outcome is
    remembered, for as long as it takes to change:
    - partial (the listing ended early or skipped a part; it says what it
      listed): the cache's TTL, its servers counting as checked;
    - timeout (no answer: a request timed out or could not connect): the
      config's ``account_retry_seconds``, *retry_seconds*, as a network
      blip heals quickly;
    - failed (an error response: credentials, permissions, a credential
      helper or SSO, a missing profile): the cache's TTL, as these do not
      heal on their own, and trying sooner would run a prompting credential
      helper again and again.
    """
    from servonaut.services.accounts.listing_record import FAILED, PARTIAL, TIMEOUT

    record = _listing_record(binding.service)
    remembered = record.load() if record is not None else None
    if remembered is not None:
        if remembered.outcome == PARTIAL:
            return remembered.rows, None
        when = f"at {_clock(remembered.at)}, tried again after {_clock(remembered.until)}"
        return [], _not_checked(
            binding.ref, f"could not be listed ({remembered.detail}; {when})", reference,
        )
    rows, problem, error = await _read_never_listed(binding, qualified)
    if not problem:
        return rows, None
    if error is None:
        if record is not None and not _has_cache(binding.service):
            record.save(PARTIAL, problem, rows)
        return rows, _not_checked(
            binding.ref, f"was only partly listed ({problem})", reference, some=True,
        )
    if _is_no_answer(error):
        outcome, detail, keep = TIMEOUT, f"no answer: {problem}", retry_seconds
    else:
        outcome, detail, keep = FAILED, problem, None
    if record is not None:
        record.save(outcome, detail, [], keep_seconds=keep)
    return [], _not_checked(binding.ref, f"could not be listed ({detail})", reference)


def _is_no_answer(error: BaseException) -> bool:
    """Whether *error*, or one it was raised from, is a timeout or a failed connection.

    Then nothing answered, and a little later something may. Anything else
    is an error response (or a local one, like a missing profile).
    """
    types = _no_answer_types()
    seen = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        if isinstance(error, types):
            return True
        error = error.__cause__ or error.__context__
    return False


def _no_answer_types() -> Tuple[type, ...]:
    """Timeout and connection errors of Python and of the provider SDKs' HTTP layers."""
    types: List[type] = [TimeoutError, ConnectionError]
    try:
        import requests

        types += [requests.exceptions.Timeout, requests.exceptions.ConnectionError]
    except ImportError:
        pass
    try:
        import botocore.exceptions as botocore_errors

        # ConnectTimeoutError and EndpointConnectionError are ConnectionErrors.
        types += [botocore_errors.ConnectionError, botocore_errors.ReadTimeoutError,
                  botocore_errors.ConnectionClosedError]
    except ImportError:
        pass
    return tuple(types)


def _listing_record(service: Any) -> Any:
    """The service's ``ListingRecord``, or None when it keeps none."""
    get = getattr(service, "listing_record", None)
    return get() if callable(get) else None


def _clock(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).strftime("%H:%M:%S")


def _seconds_setting(registry: Optional[AccountRegistry], name: str) -> float:
    """The config's *name* in seconds (never negative); its default when not a number."""
    from servonaut.config.schema import AppConfig

    default = getattr(AppConfig, name)
    value = getattr(getattr(registry, "config", None), name, default)
    try:
        if isinstance(value, bool):
            raise TypeError(value)
        return max(0.0, float(value))
    except (TypeError, ValueError):
        logger.warning("Config %s is not a number (%r); using %s", name, value, default)
        return float(default)


async def _read_never_listed(
    binding: Any, qualified: bool,
) -> Tuple[List[dict], str, Optional[BaseException]]:
    """An account's servers, why they may be incomplete ("" when they are not),
    and the error behind a failed listing (None for a partial one).

    The reason is one line, so each note stays one line on stderr.
    """
    try:
        rows = await _read_account(binding, qualified)
    except Exception as exc:  # noqa: BLE001 - one account never breaks a command
        return [], _first_line(str(exc)) or type(exc).__name__, exc
    problem = getattr(binding.service, "last_fetch_error", None)
    if not isinstance(problem, str) or not problem.strip():
        return rows, "", None
    error = getattr(binding.service, "last_fetch_exception", None)
    return rows, _first_line(problem), error if isinstance(error, BaseException) else None


def _first_line(text: str) -> str:
    """The first non-empty line of *text*, stripped (a helper's stderr may follow)."""
    return next((line.strip() for line in text.splitlines() if line.strip()), "")


def _not_checked(ref: AccountRef, what: str, reference: str, *, some: bool = False) -> str:
    """``Note: Hetzner project 'staging' could not be listed (...); its servers ...``."""
    noun = _ACCOUNT_NOUNS.get(ref.provider, "account")
    title = PROVIDER_TITLES.get(ref.provider, ref.provider)
    servers = "some of its servers" if some else "its servers"
    return f"Note: {title} {noun} {ref.label!r} {what}; {servers} were not checked for {reference!r}"


def _read_done(provider: str, read: _AccountRead, future: asyncio.Future) -> None:
    if future.cancelled() or future.exception() is None:
        return
    read.retry_at = time.monotonic() + read.retry_seconds
    title = PROVIDER_TITLES.get(provider, provider)
    logger.warning(
        "Listing %s account %r failed; its servers are left out of name "
        "lookups for now: %s", title, read.binding.ref.label, future.exception(),
    )


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


async def _target_rows(fleet: Any, owner: Optional[AccountRef] = None) -> List[dict]:
    """The rows a lifecycle target is looked up in.

    A single account keeps the cached rows, as before. With several
    accounts the inventory is read through its cache (fresh caches as they
    are, missing or stale ones fetched): a cache a mutation invalidated, or
    one never written, must not make a server of that account unknown. When
    the call already names its account (*owner*), only that account is
    read; the others keep their cached rows.
    """
    if fleet is None:
        return []
    if not fleet.multi:
        return _rows(fleet.get_cached_instances())
    if owner is not None:
        return await _owner_rows(fleet, owner)
    try:
        return _rows(await fleet.fetch_instances_cached())
    except Exception as exc:  # noqa: BLE001 - every account failed: use caches
        logger.warning("Refreshing the %s inventory failed: %s", fleet.provider, exc)
        return _rows(fleet.get_cached_instances())


async def _owner_rows(fleet: Any, owner: AccountRef) -> List[dict]:
    """*owner*'s servers read through its cache, the other accounts' cached."""
    cached = _rows(fleet.get_cached_instances())
    others = [row for row in cached if row_account_key(row) != owner.key]
    binding = fleet.binding(owner.label)
    if binding is None:  # configured, but it cannot connect
        return cached
    try:
        own = await _read_account(binding, fleet.multi)
    except Exception as exc:  # noqa: BLE001 - its cached rows still count
        logger.warning("Refreshing %s failed: %s", owner.title, exc)
        return cached
    return others + own


def _qualifier_account(
    registry: AccountRegistry, provider: str, reference: str,
) -> Optional[AccountRef]:
    """The *provider* account an ``<account>/...`` reference names, if any."""
    ref = qualifier_account(registry, reference)
    return ref if ref is not None and ref.provider == provider else None


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
    is refreshed where its cache is missing or stale (only the named
    account's when *account* or a qualifier names one), and a reference no
    account lists is refused rather than sent to the default account.

    Raises:
        UnknownAccountError: *account* or the qualifier names no account of
            *provider*, or they name different accounts; an
            :class:`AccountUnavailableError` when the qualifier names one
            that cannot connect.
        AmbiguousInstanceError: The reference matches several servers.
        TargetNotFoundError: Several accounts, none of which lists the
            reference, and none was named.
    """
    title = PROVIDER_TITLES.get(provider, provider)
    wanted = registry.account(provider, account) if account else None
    fleet = registry.fleet(provider)
    # A bare name or id with several accounts refreshes every account: which
    # one lists the server is exactly what is being asked.
    every_row = await _target_rows(
        fleet, wanted or _qualifier_account(registry, provider, reference),
    )

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
            ref = registry.find_account(label, include_unavailable=True)
            if ref is not None and ref.provider != provider:
                raise UnknownAccountError(
                    f"{ref.label!r} is a {PROVIDER_TITLES.get(ref.provider, ref.provider)} "
                    f"account, not a {title} account"
                )
            if ref is not None:
                ref = usable_account(registry, ref)
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
