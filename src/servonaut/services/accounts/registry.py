"""The account registry: every provider account and the services behind it.

Single construction point for provider services. The TUI, the MCP server,
the CLI and the relay runner all build one registry from the config and ask
it for:

- ``fleet(provider)``: every account's instances, merged and tagged;
- ``service(provider, account)``: one account's service, for account-level
  work (an account picker, an ``account`` tool argument);
- ``service_for(row)``: the service of the account a server belongs to, for
  anything done to that server (start, stop, snapshots, firewall, ...).

The primary account of each provider is built exactly like before extra
accounts existed, so a config without extra accounts behaves as it always
did.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from servonaut.config.accounts import (
    AWS,
    HETZNER,
    OVH,
    PROVIDER_TITLES,
    AccountRef,
    account_cache_path,
    account_problems,
    aws_accounts,
    describe_account_problems,
    hetzner_accounts,
    ovh_accounts,
    ovh_cache_path,
    primary_label,
)
from servonaut.services.accounts.aws_account import AWSAccountContext
from servonaut.services.accounts.fleet import ACCOUNT_KEY, AccountBinding, AccountFleet

if TYPE_CHECKING:
    from servonaut.config.schema import AppConfig
    from servonaut.services.cache_service import CacheService

logger = logging.getLogger(__name__)

CUSTOM = "custom"
_ROW_FLAGS = (("is_custom", CUSTOM), ("is_ovh", OVH), ("is_hetzner", HETZNER))


class UnknownAccountError(ValueError):
    """An account label that names no usable account of the provider."""


class AccountUnavailableError(UnknownAccountError):
    """An account that is set up but cannot connect.

    The message says why (a token that does not resolve, missing
    credentials); *provider* and *label* name the account.
    """

    def __init__(self, ref: AccountRef, message: str):
        super().__init__(message)
        self.provider = ref.provider
        self.label = ref.label


def row_provider(row: Dict[str, Any]) -> str:
    """``"custom"``, ``"ovh"``, ``"hetzner"`` or ``"aws"`` for an instance row."""
    for flag, provider in _ROW_FLAGS:
        if row.get(flag):
            return provider
    return AWS


@dataclass
class OVHAccountServices:
    """One OVH account's API service and the services that wrap it."""

    ovh: Any
    billing: Any = None
    vps: Any = None
    dedicated: Any = None
    cloud: Any = None
    ip: Any = None
    snapshot: Any = None
    storage: Any = None
    dns: Any = None


@dataclass
class AWSAccountServices:
    """One AWS account's services, all acting with that account's credentials."""

    context: AWSAccountContext
    ec2: Any
    client_factory: Any
    cloudtrail: Any
    cloudwatch: Any
    ssm: Any
    rds: Any
    ingress: Any
    waf: Any


@dataclass
class _ProviderAccounts:
    """Usable accounts of one provider, in config order (primary first)."""

    refs: List[AccountRef] = field(default_factory=list)
    services: Dict[str, Any] = field(default_factory=dict)  # key -> service
    # Effective settings each usable account runs with (key -> settings).
    settings: Dict[str, Any] = field(default_factory=dict)
    # Every account the config sets up (valid label and settings), whether
    # or not it can connect right now.
    configured: List[AccountRef] = field(default_factory=list)


@dataclass
class _RegistryState:
    """Everything built from one config.

    A rebuild builds a whole new state and swaps it in with one assignment,
    and every lookup reads the state once, so a caller on another thread
    never sees half of one config and half of the next.
    """

    config: "AppConfig"
    providers: Dict[str, _ProviderAccounts] = field(default_factory=dict)
    aws_contexts: Dict[str, AWSAccountContext] = field(default_factory=dict)
    # Built on first use, into the state they belong to.
    aws_factories: Dict[str, Any] = field(default_factory=dict)
    object_storage: Dict[str, Any] = field(default_factory=dict)
    aws_bundles: Dict[str, "AWSAccountServices"] = field(default_factory=dict)
    ovh_bundles: Dict[str, OVHAccountServices] = field(default_factory=dict)
    fleets: Dict[str, AccountFleet] = field(default_factory=dict)
    # Why a configured account is not usable: {"hetzner:staging": reason}.
    unavailable: Dict[str, str] = field(default_factory=dict)
    problems: List[str] = field(default_factory=list)

    def provider(self, name: str) -> _ProviderAccounts:
        return self.providers.get(name) or _ProviderAccounts()


class AccountRegistry:
    """Every configured provider account and its services."""

    def __init__(
        self,
        config: "AppConfig",
        *,
        aws_cache_service: Optional["CacheService"] = None,
        config_manager: Optional[Any] = None,
    ) -> None:
        """Build the registry.

        Args:
            config: The loaded application config.
            aws_cache_service: Cache of the primary AWS account. Surfaces that
                already own one (the TUI shares it with other services) pass
                it in; otherwise the registry creates it.
            config_manager: Live config source for services that re-read
                their defaults on every call (CloudTrail). None serves the
                config the registry was last built from.
        """
        self._aws_cache_service = aws_cache_service
        self._config_manager = config_manager
        self._state = _RegistryState(config=config)
        self.rebuild(config)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def rebuild(self, config: "AppConfig") -> None:
        """(Re)build every account from *config* (after settings change).

        The new accounts replace the old ones all at once, and only once
        they are fully built: a failure leaves the previous accounts in use.
        """
        state = _RegistryState(config=config, problems=describe_account_problems(config))
        for message in state.problems:
            logger.warning("Account configuration: %s", message)
        skipped = account_problems(config)
        self._build_aws(state, skipped)
        self._build_hetzner(state, skipped)
        self._build_ovh(state, skipped)
        self._state = state

    def _build_aws(self, state: _RegistryState, skipped) -> None:
        from servonaut.services.aws_service import AWSService
        from servonaut.services.cache_service import CacheService

        config = state.config
        accounts = _ProviderAccounts()
        for index, settings in enumerate(aws_accounts(config)):
            if not settings.ref.primary and (AWS, index - 1) in skipped:
                continue
            ref = settings.ref
            context = AWSAccountContext(ref, settings.profile, settings.regions)
            if ref.primary:
                cache = self._aws_cache_service or CacheService(
                    ttl_seconds=config.cache_ttl_seconds
                )
                self._aws_cache_service = cache
            else:
                cache = CacheService(
                    ttl_seconds=config.cache_ttl_seconds,
                    cache_path=Path(
                        account_cache_path(str(CacheService.CACHE_PATH), ref.key)
                    ),
                )
            state.aws_contexts[ref.key] = context
            accounts.configured.append(ref)
            accounts.refs.append(ref)
            accounts.settings[ref.key] = settings
            accounts.services[ref.key] = AWSService(cache, account=context)
        state.providers[AWS] = accounts

    def _build_hetzner(self, state: _RegistryState, skipped) -> None:
        config = state.config
        accounts = _ProviderAccounts()
        state.providers[HETZNER] = accounts
        if not config.hetzner.enabled:
            return
        from servonaut.services.hetzner_service import (
            HetznerNotConfiguredError,
            HetznerService,
        )

        for index, (ref, effective) in enumerate(hetzner_accounts(config)):
            if not ref.primary and (HETZNER, index - 1) in skipped:
                continue
            accounts.configured.append(ref)
            service = HetznerService(effective, allow_ambient_token=ref.primary)
            try:
                service.resolve_token()
            except HetznerNotConfiguredError as exc:
                _mark_unavailable(state, ref, str(exc))
                continue
            accounts.refs.append(ref)
            accounts.settings[ref.key] = effective
            accounts.services[ref.key] = service

    def _build_ovh(self, state: _RegistryState, skipped) -> None:
        config = state.config
        accounts = _ProviderAccounts()
        state.providers[OVH] = accounts
        if not config.ovh.enabled:
            return
        from servonaut.services.ovh_service import _OVH_CACHE_PATH, OVHService

        for index, (ref, effective) in enumerate(ovh_accounts(config)):
            if not ref.primary and (OVH, index - 1) in skipped:
                continue
            accounts.configured.append(ref)
            # The primary account was only ever built with at least one
            # credential set; keep that rule.
            if ref.primary and not (effective.application_key or effective.client_id):
                _mark_unavailable(state, ref, "no OVH credentials configured")
                continue
            cache = None if ref.primary else Path(ovh_cache_path(str(_OVH_CACHE_PATH), ref))
            accounts.refs.append(ref)
            accounts.settings[ref.key] = effective
            accounts.services[ref.key] = OVHService(
                effective, cache_path=cache, allow_ambient_config=ref.primary,
            )

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    @property
    def config(self) -> "AppConfig":
        return self._state.config

    @property
    def unavailable(self) -> Dict[str, str]:
        """Why configured accounts cannot be used: ``{"hetzner:staging": reason}``."""
        return self._state.unavailable

    @property
    def problems(self) -> List[str]:
        """Configuration problems that made accounts be skipped, as sentences."""
        return self._state.problems

    def accounts(self, provider: str) -> List[AccountRef]:
        """Usable accounts of *provider*, primary first."""
        return list(self._state.provider(provider).refs)

    def configured_accounts(self, provider: str) -> List[AccountRef]:
        """Every account the config sets up for *provider*, usable or not."""
        return list(self._state.provider(provider).configured)

    def unavailable_reason(self, ref: AccountRef) -> Optional[str]:
        """Why a configured account cannot be used, or None when it can."""
        return self._state.unavailable.get(f"{ref.provider}:{ref.key}")

    def is_multi(self, provider: str) -> bool:
        """True when the config sets up more than one account of *provider*.

        Counted on configured accounts, usable or not: with a second account
        configured, every server names its account and every account-level
        view says which account it works on, even while one of the two
        cannot connect.
        """
        return len(self.configured_accounts(provider)) > 1

    def has_multiple_accounts(self) -> bool:
        """True when any provider has more than one configured account."""
        return any(self.is_multi(p) for p in (AWS, HETZNER, OVH))

    def account(self, provider: str, label: Optional[str] = None) -> AccountRef:
        """The account of *provider* named *label* (None = default account).

        The default account is always the primary one. When it cannot be
        used, there is no default: another account must be named, so nothing
        ever runs in an account the caller did not choose.

        Raises:
            UnknownAccountError: No usable account has that label (the
                message says why when the account is configured but cannot
                connect), the provider has no usable account at all, or no
                label was given and the primary account cannot be used.
        """
        return _account(self._state, provider, label)

    def find_account(
        self, label: str, *, include_unavailable: bool = False
    ) -> Optional[AccountRef]:
        """The account named *label* in any provider (labels are unique).

        Only usable accounts are found unless *include_unavailable* is set;
        then a configured account that cannot connect is returned too, so a
        caller can report why (``account(ref.provider, ref.label)`` raises
        with the reason) instead of treating ``label/...`` as a plain name.
        """
        wanted = (label or "").strip().lower()
        if not wanted:
            return None
        state = self._state
        for provider in (AWS, HETZNER, OVH):
            accounts = state.provider(provider)
            refs = accounts.configured if include_unavailable else accounts.refs
            for ref in refs:
                if ref.key == wanted:
                    return ref
        return None

    def settings(self, provider: str, account: Optional[str] = None) -> Any:
        """The effective settings one account runs with.

        ``HetznerConfig`` / ``OVHConfig`` with the account's own credentials,
        SSH defaults and projects on top of the provider-wide values; for AWS
        the account's profile and regions.
        """
        state = self._state
        ref = _account(state, provider, account)
        return state.providers[provider].settings[ref.key]

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    def service(self, provider: str, account: Optional[str] = None) -> Any:
        """One account's provider service (None label = default account)."""
        state = self._state
        ref = _account(state, provider, account)
        return state.providers[provider].services[ref.key]

    def default_service(self, provider: str) -> Any:
        """The primary account's service, or None when it cannot be used.

        Never another account's service: code without an account context
        must not act in an account nobody chose.
        """
        accounts = self._state.provider(provider)
        if not accounts.refs or not accounts.refs[0].primary:
            return None
        return accounts.services[accounts.refs[0].key]

    def service_for(self, row: Dict[str, Any]) -> Any:
        """The service of the account a server row belongs to.

        Rows without an account tag (older caches, rows built before the
        registry tagged them) belong to the provider's default account.

        Raises:
            UnknownAccountError: The row names an account that no longer
                exists (removed from settings since the row was listed).
            ValueError: The row is a custom server (no provider API).
        """
        provider = row_provider(row)
        if provider == CUSTOM:
            raise ValueError("Custom servers have no provider account")
        return self.service(provider, row.get(ACCOUNT_KEY) or None)

    def account_for(self, row: Dict[str, Any]) -> AccountRef:
        """The account a server row belongs to (see :meth:`service_for`)."""
        provider = row_provider(row)
        if provider == CUSTOM:
            raise ValueError("Custom servers have no provider account")
        return self.account(provider, row.get(ACCOUNT_KEY) or None)

    def aws_context(self, account: Optional[str] = None) -> AWSAccountContext:
        """Credentials of one AWS account (None label = default account)."""
        state = self._state
        ref = _account(state, AWS, account)
        return state.aws_contexts[ref.key]

    def aws_client_factory(self, account: Optional[str] = None) -> Any:
        """Control-plane client factory of one AWS account (None = default).

        Roles configured for control-plane reads and writes apply on top of
        the account's own credentials.
        """
        return _aws_client_factory(self._state, _account(self._state, AWS, account))

    def aws_services(self, account: Optional[str] = None) -> AWSAccountServices:
        """One AWS account's services (None label = default account)."""
        from servonaut.services.cloudtrail_service import CloudTrailService
        from servonaut.services.cloudwatch_service import CloudWatchService
        from servonaut.services.ingress_path_service import IngressPathService
        from servonaut.services.rds_metrics_service import RDSMetricsService
        from servonaut.services.ssm_service import SSMService
        from servonaut.services.waf_management_service import WAFManagementService

        state = self._state
        ref = _account(state, AWS, account)
        bundle = state.aws_bundles.get(ref.key)
        if bundle is not None:
            return bundle
        context = state.aws_contexts[ref.key]
        factory = _aws_client_factory(state, ref)
        bundle = AWSAccountServices(
            context=context,
            ec2=state.providers[AWS].services[ref.key],
            client_factory=factory,
            cloudtrail=CloudTrailService(self._live_config_source(), context),
            cloudwatch=CloudWatchService(client_factory=factory),
            ssm=SSMService(context),
            rds=RDSMetricsService(context),
            ingress=IngressPathService(context),
            waf=WAFManagementService(context),
        )
        state.aws_bundles[ref.key] = bundle
        return bundle

    def _live_config_source(self) -> Any:
        if self._config_manager is not None:
            return self._config_manager
        registry = self

        class _Snapshot:
            def get(self):
                return registry.config

        return _Snapshot()

    def object_storage(self, provider: str, account: Optional[str] = None) -> Any:
        """One account's object storage service, or None when not configured.

        Object storage is a product of its own: a Hetzner project or OVH
        account can have S3 keys without any usable compute credentials, so
        the keys are read from the account's config entry directly. AWS
        accounts sign with their own credentials unless S3 keys are set for
        the primary account (extra AWS accounts have no S3 settings).

        Raises:
            UnknownAccountError: No account of *provider* has that label.
        """
        from servonaut.services.object_storage_factory import (
            build_aws_object_storage,
            build_keyed_object_storage,
        )

        state = self._state
        key, storage, context = _object_storage_source(state, provider, account)
        cache_key = f"{provider}:{key}"
        if cache_key in state.object_storage:
            return state.object_storage[cache_key]
        if provider == AWS:
            service = build_aws_object_storage(
                storage, state.config.aws.default_region, context
            )
        else:
            service = build_keyed_object_storage(provider, storage)
        state.object_storage[cache_key] = service
        return service

    def aws_account_for_id(self, account_id: str) -> Optional[AccountRef]:
        """The configured AWS account whose 12-digit id is *account_id*.

        Blocking (may call STS once per account); call from a worker thread.
        """
        wanted = (account_id or "").strip()
        if not wanted:
            return None
        state = self._state
        for ref in state.provider(AWS).refs:
            if state.aws_contexts[ref.key].account_id() == wanted:
                return ref
        return None

    def ovh_services(self, account: Optional[str] = None) -> OVHAccountServices:
        """One OVH account's API service plus the services wrapping it."""
        state = self._state
        ref = _account(state, OVH, account)
        bundle = state.ovh_bundles.get(ref.key)
        if bundle is None:
            bundle = _build_ovh_bundle(state.providers[OVH].services[ref.key])
            state.ovh_bundles[ref.key] = bundle
        return bundle

    def fleet(self, provider: str) -> Optional[AccountFleet]:
        """Every account of *provider* as one inventory; None when unused."""
        state = self._state
        fleet = state.fleets.get(provider)
        if fleet is not None:
            return fleet
        accounts = state.provider(provider)
        if not accounts.refs:
            return None
        bindings = []
        for ref in accounts.refs:
            account_id = None
            if provider == AWS:
                account_id = state.aws_contexts[ref.key].account_id
            bindings.append(AccountBinding(ref, accounts.services[ref.key], account_id))
        unavailable = {
            ref.label: state.unavailable.get(f"{ref.provider}:{ref.key}") or "not available"
            for ref in accounts.configured
            if ref.key not in accounts.services
        }
        fleet = AccountFleet(
            provider, bindings, qualified=len(accounts.configured) > 1,
            unavailable=unavailable,
        )
        state.fleets[provider] = fleet
        return fleet


# ---------------------------------------------------------------------------
# State lookups (each reads one state, never two)
# ---------------------------------------------------------------------------


def _mark_unavailable(state: _RegistryState, ref: AccountRef, reason: str) -> None:
    state.unavailable[f"{ref.provider}:{ref.key}"] = reason
    logger.info("%s is not available: %s", ref.title, reason)


def _account(state: _RegistryState, provider: str, label: Optional[str]) -> AccountRef:
    """See :meth:`AccountRegistry.account`."""
    title = PROVIDER_TITLES.get(provider, provider)
    accounts = state.provider(provider)
    refs = accounts.refs
    if not label:
        if refs and refs[0].primary:
            return refs[0]
        if not refs:
            raise _no_usable_account(state, provider)
        primary = next((ref for ref in accounts.configured if ref.primary), None)
        if primary is None:  # every provider block is its primary account
            raise UnknownAccountError(f"{title} has no primary account")
        reason = _unavailable_reason(state, primary)
        raise AccountUnavailableError(
            primary,
            f"The primary {title} account {primary.label!r} is not available"
            f"{': ' + reason if reason else ''}. "
            f"Name the account to use: {', '.join(r.label for r in refs)}",
        )
    wanted = label.strip().lower()
    for ref in refs:
        if ref.key == wanted:
            return ref
    for ref in accounts.configured:
        if ref.key == wanted:
            reason = _unavailable_reason(state, ref) or "cannot connect"
            raise AccountUnavailableError(
                ref, f"{title} account {ref.label!r} is not available: {reason}"
            )
    if not refs:
        raise _no_usable_account(state, provider)
    raise UnknownAccountError(
        f"No {title} account named {label!r}. Accounts: {', '.join(r.label for r in refs)}"
    )


def _unavailable_reason(state: _RegistryState, ref: AccountRef) -> str:
    """Why *ref* cannot connect, without a closing period (it is embedded)."""
    return (state.unavailable.get(f"{ref.provider}:{ref.key}") or "").strip().rstrip(".")


def _no_usable_account(state: _RegistryState, provider: str) -> UnknownAccountError:
    """The error for a provider none of whose accounts can be used.

    A configured provider says why each account cannot connect, so a single
    account keeps its setup hint (for Hetzner: where the token is read from).
    """
    title = PROVIDER_TITLES.get(provider, provider)
    configured = state.provider(provider).configured
    if not configured:
        return UnknownAccountError(f"{title} is not configured")
    if len(configured) == 1:
        reason = _unavailable_reason(state, configured[0]) or "cannot connect"
        return UnknownAccountError(f"{title} is not available: {reason}")
    reasons = "; ".join(
        f"{ref.label}: {_unavailable_reason(state, ref) or 'cannot connect'}" for ref in configured
    )
    return UnknownAccountError(f"No {title} account is available ({reasons})")


def _aws_client_factory(state: _RegistryState, ref: AccountRef) -> Any:
    from servonaut.services.aws_client_factory import AWSClientFactory

    factory = state.aws_factories.get(ref.key)
    if factory is None:
        factory = AWSClientFactory(state.config.aws, state.aws_contexts[ref.key])
        state.aws_factories[ref.key] = factory
    return factory


def _object_storage_source(state: _RegistryState, provider: str, account: Optional[str]):
    """(cache key, ObjectStorageConfig, AWS context or None) for an account."""
    config = state.config
    if provider == AWS:
        ref = _account(state, AWS, account)
        storage = config.aws.object_storage if ref.primary else _empty_storage()
        return ref.key, storage, state.aws_contexts[ref.key]
    if provider not in (HETZNER, OVH):
        raise UnknownAccountError(f"No object storage for provider {provider!r}")
    block = config.hetzner if provider == HETZNER else config.ovh
    primary = primary_label(provider, config)
    wanted = (account or "").strip().lower()
    if not wanted or wanted == primary.lower():
        return primary.lower(), block.object_storage, None
    for entry in block.accounts:
        if (entry.label or "").strip().lower() == wanted:
            return wanted, entry.object_storage, None
    known = ", ".join([primary] + [e.label for e in block.accounts if e.label])
    raise UnknownAccountError(
        f"No {PROVIDER_TITLES[provider]} account named {account!r}. Accounts: {known}"
    )


def _empty_storage():
    from servonaut.config.schema import ObjectStorageConfig

    return ObjectStorageConfig()


def _build_ovh_bundle(ovh_service: Any) -> OVHAccountServices:
    from servonaut.services.ovh_billing_service import OVHBillingService
    from servonaut.services.ovh_cloud_service import OVHCloudService
    from servonaut.services.ovh_dedicated_service import OVHDedicatedService
    from servonaut.services.ovh_dns_service import OVHDNSService
    from servonaut.services.ovh_ip_service import OVHIPService
    from servonaut.services.ovh_snapshot_service import OVHSnapshotService
    from servonaut.services.ovh_storage_service import OVHStorageService
    from servonaut.services.ovh_vps_service import OVHVPSService

    return OVHAccountServices(
        ovh=ovh_service,
        billing=OVHBillingService(ovh_service),
        vps=OVHVPSService(ovh_service),
        dedicated=OVHDedicatedService(ovh_service),
        cloud=OVHCloudService(ovh_service),
        ip=OVHIPService(ovh_service),
        snapshot=OVHSnapshotService(ovh_service),
        storage=OVHStorageService(ovh_service),
        dns=OVHDNSService(ovh_service),
    )
