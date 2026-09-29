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
        self._providers: Dict[str, _ProviderAccounts] = {}
        self._aws_contexts: Dict[str, AWSAccountContext] = {}
        self._aws_factories: Dict[str, Any] = {}
        self._object_storage: Dict[str, Any] = {}
        self._aws_bundles: Dict[str, AWSAccountServices] = {}
        self._ovh_bundles: Dict[str, OVHAccountServices] = {}
        self._fleets: Dict[str, AccountFleet] = {}
        # Why a configured account is not usable: {"hetzner:staging": reason}.
        self.unavailable: Dict[str, str] = {}
        self.problems: List[str] = []
        self.rebuild(config)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def rebuild(self, config: "AppConfig") -> None:
        """(Re)build every account from *config* (after settings change)."""
        self._config = config
        self._providers = {}
        self._aws_contexts = {}
        self._aws_factories = {}
        self._object_storage = {}
        self._aws_bundles = {}
        self._ovh_bundles = {}
        self._fleets = {}
        self.unavailable = {}
        self.problems = describe_account_problems(config)
        for message in self.problems:
            logger.warning("Account configuration: %s", message)
        skipped = account_problems(config)
        self._build_aws(config, skipped)
        self._build_hetzner(config, skipped)
        self._build_ovh(config, skipped)

    def _build_aws(self, config: "AppConfig", skipped) -> None:
        from servonaut.services.aws_service import AWSService
        from servonaut.services.cache_service import CacheService

        accounts = _ProviderAccounts()
        for index, settings in enumerate(aws_accounts(config.aws)):
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
            self._aws_contexts[ref.key] = context
            accounts.refs.append(ref)
            accounts.services[ref.key] = AWSService(cache, account=context)
        self._providers[AWS] = accounts

    def _build_hetzner(self, config: "AppConfig", skipped) -> None:
        accounts = _ProviderAccounts()
        if not config.hetzner.enabled:
            self._providers[HETZNER] = accounts
            return
        try:
            from servonaut.services.hetzner_service import (
                HetznerNotConfiguredError,
                HetznerService,
            )
        except ImportError as exc:  # pragma: no cover - module is pure python
            logger.warning("Hetzner provider unavailable: %s", exc)
            self._providers[HETZNER] = accounts
            return
        for index, (ref, effective) in enumerate(hetzner_accounts(config.hetzner)):
            if not ref.primary and (HETZNER, index - 1) in skipped:
                continue
            service = HetznerService(effective, allow_ambient_token=ref.primary)
            try:
                service.resolve_token()
            except HetznerNotConfiguredError as exc:
                self._mark_unavailable(ref, str(exc))
                continue
            accounts.refs.append(ref)
            accounts.services[ref.key] = service
        self._providers[HETZNER] = accounts

    def _build_ovh(self, config: "AppConfig", skipped) -> None:
        accounts = _ProviderAccounts()
        if not config.ovh.enabled:
            self._providers[OVH] = accounts
            return
        from servonaut.services.ovh_service import _OVH_CACHE_PATH, OVHService

        for index, (ref, effective) in enumerate(ovh_accounts(config.ovh)):
            if ref.primary:
                # The primary account was only ever built with at least one
                # credential set; keep that rule.
                if not (effective.application_key or effective.client_id):
                    self._mark_unavailable(ref, "no OVH credentials configured")
                    continue
            elif (OVH, index - 1) in skipped:
                continue
            cache = None if ref.primary else Path(ovh_cache_path(str(_OVH_CACHE_PATH), ref))
            accounts.refs.append(ref)
            accounts.services[ref.key] = OVHService(effective, cache_path=cache)
        self._providers[OVH] = accounts

    def _mark_unavailable(self, ref: AccountRef, reason: str) -> None:
        self.unavailable[f"{ref.provider}:{ref.key}"] = reason
        logger.info("%s is not available: %s", ref.title, reason)

    # ------------------------------------------------------------------
    # Accounts
    # ------------------------------------------------------------------

    @property
    def config(self) -> "AppConfig":
        return self._config

    def accounts(self, provider: str) -> List[AccountRef]:
        """Usable accounts of *provider*, primary first."""
        return list(self._providers.get(provider, _ProviderAccounts()).refs)

    def is_multi(self, provider: str) -> bool:
        """True when *provider* has more than one usable account."""
        return len(self.accounts(provider)) > 1

    def has_multiple_accounts(self) -> bool:
        """True when any provider has more than one usable account."""
        return any(self.is_multi(p) for p in (AWS, HETZNER, OVH))

    def account(self, provider: str, label: Optional[str] = None) -> AccountRef:
        """The account of *provider* named *label* (None = default account).

        Raises:
            UnknownAccountError: No usable account has that label, or the
                provider has no usable account at all.
        """
        refs = self.accounts(provider)
        if not refs:
            raise UnknownAccountError(
                f"{PROVIDER_TITLES.get(provider, provider)} is not configured"
            )
        if not label:
            return refs[0]
        wanted = label.strip().lower()
        for ref in refs:
            if ref.key == wanted:
                return ref
        known = ", ".join(r.label for r in refs)
        raise UnknownAccountError(
            f"No {PROVIDER_TITLES.get(provider, provider)} account named "
            f"{label!r}. Accounts: {known}"
        )

    def find_account(self, label: str) -> Optional[AccountRef]:
        """The account named *label* in any provider (labels are unique)."""
        wanted = (label or "").strip().lower()
        if not wanted:
            return None
        for provider in (AWS, HETZNER, OVH):
            for ref in self.accounts(provider):
                if ref.key == wanted:
                    return ref
        return None

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    def service(self, provider: str, account: Optional[str] = None) -> Any:
        """One account's provider service (None label = default account)."""
        ref = self.account(provider, account)
        return self._providers[provider].services[ref.key]

    def default_service(self, provider: str) -> Any:
        """The default account's service, or None when the provider has none."""
        refs = self.accounts(provider)
        if not refs:
            return None
        return self._providers[provider].services[refs[0].key]

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
        ref = self.account(AWS, account)
        return self._aws_contexts[ref.key]

    def aws_client_factory(self, account: Optional[str] = None) -> Any:
        """Control-plane client factory of one AWS account (None = default).

        Roles configured for control-plane reads and writes apply on top of
        the account's own credentials.
        """
        from servonaut.services.aws_client_factory import AWSClientFactory

        ref = self.account(AWS, account)
        factory = self._aws_factories.get(ref.key)
        if factory is None:
            factory = AWSClientFactory(self._config.aws, self._aws_contexts[ref.key])
            self._aws_factories[ref.key] = factory
        return factory

    def aws_services(self, account: Optional[str] = None) -> AWSAccountServices:
        """One AWS account's services (None label = default account)."""
        from servonaut.services.cloudtrail_service import CloudTrailService
        from servonaut.services.cloudwatch_service import CloudWatchService
        from servonaut.services.ingress_path_service import IngressPathService
        from servonaut.services.rds_metrics_service import RDSMetricsService
        from servonaut.services.ssm_service import SSMService
        from servonaut.services.waf_management_service import WAFManagementService

        ref = self.account(AWS, account)
        bundle = self._aws_bundles.get(ref.key)
        if bundle is not None:
            return bundle
        context = self._aws_contexts[ref.key]
        factory = self.aws_client_factory(ref.label)
        bundle = AWSAccountServices(
            context=context,
            ec2=self._providers[AWS].services[ref.key],
            client_factory=factory,
            cloudtrail=CloudTrailService(self._live_config_source(), context),
            cloudwatch=CloudWatchService(client_factory=factory),
            ssm=SSMService(context),
            rds=RDSMetricsService(context),
            ingress=IngressPathService(context),
            waf=WAFManagementService(context),
        )
        self._aws_bundles[ref.key] = bundle
        return bundle

    def _live_config_source(self) -> Any:
        if self._config_manager is not None:
            return self._config_manager
        registry = self

        class _Snapshot:
            def get(self):
                return registry._config

        return _Snapshot()

    def object_storage(self, provider: str, account: Optional[str] = None) -> Any:
        """One account's object storage service, or None when not configured.

        AWS accounts sign with their own credentials unless S3 keys are set
        for the primary account. A Hetzner project or OVH account needs its
        own S3 keys (object storage is a separate product with its own
        credentials); an extra account without them has no object storage.

        Raises:
            UnknownAccountError: No usable account of *provider* has that label.
        """
        from servonaut.services.object_storage_factory import (
            build_aws_object_storage,
            build_keyed_object_storage,
        )

        ref = self.account(provider, account)
        cache_key = f"{provider}:{ref.key}"
        if cache_key in self._object_storage:
            return self._object_storage[cache_key]
        config = self._config
        if provider == AWS:
            # Only the primary account has S3 settings of its own; extra
            # accounts use their profile and the provider default region.
            storage = config.aws.object_storage if ref.primary else _empty_storage()
            service = build_aws_object_storage(
                storage, config.aws.default_region, self._aws_contexts[ref.key]
            )
        elif provider == HETZNER:
            service = build_keyed_object_storage(
                HETZNER, self._providers[HETZNER].services[ref.key]._config.object_storage
            )
        elif provider == OVH:
            service = build_keyed_object_storage(
                OVH, self._providers[OVH].services[ref.key]._config.object_storage
            )
        else:
            raise UnknownAccountError(f"No object storage for provider {provider!r}")
        self._object_storage[cache_key] = service
        return service

    def aws_account_for_id(self, account_id: str) -> Optional[AccountRef]:
        """The configured AWS account whose 12-digit id is *account_id*.

        Blocking (may call STS once per account); call from a worker thread.
        """
        wanted = (account_id or "").strip()
        if not wanted:
            return None
        for ref in self.accounts(AWS):
            if self._aws_contexts[ref.key].account_id() == wanted:
                return ref
        return None

    def ovh_services(self, account: Optional[str] = None) -> OVHAccountServices:
        """One OVH account's API service plus the services wrapping it."""
        ref = self.account(OVH, account)
        bundle = self._ovh_bundles.get(ref.key)
        if bundle is None:
            bundle = _build_ovh_bundle(self._providers[OVH].services[ref.key])
            self._ovh_bundles[ref.key] = bundle
        return bundle

    def fleet(self, provider: str) -> Optional[AccountFleet]:
        """Every account of *provider* as one inventory; None when unused."""
        fleet = self._fleets.get(provider)
        if fleet is not None:
            return fleet
        refs = self.accounts(provider)
        if not refs:
            return None
        services = self._providers[provider].services
        bindings = []
        for ref in refs:
            account_id = None
            if provider == AWS:
                account_id = self._aws_contexts[ref.key].account_id
            bindings.append(AccountBinding(ref, services[ref.key], account_id))
        fleet = AccountFleet(provider, bindings)
        self._fleets[provider] = fleet
        return fleet


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
