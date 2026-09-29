"""A real AccountRegistry whose provider services are in-memory fakes.

``build_registry`` builds the registry from a real ``AppConfig`` with extra
accounts, but every provider service it constructs is a ``FakeProvider``
holding canned rows and recording the API calls made on it. Nothing talks
to AWS, Hetzner or OVH.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from unittest.mock import MagicMock

from servonaut.config.schema import (
    AppConfig,
    AWSAccount,
    AWSConfig,
    HetznerAccount,
    HetznerConfig,
    OVHAccount,
    OVHConfig,
)
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tools import ServonautTools
from servonaut.services.accounts import AccountRegistry
from servonaut.services.accounts.aws_account import AWSAccountContext

Rows = Sequence[Mapping[str, Any]]


class FakeProvider:
    """One account's provider service: canned rows, recorded API calls."""

    def __init__(self, provider: str, label: str, rows: Rows = (), config: Any = None):
        self.provider = provider
        self.label = label
        self.rows = [dict(r) for r in rows]
        self._config = config
        self.calls: List[Tuple[str, tuple, dict]] = []
        self.fetches = 0
        self.cache_reads = 0
        # The on-disk cache; None when it was never written or was dropped.
        self.cached: Optional[List[dict]] = [dict(r) for r in self.rows]
        # Drop the cache after every API call, as the Hetzner service does
        # after a power action or a delete.
        self.invalidates_cache = False
        self.last_fetch_error: Optional[str] = None
        self.last_fetch_partial = False
        # Return values of recorded API calls, by method name.
        self.returns: Dict[str, Any] = {}

    async def fetch_instances_cached(self, force_refresh: bool = False) -> List[dict]:
        self.fetches += 1
        self.cached = [dict(r) for r in self.rows]
        return [dict(r) for r in self.rows]

    def get_cached_instances(self) -> List[dict]:
        self.cache_reads += 1
        return [dict(r) for r in (self.cached or [])]

    def is_cache_fresh(self) -> bool:
        return True

    def resolve_token(self) -> str:
        return "token"

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)

        async def _call(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            if self.invalidates_cache:
                self.cached = None
            return self.returns.get(name)

        return _call

    def called(self, name: str) -> List[tuple]:
        return [args for method, args, _ in self.calls if method == name]


def _labels(accounts: Optional[Mapping[str, Rows]], default: str) -> List[str]:
    return list(accounts) if accounts else [default]


def build_registry(
    monkeypatch,
    *,
    aws: Optional[Mapping[str, Rows]] = None,
    hetzner: Optional[Mapping[str, Rows]] = None,
    ovh: Optional[Mapping[str, Rows]] = None,
    account_ids: Optional[Mapping[str, str]] = None,
    config: Optional[AppConfig] = None,
) -> Tuple[AccountRegistry, Dict[Tuple[str, str], FakeProvider]]:
    """A registry with the given accounts (label -> rows; first = primary).

    Providers left out: AWS gets only its primary account ``aws`` (no rows);
    Hetzner and OVH are disabled. Returns the registry and the fake service
    of every account, keyed ``(provider, label)``.
    """
    services: Dict[Tuple[str, str], FakeProvider] = {}
    aws = aws or {"aws": []}

    def fake_aws(cache, account=None):
        label = account.ref.label
        service = FakeProvider("aws", label, aws.get(label, ()))
        service.account = account
        services[("aws", label)] = service
        return service

    def fake_hetzner(effective, allow_ambient_token=True):
        label = effective.label or "hetzner"
        service = FakeProvider("hetzner", label, (hetzner or {}).get(label, ()), effective)
        services[("hetzner", label)] = service
        return service

    def fake_ovh(effective, cache_path=None, allow_ambient_config=True):
        label = effective.label or "ovh"
        service = FakeProvider("ovh", label, (ovh or {}).get(label, ()), effective)
        services[("ovh", label)] = service
        return service

    monkeypatch.setattr("servonaut.services.aws_service.AWSService", fake_aws)
    monkeypatch.setattr("servonaut.services.hetzner_service.HetznerService", fake_hetzner)
    monkeypatch.setattr("servonaut.services.ovh_service.OVHService", fake_ovh)
    ids = dict(account_ids or {})
    monkeypatch.setattr(
        AWSAccountContext, "account_id", lambda self: ids.get(self.ref.label, ""),
    )

    config = config or AppConfig()
    aws_labels = _labels(aws, "aws")
    config.aws = AWSConfig(
        label="" if aws_labels[0] == "aws" else aws_labels[0],
        accounts=[AWSAccount(label=l, profile=f"profile-{l}") for l in aws_labels[1:]],
    )
    if hetzner:
        labels = _labels(hetzner, "hetzner")
        config.hetzner = HetznerConfig(
            enabled=True, api_token="primary-token",
            label="" if labels[0] == "hetzner" else labels[0],
            accounts=[HetznerAccount(label=l, api_token=f"token-{l}") for l in labels[1:]],
        )
    if ovh:
        labels = _labels(ovh, "ovh")
        config.ovh = OVHConfig(
            enabled=True, application_key="k", application_secret="s", consumer_key="c",
            label="" if labels[0] == "ovh" else labels[0],
            accounts=[
                OVHAccount(label=l, application_key="k", application_secret="s", consumer_key="c")
                for l in labels[1:]
            ],
        )
    registry = AccountRegistry(config)
    return registry, services


def make_tools(
    registry: AccountRegistry,
    *,
    guard_level: str = GuardLevel.DANGEROUS,
    custom: Iterable[Mapping[str, Any]] = (),
) -> ServonautTools:
    """ServonautTools serving *registry* (audit is a MagicMock)."""
    config = registry.config
    config.mcp.guard_level = guard_level
    config_manager = MagicMock()
    config_manager.get.return_value = config
    custom_service = MagicMock()
    custom_service.list_as_instances.return_value = [dict(r) for r in custom]
    tools = ServonautTools(
        config_manager, registry.default_service("aws"), custom_service,
        MagicMock(), MagicMock(), MagicMock(), MagicMock(),
        CommandGuard(config.mcp, config_manager), MagicMock(),
    )
    tools.bind_accounts(registry)
    return tools


def audit_rows(tools: ServonautTools) -> List[tuple]:
    """``(tool, args, allowed, reason)`` of every audit row written."""
    rows = []
    for call in tools._audit.log.call_args_list:
        args = call.args
        reason = args[4] if len(args) > 4 else call.kwargs.get("reason", "")
        rows.append((args[0], args[1], args[3], reason))
    return rows
