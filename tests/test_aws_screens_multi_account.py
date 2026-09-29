"""AWS account-level screens with two AWS accounts.

Each test builds a real :class:`AccountRegistry` from a config with a
primary account ("prod") and an extra one ("staging"), with every account's
services replaced by recording fakes, and proves the screen talks to the
account it should: the row's own account for server actions, the picked
account for account-level screens. Nothing reaches the network.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional
from unittest.mock import MagicMock

import pytest
from textual.app import App
from textual.widgets import Button, DataTable, Input, Select, Static

from servonaut.config.schema import AppConfig, AWSAccount, IPBanConfig
from servonaut.services.accounts import AccountRegistry
from servonaut.services.accounts.aws_account import AWSAccountContext
from servonaut.services.cloudtrail_service import LookupPage


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

_REGIONS = {"prod": "us-east-1", "staging": "eu-west-1"}


def _row(label: str, number: int, name: str, state: str) -> dict:
    return {
        "id": f"i-{number:017d}", "name": name, "type": "t3.micro", "state": state,
        "public_ip": None, "private_ip": f"10.0.0.{number}",
        "region": _REGIONS[label], "key_name": "",
    }


class FakeEC2:
    """One account's EC2 service: fixed rows, recorded calls."""

    last_fetch_error: Optional[str] = None
    last_fetch_partial = False

    def __init__(self, label: str, rows: List[dict]) -> None:
        self.label = label
        self.rows = rows
        self.calls: List[tuple] = []

    async def fetch_instances_cached(self, force_refresh: bool = False) -> List[dict]:
        self.calls.append(("fetch", force_refresh))
        return [dict(row) for row in self.rows]

    def get_cached_instances(self) -> List[dict]:
        return [dict(row) for row in self.rows]

    def is_cache_fresh(self) -> bool:
        return True

    async def _record(self, name: str, *args: Any, **kwargs: Any) -> dict:
        self.calls.append((name, *args, kwargs) if kwargs else (name, *args))
        return {}

    async def start_instance(self, instance_id: str, region: str) -> dict:
        return await self._record("start_instance", instance_id, region)

    async def stop_instance(self, instance_id: str, region: str) -> dict:
        return await self._record("stop_instance", instance_id, region)

    async def terminate_instance(self, instance_id: str, region: str) -> dict:
        return await self._record("terminate_instance", instance_id, region)

    async def list_regions(self, bootstrap_region: str = "us-east-1") -> List[str]:
        self.calls.append(("list_regions",))
        return [_REGIONS[self.label]]

    async def list_amis(self, region: str, name_filter: str = "") -> List[dict]:
        self.calls.append(("list_amis", region))
        return [{"image_id": f"ami-{self.label}", "name": "base", "architecture": "x86_64",
                 "virtualization_type": "hvm", "creation_date": "2026-01-01"}]

    async def list_instance_types(self, region: str) -> List[dict]:
        self.calls.append(("list_instance_types", region))
        return [{"instance_type": "t3.micro", "vcpus": 2, "memory_mib": 1024}]

    async def list_key_pairs(self, region: str) -> List[dict]:
        self.calls.append(("list_key_pairs", region))
        return [{"key_name": f"{self.label}-key", "key_pair_id": "key-1", "fingerprint": "aa"}]

    async def list_subnets(self, region: str) -> List[dict]:
        self.calls.append(("list_subnets", region))
        return [{"subnet_id": f"subnet-{self.label}", "vpc_id": "vpc-1",
                 "availability_zone": f"{region}a", "cidr_block": "10.0.0.0/24",
                 "available_ip_count": 10}]

    async def list_security_groups(self, region: str) -> List[dict]:
        self.calls.append(("list_security_groups", region))
        return [{"group_id": f"sg-{self.label}", "group_name": "web",
                 "description": "", "vpc_id": "vpc-1"}]

    async def run_instances(self, **kwargs: Any) -> List[dict]:
        self.calls.append(("run_instances", kwargs))
        return [{"id": "i-00000000000000099"}]

    def called(self, name: str) -> List[tuple]:
        return [call for call in self.calls if call[0] == name]


class FakeCloudTrail:
    def __init__(self, label: str) -> None:
        self.label = label
        self.calls: List[dict] = []

    async def lookup_page(self, **kwargs: Any) -> LookupPage:
        self.calls.append(kwargs)
        event = {"event_time": "2026-01-01 00:00:00", "event_name": f"{self.label}-event",
                 "username": f"{self.label}-user", "source_ip": "10.0.0.1",
                 "resource_name": "", "resource_type": "AWS::EC2::Instance",
                 "region": "us-east-1", "error_code": ""}
        return LookupPage(events=[event], next_token=None)


class FakeCloudWatch:
    def __init__(self, label: str) -> None:
        self.label = label
        self.group_calls: List[str] = []
        self.event_calls: List[dict] = []

    async def list_log_groups(self, prefix: str = "", region: str = "") -> List[dict]:
        self.group_calls.append(region)
        return [{"name": f"{self.label}-group"}]

    async def get_log_events(self, **kwargs: Any) -> List[dict]:
        self.event_calls.append(kwargs)
        return [{"timestamp": "2026-01-01 00:00:00", "log_stream": "s",
                 "message": f"{self.label} 10.0.0.1"}]


# ---------------------------------------------------------------------------
# Registry and host
# ---------------------------------------------------------------------------


def _config(*, extra: bool = True) -> AppConfig:
    config = AppConfig()
    config.aws.label = "prod"
    if extra:
        config.aws.accounts = [AWSAccount(label="staging", profile="staging")]
    return config


@pytest.fixture
def ec2(monkeypatch: pytest.MonkeyPatch) -> Dict[str, FakeEC2]:
    """Every AWS account's EC2 service, by account key; never on the network."""
    fakes = {
        "prod": FakeEC2("prod", [_row("prod", 1, "app-1", "running"),
                                  _row("prod", 2, "db-1", "stopped")]),
        "staging": FakeEC2("staging", [_row("staging", 11, "app-1", "stopped"),
                                        _row("staging", 12, "worker-1", "running")]),
    }
    monkeypatch.setattr(
        "servonaut.services.aws_service.AWSService",
        lambda cache, account=None: fakes[account.ref.key],
    )
    # The fleet reads each account's id for display; that is an STS call.
    monkeypatch.setattr(AWSAccountContext, "account_id", lambda self: "")
    return fakes


def _registry(config: Optional[AppConfig] = None) -> AccountRegistry:
    return AccountRegistry(config or _config())


class Host(App):
    """A minimal app with a real account registry."""

    def __init__(self, registry: AccountRegistry, screen: Callable[[], Any]) -> None:
        super().__init__()
        self.accounts = registry
        self.config_manager = MagicMock()
        self.config_manager.get.return_value = registry.config
        self.aws_service = registry.default_service("aws")
        self.aws_audit = MagicMock()
        self.demo_mode = False
        self.redaction_service = None
        self.instances: List[dict] = []
        self.notices: List[tuple] = []
        self._screen_factory = screen

    def provider_inventory(self, provider: str):
        return self.accounts.fleet(provider)

    def notify(self, message, *, severity="information", **kwargs):  # noqa: ANN001
        self.notices.append((severity, str(message)))

    def on_mount(self) -> None:
        self.push_screen(self._screen_factory())


async def _wait_for(pilot, predicate: Callable[[], Any], what: str) -> None:
    for _ in range(500):
        if predicate():
            return
        await pilot.pause(0.01)
    raise AssertionError(f"timed out waiting for {what}")


def _pick_account(screen, picker_id: str, label: str) -> None:
    screen.query_one(f"#{picker_id}_select", Select).value = label


# ---------------------------------------------------------------------------
# Screen account helpers
# ---------------------------------------------------------------------------


def test_helpers_use_the_registry_of_the_app(ec2) -> None:
    from types import SimpleNamespace

    from servonaut.screens import _accounts

    registry = _registry()
    app = SimpleNamespace(accounts=registry, provider_inventory=registry.fleet)
    assert _accounts.account_registry(app) is registry
    assert _accounts.is_multi(app, "aws")
    assert _accounts.default_label(app, "aws") == "prod"
    assert _accounts.provider_inventory(app, "aws") is registry.fleet("aws")
    assert _accounts.aws_service(app) is ec2["prod"]
    assert _accounts.aws_service(app, "staging") is ec2["staging"]
    assert _accounts.row_service(app, "aws", {"account": "staging"}) == (
        ec2["staging"], "staging",
    )
    assert _accounts.cloudtrail_service(app, "staging") is (
        registry.aws_services("staging").cloudtrail
    )
    assert _accounts.cloudwatch_service(app, "staging") is (
        registry.aws_services("staging").cloudwatch
    )
    assert _accounts.aws_context(app, "staging") is registry.aws_context("staging")


def test_helpers_fall_back_to_the_default_services_on_a_stand_in_app() -> None:
    from types import SimpleNamespace

    from servonaut.screens import _accounts

    services = {name: object() for name in (
        "aws_service", "cloudtrail_service", "cloudwatch_service",
        "aws_object_storage_service",
    )}
    for app in (SimpleNamespace(**services), MagicMock(**services)):
        assert _accounts.account_registry(app) is None
        assert not _accounts.is_multi(app, "aws")
        assert _accounts.default_label(app, "aws") == ""
        assert _accounts.provider_inventory(app, "aws") is services["aws_service"]
        assert _accounts.aws_service(app) is services["aws_service"]
        assert _accounts.row_service(app, "aws", {"id": "i-1"}) == (
            services["aws_service"], "",
        )
        assert _accounts.cloudtrail_service(app) is services["cloudtrail_service"]
        assert _accounts.cloudwatch_service(app) is services["cloudwatch_service"]
        assert _accounts.aws_context(app) is None
        assert _accounts.object_storage(app, "aws") is services["aws_object_storage_service"]
