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
# AWS manager
# ---------------------------------------------------------------------------


def _names(table: DataTable) -> List[str]:
    return [str(table.get_row_at(i)[1]) for i in range(table.row_count)]


@pytest.mark.asyncio
async def test_manager_lists_every_account_with_qualified_names(ec2) -> None:
    from servonaut.screens.aws_manager import AWSManagerScreen

    app = Host(_registry(), AWSManagerScreen)
    async with app.run_test() as pilot:
        table = app.screen.query_one("#aws_mgr_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 4, "both accounts' rows")
        assert _names(table) == [
            "prod/app-1", "prod/db-1", "staging/app-1", "staging/worker-1",
        ]


@pytest.mark.asyncio
async def test_manager_says_which_account_failed_to_refresh(ec2) -> None:
    from servonaut.screens.aws_manager import AWSManagerScreen

    ec2["staging"].last_fetch_error = "could not list AWS regions: denied"
    app = Host(_registry(), AWSManagerScreen)
    async with app.run_test() as pilot:
        table = app.screen.query_one("#aws_mgr_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 4, "both accounts' rows")
        status = str(app.screen.query_one("#aws_mgr_status", Static).render())
    assert "4 instances." in status
    assert "Refresh incomplete: staging: could not list AWS regions: denied" in status


@pytest.mark.asyncio
async def test_manager_single_account_keeps_plain_names(ec2) -> None:
    from servonaut.screens.aws_manager import AWSManagerScreen

    app = Host(_registry(_config(extra=False)), AWSManagerScreen)
    async with app.run_test() as pilot:
        table = app.screen.query_one("#aws_mgr_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 2, "the rows")
        assert _names(table) == ["app-1", "db-1"]
        status = str(app.screen.query_one("#aws_mgr_status", Static).render())
        assert status.strip() == "2 instances."


@pytest.mark.asyncio
async def test_manager_starts_in_the_rows_account_and_refreshes_all(ec2) -> None:
    from servonaut.screens.aws_manager import AWSManagerScreen

    app = Host(_registry(), AWSManagerScreen)
    async with app.run_test() as pilot:
        screen = app.screen
        table = screen.query_one("#aws_mgr_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 4, "both accounts' rows")
        table.move_cursor(row=2)  # staging/app-1, stopped
        await pilot.pause()
        screen.action_start()
        await _wait_for(pilot, lambda: ec2["staging"].called("start_instance"), "the start")

        assert ec2["staging"].called("start_instance") == [
            ("start_instance", "i-00000000000000011", "eu-west-1")
        ]
        assert not ec2["prod"].called("start_instance")
        details = app.aws_audit.log_action.call_args.kwargs["details"]
        assert details == {"region": "eu-west-1", "account": "staging"}
        # The refresh after the action reads every account, not just staging.
        await _wait_for(pilot, lambda: len(ec2["prod"].called("fetch")) == 2, "the refresh")
        await _wait_for(pilot, lambda: table.row_count == 4, "both accounts again")


@pytest.mark.asyncio
async def test_manager_stops_in_the_rows_account_after_confirming(ec2) -> None:
    from servonaut.screens.aws_manager import AWSManagerScreen

    app = Host(_registry(), AWSManagerScreen)
    async with app.run_test() as pilot:
        screen = app.screen
        table = screen.query_one("#aws_mgr_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 4, "both accounts' rows")
        table.move_cursor(row=3)  # staging/worker-1, running
        await pilot.pause()
        screen.action_stop()
        await _wait_for(
            pilot, lambda: type(app.screen).__name__ == "PowerActionConfirmModal", "the prompt"
        )
        assert "staging/worker-1" in str(app.screen.message)
        app.screen.query_one("#btn_power_confirm_yes", Button).press()
        await _wait_for(pilot, lambda: ec2["staging"].called("stop_instance"), "the stop")
        assert not ec2["prod"].called("stop_instance")


@pytest.mark.asyncio
async def test_manager_terminates_in_the_rows_account(ec2) -> None:
    from unittest.mock import AsyncMock

    from servonaut.screens.aws_manager import AWSManagerScreen

    app = Host(_registry(), AWSManagerScreen)
    async with app.run_test() as pilot:
        screen = app.screen
        table = screen.query_one("#aws_mgr_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 4, "both accounts' rows")
        app.push_screen_wait = AsyncMock(return_value=True)
        await screen._do_terminate(screen._instances[3])

        assert ec2["staging"].called("terminate_instance") == [
            ("terminate_instance", "i-00000000000000012", "eu-west-1")
        ]
        assert not ec2["prod"].called("terminate_instance")
        details = app.aws_audit.log_action.call_args.kwargs["details"]
        assert details["account"] == "staging"
        assert details["name"] == "staging/worker-1"


@pytest.mark.asyncio
async def test_manager_refuses_a_row_whose_account_was_removed(ec2) -> None:
    from servonaut.screens.aws_manager import AWSManagerScreen

    app = Host(_registry(), AWSManagerScreen)
    async with app.run_test() as pilot:
        screen = app.screen
        table = screen.query_one("#aws_mgr_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 4, "both accounts' rows")
        app.accounts.rebuild(_config(extra=False))  # staging removed in Settings
        table.move_cursor(row=2)
        await pilot.pause()
        screen.action_start()
        await pilot.pause()

        assert not ec2["staging"].called("start_instance")
        assert not ec2["prod"].called("start_instance")
        assert any("staging" in text for severity, text in app.notices if severity == "error")


# ---------------------------------------------------------------------------
# AWS create
# ---------------------------------------------------------------------------


async def _wait_for_create_tables(pilot, screen) -> None:
    await _wait_for(
        pilot,
        lambda: screen.query_one("#aws_sg_table", DataTable).row_count == 1
        and screen.query_one("#aws_amis_table", DataTable).row_count == 1,
        "the region's tables",
    )


@pytest.mark.asyncio
async def test_create_loads_and_launches_in_the_picked_account(ec2) -> None:
    from unittest.mock import AsyncMock

    from servonaut.screens.aws_create import AWSCreateScreen

    app = Host(_registry(), AWSCreateScreen)
    async with app.run_test(size=(160, 80)) as pilot:
        screen = app.screen
        picker = screen.query_one("#aws_create_account")
        assert picker.display is True
        await _wait_for_create_tables(pilot, screen)
        assert {region for _name, region in ec2["prod"].called("list_amis")} == {"us-east-1"}
        assert not ec2["staging"].calls

        _pick_account(screen, "aws_create_account", "staging")
        await _wait_for(pilot, lambda: ec2["staging"].called("list_security_groups"), "reload")
        await _wait_for_create_tables(pilot, screen)
        assert screen._regions == ["eu-west-1"]
        assert screen._amis[0]["image_id"] == "ami-staging"
        assert screen._key_pairs[0]["key_name"] == "staging-key"

        screen.query_one("#aws_input_name", Input).value = "web-9"
        app.push_screen_wait = AsyncMock(return_value=True)
        prod_fetches = len(ec2["prod"].called("fetch"))
        await screen._on_create()

    (launch,) = ec2["staging"].called("run_instances")
    assert launch[1]["region"] == "eu-west-1"
    assert launch[1]["subnet_id"] == "subnet-staging"
    assert launch[1]["security_group_ids"] == ["sg-staging"]
    assert not ec2["prod"].called("run_instances")
    assert app.aws_audit.log_action.call_args.kwargs["details"]["account"] == "staging"
    # The fleet is refreshed across accounts, so both accounts stay listed.
    assert len(ec2["prod"].called("fetch")) == prod_fetches + 1
    assert {row.get("account") for row in app.instances} == {"prod", "staging"}


@pytest.mark.asyncio
async def test_create_hides_the_picker_with_one_account(ec2) -> None:
    from servonaut.screens.aws_create import AWSCreateScreen

    app = Host(_registry(_config(extra=False)), AWSCreateScreen)
    async with app.run_test(size=(160, 80)) as pilot:
        screen = app.screen
        await _wait_for_create_tables(pilot, screen)
        assert screen.query_one("#aws_create_account").display is False
        assert screen.query_one("#aws_create_account_select", Select).disabled


# ---------------------------------------------------------------------------
# CloudTrail
# ---------------------------------------------------------------------------


def _bundle_fakes(registry: AccountRegistry, attr: str, factory) -> Dict[str, Any]:
    fakes = {}
    for ref in registry.accounts("aws"):
        fakes[ref.key] = factory(ref.key)
        setattr(registry.aws_services(ref.label), attr, fakes[ref.key])
    return fakes


@pytest.mark.asyncio
async def test_cloudtrail_reads_the_picked_accounts_trail(ec2) -> None:
    from servonaut.screens.cloudtrail_browser import CloudTrailBrowserScreen

    registry = _registry()
    trails = _bundle_fakes(registry, "cloudtrail", FakeCloudTrail)
    app = Host(registry, CloudTrailBrowserScreen)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        screen.action_fetch()
        await _wait_for(pilot, lambda: screen._events, "prod events")
        assert screen._events[0]["event_name"] == "prod-event"
        assert not trails["staging"].calls

        _pick_account(screen, "ct_filter_account", "staging")
        await _wait_for(pilot, lambda: trails["staging"].calls, "the staging fetch")
        await _wait_for(
            pilot, lambda: screen._events and screen._events[0]["event_name"] == "staging-event",
            "staging events",
        )
        assert len(trails["prod"].calls) == 1
        users = [value for _label, value in screen.query_one("#ct_select_username", Select)._options]
        assert "prod-user" not in users


# ---------------------------------------------------------------------------
# CloudWatch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cloudwatch_reads_the_picked_accounts_logs(ec2) -> None:
    from servonaut.screens.cloudwatch_browser import CloudWatchBrowserScreen

    registry = _registry()
    logs = _bundle_fakes(registry, "cloudwatch", FakeCloudWatch)
    app = Host(registry, CloudWatchBrowserScreen)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        assert screen.query_one("#cloudwatch_filter_bar").has_class("-with-account")
        screen.query_one("#cw_select_region", Select).value = "us-east-1"
        groups = screen.query_one("#cw_select_log_group", Select)
        await _wait_for(pilot, lambda: groups.prompt == "Select log group", "prod groups")
        groups.value = "prod-group"
        await pilot.pause()
        screen.action_fetch()
        await _wait_for(pilot, lambda: screen._events, "prod events")

        _pick_account(screen, "cw_filter_account", "staging")
        await _wait_for(pilot, lambda: logs["staging"].group_calls, "staging groups")
        assert logs["staging"].group_calls == ["us-east-1"]
        assert screen._events == [] and screen._top_ips == []
        await _wait_for(pilot, lambda: groups.prompt == "Select log group", "staging groups")
        groups.value = "staging-group"
        await pilot.pause()
        screen.action_fetch()
        await _wait_for(pilot, lambda: logs["staging"].event_calls, "staging events")
        assert logs["staging"].event_calls[0]["log_group"] == "staging-group"
        assert len(logs["prod"].event_calls) == 1


@pytest.mark.asyncio
async def test_cloudwatch_single_account_has_no_account_column(ec2) -> None:
    from servonaut.screens.cloudwatch_browser import CloudWatchBrowserScreen

    app = Host(_registry(_config(extra=False)), CloudWatchBrowserScreen)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        assert not screen.query_one("#cloudwatch_filter_bar").has_class("-with-account")
        assert screen.query_one("#cw_filter_account").display is False


# ---------------------------------------------------------------------------
# IP ban screen
# ---------------------------------------------------------------------------


def _ban_config() -> AppConfig:
    config = _config()
    config.ip_ban_configs = [
        IPBanConfig(name="edge", method="waf", region="us-east-1",
                    ip_set_id="set-1", ip_set_name="block"),
        IPBanConfig(name="edge-staging", method="waf", region="eu-west-1",
                    account="staging", ip_set_id="set-2", ip_set_name="block"),
        IPBanConfig(name="old", method="waf", region="eu-west-1",
                    account="retired", ip_set_id="set-3", ip_set_name="block"),
    ]
    return config


class _FakeWAF:
    def __init__(self) -> None:
        self.updates: List[dict] = []

    def get_ip_set(self, **kwargs: Any) -> dict:
        return {"IPSet": {"Addresses": []}, "LockToken": "t"}

    def update_ip_set(self, **kwargs: Any) -> None:
        self.updates.append(kwargs)


def _ip_ban_host(registry: AccountRegistry) -> Host:
    from servonaut.screens.ip_ban import IPBanScreen
    from servonaut.services.ip_ban_service import IPBanService

    app = Host(registry, IPBanScreen)
    app.ip_ban_service = IPBanService(app.config_manager, accounts=registry)
    return app


@pytest.mark.asyncio
async def test_ip_ban_shows_each_configs_account_and_bans_there(ec2, monkeypatch) -> None:
    registry = _registry(_ban_config())
    used: List[Any] = []
    waf = _FakeWAF()

    def fake_client(account, boto3_module, service, **kwargs):  # noqa: ANN001
        used.append(account)
        return waf

    monkeypatch.setattr("servonaut.services.ip_ban_service.aws_client", fake_client)
    app = _ip_ban_host(registry)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        options = [str(label) for label, _value in screen._get_config_options()]
        assert options == [
            "edge (waf, prod)", "edge-staging (waf, staging)", "old (waf, retired)",
        ]
        await screen._ban_ip("9.9.9.9", "edge-staging")
        await pilot.pause()

    assert used and all(ctx is registry.aws_context("staging") for ctx in used)
    assert waf.updates and waf.updates[0]["Addresses"] == ["9.9.9.9/32"]


@pytest.mark.asyncio
async def test_ip_ban_refuses_a_config_of_a_removed_account(ec2) -> None:
    registry = _registry(_ban_config())
    app = _ip_ban_host(registry)
    ban = MagicMock()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        app.ip_ban_service.ban_ip = ban
        screen.query_one("#ban_config_selector", Select).value = "old"
        screen.query_one("#ip_input", Input).value = "9.9.9.9"
        await pilot.pause()
        screen._do_ban()
        await pilot.pause()

    ban.assert_not_called()
    errors = [text for severity, text in app.notices if severity == "error"]
    assert any("'retired'" in text and "Settings" in text for text in errors)


@pytest.mark.asyncio
async def test_ip_ban_single_account_labels_are_unchanged(ec2) -> None:
    config = _config(extra=False)
    config.ip_ban_configs = [IPBanConfig(name="edge", method="waf", region="us-east-1")]
    app = _ip_ban_host(_registry(config))
    async with app.run_test(size=(160, 50)):
        options = [str(label) for label, _value in app.screen._get_config_options()]
    assert options == ["edge (waf)"]


# ---------------------------------------------------------------------------
# IP ban settings panel
# ---------------------------------------------------------------------------


class PanelHost(App):
    def __init__(self, registry: Optional[AccountRegistry], config: AppConfig) -> None:
        super().__init__()
        self.accounts = registry
        self.config_manager = MagicMock()
        self.config_manager.get.return_value = config
        self.auth_service = MagicMock()
        self.auth_service.is_authenticated = False
        self.notices: List[tuple] = []
        self.panel = None

    def notify(self, message, *, severity="information", **kwargs):  # noqa: ANN001
        self.notices.append((severity, str(message)))

    def on_mount(self) -> None:
        from servonaut.screens.settings.panels.ip_ban import IpBanPanel

        self.panel = IpBanPanel()
        self.mount(self.panel)


def _fill_waf_form(panel, name: str) -> None:
    panel.query_one("#ipban_input_name", Input).value = name
    panel.query_one("#ipban_select_method", Select).value = "waf"
    panel.query_one("#ipban_input_ip_set_id", Input).value = "set-9"
    panel.query_one("#ipban_input_ip_set_name", Input).value = "block"


@pytest.mark.asyncio
async def test_panel_saves_the_chosen_account(ec2) -> None:
    config = _config()
    app = PanelHost(_registry(config), config)
    async with app.run_test(size=(160, 60)) as pilot:
        await pilot.pause()
        panel = app.panel
        panel._handle_ipban_add()
        await pilot.pause()
        assert panel.query_one("#ipban_account_row").display is True
        _fill_waf_form(panel, "edge-staging")
        panel.query_one("#ipban_select_account", Select).value = "staging"
        panel._handle_ipban_save()
        panel._handle_ipban_add()
        await pilot.pause()
        _fill_waf_form(panel, "edge-prod")
        panel.query_one("#ipban_select_account", Select).value = "prod"
        panel._handle_ipban_save()
        await pilot.pause()
        headers = [str(col.label) for col in panel.query_one("#ipban_table", DataTable).columns.values()]

    saved = {cfg.name: cfg.account for cfg in config.ip_ban_configs}
    # The default account is saved as "", so the entry follows it.
    assert saved == {"edge-staging": "staging", "edge-prod": ""}
    assert headers == ["Name", "Account", "Method", "Region", "Details"]


@pytest.mark.asyncio
async def test_panel_refuses_an_account_that_is_not_configured(ec2) -> None:
    config = _config()
    config.ip_ban_configs = [
        IPBanConfig(name="old", method="waf", region="eu-west-1", account="retired",
                    ip_set_id="set-3", ip_set_name="block"),
    ]
    app = PanelHost(_registry(config), config)
    async with app.run_test(size=(160, 60)) as pilot:
        await pilot.pause()
        panel = app.panel
        row = panel.query_one("#ipban_table", DataTable).get_row_at(0)
        assert str(row[1]) == "retired (not configured)"
        panel._handle_ipban_edit()
        await pilot.pause()
        select = panel.query_one("#ipban_select_account", Select)
        assert select.value == "retired"
        assert "retired (not configured)" in [str(label) for label, _ in select._options]
        panel._handle_ipban_save()
        assert config.ip_ban_configs[0].account == "retired"
        assert any("retired" in text for severity, text in app.notices if severity == "error")

        select.value = "staging"
        panel._handle_ipban_save()
    assert config.ip_ban_configs[0].account == "staging"


@pytest.mark.asyncio
async def test_panel_discovers_with_the_chosen_accounts_credentials(ec2, monkeypatch) -> None:
    registry = _registry()
    used: List[Any] = []

    class FakeWAFv2:
        def list_ip_sets(self, **kwargs: Any) -> dict:
            return {"IPSets": [{"Id": "set-7", "Name": "block", "ARN": ""}]}

    def fake_client(account, boto3_module, service, **kwargs):  # noqa: ANN001
        used.append((account, service, kwargs.get("region_name")))
        return FakeWAFv2()

    monkeypatch.setattr(
        "servonaut.screens.settings.panels.ip_ban.aws_client", fake_client
    )
    app = PanelHost(registry, registry.config)
    async with app.run_test(size=(160, 60)) as pilot:
        await pilot.pause()
        panel = app.panel
        panel._handle_ipban_add()
        await pilot.pause()
        panel.query_one("#ipban_select_method", Select).value = "waf"
        panel.query_one("#ipban_select_region", Select).value = "eu-west-1"
        panel.query_one("#ipban_select_account", Select).value = "staging"
        await pilot.pause()
        panel._handle_ipban_discover()
        await _wait_for(pilot, lambda: used, "discovery")
        await pilot.pause()

    assert used == [(registry.aws_context("staging"), "wafv2", "eu-west-1")]


@pytest.mark.asyncio
async def test_panel_hides_the_account_with_one_account(ec2) -> None:
    config = _config(extra=False)
    app = PanelHost(_registry(config), config)
    async with app.run_test(size=(160, 60)) as pilot:
        await pilot.pause()
        panel = app.panel
        panel._handle_ipban_add()
        await pilot.pause()
        assert panel.query_one("#ipban_account_row").display is False
        _fill_waf_form(panel, "edge")
        panel._handle_ipban_save()
        headers = [str(col.label) for col in panel.query_one("#ipban_table", DataTable).columns.values()]

    assert config.ip_ban_configs[0].account == ""
    assert headers == ["Name", "Method", "Region", "Details"]


# ---------------------------------------------------------------------------
# Object storage
# ---------------------------------------------------------------------------


class FakeStorage:
    def __init__(self, label: str) -> None:
        self.label = label

    async def list_buckets(self) -> List[dict]:
        return [{"name": f"{self.label}-bucket", "creation_date": "2026-01-01"}]


@pytest.mark.asyncio
async def test_object_storage_uses_the_picked_account(ec2, monkeypatch) -> None:
    from servonaut.screens.object_storage import ObjectStorageScreen

    registry = _registry()
    extra: Dict[str, Optional[FakeStorage]] = {"staging": None}
    asked: List[tuple] = []

    def object_storage(provider: str, account: Optional[str] = None):
        ref = registry.account(provider, account)
        asked.append((provider, ref.label))
        return extra[ref.key]

    monkeypatch.setattr(registry, "object_storage", object_storage)
    app = Host(registry, lambda: ObjectStorageScreen("aws"))
    # The primary account keeps the app's own service (rebuilt by Settings).
    app.aws_object_storage_service = FakeStorage("prod")
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        table = screen.query_one("#s3_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 1, "prod buckets")
        assert "prod-bucket" in str(table.get_row_at(0)[1])
        assert asked == []

        _pick_account(screen, "s3_account", "staging")
        await _wait_for(pilot, lambda: ("aws", "staging") in asked, "the staging lookup")
        await pilot.pause()
        status = str(screen.query_one("#s3_status", Static).render())
        assert "not configured for account staging" in status
        assert table.row_count == 0

        extra["staging"] = FakeStorage("staging")
        screen.action_refresh()
        await _wait_for(pilot, lambda: table.row_count == 1, "staging buckets")
        assert "staging-bucket" in str(table.get_row_at(0)[1])


@pytest.mark.asyncio
async def test_object_storage_without_compute_accounts_uses_the_app_service(ec2) -> None:
    """Hetzner object storage works with S3 keys alone (no API token)."""
    from servonaut.screens.object_storage import ObjectStorageScreen

    registry = _registry()
    assert registry.accounts("hetzner") == []
    app = Host(registry, lambda: ObjectStorageScreen("hetzner"))
    app.hetzner_object_storage_service = FakeStorage("hetzner")
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        table = screen.query_one("#s3_table", DataTable)
        await _wait_for(pilot, lambda: table.row_count == 1, "the buckets")
        assert screen.query_one("#s3_account").display is False


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
