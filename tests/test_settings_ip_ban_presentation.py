"""IP-ban inline controls remain reachable during entry edits and discovery."""

from __future__ import annotations

import socket
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import boto3
import pytest
from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input, Select, Static

from servonaut.config import manager as manager_module
from servonaut.config import secrets as config_secrets
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.screens.settings.panels import ip_ban as panel_module
from servonaut.services.accounts import aws_account
from tests._account_fixtures import build_registry
from tests._async_bounds import STEP_TIMEOUT_SECONDS, wait_until
from tests.test_settings_presentation import _Host, _ready

pytestmark = pytest.mark.usefixtures("navigation_open")


SIZES = [(160, 50), (100, 30)]
COMMON_FIELDS = [
    ("ipban_input_name", "Name:"),
    ("ipban_select_account", "Account:"),
    ("ipban_select_method", "Method:"),
    ("ipban_select_region", "Region:"),
]
METHOD_FIELDS = {
    "waf": [
        ("ipban_select_ip_set", "WAF IP Set:"),
        ("ipban_input_ip_set_id", "IP Set ID:"),
        ("ipban_input_ip_set_name", "IP Set Name:"),
        ("ipban_select_waf_scope", "WAF Scope:"),
    ],
    "security_group": [
        ("ipban_select_sg", "Security Group:"),
        ("ipban_input_sg_id", "Security Group ID:"),
    ],
    "nacl": [
        ("ipban_select_nacl", "Network ACL:"),
        ("ipban_input_nacl_id", "NACL ID:"),
        ("ipban_input_rule_number_start", "Rule Number Start:"),
    ],
}


@pytest.fixture(autouse=True)
def no_real_credentials_or_network(monkeypatch):
    monkeypatch.setattr(manager_module, "load_secrets_env", lambda: None)
    monkeypatch.setattr(config_secrets, "load_secrets_env", lambda *args, **kwargs: None)
    blocked = Mock(side_effect=AssertionError("Settings fixtures must not use credentials or network"))
    for module, name in (
        (config_secrets, "resolve_secret"),
        (boto3, "client"), (boto3, "Session"), (boto3.session, "Session"),
        (aws_account, "raw_config_parse"), (aws_account, "load_config"),
        (socket, "create_connection"), (socket.socket, "connect"),
        (panel_module, "aws_client"),
    ):
        monkeypatch.setattr(module, name, blocked)
    yield
    blocked.assert_not_called()


@pytest.fixture
def manager(tmp_path: Path, no_real_credentials_or_network) -> ConfigManager:
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.save(AppConfig())
    manager.load()
    return manager


class _IPBanHost(_Host):
    def __init__(self, manager: ConfigManager, navigation: bool, registry) -> None:
        super().__init__(manager, "ip_ban", navigation_visible=navigation)
        self.accounts = registry
        self.cache_service = SimpleNamespace(is_fresh=lambda: True, get_age=lambda: None, load_any=lambda: [])
        self.notes: list[str] = []

    def provider_inventory(self, provider: str) -> None:
        return None

    def notify(self, message: str, **kwargs) -> None:
        self.notes.append(str(message))
        super().notify(message, **kwargs)


def _host(monkeypatch, manager: ConfigManager, navigation: bool) -> _IPBanHost:
    registry, _ = build_registry(
        monkeypatch, aws={"primary": [], "secondary": []}, config=manager.get(),
    )
    return _IPBanHost(manager, navigation, registry)


def _exposed(app: _IPBanHost, widget: Widget) -> bool:
    hit, _ = app.get_widget_at(*widget.region.center)
    return widget.region.width > 0 and widget.region.height > 0 and app.screen.region.contains_region(widget.region) and (hit is widget or widget in hit.ancestors)


async def _click(app: _IPBanHost, pilot: Pilot, widget: Widget) -> None:
    if isinstance(widget, Button):
        await wait_until(lambda: not widget.has_class("-active"))
    widget.scroll_visible(animate=False)
    await pilot.pause()
    await wait_until(lambda: _exposed(app, widget))
    point = widget.region.offset
    hit = app.get_widget_at(*point)[0]
    assert hit is widget or widget in hit.ancestors
    # Keep the original point when a composite control's child owns the hit.
    offset = (point.x - hit.region.x, point.y - hit.region.y)
    assert await pilot.click(hit, offset=offset)


async def _tab_to(app: _IPBanHost, pilot: Pilot, widget: Widget) -> None:
    for _ in range(len(app.screen.focus_chain) + 1):
        if app.focused is widget:
            assert _exposed(app, widget)
            return
        await pilot.press("tab")
    pytest.fail(f"Tab did not reach {widget.id}")


def _paint(app: _IPBanHost) -> str:
    return "\n".join(strip.text for strip in app.screen._compositor.render_strips())


def _compact(value: str) -> str:
    return "".join(value.split())


async def _open_form(app: _IPBanHost, pilot: Pilot, panel, method: str) -> None:
    await _click(app, pilot, panel.query_one("#btn_ipban_add", Button))
    await wait_until(lambda: panel.query_one("#ipban-form-container").display)
    panel.query_one("#ipban_select_method", Select).value = method
    panel.query_one("#ipban_select_region", Select).value = "eu-west-1"
    panel.query_one("#ipban_select_account", Select).value = "secondary"
    await pilot.pause()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("method", list(METHOD_FIELDS))
async def test_method_form_labels_and_native_inline_save_are_reachable(
    monkeypatch, manager, size, navigation, method,
) -> None:
    app = _host(monkeypatch, manager, navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        assert not panel.query_one("#ipban-form-container").display
        await _open_form(app, pilot, panel, method)
        assert panel.query_one("#ipban_account_row").display
        for field_id, label in COMMON_FIELDS + METHOD_FIELDS[method]:
            field = panel.query_one(f"#{field_id}")
            field.parent.scroll_visible(animate=False)
            await pilot.pause()
            assert _exposed(app, field)
            assert _compact(label) in _compact(_paint(app))
        for other, container in (("waf", "waf"), ("security_group", "sg"), ("nacl", "nacl")):
            assert panel.query_one(f"#ipban_{container}_fields").display == (method == other)
        await _tab_to(app, pilot, panel.query_one("#btn_ipban_discover", Button))
        await _tab_to(app, pilot, panel.query_one("#btn_ipban_cancel", Button))
        await _tab_to(app, pilot, panel.query_one("#btn_ipban_save", Button))
        panel.query_one("#ipban_input_name", Input).value = "example-blocklist"
        panel.query_one("#ipban_input_ip_set_id", Input).value = "set-example"
        panel.query_one("#ipban_input_ip_set_name", Input).value = "example-set"
        panel.query_one("#ipban_input_sg_id", Input).value = "sg-example"
        panel.query_one("#ipban_input_nacl_id", Input).value = "acl-example"
        panel.query_one("#ipban_input_rule_number_start", Input).value = "120"
        await _click(app, pilot, panel.query_one("#btn_ipban_save", Button))
        await wait_until(lambda: not panel.query_one("#ipban-form-container").display)
        assert panel.query_one("#ipban_table", DataTable).row_count == 1
        saved = ConfigManager(config_path=manager._config_path).load().ip_ban_configs
        assert len(saved) == 1 and saved[0].name == "example-blocklist"
        assert (saved[0].method, saved[0].account, saved[0].region) == (method, "secondary", "eu-west-1")
        assert not panel.is_dirty()


class _DelayedWAF:
    """Hold only the fake provider response; execute the real discovery worker."""

    def __init__(self, outcome: str) -> None:
        self.outcome = outcome
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls: list[dict] = []

    def list_ip_sets(self, **kwargs) -> dict:
        self.calls.append(kwargs)
        self.started.set()
        assert self.release.wait(STEP_TIMEOUT_SECONDS), "Fake discovery release was not signalled"
        if self.outcome == "failure":
            raise RuntimeError("example discovery unavailable")
        if self.outcome == "empty":
            return {"IPSets": []}
        return {"IPSets": [{"Id": "set-example", "Name": "example-set", "ARN": ""}]}


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("outcome", ["found", "empty", "failure"])
async def test_pointer_discovery_paints_pending_and_recovers_without_implicit_save(
    monkeypatch, manager, size, navigation, outcome,
) -> None:
    app = _host(monkeypatch, manager, navigation)
    fake = _DelayedWAF(outcome)
    used: list[tuple] = []

    def fake_client(account, boto3_module, service, **kwargs):
        used.append((account, service, kwargs))
        return fake

    monkeypatch.setattr(panel_module, "aws_client", fake_client)
    before = manager._config_path.read_bytes()
    try:
        async with app.run_test(size=size) as pilot:
            panel = await _ready(app, pilot)
            try:
                assert not used and not fake.calls
                await _open_form(app, pilot, panel, "waf")
                button = panel.query_one("#btn_ipban_discover", Button)
                await _click(app, pilot, button)
                await wait_until(fake.started.is_set)
                hint = panel.query_one("#ipban_discover_hint", Static)
                await wait_until(
                    lambda: button.disabled and _exposed(app, hint)
                    and "Discovering..." in _paint(app)
                )
                assert button.disabled and _exposed(app, hint)
                assert "Discovering..." in _paint(app)
                assert await pilot.click(button)
                assert len(fake.calls) == 1
                # An actual input interaction proves the worker leaves the UI usable.
                name = panel.query_one("#ipban_input_name", Input)
                await _click(app, pilot, name)
                await pilot.press("x")
                assert name.value == "x"
                fake.release.set()
                await wait_until(lambda: not button.disabled)
                assert used == [(app.accounts.aws_context("secondary"), "wafv2", {"region_name": "eu-west-1"})]
                assert fake.calls == [{"Scope": "REGIONAL"}]
                hint.parent.scroll_visible(animate=False)
                await pilot.pause()
                assert "Discovering..." not in _paint(app)
                select = panel.query_one("#ipban_select_ip_set", Select)
                select.parent.scroll_visible(animate=False)
                await pilot.pause()
                assert _exposed(app, select)
                if outcome == "found":
                    assert any("Found 1 WAF IP set" in note for note in app.notes)
                    assert select.value is Select.NULL
                    await _click(app, pilot, select)
                    await wait_until(lambda: select.expanded)
                    # Home targets the blank prompt; Down reaches the first discovered set.
                    await pilot.press("home", "down", "enter")
                    await wait_until(lambda: select.value == "set-example|example-set")
                    await wait_until(lambda: panel.query_one("#ipban_input_ip_set_id", Input).value == "set-example")
                    assert panel.query_one("#ipban_input_ip_set_name", Input).value == "example-set"
                elif outcome == "empty":
                    assert "No IP sets found" in _paint(app)
                    assert any("No WAF IP sets found" in note for note in app.notes)
                else:
                    assert any("Discovery failed: example discovery unavailable" in note for note in app.notes)
                assert manager._config_path.read_bytes() == before
                assert not manager.get().ip_ban_configs and not panel.is_dirty()
                await _click(app, pilot, panel.query_one("#btn_ipban_cancel", Button))
                assert not panel.query_one("#ipban-form-container").display
            finally:
                # Finish the held fake read while its panel is still mounted.
                fake.release.set()
                for worker in tuple(app.workers):
                    if worker.node is panel and worker.name == "ipban_discover":
                        await worker.wait()
    finally:
        fake.release.set()
