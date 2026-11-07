"""Connection forms retain visible controls and explicit staged save boundaries."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input

from servonaut.config import manager as manager_module
from servonaut.config import secrets as config_secrets
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig, ConnectionProfile, ConnectionRule
from servonaut.screens.settings.widgets import KeyValueEditor, StringListEditor
from tests._async_bounds import wait_until
from tests.test_settings_presentation import _Host, _ready


SIZES = [(160, 50), (100, 30)]
REFERENCE = "$SERVONAUT_CONNECTIONS_TEST_KEY"
FIELDS = {
    "profile": [
        ("pf_name", "Profile name"), ("pf_bastion_host", "Bastion host"),
        ("pf_bastion_user", "Bastion user"), ("pf_bastion_key", "Bastion key"),
        ("pf_username", "Username (target)"), ("pf_proxy_command", "Proxy command"),
        ("pf_ssh_port", "SSH port (1-65535)"),
    ],
    "rule": [("rl_name", "Rule name"), ("rl_profile_name", "Profile name")],
}


@pytest.fixture(autouse=True)
def no_external_secret_resolution(monkeypatch):
    monkeypatch.delenv("SERVONAUT_CONNECTIONS_TEST_KEY", raising=False)
    monkeypatch.setattr(manager_module, "load_secrets_env", lambda: None)
    monkeypatch.setattr(config_secrets, "load_secrets_env", lambda *args, **kwargs: None)
    resolver = Mock(side_effect=AssertionError("Connection editing must preserve raw references"))
    monkeypatch.setattr(config_secrets, "resolve_secret", resolver)
    yield
    resolver.assert_not_called()


@pytest.fixture
def manager(tmp_path: Path, no_external_secret_resolution) -> ConfigManager:
    config = AppConfig(
        connection_profiles=[ConnectionProfile(
            "first-profile", bastion_host="gateway.example.test", bastion_user="operator",
            bastion_key=REFERENCE, username="appuser", proxy_command="echo route %h:%p",
            ssh_port=2222, extra_ssh_options=["IdentitiesOnly=yes"],
        )],
        connection_rules=[ConnectionRule("first-rule", {"name_contains": "web", "region": "local"}, "first-profile")],
    )
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.save(config)
    manager.load()
    return manager


class _ConnectionsHost(_Host):
    def __init__(self, manager: ConfigManager, navigation: bool) -> None:
        super().__init__(manager, "connections", navigation_visible=navigation)
        self.cache_service = SimpleNamespace(is_fresh=lambda: True, get_age=lambda: None, load_any=lambda: [])
        self.ssh_service = SimpleNamespace(connect=Mock(side_effect=AssertionError("No SSH from settings")), list_available_keys=Mock(side_effect=AssertionError("No real key paths")))
        self.connection_service = SimpleNamespace(resolve_profile=Mock(side_effect=AssertionError("No connection resolution from settings")))
        self.notes: list[str] = []

    def provider_inventory(self, provider: str) -> None:
        return None

    def notify(self, message: str, **kwargs) -> None:
        self.notes.append(str(message))
        super().notify(message, **kwargs)

    def assert_no_external_operations(self) -> None:
        self.ssh_service.connect.assert_not_called()
        self.ssh_service.list_available_keys.assert_not_called()
        self.connection_service.resolve_profile.assert_not_called()


def _exposed(app: _ConnectionsHost, widget: Widget) -> bool:
    hit, _ = app.get_widget_at(*widget.region.center)
    return widget.region.width > 0 and widget.region.height > 0 and app.screen.region.contains_region(widget.region) and (hit is widget or widget in hit.ancestors)


async def _click(app: _ConnectionsHost, pilot: Pilot, widget: Widget) -> None:
    if isinstance(widget, Button):
        await wait_until(lambda: not widget.has_class("-active"))
    widget.scroll_visible(animate=False)
    await pilot.pause()
    await wait_until(lambda: _exposed(app, widget))
    assert await pilot.click(widget)


async def _tab_to(app: _ConnectionsHost, pilot: Pilot, widget: Widget) -> None:
    for _ in range(len(app.screen.focus_chain) + 1):
        if app.focused is widget:
            assert _exposed(app, widget)
            return
        await pilot.press("tab")
    pytest.fail(f"Tab did not reach {widget.id}")


def _paint(app: _ConnectionsHost) -> str:
    return "\n".join(strip.text for strip in app.screen._compositor.render_strips())


def _compact(value: str) -> str:
    return "".join(value.split())


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("form_kind", ["profile", "rule"])
async def test_connection_form_labels_editor_and_actions_keep_native_reachability(
    manager, size, navigation, form_kind,
) -> None:
    app = _ConnectionsHost(manager, navigation)
    before = manager._config_path.read_bytes()
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        await _click(app, pilot, panel.query_one(f"#btn_{form_kind}_edit", Button))
        form = panel.query_one(f"#{form_kind}_form")
        await wait_until(lambda: form.display)
        for field_id, label in FIELDS[form_kind]:
            field = panel.query_one(f"#{field_id}", Input)
            field.parent.scroll_visible(animate=False)
            await pilot.pause()
            assert _exposed(app, field)
            assert _compact(label) in _compact(_paint(app))
        editor = panel.query_one("#pf_extra_ssh_options" if form_kind == "profile" else "#rl_match_conditions")
        editor.scroll_visible(animate=False)
        await pilot.pause()
        assert editor.region.x == form.content_region.x
        assert editor.region.right == form.content_region.right
        await _tab_to(app, pilot, editor.query_one(".list-add" if form_kind == "profile" else ".kv-add", Button))
        await _tab_to(app, pilot, panel.query_one(f"#btn_{form_kind}_save", Button))
        assert _exposed(app, panel.query_one("#save_connections", Button))
        await _click(app, pilot, panel.query_one(f"#btn_{form_kind}_cancel", Button))
        assert not form.display and not panel.is_dirty()
        assert manager._config_path.read_bytes() == before
        app.assert_no_external_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
async def test_pointer_profile_rule_saves_are_staged_and_final_save_keeps_raw_values(
    manager, size, navigation,
) -> None:
    app = _ConnectionsHost(manager, navigation)
    before = manager._config_path.read_bytes()
    unrelated = manager.get().scan_rules
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        await _click(app, pilot, panel.query_one("#btn_profile_add", Button))
        for field_id, value in {
            "pf_name": "second-profile", "pf_bastion_host": "jump.example.test",
            "pf_bastion_user": "operator", "pf_bastion_key": REFERENCE,
            "pf_username": "appuser", "pf_proxy_command": "echo fixture %h:%p", "pf_ssh_port": "2202",
        }.items():
            panel.query_one(f"#{field_id}", Input).value = value
        options = panel.query_one("#pf_extra_ssh_options", StringListEditor)
        options.query_one(".list-new", Input).value = "IdentityAgent=$SERVONAUT_CONNECTIONS_TEST_AGENT"
        await _click(app, pilot, options.query_one(".list-add", Button))
        await _click(app, pilot, panel.query_one("#btn_profile_save", Button))
        await wait_until(lambda: not panel.query_one("#profile_form").display)
        assert panel.query_one("#conn_profiles_table", DataTable).row_count == 2
        assert panel.is_dirty() and manager._config_path.read_bytes() == before
        await _click(app, pilot, panel.query_one("#btn_rule_add", Button))
        panel.query_one("#rl_name", Input).value = "second-rule"
        panel.query_one("#rl_profile_name", Input).value = "second-profile"
        conditions = panel.query_one("#rl_match_conditions", KeyValueEditor)
        conditions.query_one(".kv-new-key", Input).value = "name_contains"
        conditions.query_one(".kv-new-value", Input).value = "db"
        await _click(app, pilot, conditions.query_one(".kv-add", Button))
        await _click(app, pilot, panel.query_one("#btn_rule_save", Button))
        await wait_until(lambda: not panel.query_one("#rule_form").display)
        assert panel.query_one("#conn_rules_table", DataTable).row_count == 2
        assert manager._config_path.read_bytes() == before
        await _click(app, pilot, panel.query_one("#save_connections", Button))
        await wait_until(lambda: "Connection settings saved" in app.notes and not panel._settling)
        saved = ConfigManager(config_path=manager._config_path).load()
        assert saved.connection_profiles[1] == ConnectionProfile(
            "second-profile", bastion_host="jump.example.test", bastion_user="operator",
            bastion_key=REFERENCE, username="appuser", proxy_command="echo fixture %h:%p",
            ssh_port=2202, extra_ssh_options=["IdentityAgent=$SERVONAUT_CONNECTIONS_TEST_AGENT"],
        )
        assert saved.connection_rules[1] == ConnectionRule("second-rule", {"name_contains": "db"}, "second-profile")
        assert saved.scan_rules == unrelated
        assert not panel.is_dirty()
        app.assert_no_external_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("kind,field_id,value", [
    ("profile", "pf_ssh_port", "0"),
    ("profile", "pf_name", "first-profile"),
    ("rule", "rl_profile_name", "unknown-profile"),
])
async def test_inline_invalid_profile_or_rule_focuses_visible_field_without_committing(
    manager, size, kind, field_id, value,
) -> None:
    app = _ConnectionsHost(manager, False)
    before = manager._config_path.read_bytes()
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        await _click(app, pilot, panel.query_one(f"#btn_{kind}_add", Button))
        panel.query_one("#pf_name" if kind == "profile" else "#rl_name", Input).value = "new-example"
        field = panel.query_one(f"#{field_id}", Input)
        field.value = value
        await _click(app, pilot, panel.query_one(f"#btn_{kind}_save", Button))
        await wait_until(lambda: app.focused is field)
        # Native focus schedules animated scrolling; geometry needs its final frame.
        await pilot.wait_for_scheduled_animations()
        assert app.focused is field
        assert _exposed(app, field) and panel.query_one(f"#{kind}_form").display
        assert not panel.is_dirty()
        assert manager._config_path.read_bytes() == before
        app.assert_no_external_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("kind", ["profile", "rule"])
async def test_demo_keyboard_toggle_closes_bound_forms_and_refuses_pointer_edit(
    manager, navigation, kind,
) -> None:
    app = _ConnectionsHost(manager, navigation)
    before = manager._config_path.read_bytes()
    original_profiles = list(manager.get().connection_profiles)
    original_rules = list(manager.get().connection_rules)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        await _click(app, pilot, panel.query_one(f"#btn_{kind}_edit", Button))
        assert panel.query_one(f"#{kind}_form").display
        await pilot.press("ctrl+shift+d")
        await wait_until(lambda: app.demo_mode and not panel.query_one(f"#{kind}_form").display)
        tables = [panel.query_one(f"#conn_{name}_table", DataTable) for name in ("profiles", "rules")]
        cells = " ".join(str(cell) for table in tables for row_key in table.rows for cell in table.get_row(row_key))
        assert "first-profile" not in cells and "gateway.example.test" not in cells
        assert "local" in cells
        await _click(app, pilot, panel.query_one(f"#btn_{kind}_edit", Button))
        await wait_until(lambda: any("Editing is disabled in demo mode" in note for note in app.notes))
        assert not panel.query_one(f"#{kind}_form").display
        assert not panel.is_dirty()
        assert manager.get().connection_profiles == original_profiles
        assert manager.get().connection_rules == original_rules
        assert manager._config_path.read_bytes() == before
        app.assert_no_external_operations()
