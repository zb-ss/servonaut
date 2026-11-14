"""Scalar limits and full-width editors stay reachable inside Settings."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import Button, Input, Select, Static, Switch

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.screens.settings.widgets import KeyValueEditor, StringListEditor
from tests._async_bounds import wait_until
from tests.test_settings_presentation import _Host, _ready

pytestmark = pytest.mark.usefixtures("navigation_open")


SIZES = [(160, 50), (100, 30)]
SCALARS = {
    "mcp": [
        ("mcp_guard_level", "Guard level"),
        ("mcp_audit_path", "Audit log path"),
        ("mcp_max_output_lines", "Max output lines"),
        ("mcp_allow_destructive", "Allow destructive AWS calls"),
    ],
    "log_viewer": [
        ("lv_scan_max_depth", "Max scan depth"),
        ("lv_max_lines", "Max lines to load"),
        ("lv_tail_lines", "Tail lines (follow mode)"),
    ],
}
EDITORS = {
    "mcp": ["mcp_blocklist", "mcp_allowlist"],
    "log_viewer": ["lv_default_paths", "lv_scan_directories", "lv_custom_paths"],
}


@pytest.fixture
def manager(tmp_path: Path) -> ConfigManager:
    config = AppConfig()
    config.mcp = replace(config.mcp, command_blocklist=["blocked-example"], command_allowlist=["echo"], guard_level="standard", allow_destructive_aws_call=False)
    config.log_viewer_default_paths = ["/var/log/example.log"]
    config.log_viewer_scan_directories = ["/var/log"]
    config.log_viewer_custom_paths = {"group-a": ["/var/log/base.log"]}
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.save(config)
    manager.load()
    return manager


class _EditorHost(_Host):
    def __init__(self, manager: ConfigManager, panel_id: str, navigation: bool) -> None:
        super().__init__(manager, panel_id, navigation_visible=navigation)
        self.cache_service = SimpleNamespace(is_fresh=lambda: True, get_age=lambda: None, load_any=lambda: [])
        self.notes: list[str] = []

    def provider_inventory(self, provider: str) -> None:
        return None

    def notify(self, message: str, **kwargs) -> None:
        self.notes.append(str(message))
        super().notify(message, **kwargs)


def _exposed(app: _EditorHost, widget: Widget) -> bool:
    hit, _ = app.get_widget_at(*widget.region.center)
    return widget.region.width > 0 and widget.region.height > 0 and app.screen.region.contains_region(widget.region) and (hit is widget or widget in hit.ancestors)


async def _click(app: _EditorHost, pilot: Pilot, widget: Widget) -> None:
    if isinstance(widget, Button):
        await wait_until(lambda: not widget.has_class("-active"))
    widget.scroll_visible(animate=False)
    await pilot.pause()
    await wait_until(lambda: _exposed(app, widget))
    assert await pilot.click(widget)


async def _tab_to(app: _EditorHost, pilot: Pilot, widget: Widget) -> None:
    for _ in range(len(app.screen.focus_chain) + 1):
        if app.focused is widget:
            assert _exposed(app, widget)
            return
        await pilot.press("tab")
    pytest.fail(f"Tab did not reach {widget.id}")


def _paint(app: _EditorHost) -> str:
    return "\n".join(strip.text for strip in app.screen._compositor.render_strips())


def _compact(value: str) -> str:
    return "".join(value.split())


def _widget_paint(app: _EditorHost, widget: Widget) -> str:
    rows = app.screen._compositor.render_strips()
    region = widget.content_region.intersection(app.screen.region)
    return "\n".join(rows[y].crop(region.x, region.right).text
                     for y in range(region.y, region.bottom))


async def _settled_scroll(body: Widget) -> None:
    """Wait until the body has stopped scrolling (animations included)."""
    steady = 0
    last = None
    while steady < 6:
        await asyncio.sleep(0.05)
        current = (body.scroll_y, body.scroll_x)
        steady = steady + 1 if current == last else 0
        last = current


async def _reveal_literal(
    app: _EditorHost, pilot: Pilot, body: Widget, widget: Static,
    expected: str, scroll_target: Widget | None = None,
) -> None:
    await wait_until(lambda: expected == widget.render().plain)
    (widget if scroll_target is None else scroll_target).scroll_visible(
        animate=False, immediate=True,
    )
    await wait_until(lambda: (
        widget.region.width > 0 and widget.region.height > 0
        and body.scrollable_content_region.contains_region(widget.region)
        and app.screen.region.contains_region(widget.region)
        and _compact(_widget_paint(app, widget)) == _compact(expected)
    ))
    await _settled_scroll(body)
    assert body.scrollable_content_region.contains_region(widget.region)
    for row in range(widget.region.y, widget.region.bottom):
        hit = app.get_widget_at(widget.region.center[0], row)[0]
        assert hit is widget or widget in hit.ancestors
    assert _compact(_widget_paint(app, widget)) == _compact(expected)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
@pytest.mark.parametrize("panel_id", ["mcp", "log_viewer"])
async def test_scalar_labels_and_fullwidth_editor_controls_are_actually_reachable(
    manager, size, navigation, panel_id,
) -> None:
    app = _EditorHost(manager, panel_id, navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        body = panel.query_one(".panel-body")
        for field_id, label in SCALARS[panel_id]:
            field = panel.query_one(f"#{field_id}")
            label_widget = field.parent.query_one(".label", Static)
            await _reveal_literal(app, pilot, body, label_widget, label, field.parent)
            assert _exposed(app, field)
            assert body.scrollable_content_region.contains_region(field.region)
        for editor_id in EDITORS[panel_id]:
            editor = panel.query_one(f"#{editor_id}")
            editor.scroll_visible(animate=False)
            await pilot.pause()
            if panel_id == "log_viewer":
                # Analysis cards use a bounded frame around the full-width editor.
                section = editor.parent
                assert section is not None and section.has_class("settings-analysis-section")
                assert section.has_class("settings-form-section") and section.parent is body
                assert section.region.x == body.scrollable_content_region.x
                assert section.region.right == body.scrollable_content_region.right
                usable = section.scrollable_content_region
                assert usable.x - section.region.x == 2
                assert section.region.right - usable.right == 1
                assert editor.region.x == usable.x
                assert editor.region.right == usable.right
            else:
                assert editor.region.x == body.scrollable_content_region.x
                assert editor.region.right == body.scrollable_content_region.right
            add = editor.query_one(".list-add" if isinstance(editor, StringListEditor) else ".kv-add", Button)
            await _tab_to(app, pilot, add)
            assert "+ Add" in _paint(app)
        save = panel.query_one(f"#save_{panel_id}", Button)
        await _tab_to(app, pilot, save)
        assert not panel.is_dirty()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
async def test_mcp_security_warnings_are_painted_after_actual_control_changes(
    manager, size, navigation,
) -> None:
    app = _EditorHost(manager, "mcp", navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        guard = panel.query_one("#mcp_guard_level", Select)
        guard.value = "dangerous"
        await pilot.pause()
        body = panel.query_one(".panel-body")
        warning = panel.query_one("#mcp_guard_warn", Static)
        await _reveal_literal(app, pilot, body, warning,
            "Warning: 'Dangerous' tier grants the MCP client elevated tool access. "
            "Use only when you trust the AI agent fully.")
        await _click(app, pilot, panel.query_one("#mcp_allow_destructive", Switch))
        warning = panel.query_one("#mcp_destructive_warn", Static)
        await _reveal_literal(app, pilot, body, warning,
            "Warning: Enabling this allows destructive AWS operations (delete/terminate/purge) "
            "through the generic aws_call tool. The dangerous guard tier is also required.")
        editor = panel.query_one("#mcp_blocklist", StringListEditor)
        await _click(app, pilot, editor.query_one(".list-remove", Button))
        await wait_until(lambda: not editor.get_values())
        warning = panel.query_one("#mcp_blocklist_warn", Static)
        await _reveal_literal(app, pilot, body, warning,
            "Warning: The command blocklist is empty. The MCP server will not block any "
            "commands by pattern. Re-add entries to restore protection.")
        assert _exposed(app, panel.query_one("#save_mcp", Button))


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
async def test_log_editor_pointer_additions_and_numeric_values_roundtrip_without_clobbering(
    manager, size, navigation,
) -> None:
    app = _EditorHost(manager, "log_viewer", navigation)
    original_mcp = manager.get().mcp
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        panel.query_one("#lv_scan_max_depth", Input).value = "3"
        panel.query_one("#lv_max_lines", Input).value = "4200"
        panel.query_one("#lv_tail_lines", Input).value = "125"
        defaults = panel.query_one("#lv_default_paths", StringListEditor)
        defaults.query_one(".list-new", Input).value = "/var/log/extra.log"
        await _click(app, pilot, defaults.query_one(".list-add", Button))
        directories = panel.query_one("#lv_scan_directories", StringListEditor)
        directories.query_one(".list-new", Input).value = "/srv/logs"
        await _click(app, pilot, directories.query_one(".list-add", Button))
        custom = panel.query_one("#lv_custom_paths", KeyValueEditor)
        row_inputs = list(custom.query_one(".kv-row").query(Input))
        row_inputs[1].value = "/var/log/one.log, /var/log/two.log"
        custom.query_one(".kv-new-key", Input).value = "empty-group"
        custom.query_one(".kv-new-value", Input).value = ""
        await _click(app, pilot, custom.query_one(".kv-add", Button))
        await wait_until(lambda: "empty-group" in custom.get_map())
        await pilot.pause()
        assert panel.is_dirty()
        await _click(app, pilot, panel.query_one("#save_log_viewer", Button))
        await wait_until(lambda: "Saved" in app.notes and not panel._settling)
        saved = ConfigManager(config_path=manager._config_path).load()
        assert saved.log_viewer_scan_max_depth == 3
        assert saved.log_viewer_max_lines == 4200 and saved.log_viewer_tail_lines == 125
        assert saved.log_viewer_default_paths == ["/var/log/example.log", "/var/log/extra.log"]
        assert saved.log_viewer_scan_directories == ["/var/log", "/srv/logs"]
        assert saved.log_viewer_custom_paths == {"group-a": ["/var/log/one.log", "/var/log/two.log"], "empty-group": []}
        assert saved.mcp == original_mcp
        assert not panel.is_dirty()


@pytest.mark.asyncio
@pytest.mark.parametrize("field_id", ["lv_scan_max_depth", "lv_max_lines", "lv_tail_lines"])
@pytest.mark.parametrize("value", ["not-a-number", "0"])
async def test_log_invalid_limit_focuses_visible_field_and_keeps_disk_unchanged(manager, field_id, value) -> None:
    app = _EditorHost(manager, "log_viewer", False)
    before = manager._config_path.read_bytes()
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        field = panel.query_one(f"#{field_id}", Input)
        field.value = value
        await pilot.pause()
        await _click(app, pilot, panel.query_one("#save_log_viewer", Button))
        await wait_until(lambda: app.focused is field)
        assert _exposed(app, field)
        assert manager._config_path.read_bytes() == before
        assert "Saved" not in app.notes


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("navigation", [True, False])
async def test_removing_the_last_blocklist_entry_keeps_the_new_warning_in_view(
    manager, size, navigation,
) -> None:
    app = _EditorHost(manager, "mcp", navigation)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        body = panel.query_one(".panel-body")
        editor = panel.query_one("#mcp_blocklist", StringListEditor)
        remove = editor.query_one(".list-remove", Button)
        remove.scroll_visible(animate=False, immediate=True)
        await _settled_scroll(body)
        await _click(app, pilot, remove)
        warning = panel.query_one("#mcp_blocklist_warn", Static)
        await wait_until(lambda: bool(warning.render().plain))
        await _settled_scroll(body)
        assert app.focused is editor.query_one(".list-new", Input)
        assert body.scrollable_content_region.contains_region(warning.region)
