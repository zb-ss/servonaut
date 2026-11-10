"""Policy forms retain readable warnings, native editors and safe persistence."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

import pytest
from rich.color import Color
from textual.containers import VerticalScroll
from textual.widget import Widget
from textual.widgets import Button, Input, Select, Static, TextArea

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.screens.settings.panels.ai_chat import _DANGEROUS_WARNING
from servonaut.screens.settings.panels.relay import _WARN_DANGEROUS_AUTO_APPROVE
from servonaut.screens.settings.shell import DiscardChangesModal
from servonaut.styles.themes import SERVONAUT_THEMES
from tests._async_bounds import wait_until
from tests.test_navigation_dialog_contrast import _painted_text_styles
from tests.test_settings_presentation import _Host, _ready, _tab_to

pytestmark = pytest.mark.usefixtures("navigation_open")

PANELS = ("vault", "relay", "ai_chat")
PROMPT = "first café\nsecond Ω"
GUARDS = (
    ("relay", "relay_ai_tool_auto_approve", "relay_auto_approve_warn"),
    ("ai_chat", "ai_chat_tool_guard_level", "ai_chat_guard_warning"),
)


@pytest.fixture
def manager(tmp_path: Path) -> ConfigManager:
    config = AppConfig()
    config.ai_system_prompt = PROMPT
    config.chat_system_prompt = PROMPT
    config.relay.base_url = "https://relay.example.test"
    config.relay.mercure_url = "https://relay.example.test/events"
    # These policies are intentionally absent from the three panel forms.
    config.relay.heartbeat_rejection_alert_after = 9
    config.vault.binding_read_cache_seconds = 17.5
    config.vault.binding_read_backoff_seconds = 9.5
    result = ConfigManager(config_path=tmp_path / "config.json")
    result.save(config)
    result.load()
    return result


@pytest.fixture(autouse=True)
def _terminal_colours(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)


def _painted(widget: Widget) -> str:
    return "\n".join(
        strip.text for strip in widget.render_lines(widget.region.size.region)
    )


def _assert_save_exposed(app: _Host, panel_id: str) -> Button:
    save = app.screen.query_one(f"#save_{panel_id}", Button)
    assert app.screen.region.contains_region(save.region)
    assert app.get_widget_at(*save.region.center)[0] is save
    return save


@pytest.mark.asyncio
@pytest.mark.parametrize("panel_id", PANELS)
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_policy_labels_and_fields_fit_with_the_save_dock_pinned(
    manager: ConfigManager, panel_id: str, size: tuple[int, int],
    navigation_visible: bool,
) -> None:
    app = _Host(manager, panel_id, navigation_visible=navigation_visible)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        assert not panel.has_unsaved_changes()
        save_region = _assert_save_exposed(app, panel_id).region
        body = panel.query_one(".panel-body", VerticalScroll)
        for row in panel.query(".setting_row"):
            label = row.query_one(".label", Static)
            field = next(child for child in row.children if child is not label)
            row.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            assert body.scrollable_content_region.contains_region(row.region)
            assert app.get_widget_at(*field.region.center)[0] in {
                field, *field.query("*"),
            }
            assert field.region.right <= body.scrollable_content_region.right
            expected = label.render().plain
            assert "".join(expected.split()) in "".join(_painted(label).split())
            if app.screen.has_class("-content-narrow"):
                assert field.region.y >= label.region.bottom
                assert field.region.x == label.region.x
            else:
                assert field.region.x >= label.region.right
            assert _assert_save_exposed(app, panel_id).region == save_region
        assert not panel.has_unsaved_changes()


@pytest.mark.asyncio
@pytest.mark.parametrize("panel_id,select_id,warning_id", GUARDS)
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light"])
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_dangerous_selection_paints_an_adjacent_warning_and_reverts_cleanly(
    manager: ConfigManager, panel_id: str, select_id: str, warning_id: str,
    theme: str, size: tuple[int, int],
) -> None:
    app = _Host(manager, panel_id, navigation_visible=True)
    app.theme = theme
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        control = panel.query_one(f"#{select_id}", Select)
        warning = panel.query_one(f"#{warning_id}", Static)
        assert not warning.render().plain
        save_region = _assert_save_exposed(app, panel_id).region
        await _tab_to(pilot, control)
        await pilot.press("enter", "down", "enter")
        await wait_until(lambda: control.value == "dangerous")
        await pilot.pause()
        message = warning.render().plain
        assert message == (
            _WARN_DANGEROUS_AUTO_APPROVE if panel_id == "relay" else _DANGEROUS_WARNING
        )
        assert "Warning:" in message and "dangerous" in message.lower()
        assert warning.parent is control.parent.parent
        assert 0 <= warning.region.y - control.parent.region.bottom <= 1
        warning.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        # The warning is actionable text, so inspect the actual painted role
        # rather than trusting panel DEFAULT_CSS in the application cascade.
        registered = next(t for t in SERVONAUT_THEMES if t.name == theme)
        expected = Color.parse(registered.variables["text-warning"]).get_truecolor()
        styles = _painted_text_styles(warning, "Warning:")
        assert all(
            style.color and style.color.get_truecolor() == expected for style in styles
        ), {"theme": theme, "expected": expected, "painted": styles}
        # Theme-aware text spans must follow a palette change while mounted.
        other_theme = "servonaut-light" if theme == "servonaut" else "servonaut"
        app.theme = other_theme
        await pilot.pause()
        other_registered = next(
            t for t in SERVONAUT_THEMES if t.name == other_theme
        )
        other_expected = Color.parse(
            other_registered.variables["text-warning"],
        ).get_truecolor()
        assert all(
            style.color and style.color.get_truecolor() == other_expected
            for style in _painted_text_styles(warning, "Warning:")
        )
        assert _assert_save_exposed(app, panel_id).region == save_region
        await _tab_to(pilot, control)
        await pilot.press("enter", "home", "enter")
        await wait_until(lambda: control.value == "readonly")
        await pilot.pause()
        assert not warning.render().plain
        assert panel.has_unsaved_changes()
        assert _assert_save_exposed(app, panel_id).region == save_region


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize(
    "editor_id", ["ai_chat_system_prompt", "ai_chat_chat_system_prompt"],
)
async def test_prompt_editors_stay_full_width_with_native_f6_f7_selection(
    manager: ConfigManager, size: tuple[int, int], editor_id: str,
) -> None:
    app = _Host(manager, "ai_chat", navigation_visible=True)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        editor = panel.query_one(f"#{editor_id}", TextArea)
        body = panel.query_one(".panel-body", VerticalScroll)
        await _tab_to(pilot, editor)
        await pilot.pause()
        assert app.focused is editor
        # The editor fills its full-width section, allowing only the declared frame.
        section = editor.parent
        assert section is not None and section.has_class("settings-analysis-section")
        assert section.parent is body
        assert section.region.x == body.scrollable_content_region.x
        assert section.region.width == body.scrollable_content_region.width
        usable = section.scrollable_content_region
        assert usable.x - section.region.x == 2
        assert section.region.right - usable.right == 1
        assert editor.region.x == usable.x
        assert editor.region.width == usable.width
        editor.move_cursor((0, 0))
        await pilot.press("f6")
        assert editor.selected_text == "first café"
        await pilot.press("f7")
        assert editor.selected_text == PROMPT
        assert app.focused is editor
        assert not panel.has_unsaved_changes()
        _assert_save_exposed(app, "ai_chat")


@pytest.mark.asyncio
@pytest.mark.parametrize("panel_id,field_id,value", [
    ("vault", "vault_agent_key_ttl_seconds", "48"),
    ("relay", "relay_heartbeat_interval", "47"),
    ("ai_chat", "ai_chat_max_tool_rounds", "4"),
])
async def test_policy_save_clears_dirty_and_preserves_unexposed_configuration(
    manager: ConfigManager, tmp_path: Path, panel_id: str, field_id: str, value: str,
) -> None:
    expected = asdict(manager.get())
    app = _Host(manager, panel_id, navigation_visible=True)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        panel.query_one(f"#{field_id}", Input).value = value
        await pilot.pause()
        assert panel.has_unsaved_changes()
        assert "unsaved" in _painted(panel.query_one(f"#dirty_{panel_id}"))
        with patch.object(app, "notify", wraps=app.notify) as notify:
            assert await pilot.click(_assert_save_exposed(app, panel_id))
            await wait_until(lambda: not panel.has_unsaved_changes())
            notify.assert_any_call("Saved", severity="information", markup=False)
    if panel_id == "vault":
        expected["vault"]["agent_key_ttl_seconds"] = int(value)
    elif panel_id == "relay":
        expected["relay"]["heartbeat_interval"] = int(value)
    else:
        expected["chat_max_tool_rounds"] = int(value)
        expected["chat_inject_server_memory_decision"] = (
            "allowed" if expected["chat_inject_server_memory"] else "denied"
        )
    fresh = ConfigManager(config_path=tmp_path / "config.json").load()
    assert asdict(fresh) == expected


@pytest.mark.asyncio
async def test_invalid_vault_draft_keeps_native_switch_guard_and_discard_reload(
    manager: ConfigManager, tmp_path: Path,
) -> None:
    path = tmp_path / "config.json"
    saved_bytes = path.read_bytes()
    saved_poll = str(manager.get().vault.poll_after_seconds)
    app = _Host(manager, "vault", navigation_visible=True)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        screen = app.screen
        field = panel.query_one("#vault_poll_after_seconds", Input)
        await _tab_to(pilot, field)
        await pilot.press("ctrl+shift+a", "0")
        await wait_until(lambda: field.value == "0")
        assert panel.has_unsaved_changes()
        assert await pilot.click(_assert_save_exposed(app, "vault"))
        await wait_until(lambda: app.focused is field)
        assert panel.has_unsaved_changes() and field.has_class("field-error")
        assert "at least 1" in panel.query_one("#status_vault", Static).render().plain
        assert path.read_bytes() == saved_bytes

        await pilot.press("ctrl+f", *"history")
        destination = screen.query_one("#navbtn_history_paths", Button)
        await _tab_to(pilot, destination)
        await pilot.press("enter")
        await wait_until(lambda: isinstance(app.screen, DiscardChangesModal))
        assert await pilot.click("#discard-cancel")
        await wait_until(lambda: app.screen is screen)
        assert field.value == "0" and panel.has_unsaved_changes()
        assert path.read_bytes() == saved_bytes
        assert app.focused is not None
        assert screen.region.contains_region(app.focused.region)
        hit = app.get_widget_at(*app.focused.region.center)[0]
        assert hit is app.focused or app.focused in hit.ancestors

        await _tab_to(pilot, destination)
        await pilot.press("enter")
        await wait_until(lambda: isinstance(app.screen, DiscardChangesModal))
        assert await pilot.click("#discard-confirm")
        await wait_until(lambda: app.screen is screen)
        await _ready(app, pilot)
        assert screen._active_id == "history_paths"
        assert not panel.has_unsaved_changes() and field.value == saved_poll
        assert path.read_bytes() == saved_bytes

        await pilot.press("ctrl+f", "ctrl+shift+a", *"vault")
        vault = screen.query_one("#navbtn_vault", Button)
        await _tab_to(pilot, vault)
        await pilot.press("enter")
        await wait_until(lambda: screen._active_id == "vault")
        assert screen._current_panel() is panel
        assert field.value == saved_poll and not panel.has_unsaved_changes()
        assert set(screen._panels) == {"vault", "history_paths"}


@pytest.mark.asyncio
@pytest.mark.parametrize("panel_id,field_id,value", [
    ("vault", "vault_poll_after_seconds", "0"),
    ("relay", "relay_heartbeat_interval", "not a number"),
    ("ai_chat", "ai_chat_chunk_size", "0"),
])
async def test_invalid_policy_save_focuses_field_without_persisting(
    manager: ConfigManager, tmp_path: Path, panel_id: str, field_id: str, value: str,
) -> None:
    path = tmp_path / "config.json"
    before = path.read_bytes()
    app = _Host(manager, panel_id, navigation_visible=True)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        field = panel.query_one(f"#{field_id}", Input)
        field.value = value
        await pilot.pause()
        assert await pilot.click(_assert_save_exposed(app, panel_id))
        await pilot.pause()
        assert app.focused is field
        assert panel.has_unsaved_changes()
        assert panel.query_one(f"#status_{panel_id}", Static).render().plain
        assert path.read_bytes() == before
        _assert_save_exposed(app, panel_id)


@pytest.mark.asyncio
async def test_relay_demo_url_masks_preserve_raw_values_and_save_payload(
    manager: ConfigManager, tmp_path: Path,
) -> None:
    expected = asdict(manager.get())
    app = _Host(manager, "relay", navigation_visible=True)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        before = panel.current_values()
        app.action_toggle_demo()
        await pilot.pause()
        assert panel.query_one("#relay_base_url", Input).value != before["base_url"]
        assert (
            panel.query_one("#relay_mercure_url", Input).value != before["mercure_url"]
        )
        assert panel.current_values() == before
        assert not panel.has_unsaved_changes()
        changed_interval = int(before["heartbeat_interval"]) + 1
        panel.query_one("#relay_heartbeat_interval", Input).value = str(changed_interval)
        await pilot.pause()
        assert panel.has_unsaved_changes()
        expected["relay"]["heartbeat_interval"] = changed_interval
        expected_values = {**before, "heartbeat_interval": str(changed_interval)}
        assert await pilot.click(_assert_save_exposed(app, "relay"))
        await wait_until(lambda: not panel.has_unsaved_changes())
        assert panel.current_values() == expected_values
        app.action_toggle_demo()
        await pilot.pause()
        assert panel.current_values() == expected_values
    fresh = ConfigManager(config_path=tmp_path / "config.json").load()
    assert asdict(fresh) == expected
