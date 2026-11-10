"""Settings navigation, compact forms and pinned actions as users reach them."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest
from textual import events
from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import Button, Input, Select, Static

from servonaut.app import ServonautApp
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.screens.settings import shell
from servonaut.screens.settings.base import SettingsPanel
from servonaut.screens.settings.panels.general import GeneralPanel
from servonaut.screens.settings.registry import PANELS, PanelSpec
from servonaut.screens.settings.shell import DiscardChangesModal, SettingsScreen
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen
from tests._async_bounds import wait_until

pytestmark = pytest.mark.usefixtures("navigation_open")


@pytest.fixture
def manager(tmp_path: Path) -> ConfigManager:
    config = ConfigManager(config_path=tmp_path / "config.json")
    config.save(AppConfig())
    config.load()
    return config


class _Host(ServonautApp):
    def __init__(
        self,
        manager: ConfigManager,
        panel_id: str = "general",
        *,
        navigation_visible: bool = False,
    ) -> None:
        super().__init__()
        self.config_manager = manager
        self.workspace_state.navigation_visible = navigation_visible
        self.theme = manager.get().theme
        self.panel_id = panel_id

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        self.push_screen(SettingsScreen(self.panel_id))

    async def on_unmount(self, event: events.Unmount) -> None:
        event.prevent_default()


async def _ready(app: _Host, pilot: Pilot) -> SettingsPanel:
    await pilot.pause()
    await wait_until(lambda: isinstance(app.screen, SettingsScreen))
    await wait_until(lambda: app.screen._current_panel() is not None)
    panel = app.screen._current_panel()
    await wait_until(lambda: panel._loaded and not panel._settling)
    return panel


async def _tab_to(pilot: Pilot, target: Widget) -> None:
    """Reach a control through one complete native focus cycle."""
    for _ in range(len(pilot.app.screen.focus_chain) + 1):
        await pilot.press("tab")
        if pilot.app.focused is target:
            return
    raise AssertionError(f"{target!r} must be reachable with Tab")


def _assert_visible_in_nav(app: _Host, control: Widget) -> None:
    navigation = app.screen.query_one("#settings-nav-list", VerticalScroll)
    assert control.region.width > 0 and control.region.height > 0
    assert navigation.scrollable_content_region.contains_region(control.region)
    hit, _ = app.get_widget_at(*control.region.center)
    assert hit is control


def _painted_label(control: Widget) -> tuple[str, dict[str, Any]]:
    text = "\n".join(strip.text for strip in control.render_lines(control.region.size.region))
    return text, {
        "id": control.id,
        "painted": text,
        "region": tuple(control.region),
        "content_region": tuple(control.content_region),
        "padding": str(control.styles.padding),
        "line_pad": control.styles.line_pad,
        "text_align": control.styles.text_align,
        "content_align": str(control.styles.content_align),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_registered_category_names_are_actually_painted_in_the_narrow_rail(
    manager: ConfigManager, navigation_visible: bool,
) -> None:
    app = _Host(manager, navigation_visible=navigation_visible)
    async with app.run_test(size=(100, 30)) as pilot:
        await _ready(app, pilot)
        screen = app.screen
        await pilot.press("ctrl+f")
        clipped: list[dict[str, Any]] = []
        missing_tooltips: list[str] = []
        for group, section in screen._sections.items():
            header = section.query_one(".section-header", Button)
            await _tab_to(pilot, header)
            await pilot.pause()
            _assert_visible_in_nav(app, header)
            painted, diagnostic = _painted_label(header)
            chevron = "▶ " if section.collapsed else "▼ "
            expected_label = chevron + group
            assert header.label.plain == expected_label
            # The complete literal may wrap across native auto-height rows.
            if " ".join(painted.split()) != " ".join(expected_label.split()):
                clipped.append({"expected": expected_label, **diagnostic})
            # Native Button line padding sits inside the content region.
            start = header.content_region.x - header.region.x + header.styles.line_pad
            first_row = painted[start:].partition("\n")[0].rstrip(" ")
            if not first_row or not expected_label.startswith(first_row):
                clipped.append({"expected_left": expected_label, **diagnostic})
            if group not in str(header.tooltip or ""):
                missing_tooltips.append(group)
            if section.collapsed:
                await pilot.press("enter")
            for spec in (spec for spec in PANELS if spec.group == group):
                button = screen.query_one(f"#navbtn_{spec.id}", Button)
                await _tab_to(pilot, button)
                await pilot.pause()
                _assert_visible_in_nav(app, button)
                painted, diagnostic = _painted_label(button)
                if spec.title not in painted:
                    clipped.append({"expected": spec.title, **diagnostic})
                start = button.content_region.x - button.region.x + button.styles.line_pad
                if not painted[start:].startswith(spec.title):
                    clipped.append({"expected_left": spec.title, **diagnostic})
                if spec.title not in str(button.tooltip or ""):
                    missing_tooltips.append(spec.title)
                if spec.preview and "preview" not in str(button.tooltip or "").lower():
                    missing_tooltips.append(f"{spec.title} preview")
        if clipped:
            for diagnostic in clipped:
                print(diagnostic)
        assert not clipped, clipped
        assert not missing_tooltips, missing_tooltips


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["ansi-dark", "ansi-light"])
async def test_inactive_ansi_category_edge_paints_blank_without_a_dark_bar(
    manager: ConfigManager, monkeypatch: pytest.MonkeyPatch, theme: str,
) -> None:
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)
    manager.update(theme=theme)
    app = _Host(manager)
    async with app.run_test(size=(100, 30)) as pilot:
        await _ready(app, pilot)
        inactive = app.screen.query_one("#navbtn_history_paths", Button)
        first_line = inactive.render_lines(inactive.region.size.region)[0]
        edge = first_line.crop(0, 1)
        _, diagnostic = _painted_label(inactive)
        diagnostic["edge_segments"] = [(segment.text, str(segment.style)) for segment in edge]
        assert edge.text == " ", diagnostic
        assert inactive.get_style_at(0, 0).bgcolor == inactive.get_style_at(1, 0).bgcolor


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_validation_status_is_separate_from_the_scrolling_form(
    manager: ConfigManager, navigation_visible: bool,
) -> None:
    app = _Host(manager, "cloudtrail", navigation_visible=navigation_visible)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        field = panel.query_one("#cloudtrail_max_events", Input)
        field.value = "0"
        await pilot.pause()
        assert await pilot.click("#save_cloudtrail")
        await wait_until(lambda: field.has_class("field-error"))
        body = panel.query_one(".panel-body", VerticalScroll)
        status = panel.query_one("#status_cloudtrail", Static)
        save = panel.query_one("#save_cloudtrail", Button)
        assert "at least 1" in str(status.render())
        # The bordered form and zero-margin status are adjacent siblings.
        assert body.parent is status.parent is panel
        assert status.region.y >= body.region.bottom
        assert not status.region.overlaps(body.region)
        assert app.screen.region.contains_region(status.region)
        assert "at least 1" in _painted_label(status)[0]
        assert status.region.bottom <= save.region.y
        assert app.screen.region.contains_region(save.region)
        assert app.get_widget_at(*save.region.center)[0] is save


@pytest.mark.asyncio
async def test_search_without_matches_keeps_form_and_has_clear_recovery(
    manager: ConfigManager,
) -> None:
    app = _Host(manager)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        screen = app.screen
        await pilot.press("ctrl+f", *"no-such-setting")
        await wait_until(lambda: screen.query_one("#settings-search-empty").display)
        assert "No matching settings" in str(
            screen.query_one("#settings-search-empty", Static).render()
        )
        assert list(screen._panels) == ["general"]
        assert screen._current_panel() is panel
        assert panel.display
        assert not any(section.display for section in screen._sections.values())
        assert await pilot.click("#settings-search-clear")
        await wait_until(lambda: screen.query_one("#settings-search", Input).value == "")
        assert not screen.query_one("#settings-search-empty").display
        assert all(screen.query_one(f"#navbtn_{spec.id}").display for spec in PANELS)
        assert app.focused is screen.query_one("#settings-search")
        assert screen._current_panel() is panel


@pytest.mark.asyncio
async def test_category_group_can_be_focused_and_expanded_by_keyboard(
    manager: ConfigManager,
) -> None:
    app = _Host(manager)
    async with app.run_test(size=(100, 30)) as pilot:
        await _ready(app, pilot)
        section = app.screen._sections["Cloud Providers"]
        header = section.query_one(".section-header", Button)
        await pilot.press("ctrl+f")
        assert app.focused is app.screen.query_one("#settings-search")
        await _tab_to(pilot, header)
        assert section.collapsed
        await pilot.press("enter")
        await wait_until(lambda: not section.collapsed)
        await pilot.press("tab")
        assert app.focused is app.screen.query_one("#navbtn_aws")


@pytest.mark.asyncio
@pytest.mark.parametrize("clear_search_first", [False, True])
async def test_last_category_group_is_visible_when_reached_and_opened_by_keyboard(
    manager: ConfigManager, clear_search_first: bool,
) -> None:
    app = _Host(manager, navigation_visible=True)
    async with app.run_test(size=(100, 30)) as pilot:
        await _ready(app, pilot)
        screen = app.screen
        await pilot.press("ctrl+f")
        if clear_search_first:
            await pilot.press(*"no such setting")
            await wait_until(lambda: screen.query_one("#settings-search-empty").display)
            assert await pilot.click("#settings-search-clear")
            await wait_until(lambda: screen.query_one("#settings-search", Input).value == "")
        assert app.focused is screen.query_one("#settings-search")
        group, section = next(reversed(screen._sections.items()))
        header = section.query_one(".section-header", Button)
        assert section.collapsed
        await _tab_to(pilot, header)
        await pilot.pause()
        _assert_visible_in_nav(app, header)
        await pilot.press("enter")
        await wait_until(lambda: not section.collapsed)
        await pilot.press("tab")
        first_id = next(spec.id for spec in PANELS if spec.group == group)
        destination = screen.query_one(f"#navbtn_{first_id}", Button)
        assert app.focused is destination
        await pilot.pause()
        _assert_visible_in_nav(app, destination)


class _ChildWorkspace(WorkspaceScreen):
    BINDINGS = [("escape", "back", "Back")]

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield WorkspaceControls("Child view")
        with Horizontal(id="main-layout"):
            yield self.workspace_sidebar()
            yield Input(id="child-input")

    def action_back(self) -> None:
        self.app.pop_screen()


@pytest.mark.asyncio
async def test_resuming_settings_applies_changed_workspace_preference_and_refreshes_once(
    manager: ConfigManager, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _Host(manager, navigation_visible=False)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        parent = app.screen
        sidebar = parent.query_one(Sidebar)
        panel.query_one("#general_username", Input).value = "keep-this-draft"
        await pilot.pause()
        applied: list[str] = []
        refreshed: list[str] = []
        original_apply = parent.apply_workspace_state
        original_refresh = panel.refresh_external_state

        def apply_workspace() -> None:
            applied.append("apply")
            original_apply()

        def refresh_panel() -> None:
            refreshed.append("refresh")
            original_refresh()

        monkeypatch.setattr(parent, "apply_workspace_state", apply_workspace)
        monkeypatch.setattr(panel, "refresh_external_state", refresh_panel)
        child = _ChildWorkspace()
        await app.push_screen(child)
        assert await pilot.click("#workspace_navigation")
        await wait_until(lambda: child.query_one(Sidebar).display)
        assert app.workspace_state.navigation_visible
        assert not sidebar.display
        assert applied == [] and refreshed == []
        await pilot.press("escape")
        await wait_until(lambda: app.screen is parent and sidebar.display)
        await pilot.pause()
        assert applied == ["apply"]
        assert refreshed == ["refresh"]
        assert parent._current_panel() is panel
        assert panel.query_one("#general_username", Input).value == "keep-this-draft"


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_workspace_toggle_preserves_form_and_keeps_settings_controls_usable(
    manager: ConfigManager, size: tuple[int, int], navigation_visible: bool,
) -> None:
    app = _Host(manager, navigation_visible=navigation_visible)
    async with app.run_test(size=size) as pilot:
        panel = await _ready(app, pilot)
        field = panel.query_one("#general_username", Input)
        field.value = "deploy"
        await pilot.pause()
        sidebar = app.screen.query_one(Sidebar)
        assert sidebar.display is navigation_visible
        toggle = app.screen.query_one("#workspace_navigation", Button)
        for expected_visibility in (not navigation_visible, navigation_visible):
            await wait_until(lambda: not toggle.has_class("-active"))
            assert await pilot.click(toggle)
            await wait_until(lambda: sidebar.display is expected_visibility)
            assert app.workspace_state.navigation_visible is expected_visibility
            assert app.screen._current_panel() is panel
            assert field.value == "deploy"
            for selector in ("#settings-search", "#save_general", "#settings-back"):
                control = app.screen.query_one(selector)
                assert control.region.width > 0 and control.region.height > 0
                assert app.screen.region.contains_region(control.region)
                widget, _ = app.get_widget_at(*control.region.center)
                assert widget is control


@pytest.mark.asyncio
async def test_contextual_back_obeys_existing_dirty_guard(manager: ConfigManager) -> None:
    app = _Host(manager)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        screen = app.screen
        panel.query_one("#general_username", Input).value = "unsaved-user"
        await pilot.pause()
        assert await pilot.click("#settings-back")
        await wait_until(lambda: isinstance(app.screen, DiscardChangesModal))
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
        assert panel.query_one("#general_username", Input).value == "unsaved-user"
        assert panel.has_unsaved_changes()


@pytest.mark.asyncio
async def test_failed_initial_factory_falls_through_and_is_cached(
    manager: ConfigManager, monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts: list[str] = []

    def unavailable() -> type[SettingsPanel]:
        attempts.append("unavailable")
        raise RuntimeError("Panel is unavailable")

    monkeypatch.setattr(shell, "PANELS", [
        PanelSpec("unavailable", "Unavailable", "General", factory=unavailable),
        PanelSpec("general", "General", "General", factory=lambda: GeneralPanel),
    ])
    app = _Host(manager, "unavailable")
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        screen = app.screen
        assert panel.PANEL_ID == "general"
        assert attempts == ["unavailable"]
        assert not screen.query_one("#placeholder_unavailable").display
        screen.show_panel("unavailable")
        await pilot.pause()
        assert screen.query_one("#placeholder_unavailable").display
        screen.show_panel("general")
        screen.show_panel("unavailable")
        await pilot.pause()
        assert attempts == ["unavailable"]
        assert list(screen._panels) == ["general"]


_SCALAR_EDITS = [
    ("history_paths", {
        "hp_keyword_store_path": ("keyword_store_path", "{root}/keywords-next.json"),
        "hp_command_history_path": ("command_history_path", "{root}/commands-next.json"),
        "hp_max_command_history": ("max_command_history", 21),
        "hp_chat_history_path": ("chat_history_path", "{root}/chats-next"),
    }),
    ("cloudtrail", {
        "cloudtrail_default_region": ("cloudtrail_default_region", "region-2"),
        "cloudtrail_max_events": ("cloudtrail_max_events", 37),
        "cloudtrail_default_lookback_hours": ("cloudtrail_default_lookback_hours", 0),
        "cloudtrail_default_lookback_minutes": ("cloudtrail_default_lookback_minutes", 5),
    }),
    ("cloudwatch", {
        "cloudwatch_default_region": ("cloudwatch_default_region", ""),
        "cloudwatch_max_events": ("cloudwatch_max_events", 1),
        "cloudwatch_log_group_prefix": ("cloudwatch_log_group_prefix", "/applications/"),
    }),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("panel_id,edits", _SCALAR_EDITS)
async def test_scalar_save_roundtrips_every_field_and_preserves_other_configuration(
    manager: ConfigManager, tmp_path: Path, panel_id: str,
    edits: dict[str, tuple[str, Any]],
) -> None:
    expected = asdict(manager.get())
    app = _Host(manager, panel_id)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        for field_id, (config_key, value) in edits.items():
            value = value.format(root=tmp_path) if isinstance(value, str) else value
            panel.query_one(f"#{field_id}", Input).value = str(value)
            expected[config_key] = value
        await pilot.pause()
        assert await pilot.click(f"#save_{panel_id}")
        await wait_until(lambda: not panel.has_unsaved_changes())
    fresh = ConfigManager(config_path=tmp_path / "config.json").load()
    assert asdict(fresh) == expected


_INVALID_FIELDS = [
    ("general", "general_username", "", "cannot be empty"),
    ("history_paths", "hp_keyword_store_path", "", "cannot be empty"),
    ("history_paths", "hp_command_history_path", "", "cannot be empty"),
    ("history_paths", "hp_chat_history_path", "", "cannot be empty"),
    ("history_paths", "hp_max_command_history", "0", "at least 1"),
    ("cloudtrail", "cloudtrail_max_events", "0", "at least 1"),
    ("cloudtrail", "cloudtrail_default_lookback_hours", "-1", "zero or greater"),
    ("cloudtrail", "cloudtrail_default_lookback_minutes", "-1", "zero or greater"),
    ("cloudwatch", "cloudwatch_max_events", "invalid", "whole number"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("panel_id,field_id,value,message", _INVALID_FIELDS)
async def test_invalid_scalar_save_focuses_field_and_leaves_disk_unchanged(
    manager: ConfigManager, tmp_path: Path, panel_id: str,
    field_id: str, value: str, message: str,
) -> None:
    before = (tmp_path / "config.json").read_bytes()
    app = _Host(manager, panel_id)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        field = panel.query_one(f"#{field_id}", Input)
        field.value = value
        await pilot.pause()
        assert await pilot.click(f"#save_{panel_id}")
        await wait_until(lambda: field.has_class("field-error") and app.focused is field)
        assert message in str(panel.query_one(f"#status_{panel_id}", Static).render())
        assert (tmp_path / "config.json").read_bytes() == before
