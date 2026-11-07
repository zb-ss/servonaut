"""Workspace controls preserve content and the existing screen-stack behavior."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from textual import events
from textual.app import ComposeResult
from textual.command import CommandList, CommandPalette
from textual.containers import Horizontal
from textual.pilot import Pilot
from textual.screen import Screen
from textual.widgets import Button, Input, TextArea

from servonaut.app import ServonautApp
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.instance_table import InstanceTable
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.sidebar_section import SidebarSection
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen
from tests._async_bounds import wait_until


def _row(name: str) -> dict:
    return {
        "id": f"id-{name}", "name": name, "type": "small", "state": "running",
        "public_ip": "192.0.2.10", "private_ip": "10.0.0.1", "region": "local",
        "key_name": "", "is_custom": True,
    }


class _Host(ServonautApp):
    def __init__(self, *, navigation_visible: bool = True) -> None:
        super().__init__()
        self.workspace_state.navigation_visible = navigation_visible
        self.instances = [_row("web-1"), _row("db-1")]
        self.cache_service = SimpleNamespace(
            is_fresh=lambda: True, get_age=lambda: None, load_any=lambda: [],
        )

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        self.push_screen(InstanceListScreen())

    async def on_unmount(self, event: events.Unmount) -> None:
        event.prevent_default()


class _UnpilotedScreen(Screen):
    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Sidebar()
            yield Input()


class _RoutingHost(_Host):
    def __init__(self) -> None:
        super().__init__()
        self.destinations: list[str | None] = []

    def on_sidebar_navigation_requested(self, message: Sidebar.NavigationRequested) -> None:
        message.prevent_default()
        self.destinations.append(message.target_id)


class _DelayedSidebarScreen(WorkspaceScreen):
    """Attach the rail only after the permanent controls have mounted."""

    def compose(self) -> ComposeResult:
        yield WorkspaceControls("Delayed navigation")
        yield Input()

    async def on_mount(self) -> None:
        await self.mount(self.workspace_sidebar())
        self.apply_workspace_state()


def _assert_controls_clickable(app: ServonautApp) -> None:
    for button_id in ("workspace_navigation", "workspace_chat"):
        button = app.screen.query_one(f"#{button_id}", Button)
        assert button.region.width > 0
        assert button.region.height == 1
        assert app.get_widget_at(*button.region.center)[0] is button


async def _click(pilot: Pilot, selector: str) -> None:
    button = pilot.app.screen.query_one(selector, Button)
    await wait_until(lambda: not button.has_class("-active"))
    assert await pilot.click(selector)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_navigation_toggle_reclaims_width_without_changing_content(size: tuple) -> None:
    app = _Host()
    async with app.run_test(size=size) as pilot:
        screen = app.screen
        table = screen.query_one(InstanceTable)
        assert app.focused is table
        table.move_cursor(row=1)
        await pilot.pause()
        old_width = table.region.width
        old_row = table.cursor_row
        sidebar_width = screen.query_one(Sidebar).region.width
        details = screen.query_one("#instance_detail", TextArea)
        original_text = details.text
        await _click(pilot, "#workspace_navigation")
        await pilot.pause()
        assert not screen.query_one(Sidebar).display
        assert table.region.width == old_width + sidebar_width
        assert table.cursor_row == old_row
        assert details.text == original_text
        assert app.focused is table
        _assert_controls_clickable(app)
        await _click(pilot, "#workspace_navigation")
        await pilot.pause()
        assert table.region.width == old_width


@pytest.mark.asyncio
@pytest.mark.parametrize("visible", [False, True])
async def test_push_and_pop_apply_preference_without_losing_fleet_state(visible: bool) -> None:
    app = _Host(navigation_visible=visible)
    async with app.run_test(size=(100, 30)) as pilot:
        fleet = app.screen
        table = fleet.query_one(InstanceTable)
        assert app.focused is table
        assert fleet.query_one(Sidebar).display is visible
        table.move_cursor(row=1)
        await pilot.press("o")
        actions = app.screen
        assert isinstance(actions, ServerActionsScreen)
        assert app.focused is actions.query_one("#btn_browse", Button)
        assert actions.query_one(Sidebar).display is visible
        await _click(pilot, "#workspace_navigation")
        await pilot.press("9")
        assert app.screen is fleet
        assert fleet.query_one(Sidebar).display is not visible
        assert table.cursor_row == 1
        assert app.focused is table
        await app.push_screen(_UnpilotedScreen())
        await pilot.pause()
        assert app.screen.query_one(Sidebar).display
        assert not app.screen.query(WorkspaceControls)
        assert app.check_action("focus_navigation", ()) is False


@pytest.mark.asyncio
@pytest.mark.parametrize("visible", [False, True])
@pytest.mark.parametrize("leave", ["escape", "shift+f6"])
async def test_explicit_navigation_returns_to_content(visible: bool, leave: str) -> None:
    app = _Host(navigation_visible=visible)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = app.screen
        search = screen.query_one("#search_input", Input)
        search.focus()
        await pilot.press("shift+f6")
        await pilot.pause()
        sidebar = screen.query_one(Sidebar)
        assert sidebar.navigation_mode
        assert sidebar.display
        assert app.focused is sidebar.query_one("#nav_list", Button)
        assert all(not button.can_focus for button in sidebar.query(Button) if not button.visible)
        await pilot.press(leave)
        await pilot.pause()
        assert app.focused is search
        assert not sidebar.navigation_mode
        assert sidebar.display is visible
        assert app.workspace_state.navigation_visible is visible
        assert not any(button.can_focus for button in sidebar.query(Button))


@pytest.mark.asyncio
async def test_navigation_blocks_fleet_letters_and_does_not_pop_actions_on_escape() -> None:
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        fleet = app.screen
        fleet.action_ssh_connect = Mock()
        await pilot.press("shift+f6", "s")
        fleet.action_ssh_connect.assert_not_called()
        await pilot.press("escape", "o")
        actions = app.screen
        assert isinstance(actions, ServerActionsScreen)
        await pilot.press("shift+f6", "escape")
        assert app.screen is actions
        assert app.focused is actions.query_one("#btn_browse", Button)
        await pilot.press("escape")
        assert app.screen is fleet


@pytest.mark.asyncio
@pytest.mark.parametrize("leave", ["escape", "shift+f6"])
async def test_navigation_returns_safely_if_the_previous_control_was_removed(leave: str) -> None:
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        screen = app.screen
        search = screen.query_one("#search_input", Input)
        search.focus()
        await pilot.press("shift+f6")
        await search.remove()
        await pilot.press(leave)
        await pilot.pause()
        assert app.screen is screen
        assert not screen.query_one(Sidebar).navigation_mode
        assert app.focused is screen.query_one(InstanceTable)


@pytest.mark.asyncio
async def test_tab_out_and_mouse_hide_leave_navigation_without_stealing_focus() -> None:
    app = _Host(navigation_visible=False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        table = screen.query_one(InstanceTable)
        sidebar = screen.query_one(Sidebar)
        await pilot.press("shift+f6")
        await pilot.pause()
        sidebar.query_one("#nav_quit", Button).focus()
        await pilot.press("tab")
        await pilot.pause()
        assert not sidebar.navigation_mode
        assert not sidebar.display
        assert app.focused is screen.query_one("#search_input", Input)
        table.focus()
        await _click(pilot, "#workspace_navigation")
        await pilot.press("shift+f6")
        await _click(pilot, "#workspace_navigation")
        await pilot.pause()
        assert not sidebar.display
        assert not sidebar.navigation_mode
        assert app.focused is table


@pytest.mark.asyncio
async def test_mouse_hide_uses_the_temporarily_visible_navigation_state() -> None:
    app = _Host(navigation_visible=False)
    async with app.run_test(size=(100, 30)) as pilot:
        table = app.screen.query_one(InstanceTable)
        await pilot.press("shift+f6")
        sidebar = app.screen.query_one(Sidebar)
        assert sidebar.display and sidebar.navigation_mode
        assert "Hide navigation" in str(app.screen.query_one("#workspace_navigation").tooltip)
        await _click(pilot, "#workspace_navigation")
        await pilot.pause()
        assert not sidebar.display
        assert not sidebar.navigation_mode
        assert not app.workspace_state.navigation_visible
        assert app.focused is table


@pytest.mark.asyncio
async def test_navigation_enter_and_click_emit_the_same_destination() -> None:
    app = _RoutingHost()
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.press("shift+f6", "enter")
        await pilot.pause()
        await _click(pilot, "#nav_list")
        assert app.destinations == ["nav_list", "nav_list"]
        section = app.screen.query_one("#section_tools", SidebarSection)
        section.query_one(".section-header", Button).focus()
        await pilot.press("enter")
        await pilot.pause()
        assert not section.collapsed
        assert section.query_one("#nav_settings", Button).can_focus
        assert not app.screen.query_one("#nav_teams", Button).can_focus


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["textual-dark", "textual-light", "servonaut", "nord"])
async def test_navigation_focus_has_a_non_color_cue(theme: str) -> None:
    app = _Host()
    app.theme = theme
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("shift+f6")
        await pilot.pause()
        button = app.screen.query_one("#nav_list", Button)
        assert app.focused is button
        label_segments = [
            segment for y in range(button.size.height) for segment in button.render_line(y)
            if "Instances" in segment.text
        ]
        assert label_segments and all(
            segment.style and segment.style.underline for segment in label_segments
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("modal_kind", ["confirmation", "palette"])
async def test_workspace_keys_are_inert_inside_modals(modal_kind: str) -> None:
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        fleet = app.screen
        if modal_kind == "confirmation":
            await app.push_screen(ConfirmActionScreen(
                title="Delete", description="Delete a server", consequences=[],
                confirm_text="web-1", action_label="Delete",
            ))
        else:
            await pilot.press("ctrl+p")
        modal = app.screen
        assert isinstance(modal, (ConfirmActionScreen, CommandPalette))
        focus = app.focused
        await pilot.press("f2", "ctrl+g", "shift+f6")
        assert app.screen is modal
        assert app.focused is focus
        assert app.workspace_state.navigation_visible
        assert not fleet.query("#chat-panel")
        assert not fleet.query_one(Sidebar).navigation_mode
        app.action_toggle_navigation()
        app.action_focus_navigation()
        assert app.workspace_state.navigation_visible


@pytest.mark.asyncio
async def test_navigation_preference_survives_resize_theme_and_navigation_holds() -> None:
    app = _Host(navigation_visible=False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        app.theme = "servonaut-light"
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert not screen.query_one(Sidebar).display
        screen.navigation_hold_reason = lambda: "An operation is still running."
        await pilot.press("shift+f6")
        await _click(pilot, "#workspace_navigation")
        assert not screen.query_one(Sidebar).display
        assert app.workspace_state.navigation_visible is False


@pytest.mark.asyncio
@pytest.mark.parametrize("visible", [False, True])
async def test_chat_overlay_keeps_controls_and_text_selection_usable(
    monkeypatch: pytest.MonkeyPatch, visible: bool,
) -> None:
    # Rendering/focus is under test; no session, model or microphone is started.
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    app = _Host(navigation_visible=visible)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = app.screen
        detail = screen.query_one("#instance_detail", TextArea)
        detail.load_text("Name: web-1\nFull value: example-server-with-a-long-identifier")
        detail.focus()
        await pilot.press("f6")
        assert detail.selected_text == "Name: web-1"
        await pilot.press("f7")
        assert detail.selected_text == detail.text
        await _click(pilot, "#workspace_chat")
        await pilot.pause()
        panel = screen.query_one(ChatPanel)
        assert panel.display
        assert screen.query_one(Sidebar).display is visible
        _assert_controls_clickable(app)
        composer = panel.query_one("#chat-input", TextArea)
        composer.load_text("An unsent draft\nSecond line")
        composer.focus()
        await pilot.press("f6")
        assert composer.selected_text == "An unsent draft"
        await pilot.press("f7")
        assert composer.selected_text == composer.text
        composer.move_cursor((1, 5))
        await pilot.press("ctrl+a")
        assert composer.cursor_location == (1, 0)
        await _click(pilot, "#workspace_navigation")
        await pilot.pause()
        assert composer.text == "An unsent draft\nSecond line"
        assert app.focused is composer
        detail.focus()
        app.copy_to_clipboard = Mock()
        await pilot.press("f7", "ctrl+c")
        assert detail.selected_text == detail.text
        app.copy_to_clipboard.assert_called_once_with(detail.text)
        await _click(pilot, "#workspace_chat")
        await pilot.pause()
        assert screen.query_one(ChatPanel)._collapsed
        _assert_controls_clickable(app)


@pytest.mark.asyncio
async def test_workspace_actions_are_inert_after_app_exit() -> None:
    app = _Host()
    async with app.run_test(size=(100, 30)):
        pass
    assert app.screen_stack == []
    assert app.check_action("focus_navigation", ()) is False
    assert app.check_action("toggle_navigation", ()) is False
    app.action_focus_navigation()
    app.action_toggle_navigation()


@pytest.mark.asyncio
async def test_controls_allow_delayed_sidebar_mount_and_late_callbacks() -> None:
    app = _Host(navigation_visible=False)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = _DelayedSidebarScreen()
        await app.push_screen(screen)
        await pilot.pause()
        assert not screen.query_one(Sidebar).display
        controls = screen.query_one(WorkspaceControls)
        await controls.remove()
        screen.call_after_refresh(controls.sync_state)
        await pilot.pause()


@pytest.mark.asyncio
async def test_controls_ignore_a_callback_queued_after_their_removal() -> None:
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        screen = app.screen
        controls = screen.query_one(WorkspaceControls)
        await controls.remove()
        screen.call_after_refresh(controls.sync_state)
        await pilot.pause()


@pytest.mark.asyncio
async def test_workspace_layers_keep_framework_overlays_once_and_above_controls() -> None:
    app = _Host()
    async with app.run_test(size=(100, 30), notifications=True, tooltips=True):
        layers = app.screen.layers
        assert len(layers) == len(set(layers))
        assert layers.index("workspace") < layers.index("_loading")
        assert layers.index("workspace") < layers.index("_toastrack") < layers.index("_tooltips")


@pytest.mark.asyncio
@pytest.mark.parametrize("modal_kind", ["confirmation", "palette"])
@pytest.mark.parametrize("pilot_screen", ["fleet", "actions"])
async def test_suspend_navigation_preserves_origin_and_modal_focus(
    modal_kind: str, pilot_screen: str,
) -> None:
    app = _Host(navigation_visible=False)
    async with app.run_test(size=(100, 30)) as pilot:
        if pilot_screen == "actions":
            await pilot.press("o")
        content_screen = app.screen
        origin = (content_screen.query_one("#instance_detail", TextArea)
                  if pilot_screen == "fleet"
                  else content_screen.query_one("#btn_browse", Button))
        origin.focus()
        await pilot.press("shift+f6")
        assert content_screen.query_one(Sidebar).navigation_mode
        if modal_kind == "confirmation":
            await app.push_screen(ConfirmActionScreen(
                title="Delete", description="Delete a server", consequences=[],
                confirm_text="web-1", action_label="Delete",
            ))
        else:
            await pilot.press("ctrl+p")
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, (ConfirmActionScreen, CommandPalette))
        modal_focus = modal.focused
        assert modal_focus is not None and modal_focus.screen is modal
        assert app.focused is modal_focus
        assert content_screen.focused is origin
        assert not content_screen.query_one(Sidebar).navigation_mode
        await pilot.press("escape")
        await pilot.pause()
        assert app.screen is content_screen
        assert app.focused is origin
        assert not content_screen.query_one(Sidebar).display


@pytest.mark.asyncio
@pytest.mark.parametrize("pilot_screen", ["fleet", "actions"])
async def test_collapsing_previous_chat_focus_returns_to_primary_content(
    monkeypatch: pytest.MonkeyPatch, pilot_screen: str,
) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        if pilot_screen == "actions":
            await pilot.press("o")
        screen = app.screen
        await pilot.press("f2")
        await pilot.pause()
        composer = screen.query_one("#chat-input", TextArea)
        composer.focus()
        await pilot.press("shift+f6", "f2")
        await pilot.pause()
        assert screen.query_one(ChatPanel)._collapsed
        await pilot.press("escape")
        await pilot.pause()
        primary = (screen.query_one(InstanceTable) if pilot_screen == "fleet"
                   else screen.query_one("#btn_browse", Button))
        assert app.screen is screen
        assert app.focused is primary


@pytest.mark.asyncio
async def test_search_shortcut_leaves_navigation_but_row_shortcuts_stay_muted() -> None:
    app = _Host(navigation_visible=False)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = app.screen
        screen.action_ssh_connect = Mock()
        await pilot.press("shift+f6", "s", "slash")
        await pilot.pause()
        screen.action_ssh_connect.assert_not_called()
        assert app.focused is screen.query_one("#search_input", Input)
        assert not screen.query_one(Sidebar).navigation_mode
        assert not screen.query_one(Sidebar).display


@pytest.mark.asyncio
async def test_palette_selection_toggles_navigation_after_returning_to_content() -> None:
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        fleet = app.screen
        origin = fleet.query_one("#instance_detail", TextArea)
        origin.focus()
        for expected_visible in (False, True):
            await pilot.press("ctrl+p", *"Toggle navigation")
            commands = app.screen.query_one(CommandList)
            await wait_until(lambda: commands.option_count == 1)
            assert str(commands.get_option_at_index(0).hit.text) == "Toggle navigation"
            await pilot.press("enter")
            await wait_until(lambda: app.screen is fleet)
            await pilot.pause()
            assert fleet.query_one(Sidebar).display is expected_visible
            assert app.workspace_state.navigation_visible is expected_visible
            assert app.focused is origin
