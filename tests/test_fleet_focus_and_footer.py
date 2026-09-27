"""Where keyboard focus starts on the fleet screen, and what its footer lists.

The fleet screen opens on the table, so the arrow keys and the fleet
shortcuts work at once. When the search box has focus, the footer still
lists the fleet shortcuts, greyed out, while every letter typed goes into
the box. Nothing in the sidebar ever takes focus, so no screen can open on
it by accident.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Input

from servonaut.screens.instance_list import FleetSearchInput, InstanceListScreen
from servonaut.widgets.instance_table import InstanceTable
from servonaut.widgets.sidebar import Sidebar

# The single-letter fleet shortcuts (``/`` itself moves to the search box).
_SHORTCUT_KEYS = {"r", "o", "s", "b", "c", "t", "l", "a", "m", "D", "k", "v", "y"}


def _row(name: str) -> dict:
    return {
        "id": f"id-{name}",
        "name": name,
        "type": "t3.micro",
        "state": "running",
        "public_ip": "",
        "private_ip": "10.0.0.1",
        "region": "us-east-1",
        "key_name": "",
    }


class _FleetHost(App):
    """Just enough of the app for the fleet screen to open with two rows."""

    def __init__(self) -> None:
        super().__init__()
        self.instances = [_row("app-1"), _row("db-1")]
        self.cache_service = SimpleNamespace(
            is_fresh=lambda: True, get_age=lambda: None, load_any=lambda: []
        )
        self.ovh_service = None
        self.hetzner_service = None

    def on_mount(self) -> None:
        self.push_screen(InstanceListScreen())


async def _open_fleet(pilot) -> InstanceListScreen:
    for _ in range(50):
        await pilot.pause()
        screen = pilot.app.screen
        if isinstance(screen, InstanceListScreen) and screen.query(InstanceTable):
            return screen
    raise AssertionError("the fleet screen did not open")


def _footer_keys(screen: Screen) -> dict:
    """Shown bindings as the footer lists them: key -> enabled."""
    return {
        key: active.enabled
        for key, active in screen.active_bindings.items()
        if active.binding.show
    }


@pytest.mark.asyncio
async def test_the_fleet_screen_opens_with_the_table_focused() -> None:
    app = _FleetHost()
    async with app.run_test(size=(160, 40)) as pilot:
        await _open_fleet(pilot)
        assert isinstance(app.focused, InstanceTable)


@pytest.mark.asyncio
async def test_the_table_takes_the_arrow_keys_and_shortcuts_at_once() -> None:
    app = _FleetHost()
    async with app.run_test(size=(160, 40)) as pilot:
        screen = await _open_fleet(pilot)
        table = screen.query_one(InstanceTable)
        await pilot.press("down")
        assert table.cursor_row == 1
        footer = _footer_keys(screen)
        assert {key for key in _SHORTCUT_KEYS if footer.get(key)} == _SHORTCUT_KEYS


@pytest.mark.asyncio
async def test_the_footer_keeps_the_shortcuts_greyed_while_searching() -> None:
    app = _FleetHost()
    async with app.run_test(size=(160, 40)) as pilot:
        screen = await _open_fleet(pilot)
        await pilot.press("slash")
        assert isinstance(app.focused, FleetSearchInput)

        footer = _footer_keys(screen)
        missing = _SHORTCUT_KEYS - footer.keys()
        assert not missing, f"footer dropped {sorted(missing)} while searching"
        assert not any(footer[key] for key in _SHORTCUT_KEYS), footer


@pytest.mark.asyncio
async def test_shortcut_letters_typed_in_the_search_box_are_text() -> None:
    app = _FleetHost()
    async with app.run_test(size=(160, 40)) as pilot:
        await _open_fleet(pilot)
        depth = len(app.screen_stack)
        await pilot.press("slash", "s", "D", "b")
        await pilot.pause()

        assert app.screen_stack[-1] is app.screen
        assert len(app.screen_stack) == depth, "a shortcut ran while typing"
        assert app.screen.query_one("#search_input", Input).value == "sDb"


def test_keys_the_screen_does_not_bind_are_still_consumed_as_text() -> None:
    box = FleetSearchInput(frozenset({"s"}))
    assert box.check_consume_key("s", "s") is False
    assert box.check_consume_key("q", "q") is True
    assert box.check_consume_key("enter", None) is False


class _ProbeSidebar(Sidebar):
    """Records which sidebar widgets could take focus as the sidebar mounts.

    Textual runs each class's ``on_mount`` handler, subclass first, so this
    one sees the sidebar before ``Sidebar.on_mount`` has run: the state a
    screen's first auto-focus pass can meet.
    """

    focusable_at_mount: list = []

    def on_mount(self) -> None:
        self.focusable_at_mount = [
            f"{type(widget).__name__}#{widget.id}"
            for widget in self.query("*")
            if widget.can_focus
        ]


class _SidebarHost(App):
    """A screen with default auto-focus: its first focusable widget."""

    def compose(self) -> ComposeResult:
        yield _ProbeSidebar()
        yield Input(id="first_control")


@pytest.mark.asyncio
async def test_a_screen_never_opens_with_the_sidebar_focused() -> None:
    app = _SidebarHost()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert app.focused is app.query_one("#first_control")
        sidebar = app.query_one(_ProbeSidebar)
        # Unfocusable from construction, not only once Sidebar.on_mount runs:
        # how start-up timing orders the two differs between Python versions.
        assert sidebar.focusable_at_mount == []
        assert not [widget for widget in sidebar.query("*") if widget.can_focus]


# ---------------------------------------------------------------------------
# Footer width
# ---------------------------------------------------------------------------


def _footer_layout(screen: Screen) -> tuple:
    """The footer's width, its drawn keys and where the palette key starts."""
    from textual.widgets import Footer
    from textual.widgets._footer import FooterKey

    footer = screen.query_one(Footer)
    keys = [key for key in footer.query(FooterKey) if "-command-palette" not in key.classes]
    palette = [key for key in footer.query(FooterKey) if "-command-palette" in key.classes]
    right_edge = palette[0].region.x if palette else footer.region.right
    return footer, keys, right_edge


@pytest.mark.asyncio
@pytest.mark.parametrize("width", [80, 100, 120, 160, 220])
async def test_every_footer_label_is_drawn_whole(width: int) -> None:
    app = _FleetHost()
    async with app.run_test(size=(width, 30)) as pilot:
        screen = await _open_fleet(pilot)
        await pilot.pause()
        _, keys, right_edge = _footer_layout(screen)
        assert keys, "the footer lists no shortcut"
        cut = [
            f"{key.key} {key.description}"
            for key in keys
            if key.region.right > right_edge or key.region.width < key.get_content_width(
                key.size, key.size
            )
        ]
        assert not cut, f"cut at {width} columns: {cut}"


@pytest.mark.asyncio
async def test_the_footer_refits_when_the_terminal_is_resized() -> None:
    app = _FleetHost()
    async with app.run_test(size=(220, 30)) as pilot:
        screen = await _open_fleet(pilot)
        wide = {key.key for key in _footer_layout(screen)[1]}
        await pilot.resize_terminal(100, 30)
        for _ in range(5):
            await pilot.pause()
        narrow = {key.key for key in _footer_layout(screen)[1]}
        assert narrow < wide
        # The most useful shortcuts stay.
        assert {"o", "slash", "s"} <= narrow


@pytest.mark.asyncio
async def test_shortcuts_left_out_of_the_footer_still_work() -> None:
    app = _FleetHost()
    async with app.run_test(size=(80, 30)) as pilot:
        screen = await _open_fleet(pilot)
        shown = {key.key for key in _footer_layout(screen)[1]}
        assert "y" not in shown
        ran = []
        screen.action_copy_row = lambda: ran.append("copy")
        await pilot.press("y")
        assert ran == ["copy"]


def test_every_fleet_shortcut_has_a_footer_rank() -> None:
    actions = {binding.action for binding in InstanceListScreen.BINDINGS if binding.show}
    # Enter is DataTable's own key on the fleet; "o" is its footer entry.
    assert actions <= set(InstanceListScreen.FOOTER_PRIORITY)
