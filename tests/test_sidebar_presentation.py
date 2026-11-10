"""Compact navigation preserves painted cues, destinations and bottom status."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
import regex
from rich.color import Color
from rich.style import Style
from textual.pilot import Pilot
from textual.widgets import Button

from servonaut import get_version
from servonaut.screens.login import LoginScreen
from servonaut.services.relay_manager import RelayState
from servonaut.styles.themes import SERVONAUT_THEMES
from servonaut.widgets.relay_indicator import RelayIndicator, RelayStatusScreen
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.sidebar_section import SidebarSection
from tests._async_bounds import wait_until
from tests.test_navigation_dialog_contrast import (
    PALETTES,
    _OrdinarySidebarScreen,
    _assert_readable,
    _paint_colours,
    _painted_text_styles,
)
from tests.test_workspace_pilot import _Host, _click

pytestmark = pytest.mark.usefixtures("navigation_open")

THEMES = ("servonaut", "servonaut-light", "ansi-dark", "ansi-light")


class _SidebarHost(_Host):
    def __init__(self, *, all_providers: bool = True) -> None:
        super().__init__()
        self.destinations: list[str | None] = []
        self.ovh_service = object() if all_providers else None
        self.hetzner_service = object() if all_providers else None
        self.aws_object_storage_service = object() if all_providers else None
        self.ovh_object_storage_service = object() if all_providers else None
        self.hetzner_object_storage_service = object() if all_providers else None
        self.auth_service = SimpleNamespace(
            is_authenticated=True, has_feature=lambda _feature: True,
        )
        self.memory_sync_service = SimpleNamespace(is_configured=True)
        self.vault_available = True

    def on_sidebar_navigation_requested(
        self, message: Sidebar.NavigationRequested,
    ) -> None:
        message.prevent_default()
        self.destinations.append(message.target_id)


@pytest.fixture(autouse=True)
def _terminal_colours(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)


def _painted_row(button: Button) -> str:
    return "".join(
        strip.text for strip in button.render_lines(button.region.size.region)
    )


def _assert_exposed(app: _Host, control: Button) -> None:
    sidebar = app.screen.query_one(Sidebar)
    viewport = sidebar.query_one("#sidebar-scroll").scrollable_content_region
    assert viewport.contains_region(control.region)
    assert app.get_widget_at(*control.region.center)[0] is control


async def _tab_to(pilot: Pilot, control: Button) -> None:
    if pilot.app.focused is control:
        return
    for _ in range(len(pilot.app.screen.focus_chain) + 1):
        await pilot.press("tab")
        if pilot.app.focused is control:
            return
    raise AssertionError(f"{control!r} must remain reachable with Tab")


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_routes_and_headers_paint_complete_left_aligned_single_rows(
    theme: str, size: tuple[int, int],
) -> None:
    app = _SidebarHost()
    app.theme = theme
    async with app.run_test(size=size) as pilot:
        sidebar = app.screen.query_one(Sidebar)
        assert sidebar.region.width == 25
        sidebar.enter_navigation_mode()
        await wait_until(lambda: app.focused is sidebar.query_one("#nav_list"))
        await pilot.press("shift+tab")
        for section in sidebar.query(SidebarSection):
            if not section.display:
                continue
            header = section.query_one(".section-header", Button)
            await _tab_to(pilot, header)
            await pilot.pause()
            _assert_exposed(app, header)
            assert header.region.height == 1, {
                "region": tuple(header.region), "painted": _painted_row(header),
            }
            assert not any(edge[0] for edge in header.styles.border)
            label = header.label.plain
            assert label.startswith(("▶ ", "▼ "))
            start = header.content_region.x - header.region.x
            assert _painted_row(header)[start:].startswith(label)
            if section.collapsed:
                await pilot.press("enter")
                await pilot.pause()
            for route in section.query(".nav-button"):
                if not route.display:
                    continue
                await _tab_to(pilot, route)
                await pilot.pause()
                _assert_exposed(app, route)
                assert route.region.height == 1
                assert route.region.right == header.region.right
                label = route.label.plain
                assert not regex.search(r"\p{Extended_Pictographic}|\uFE0F", label)
                start = route.content_region.x - route.region.x
                assert _painted_row(route)[start:].startswith(label)
                edge = route.region.right - 1, route.region.y
                assert app.get_widget_at(*edge)[0] is route
        assert sidebar.border_title == "Navigate"
        assert sidebar.styles.border_top[0] == "round"
        assert not sidebar.query("#sidebar-logo, #sidebar-subtitle")
        assert not app.destinations
        target = sidebar.query_one("#nav_custom_servers", Button)
        target.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        assert await pilot.click(target, offset=(target.region.width - 1, 0))
        await wait_until(lambda: app.destinations == ["nav_custom_servers"])


def _cell_style(button: Button, x: int) -> Style:
    strip = button.render_lines(button.region.size.region)[0].crop(x, x + 1)
    segments = list(strip)
    assert len(segments) == 1
    return segments[0].style or Style()


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
async def test_section_headers_paint_readable_text_before_and_during_navigation(
    theme: str,
) -> None:
    app = _SidebarHost()
    app.theme = theme
    async with app.run_test(size=(100, 30)) as pilot:
        sidebar = app.screen.query_one(Sidebar)
        core = sidebar.query_one("#section_core .section-header", Button)
        tools = sidebar.query_one("#section_tools .section-header", Button)
        for header, text in ((core, "Core"), (tools, "Tools")):
            _assert_exposed(app, header)
            _assert_readable(
                _painted_text_styles(header, text),
                context=f"{theme}/{text}/content focus",
            )
        sidebar.enter_navigation_mode()
        await wait_until(lambda: app.focused is sidebar.query_one("#nav_list"))
        await pilot.press("shift+tab")
        for header, text in ((core, "Core"), (tools, "Tools")):
            await _tab_to(pilot, header)
            await pilot.pause()
            _assert_exposed(app, header)
            styles = _painted_text_styles(header, text)
            _assert_readable(styles, context=f"{theme}/{text}/header focus")
            assert all(style.underline for style in styles)


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
async def test_active_route_keeps_full_row_band_and_bar_through_focus_changes(
    theme: str,
) -> None:
    app = _SidebarHost()
    app.theme = theme
    async with app.run_test(size=(100, 30)) as pilot:
        sidebar = app.screen.query_one(Sidebar)
        active = sidebar.query_one("#nav_list", Button)
        alternate = sidebar.query_one("#nav_custom_servers", Button)
        original_regions = active.region, alternate.region
        for state in ("content", "active", "alternate", "restored"):
            if state == "active":
                sidebar.enter_navigation_mode()
                await wait_until(lambda: app.focused is active)
            elif state == "alternate":
                await pilot.press("tab")
                await pilot.pause()
                assert app.focused is alternate
            elif state == "restored":
                await pilot.press("escape")
                await pilot.pause()
                assert not sidebar.navigation_mode
                assert app.focused not in (active, alternate)
            await pilot.pause()
            assert active.styles.border_left[0] == "thick"
            assert active.region.height == 1
            assert (active.region, alternate.region) == original_regions
            text_styles = _painted_text_styles(active, "Instances")
            _assert_readable(text_styles, context=f"{theme}/{state}/active route")
            near = _cell_style(active, 1)
            far = _cell_style(active, active.region.width - 1)
            inactive_far = _cell_style(alternate, alternate.region.width - 1)
            for name, palette in PALETTES.items():
                near_background = _paint_colours(near, palette)[1]
                far_background = _paint_colours(far, palette)[1]
                inactive_background = _paint_colours(inactive_far, palette)[1]
                assert near_background == far_background, (theme, state, name)
                assert far_background != inactive_background, (theme, state, name)
            if state == "active":
                assert all(style.underline for style in text_styles)
            elif state == "alternate":
                assert all(style.underline for style in _painted_text_styles(
                    alternate, "Custom Servers",
                ))


@pytest.mark.asyncio
async def test_bottom_relay_follows_state_and_real_click_routing() -> None:
    app = _SidebarHost()
    async with app.run_test(size=(100, 30)) as pilot:
        indicator = app.screen.query_one(RelayIndicator)
        assert indicator.parent.id == "sidebar-bottom"
        for state, text, destination in (
            (RelayState.CONNECTED, "connected", RelayStatusScreen),
            (RelayState.SESSION_EXPIRED, "session expired", LoginScreen),
        ):
            app.relay_state = state
            await wait_until(lambda: indicator.state is state)
            await pilot.pause()
            assert text in "".join(
                strip.text
                for strip in indicator.render_lines(indicator.region.size.region)
            )
            assert app.get_widget_at(*indicator.region.center)[0] is indicator
            with patch.object(app, "push_screen") as push:
                assert await pilot.click(indicator)
                await pilot.pause()
                assert isinstance(push.call_args.args[0], destination)


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
async def test_update_reveal_and_remount_keep_text_and_exact_destination(
    theme: str,
) -> None:
    app = _SidebarHost()
    app.theme = theme
    # A deliberately neutral local fixture exercises the update suffix contract.
    version = "9.8.7"
    async with app.run_test(size=(100, 30)) as pilot:
        sidebar = app.screen.query_one(Sidebar)
        update = sidebar.query_one("#nav_update", Button)
        assert update.has_class("hidden")
        app._show_update_button(version)
        await pilot.pause()
        assert update.label.plain == f"Update to v{version}"
        assert not update.has_class("hidden")
        assert update.region.height == 1
        styles = _painted_text_styles(update, f"Update to v{version}")
        assert all(style.underline for style in styles)
        expected = None
        if theme.startswith("ansi"):
            _assert_readable(styles, context=f"{theme}/revealed Update action")
        else:
            registered = next(t for t in SERVONAUT_THEMES if t.name == theme)
            expected = Color.parse(registered.variables["text-accent"]).get_truecolor()
            assert all(
                style.color and style.color.get_truecolor() == expected
                for style in styles
            )
        assert await pilot.click(update)
        await pilot.pause()
        assert app.destinations == ["nav_update"]
        app._latest_version = version
        await app.push_screen(_OrdinarySidebarScreen())
        await pilot.pause()
        sidebar = app.screen.query_one(Sidebar)
        update = sidebar.query_one("#nav_update", Button)
        assert update.label.plain == f"Update to v{version}"
        assert not update.has_class("hidden")
        remounted_styles = _painted_text_styles(update, f"Update to v{version}")
        assert all(style.underline for style in remounted_styles)
        if expected is None:
            _assert_readable(
                remounted_styles, context=f"{theme}/remounted Update action",
            )
        else:
            assert all(
                style.color and style.color.get_truecolor() == expected
                for style in remounted_styles
            )
        quit_button = sidebar.query_one("#nav_quit", Button)
        assert quit_button.label.plain == "Quit"
        assert await pilot.click(quit_button)
        await pilot.pause()
        assert app.destinations == ["nav_update", "nav_quit"]


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
async def test_update_keyboard_focus_paints_a_distinct_cue_without_moving_the_row(
    theme: str,
) -> None:
    app = _SidebarHost()
    app.theme = theme
    async with app.run_test(size=(100, 30)) as pilot:
        app._show_update_button("9.8.7")
        await pilot.pause()
        sidebar = app.screen.query_one(Sidebar)
        update = sidebar.query_one("#nav_update", Button)
        label = update.label.plain
        region = update.region
        palette = PALETTES[
            "servonaut-light" if theme.endswith("light") else "servonaut-dark"
        ]

        def signature(styles: list[Style]) -> tuple:
            return tuple(
                (
                    *_paint_colours(style, palette),
                    bool(style.bold),
                    bool(style.underline),
                )
                for style in styles
            )

        unfocused = signature(_painted_text_styles(update, label))
        sidebar.enter_navigation_mode()
        await wait_until(lambda: app.focused is sidebar.query_one("#nav_list"))
        await _tab_to(pilot, update)
        await pilot.pause()
        assert app.focused is update
        focused_styles = _painted_text_styles(update, label)
        assert signature(focused_styles) != unfocused
        assert all(style.underline for style in focused_styles)
        if theme.startswith("ansi"):
            _assert_readable(focused_styles, context=f"{theme}/focused Update action")
        assert update.region == region and update.label.plain == label
        await pilot.press("escape")
        await pilot.pause()
        assert app.focused is not update
        assert signature(_painted_text_styles(update, label)) == unfocused
        assert update.region == region and update.label.plain == label


@pytest.mark.asyncio
@pytest.mark.parametrize("demo", [False, True])
async def test_header_keeps_version_visible_when_navigation_is_hidden(
    demo: bool,
) -> None:
    app = _SidebarHost()
    async with app.run_test(size=(100, 30)) as pilot:
        if demo:
            app.action_toggle_demo()
            await pilot.pause()
        assert app.title == "Servonaut"
        for _ in range(2):
            header = app.screen.query_one(SafeHeader)
            assert f"v{get_version()}" in header.format_title().plain
            title = header.query_one("HeaderTitle")
            assert f"v{get_version()}" in "".join(
                strip.text for strip in title.render_lines(title.region.size.region)
            )
            await _click(pilot, "#workspace_navigation")
            await pilot.pause()
        assert app.screen.query_one(Sidebar).display
