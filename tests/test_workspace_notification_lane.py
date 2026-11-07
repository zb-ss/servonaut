"""Native workspace alerts remain readable without covering active controls."""

from __future__ import annotations

import asyncio

import pytest
from textual import events
from textual.widgets import Button, Footer, TextArea
from textual.widgets._toast import Toast, ToastRack
from textual.widgets.text_area import Selection

from servonaut.widgets.chat_panel import ChatPanel
from tests._async_bounds import wait_until
from tests.test_fleet_workspace_layout import _LayoutHost, _open_chat


@pytest.fixture(autouse=True)
def _no_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    # Real chat widgets/routing and an owned held worker, without provider/audio.
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)


def _paint(app, widget) -> str:
    strips = app.screen._compositor.render_strips()
    region = widget.region.intersection(app.screen.region)
    return "\n".join(strips[y].crop(region.x, region.right).text
                     for y in range(region.y, region.bottom))


def _controls(screen):
    controls = [screen.query_one(f"#{name}", Button) for name in (
        "workspace_navigation", "workspace_chat", "workspace_chat_end",
    )]
    for selector in ("#chat-controls Button", "#chat-input-row Button"):
        controls.extend(button for button in screen.query(selector)
                        if button.region.width and button.region.height)
    return controls


def _pose(screen, composer):
    return (composer.region, tuple(button.region for button in _controls(screen)),
            tuple(footer.region for footer in screen.query(Footer)))


def _protected(app, screen, composer, original_pose) -> None:
    rack = screen.query_one(ToastRack)
    # On the original source this must fail for actual painted occlusion before
    # any query/assertion of the new helper type: no ImportError/NoMatches red.
    observed = {"rack": tuple(rack.region), "composer": tuple(composer.region),
                "rack_paint": _paint(app, rack), "composer_paint": _paint(app, composer),
                "center_hit": repr(app.get_widget_at(*composer.region.center)[0])}
    assert not rack.display or not rack.region.overlaps(composer.region), observed
    assert screen.region.contains_region(composer.region), observed
    for y in range(composer.region.y, composer.region.bottom):
        for x in range(composer.region.x, composer.region.right):
            hit = app.get_widget_at(x, y)[0]
            assert hit is composer or composer in hit.ancestors, (x, y, hit, observed)
    for button in _controls(screen):
        assert screen.region.contains_region(button.region)
        assert not rack.display or not rack.region.overlaps(button.region), observed
        hit = app.get_widget_at(*button.region.center)[0]
        assert hit is button or button in hit.ancestors
        assert button.label.plain in _paint(app, button)
    footers = list(screen.query(Footer))
    assert footers
    for footer in footers:
        assert screen.region.contains_region(footer.region)
        assert not rack.display or not rack.region.overlaps(footer.region), observed
        hit = app.get_widget_at(*footer.region.center)[0]
        assert hit is footer or footer in hit.ancestors
    assert _pose(screen, composer) == original_pose


async def _wheel_to(app, pilot, screen, rack, *, bottom: bool, expected: str) -> None:
    event = events.MouseScrollDown if bottom else events.MouseScrollUp
    destination = rack.max_scroll_y if bottom else 0
    initial = rack.scroll_y
    for _ in range(64):
        if rack.scroll_y == destination:
            break
        before = rack.scroll_y
        point = (rack.region.x + rack.size.width * 3 // 4,
                 rack.region.y + rack.size.height // 2)
        hit = app.get_widget_at(*point)[0]
        assert hit is rack or rack in hit.ancestors
        await pilot._post_mouse_events(
            [event], widget=rack,
            offset=(rack.size.width * 3 // 4, rack.size.height // 2),
        )
        await pilot.pause()
        assert rack.scroll_y != before
    assert rack.scroll_y == destination and rack.scroll_y != initial
    assert expected in _paint(app, rack)
    assert app.screen is screen


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("route", ["fleet", "actions"])
async def test_notifications_keep_live_composer_controls_and_footer_clear(
    size: tuple[int, int], route: str,
) -> None:
    app = _LayoutHost(navigation_visible=False)
    # The measured source defect was visible in this actual registered theme.
    app.theme = "atom-one-dark"
    started, stopped = asyncio.Event(), asyncio.Event()

    async def held_turn() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    async with app.run_test(size=size, notifications=True) as pilot:
        if route == "actions":
            await pilot.press("o")
        screen = app.screen
        panel = await _open_chat(app, pilot)
        composer = panel.query_one("#chat-input", TextArea)
        composer.load_text("Keep this unsent draft\nSecond line")
        composer.selection = Selection.cursor((1, 4))
        await pilot.pause()
        document, selection, original_pose = composer.document, composer.selection, _pose(screen, composer)
        worker = panel.run_worker(held_turn(), group="ai_chat")
        await wait_until(started.is_set)
        try:
            # Real native notifications, held long enough to assert while live;
            # this is a lane test, not a substitute for existing clipboard tests.
            app.notify("Copied 2 lines", timeout=60)
            app.notify("\n".join(f"Example detail {i + 1}." for i in range(12)),
                       title="Operation failed", severity="error", timeout=60)
            rack = screen.query_one(ToastRack)
            await wait_until(lambda: len(rack.query(Toast)) == 2 and rack.max_scroll_y > 0)
            await pilot.pause()
            _protected(app, screen, composer, original_pose)
            lanes = list(screen.query("WorkspaceNotificationSpace"))
            assert len(lanes) == 1 and lanes[0].parent is screen
            assert not lanes[0].can_focus
            # visibility:hidden reserves layout space but is omitted from the
            # compositor map, so Widget.region is correctly empty. Inspect the
            # same actual child arrangement used by the native compositor.
            arrangement = screen.arrange(screen.scrollable_content_region.size)
            placement = next(p for p in arrangement.placements if p.widget is lanes[0])
            reserved = placement.region + placement.offset + screen.scrollable_content_region.offset
            assert reserved.height == 4 and reserved.width == screen.scrollable_content_region.width
            assert reserved.bottom == screen.scrollable_content_region.bottom - 2
            assert screen.region.contains_region(reserved)
            assert arrangement.scroll_spacing.bottom >= 6
            assert screen.query_one("#main-layout").region.bottom <= reserved.y
            assert rack.region.height <= 4
            assert not worker.is_finished and not stopped.is_set()
            assert composer.document is document and composer.selection == selection
            assert app.focused is composer

            await wait_until(lambda: rack.scroll_y == rack.max_scroll_y)
            for bottom, expected in ((False, "Copied 2 lines"), (True, "Example detail 12.")):
                await _wheel_to(app, pilot, screen, rack, bottom=bottom, expected=expected)
                _protected(app, screen, composer, original_pose)
                assert composer.document is document and composer.selection == selection
                assert app.focused is composer and not worker.is_finished

            # Native pointer dismissal, with actual hit proof inside the rack.
            while rack.query(Toast):
                toast = next(t for t in rack.query(Toast)
                             if rack.scrollable_content_region.intersection(t.region).area > 0)
                visible = rack.scrollable_content_region.intersection(toast.region)
                point = visible.center
                assert app.get_widget_at(*point)[0] is toast
                assert await pilot.click(offset=tuple(point))
                await wait_until(lambda: not toast.is_attached and not toast.is_running)
                await pilot.pause()
                assert not toast._timers
                _protected(app, screen, composer, original_pose)
            await wait_until(lambda: not app._notifications)

            # A separate live alert exercises native expiry after protected
            # geometry/hits are already proven with visible stacked alerts.
            app.notify("Brief notification", timeout=1)
            await wait_until(lambda: len(rack.query(Toast)) == 1)
            expiring = rack.query_one(Toast)
            _protected(app, screen, composer, original_pose)
            await wait_until(lambda: not expiring.is_attached and not expiring.is_running)
            await pilot.pause()
            assert not expiring._timers and not app._notifications
            # Native Toast._expire removes its holder without refreshing the
            # rack's display flag; an empty auto-height rack legitimately stays
            # display=True. Its empty region must not occupy/intercept input.
            assert not rack.query(Toast) and rack.region.height == 0
            _protected(app, screen, composer, original_pose)
            assert len(screen.query("WorkspaceNotificationSpace")) == 1
            assert composer.document is document and composer.selection == selection
            assert composer.text == "Keep this unsent draft\nSecond line"
            assert app.focused is composer and not worker.is_finished
            assert app._exception is None
        finally:
            app.action_end_chat()
            await wait_until(stopped.is_set)
            await wait_until(lambda: worker.is_finished and not panel.is_attached)
        assert worker.is_finished and not panel.is_attached
