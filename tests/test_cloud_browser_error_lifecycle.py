"""Cloud error diagnostics follow real demo redaction and current selections."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from textual.containers import VerticalScroll
from textual.pilot import Pilot
from textual.widgets import Button, DataTable, Select, Static
from textual.widgets._toast import Toast

from servonaut.app import ServonautApp
from servonaut.screens.cloudtrail_browser import CloudTrailBrowserScreen
from servonaut.screens.cloudwatch_browser import CloudWatchBrowserScreen
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.services.cloudtrail_service import LookupPage
from servonaut.services.redaction_service import RedactionService
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import tab_to
from tests.test_selection_copy import _Clipboard, clipboard as clipboard
from tests.test_workspace_security_reflow import (
    _SecurityHost,
    _fake_boundaries as _fake_boundaries,
)

pytestmark = pytest.mark.usefixtures("navigation_open")


Browser = CloudWatchBrowserScreen | CloudTrailBrowserScreen
PAYLOAD = (
    "private-node 1.1.1.1 /aws/lambda/private-group\n"
    "[$text-error]literal[/$text-error] [unmatched"
)
# Independent pinned stand-ins follow the public deterministic hash contract.
MASKED = (
    "link-replica-22 198.51.100.149 /aws/lambda/node-public-5\n"
    "[$text-error]literal[/$text-error] [unmatched"
)
PARTS = ("private-node", "1.1.1.1", "private-group")
SELECTORS = {
    "watch": ("cw_btn_fetch", "cloudwatch_events_table", "cloudwatch_detail_text", "cloudwatch_detail"),
    "trail": ("ct_btn_fetch", "cloudtrail_table", "event_detail_text", "event_detail"),
}


def _host(demo: bool) -> _SecurityHost:
    app = _SecurityHost(True)
    assert app.redact_display_text.__func__ is ServonautApp.redact_display_text
    assert app._demo_known_identifiers.__func__ is ServonautApp._demo_known_identifiers
    app.config_manager.update(
        cloudwatch_default_region="us-east-1", cloudtrail_default_region="us-east-1",
    )
    app.demo_mode = demo
    app.redaction_service = RedactionService() if demo else None
    app.replace_instances(None, [{
        "id": "id-private-node", "name": "private-node", "is_custom": True,
        "state": "running", "type": "small", "host": "node.example.test",
        "public_ip": "1.1.1.1", "private_ip": "10.0.0.1",
        "region": "local", "key_name": "", "username": "operator",
    }])
    assert app.redact_display_text(PAYLOAD) == (MASKED if demo else PAYLOAD)
    return app


def _service(app: _SecurityHost, kind: str) -> Any:
    return app.cloudwatch_service.get_log_events if kind == "watch" else app.cloudtrail_service.lookup_page


def _response(kind: str, events: list[dict[str, Any]]) -> Any:
    return events if kind == "watch" else LookupPage(events=events, next_token=None)


def _events(kind: str, prefix: str) -> list[dict[str, Any]]:
    if kind == "watch":
        return [{
            "timestamp": f"2026-01-01 00:00:0{index}", "log_stream": "fixture-stream",
            "message": f"{prefix} {index} from 1.1.1.1 [literal] Ω",
        } for index in range(6)]
    return [{
        "event_time": f"2026-01-01 00:00:0{6 - index}",
        "event_name": f"{prefix}{index}", "username": "operator",
        "source_ip": "1.1.1.1", "resource_type": "Example::Resource",
        "resource_name": "private-node", "region": "us-east-1", "error_code": "",
        "raw_event": f"{prefix} {index} [$text-error]literal[/$text-error] [unmatched",
    } for index in range(6)]


async def _open(app: _SecurityHost, pilot: Pilot, kind: str) -> Browser:
    await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
    screen = CloudWatchBrowserScreen() if kind == "watch" else CloudTrailBrowserScreen()
    await app.push_screen(screen)
    if kind == "watch":
        group = screen.query_one("#cw_select_log_group", Select)
        await wait_until(lambda: group.prompt == "Select log group")
        # Filter setup is separate from the native event selection under test.
        group.value = "/logs/example"
    await pilot.pause()
    app.clear_notifications()
    await pilot.pause()
    return screen


async def _fetch(pilot: Pilot, screen: Browser, kind: str) -> None:
    button = screen.query_one("#" + SELECTORS[kind][0], Button)
    await tab_to(pilot, button)
    await pilot.wait_for_scheduled_animations()
    await pilot.pause()
    assert pilot.app.focused is button and not button.disabled
    await wait_until(lambda: not button.has_class("-active"))
    await pilot.press("enter")


async def _finished(pilot: Pilot, screen: Browser, kind: str, count: int) -> None:
    service = _service(pilot.app, kind)
    button = screen.query_one("#" + SELECTORS[kind][0], Button)
    await wait_until(lambda: service.await_count == count and not button.disabled)
    await pilot.pause()


async def _error_toast(app: _SecurityHost, pilot: Pilot, expected: str) -> None:
    def errors() -> list[Toast]:
        return [toast for toast in app.screen.query(Toast)
                if toast._notification.severity == "error"]

    await wait_until(lambda: bool(errors()))
    await pilot.pause()
    toast = errors()[-1]
    assert toast._notification.markup is False
    assert toast.render().plain == expected
    if app.demo_mode:
        assert not any(part in toast.render().plain for part in PARTS)


def _painted(app: _SecurityHost, widget: Static, reader: VerticalScroll) -> str:
    region = widget.region.intersection(reader.scrollable_content_region).intersection(app.screen.region)
    strips = app.screen._compositor.render_strips()
    return "\n".join(strips[y].crop(region.x, region.right).text
                     for y in range(region.y, region.bottom))


async def _error_pane(app: _SecurityHost, pilot: Pilot, screen: Browser,
                      kind: str, expected: str) -> None:
    detail = screen.query_one("#" + SELECTORS[kind][2], Static)
    reader = screen.query_one("#" + SELECTORS[kind][3], VerticalScroll)
    assert detail.render().plain == expected
    await tab_to(pilot, reader)
    await pilot.press("home")
    await pilot.wait_for_scheduled_animations()
    await pilot.pause()
    compact = lambda value: "".join(value.split())
    assert compact(expected.splitlines()[0]) in compact(_painted(app, detail, reader))
    await pilot.press("end")
    await pilot.wait_for_scheduled_animations()
    await pilot.pause()
    assert compact(expected.splitlines()[-1]) in compact(_painted(app, detail, reader))
    assert app.focused is reader and app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["watch", "trail"])
@pytest.mark.parametrize("initial_demo", [False, True])
async def test_fetch_error_uses_full_redaction_and_literal_pane_across_demo_toggles(
    kind: str, initial_demo: bool,
) -> None:
    app = _host(initial_demo)
    service = _service(app, kind)
    service.side_effect = RuntimeError(PAYLOAD)
    prefix = "CloudWatch" if kind == "watch" else "CloudTrail"
    diagnostic = lambda demo: f"{prefix} fetch failed: {MASKED if demo else PAYLOAD}"
    async with app.run_test(size=(160, 50), notifications=True) as pilot:
        screen = await _open(app, pilot, kind)
        await _fetch(pilot, screen, kind)
        await _finished(pilot, screen, kind, 1)
        detail = screen.query_one("#" + SELECTORS[kind][2], Static)
        assert detail.render().plain == diagnostic(initial_demo)
        await _error_toast(app, pilot, diagnostic(initial_demo))
        await _error_pane(app, pilot, screen, kind, diagnostic(initial_demo))

        # Old OFF-mode toasts are app-wide history; this test only qualifies
        # fresh ON-mode error toasts and the persistent diagnostic's redraw.
        app.clear_notifications()
        if initial_demo:
            await pilot.press("ctrl+shift+d")
            await wait_until(lambda: not app.demo_mode)
            await pilot.pause()
            await _error_pane(app, pilot, screen, kind, diagnostic(False))
        await pilot.press("ctrl+shift+d")
        await wait_until(lambda: app.demo_mode)
        await pilot.pause()
        assert app.redact_display_text(PAYLOAD) == MASKED
        await _error_pane(app, pilot, screen, kind, diagnostic(True))
        assert service.await_count == 1
        app.clear_notifications()
        await pilot.pause()
        await _fetch(pilot, screen, kind)
        await _finished(pilot, screen, kind, 2)
        await _error_toast(app, pilot, diagnostic(True))
        await _error_pane(app, pilot, screen, kind, diagnostic(True))
        await pilot.press("ctrl+shift+d")
        await wait_until(lambda: not app.demo_mode)
        await pilot.pause()
        await _error_pane(app, pilot, screen, kind, diagnostic(False))

        service.side_effect = None
        service.return_value = _response(kind, _events(kind, "Recovered"))
        await _fetch(pilot, screen, kind)
        await _finished(pilot, screen, kind, 3)
        detail = screen.query_one("#" + SELECTORS[kind][2], Static)
        guidance = detail.render().plain
        assert "Select" in guidance and "fetch failed" not in guidance
        await pilot.press("ctrl+shift+d")
        await wait_until(lambda: app.demo_mode)
        await pilot.pause()
        assert detail.render().plain == guidance
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["watch", "trail"])
@pytest.mark.parametrize("outcome", ["replacement", "failure", "empty"])
async def test_native_selection_and_copy_follow_invalidated_and_replacement_results(
    kind: str, outcome: str, clipboard: _Clipboard,
) -> None:
    app = _host(False)
    service = _service(app, kind)
    original = _events(kind, "Original")
    replacement = _events(kind, "Replacement") if outcome == "replacement" else []
    service.return_value = _response(kind, original)
    entered, release = asyncio.Event(), asyncio.Event()

    async def replace_results(**kwargs: Any) -> Any:
        entered.set()
        await release.wait()
        if outcome == "failure":
            raise RuntimeError(PAYLOAD)
        return _response(kind, replacement)

    async with app.run_test(size=(160, 50), notifications=True) as pilot:
        screen = await _open(app, pilot, kind)
        await _fetch(pilot, screen, kind)
        await _finished(pilot, screen, kind, 1)
        table = screen.query_one("#" + SELECTORS[kind][1], DataTable)
        assert table.row_count == 6
        if kind == "watch":
            ips = screen.query_one("#cloudwatch_ips_table", DataTable)
            assert ips.row_count == 1
            await tab_to(pilot, ips)
            await pilot.press("home", "enter")
            await screen.workers.wait_for_complete()
            assert screen._selected_ip_row == 0
        await tab_to(pilot, table)
        await pilot.press("home", "down", "down", "down", "down", "enter")
        if kind == "watch":
            await wait_until(lambda: screen._selected_event_row == 4)
            assert screen._selected_event_row == 4
        else:
            await wait_until(lambda: screen._selected_event is original[4])
            assert screen._selected_event is original[4]
        await pilot.press("y")
        await wait_until(lambda: bool(clipboard.calls))
        assert "Original" in clipboard.calls[-1]
        clipboard.calls.clear()
        service.side_effect = replace_results
        try:
            await _fetch(pilot, screen, kind)
            await wait_until(entered.is_set)
            assert table.row_count == 0 and screen._events == []
            detail = screen.query_one("#" + SELECTORS[kind][2], Static)
            assert detail.render().plain == "Loading..."
            if outcome == "empty":
                # Loading has its own invalidation check; replacement/failure
                # below exercise the actual completed clipboard contract.
                if kind == "watch":
                    assert screen._selected_event_row is None
                    assert screen._selected_ip_row is None
                else:
                    assert screen._selected_event is None
                await pilot.press("y")
                assert clipboard.calls == []
            release.set()
            await _finished(pilot, screen, kind, 2)
            assert table.row_count == len(replacement)
            if outcome == "replacement":
                assert "Select" in detail.render().plain
                await pilot.press("y")
                await wait_until(lambda: bool(clipboard.calls))
                expected = ("\n".join(event["message"] for event in replacement)
                            if kind == "watch" else "\n".join(
                                f"Replacement{index} | operator | 1.1.1.1"
                                for index in range(6)))
                assert clipboard.calls == [expected]
                if kind == "watch":
                    assert screen._selected_event_row is None
                else:
                    assert screen._selected_event is None
                await tab_to(pilot, table)
                await pilot.press("home", "down", "enter")
                await wait_until(lambda: screen._selected_event_row == 1
                                 if kind == "watch" else screen._selected_event is replacement[1])
                await pilot.press("y")
                await wait_until(lambda: len(clipboard.calls) == 2)
                assert "Replacement 1" in clipboard.calls[-1]
                assert "[literal] Ω" in clipboard.calls[-1] if kind == "watch" else "[unmatched" in clipboard.calls[-1]
            else:
                assert ("fetch failed" if outcome == "failure" else "No events found.") in detail.render().plain
                await pilot.press("y")
                assert clipboard.calls == []
                if kind == "watch":
                    assert screen._selected_event_row is None
                    assert screen._selected_ip_row is None
                else:
                    assert screen._selected_event is None
            assert app._exception is None
        finally:
            release.set()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["watch", "trail"])
async def test_unavailable_demo_redaction_hides_errors_and_preserves_fetch_recovery(
    kind: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _host(True)
    service = _service(app, kind)
    service.side_effect = RuntimeError(PAYLOAD)
    label = "CloudWatch" if kind == "watch" else "CloudTrail"
    raw = f"{label} fetch failed: {PAYLOAD}"
    masked = f"{label} fetch failed: {MASKED}"
    fallback = f"{label} fetch failed: details unavailable in demo mode."
    async with app.run_test(size=(160, 50), notifications=True) as pilot:
        screen = await _open(app, pilot, kind)
        for count, variant in enumerate(("missing", "raises", "non-string"), 1):
            app.clear_notifications()
            await pilot.pause()
            original = app.redact_display_text

            def unavailable(text: str) -> Any:
                # Other app notifications still use the real redaction API.
                if text.startswith(f"{label} fetch failed:"):
                    if variant == "raises":
                        raise ValueError("Synthetic redaction unavailable")
                    return {"unexpected": "non-string"}
                return original(text)

            with monkeypatch.context() as patch:
                if variant == "missing":
                    patch.setattr(app, "redaction_service", None)
                else:
                    patch.setattr(app, "redact_display_text", unavailable)
                await _fetch(pilot, screen, kind)
                await _finished(pilot, screen, kind, count)
                detail = screen.query_one("#" + SELECTORS[kind][2], Static)
                assert detail.render().plain == fallback
                assert not any(part in detail.render().plain for part in PARTS)
                await _error_pane(app, pilot, screen, kind, fallback)
                assert not [toast for toast in screen.query(Toast)
                            if toast._notification.severity == "error"]
                assert not screen.query_one("#" + SELECTORS[kind][0], Button).disabled
                assert app._exception is None

            # Recover through the real mode action, not a forced presenter call.
            await pilot.press("ctrl+shift+d")
            await wait_until(lambda: not app.demo_mode)
            await pilot.pause()
            assert detail.render().plain == raw
            await pilot.press("ctrl+shift+d")
            await wait_until(lambda: app.demo_mode)
            await pilot.pause()
            assert app.redact_display_text(PAYLOAD) == MASKED
            assert detail.render().plain == masked
            assert service.await_count == count
            assert app._exception is None
