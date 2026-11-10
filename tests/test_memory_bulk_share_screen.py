"""The bulk Share form: one team, role and module choice for several servers."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App
from textual.widgets import Button, Checkbox, SelectionList, Static

from servonaut.screens.memory_bulk_share import BulkShareScreen
from servonaut.services.api_client import APIError
from servonaut.services.memory import bulk_share as bulk
from servonaut.services.memory.bulk_share import ShareTarget
from tests._bulk_share_fakes import (
    GRANT_PATH,
    SLUG,
    FakeTeamBackend,
    grant,
    member,
    rate_limited,
    team_memory_service,
)

pytestmark = [pytest.mark.asyncio, pytest.mark.usefixtures("navigation_open")]

TARGETS = [
    ShareTarget("web-1", "web-1"),
    ShareTarget("web-2", "web-2"),
    ShareTarget("vps-1.example.net", "vps-1"),
]


class _Host(App):
    def __init__(self, backend: FakeTeamBackend, *, targets=None, demo: bool = False,
                 locked: bool = False) -> None:
        super().__init__()
        self.backend = backend
        self._targets = list(TARGETS if targets is None else targets)
        auth = MagicMock()
        auth.has_feature = MagicMock(return_value=True)
        auth.list_teams = AsyncMock(return_value=[{"name": "Real Team Name", "slug": SLUG}])
        self.auth_service = auth
        self.team_memory_service = team_memory_service(backend, locked=locked)
        self.demo_mode = demo
        if demo:
            self.redaction_service = MagicMock()
            self.redaction_service.redact_name = lambda n: f"stand-in-{len(n)}"
            self.redaction_service.scrub_stream = lambda t: t
        self.notes: List[str] = []
        self.result: Optional[bool] = None

    def on_mount(self) -> None:
        self.push_screen(BulkShareScreen(self._targets), self._bulk_form_closed)

    def _bulk_form_closed(self, ran: Optional[bool]) -> None:
        self.result = ran

    def notify(self, message, *a, **kw):  # type: ignore[override]
        self.notes.append(str(message))


async def _settle(pilot, cond, what: str = "state") -> None:
    for _ in range(200):
        await pilot.pause(0.05)
        if cond():
            return
    raise AssertionError(f"timed out waiting for {what}")


def _text(screen, selector: str) -> str:
    return str(screen.query_one(selector, Static).render())


async def _open(app: _Host, pilot) -> BulkShareScreen:
    await _settle(pilot, lambda: isinstance(app.screen, BulkShareScreen)
                  and "Will be able" in _text(app.screen, "#bulk-readers"), "readers")
    return app.screen


async def _share(app: _Host, pilot, screen: BulkShareScreen) -> str:
    screen.query_one("#bulk-btn-confirm", Button).press()
    await _settle(pilot, lambda: "Done" in _text(screen, "#bulk-status")
                  or app.screen is not screen, "the batch")
    return _text(screen, "#bulk-summary")


def _backend(**kw: Any) -> FakeTeamBackend:
    kw.setdefault("members", [member(2, "Kim Member"), member(3, "Lee Admin", "admin")])
    kw.setdefault("stored", {"web-1": ["os"], "web-2": ["os"]})
    return FakeTeamBackend(**kw)


async def test_the_form_starts_with_the_single_forms_defaults():
    app = _Host(_backend())
    async with app.run_test(size=(140, 50)) as pilot:
        screen = await _open(app, pilot)
        ticked = set(screen.query_one("#bulk-modules-list", SelectionList).selected)
        assert {"os", "runtimes", "services", "git", "logs"} <= ticked
        assert not ticked & {"annotations", "findings"}
        assert screen.query_one("#bulk-update-existing", Checkbox).value is False
        confirm = screen.query_one("#bulk-btn-confirm", Button)
        assert str(confirm.label) == "Share 3 servers" and not confirm.disabled
        assert "web-1, web-2, vps-1" in _text(screen, "#bulk-servers")


@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_update_existing_caption_is_fully_painted_and_clickable(size):
    backend = _backend()
    app = _Host(backend)
    async with app.run_test(size=size) as pilot:
        screen = await _open(app, pilot)
        checkbox = screen.query_one("#bulk-update-existing", Checkbox)
        caption = "Update existing shares to these settings"
        assert checkbox.label.plain == caption
        assert screen.has_class("-content-narrow") is (size == (100, 30))
        for _ in range(len(screen.focus_chain) + 1):
            if app.focused is checkbox:
                break
            await pilot.press("tab")
        await pilot.wait_for_scheduled_animations()
        await pilot.pause()
        assert app.focused is checkbox
        assert screen.region.contains_region(checkbox.region)
        assert app.get_widget_at(*checkbox.content_region.center)[0] is checkbox
        region = checkbox.region
        strips = screen._compositor.render_strips()
        painted = "\n".join(
            strips[y].crop(region.x, region.right).text
            for y in range(region.y, region.bottom)
        )
        assert caption in painted, painted
        assert checkbox.value is False
        offset = (checkbox.size.width // 2, checkbox.size.height // 2)
        assert await pilot.click(checkbox, offset=offset)
        await pilot.pause()
        assert checkbox.value is True
        assert await pilot.click(checkbox, offset=offset)
        await pilot.pause()
        assert checkbox.value is False
        assert backend.writes() == []
        assert app._exception is None


async def test_the_readers_are_listed_once_for_the_chosen_role():
    app = _Host(_backend())
    async with app.run_test(size=(140, 50)) as pilot:
        screen = await _open(app, pilot)
        readers = _text(screen, "#bulk-readers")
        assert "(2): Kim Member, Lee Admin" in readers
        assert readers.count("Will be able") == 1


async def test_the_summary_has_one_line_per_server():
    waiting = {"user_id": 9, "name": "Pat Waiting", "role": "member", "reason": "no_memory_key"}
    backend = _backend(live=[grant("web-2")])
    backend.pending = {"web-1": [waiting]}
    app = _Host(backend)
    async with app.run_test(size=(140, 50)) as pilot:
        screen = await _open(app, pilot)
        summary = await _share(app, pilot, screen)
        assert "Shared (1)" in summary and "web-1" in summary
        assert "Already shared, left as it was (1)" in summary
        assert "Skipped (1)" in summary
        assert "vps-1 — Memory Sync does not accept this server's id" in summary
        assert "No memory key yet: Pat Waiting" in summary
        assert "1 shared, 1 already shared, 1 skipped" in _text(screen, "#bulk-status")
        assert backend.writes() == [f"POST {GRANT_PATH} web-1"]
        assert not screen.query_one("#bulk-btn-confirm", Button).display
        await pilot.press("escape")
        await _settle(pilot, lambda: app.result is not None, "the form to close")
        assert app.result is True


async def test_update_existing_replaces_the_shares_that_exist():
    backend = _backend(live=[grant("web-2")])
    app = _Host(backend, targets=TARGETS[:2])
    async with app.run_test(size=(140, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#bulk-update-existing", Checkbox).value = True
        summary = await _share(app, pilot, screen)
        assert "Already shared, updated to these settings (1)" in summary
        assert f"DELETE {GRANT_PATH}/g-1" in backend.writes()


async def test_a_failure_shows_the_service_text_literally():
    backend = _backend()
    backend.post_errors["web-1"] = [APIError(code="x", message="[bold]boom[/bold]", status=500)]
    app = _Host(backend, targets=TARGETS[:2])
    async with app.run_test(size=(140, 50)) as pilot:
        screen = await _open(app, pilot)
        summary = await _share(app, pilot, screen)
        assert "Failed (1)" in summary
        assert "[bold]boom[/bold] (HTTP 500)" in summary
        assert "Shared (1)" in summary  # the other server still went


async def test_a_persistent_rate_limit_says_how_many_were_not_sent():
    backend = _backend(stored={"web-1": ["os"], "web-2": ["os"]})
    backend.post_errors["web-1"] = [rate_limited("120")]
    app = _Host(backend)
    async with app.run_test(size=(140, 50)) as pilot:
        screen = await _open(app, pilot)
        summary = await _share(app, pilot, screen)
        assert "Not sent (2)" in summary
        assert "try again in 2 min" in summary
        assert "2 not sent" in _text(screen, "#bulk-status")


async def test_a_changed_key_asks_first_and_sends_nothing():
    from servonaut.screens.memory_key_change import MemberKeyChangeScreen

    backend = _backend(members=[member(2, "Kim Member", key_changed=True)])
    app = _Host(backend)
    async with app.run_test(size=(140, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#bulk-btn-confirm", Button).press()
        await _settle(pilot, lambda: isinstance(app.screen, MemberKeyChangeScreen), "the key check")
        assert backend.writes() == []
        await pilot.press("escape")
        await _settle(pilot, lambda: app.screen is screen, "the form again")
        assert "Nothing was shared" in _text(screen, "#bulk-status")
        assert "Kim Member" in _text(screen, "#bulk-status")
        assert backend.writes() == []


async def test_no_module_ticked_sends_nothing():
    backend = _backend()
    app = _Host(backend)
    async with app.run_test(size=(140, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#bulk-modules-list", SelectionList).deselect_all()
        screen.query_one("#bulk-btn-confirm", Button).press()
        await pilot.pause(0.2)
        assert "Select at least one module" in _text(screen, "#bulk-status")
        assert backend.writes() == []


async def test_a_locked_memory_key_says_so_and_sends_nothing():
    backend = _backend()
    app = _Host(backend, locked=True)
    async with app.run_test(size=(140, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#bulk-btn-confirm", Button).press()
        await _settle(pilot, lambda: "Unlock Memory Sync" in _text(screen, "#bulk-status"), "refusal")
        assert backend.writes() == []


async def test_cancel_closes_without_marking_anything_sent():
    app = _Host(_backend())
    async with app.run_test(size=(140, 50)) as pilot:
        await _open(app, pilot)
        await pilot.press("escape")
        await _settle(pilot, lambda: app.result is not None, "the form to close")
        assert app.result is False


async def test_demo_mode_shows_no_real_team_member_or_server_name():
    backend = _backend()
    backend.post_errors["web-2"] = [APIError(code="x", message="Real Person lacks a key", status=500)]
    app = _Host(backend, demo=True, targets=TARGETS[:2])
    async with app.run_test(size=(140, 50)) as pilot:
        screen = await _open(app, pilot)
        shown = " ".join(_text(screen, s) for s in ("#bulk-servers", "#bulk-readers"))
        assert "web-1" not in shown and "Kim Member" not in shown and "stand-in" in shown
        summary = await _share(app, pilot, screen)
        everything = summary + _text(screen, "#bulk-status") + " ".join(app.notes)
        for real in ("web-1", "web-2", "Kim Member", "Real Team Name", "Real Person"):
            assert real not in everything, real
        assert "turn demo mode off to see why" in summary


# --- while a batch is sending ----------------------------------------------


def _three() -> List[ShareTarget]:
    return [ShareTarget(f"web-{i}", f"web-{i}") for i in (1, 2, 3)]


async def _hold_first_post(app: _Host, pilot, screen: BulkShareScreen) -> asyncio.Event:
    gate = asyncio.Event()
    app.backend.post_gate = gate
    screen.query_one("#bulk-btn-confirm", Button).press()
    await _settle(pilot, lambda: any(c.startswith("POST") for c in app.backend.calls), "the first POST")
    return gate


async def test_stop_ends_the_batch_after_the_current_server():
    backend = _backend(stored={f"web-{i}": ["os"] for i in (1, 2, 3)})
    app = _Host(backend, targets=_three())
    async with app.run_test(size=(140, 50)) as pilot:
        screen = await _open(app, pilot)
        gate = await _hold_first_post(app, pilot, screen)
        stop = screen.query_one("#bulk-btn-stop", Button)
        assert stop.display and stop.has_class("-shown")
        await pilot.press("s")
        assert stop.disabled and "Stopping" in str(stop.label)
        gate.set()
        await _settle(pilot, lambda: "Done" in _text(screen, "#bulk-status"), "the summary")
        summary = _text(screen, "#bulk-summary")
        assert "Shared (1)" in summary and "Not sent (2)" in summary
        assert "You stopped the batch" in summary
        assert backend.writes() == [f"POST {GRANT_PATH} web-1"]
        assert not stop.has_class("-shown")


async def test_the_form_cannot_be_left_while_a_batch_is_sending():
    backend = _backend(stored={f"web-{i}": ["os"] for i in (1, 2, 3)})
    app = _Host(backend, targets=_three())
    async with app.run_test(size=(140, 50)) as pilot:
        screen = await _open(app, pilot)
        gate = await _hold_first_post(app, pilot, screen)
        assert screen.navigation_hold_reason()
        await pilot.press("escape")
        await pilot.pause(0.1)
        assert app.screen is screen and app.result is None
        assert any("Sharing is in progress" in n for n in app.notes)
        gate.set()
        await _settle(pilot, lambda: "Done" in _text(screen, "#bulk-status"), "the summary")
        assert screen.navigation_hold_reason() is None


async def test_the_app_keeps_the_screen_while_a_batch_is_sending(monkeypatch):
    from servonaut.app import ServonautApp
    from servonaut.widgets.sidebar import Sidebar

    screen = BulkShareScreen(_three())
    monkeypatch.setattr(BulkShareScreen, "compose", lambda self: iter(()))
    monkeypatch.setattr(BulkShareScreen, "on_mount", lambda self, event: event.prevent_default())
    screen._sending = True

    class _App(ServonautApp):
        def on_mount(self, event):
            event.prevent_default()
            self.push_screen(screen)

        async def on_unmount(self, event):
            event.prevent_default()

    app = _App()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.on_sidebar_navigation_requested(Sidebar.NavigationRequested("nav_list"))
        await pilot.pause()
        assert app.screen is screen
        await pilot.press("q")
        await pilot.pause()
        assert not app._exit and app.screen is screen
        screen._sending = False


async def test_an_error_after_servers_were_shared_does_not_say_nothing_was_shared():
    backend = _backend(stored={f"web-{i}": ["os"] for i in (1, 2, 3)})
    app = _Host(backend, targets=_three())
    async with app.run_test(size=(140, 50)) as pilot:
        screen = await _open(app, pilot)
        real_share = bulk.BulkMemoryShareService.share

        async def share_then_fail(self, *args, **kwargs):
            kwargs["on_progress"](1, 3, bulk.ShareOutcome(_three()[0], bulk.SHARED))
            raise RuntimeError("lost")

        bulk.BulkMemoryShareService.share = share_then_fail
        try:
            screen.query_one("#bulk-btn-confirm", Button).press()
            await _settle(pilot, lambda: "ended early" in _text(screen, "#bulk-status"), "the error")
        finally:
            bulk.BulkMemoryShareService.share = real_share
        assert "Nothing was shared" not in _text(screen, "#bulk-status")
        assert "1 of 3" in _text(screen, "#bulk-status")


async def test_an_old_error_line_is_cleared_when_a_batch_starts():
    backend = _backend()
    app = _Host(backend, targets=TARGETS[:1])
    async with app.run_test(size=(140, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#bulk-modules-list", SelectionList).deselect_all()
        screen.query_one("#bulk-btn-confirm", Button).press()
        await pilot.pause(0.1)
        assert "Select at least one module" in _text(screen, "#bulk-status")
        screen.query_one("#bulk-modules-list", SelectionList).select("os")
        screen.query_one("#bulk-btn-confirm", Button).press()
        await _settle(pilot, lambda: "Done" in _text(screen, "#bulk-status"), "the summary")
        assert "Select at least one module" not in _text(screen, "#bulk-status")


async def test_no_tick_hint_when_existing_shares_were_to_be_updated():
    from servonaut.services.api_client import GrantExistsError

    backend = _backend(stored={"web-1": ["os"]})
    backend.post_errors["web-1"] = [GrantExistsError(code="grant_exists", message="x", status=409)]
    app = _Host(backend, targets=TARGETS[:1])
    async with app.run_test(size=(140, 50)) as pilot:
        screen = await _open(app, pilot)
        screen.query_one("#bulk-update-existing", Checkbox).value = True
        summary = await _share(app, pilot, screen)
        assert "Already shared, left as it was (1)" in summary
        assert "does not list that share to you" in summary
        assert "Tick" not in summary
