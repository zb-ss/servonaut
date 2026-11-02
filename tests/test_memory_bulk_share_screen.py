"""The bulk Share form: one team, role and module choice for several servers."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App
from textual.widgets import Button, Checkbox, SelectionList, Static

from servonaut.screens.memory_bulk_share import BulkShareScreen
from servonaut.services.api_client import APIError
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

pytestmark = pytest.mark.asyncio

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
