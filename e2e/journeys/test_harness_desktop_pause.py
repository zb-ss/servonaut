"""Self-tests for the desktop harness's pause.

Each check drives a small app of its own, so it shows what the harness does
rather than what Servonaut does.
"""

from __future__ import annotations

import asyncio

import pytest
from textual.app import App, ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Static

from e2e.harness import desktop
from e2e.harness.desktop import DesktopTimeout, _LoopPilot

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


class _Dialog(ModalScreen[None]):
    def compose(self) -> ComposeResult:
        yield Static("dialog")


class _Plain(App):
    def compose(self) -> ComposeResult:
        yield Static("main")


def _drop_layout_callbacks(screen, monkeypatch) -> None:
    """Make *screen* lose what is queued after its refresh, as a closing screen does."""
    monkeypatch.setattr(screen, "call_after_refresh", lambda callback: True)


async def test_a_pause_follows_a_dialog_that_closes_while_it_waits(monkeypatch):
    app = _Plain()
    async with app.run_test(size=(60, 10)):
        await app.push_screen(_Dialog())
        dialog = app.screen
        _drop_layout_callbacks(dialog, monkeypatch)
        waiting = asyncio.create_task(_LoopPilot(app).pause())
        await asyncio.sleep(0.3)
        assert not waiting.done()

        app.pop_screen()
        # The pause now waits for the screen shown instead: well inside its own timeout.
        await asyncio.wait_for(waiting, 5)
        assert app.screen is not dialog


async def test_a_pause_still_fails_when_the_screen_shown_never_lays_out(monkeypatch):
    monkeypatch.setattr(desktop, "_PAUSE_TIMEOUT", 0.6)
    app = _Plain()
    async with app.run_test(size=(60, 10)):
        await app.push_screen(_Dialog())
        _drop_layout_callbacks(app.screen, monkeypatch)
        with pytest.raises(DesktopTimeout, match="the screen's layout"):
            await _LoopPilot(app).pause()
