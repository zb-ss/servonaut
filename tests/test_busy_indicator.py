"""BusyIndicator: a hidden-when-idle spinner line with the running message."""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult

from servonaut.widgets.busy_indicator import BusyIndicator


class _Host(App):
    def compose(self) -> ComposeResult:
        yield BusyIndicator(id="busy")


def _text(widget: BusyIndicator) -> str:
    return str(widget.render())


@pytest.mark.asyncio
async def test_hidden_until_started_and_after_stop():
    app = _Host()
    async with app.run_test() as pilot:
        busy = app.query_one(BusyIndicator)
        assert not busy.is_active and busy.display is False

        busy.start("Importing keys…")
        await pilot.pause()
        assert busy.is_active and busy.display is True
        assert "Importing keys…" in _text(busy)

        busy.stop()
        await pilot.pause()
        assert not busy.is_active and busy.display is False and busy.message == ""


@pytest.mark.asyncio
async def test_elapsed_time_appears_only_once_the_work_is_slow():
    now = [100.0]
    app = _Host()
    async with app.run_test() as pilot:
        busy = app.query_one(BusyIndicator)
        busy._clock = lambda: now[0]
        busy.start("Decrypting the item…")
        await pilot.pause()
        assert not _text(busy).rstrip().endswith("s")

        now[0] += 12.4
        busy._tick()
        assert _text(busy).rstrip().endswith("12s")

        # A new message keeps counting from the first start.
        busy.start("Still decrypting…")
        assert "Still decrypting…" in _text(busy) and _text(busy).rstrip().endswith("12s")


@pytest.mark.asyncio
async def test_message_is_plain_text_not_markup():
    app = _Host()
    async with app.run_test() as pilot:
        busy = app.query_one(BusyIndicator)
        busy.start("Loading [bold]keys[/] for [@click=app.quit]x[/]")
        await pilot.pause()
        assert "[bold]keys[/]" in _text(busy)
        assert "[@click=app.quit]" in _text(busy)


@pytest.mark.asyncio
async def test_spinner_moves_while_running_and_timer_ends_on_stop():
    app = _Host()
    async with app.run_test() as pilot:
        busy = app.query_one(BusyIndicator)
        busy.start("Working…")
        first = _text(busy)[0]
        for _ in range(40):
            await pilot.pause(0.05)
            if _text(busy)[0] != first:
                break
        assert _text(busy)[0] != first
        busy.stop()
        await pilot.pause(0.3)
        assert busy._timer is None and _text(busy) == ""


class _Redactor:
    def scrub_stream(self, text: str) -> str:
        return text.replace("workstation", "<host>")


class _DemoHost(_Host):
    demo_mode = True
    redaction_service = _Redactor()


@pytest.mark.asyncio
async def test_demo_mode_hides_names_in_the_message_and_keeps_the_real_one():
    app = _DemoHost()
    async with app.run_test() as pilot:
        busy = app.query_one(BusyIndicator)
        busy.start("Waiting for another device to approve “workstation”…")
        await pilot.pause()
        assert "“<host>”" in _text(busy) and "workstation" not in _text(busy)
        assert busy.message == "Waiting for another device to approve “workstation”…"

        app.demo_mode = False
        busy._tick()
        assert "“workstation”" in _text(busy)
