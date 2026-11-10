"""A button and the key printed on it run the same action; outside text stays literal."""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.widgets import DataTable, Input, Static

from servonaut.widgets.memory_prompt import MemoryPrompt
from tests.test_memory_summary_ui import _INSTANCE, _MemorySummaryApp
from tests.test_workspace_security_reflow import (
    _SecurityHost,
    _fake_boundaries as _fake_boundaries,
    _opener,
)


@pytest.mark.asyncio
async def test_ip_ban_enter_in_the_table_and_the_button_use_the_selected_address() -> None:
    app = _SecurityHost(True)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _opener("ban")(app, pilot)
        table = screen.query_one("#banned_table", DataTable)
        field = screen.query_one("#ip_input", Input)
        table.focus()
        table.move_cursor(row=1)
        await pilot.pause()
        assert field.value == ""
        await pilot.press("enter")
        await pilot.pause()
        assert field.value == "8.8.8.8"

        field.value = ""
        table.move_cursor(row=0)
        await pilot.pause()
        assert await pilot.click("#ip_ban_use_selected")
        await pilot.pause()
        assert field.value == "1.1.1.1"


@pytest.mark.asyncio
async def test_server_memory_opens_for_a_markup_like_server_name(monkeypatch) -> None:
    hostile = "a [link=  x\\"
    monkeypatch.setitem(_INSTANCE, "name", hostile)
    app = _MemorySummaryApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        title = app.screen.query_one("#memory-title", Static)
        assert title.content.plain == f"Server memory: {hostile}"


class _PromptHost(App):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[str] = []

    def compose(self) -> ComposeResult:
        yield MemoryPrompt({"id": "i-1", "name": "web-1"})


@pytest.fixture
def prompt_calls(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(MemoryPrompt, "_dispatch_build", lambda self: calls.append("build"))
    monkeypatch.setattr(MemoryPrompt, "_increment_dismissal", lambda self: calls.append("dismiss"))
    return calls


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("how", "expected"),
    [
        ("click-build", "build"), ("key-y", "build"),
        ("click-dismiss", "dismiss"), ("key-n", "dismiss"),
    ],
)
async def test_memory_prompt_buttons_and_keys_run_the_same_actions(
    prompt_calls, how: str, expected: str,
) -> None:
    app = _PromptHost()
    async with app.run_test(size=(100, 30)) as pilot:
        prompt = app.query_one(MemoryPrompt)
        if how.startswith("click"):
            target = "#memory_prompt_accept" if how == "click-build" else "#memory_prompt_dismiss"
            assert await pilot.click(target)
        else:
            prompt.focus()
            await pilot.press(how[-1])
        await pilot.pause()
        assert prompt_calls == [expected]
