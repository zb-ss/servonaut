"""Tests for the AI tool-call confirmation modals.

Uses Textual's ``App.run_test`` pilot pattern (matches
``tests/test_ai_picker_modal.py``) so we exercise real widget IDs and
dismiss values rather than introspecting ``compose()`` output.

Regression focus: the dangerous typed-confirm modal must NEVER silently
deny on Enter — a wrong/empty value re-prompts and stays open; only
Escape / Cancel deny; an exact (whitespace-tolerant) ``RUN`` confirms.
"""
from __future__ import annotations

import pytest
from textual.app import App
from textual.widgets import Input, Static

from servonaut.screens.tool_confirm_modal import (
    DangerousToolConfirmModal,
    ToolConfirmModal,
)


class _WrapperApp(App):
    """Minimal host app to push a modal and capture its dismiss value."""

    def __init__(self, modal) -> None:
        super().__init__()
        self._modal = modal
        self.dismissed = []

    def on_mount(self) -> None:
        self.push_screen(self._modal, callback=self.dismissed.append)


# ---------------------------------------------------------------------------
# Dangerous typed-confirm modal
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dangerous_modal_confirms_on_exact_run():
    app = _WrapperApp(DangerousToolConfirmModal("deploy", {"target": "prod"}))
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        app._modal.query_one("#dangerous_confirm_input", Input).value = "RUN"
        await pilot.press("enter")
        await pilot.pause()
    assert app.dismissed == [True]


@pytest.mark.asyncio
async def test_dangerous_modal_tolerates_surrounding_whitespace():
    """A trailing space is not intent to cancel — it still confirms."""
    app = _WrapperApp(DangerousToolConfirmModal("deploy"))
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        app._modal.query_one("#dangerous_confirm_input", Input).value = "RUN "
        await pilot.press("enter")
        await pilot.pause()
    assert app.dismissed == [True]


@pytest.mark.asyncio
async def test_dangerous_modal_enter_on_empty_does_not_dismiss():
    """The core regression: Enter with an empty box must NOT silently deny."""
    app = _WrapperApp(DangerousToolConfirmModal("deploy"))
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        # Modal stayed open (no dismiss) and surfaced the hint.
        assert app.dismissed == []
        err = app._modal.query_one("#dangerous_confirm_error", Static)
        assert "visible" in err.classes
    # After the test block the app tears down; the key assertion is that
    # no dismiss value was recorded while the modal was live.


@pytest.mark.asyncio
async def test_dangerous_modal_enter_on_wrong_word_reprompts():
    app = _WrapperApp(DangerousToolConfirmModal("deploy"))
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        app._modal.query_one("#dangerous_confirm_input", Input).value = "run"  # wrong case
        await pilot.press("enter")
        await pilot.pause()
        assert app.dismissed == []
        assert "visible" in app._modal.query_one("#dangerous_confirm_error", Static).classes


@pytest.mark.asyncio
async def test_dangerous_modal_escape_denies():
    app = _WrapperApp(DangerousToolConfirmModal("deploy"))
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
    assert app.dismissed == [False]


@pytest.mark.asyncio
async def test_dangerous_modal_cancel_button_denies():
    app = _WrapperApp(DangerousToolConfirmModal("deploy"))
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.click("#btn_dangerous_cancel")
        await pilot.pause()
    assert app.dismissed == [False]


# ---------------------------------------------------------------------------
# Standard y/n modal
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_standard_modal_approves_on_y():
    app = _WrapperApp(ToolConfirmModal("run_command", {"command": "uptime"}))
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
    assert app.dismissed == [True]


@pytest.mark.asyncio
async def test_standard_modal_denies_on_n_and_escape():
    for key in ("n", "escape"):
        app = _WrapperApp(ToolConfirmModal("run_command", {"command": "uptime"}))
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.press(key)
            await pilot.pause()
        assert app.dismissed == [False], f"key {key!r} should deny"


# ---------------------------------------------------------------------------
# build_modal_confirm: a prompt past its deadline closes itself
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_modal_confirm_closes_the_prompt_when_the_deadline_passes():
    import asyncio
    from types import SimpleNamespace

    from servonaut.screens.tool_confirm_modal import build_modal_confirm

    app = App()
    outcome = []
    async with app.run_test(headless=True) as pilot:
        confirm = build_modal_confirm(app)
        call = SimpleNamespace(
            tool="run_command", args={"command": "uptime"}, guard_level="standard",
        )

        async def _ask():
            try:
                outcome.append(await asyncio.wait_for(confirm(call), timeout=0.3))
            except asyncio.TimeoutError:
                outcome.append("timeout")

        worker = app.run_worker(_ask(), exit_on_error=False)
        await pilot.pause(0.1)
        assert isinstance(app.screen, ToolConfirmModal)

        await worker.wait()
        await pilot.pause()

        assert outcome == ["timeout"]
        assert not isinstance(app.screen, ToolConfirmModal)


@pytest.mark.asyncio
async def test_modal_confirm_returns_the_answer():
    import asyncio
    from types import SimpleNamespace

    from servonaut.screens.tool_confirm_modal import build_modal_confirm

    app = App()
    outcome = []
    async with app.run_test(headless=True) as pilot:
        confirm = build_modal_confirm(app)
        call = SimpleNamespace(tool="run_command", args={}, guard_level="standard")

        async def _ask():
            outcome.append(await confirm(call))

        worker = app.run_worker(_ask(), exit_on_error=False)
        await pilot.pause(0.1)
        app.screen.dismiss(True)
        await worker.wait()

    assert outcome == [True]
