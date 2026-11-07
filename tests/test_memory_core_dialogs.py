"""Memory field dialogs preserve raw results, trusted questions and native focus."""

from __future__ import annotations

import pytest
from textual.widgets import Button, Input

from servonaut.screens.memory import PinKeyModal, SimpleConfirmModal
from servonaut.widgets.dialogs import DialogBody, DialogFrame
from tests._async_bounds import wait_until
from tests.test_basic_dialogs import BasicDialogHost
from tests.test_workspace_pilot import _click
from tests.test_workspace_reflow import _painted


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("long", [False, True])
async def test_memory_dialog_initial_focus_preserves_input_and_safe_confirmation(
    size: tuple[int, int], long: bool,
) -> None:
    app = BasicDialogHost()
    async with app.run_test(size=size) as pilot:
        pin = PinKeyModal("services", "version", "example")
        app.push_screen(pin)
        await pilot.pause()
        assert app.focused is pin.query_one("#pin_value_input", Input)
        await pilot.press("escape")
        question = "Review [bold]example configuration[/bold].\n" * (45 if long else 1)
        confirm = SimpleConfirmModal(question)
        app.push_screen(confirm)
        await pilot.pause()
        assert app.focused is confirm.query_one("#confirm_no_btn", Button)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("value,expected", [("  café [literal] Ω  ", "café [literal] Ω"),
                                           ("   ", None), ("", None)])
async def test_pin_button_returns_existing_stripped_value_contract(
    size: tuple[int, int], value: str, expected: str | None,
) -> None:
    app = BasicDialogHost()
    results = []
    async with app.run_test(size=size) as pilot:
        screen = PinKeyModal("services", "version", "example")
        app.push_screen(screen, results.append)
        await pilot.pause()
        screen.query_one("#pin_value_input", Input).value = value
        await _click(pilot, "#pin_btn_confirm")
        await wait_until(lambda: app.screen is not screen)
        assert results == [expected]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("route", ["escape", "click"])
async def test_pin_cancel_returns_none_and_restores_origin(
    size: tuple[int, int], route: str,
) -> None:
    app = BasicDialogHost()
    results = []
    async with app.run_test(size=size) as pilot:
        origin = app.query_one("#origin", Input)
        origin.focus()
        screen = PinKeyModal("services", "version")
        app.push_screen(screen, results.append)
        await pilot.pause()
        if route == "click":
            await _click(pilot, "#pin_btn_cancel")
        else:
            await pilot.press("escape")
        await wait_until(lambda: app.screen is not screen)
        assert results == [None] and app.focused is origin


@pytest.mark.asyncio
async def test_pin_input_enter_keeps_the_existing_edit_open() -> None:
    app = BasicDialogHost()
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        screen = PinKeyModal("services", "version")
        app.push_screen(screen, results.append)
        await pilot.pause()
        screen.query_one("#pin_value_input", Input).value = "example value"
        await pilot.press("enter")
        await pilot.pause()
        assert app.screen is screen and results == []
        assert app.focused is screen.query_one("#pin_value_input", Input)
        await pilot.press("escape")
        await wait_until(lambda: app.screen is not screen)
        assert results == [None]


@pytest.mark.asyncio
@pytest.mark.parametrize("module,key,current", [
    ("services", "packages", '["nginx", "sshd"]'),
    ("module[/b]name", "key", "a[/b]c"),
    ("services", "[bold]key[/bold]", "before [bold]word[/bold] after"),
])
async def test_pin_data_paints_literally(module: str, key: str, current: str) -> None:
    app = BasicDialogHost()
    async with app.run_test(size=(100, 30)) as pilot:
        screen = PinKeyModal(module, key, current)
        app.push_screen(screen)
        await pilot.pause()
        assert module in _painted(app, screen.query_one("#pin_modal_title"))
        assert key in _painted(app, screen.query_one("#pin_modal_title"))
        assert current in _painted(app, screen.query_one("#pin_modal_field"))
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("route,result", [
    ("no", False), ("yes", True), ("escape", False), ("enter", False),
])
async def test_simple_question_keeps_trusted_markup_and_exact_bool_result(
    size: tuple[int, int], route: str, result: bool,
) -> None:
    app = BasicDialogHost()
    results = []
    async with app.run_test(size=size) as pilot:
        origin = app.query_one("#origin", Input)
        origin.focus()
        screen = SimpleConfirmModal("Review [bold]example configuration[/bold] now?")
        app.push_screen(screen, results.append)
        await pilot.pause()
        message = _painted(app, screen.query_one("#confirm_message"))
        assert "Review example configuration now?" in message and "[bold]" not in message
        if route in ("yes", "no"):
            await _click(pilot, f"#confirm_{route}_btn")
        else:
            await pilot.press(route)
        await wait_until(lambda: app.screen is not screen)
        assert results == [result] and app.focused is origin


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"])
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["pin", "question"])
async def test_memory_dialog_scroll_keeps_actions_painted_and_stationary_during_notice(
    theme: str, size: tuple[int, int], kind: str,
) -> None:
    app = BasicDialogHost()
    app.theme = theme
    async with app.run_test(size=size) as pilot:
        screen = (PinKeyModal("services", "version", "Observed configuration\n" * 45)
                  if kind == "pin" else SimpleConfirmModal("Review this configuration.\n" * 45))
        app.push_screen(screen)
        await pilot.pause()
        body = screen.query_one(DialogBody)
        frame = screen.query_one(DialogFrame)
        actions = [screen.query_one(f"#{name}", Button) for name in
                   (("pin_btn_cancel", "pin_btn_confirm") if kind == "pin"
                    else ("confirm_no_btn", "confirm_yes_btn"))]
        regions = [button.region for button in actions]
        editor = screen.query_one("#pin_value_input", Input) if kind == "pin" else None
        editor_region = editor.region if editor is not None else None
        if editor is not None:
            editor.value = "Retain the pending value"
        assert body.allow_vertical_scroll and body.max_scroll_y > 0
        body.focus()
        await pilot.press("end")
        await pilot.pause()
        assert body.scroll_y > 0
        assert [button.region for button in actions] == regions
        if editor is not None:
            assert editor.region == editor_region
            assert "Retain the pending value" in _painted(app, editor)
            assert app.get_widget_at(*editor.region.center)[0] is editor
        for button in actions:
            assert frame.content_region.contains_region(button.region)
            assert app.get_widget_at(*button.region.center)[0] is button
            assert button.label.plain in _painted(app, button)
        app.notify("Example status notice", timeout=0.1)
        await pilot.pause()
        assert [button.region for button in actions] == regions
        await wait_until(lambda: not app.screen.query("Toast"))
        assert [button.region for button in actions] == regions
        if editor is not None:
            assert editor.region == editor_region
            assert "Retain the pending value" in _painted(app, editor)
