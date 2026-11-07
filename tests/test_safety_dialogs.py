"""Real-stylesheet safety dialog contracts, overflow and native notifications."""

from __future__ import annotations

import pytest
from textual.color import Color
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from servonaut.screens.remediation_confirm import RemediationConfirmModal
from servonaut.screens.tool_confirm_modal import DangerousToolConfirmModal, ToolConfirmModal
from servonaut.widgets.dialogs import DialogActions, DialogBody, DialogFrame
from tests.test_basic_dialogs import BasicDialogHost, assert_exposed


def make_preview(*, long: bool = False, long_undo: bool = False) -> dict:
    """Use neutral literal strings, including brackets meaningful to Rich."""
    command = "\n".join(
        f"printf  '%s\\n'  'example step {index + 1} [red]literal[/red]'"
        for index in range(45 if long else 1)
    )
    undo = "\n".join(
        f"Restore example setting {index + 1} [blue]literally[/blue]."
        for index in range(45 if long_undo else 1)
    )
    return {
        "action": "example_action", "exec_risk": "medium", "reversible": True,
        "command": {"human": command}, "revert_plan": {"human": undo},
        "expires_at": "2026-12-01T12:00:00Z",
    }


def make_dialog(kind: str, *, long: bool = False) -> tuple[ModalScreen, str, str]:
    args = {
        f"option {index + 1} [red]literal[/red]": "value [blue]literal[/blue]"
        for index in range(45 if long else 1)
    }
    if kind == "standard":
        return ToolConfirmModal("example [red]tool[/red]", args), "btn_tool_cancel", "btn_tool_confirm"
    if kind == "dangerous":
        return DangerousToolConfirmModal("example [red]tool[/red]", args), "dangerous_confirm_input", "btn_dangerous_confirm"
    return RemediationConfirmModal(make_preview(long=long), dry_run=False), "remediation_confirm_input", "remediation_confirm_run"


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("value", ["RUN", " RUN ", "\tRUN\t"])
@pytest.mark.parametrize("submit", ["enter", "click"])
async def test_dangerous_tool_trims_run_and_submits_from_input(
    size: tuple[int, int], value: str, submit: str,
) -> None:
    app = BasicDialogHost()
    screen, _, confirm_id = make_dialog("dangerous")
    results = []
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        field = screen.query_one("#dangerous_confirm_input", Input)
        assert screen.focused is field
        field.value = value
        if submit == "enter":
            await pilot.press("enter")
        else:
            assert await pilot.click(screen.query_one(f"#{confirm_id}", Button))
        await pilot.pause()
        assert results == [True]


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["", "run", "RUN!"])
@pytest.mark.parametrize("submit", ["enter", "click"])
async def test_invalid_dangerous_tool_reprompts_with_pinned_error_and_input(
    value: str, submit: str,
) -> None:
    app = BasicDialogHost()
    screen, _, confirm_id = make_dialog("dangerous", long=True)
    results = []
    async with app.run_test(size=(100, 30), notifications=True) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        app.notify("Example notification.", timeout=60)
        field = screen.query_one("#dangerous_confirm_input", Input)
        field.value = value
        if submit == "enter":
            await pilot.press("enter")
        else:
            assert await pilot.click(screen.query_one(f"#{confirm_id}", Button))
        await pilot.pause()
        error = screen.query_one("#dangerous_confirm_error", Static)
        assert "visible" in error.classes and error.display
        assert "RUN" in error.render().plain
        assert screen.focused is field and results == []
        assert_exposed(app, screen, error)
        assert_exposed(app, screen, field)
        assert_exposed(app, screen, screen.query_one("#dangerous_confirm_body", Static))
        for button in screen.query_one(DialogActions).query(Button):
            assert_exposed(app, screen, button)
        await pilot.press("escape")
        await pilot.pause()
        assert results == [False]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("value", ["RUN", " RUN "])
async def test_remediation_trims_run_but_input_enter_never_executes(
    size: tuple[int, int], dry_run: bool, value: str,
) -> None:
    app = BasicDialogHost()
    screen = RemediationConfirmModal(make_preview(long=True), dry_run=dry_run)
    results = []
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        field = screen.query_one("#remediation_confirm_input", Input)
        execute = screen.query_one("#remediation_confirm_run", Button)
        assert screen.focused is field and execute.disabled
        field.value = value
        await pilot.pause()
        assert not execute.disabled
        await pilot.press("enter")
        await pilot.pause()
        assert app.screen is screen and results == []
        assert_exposed(app, screen, execute)
        assert await pilot.click(execute)
        await pilot.pause()
        assert results == ["confirm"]


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["", "run", "RUN!"])
async def test_remediation_invalid_input_keeps_execute_disabled(value: str) -> None:
    app = BasicDialogHost()
    screen = RemediationConfirmModal(make_preview(), dry_run=False)
    results = []
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        screen.query_one("#remediation_confirm_input", Input).value = value
        await pilot.pause()
        execute = screen.query_one("#remediation_confirm_run", Button)
        assert execute.disabled
        await pilot.press("enter")
        execute.press()
        await pilot.pause()
        assert app.screen is screen and results == []
        await pilot.press("escape")
        await pilot.pause()
        assert results == [None]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("dry_run", [False, True])
async def test_remediation_safer_action_has_distinct_result_and_live_only_button(
    size: tuple[int, int], dry_run: bool,
) -> None:
    app = BasicDialogHost()
    screen = RemediationConfirmModal(make_preview(), dry_run=dry_run)
    results = []
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        assert len(screen.query("#remediation_confirm_dry_run")) == (0 if dry_run else 1)
        button_id = "remediation_confirm_cancel" if dry_run else "remediation_confirm_dry_run"
        button = screen.query_one(f"#{button_id}", Button)
        assert_exposed(app, screen, button)
        assert await pilot.click(button)
        await pilot.pause()
        assert results == [None if dry_run else "dry_run"]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["standard", "dangerous", "remediation"])
@pytest.mark.parametrize("cancel", ["escape", "click"])
async def test_safety_dialog_cancellation_preserves_false_versus_none(
    size: tuple[int, int], kind: str, cancel: str,
) -> None:
    app = BasicDialogHost()
    screen, _, _ = make_dialog(kind)
    results = []
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        if cancel == "escape":
            await pilot.press("escape")
        else:
            cancel_id = {
                "standard": "btn_tool_cancel", "dangerous": "btn_dangerous_cancel",
                "remediation": "remediation_confirm_cancel",
            }[kind]
            assert await pilot.click(screen.query_one(f"#{cancel_id}", Button))
        await pilot.pause()
        assert results == [None if kind == "remediation" else False]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["standard", "dangerous", "remediation"])
async def test_long_safety_details_scroll_without_moving_pinned_controls(
    size: tuple[int, int], kind: str,
) -> None:
    app = BasicDialogHost()
    screen, safe_id, _ = make_dialog(kind, long=True)
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        assert screen.focused is screen.query_one(f"#{safe_id}")
        body = screen.query_one(DialogBody)
        assert body.max_scroll_y > 0
        assert screen.query_one(DialogFrame).border_subtitle
        buttons = list(screen.query_one(DialogActions).query(Button))
        positions = [button.region for button in buttons]
        body.focus()
        await pilot.press("pagedown")
        await pilot.pause()
        assert body.scroll_y > 0
        assert [button.region for button in buttons] == positions
        for button in buttons:
            assert_exposed(app, screen, button)
        if kind == "remediation":
            undo = screen.query_one("#remediation_confirm_revert", Static)
            assert body not in undo.ancestors
            assert_exposed(app, screen, undo)
            command = screen.query_one("#remediation_confirm_command", Static).render().plain
            assert command == (
                "Exact command (server-signed):\n" + make_preview(long=True)["command"]["human"]
                + "\n\nPreview token expires: 2026-12-01T12:00:00Z"
            )
        else:
            prefix = "dangerous" if kind == "dangerous" else "tool"
            assert "example [red]tool[/red]" in screen.query_one(f"#{prefix}_confirm_title", Static).render().plain
            args = screen.query_one(f"#{prefix}_confirm_args", Static).render().plain
            assert "option 1 [red]literal[/red]: value [blue]literal[/blue]" in args
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_long_undo_stays_accessible_without_hiding_remediation_controls(
    size: tuple[int, int],
) -> None:
    app = BasicDialogHost()
    preview = make_preview(long=True, long_undo=True)
    screen = RemediationConfirmModal(preview, dry_run=False)
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        field = screen.query_one("#remediation_confirm_input", Input)
        assert_exposed(app, screen, field)
        buttons = list(screen.query_one(DialogActions).query(Button))
        positions = [button.region for button in buttons]
        for button in buttons:
            assert_exposed(app, screen, button)
        body = screen.query_one("#remediation_confirm_scroll", DialogBody)
        undo = screen.query_one("#remediation_confirm_revert", Static)
        assert body not in undo.ancestors
        assert undo.render().plain == preview["revert_plan"]["human"]
        undo_scroll = undo.parent
        assert undo_scroll.max_scroll_y > 0 and undo_scroll.allow_focus()
        undo_scroll.focus()
        await pilot.press("pagedown")
        await pilot.pause()
        assert undo_scroll.scroll_y > 0
        assert_exposed(app, screen, field)
        assert [button.region for button in buttons] == positions
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["standard", "dangerous", "remediation"])
async def test_toast_lifecycle_keeps_safety_targets_stable_until_explicit_click(
    size: tuple[int, int], kind: str,
) -> None:
    app = BasicDialogHost()
    screen, _, confirm_id = make_dialog(kind)
    results = []
    async with app.run_test(size=size, notifications=True) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        frame = screen.query_one(DialogFrame)
        original_frame = frame.region
        buttons = list(screen.query_one(DialogActions).query(Button))
        positions = [button.region for button in buttons]
        for count in (1, 8, 1, 0, 2):
            existing = list(screen.query("Toast"))
            if len(existing) > count:
                for toast in existing[count:]:
                    toast._expire()
            else:
                for index in range(len(existing), count):
                    app.notify(f"Example operation {index + 1}.", timeout=60)
            await pilot.pause()
            assert len(screen.query("Toast")) == count
            assert frame.region == original_frame
            assert [button.region for button in buttons] == positions
            for button in buttons:
                assert_exposed(app, screen, button)
        if kind != "standard":
            input_id = "dangerous_confirm_input" if kind == "dangerous" else "remediation_confirm_input"
            screen.query_one(f"#{input_id}", Input).value = " RUN "
            await pilot.pause()
        confirm = screen.query_one(f"#{confirm_id}", Button)
        region = confirm.region
        point = (region.x + region.width // 2, region.y + region.height // 2)
        screen.query("Toast").first()._expire()
        await pilot.pause()
        assert confirm.region == region and app.get_widget_at(*point)[0] is confirm
        assert await pilot.click(offset=point)
        await pilot.pause()
        assert results == ["confirm" if kind == "remediation" else True]


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light", "textual-dark", "textual-light"])
async def test_dangerous_validation_hint_is_painted_in_error_theme_role(
    theme: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Application Static styling must not erase the validation error colour."""
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)
    app = BasicDialogHost()
    app.theme = theme
    screen, _, _ = make_dialog("dangerous", long=True)
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        error = screen.query_one("#dangerous_confirm_error", Static)
        assert error.display and "visible" in error.classes
        assert_exposed(app, screen, error)
        expected = Color.parse(app.get_css_variables()["error"]).rich_color
        painted = screen._compositor.get_style_at(
            error.content_region.x, error.content_region.y,
        )
        assert painted.color == expected
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_undo_heading_remains_painted_while_reading_long_plan(
    size: tuple[int, int],
) -> None:
    """Scrolling the plan must retain the label that identifies its meaning."""
    app = BasicDialogHost()
    screen = RemediationConfirmModal(make_preview(long=True, long_undo=True), dry_run=False)
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        undo_scroll = screen.query_one(".remediation-undo", DialogBody)
        before = "\n".join(strip.text for strip in screen._compositor.render_strips())
        assert "Undo, if needed:" in before
        field = screen.query_one("#remediation_confirm_input", Input)
        buttons = list(screen.query_one(DialogActions).query(Button))
        positions = [button.region for button in buttons]
        undo_scroll.focus()
        await pilot.press("pagedown")
        await pilot.pause()
        assert undo_scroll.scroll_y > 0
        after = "\n".join(strip.text for strip in screen._compositor.render_strips())
        assert "Undo, if needed:" in after
        assert_exposed(app, screen, field)
        assert [button.region for button in buttons] == positions
        await pilot.press("escape")
