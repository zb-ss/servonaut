"""Conversations dialogs keep typed results, safe focus and native callbacks."""

from __future__ import annotations

from pathlib import Path

import pytest
from rich.markup import escape
from textual.widgets import Button, Input, Static

from servonaut.screens.ai_conversations_screen import (
    AIConversationsScreen, _ConfirmModal, _ExportPathModal,
)
from servonaut.widgets.dialogs import DialogActions, DialogBody, DialogFrame
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import tab_to
from tests.test_selection_copy import _Clipboard, _drag
from tests.test_selection_copy import clipboard as clipboard
from tests.test_workspace_pilot import _click
from tests.test_workspace_reflow import _painted
from tests.test_workspace_remaining_reflow import (
    TITLE, _RemainingHost, _no_external_services as _no_external_services,
    _opener,
)

pytestmark = pytest.mark.usefixtures("navigation_open")


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,value,expected", [
    ("enter", "  report café [literal].md  ", "report café [literal].md"),
    ("pointer", "  report café [literal].md  ", "report café [literal].md"),
    ("enter", "", None), ("pointer", "   ", None),
    ("cancel", "keep.md", None), ("escape", "keep.md", None),
])
async def test_export_native_results_and_initial_input_focus(
    mode: str, value: str, expected: str | None,
) -> None:
    app = _RemainingHost()
    results: list[str | None] = []
    async with app.run_test(size=(100, 30)) as pilot:
        origin = app.focused
        modal = _ExportPathModal("original Ω.md")
        await app.push_screen(modal, results.append)
        field = modal.query_one("#export_path_input", Input)
        await wait_until(lambda: app.focused is field)
        assert field.value == "original Ω.md"
        field.value = value
        await pilot.pause()
        if mode == "pointer":
            await _click(pilot, "#btn_export_save")
        elif mode == "cancel":
            await _click(pilot, "#btn_export_cancel")
        else:
            await pilot.press("enter" if mode == "enter" else "escape")
        await wait_until(lambda: bool(results))
        assert results == [expected] and app.screen is not modal
        assert app.focused is origin
        app.ai_conversations_client.export_md.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("danger", [False, True])
@pytest.mark.parametrize("mode,expected", [
    ("enter", False), ("escape", False), ("y", True), ("n", False),
    ("confirm", True), ("cancel", False),
])
async def test_confirmation_native_safe_focus_typed_result_exactly_once(
    danger: bool, mode: str, expected: bool,
) -> None:
    app = _RemainingHost()
    results: list[bool] = []
    async with app.run_test(size=(100, 30)) as pilot:
        origin = app.focused
        modal = _ConfirmModal("Review conversation", f"Delete [bold]{escape(TITLE)}[/bold]?", danger)
        await app.push_screen(modal, results.append)
        cancel = modal.query_one("#btn_no", Button)
        confirm = modal.query_one("#btn_yes", Button)
        await wait_until(lambda: app.focused is cancel)
        assert confirm.variant == ("error" if danger else "primary")
        assert TITLE in modal.query_one(DialogBody).query_one(Static).render().plain
        if mode in ("confirm", "cancel"):
            await _click(pilot, "#btn_yes" if mode == "confirm" else "#btn_no")
        else:
            await pilot.press(mode)
        await wait_until(lambda: bool(results))
        assert results == [expected] and app.screen is not modal
        assert app.focused is origin
        app.ai_conversations_client.delete.assert_not_awaited()
        app.ai_conversations_client.patch.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "servonaut-light", "ansi-dark", "ansi-light"])
async def test_long_confirm_copy_scrolls_without_moving_native_actions(theme: str) -> None:
    app = _RemainingHost()
    app.theme = theme
    assert app.config_manager.get().theme == theme
    message = escape(TITLE) + "\n" + "\n".join(f"Detail line {i}" for i in range(45))
    async with app.run_test(size=(100, 30)) as pilot:
        modal = _ConfirmModal("Delete Conversation", message, danger=True)
        await app.push_screen(modal)
        await pilot.pause()
        body = modal.query_one(DialogBody)
        frame = modal.query_one(DialogFrame)
        buttons = list(modal.query_one(DialogActions).query(Button))
        original = [button.region for button in buttons]
        assert body.max_scroll_y > 0 and frame.max_scroll_y == 0
        await tab_to(pilot, body)
        await pilot.press("end")
        await pilot.pause()
        assert body.scroll_y > 0 and "Detail line 44" in _painted(app, body)
        app.notify("[literal] review is still open", markup=False)
        await pilot.pause()
        for button, region in zip(buttons, original):
            assert button.region == region
            assert frame.content_region.contains_region(region)
            assert modal.region.contains_region(region)
            assert app.get_widget_at(*region.center)[0] is button
            assert button.label.plain in _painted(app, button)
        assert "Scroll for all details" == frame.border_subtitle
        await _click(pilot, "#btn_no")


@pytest.mark.asyncio
@pytest.mark.parametrize("writer_succeeds", [False, True])
async def test_confirmation_static_selection_uses_existing_literal_copy_once(
    clipboard: _Clipboard, writer_succeeds: bool,
) -> None:
    clipboard.succeeds = writer_succeeds
    app = _RemainingHost()
    async with app.run_test(size=(100, 30)) as pilot:
        modal = _ConfirmModal("Review", escape(TITLE))
        await app.push_screen(modal)
        label = modal.query_one(DialogBody).query_one(Static)
        await pilot.pause()
        await _drag(pilot, label, (0, 0), (len(TITLE), 0))
        assert clipboard.calls == [TITLE]
        if not writer_succeeds:
            assert app.clipboard == TITLE


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["archive", "cloud-delete", "paired-local-delete"])
async def test_real_history_confirmation_cancel_then_exact_selected_mutation(kind: str) -> None:
    app = _RemainingHost()
    row = app.chat_service.list_sessions.return_value[0]
    if kind == "paired-local-delete":
        row["remote_conversation_id"] = "conversation-one"
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _opener("history")(app, pilot)
        assert isinstance(screen, AIConversationsScreen)
        if kind != "paired-local-delete":
            assert await pilot.click("#--content-tab-tab_cloud")
            await wait_until(lambda: screen._active_tab == "tab_cloud")
        button = {
            "archive": "#btn_convs_archive", "cloud-delete": "#btn_convs_delete",
            "paired-local-delete": "#btn_local_delete",
        }[kind]
        await _click(pilot, button)
        await wait_until(lambda: isinstance(app.screen, _ConfirmModal))
        app.ai_conversations_client.patch.assert_not_awaited()
        app.ai_conversations_client.delete.assert_not_awaited()
        app.chat_service.delete_session.assert_not_called()
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
        app.ai_conversations_client.patch.assert_not_awaited()
        app.ai_conversations_client.delete.assert_not_awaited()
        app.chat_service.delete_session.assert_not_called()
        await _click(pilot, button)
        await wait_until(lambda: isinstance(app.screen, _ConfirmModal))
        await _click(pilot, "#btn_yes")
        if kind == "archive":
            await wait_until(lambda: app.ai_conversations_client.patch.await_count == 1)
            app.ai_conversations_client.patch.assert_awaited_once_with("conversation-one", status="archived")
            app.ai_conversations_client.delete.assert_not_awaited()
        else:
            await wait_until(lambda: app.ai_conversations_client.delete.await_count == 1)
            app.ai_conversations_client.delete.assert_awaited_once_with("conversation-one")
            app.ai_conversations_client.patch.assert_not_awaited()
        if kind == "paired-local-delete":
            await wait_until(lambda: app.chat_service.delete_session.call_count == 1)
            app.chat_service.delete_session.assert_called_once_with("session-one")
        else:
            app.chat_service.delete_session.assert_not_called()
        assert app.screen is screen


@pytest.mark.asyncio
@pytest.mark.parametrize("submit", ["enter", "pointer"])
async def test_real_history_export_callback_preserves_literal_path_and_once_target(submit: str) -> None:
    app = _RemainingHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _opener("history")(app, pilot)
        assert await pilot.click("#--content-tab-tab_cloud")
        await wait_until(lambda: screen._active_tab == "tab_cloud")
        await _click(pilot, "#btn_convs_export")
        await wait_until(lambda: isinstance(app.screen, _ExportPathModal))
        modal = app.screen

        def ready() -> bool:
            if app._exception is not None:
                raise app._exception
            if app.screen is not modal or not modal.is_mounted or not modal.is_attached:
                return False
            for selector, expected_type in (
                ("#export_path_input", Input), ("#btn_export_save", Button),
                ("#btn_export_cancel", Button),
            ):
                children = list(modal.query(selector))
                if len(children) != 1 or not isinstance(children[0], expected_type):
                    return False
                child = children[0]
                if not child.is_mounted or not child.is_attached:
                    return False
                if child.region.width <= 0 or child.region.height <= 0:
                    return False
            return not modal._layout_required

        await wait_until(ready)
        field = app.screen.query_one("#export_path_input", Input)
        await wait_until(lambda: app.focused is field)
        app.ai_conversations_client.export_md.assert_not_awaited()
        field.value = "  report café [literal].md  "
        await pilot.pause()
        if submit == "enter":
            await pilot.press("enter")
        else:
            await _click(pilot, "#btn_export_save")
        await wait_until(lambda: app.ai_conversations_client.export_md.await_count == 1)
        app.ai_conversations_client.export_md.assert_awaited_once_with(
            "conversation-one", Path("report café [literal].md"),
        )
        assert app.screen is screen
