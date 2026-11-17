"""Mounted contracts for basic dialogs using the application stylesheet."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from textual.app import App, ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from servonaut.screens.backup_restore import BackupConfirmModal
from servonaut.screens.secrets_clear_modal import ConfirmClearCacheModal
from servonaut.screens.snapshot_manager import (
    ConfirmModal,
    LabelInputModal,
    SnapshotManagerScreen,
)
from servonaut.screens.voice_model_cleanup_modal import VoiceModelCleanupModal
from servonaut.services.voice_setup_service import InstalledModel
from servonaut.styles import CSS_FILES
from servonaut.styles.themes import SERVONAUT_THEMES
from servonaut.widgets.dialogs import DialogActions, DialogBody, DialogFrame


class BasicDialogHost(App):
    """Mount real modals without reading configuration or constructing services."""

    CSS_PATH = CSS_FILES

    def __init__(self) -> None:
        super().__init__()
        for theme in SERVONAUT_THEMES:
            self.register_theme(theme)
        self.theme = "servonaut"
        self.animation_level = "none"

    def compose(self) -> ComposeResult:
        yield Input(id="origin")


def make_dialog(kind: str, *, long: bool = False) -> tuple[ModalScreen, str, str]:
    """Return a real modal, its safe target, and its explicit confirmation target."""
    message = "\n".join(["Review the example configuration."] * (45 if long else 1))
    if kind == "clear":
        return ConfirmClearCacheModal(), "confirm_clear_no", "confirm_clear_yes"
    if kind == "voice":
        models = [
            InstalledModel(
                engine="example", label=f"Unused model {index + 1}", key=str(index),
                path=Path("/tmp/example-model-cache"), size_bytes=1024, in_use=False,
            )
            for index in range(45 if long else 1)
        ]
        return VoiceModelCleanupModal(models, "Active model"), "vmc_keep", "vmc_remove"
    if kind == "backup":
        return BackupConfirmModal(message), "btn_bkp_no", "btn_bkp_yes"
    if kind == "snapshot":
        return ConfirmModal("Restore snapshot", message), "btn_confirm_no", "btn_confirm_yes"
    return LabelInputModal("Rename snapshot"), "label_input", "btn_label_save"


def assert_exposed(app: App, screen: ModalScreen, widget: Static | Input | Button) -> None:
    """Check both layout containment and the widget painted at its integer cells."""
    assert screen.query_one(DialogFrame).content_region.contains_region(widget.region)
    assert screen.region.contains_region(widget.region)
    for y in range(widget.region.y, widget.region.bottom):
        for x in range(widget.region.x, widget.region.right):
            assert app.get_widget_at(x, y)[0] is widget


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["clear", "voice", "backup", "snapshot"])
async def test_safe_default_enter_cancels_and_restores_focus(
    kind: str, size: tuple[int, int],
) -> None:
    """An accidental Enter must not clear, remove, or restore anything."""
    app = BasicDialogHost()
    screen, _, _ = make_dialog(kind)
    results: list[bool] = []
    async with app.run_test(size=size) as pilot:
        origin = app.query_one("#origin", Input)
        origin.focus()
        app.push_screen(screen, results.append)
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert results == [False]
        assert app.screen is not screen and app.focused is origin


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["clear", "voice", "backup", "snapshot", "label"])
async def test_explicit_confirm_click_keeps_exact_result_contract(
    kind: str, size: tuple[int, int],
) -> None:
    app = BasicDialogHost()
    screen, safe_id, confirm_id = make_dialog(kind)
    results: list[bool | str | None] = []
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        assert screen.focused is screen.query_one(f"#{safe_id}")
        if kind == "label":
            screen.query_one("#label_input", Input).value = "  example [red] label  "
        button = screen.query_one(f"#{confirm_id}", Button)
        assert_exposed(app, screen, button)
        assert await pilot.click(button)
        await pilot.pause()
        assert results == ["example [red] label" if kind == "label" else True]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["clear", "backup", "snapshot"])
@pytest.mark.parametrize("key, expected", [("y", True), ("n", False), ("escape", False)])
async def test_confirmation_shortcuts_preserve_bool_result(
    kind: str, key: str, expected: bool,
) -> None:
    app = BasicDialogHost()
    screen, _, _ = make_dialog(kind)
    results: list[bool] = []
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        await pilot.press(key)
        await pilot.pause()
        assert results == [expected]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["voice", "label"])
@pytest.mark.parametrize("cancel_method", ["escape", "click"])
async def test_keep_and_label_cancel_preserve_false_and_none(
    kind: str, cancel_method: str,
) -> None:
    app = BasicDialogHost()
    screen, safe_id, _ = make_dialog(kind)
    results: list[bool | None] = []
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        if cancel_method == "escape":
            await pilot.press("escape")
        else:
            cancel_id = "btn_label_cancel" if kind == "label" else safe_id
            assert await pilot.click(screen.query_one(f"#{cancel_id}", Button))
        await pilot.pause()
        assert results == [None if kind == "label" else False]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("value", ["", "   ", "x" * 101])
async def test_label_validation_remains_open_with_exposed_error(
    size: tuple[int, int], value: str,
) -> None:
    app = BasicDialogHost()
    screen = LabelInputModal("Rename snapshot", initial=value)
    results: list[str | None] = []
    async with app.run_test(size=size, notifications=True) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        app.notify("Example notification.", timeout=60)
        await pilot.press("enter")
        await pilot.pause()
        error = screen.query_one("#label_modal_error", Static)
        expected = "100 characters or fewer" if len(value) > 100 else "cannot be empty"
        assert expected in error.render().plain
        assert app.screen is screen and results == []
        assert_exposed(app, screen, error)
        assert_exposed(app, screen, screen.query_one("#label_input", Input))
        save = screen.query_one("#btn_label_save", Button)
        assert_exposed(app, screen, save)
        assert await pilot.click(save)
        await pilot.pause()
        assert app.screen is screen and results == []
        await pilot.press("escape")
        await pilot.pause()
        assert results == [None]


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["  x  ", "  " + "x" * 100 + "  "])
@pytest.mark.parametrize("submit_method", ["enter", "click"])
async def test_label_accepts_trimmed_boundary_lengths(value: str, submit_method: str) -> None:
    app = BasicDialogHost()
    screen = LabelInputModal("New snapshot", initial=value, placeholder="Example label")
    results: list[str | None] = []
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen, results.append)
        await pilot.pause()
        assert screen.query_one("#label_input", Input).placeholder == "Example label"
        if submit_method == "enter":
            await pilot.press("enter")
        else:
            assert await pilot.click(screen.query_one("#btn_label_save", Button))
        await pilot.pause()
        assert results == [value.strip()]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["voice", "backup", "snapshot"])
async def test_long_content_scrolls_with_pinned_actions_and_status(
    kind: str, size: tuple[int, int],
) -> None:
    app = BasicDialogHost()
    screen, safe_id, _ = make_dialog(kind, long=True)
    async with app.run_test(size=size) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        assert screen.focused is screen.query_one(f"#{safe_id}")
        body = screen.query_one(DialogBody)
        frame = screen.query_one(DialogFrame)
        assert body.max_scroll_y > 0 and frame.border_subtitle
        buttons = list(screen.query_one(DialogActions).query(Button))
        original_regions = [button.region for button in buttons]
        body.focus()
        await pilot.press("pagedown")
        await pilot.pause()
        assert body.scroll_y > 0 and frame.max_scroll_y == 0
        assert [button.region for button in buttons] == original_regions
        for button in buttons:
            assert_exposed(app, screen, button)
        if kind == "voice":
            assert_exposed(app, screen, screen.query_one("#vmc_total", Static))
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("kind", ["clear", "voice", "backup", "snapshot", "label"])
async def test_notifications_leave_modal_targets_stationary_and_clickable(
    kind: str, size: tuple[int, int],
) -> None:
    app = BasicDialogHost()
    screen, _, _ = make_dialog(kind)
    async with app.run_test(size=size, notifications=True) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        frame = screen.query_one(DialogFrame)
        original_frame = frame.region
        buttons = list(screen.query_one(DialogActions).query(Button))
        original_regions = [button.region for button in buttons]
        for count in (1, 8, 0):
            if not count:
                app.clear_notifications()
            else:
                for index in range(len(screen.query("Toast")), count):
                    app.notify(f"Example operation {index + 1}.", timeout=60)
            await pilot.pause()
            assert len(screen.query("Toast")) == count
            assert frame.region == original_frame
            assert [button.region for button in buttons] == original_regions
            for button in buttons:
                assert_exposed(app, screen, button)
        await pilot.press("escape")


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["restore", "delete"])
@pytest.mark.parametrize("label", ["a[/b]c", "x[red]y"])
async def test_snapshot_confirmation_treats_label_as_literal(
    action: str, label: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Labels accepted by the editor must not become Rich tags in confirmations."""
    owner = SnapshotManagerScreen()
    snapshot = {"id": "example", "label": label}
    capture = MagicMock()
    monkeypatch.setattr(owner, "_selected", lambda: snapshot)
    with patch.object(SnapshotManagerScreen, "app", new_callable=PropertyMock, return_value=capture):
        if action == "restore":
            owner._confirm_and_restore(snapshot)
        else:
            owner.action_delete()
    screen = capture.push_screen.call_args.args[0]
    app = BasicDialogHost()
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(screen)
        await pilot.pause()
        text = screen.query_one("#confirm_modal_message", Static).render().plain
        if action == "restore":
            assert text == (
                f"Replace your local config with snapshot {label}?\n"
                "Local-only fields (instance keys, paths) will be preserved."
            )
        else:
            assert text == f"Permanently delete {label}?\nThis cannot be undone."
        await pilot.press("escape")
