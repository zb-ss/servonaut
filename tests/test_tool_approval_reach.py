"""Tool approvals: every argument line and the scroll cue are drawn at any height."""
from __future__ import annotations

import pytest
from textual.app import App
from textual.containers import VerticalScroll
from textual.widgets import Button, Input, Static

from servonaut.screens.tool_confirm_modal import DangerousToolConfirmModal, ToolConfirmModal
from servonaut.styles import CSS_FILES

ARGS = {f"option {i:02d}": f"value {i:02d}" for i in range(1, 40)}
ARGS["zz_final"] = "LAST-LINE-VISIBLE"


class _Host(App):
    CSS_PATH = CSS_FILES

    def __init__(self, modal) -> None:
        super().__init__()
        self._modal = modal
        self.dismissed: list = []

    def on_mount(self) -> None:
        self.push_screen(self._modal, callback=self.dismissed.append)


def _drawn(app) -> str:
    strips = app.screen._compositor.render_strips()
    return "\n".join("".join(segment.text for segment in strip) for strip in strips)


async def _settled(pilot, screen, prefix):
    for _ in range(60):
        await pilot.pause(0.05)
        cue = screen.query_one(f"#{prefix}_confirm_more", Static)
        if cue.display:
            return
    raise AssertionError("the cue never appeared")


MODALS = [(ToolConfirmModal, "tool"), (DangerousToolConfirmModal, "dangerous")]
SIZES = [(80, 24), (100, 30), (160, 50)]


@pytest.mark.asyncio
@pytest.mark.parametrize("modal_cls,prefix", MODALS)
@pytest.mark.parametrize("size", SIZES)
async def test_the_last_argument_and_the_cue_are_drawn(modal_cls, prefix, size) -> None:
    app = _Host(modal_cls("run_command", dict(ARGS)))
    async with app.run_test(size=size) as pilot:
        await _settled(pilot, app.screen, prefix)
        assert "more lines below: Down or Page Down, or the mouse." in _drawn(app)
        assert "LAST-LINE-VISIBLE" not in _drawn(app)
        scroll = app.screen.query_one(f"#{prefix}_confirm_scroll", VerticalScroll)
        scroll.scroll_end(animate=False)
        await pilot.pause(0.3)
        drawn = _drawn(app)
        assert "LAST-LINE-VISIBLE" in drawn
        assert "End of the text." in drawn
        for button in app.screen.query(Button):
            assert button.region.area > 0 and button.region.bottom <= app.size.height


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(80, 24), (100, 30)])
async def test_the_cue_shows_lines_remaining_in_full_while_some_are_below(size) -> None:
    app = _Host(ToolConfirmModal("run_command", dict(ARGS)))
    async with app.run_test(size=size) as pilot:
        await _settled(pilot, app.screen, "tool")
        await pilot.press("down")
        await pilot.pause(0.2)
        assert "more lines below: Down or Page Down, or the mouse." in _drawn(app)


@pytest.mark.asyncio
async def test_enter_on_cancel_still_cancels_and_keys_never_approve() -> None:
    app = _Host(ToolConfirmModal("run_command", dict(ARGS)))
    async with app.run_test(size=(80, 24)) as pilot:
        await _settled(pilot, app.screen, "tool")
        await pilot.press("down", "pagedown", "up", "pageup")
        assert app.dismissed == []
        await pilot.press("enter")
        await pilot.pause(0.1)
    assert app.dismissed == [False]


@pytest.mark.asyncio
async def test_typing_run_still_confirms_after_scrolling_with_the_input_focused() -> None:
    app = _Host(DangerousToolConfirmModal("deploy", dict(ARGS)))
    async with app.run_test(size=(80, 24)) as pilot:
        await _settled(pilot, app.screen, "dangerous")
        await pilot.press("down", "pagedown")
        scroll = app.screen.query_one("#dangerous_confirm_scroll", VerticalScroll)
        assert scroll.scroll_y > 0
        await pilot.press("R", "U", "N")
        assert app.screen.query_one("#dangerous_confirm_input", Input).value == "RUN"
        await pilot.press("enter")
        await pilot.pause(0.1)
    assert app.dismissed == [True]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("long_undo", [False, True])
async def test_the_remediation_command_is_drawn_and_reachable(size, long_undo) -> None:
    from servonaut.screens.remediation_confirm import RemediationConfirmModal
    from tests.test_safety_dialogs import make_preview

    preview = make_preview(long=True, long_undo=long_undo)
    app = _Host(RemediationConfirmModal(preview, dry_run=False))
    async with app.run_test(size=size) as pilot:
        await pilot.pause(0.5)
        body = app.screen.query_one("#remediation_confirm_scroll", VerticalScroll)
        assert body.size.height >= 3
        drawn = _drawn(app)
        assert "Exact command (server-signed):" in drawn
        assert "example step 1 [red]literal[/red]" in drawn
        body.scroll_end(animate=False)
        await pilot.pause(0.3)
        assert "example step 45 [red]literal[/red]" in _drawn(app)
        for button in app.screen.query(Button):
            assert button.region.area > 0 and button.region.bottom <= app.size.height


@pytest.mark.asyncio
@pytest.mark.parametrize("modal_cls,prefix,rows", [
    (ToolConfirmModal, "tool", 9), (DangerousToolConfirmModal, "dangerous", 6),
])
async def test_the_arguments_use_the_spare_rows_of_a_short_terminal(modal_cls, prefix, rows) -> None:
    app = _Host(modal_cls("run_command", dict(ARGS)))
    async with app.run_test(size=(80, 24)) as pilot:
        await _settled(pilot, app.screen, prefix)
        assert app.screen.query_one(f"#{prefix}_confirm_scroll").size.height >= rows
        # The heading stays below the toast lane's first rows.
        assert app.screen.query_one(f"#{prefix}_confirm_title").region.y >= 4


@pytest.mark.asyncio
@pytest.mark.parametrize("modal_cls,prefix", MODALS)
async def test_an_approval_shows_one_scroll_cue_not_two(modal_cls, prefix) -> None:
    from servonaut.widgets.dialogs import DialogFrame

    app = _Host(modal_cls("run_command", dict(ARGS)))
    async with app.run_test(size=(100, 30)) as pilot:
        await _settled(pilot, app.screen, prefix)
        assert app.screen.query_one(DialogFrame).border_subtitle == ""
        assert "Scroll for all details" not in _drawn(app)


@pytest.mark.asyncio
async def test_other_dialogs_keep_the_border_hint() -> None:
    from servonaut.screens.remediation_confirm import RemediationConfirmModal
    from servonaut.widgets.dialogs import DialogFrame
    from tests.test_safety_dialogs import make_preview

    app = _Host(RemediationConfirmModal(make_preview(long=True), dry_run=False))
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.5)
        assert app.screen.query_one(DialogFrame).border_subtitle == "Scroll for all details"


@pytest.mark.asyncio
@pytest.mark.parametrize("size,undo_rows", [((80, 24), 1), ((80, 29), 1), ((100, 30), 3), ((160, 50), 3)])
async def test_the_undo_box_shrinks_only_on_a_short_terminal(size, undo_rows) -> None:
    from servonaut.screens.remediation_confirm import RemediationConfirmModal
    from tests.test_safety_dialogs import make_preview

    app = _Host(RemediationConfirmModal(make_preview(long=False, long_undo=True), dry_run=False))
    async with app.run_test(size=size) as pilot:
        await pilot.pause(0.5)
        undo = app.screen.query_one("#remediation_confirm_revert").parent
        assert undo.size.height == undo_rows
        assert app.screen.query_one("#remediation_confirm_scroll").size.height >= 3
