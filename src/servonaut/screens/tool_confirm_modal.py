"""Confirmation modals for AI-originated tool calls.

Two ModalScreen flavours, sized by the tool's ``guard_level``:

- :class:`ToolConfirmModal` — single y/n for ``standard`` tools
  (``run_command``, ``transfer_file``).
- :class:`DangerousToolConfirmModal` — typed-confirm "RUN" for
  ``dangerous`` tools (``deploy``, ``provision``, ``security_scan``).

Both present a brief blocking choice over the current conversation;
dismissing the prompt returns to chat. All user-influenced strings (tool names,
arg values from the model) are built as ``Content`` and never parsed as
markup, so what the user approves is exactly what the model sent.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
from typing import Any, Awaitable, Callable, Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.content import Content
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Input, Static

from servonaut.utils.markup import literal
from servonaut.widgets.dialogs import (
    DIALOG_VERTICAL_BREAKPOINTS,
    DialogActions,
    DialogBody,
    DialogFrame,
    DialogNotificationSpace,
)
from servonaut.widgets.safe_header import SafeHeader

logger = logging.getLogger(__name__)


# How to reach the rest. The modal binds these keys itself, so they scroll the
# argument box whichever control has the focus.
_CUE_HOW = "Down or Page Down, or the mouse."

_ARG_SCROLL_BINDINGS = [
    Binding("down", "scroll_args(1)", "Scroll", show=False),
    Binding("up", "scroll_args(-1)", "Scroll", show=False),
    Binding("pagedown", "page_args(1)", "Scroll", show=False),
    Binding("pageup", "page_args(-1)", "Scroll", show=False),
]


def _show_overflow_cue(screen: ModalScreen, prefix: str) -> None:
    """Say how much of the arguments is still below the box.

    What the user approves must be readable in full: a cut with no sign of it
    would let a long value hide its tail. The line keeps its row while the
    text is longer than the box, so scrolling never moves the layout.
    """
    try:
        scroll = screen.query_one(f"#{prefix}_confirm_scroll", VerticalScroll)
        cue = screen.query_one(f"#{prefix}_confirm_more", Static)
    except Exception:  # pragma: no cover - modal closed meanwhile
        return
    cue.display = scroll.max_scroll_y > 0
    remaining = math.ceil(scroll.max_scroll_y - scroll.scroll_y)
    if remaining > 0:
        cue.update(f"{remaining} more lines below: {_CUE_HOW}")
    else:
        cue.update("End of the text.")


def _follow_scroll(screen: ModalScreen, prefix: str) -> None:
    """Keep the cue in step with the scroll position (keys, wheel, scrollbar)."""
    scroll = screen.query_one(f"#{prefix}_confirm_scroll", VerticalScroll)
    screen.watch(scroll, "scroll_y", lambda _old, _new: _show_overflow_cue(screen, prefix))
    screen.call_after_refresh(_show_overflow_cue, screen, prefix)


def _arguments_box(args: Dict[str, Any], prefix: str) -> DialogBody:
    """The frame-sized, scrolling argument text."""
    return DialogBody(
        Static(_format_args(args), id=f"{prefix}_confirm_args"),
        id=f"{prefix}_confirm_scroll",
    )


def _overflow_cue(prefix: str) -> Static:
    """The line, pinned beside the actions, that follows the scroll position."""
    return Static("", id=f"{prefix}_confirm_more", classes="dialog-scroll-cue")


class _ArgumentScrollMixin:
    """Scroll the argument box from the keyboard whatever has the focus."""

    _prefix = "tool"

    def _argument_box(self) -> VerticalScroll:
        return self.query_one(f"#{self._prefix}_confirm_scroll", VerticalScroll)  # type: ignore[attr-defined]

    def action_scroll_args(self, delta: int) -> None:
        self._argument_box().scroll_relative(y=delta, animate=False)

    def action_page_args(self, delta: int) -> None:
        box = self._argument_box()
        box.scroll_relative(y=delta * max(1, box.size.height - 1), animate=False)


# Typed-confirm magic word for dangerous tools. Match is case-sensitive;
# wrong values leave the modal open and show a correction hint.
_DANGEROUS_CONFIRM_WORD = "RUN"


def _format_args(args: Dict[str, Any]) -> Content:
    """Render an args dict as ``key: value`` lines, one per argument.

    Every value is shown in full: the user approves what is displayed, so
    nothing may be cut or hidden. The argument area scrolls. Non-string
    values are JSON-serialised for compact display so a list of paths shows
    up without Python's repr noise.
    """
    if not args:
        return Content.styled("<no arguments>", "dim")
    lines = []
    for key, value in args.items():
        if isinstance(value, str):
            display = value
        else:
            try:
                display = json.dumps(value, default=str)
            except (TypeError, ValueError):
                display = str(value)
        lines.append(Content.assemble(literal(f"{key}:", "dim"), " ", literal(display)))
    return Content("\n").join(lines)


def _note_of(call: Any) -> str:
    note = getattr(call, "confirm_note", "")
    return note if isinstance(note, str) else ""


def _note_widgets(note: str, widget_id: str) -> List[Static]:
    """The optional one-line note under the dialog body; empty when no note."""
    if not note:
        return []
    return [Static(literal(note), id=widget_id, classes="tool_confirm_note")]


# ---------------------------------------------------------------------------
# Standard (single y/n) confirm modal
# ---------------------------------------------------------------------------


class ToolConfirmModal(_ArgumentScrollMixin, ModalScreen[bool]):
    """Single-line y/n confirm for ``standard`` guard-level tools.

    Returns ``True`` when the user clicks "Confirm" or presses ``y``;
    ``False`` for "Cancel" / Escape / ``n``.
    """

    BINDINGS = [
        Binding("escape", "deny", "Cancel", show=True),
        Binding("y", "approve", "Yes", show=True),
        Binding("n", "deny", "No", show=True),
        *_ARG_SCROLL_BINDINGS,
    ]

    AUTO_FOCUS = "#btn_tool_cancel"
    VERTICAL_BREAKPOINTS = DIALOG_VERTICAL_BREAKPOINTS

    def __init__(
        self,
        tool: str,
        args: Optional[Dict[str, Any]] = None,
        note: str = "",
    ) -> None:
        super().__init__(classes="dialog-screen dialog-approval")
        self._tool = tool or "<unknown tool>"
        self._args = args or {}
        self._note = note

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static(
                literal(self._tool, "bold $text-accent"),
                id="tool_confirm_title",
            ),
            body=_arguments_box(self._args, "tool"),
            status=Vertical(
                *_note_widgets(self._note, "tool_confirm_note"),
                _overflow_cue("tool"),
                Static(
                    "Servonaut AI wants to run this tool. "
                    "Press [bold]y[/bold] to confirm or [bold]n[/bold] to cancel.",
                    id="tool_confirm_body",
                ),
            ),
            actions=DialogActions(
                Button("Confirm", id="btn_tool_confirm", variant="primary"),
                Button("Cancel", id="btn_tool_cancel", variant="default"),
                id="tool_confirm_buttons",
            ),
            id="tool_confirm_container",
            overflow_hint=False,
        )
        yield Footer()

    def on_mount(self) -> None:
        _follow_scroll(self, "tool")

    def on_resize(self) -> None:
        self.call_after_refresh(_show_overflow_cue, self, "tool")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_tool_confirm":
            self.dismiss(True)
        elif event.button.id == "btn_tool_cancel":
            self.dismiss(False)

    def action_approve(self) -> None:
        self.dismiss(True)

    def action_deny(self) -> None:
        self.dismiss(False)


# ---------------------------------------------------------------------------
# Dangerous (typed-confirm RUN) modal
# ---------------------------------------------------------------------------


class DangerousToolConfirmModal(_ArgumentScrollMixin, ModalScreen[bool]):
    """Typed-confirm "RUN" modal for ``dangerous`` guard-level tools.

    The user must type case-sensitive ``RUN``, with optional surrounding
    whitespace, for ``True``. Wrong or empty input shows a hint and keeps
    the modal open; Cancel and Escape return ``False``. This is additional
    confirmation; the server enforces the ``allow_dangerous_ai_tools``
    entitlement separately.
    """

    BINDINGS = [
        Binding("escape", "deny", "Cancel", show=True),
        *_ARG_SCROLL_BINDINGS,
    ]

    _prefix = "dangerous"
    AUTO_FOCUS = "#dangerous_confirm_input"
    VERTICAL_BREAKPOINTS = DIALOG_VERTICAL_BREAKPOINTS

    DEFAULT_CSS = """
    DangerousToolConfirmModal #dangerous_confirm_error {
        color: $error;
        display: none;
    }

    DangerousToolConfirmModal #dangerous_confirm_error.visible {
        display: block;
    }

    """

    def __init__(
        self,
        tool: str,
        args: Optional[Dict[str, Any]] = None,
        note: str = "",
    ) -> None:
        super().__init__(classes="dialog-screen dialog-approval")
        self._tool = tool or "<unknown tool>"
        self._args = args or {}
        self._note = note

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static(
                Content.assemble(
                    Content.styled("Dangerous tool:", "bold $text-error"),
                    " ",
                    literal(self._tool, "bold $text-error"),
                ),
                id="dangerous_confirm_title",
            ),
            body=_arguments_box(self._args, "dangerous"),
            status=Vertical(
                *_note_widgets(self._note, "dangerous_confirm_note"),
                _overflow_cue("dangerous"),
                Static(
                    "Servonaut AI wants to run a [bold]potentially destructive[/bold] tool. "
                    f"Type [bold]{_DANGEROUS_CONFIRM_WORD}[/bold] below to confirm, or press Escape to cancel.",
                    id="dangerous_confirm_body",
                ),
                Input(
                    placeholder=f"Type {_DANGEROUS_CONFIRM_WORD} to confirm",
                    id="dangerous_confirm_input",
                ),
                Static("", id="dangerous_confirm_error"),
            ),
            actions=DialogActions(
                Button("Confirm", id="btn_dangerous_confirm", variant="error"),
                Button("Cancel", id="btn_dangerous_cancel", variant="default"),
                id="dangerous_confirm_buttons",
            ),
            id="dangerous_confirm_container",
            overflow_hint=False,
            severity="danger",
        )
        yield Footer()

    def on_resize(self) -> None:
        self.call_after_refresh(_show_overflow_cue, self, "dangerous")

    def on_mount(self) -> None:
        _follow_scroll(self, "dangerous")
        # Focus the input so the user can type immediately.
        try:
            self.query_one("#dangerous_confirm_input", Input).focus()
        except Exception:  # pragma: no cover - defensive
            pass

    def _typed_run(self) -> bool:
        try:
            value = self.query_one("#dangerous_confirm_input", Input).value
        except Exception:  # pragma: no cover - defensive
            return False
        # Tolerate surrounding whitespace (a trailing space from the user
        # or a paste is not intent to cancel) but keep the word match
        # case-sensitive — the typed-confirm is a deliberate friction.
        return value.strip() == _DANGEROUS_CONFIRM_WORD

    def _confirm_or_reprompt(self) -> None:
        """Approve on an exact ``RUN``; otherwise keep the modal open.

        A wrong/empty value must NEVER silently dismiss the modal — Enter
        is the universal "submit" reflex and a silent cancel here looks
        like the confirm was lost. Only Escape / Cancel deny; everything
        else either confirms or re-prompts with a visible hint.
        """
        if self._typed_run():
            self.dismiss(True)
            return
        try:
            err = self.query_one("#dangerous_confirm_error", Static)
            err.update(
                f"Type [bold]{_DANGEROUS_CONFIRM_WORD}[/bold] exactly to confirm, "
                "or press Escape to cancel."
            )
            err.add_class("visible")
            self.query_one("#dangerous_confirm_input", Input).focus()
        except Exception:  # pragma: no cover - defensive
            pass

    def on_input_submitted(self, event: Input.Submitted) -> None:
        # Pressing Enter inside the input confirms on an exact match and
        # otherwise re-prompts — it does not deny.
        self._confirm_or_reprompt()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_dangerous_confirm":
            self._confirm_or_reprompt()
        elif event.button.id == "btn_dangerous_cancel":
            self.dismiss(False)

    def action_deny(self) -> None:
        self.dismiss(False)


def build_modal_confirm(app: Any) -> Callable[[Any], Awaitable[bool]]:
    """Confirm callback that pushes the right modal and awaits the answer.

    Must be awaited from a worker (``push_screen_wait``). When the awaiting
    task is cancelled — the tool bridge's confirmation deadline passed, or
    the chat turn was cancelled — the prompt is closed so an answer given
    afterwards cannot look like it did anything.
    """

    async def _confirm(call: Any) -> bool:
        shown_args = dict(call.args)
        from servonaut.services.ai_tool_bridge import command_to_send

        checked = command_to_send(call)
        if isinstance(checked, str):
            # Show the text that will run, not the text the model wrote.
            shown_args["command"] = checked
        if call.guard_level == "dangerous":
            modal: ModalScreen[bool] = DangerousToolConfirmModal(
                call.tool, shown_args, note=_note_of(call),
            )
        else:
            modal = ToolConfirmModal(
                call.tool, shown_args, note=_note_of(call),
            )
        try:
            result = await app.push_screen_wait(modal)
        except asyncio.CancelledError:
            _close_if_top(app, modal)
            raise
        except Exception:  # pragma: no cover — defensive
            logger.exception("push_screen_wait failed for tool confirm")
            return False
        return bool(result)

    return _confirm


def _close_if_top(app: Any, modal: ModalScreen) -> None:
    """Close *modal* if it is still the active screen; never raises.

    A prompt that is no longer on top is left alone: dismissing pops the
    top screen, which would close whatever the user opened over it. Its
    answer goes nowhere either way, because nothing awaits it any more.
    """
    try:
        if app.screen is modal:
            modal.dismiss(False)
    except Exception:  # noqa: BLE001 — best-effort cleanup
        logger.debug("Could not close an expired tool prompt", exc_info=True)


__all__ = [
    "ToolConfirmModal",
    "DangerousToolConfirmModal",
    "build_modal_confirm",
]
