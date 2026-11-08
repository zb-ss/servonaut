"""Confirmation modals for AI-originated tool calls (T6).

Two ModalScreen flavours, sized by the tool's ``guard_level``:

- :class:`ToolConfirmModal` — single y/n for ``standard`` tools
  (``run_command``, ``transfer_file``).
- :class:`DangerousToolConfirmModal` — typed-confirm "RUN" for
  ``dangerous`` tools (``deploy``, ``provision``, ``security_scan``).

Per the "ModalScreen vs Screen" convention: both fit the
"brief blocking choice" pattern (small surface, single decision, dim
background returns to chat). All user-influenced strings (tool names,
arg values from the model) are built as ``Content`` and never parsed as
markup, so what the user approves is exactly what the model sent.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Awaitable, Callable, Dict, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.content import Content
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Input, Static

from servonaut.utils.markup import literal
from servonaut.widgets.safe_header import SafeHeader

logger = logging.getLogger(__name__)


# How to reach the rest, per modal: the standard modal starts with the box
# focused, in the dangerous one the typed-confirm input has the focus first.
_CUES = {
    "tool": "Longer than the box: scroll with the arrow keys or the mouse to read it all.",
    "dangerous": (
        "Longer than the box: press Shift+Tab, then the arrow keys, "
        "or scroll with the mouse to read it all."
    ),
}


def _show_overflow_cue(screen: ModalScreen, prefix: str) -> None:
    """Say so when the arguments are longer than their box.

    What the user approves must be readable in full: a cut with no sign of it
    would let a long value hide its tail.
    """
    try:
        scroll = screen.query_one(f"#{prefix}_confirm_scroll", VerticalScroll)
        cue = screen.query_one(f"#{prefix}_confirm_more", Static)
    except Exception:  # pragma: no cover - modal closed meanwhile
        return
    cue.display = scroll.max_scroll_y > 0
    cue.update(_CUES[prefix])


# Typed-confirm magic word for dangerous tools. Match is case-sensitive;
# anything else returns False.
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


# ---------------------------------------------------------------------------
# Standard (single y/n) confirm modal
# ---------------------------------------------------------------------------


class ToolConfirmModal(ModalScreen[bool]):
    """Single-line y/n confirm for ``standard`` guard-level tools.

    Returns ``True`` when the user clicks "Confirm" or presses ``y``;
    ``False`` for "Cancel" / Escape / ``n``.
    """

    BINDINGS = [
        Binding("escape", "deny", "Cancel", show=True),
        Binding("y", "approve", "Yes", show=True),
        Binding("n", "deny", "No", show=True),
    ]

    DEFAULT_CSS = """
    ToolConfirmModal {
        align: center middle;
    }

    ToolConfirmModal #tool_confirm_container {
        width: 80;
        height: auto;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }

    ToolConfirmModal #tool_confirm_title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }

    ToolConfirmModal #tool_confirm_body {
        margin-bottom: 1;
    }

    ToolConfirmModal #tool_confirm_scroll {
        height: auto;
        max-height: 12;
        margin-bottom: 0;
    }

    ToolConfirmModal #tool_confirm_more {
        color: $text-warning;
        margin-bottom: 1;
        display: none;
    }

    ToolConfirmModal #tool_confirm_buttons {
        height: auto;
        align: center middle;
    }

    ToolConfirmModal #tool_confirm_buttons Button {
        margin: 0 1;
    }
    """

    def __init__(self, tool: str, args: Optional[Dict[str, Any]] = None) -> None:
        super().__init__()
        self._tool = tool or "<unknown tool>"
        self._args = args or {}

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield Container(
            Static(
                literal(self._tool, "bold"),
                id="tool_confirm_title",
            ),
            Static(
                "Servonaut AI wants to run this tool. "
                "Press [bold]y[/bold] to confirm or [bold]n[/bold] to cancel.",
                id="tool_confirm_body",
            ),
            VerticalScroll(
                Static(_format_args(self._args), id="tool_confirm_args"),
                id="tool_confirm_scroll",
            ),
            Static("", id="tool_confirm_more"),
            Horizontal(
                Button("Confirm", id="btn_tool_confirm", variant="primary"),
                Button("Cancel", id="btn_tool_cancel", variant="default"),
                id="tool_confirm_buttons",
            ),
            id="tool_confirm_container",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.call_after_refresh(_show_overflow_cue, self, "tool")

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


class DangerousToolConfirmModal(ModalScreen[bool]):
    """Typed-confirm "RUN" modal for ``dangerous`` guard-level tools.

    The user must type the literal string ``RUN`` (case-sensitive) into
    the Input field for ``True``; anything else (including pressing
    Confirm with the wrong word) returns ``False``. Per architect plan
    Risk §9: this is defense-in-depth, the server already enforces the
    ``allow_dangerous_ai_tools`` entitlement.
    """

    BINDINGS = [
        Binding("escape", "deny", "Cancel", show=True),
    ]

    DEFAULT_CSS = """
    DangerousToolConfirmModal {
        align: center middle;
    }

    DangerousToolConfirmModal #dangerous_confirm_container {
        width: 84;
        height: auto;
        border: round $error;
        background: $surface;
        padding: 1 2;
    }

    DangerousToolConfirmModal #dangerous_confirm_title {
        text-style: bold;
        color: $error;
        margin-bottom: 1;
    }

    DangerousToolConfirmModal #dangerous_confirm_body {
        margin-bottom: 1;
    }

    DangerousToolConfirmModal #dangerous_confirm_scroll {
        height: auto;
        max-height: 10;
        margin-bottom: 0;
    }

    DangerousToolConfirmModal #dangerous_confirm_more {
        color: $text-warning;
        margin-bottom: 1;
        display: none;
    }

    DangerousToolConfirmModal #dangerous_confirm_input {
        margin-bottom: 1;
    }

    DangerousToolConfirmModal #dangerous_confirm_error {
        color: $error;
        margin-bottom: 1;
        display: none;
    }

    DangerousToolConfirmModal #dangerous_confirm_error.visible {
        display: block;
    }

    DangerousToolConfirmModal #dangerous_confirm_buttons {
        height: auto;
        align: center middle;
    }

    DangerousToolConfirmModal #dangerous_confirm_buttons Button {
        margin: 0 1;
    }
    """

    def __init__(self, tool: str, args: Optional[Dict[str, Any]] = None) -> None:
        super().__init__()
        self._tool = tool or "<unknown tool>"
        self._args = args or {}

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield Container(
            Static(
                Content.assemble(
                    Content.styled("Dangerous tool:", "bold"),
                    " ",
                    literal(self._tool, "bold"),
                ),
                id="dangerous_confirm_title",
            ),
            Static(
                "Servonaut AI wants to run a [bold]potentially destructive[/bold] tool. "
                f"Type [bold]{_DANGEROUS_CONFIRM_WORD}[/bold] below to confirm, or press Escape to cancel.",
                id="dangerous_confirm_body",
            ),
            VerticalScroll(
                Static(_format_args(self._args), id="dangerous_confirm_args"),
                id="dangerous_confirm_scroll",
            ),
            Static("", id="dangerous_confirm_more"),
            Input(
                placeholder=f"Type {_DANGEROUS_CONFIRM_WORD} to confirm",
                id="dangerous_confirm_input",
            ),
            Static("", id="dangerous_confirm_error"),
            Horizontal(
                Button("Confirm", id="btn_dangerous_confirm", variant="error"),
                Button("Cancel", id="btn_dangerous_cancel", variant="default"),
                id="dangerous_confirm_buttons",
            ),
            id="dangerous_confirm_container",
        )
        yield Footer()

    def on_resize(self) -> None:
        self.call_after_refresh(_show_overflow_cue, self, "dangerous")

    def on_mount(self) -> None:
        self.call_after_refresh(_show_overflow_cue, self, "dangerous")
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
        if call.guard_level == "dangerous":
            modal: ModalScreen[bool] = DangerousToolConfirmModal(call.tool, dict(call.args))
        else:
            modal = ToolConfirmModal(call.tool, dict(call.args))
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
