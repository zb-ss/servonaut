"""Confirmation modals for AI-originated tool calls (T6).

Two ModalScreen flavours, sized by the tool's ``guard_level``:

- :class:`ToolConfirmModal` — single y/n for ``standard`` tools
  (``run_command``, ``transfer_file``).
- :class:`DangerousToolConfirmModal` — typed-confirm "RUN" for
  ``dangerous`` tools (``deploy``, ``provision``, ``security_scan``).

Per the "ModalScreen vs Screen" convention: both fit the
"brief blocking choice" pattern (small surface, single decision, dim
background returns to chat). All user-influenced strings (tool names,
arg values from the model) are passed through ``rich.markup.escape``
before interpolation — the model output can contain rich-markup
metacharacters and we don't want a malformed brace to corrupt the row.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Header, Input, Static


# Maximum displayed length per arg value before we truncate. Models
# can dump multi-KB blobs into args (e.g. file content for transfer);
# long values blow out the modal layout.
_MAX_ARG_VALUE_LEN = 200

# Typed-confirm magic word for dangerous tools. Match is case-sensitive;
# anything else returns False.
_DANGEROUS_CONFIRM_WORD = "RUN"


def _format_args(args: Dict[str, Any]) -> str:
    """Render an args dict as escaped ``key: value`` pairs, one per line.

    Long values are truncated with an ellipsis. Non-string values are
    JSON-serialised for compact display so a list of paths shows up
    without Python's repr noise.
    """
    if not args:
        return "[dim]<no arguments>[/dim]"
    lines = []
    for key, value in args.items():
        if isinstance(value, str):
            display = value
        else:
            try:
                display = json.dumps(value, default=str)
            except (TypeError, ValueError):
                display = str(value)
        if len(display) > _MAX_ARG_VALUE_LEN:
            display = display[: _MAX_ARG_VALUE_LEN - 3] + "..."
        lines.append(f"[dim]{escape(str(key))}:[/dim] {escape(display)}")
    return "\n".join(lines)


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

    ToolConfirmModal #tool_confirm_args {
        margin-bottom: 1;
        max-height: 12;
        overflow-y: auto;
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
        yield Header()
        yield Container(
            Static(
                f"[bold]{escape(self._tool)}[/bold]",
                id="tool_confirm_title",
            ),
            Static(
                "Servonaut AI wants to run this tool. "
                "Press [bold]y[/bold] to confirm or [bold]n[/bold] to cancel.",
                id="tool_confirm_body",
            ),
            Static(
                _format_args(self._args),
                id="tool_confirm_args",
            ),
            Horizontal(
                Button("Confirm", id="btn_tool_confirm", variant="primary"),
                Button("Cancel", id="btn_tool_cancel", variant="default"),
                id="tool_confirm_buttons",
            ),
            id="tool_confirm_container",
        )
        yield Footer()

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

    DangerousToolConfirmModal #dangerous_confirm_args {
        margin-bottom: 1;
        max-height: 10;
        overflow-y: auto;
    }

    DangerousToolConfirmModal #dangerous_confirm_input {
        margin-bottom: 1;
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
        yield Header()
        yield Container(
            Static(
                f"[bold]Dangerous tool:[/bold] [bold]{escape(self._tool)}[/bold]",
                id="dangerous_confirm_title",
            ),
            Static(
                "Servonaut AI wants to run a [bold]potentially destructive[/bold] tool. "
                f"Type [bold]{_DANGEROUS_CONFIRM_WORD}[/bold] below to confirm, or press Escape to cancel.",
                id="dangerous_confirm_body",
            ),
            Static(
                _format_args(self._args),
                id="dangerous_confirm_args",
            ),
            Input(
                placeholder=f"Type {_DANGEROUS_CONFIRM_WORD} to confirm",
                id="dangerous_confirm_input",
            ),
            Horizontal(
                Button("Confirm", id="btn_dangerous_confirm", variant="error"),
                Button("Cancel", id="btn_dangerous_cancel", variant="default"),
                id="dangerous_confirm_buttons",
            ),
            id="dangerous_confirm_container",
        )
        yield Footer()

    def on_mount(self) -> None:
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
        return value == _DANGEROUS_CONFIRM_WORD

    def on_input_submitted(self, event: Input.Submitted) -> None:
        # Pressing Enter inside the input is equivalent to clicking
        # Confirm — only succeeds when the value matches exactly.
        self.dismiss(self._typed_run())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_dangerous_confirm":
            self.dismiss(self._typed_run())
        elif event.button.id == "btn_dangerous_cancel":
            self.dismiss(False)

    def action_deny(self) -> None:
        self.dismiss(False)


__all__ = [
    "ToolConfirmModal",
    "DangerousToolConfirmModal",
]
