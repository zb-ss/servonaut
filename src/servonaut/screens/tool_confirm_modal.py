"""Confirmation modals for AI-originated tool calls.

Two ModalScreen flavours, sized by the tool's ``guard_level``:

- :class:`ToolConfirmModal` — single y/n for ``standard`` tools
  (``run_command``, ``transfer_file``).
- :class:`DangerousToolConfirmModal` — typed-confirm "RUN" for
  ``dangerous`` tools (``deploy``, ``provision``, ``security_scan``).

Both present a brief blocking choice over the current conversation;
dismissing the prompt returns to chat. All user-influenced strings (tool names,
arg values from the model) are passed through ``rich.markup.escape``
before interpolation — the model output can contain rich-markup
metacharacters and we don't want a malformed brace to corrupt the row.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Awaitable, Callable, Dict, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Input, Static

from servonaut.widgets.dialogs import (
    DialogActions,
    DialogBody,
    DialogFrame,
    DialogNotificationSpace,
)
from servonaut.widgets.safe_header import SafeHeader

logger = logging.getLogger(__name__)


# Maximum displayed length per arg value before we truncate. Models
# can dump multi-KB blobs into args (e.g. file content for transfer);
# long values blow out the modal layout.
_MAX_ARG_VALUE_LEN = 200

# Typed-confirm magic word for dangerous tools. Match is case-sensitive;
# wrong values leave the modal open and show a correction hint.
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

    AUTO_FOCUS = "#btn_tool_cancel"

    def __init__(self, tool: str, args: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(classes="dialog-screen")
        self._tool = tool or "<unknown tool>"
        self._args = args or {}

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static(
                f"[bold $text-accent]{escape(self._tool)}[/bold $text-accent]",
                id="tool_confirm_title",
            ),
            body=DialogBody(
                Static(
                    "Servonaut AI wants to run this tool. "
                    "Press [bold]y[/bold] to confirm or [bold]n[/bold] to cancel.",
                    id="tool_confirm_body",
                    classes="dialog-description",
                ),
                Static(_format_args(self._args), id="tool_confirm_args"),
            ),
            actions=DialogActions(
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

    The user must type case-sensitive ``RUN``, with optional surrounding
    whitespace, for ``True``. Wrong or empty input shows a hint and keeps
    the modal open; Cancel and Escape return ``False``. This is additional
    confirmation; the server enforces the ``allow_dangerous_ai_tools``
    entitlement separately.
    """

    BINDINGS = [
        Binding("escape", "deny", "Cancel", show=True),
    ]

    AUTO_FOCUS = "#dangerous_confirm_input"

    DEFAULT_CSS = """
    DangerousToolConfirmModal #dangerous_confirm_error {
        color: $error;
        display: none;
    }

    DangerousToolConfirmModal #dangerous_confirm_error.visible {
        display: block;
    }

    """

    def __init__(self, tool: str, args: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(classes="dialog-screen")
        self._tool = tool or "<unknown tool>"
        self._args = args or {}

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static(
                "[bold $text-error]Dangerous tool: "
                f"{escape(self._tool)}[/bold $text-error]",
                id="dangerous_confirm_title",
            ),
            body=DialogBody(
                Static(_format_args(self._args), id="dangerous_confirm_args"),
            ),
            status=Vertical(
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
            severity="danger",
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
