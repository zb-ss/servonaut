"""Typed-confirmation modal for executing a finding remediation.

The modal renders the SERVER-SIGNED preview — the exact structured
command the server will dispatch, not a
client-side reconstruction — and requires the user to type ``RUN``
before the Execute button does anything. It returns a decision string;
the owning :class:`FindingDetailScreen` performs the actual API call so
this modal stays side-effect-free:

- ``"confirm"`` — execute the previewed command (token already held by
  the caller).
- ``"dry_run"`` — the user wants the safer dry-run variant first; the
  caller re-fetches a preview with ``dry_run=True``.
- ``None`` — cancelled.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.content import Content
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from servonaut.utils.markup import literal
from servonaut.widgets.dialogs import (
    DIALOG_VERTICAL_BREAKPOINTS,
    DialogActions,
    DialogBody,
    DialogFrame,
    DialogNotificationSpace,
)

#: The literal the user must type to arm the Execute button.
CONFIRM_PHRASE = "RUN"

# Below this many rows the undo box shrinks to one line so the command being
# approved keeps its room.
_UNDO_COMPACT_BELOW_ROWS = 30

#: Shown when the preview carries no usable undo plan. Silence would
#: read as "reversible" — say so explicitly instead.
NO_REVERT_TEXT = "no clean revert — this cannot be undone automatically"


def preview_command_lines(preview: Dict[str, Any]) -> list:
    """Render the preview's command deterministically.

    ``command.human`` is the byte-for-byte string the
    confirm token was signed over — render it VERBATIM, never a
    client-side reconstruction. Older/other shapes (``type``/``args``)
    fall back to a sorted structural render.
    """
    command = preview.get("command")
    if not isinstance(command, dict):
        return ["(no command payload in preview)"]
    human = command.get("human")
    if isinstance(human, str) and human:
        return human.splitlines() or [human]
    lines = [f"type: {command.get('verb') or command.get('type', '?')}"]
    args = command.get("args")
    if isinstance(args, dict):
        for key in sorted(args):
            lines.append(f"  {key}: {json.dumps(args[key], sort_keys=True)}")
    return lines


def revert_plan_summary(preview: Dict[str, Any]) -> str:
    """Return the human "what undoes this" line for the confirm modal.

    The preview carries ``revert_plan`` so the operator
    sees the undo path at the moment of confirmation, not after the
    fact. ``human`` is the server-authored sentence; anything missing,
    non-dict or blank falls back to :data:`NO_REVERT_TEXT` so the modal
    always answers the question one way or the other.
    """
    plan = preview.get("revert_plan")
    if isinstance(plan, dict):
        human = plan.get("human")
        if isinstance(human, str) and human.strip():
            return human.strip()
    return NO_REVERT_TEXT


class RemediationConfirmModal(ModalScreen[Optional[str]]):
    """Preview + typed-RUN confirmation for one remediation action."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    AUTO_FOCUS = "#remediation_confirm_input"
    VERTICAL_BREAKPOINTS = DIALOG_VERTICAL_BREAKPOINTS

    def on_resize(self) -> None:
        # The undo box gives way first, and only when the terminal is short.
        self.set_class(self.size.height < _UNDO_COMPACT_BELOW_ROWS, "-undo-compact")

    def __init__(
        self, preview: Dict[str, Any], *, dry_run: bool,
        label: Optional[str] = None,
    ) -> None:
        """``label`` is the human title for the header.

        The server's preview envelope has no ``label`` field — it
        carries the raw verb in ``action``/``verb`` — so a caller that
        knows the playbook option's wording ("Block 198.51.100.23")
        passes it here rather than letting the header read "block_ip".
        """
        super().__init__(classes="dialog-screen")
        self._preview = dict(preview)
        self._dry_run = dry_run
        self._label = label

    def compose(self) -> ComposeResult:
        p = self._preview
        label = str(
            self._label or p.get("label") or p.get("action")
            or p.get("verb") or "Remediation",
        )
        risk = str(p.get("exec_risk") or p.get("risk_tier") or "unknown")
        reversible = "reversible" if p.get("reversible") else "not reversible"
        mode = (
            Content.assemble(
                Content.styled("DRY RUN", "bold $text-accent"),
                " — nothing changes on the box",
            )
            if self._dry_run
            else Content.assemble(
                Content.styled("LIVE EXECUTION", "bold $text-error"),
                " — this mutates the server",
            )
        )
        command_block = literal("\n".join(preview_command_lines(p)))
        expires = str(p.get("expires_at") or "")
        revert_line = revert_plan_summary(p)

        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static(
                Content.assemble(
                    literal(label, "bold"),
                    "\n",
                    literal(f"{risk} risk · {reversible}", "dim"),
                    "\n\n",
                    mode,
                ),
                id="remediation_confirm_header",
            ),
            body=DialogBody(
                Static(
                    Content.assemble(
                        Content.styled("Exact command (server-signed):", "bold"),
                        "\n",
                        command_block,
                        "\n\n",
                        literal(f"Preview token expires: {expires}", "dim"),
                    ),
                    id="remediation_confirm_command",
                ),
                id="remediation_confirm_scroll",
            ),
            # Outside the scroll on purpose: a long command must not
            # push the undo path out of view at confirm time.
            status=Vertical(
                Static("[dim]Undo, if needed:[/dim]"),
                DialogBody(
                    Static(
                        literal(revert_line, "dim"),
                        id="remediation_confirm_revert",
                    ),
                    classes="remediation-undo",
                ),
                Input(
                    placeholder=f"Type {CONFIRM_PHRASE} to arm Execute",
                    id="remediation_confirm_input",
                ),
            ),
            actions=DialogActions(
                Button(
                    "Execute", id="remediation_confirm_run",
                    variant="primary" if self._dry_run else "error",
                    disabled=True,
                ),
                *(
                    []
                    if self._dry_run
                    else [Button(
                        "Dry run first", id="remediation_confirm_dry_run",
                        variant="default",
                    )]
                ),
                Button("Cancel", id="remediation_confirm_cancel"),
                id="remediation_confirm_buttons",
            ),
            id="remediation_confirm_container",
            severity="danger",
        )

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "remediation_confirm_input":
            armed = event.value.strip() == CONFIRM_PHRASE
            self.query_one("#remediation_confirm_run", Button).disabled = (
                not armed
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "remediation_confirm_run":
            typed = self.query_one(
                "#remediation_confirm_input", Input,
            ).value.strip()
            if typed != CONFIRM_PHRASE:
                self.app.notify(
                    f"Type {CONFIRM_PHRASE} to confirm execution.",
                    severity="warning",
                )
                return
            self.dismiss("confirm")
        elif event.button.id == "remediation_confirm_dry_run":
            self.dismiss("dry_run")
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)
