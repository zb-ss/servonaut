"""Typed-confirmation modal for executing a finding remediation.

Phase 3 of proactive monitoring. The modal renders the SERVER-SIGNED
preview — the exact structured command the server will dispatch, not a
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

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

#: The literal the user must type to arm the Execute button.
CONFIRM_PHRASE = "RUN"


def preview_command_lines(preview: Dict[str, Any]) -> list:
    """Render the preview's command deterministically.

    Contract §F.3: ``command.human`` is the byte-for-byte string the
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


class RemediationConfirmModal(ModalScreen[Optional[str]]):
    """Preview + typed-RUN confirmation for one remediation action."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

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
        super().__init__()
        self._preview = dict(preview)
        self._dry_run = dry_run
        self._label = label

    def compose(self) -> ComposeResult:
        p = self._preview
        label = escape(str(
            self._label or p.get("label") or p.get("action")
            or p.get("verb") or "Remediation",
        ))
        risk = escape(str(
            p.get("exec_risk") or p.get("risk_tier") or "unknown",
        ))
        reversible = "reversible" if p.get("reversible") else "not reversible"
        mode = ("[bold cyan]DRY RUN[/bold cyan] — nothing changes on the box"
                if self._dry_run
                else "[bold red]LIVE EXECUTION[/bold red] — this mutates the server")
        command_block = "\n".join(
            escape(line) for line in preview_command_lines(p)
        )
        expires = escape(str(p.get("expires_at") or ""))

        yield Container(
            Static(
                f"[bold]{label}[/bold]\n"
                f"[dim]{risk} risk · {reversible}[/dim]\n\n"
                f"{mode}",
                id="remediation_confirm_header",
            ),
            VerticalScroll(
                Static(
                    "[bold]Exact command (server-signed):[/bold]\n"
                    f"{command_block}\n\n"
                    f"[dim]Preview token expires: {expires}[/dim]",
                    id="remediation_confirm_command",
                ),
                id="remediation_confirm_scroll",
            ),
            Input(
                placeholder=f"Type {CONFIRM_PHRASE} to arm Execute",
                id="remediation_confirm_input",
            ),
            Horizontal(
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
