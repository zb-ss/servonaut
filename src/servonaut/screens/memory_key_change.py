"""MemberKeyChangeScreen — confirm a team member's changed memory key.

A member's key changes when they set up Memory Sync again or use a new
computer. Sealing a server's data key for the new key is only safe once the
user has checked it with the member, so nothing is shared until each key is
ticked here. A regular Screen (not a modal): several members, each with two
fingerprints and a checkbox, and the sidebar stays in view.

Dismisses with the confirmed :class:`KeyChange` list, or ``None`` on cancel.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List, Literal, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Footer, Static

from servonaut.services.memory.crypto import short_fingerprint
from servonaut.services.memory.team_service import display_name
from servonaut.services.memory.team_wraps import KeyChange
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar

Mode = Literal["share", "catch_up"]


def _changed_on(raw: Optional[str]) -> Optional[str]:
    """The time the service reported, readable; None when it cannot be read."""
    if not raw:
        return None
    try:
        stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


class MemberKeyChangeScreen(Screen[Optional[List[KeyChange]]]):
    """Lists changed member keys and asks the user to confirm each one.

    Args:
        changes: The keys to confirm.
        mode: ``"share"`` needs every key ticked (a share cannot leave a
            member out); ``"catch_up"`` needs at least one.
        again: In ``share`` mode, label the button for Share again.
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]

    def __init__(self, changes: List[KeyChange], *, mode: Mode = "share", again: bool = False) -> None:
        super().__init__()
        self._changes = list(changes)
        self._mode = mode
        self._again = again

    def _shown_name(self, change: KeyChange) -> str:
        """The member as the screen shows them: a stand-in in demo mode."""
        name = display_name(change.name, change.user_id)
        redaction = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redaction is not None:
            return redaction.redact_name(name)
        return name

    def _confirm_label(self) -> str:
        if self._mode == "catch_up":
            return "Trust checked keys"
        return "Trust and share again" if self._again else "Trust and share"

    def _describe(self, change: KeyChange) -> str:
        lines = [
            f"[bold]{escape(self._shown_name(change))}[/bold]",
            f"New key: {short_fingerprint(change.fingerprint)}",
        ]
        if change.previous_fingerprint:
            lines.append(f"Previous key: {short_fingerprint(change.previous_fingerprint)}")
        when = _changed_on(change.rotated_at)
        if when:
            lines.append(f"Changed on: {when}")
        return "\n".join(lines)

    def compose(self) -> ComposeResult:
        many = len(self._changes) > 1
        need = (
            "Tick every key that matches. A share cannot leave a member out."
            if self._mode == "share"
            else "Tick the keys that match. The others keep waiting."
        )
        yield SafeHeader()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            with Container(id="keychange-outer"):
                with Container(id="keychange-container"):
                    yield Static(
                        "[bold $text-accent]Confirm changed memory keys[/bold $text-accent]"
                        if many
                        else "[bold $text-accent]Confirm changed memory key[/bold $text-accent]",
                        id="keychange-title",
                    )
                    with VerticalScroll(id="keychange-scroll"):
                        yield Static(
                            "A memory key changes when a member sets up Memory Sync "
                            "again or uses a new computer. Someone who took over their "
                            "account could also replace it to read what the team "
                            "shares. Ask the member to open Memory Sync and read out "
                            "their Key fingerprint, then compare it with the new key "
                            f"below. {need}",
                            id="keychange-body",
                        )
                        with Vertical(id="keychange-list"):
                            for index, change in enumerate(self._changes):
                                with Vertical(classes="keychange-item"):
                                    yield Static(self._describe(change), classes="keychange-details")
                                    yield Checkbox(
                                        f"{escape(self._shown_name(change))}'s key matches",
                                        id=f"keychange-check-{index}",
                                    )
                    with Horizontal(id="keychange-btn-row"):
                        yield Button("Cancel", id="keychange-btn-cancel")
                        yield Button(
                            self._confirm_label(), variant="primary",
                            id="keychange-btn-confirm", disabled=True,
                        )
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#keychange-btn-cancel", Button).focus()

    def _say(self, widget: Static, markup: str) -> None:
        """Write *markup*; the demo-mode scrub is a second line of defence after the stand-in names."""
        redaction = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redaction is not None:
            markup = redaction.scrub_stream(markup)
        widget.update(markup)

    def refresh_after_demo_toggle(self) -> None:
        """Redraw the member names for the new demo mode; the ticks stay."""
        for index, change in enumerate(self._changes):
            self._say(self.query(".keychange-details")[index], self._describe(change))
            self.query_one(f"#keychange-check-{index}", Checkbox).label = (
                f"{escape(self._shown_name(change))}'s key matches"
            )

    def _ticked(self) -> List[KeyChange]:
        return [
            change for index, change in enumerate(self._changes)
            if self.query_one(f"#keychange-check-{index}", Checkbox).value
        ]

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        ticked = len(self._ticked())
        ready = ticked == len(self._changes) if self._mode == "share" else ticked > 0
        self.query_one("#keychange-btn-confirm", Button).disabled = not ready

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "keychange-btn-confirm" and not event.button.disabled:
            self.dismiss(self._ticked())
        elif event.button.id == "keychange-btn-cancel":
            self.dismiss(None)
