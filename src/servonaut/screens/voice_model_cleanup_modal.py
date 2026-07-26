"""Offer to delete voice models the new configuration no longer uses.

Switching engine or model size leaves the previous weights on disk —
several hundred megabytes each, in a cache directory nobody thinks to
check. Rather than let that accumulate silently, the settings panel shows
this straight after a switch, naming what is now unused and what removing
it would reclaim.

Framed as an offer, not a warning: keeping both is legitimate (switching
back and forth without re-downloading), so neither button is destructive
by default and the modal dismisses to "keep" on escape.
"""

from __future__ import annotations

from typing import List

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from servonaut.services.voice_engines import human_bytes


class VoiceModelCleanupModal(ModalScreen[bool]):
    """Asks whether to delete the now-unused voice models.

    Dismisses True to remove them, False to keep. A brief yes/no decision,
    so a modal rather than a screen.
    """

    BINDINGS = [
        # Escape keeps the files: the safe outcome for an accidental
        # dismissal is the one that does not delete anything.
        Binding("escape", "keep", "Keep", show=True),
    ]

    DEFAULT_CSS = """
    VoiceModelCleanupModal {
        align: center middle;
    }
    VoiceModelCleanupModal #vmc_container {
        width: 68;
        height: auto;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }
    VoiceModelCleanupModal #vmc_title {
        text-style: bold;
        margin-bottom: 1;
    }
    VoiceModelCleanupModal #vmc_body {
        margin-bottom: 1;
    }
    VoiceModelCleanupModal .vmc-model {
        padding-left: 2;
        color: $text-muted;
    }
    VoiceModelCleanupModal #vmc_total {
        margin-top: 1;
        text-style: bold;
    }
    VoiceModelCleanupModal #vmc_buttons {
        height: auto;
        align: right middle;
        margin-top: 1;
    }
    VoiceModelCleanupModal #vmc_keep {
        margin-right: 1;
    }
    """

    def __init__(self, stale_models: List, active_label: str) -> None:
        """Initialise the prompt.

        Args:
            stale_models: :class:`~servonaut.services.voice_setup_service.InstalledModel`
                entries the new configuration does not use.
            active_label: Name of the model now in use, so the user can see
                what is being kept.
        """
        super().__init__()
        self._stale = list(stale_models)
        self._active_label = active_label

    def compose(self) -> ComposeResult:
        """Compose the offer, listing each unused model and its size."""
        total = sum(model.size_bytes for model in self._stale)
        rows = [
            Static(
                f"  • {escape(model.label)} — {escape(model.human_size)}",
                classes="vmc-model",
            )
            for model in self._stale
        ]

        yield Container(
            Static("Remove the unused speech model?", id="vmc_title"),
            Static(
                f"Voice input now uses [bold]{escape(self._active_label)}[/bold]. "
                "These downloads are no longer used:",
                id="vmc_body",
            ),
            *rows,
            Static(
                f"Removing them frees {escape(human_bytes(total))}. "
                "Keep them to switch back without downloading again.",
                id="vmc_total",
            ),
            Horizontal(
                Button("Keep both", variant="default", id="vmc_keep"),
                Button(
                    f"Remove and free {human_bytes(total)}",
                    variant="warning",
                    id="vmc_remove",
                ),
                id="vmc_buttons",
            ),
            id="vmc_container",
        )

    def on_mount(self) -> None:
        """Focus the keep button so a stray Enter does not delete anything."""
        self.query_one("#vmc_keep", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Resolve the prompt."""
        if event.button.id == "vmc_remove":
            self.dismiss(True)
        elif event.button.id == "vmc_keep":
            self.dismiss(False)

    def action_keep(self) -> None:
        """Escape keeps the files."""
        self.dismiss(False)
