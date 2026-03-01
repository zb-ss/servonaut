"""Progress indicator widget for Servonaut v2.0."""

from __future__ import annotations

from textual.widgets import Static


class ProgressIndicator(Static):
    """Loading indicator widget with animated text."""

    def __init__(self) -> None:
        """Initialize progress indicator."""
        super().__init__("")
        self._active = False

    def start(self, message: str = "Loading...") -> None:
        """Start showing loading indicator.

        Args:
            message: Loading message to display.
        """
        self._active = True
        self.update(f"[bold cyan]{message}[/bold cyan]")
        self.display = True

    def stop(self) -> None:
        """Stop showing loading indicator."""
        self._active = False
        self.update("")
        self.display = False
