"""A one-line indicator for slow work started from a screen or dialog."""

from __future__ import annotations

import time
from typing import Callable, Optional

from rich.text import Text
from textual.timer import Timer
from textual.widgets import Static


class BusyIndicator(Static):
    """Show a spinner, what is running and, once it is slow, for how long.

    Hidden while idle. The message is drawn as plain text, never markup, and
    scrubbed for demo mode on every draw, so a caller can include names that
    came from the server and a demo-mode toggle applies at the next frame.
    """

    DEFAULT_CSS = """
    BusyIndicator {
        height: auto;
        color: $accent;
        display: none;
    }
    BusyIndicator.-active {
        display: block;
    }
    """

    _FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    # Seconds between spinner frames.
    _FRAME_SECONDS = 0.1
    # Quick work shows only the message; slower work also shows how long it took.
    _ELAPSED_AFTER_SECONDS = 3.0

    def __init__(self, *, id: Optional[str] = None, classes: Optional[str] = None) -> None:
        super().__init__("", id=id, classes=classes)
        self._message = ""
        self._started_at = 0.0
        self._frame = 0
        self._timer: Optional[Timer] = None
        # Seconds since an arbitrary point; replaceable so tests need not touch the event loop's clock.
        self._clock: Callable[[], float] = time.monotonic

    @property
    def is_active(self) -> bool:
        return self._timer is not None

    @property
    def message(self) -> str:
        return self._message

    def start(self, message: str) -> None:
        """Show *message* as running work; restarting keeps the elapsed time."""
        if self._timer is None:
            self._started_at = self._clock()
            self._frame = 0
            self._timer = self.set_interval(self._FRAME_SECONDS, self._tick)
        self._message = message
        self.add_class("-active")
        self._draw()

    def stop(self) -> None:
        """Hide the indicator."""
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        self._message = ""
        self.remove_class("-active")
        self._draw()

    def on_unmount(self) -> None:
        if self._timer is not None:
            self._timer.stop()
            self._timer = None

    def _tick(self) -> None:
        self._frame = (self._frame + 1) % len(self._FRAMES)
        self._draw()

    def scrub_for_display(self, value: str) -> str:
        """Redact server or user data in demo mode; the kept message stays real."""
        redactor = getattr(self.app, "redaction_service", None)
        if getattr(self.app, "demo_mode", False) and redactor is not None:
            return str(redactor.scrub_stream(value))
        return value

    def _draw(self) -> None:
        if self._timer is None:
            self.update(Text())
            return
        text = Text(f"{self._FRAMES[self._frame]} {self.scrub_for_display(self._message)}")
        elapsed = self._clock() - self._started_at
        if elapsed >= self._ELAPSED_AFTER_SECONDS:
            text.append(f"  {int(elapsed)}s", style="dim")
        self.update(text)
