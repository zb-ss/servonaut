"""Command output widget for displaying SSH command results."""

from __future__ import annotations

from rich.text import Text
from textual.widgets import RichLog

from servonaut.utils.theme_text import theme_style, themed_text


class CommandOutput(RichLog):
    """RichLog widget for displaying command execution output.

    Provides formatted output with different styles for commands, output, and errors.
    """

    def __init__(self, **kwargs) -> None:
        """Initialize command output widget.

        Args:
            **kwargs: Additional arguments passed to RichLog.
        """
        super().__init__(
            highlight=True,
            markup=True,
            wrap=True,
            max_lines=1000,
            **kwargs
        )

    def append_command(self, command: str) -> None:
        """Append a command to the output log.

        Args:
            command: Command string to display.
        """
        self.write(themed_text(self.app, f"$ {command}", "text-accent", bold=True))

    def append_output(self, output: str) -> None:
        """Append command output to the log.

        Args:
            output: Output text to display.
        """
        if output:
            if self.app.demo_mode and self.app.redaction_service:
                output = self.app.redaction_service.scrub_stream(output)
            self.write(output)

    def append_error(self, error: str) -> None:
        """Append error message to the log.

        Args:
            error: Error text to display.
        """
        if error:
            # Scrub BEFORE embedding in Rich markup to preserve order:
            # redact → escape → embed.
            if self.app.demo_mode and self.app.redaction_service:
                error = self.app.redaction_service.scrub_stream(error)
            self.write(Text.from_markup(error, style=theme_style(self.app, "text-error", bold=True)))

    def append_notice(self, notice: str) -> None:
        """Append an informational line, dimmed so it does not read as an error.

        Args:
            notice: Notice text to display (already escaped for Rich markup).
        """
        if notice:
            if self.app.demo_mode and self.app.redaction_service:
                notice = self.app.redaction_service.scrub_stream(notice)
            self.write(f"[dim]{notice}[/dim]")

    def clear_output(self) -> None:
        """Clear all output from the log."""
        self.clear()
