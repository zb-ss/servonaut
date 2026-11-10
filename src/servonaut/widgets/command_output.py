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
        self.write(themed_text(self.app, f"$ {command}", "bold $text-accent"))

    def append_output(self, output: str) -> None:
        """Append command output to the log.

        Args:
            output: Output text to display.
        """
        if output:
            if self.app.demo_mode and self.app.redaction_service:
                output = self.app.redaction_service.scrub_stream(output)
            self.write(output)

    def append_error(self, error: "str | Text") -> None:
        """Append error message to the log.

        Args:
            error: Error text to display: a ``Text`` is shown literally, a string
                is Rich markup (escaped by the caller).
        """
        if not error:
            return
        style = theme_style(self.app, "bold $text-error")
        if isinstance(error, Text):
            plain = error.plain
            if self.app.demo_mode and self.app.redaction_service:
                plain = self.app.redaction_service.scrub_stream(plain)
            self.write(Text(plain, style=style))
            return
        # Scrub BEFORE embedding in Rich markup to preserve order:
        # redact → escape → embed.
        if self.app.demo_mode and self.app.redaction_service:
            error = self.app.redaction_service.scrub_stream(error)
        self.write(Text.from_markup(error, style=style))

    def append_notice(self, notice: "str | Text") -> None:
        """Append an informational line, dimmed so it does not read as an error.

        Args:
            notice: A ``Text`` (shown literally) or Rich markup already escaped.
        """
        if not notice:
            return
        if isinstance(notice, Text):
            plain = notice.plain
            if self.app.demo_mode and self.app.redaction_service:
                plain = self.app.redaction_service.scrub_stream(plain)
            self.write(Text(plain, style="dim"))
            return
        if self.app.demo_mode and self.app.redaction_service:
            notice = self.app.redaction_service.scrub_stream(notice)
        self.write(f"[dim]{notice}[/dim]")

    def clear_output(self) -> None:
        """Clear all output from the log."""
        self.clear()
