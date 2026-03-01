"""Command output widget for displaying SSH command results."""

from __future__ import annotations

from textual.widgets import RichLog


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
        self.write(f"[bold cyan]$ {command}[/bold cyan]")

    def append_output(self, output: str) -> None:
        """Append command output to the log.

        Args:
            output: Output text to display.
        """
        if output:
            self.write(output)

    def append_error(self, error: str) -> None:
        """Append error message to the log.

        Args:
            error: Error text to display.
        """
        if error:
            self.write(f"[bold red]{error}[/bold red]")

    def clear_output(self) -> None:
        """Clear all output from the log."""
        self.clear()
