"""Scan results screen for Servonaut v2.0."""

from __future__ import annotations
from typing import List

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, Button, DataTable
from textual.worker import Worker


class ScanResultsScreen(Screen):
    """Screen for displaying keyword scan results.

    Shows cached scan results or allows triggering a new scan.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("s", "scan_now", "Scan Now", show=True),
    ]

    def __init__(self, instance: dict) -> None:
        """Initialize scan results screen.

        Args:
            instance: Instance dictionary with scan configuration.
        """
        super().__init__()
        self._instance = instance
        self._results: List[dict] = []

    def compose(self) -> ComposeResult:
        """Compose the scan results UI."""
        yield Header()
        yield Container(
            Static(
                f"[bold cyan]Scan Results[/bold cyan]\n"
                f"Instance: {self._instance.get('name') or self._instance.get('id')}",
                id="scan_banner"
            ),
            Vertical(
                Button("Trigger New Scan", variant="primary", id="scan_button"),
                Static("", id="scan_status"),
                DataTable(id="results_table"),
                id="results_container"
            ),
            id="scan_container"
        )
        yield Footer()

    def on_mount(self) -> None:
        """Load cached scan results when mounted."""
        self._load_cached_results()
        self._setup_table()

    def _setup_table(self) -> None:
        """Setup DataTable columns and styling."""
        table = self.query_one("#results_table", DataTable)
        table.add_columns("Source", "Content", "Timestamp")
        table.cursor_type = "row"

    def _load_cached_results(self) -> None:
        """Load cached scan results from keyword store."""
        instance_id = self._instance.get('id')
        if not instance_id:
            self.app.notify("Invalid instance ID", severity="error")
            return

        self._results = self.app.keyword_store.get_results(instance_id)

        if self._results:
            self._populate_table()
            status = self.query_one("#scan_status", Static)
            status.update(f"[green]Loaded {len(self._results)} cached results[/green]")
        else:
            status = self.query_one("#scan_status", Static)
            status.update("[yellow]No scan results. Run a scan first.[/yellow]")

    def _populate_table(self) -> None:
        """Populate DataTable with scan results."""
        table = self.query_one("#results_table", DataTable)
        table.clear()

        for result in self._results:
            source = result.get('source', 'Unknown')
            content = result.get('content', '')
            timestamp = result.get('timestamp', '')

            # Truncate long content for display
            if len(content) > 100:
                content_display = content[:97] + "..."
            else:
                content_display = content

            # Replace newlines with spaces for table display
            content_display = content_display.replace('\n', ' ')

            table.add_row(source, content_display, timestamp)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events.

        Args:
            event: Button pressed event.
        """
        if event.button.id == "scan_button":
            self.action_scan_now()

    def action_scan_now(self) -> None:
        """Trigger a new scan for this instance."""
        status = self.query_one("#scan_status", Static)
        status.update("[yellow]Scanning server...[/yellow]")
        self.app.notify("Starting server scan...", severity="information")

        # Run scan in worker
        self.run_worker(
            self.app.scan_service.scan_server(
                self._instance,
                self.app.ssh_service,
                self.app.connection_service
            ),
            name="scan_server",
            exclusive=True
        )

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        """Handle worker state changes.

        Args:
            event: Worker state changed event.
        """
        if event.worker.name == "scan_server":
            if event.worker.is_finished:
                status = self.query_one("#scan_status", Static)

                if event.worker.error:
                    error_msg = str(event.worker.error)
                    status.update(f"[red]Scan failed:[/red] {error_msg}")
                    self.app.notify(f"Scan failed: {error_msg}", severity="error")
                else:
                    results = event.worker.result or []
                    self._results = results

                    # Save results to keyword store
                    instance_id = self._instance.get('id')
                    if instance_id:
                        self.app.keyword_store.save_results(instance_id, results)

                    # Update display
                    if results:
                        self._populate_table()
                        status.update(f"[green]Scan completed: {len(results)} results found[/green]")
                        self.app.notify(f"Scan completed: {len(results)} results", severity="information")
                    else:
                        status.update("[yellow]Scan completed: No matches found[/yellow]")
                        self.app.notify("Scan completed: No matches found", severity="information")

    def action_back(self) -> None:
        """Navigate back to previous screen."""
        self.app.pop_screen()
