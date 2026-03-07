"""CloudTrail event browser screen for Servonaut."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Static

from servonaut.screens._binding_guard import check_action_passthrough


class CloudTrailBrowserScreen(Screen):
    """Screen for browsing and filtering AWS CloudTrail events."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("f", "fetch", "Fetch", show=True),
        Binding("enter", "show_detail", "Detail", show=True),
        Binding("y", "copy_output", "Copy", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._events: List[dict] = []
        self._selected_row: Optional[int] = None

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Vertical(
                Label("[bold]CloudTrail Event Browser[/bold]", id="cloudtrail_title"),
                Horizontal(
                    Vertical(
                        Label("Region (blank = all)"),
                        Input(placeholder="e.g. us-east-1", id="input_region"),
                        id="filter_region",
                    ),
                    Vertical(
                        Label("Lookback hours"),
                        Input(placeholder="24", id="input_hours"),
                        id="filter_hours",
                    ),
                    Vertical(
                        Label("Minutes"),
                        Input(placeholder="0", id="input_minutes"),
                        id="filter_minutes",
                    ),
                    Vertical(
                        Label("Event Name"),
                        Input(placeholder="e.g. RunInstances", id="input_event_name"),
                        id="filter_event_name",
                    ),
                    Vertical(
                        Label("Username"),
                        Input(placeholder="IAM username", id="input_username"),
                        id="filter_username",
                    ),
                    Vertical(
                        Label("Resource Type"),
                        Input(placeholder="e.g. AWS::EC2::Instance", id="input_resource_type"),
                        id="filter_resource_type",
                    ),
                    Button("Fetch", id="btn_fetch", variant="primary"),
                    Button("Back", id="btn_back", variant="default"),
                    id="cloudtrail_filters",
                ),
                DataTable(id="cloudtrail_table"),
                VerticalScroll(
                    Static("Select an event to view details.", id="event_detail_text"),
                    id="event_detail",
                ),
                id="cloudtrail_container",
            ),
            id="cloudtrail_outer",
        )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#cloudtrail_table", DataTable)
        table.add_columns("Time", "Event", "User", "Source IP", "Resource", "Region", "Error")
        table.cursor_type = "row"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_fetch":
            self.action_fetch()
        elif event.button.id == "btn_back":
            self.action_back()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self._selected_row = event.cursor_row
        self._show_event_detail(event.cursor_row)

    def action_copy_output(self) -> None:
        """Copy the selected event details to the clipboard."""
        if self._selected_row is None or self._selected_row < 0 or self._selected_row >= len(self._events):
            self.notify("Select an event first", severity="warning")
            return
        event = self._events[self._selected_row]
        event_time = event.get("event_time", "")
        if hasattr(event_time, "strftime"):
            event_time = event_time.strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            f"Event:          {event.get('event_name', '')}",
            f"Time:           {event_time}",
            f"User:           {event.get('username', '')}",
            f"Source IP:      {event.get('source_ip', '')}",
            f"Resource Type:  {event.get('resource_type', '')}",
            f"Resource Name:  {event.get('resource_name', '')}",
            f"Region:         {event.get('region', '')}",
            f"Error:          {event.get('error_code', '') or '(none)'}",
        ]
        raw = event.get("raw_event", "")
        if raw:
            lines.append("")
            lines.append("Raw Event:")
            lines.append(str(raw))
        self.app.copy_to_clipboard("\n".join(lines))
        self.notify("Copied to clipboard")

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_fetch(self) -> None:
        self.query_one("#btn_fetch", Button).disabled = True
        self.query_one("#event_detail_text", Static).update("Loading...")
        table = self.query_one("#cloudtrail_table", DataTable)
        table.clear()
        self.run_worker(self._fetch_events(), name="cloudtrail_fetch", exclusive=True)

    def action_show_detail(self) -> None:
        if self._selected_row is not None:
            self._show_event_detail(self._selected_row)

    def _show_event_detail(self, row_index: int) -> None:
        if row_index < 0 or row_index >= len(self._events):
            return
        event = self._events[row_index]
        detail_widget = self.query_one("#event_detail_text", Static)
        detail_widget.update(
            f"[bold]Event:[/bold] {event.get('event_name', '')}\n"
            f"[bold]Time:[/bold] {event.get('event_time', '')}\n"
            f"[bold]User:[/bold] {event.get('username', '')}\n"
            f"[bold]Source IP:[/bold] {event.get('source_ip', '')}\n"
            f"[bold]Resource Type:[/bold] {event.get('resource_type', '')}\n"
            f"[bold]Resource Name:[/bold] {event.get('resource_name', '')}\n"
            f"[bold]Region:[/bold] {event.get('region', '')}\n"
            f"[bold]Error:[/bold] {event.get('error_code', '') or '(none)'}\n\n"
            f"[bold]Raw Event:[/bold]\n{event.get('raw_event', '')}"
        )

    async def _fetch_events(self) -> None:
        region = self.query_one("#input_region", Input).value.strip()
        event_name = self.query_one("#input_event_name", Input).value.strip()
        username = self.query_one("#input_username", Input).value.strip()
        resource_type = self.query_one("#input_resource_type", Input).value.strip()

        hours_raw = self.query_one("#input_hours", Input).value.strip()
        minutes_raw = self.query_one("#input_minutes", Input).value.strip()

        try:
            hours = int(hours_raw) if hours_raw else None
        except ValueError:
            self.app.notify("Lookback hours must be a whole number", severity="warning")
            self.query_one("#btn_fetch", Button).disabled = False
            return

        try:
            minutes = int(minutes_raw) if minutes_raw else None
        except ValueError:
            self.app.notify("Lookback minutes must be a whole number", severity="warning")
            self.query_one("#btn_fetch", Button).disabled = False
            return

        if hours is not None and hours < 0:
            self.app.notify("Lookback hours must be non-negative", severity="warning")
            self.query_one("#btn_fetch", Button).disabled = False
            return

        if minutes is not None and minutes < 0:
            self.app.notify("Lookback minutes must be non-negative", severity="warning")
            self.query_one("#btn_fetch", Button).disabled = False
            return

        config = self.app.config_manager.get()
        max_results = config.cloudtrail_max_events

        start_time: Optional[datetime] = None
        if hours is not None or minutes is not None:
            h = hours if hours is not None else 0
            m = minutes if minutes is not None else 0
            if h > 0 or m > 0:
                start_time = datetime.utcnow() - timedelta(hours=h, minutes=m)
        if start_time is None:
            # Fall back to configured default lookback
            default_hours = config.cloudtrail_default_lookback_hours
            default_minutes = config.cloudtrail_default_lookback_minutes
            start_time = datetime.utcnow() - timedelta(
                hours=default_hours, minutes=default_minutes
            )

        try:
            events = await self.app.cloudtrail_service.lookup_events(
                region=region,
                start_time=start_time,
                event_name=event_name,
                username=username,
                resource_type=resource_type,
                max_results=max_results,
            )
        except Exception as exc:
            self.app.notify(f"CloudTrail fetch failed: {exc}", severity="error")
            self.query_one("#btn_fetch", Button).disabled = False
            return

        self._events = events
        table = self.query_one("#cloudtrail_table", DataTable)
        table.clear()

        for ev in events:
            event_time = ev.get("event_time", "")
            if hasattr(event_time, "strftime"):
                event_time = event_time.strftime("%Y-%m-%d %H:%M:%S")
            table.add_row(
                str(event_time),
                ev.get("event_name", ""),
                ev.get("username", ""),
                ev.get("source_ip", ""),
                ev.get("resource_name", "") or ev.get("resource_type", ""),
                ev.get("region", ""),
                ev.get("error_code", "") or "",
            )

        self.query_one("#btn_fetch", Button).disabled = False
        count = len(events)
        if count == 0:
            self.query_one("#event_detail_text", Static).update("No events found.")
            self.app.notify("No events found for the given filters.", severity="warning")
        else:
            self.query_one("#event_detail_text", Static).update("Select an event to view details.")
            self.app.notify(f"Loaded {count} CloudTrail events.")
