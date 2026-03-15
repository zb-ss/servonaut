"""CloudTrail event browser screen for Servonaut."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll

from servonaut.widgets.sidebar import Sidebar
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Select, Static

from servonaut.screens._binding_guard import check_action_passthrough

_AWS_REGIONS = [
    ("US East (N. Virginia)", "us-east-1"),
    ("US East (Ohio)", "us-east-2"),
    ("US West (N. California)", "us-west-1"),
    ("US West (Oregon)", "us-west-2"),
    ("EU (Ireland)", "eu-west-1"),
    ("EU (Frankfurt)", "eu-central-1"),
    ("EU (London)", "eu-west-2"),
    ("EU (Paris)", "eu-west-3"),
    ("EU (Stockholm)", "eu-north-1"),
    ("EU (Milan)", "eu-south-1"),
    ("Asia Pacific (Tokyo)", "ap-northeast-1"),
    ("Asia Pacific (Seoul)", "ap-northeast-2"),
    ("Asia Pacific (Singapore)", "ap-southeast-1"),
    ("Asia Pacific (Sydney)", "ap-southeast-2"),
    ("Asia Pacific (Mumbai)", "ap-south-1"),
    ("Asia Pacific (Hong Kong)", "ap-east-1"),
    ("Canada (Central)", "ca-central-1"),
    ("South America (São Paulo)", "sa-east-1"),
    ("Middle East (Bahrain)", "me-south-1"),
    ("Africa (Cape Town)", "af-south-1"),
]

_TIME_RANGE_OPTIONS = [
    ("Last 1 hour", 60),
    ("Last 2 hours", 120),
    ("Last 6 hours", 360),
    ("Last 12 hours", 720),
    ("Last 24 hours", 1440),
    ("Last 48 hours", 2880),
    ("Last 7 days", 10080),
    ("Last 14 days", 20160),
    ("Last 30 days", 43200),
    ("Last 90 days", 129600),
]

_PAGE_SIZE = 100


class CloudTrailBrowserScreen(Screen):
    """Screen for browsing and filtering AWS CloudTrail events."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("f5", "fetch", "Fetch", show=True),
        Binding("y", "copy_output", "Copy", show=True),
        Binding("n", "next_page", "Next", show=True),
        Binding("p", "prev_page", "Prev", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._events: List[Dict[str, Any]] = []
        self._selected_row: Optional[int] = None
        self._current_page: int = 0

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    @property
    def _total_pages(self) -> int:
        if not self._events:
            return 0
        return (len(self._events) + _PAGE_SIZE - 1) // _PAGE_SIZE

    @property
    def _page_events(self) -> List[Dict[str, Any]]:
        start = self._current_page * _PAGE_SIZE
        return self._events[start : start + _PAGE_SIZE]

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Label(
                    "[bold]CloudTrail Event Browser[/bold]",
                    id="cloudtrail_title",
                ),
            Horizontal(
                Vertical(
                    Label("Region"),
                    Select(
                        [(f"{label} ({value})", value) for label, value in _AWS_REGIONS],
                        prompt="All regions",
                        id="ct_select_region",
                        allow_blank=True,
                    ),
                    id="ct_filter_region",
                ),
                Vertical(
                    Label("Time Range"),
                    Select(
                        _TIME_RANGE_OPTIONS,
                        value=1440,
                        id="ct_select_time_range",
                        allow_blank=False,
                    ),
                    id="ct_filter_time_range",
                ),
                Vertical(
                    Label("Event Name"),
                    Input(
                        placeholder="e.g. RunInstances",
                        id="ct_input_event_name",
                    ),
                    id="ct_filter_event_name",
                ),
                Vertical(
                    Label("Username"),
                    Input(
                        placeholder="IAM username",
                        id="ct_input_username",
                    ),
                    id="ct_filter_username",
                ),
                Vertical(
                    Label("Resource Type"),
                    Input(
                        placeholder="e.g. AWS::EC2::Instance",
                        id="ct_input_resource_type",
                    ),
                    id="ct_filter_resource_type",
                ),
                Button("Fetch", id="ct_btn_fetch", variant="primary"),
                Button("Back", id="ct_btn_back", variant="default"),
                id="cloudtrail_filters",
            ),
            DataTable(id="cloudtrail_table"),
            Horizontal(
                Button("◀ Prev", id="ct_btn_prev", variant="default"),
                Static("", id="ct_page_info"),
                Button("Next ▶", id="ct_btn_next", variant="default"),
                id="cloudtrail_pager",
            ),
            VerticalScroll(
                Static(
                    "Select an event to view details.",
                    id="event_detail_text",
                ),
                id="event_detail",
            ),
            id="cloudtrail_container",
        )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#cloudtrail_table", DataTable)
        table.add_columns("Time", "Event", "User", "Source IP", "Resource", "Region", "Error")
        table.cursor_type = "row"
        self._update_pager()

        config = self.app.config_manager.get()
        if config.cloudtrail_default_region:
            self.query_one("#ct_select_region", Select).value = (
                config.cloudtrail_default_region
            )

    # ------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------

    def _update_pager(self) -> None:
        total = self._total_pages
        page_info = self.query_one("#ct_page_info", Static)
        prev_btn = self.query_one("#ct_btn_prev", Button)
        next_btn = self.query_one("#ct_btn_next", Button)

        if total <= 1:
            page_info.update(
                f"[dim]{len(self._events)} events total[/dim]" if self._events else ""
            )
            prev_btn.disabled = True
            next_btn.disabled = True
        else:
            page_info.update(
                f"Page {self._current_page + 1} of {total}  "
                f"[dim]({len(self._events)} events total)[/dim]"
            )
            prev_btn.disabled = self._current_page == 0
            next_btn.disabled = self._current_page >= total - 1

    def _populate_table(self) -> None:
        table = self.query_one("#cloudtrail_table", DataTable)
        table.clear()
        for ev in self._page_events:
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

    def action_next_page(self) -> None:
        if self._current_page < self._total_pages - 1:
            self._current_page += 1
            self._populate_table()
            self._update_pager()

    def action_prev_page(self) -> None:
        if self._current_page > 0:
            self._current_page -= 1
            self._populate_table()
            self._update_pager()

    # ------------------------------------------------------------------
    # Buttons
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "ct_btn_fetch":
            self.action_fetch()
        elif btn_id == "ct_btn_back":
            self.action_back()
        elif btn_id == "ct_btn_prev":
            self.action_prev_page()
        elif btn_id == "ct_btn_next":
            self.action_next_page()

    # ------------------------------------------------------------------
    # Event detail / selection
    # ------------------------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        abs_index = self._current_page * _PAGE_SIZE + event.cursor_row
        self._selected_row = abs_index
        self._show_event_detail(abs_index)

    def _show_event_detail(self, index: int) -> None:
        if index < 0 or index >= len(self._events):
            return
        event = self._events[index]
        event_time = event.get("event_time", "")
        if hasattr(event_time, "strftime"):
            event_time = event_time.strftime("%Y-%m-%d %H:%M:%S")
        self.query_one("#event_detail_text", Static).update(
            f"[bold]Event:[/bold] {event.get('event_name', '')}\n"
            f"[bold]Time:[/bold] {event_time}\n"
            f"[bold]User:[/bold] {event.get('username', '')}\n"
            f"[bold]Source IP:[/bold] {event.get('source_ip', '')}\n"
            f"[bold]Resource Type:[/bold] {event.get('resource_type', '')}\n"
            f"[bold]Resource Name:[/bold] {event.get('resource_name', '')}\n"
            f"[bold]Region:[/bold] {event.get('region', '')}\n"
            f"[bold]Error:[/bold] {event.get('error_code', '') or '(none)'}\n\n"
            f"[bold]Raw Event:[/bold]\n{event.get('raw_event', '')}"
        )

    # ------------------------------------------------------------------
    # Copy
    # ------------------------------------------------------------------

    def action_copy_output(self) -> None:
        if self._selected_row is not None and self._selected_row < len(self._events):
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
            text = "\n".join(lines)
        else:
            text = "\n".join(
                f"{ev.get('event_name', '')} | {ev.get('username', '')} | {ev.get('source_ip', '')}"
                for ev in self._events
            )

        if not text:
            self.app.notify("Nothing to copy.", severity="warning")
            return

        from servonaut.utils.platform_utils import copy_to_clipboard

        if copy_to_clipboard(text):
            self.app.notify("Copied to clipboard.")
        else:
            self.app.copy_to_clipboard(text)
            self.app.notify("Copied to clipboard.")

    # ------------------------------------------------------------------
    # Fetch / Back
    # ------------------------------------------------------------------

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_fetch(self) -> None:
        region_select = self.query_one("#ct_select_region", Select)
        region = region_select.value
        if region is Select.NULL:
            region = ""

        time_select = self.query_one("#ct_select_time_range", Select)
        minutes = int(time_select.value) if time_select.value is not Select.NULL else 1440

        event_name = self.query_one("#ct_input_event_name", Input).value.strip()
        username = self.query_one("#ct_input_username", Input).value.strip()
        resource_type = self.query_one("#ct_input_resource_type", Input).value.strip()

        self.query_one("#ct_btn_fetch", Button).disabled = True
        self.query_one("#event_detail_text", Static).update("Loading...")
        self.query_one("#cloudtrail_table", DataTable).clear()
        self._events = []
        self._current_page = 0
        self._update_pager()

        self.run_worker(
            self._fetch_events(str(region), minutes, event_name, username, resource_type),
            name="cloudtrail_fetch",
            group="fetch",
            exclusive=True,
        )

    async def _fetch_events(
        self,
        region: str,
        minutes: int,
        event_name: str,
        username: str,
        resource_type: str,
    ) -> None:
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=minutes)

        try:
            events = await self.app.cloudtrail_service.lookup_events(
                region=region,
                start_time=start_time,
                end_time=end_time,
                event_name=event_name,
                username=username,
                resource_type=resource_type,
                max_results=0,
            )
        except Exception as exc:
            self.app.notify(f"CloudTrail fetch failed: {exc}", severity="error")
            self.query_one("#ct_btn_fetch", Button).disabled = False
            return

        self._events = events
        self._current_page = 0
        self._populate_table()
        self._update_pager()

        self.query_one("#ct_btn_fetch", Button).disabled = False
        count = len(events)
        if count == 0:
            self.query_one("#event_detail_text", Static).update("No events found.")
            self.app.notify("No events found for the given filters.", severity="warning")
        else:
            self.query_one("#event_detail_text", Static).update(
                "Select an event to view details."
            )
            self.app.notify(f"Loaded {count} CloudTrail events.")
