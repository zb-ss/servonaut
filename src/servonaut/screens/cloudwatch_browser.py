"""CloudWatch Logs browser screen for Servonaut."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Select, Static

from servonaut.screens._binding_guard import check_action_passthrough

logger = logging.getLogger(__name__)

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
    ("Last 1 min", 1),
    ("Last 5 mins", 5),
    ("Last 15 mins", 15),
    ("Last 30 mins", 30),
    ("Last 1 hour", 60),
    ("Last 2 hours", 120),
    ("Last 6 hours", 360),
    ("Last 12 hours", 720),
    ("Last 24 hours", 1440),
    ("Last 48 hours", 2880),
    ("Last 7 days", 10080),
]

_PAGE_SIZE = 100


class CloudWatchBrowserScreen(Screen):
    """Screen for browsing AWS CloudWatch log groups and events."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("f5", "fetch", "Fetch", show=True),
        Binding("y", "copy_output", "Copy", show=True),
        Binding("b", "ban_ip", "Ban IP", show=True),
        Binding("n", "next_page", "Next", show=True),
        Binding("p", "prev_page", "Prev", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._events: List[Dict[str, Any]] = []
        self._top_ips: List[Dict[str, Any]] = []
        self._selected_event_row: Optional[int] = None
        self._selected_ip_row: Optional[int] = None
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
        yield Container(
            Label(
                "[bold]CloudWatch Logs Browser[/bold]",
                id="cloudwatch_title",
            ),
            Horizontal(
                Vertical(
                    Label("Region"),
                    Select(
                        [(f"{label} ({value})", value) for label, value in _AWS_REGIONS],
                        prompt="Select region",
                        id="cw_select_region",
                        allow_blank=True,
                    ),
                    id="cw_filter_region",
                ),
                Vertical(
                    Label("Log Group"),
                    Select(
                        [],
                        prompt="Select region first",
                        id="cw_select_log_group",
                        allow_blank=True,
                    ),
                    id="cw_filter_log_group",
                ),
                Vertical(
                    Label("Time Range"),
                    Select(
                        _TIME_RANGE_OPTIONS,
                        value=60,
                        id="cw_select_time_range",
                        allow_blank=False,
                    ),
                    id="cw_filter_time_range",
                ),
                Vertical(
                    Label("Filter Pattern"),
                    Input(
                        placeholder="e.g. ERROR",
                        id="cw_input_filter_pattern",
                    ),
                    id="cw_filter_pattern",
                ),
                Button("Fetch", id="cw_btn_fetch", variant="primary"),
                Button("Back", id="cw_btn_back", variant="default"),
                id="cloudwatch_filter_bar",
            ),
            Horizontal(
                DataTable(id="cloudwatch_events_table"),
                Vertical(
                    Label("[bold]Top IPs[/bold]", id="cw_top_ips_label"),
                    DataTable(id="cloudwatch_ips_table"),
                    Button("Ban Selected IP", id="cw_btn_ban_ip", variant="error"),
                    id="cloudwatch_ips_panel",
                ),
                id="cloudwatch_main_content",
            ),
            Horizontal(
                Button("◀ Prev", id="cw_btn_prev", variant="default"),
                Static("", id="cw_page_info"),
                Button("Next ▶", id="cw_btn_next", variant="default"),
                id="cloudwatch_pager",
            ),
            VerticalScroll(
                Static(
                    "Select a log event to view the full message.",
                    id="cloudwatch_detail_text",
                ),
                id="cloudwatch_detail",
            ),
            id="cloudwatch_outer",
        )
        yield Footer()

    def on_mount(self) -> None:
        events_table = self.query_one("#cloudwatch_events_table", DataTable)
        events_table.add_columns("Time", "Stream", "Message")
        events_table.cursor_type = "row"

        ips_table = self.query_one("#cloudwatch_ips_table", DataTable)
        ips_table.add_columns("IP", "Count")
        ips_table.cursor_type = "row"

        self._update_pager()

        config = self.app.config_manager.get()
        if config.cloudwatch_default_region:
            self.query_one("#cw_select_region", Select).value = (
                config.cloudwatch_default_region
            )

    def _update_pager(self) -> None:
        """Update pagination controls."""
        total = self._total_pages
        page_info = self.query_one("#cw_page_info", Static)
        prev_btn = self.query_one("#cw_btn_prev", Button)
        next_btn = self.query_one("#cw_btn_next", Button)

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

    def _populate_events_table(self) -> None:
        """Fill the events table with the current page."""
        events_table = self.query_one("#cloudwatch_events_table", DataTable)
        events_table.clear()
        for ev in self._page_events:
            ts = ev.get("timestamp", "")
            if hasattr(ts, "strftime"):
                ts = ts.strftime("%Y-%m-%d %H:%M:%S")
            msg = ev.get("message", "").replace("\n", " ")[:120]
            events_table.add_row(str(ts), ev.get("log_stream", ""), msg)

    # ------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------

    def action_next_page(self) -> None:
        if self._current_page < self._total_pages - 1:
            self._current_page += 1
            self._populate_events_table()
            self._update_pager()

    def action_prev_page(self) -> None:
        if self._current_page > 0:
            self._current_page -= 1
            self._populate_events_table()
            self._update_pager()

    # ------------------------------------------------------------------
    # Region / log group discovery
    # ------------------------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "cw_select_region":
            region = event.value
            if region is not Select.NULL:
                self._discover_groups_for_region(str(region))
            else:
                group_select = self.query_one("#cw_select_log_group", Select)
                group_select.set_options([])
                group_select.prompt = "Select region first"

    def _discover_groups_for_region(self, region: str) -> None:
        group_select = self.query_one("#cw_select_log_group", Select)
        group_select.set_options([])
        group_select.prompt = "Loading..."
        self.run_worker(
            self._load_log_groups(region),
            name="load_groups",
            group="discover",
            exclusive=True,
        )

    async def _load_log_groups(self, region: str) -> None:
        config = self.app.config_manager.get()
        prefix = config.cloudwatch_log_group_prefix

        try:
            groups = await self.app.cloudwatch_service.list_log_groups(
                prefix=prefix, region=region
            )
        except Exception as exc:
            self.app.notify(f"Failed to load log groups: {exc}", severity="error")
            self.query_one("#cw_select_log_group", Select).prompt = "Error loading"
            return

        group_select = self.query_one("#cw_select_log_group", Select)
        if not groups:
            group_select.set_options([])
            group_select.prompt = "No log groups found"
            self.app.notify("No log groups found in this region.", severity="warning")
            return

        group_select.set_options([(g["name"], g["name"]) for g in groups])
        group_select.prompt = "Select log group"
        self.app.notify(f"Found {len(groups)} log group(s).")

    # ------------------------------------------------------------------
    # Fetch events
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "cw_btn_fetch":
            self.action_fetch()
        elif btn_id == "cw_btn_back":
            self.action_back()
        elif btn_id == "cw_btn_ban_ip":
            self.action_ban_ip()
        elif btn_id == "cw_btn_prev":
            self.action_prev_page()
        elif btn_id == "cw_btn_next":
            self.action_next_page()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_fetch(self) -> None:
        region_select = self.query_one("#cw_select_region", Select)
        group_select = self.query_one("#cw_select_log_group", Select)

        region = region_select.value
        if region is Select.NULL:
            self.app.notify("Select a region first.", severity="warning")
            return

        log_group = group_select.value
        if log_group is Select.NULL:
            self.app.notify("Select a log group first.", severity="warning")
            return

        time_select = self.query_one("#cw_select_time_range", Select)
        minutes = int(time_select.value) if time_select.value is not Select.NULL else 60
        filter_pattern = self.query_one("#cw_input_filter_pattern", Input).value.strip()

        self.query_one("#cw_btn_fetch", Button).disabled = True
        self.query_one("#cloudwatch_detail_text", Static).update("Loading...")
        self.query_one("#cloudwatch_events_table", DataTable).clear()
        self.query_one("#cloudwatch_ips_table", DataTable).clear()
        self._events = []
        self._top_ips = []
        self._current_page = 0
        self._update_pager()

        self.run_worker(
            self._fetch_events(str(region), str(log_group), minutes, filter_pattern),
            name="cloudwatch_fetch",
            group="fetch",
            exclusive=True,
        )

    async def _fetch_events(
        self, region: str, log_group: str, minutes: int, filter_pattern: str
    ) -> None:
        config = self.app.config_manager.get()
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=minutes)

        try:
            events = await self.app.cloudwatch_service.get_log_events(
                log_group=log_group,
                start_time=start_time,
                end_time=end_time,
                filter_pattern=filter_pattern,
                region=region,
                max_events=0,  # Fetch all
            )
        except Exception as exc:
            self.app.notify(f"CloudWatch fetch failed: {exc}", severity="error")
            self.query_one("#cw_btn_fetch", Button).disabled = False
            return

        self._events = events

        # Extract IPs from ALL events
        from servonaut.services.cloudwatch_service import CloudWatchService
        self._top_ips = CloudWatchService.extract_top_ips(events)

        # Populate IPs table (always shows all)
        ips_table = self.query_one("#cloudwatch_ips_table", DataTable)
        ips_table.clear()
        for entry in self._top_ips:
            ips_table.add_row(entry["ip"], str(entry["count"]))

        # Populate first page of events
        self._current_page = 0
        self._populate_events_table()
        self._update_pager()

        self.query_one("#cw_btn_fetch", Button).disabled = False
        count = len(events)
        if count == 0:
            self.query_one("#cloudwatch_detail_text", Static).update("No events found.")
            self.app.notify("No events found for the given filters.", severity="warning")
        else:
            self.query_one("#cloudwatch_detail_text", Static).update(
                "Select a log event to view the full message."
            )
            self.app.notify(
                f"Loaded {count} events ({minutes}min window), "
                f"{len(self._top_ips)} unique IPs."
            )

    # ------------------------------------------------------------------
    # Event detail / selection
    # ------------------------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        table_id = event.data_table.id
        if table_id == "cloudwatch_events_table":
            # Map table row to absolute event index
            abs_index = self._current_page * _PAGE_SIZE + event.cursor_row
            self._selected_event_row = abs_index
            self._show_event_detail(abs_index)
        elif table_id == "cloudwatch_ips_table":
            self._selected_ip_row = event.cursor_row

    def _show_event_detail(self, index: int) -> None:
        if index < 0 or index >= len(self._events):
            return
        event = self._events[index]
        ts = event.get("timestamp", "")
        if hasattr(ts, "strftime"):
            ts = ts.strftime("%Y-%m-%d %H:%M:%S")
        from rich.text import Text
        detail = Text()
        detail.append("Time: ", style="bold")
        detail.append(f"{ts}\n")
        detail.append("Stream: ", style="bold")
        detail.append(f"{event.get('log_stream', '')}\n\n")
        detail.append("Message:\n", style="bold")
        detail.append(event.get("message", ""))
        self.query_one("#cloudwatch_detail_text", Static).update(detail)

    # ------------------------------------------------------------------
    # Copy / Ban
    # ------------------------------------------------------------------

    def action_copy_output(self) -> None:
        if self._selected_event_row is not None and self._selected_event_row < len(
            self._events
        ):
            text = self._events[self._selected_event_row].get("message", "")
        else:
            text = "\n".join(e.get("message", "") for e in self._events)

        if not text:
            self.app.notify("Nothing to copy.", severity="warning")
            return

        from servonaut.utils.platform_utils import copy_to_clipboard
        if copy_to_clipboard(text):
            self.app.notify("Copied to clipboard.")
        else:
            self.app.copy_to_clipboard(text)
            self.app.notify("Copied to clipboard.")

    def action_ban_ip(self) -> None:
        ip = self._get_selected_ip()
        if not ip:
            self.app.notify(
                "Select an IP from the Top IPs table first.", severity="warning"
            )
            return
        from servonaut.screens.ip_ban import IPBanScreen
        self.app.push_screen(IPBanScreen(prefill_ip=ip))

    def _get_selected_ip(self) -> Optional[str]:
        if self._selected_ip_row is None:
            return None
        if self._selected_ip_row >= len(self._top_ips):
            return None
        return self._top_ips[self._selected_ip_row].get("ip")
