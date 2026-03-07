"""CloudWatch Logs browser screen for Servonaut."""

from __future__ import annotations

import subprocess
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Static

from servonaut.screens._binding_guard import check_action_passthrough


class CloudWatchBrowserScreen(Screen):
    """Screen for browsing AWS CloudWatch log groups and events."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("f5", "fetch", "Fetch", show=True),
        Binding("d", "discover_groups", "Discover", show=True),
        Binding("y", "copy_output", "Copy", show=True),
        Binding("b", "ban_ip", "Ban IP", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._events: List[Dict[str, Any]] = []
        self._top_ips: List[Dict[str, Any]] = []
        self._discovered_groups: List[Dict[str, Any]] = []
        self._selected_event_row: Optional[int] = None
        self._selected_ip_row: Optional[int] = None

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Vertical(
                Label(
                    "[bold]CloudWatch Logs Browser[/bold]",
                    id="cloudwatch_title",
                ),
                Horizontal(
                    Vertical(
                        Label("Region"),
                        Input(placeholder="e.g. us-east-1", id="cw_input_region"),
                        id="cw_filter_region",
                    ),
                    Vertical(
                        Label("Log Group"),
                        Input(
                            placeholder="e.g. /aws/lambda/my-fn",
                            id="cw_input_log_group",
                        ),
                        id="cw_filter_log_group",
                    ),
                    Vertical(
                        Label("Hours"),
                        Input(placeholder="1", id="cw_input_hours"),
                        id="cw_filter_hours",
                    ),
                    Vertical(
                        Label("Minutes"),
                        Input(placeholder="0", id="cw_input_minutes"),
                        id="cw_filter_minutes",
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
                    Button("Discover Groups", id="cw_btn_discover"),
                    Button("Back", id="cw_btn_back", variant="default"),
                    id="cloudwatch_filter_bar",
                ),
                DataTable(id="cw_groups_table"),
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
                VerticalScroll(
                    Static(
                        "Select a log event to view the full message.",
                        id="cloudwatch_detail_text",
                    ),
                    id="cloudwatch_detail",
                ),
                id="cloudwatch_container",
            ),
            id="cloudwatch_outer",
        )
        yield Footer()

    def on_mount(self) -> None:
        groups_table = self.query_one("#cw_groups_table", DataTable)
        groups_table.add_columns("Log Group", "Retention", "Stored")
        groups_table.cursor_type = "row"
        groups_table.display = False

        events_table = self.query_one("#cloudwatch_events_table", DataTable)
        events_table.add_columns("Time", "Stream", "Message")
        events_table.cursor_type = "row"

        ips_table = self.query_one("#cloudwatch_ips_table", DataTable)
        ips_table.add_columns("IP", "Count")
        ips_table.cursor_type = "row"

        config = self.app.config_manager.get()
        if config.cloudwatch_default_region:
            self.query_one("#cw_input_region", Input).value = (
                config.cloudwatch_default_region
            )
        if config.cloudwatch_log_group_prefix:
            self.query_one("#cw_input_log_group", Input).value = (
                config.cloudwatch_log_group_prefix
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "cw_btn_fetch":
            self.action_fetch()
        elif btn_id == "cw_btn_discover":
            self.action_discover_groups()
        elif btn_id == "cw_btn_back":
            self.action_back()
        elif btn_id == "cw_btn_ban_ip":
            self.action_ban_ip()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        table_id = event.data_table.id
        if table_id == "cloudwatch_events_table":
            self._selected_event_row = event.cursor_row
            self._show_event_detail(event.cursor_row)
        elif table_id == "cloudwatch_ips_table":
            self._selected_ip_row = event.cursor_row
        elif table_id == "cw_groups_table":
            row_data = event.data_table.get_row_at(event.cursor_row)
            group_name = str(row_data[0])
            self.query_one("#cw_input_log_group", Input).value = group_name
            event.data_table.display = False
            self.app.notify(f"Selected: {group_name}")

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_fetch(self) -> None:
        self.query_one("#cw_btn_fetch", Button).disabled = True
        self.query_one("#cloudwatch_detail_text", Static).update("Loading...")
        self.query_one("#cloudwatch_events_table", DataTable).clear()
        self.query_one("#cloudwatch_ips_table", DataTable).clear()
        self._events = []
        self._top_ips = []
        self.run_worker(
            self._fetch_events(), name="cloudwatch_fetch", exclusive=True
        )

    def action_discover_groups(self) -> None:
        self.query_one("#cw_btn_discover", Button).disabled = True
        self.run_worker(
            self._discover_groups(), name="cloudwatch_discover", exclusive=True
        )

    def action_copy_output(self) -> None:
        if self._selected_event_row is not None and self._selected_event_row < len(
            self._events
        ):
            event = self._events[self._selected_event_row]
            text = event.get("message", "")
        else:
            text = "\n".join(e.get("message", "") for e in self._events)

        if not text:
            self.app.notify("Nothing to copy.", severity="warning")
            return

        try:
            subprocess.run(
                ["xclip", "-selection", "clipboard"],
                input=text.encode(),
                check=False,
            )
            self.app.notify("Copied to clipboard.")
        except FileNotFoundError:
            try:
                subprocess.run(
                    ["xsel", "--clipboard", "--input"],
                    input=text.encode(),
                    check=False,
                )
                self.app.notify("Copied to clipboard.")
            except FileNotFoundError:
                self.app.notify("xclip/xsel not available.", severity="warning")

    def action_ban_ip(self) -> None:
        ip = self._get_selected_ip()
        if not ip:
            self.app.notify("Select an IP from the Top IPs table first.", severity="warning")
            return
        from servonaut.screens.ip_ban import IPBanScreen
        self.app.push_screen(IPBanScreen(prefill_ip=ip))

    def _get_selected_ip(self) -> Optional[str]:
        if self._selected_ip_row is None:
            return None
        if self._selected_ip_row >= len(self._top_ips):
            return None
        return self._top_ips[self._selected_ip_row].get("ip")

    def _show_event_detail(self, row_index: int) -> None:
        if row_index < 0 or row_index >= len(self._events):
            return
        event = self._events[row_index]
        ts = event.get("timestamp", "")
        if hasattr(ts, "strftime"):
            ts = ts.strftime("%Y-%m-%d %H:%M:%S")
        detail_widget = self.query_one("#cloudwatch_detail_text", Static)
        detail_widget.update(
            f"[bold]Time:[/bold] {ts}\n"
            f"[bold]Stream:[/bold] {event.get('log_stream', '')}\n\n"
            f"[bold]Message:[/bold]\n{event.get('message', '')}"
        )

    async def _fetch_events(self) -> None:
        region = self.query_one("#cw_input_region", Input).value.strip()
        log_group = self.query_one("#cw_input_log_group", Input).value.strip()
        filter_pattern = self.query_one("#cw_input_filter_pattern", Input).value.strip()

        if not log_group:
            self.app.notify("Enter a log group name.", severity="warning")
            self.query_one("#cw_btn_fetch", Button).disabled = False
            return

        hours_raw = self.query_one("#cw_input_hours", Input).value.strip()
        minutes_raw = self.query_one("#cw_input_minutes", Input).value.strip()

        try:
            hours = int(hours_raw) if hours_raw else 1
        except ValueError:
            self.app.notify("Hours must be a number.", severity="warning")
            self.query_one("#cw_btn_fetch", Button).disabled = False
            return

        try:
            minutes = int(minutes_raw) if minutes_raw else 0
        except ValueError:
            self.app.notify("Minutes must be a number.", severity="warning")
            self.query_one("#cw_btn_fetch", Button).disabled = False
            return

        config = self.app.config_manager.get()
        max_events = config.cloudwatch_max_events

        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours, minutes=minutes)

        try:
            events = await self.app.cloudwatch_service.get_log_events(
                log_group=log_group,
                start_time=start_time,
                end_time=end_time,
                filter_pattern=filter_pattern,
                region=region,
                max_events=max_events,
            )
        except Exception as exc:
            self.app.notify(f"CloudWatch fetch failed: {exc}", severity="error")
            self.query_one("#cw_btn_fetch", Button).disabled = False
            return

        self._events = events
        events_table = self.query_one("#cloudwatch_events_table", DataTable)
        events_table.clear()

        for ev in events:
            ts = ev.get("timestamp", "")
            if hasattr(ts, "strftime"):
                ts = ts.strftime("%Y-%m-%d %H:%M:%S")
            msg = ev.get("message", "").replace("\n", " ")[:120]
            events_table.add_row(
                str(ts),
                ev.get("log_stream", ""),
                msg,
            )

        from servonaut.services.cloudwatch_service import CloudWatchService

        self._top_ips = CloudWatchService.extract_top_ips(events)
        ips_table = self.query_one("#cloudwatch_ips_table", DataTable)
        ips_table.clear()
        for entry in self._top_ips:
            ips_table.add_row(entry["ip"], str(entry["count"]))

        self.query_one("#cw_btn_fetch", Button).disabled = False
        count = len(events)
        if count == 0:
            self.query_one("#cloudwatch_detail_text", Static).update("No events found.")
            self.app.notify("No events found for the given filters.", severity="warning")
        else:
            self.query_one("#cloudwatch_detail_text", Static).update(
                "Select a log event to view the full message."
            )
            self.app.notify(f"Loaded {count} log events, {len(self._top_ips)} unique IPs found.")

    async def _discover_groups(self) -> None:
        region = self.query_one("#cw_input_region", Input).value.strip()
        config = self.app.config_manager.get()
        prefix = config.cloudwatch_log_group_prefix

        try:
            groups = await self.app.cloudwatch_service.list_log_groups(
                prefix=prefix, region=region
            )
        except Exception as exc:
            self.app.notify(f"Discovery failed: {exc}", severity="error")
            self.query_one("#cw_btn_discover", Button).disabled = False
            return

        self.query_one("#cw_btn_discover", Button).disabled = False

        if not groups:
            self.app.notify("No log groups found.", severity="warning")
            return

        self._discovered_groups = groups
        groups_table = self.query_one("#cw_groups_table", DataTable)
        groups_table.clear()
        for g in groups:
            retention = g.get("retention_days")
            ret_str = f"{retention}d" if retention else "Never"
            stored = g.get("stored_bytes", 0)
            if stored >= 1_073_741_824:
                size_str = f"{stored / 1_073_741_824:.1f} GB"
            elif stored >= 1_048_576:
                size_str = f"{stored / 1_048_576:.1f} MB"
            elif stored >= 1024:
                size_str = f"{stored / 1024:.1f} KB"
            else:
                size_str = f"{stored} B"
            groups_table.add_row(g["name"], ret_str, size_str)
        groups_table.display = True
        groups_table.focus()
        self.app.notify(
            f"Found {len(groups)} log group(s). Select one from the list."
        )
