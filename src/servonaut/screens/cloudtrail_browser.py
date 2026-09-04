"""CloudTrail event browser screen for Servonaut."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll

from servonaut.widgets.sidebar import Sidebar
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Select, Static

from servonaut.screens._binding_guard import check_action_passthrough
import re

_EC2_ID_RE = re.compile(r"i-[0-9a-f]{8,17}")

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

# Chosen from the picker to type a value the loaded events do not contain.
_TYPE_A_VALUE = "\x00type-a-value"

# Picker id -> the parsed-event field it narrows.
_FILTER_FIELDS = (
    ("ct_select_event_name", "event_name"),
    ("ct_select_username", "username"),
    ("ct_select_resource_type", "resource_type"),
)
_PAGE_SIZE = 100


class FilterValueModal(ModalScreen[Optional[str]]):
    """Ask for a filter value the loaded events do not contain.

    The pickers can only offer what has been fetched, so a value further
    back in the window would be unreachable. A typed value is sent to the
    API, which searches the whole window for it.
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]

    def __init__(self, field_label: str, example: str) -> None:
        super().__init__()
        self._field_label = field_label
        self._example = example

    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                f"[bold cyan]Filter by {self._field_label}[/bold cyan]",
                id="ct_value_modal_title",
            ),
            Static(
                "[dim]Matched exactly, and case-sensitively, against the whole "
                "time range.[/dim]",
                id="ct_value_modal_hint",
            ),
            Input(placeholder=self._example, id="ct_value_input"),
            Horizontal(
                Button("Search", variant="primary", id="btn_ct_value_ok"),
                Button("Cancel", id="btn_ct_value_cancel"),
                id="ct_value_modal_buttons",
            ),
            id="ct_value_modal",
        )

    def on_mount(self) -> None:
        self.query_one("#ct_value_input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_ct_value_ok":
            self._submit()
        else:
            self.dismiss(None)

    def _submit(self) -> None:
        value = self.query_one("#ct_value_input", Input).value.strip()
        self.dismiss(value or None)

    def action_cancel(self) -> None:
        self.dismiss(None)


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
        self._visible: List[Dict[str, Any]] = []
        self._selected_row: Optional[int] = None
        self._current_page: int = 0
        self._cap_reached: bool = False
        self._fleet_names_cache: Optional[Dict[str, str]] = None
        self._next_token: Optional[Dict[str, str]] = None
        self._loading_more: bool = False
        self._fetch_args: Optional[Dict[str, Any]] = None
        # set_options() resets a Select and fires Changed; ignore those.
        self._suppress_filter_events: bool = False

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    @property
    def _total_pages(self) -> int:
        if not self._visible:
            return 0
        return (len(self._visible) + _PAGE_SIZE - 1) // _PAGE_SIZE

    @property
    def _page_events(self) -> List[Dict[str, Any]]:
        start = self._current_page * _PAGE_SIZE
        return self._visible[start : start + _PAGE_SIZE]

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
                    Label("Event"),
                    Select(
                        [],
                        prompt="All events",
                        id="ct_select_event_name",
                        allow_blank=True,
                    ),
                    id="ct_filter_event_name",
                ),
                Vertical(
                    Label("User"),
                    Select(
                        [],
                        prompt="All users",
                        id="ct_select_username",
                        allow_blank=True,
                    ),
                    id="ct_filter_username",
                ),
                Vertical(
                    Label("Resource Type"),
                    Select(
                        [],
                        prompt="All types",
                        id="ct_select_resource_type",
                        allow_blank=True,
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

    def _filter_values(self) -> Dict[str, str]:
        """Current picker selections, keyed by the event field they filter."""
        values: Dict[str, str] = {}
        for widget_id, field in _FILTER_FIELDS:
            try:
                value = self.query_one(f"#{widget_id}", Select).value
            except Exception:  # noqa: BLE001 - screen may not be composed yet
                value = Select.NULL
            text = "" if value is Select.NULL else str(value)
            values[field] = "" if text == _TYPE_A_VALUE else text
        return values

    def _refresh_filter_options(self) -> None:
        """Offer exactly the values present in the loaded events, with counts.

        Typing a filter meant guessing an exact, case-sensitive value that
        might not occur at all. Usernames are redacted for display only; the
        value behind the option stays real so the lookup still works.
        """
        for widget_id, field in _FILTER_FIELDS:
            counts = Counter(str(ev.get(field) or "") for ev in self._events)
            counts.pop("", None)
            select = self.query_one(f"#{widget_id}", Select)
            previous = select.value
            options = [
                (
                    f"{self._username_label(value) if field == 'username' else value}"
                    f"  ({count})",
                    value,
                )
                for value, count in sorted(
                    counts.items(), key=lambda item: (-item[1], item[0])
                )
            ]
            # A value further back in the window is not in the loaded events,
            # so keep a typed one listed and always offer to type another.
            if (
                previous is not Select.NULL
                and previous != _TYPE_A_VALUE
                and previous not in counts
            ):
                options.append((f"{previous}  (typed)", previous))
            options.append(("Type a value...", _TYPE_A_VALUE))
            self._suppress_filter_events = True
            try:
                select.set_options(options)
                if previous is not Select.NULL and previous != _TYPE_A_VALUE:
                    select.value = previous
            finally:
                self._suppress_filter_events = False

    _VALUE_PROMPTS = {
        "ct_select_event_name": ("event name", "e.g. TerminateInstances"),
        "ct_select_username": ("user", "an IAM user name or an instance ID"),
        "ct_select_resource_type": ("resource type", "e.g. AWS::EC2::Instance"),
    }

    def _prompt_for_value(self, widget_id: str) -> None:
        """Ask for a value, then search the window for it."""
        label, example = self._VALUE_PROMPTS.get(widget_id, ("value", ""))
        select = self.query_one(f"#{widget_id}", Select)

        def _apply(value: Optional[str]) -> None:
            self._suppress_filter_events = True
            try:
                if not value:
                    select.value = Select.NULL
                    return
                options = [
                    (str(text), val)
                    for text, val in select._options
                    if val is not Select.NULL and val != _TYPE_A_VALUE
                ]
                if value not in [val for _, val in options]:
                    options.append((f"{value}  (typed)", value))
                options.append(("Type a value...", _TYPE_A_VALUE))
                select.set_options(options)
                select.value = value
            finally:
                self._suppress_filter_events = False
            if value:
                # A typed value is usually absent from the loaded events, so
                # narrowing locally would just empty the table; ask the API.
                self.action_fetch()

        self.app.push_screen(FilterValueModal(label, example), _apply)

    def _apply_filters(self) -> None:
        """Narrow the loaded events to the current selections.

        Combining selections is a local pass, which the API cannot do: it
        honours one lookup attribute per call.
        """
        active = {f: v for f, v in self._filter_values().items() if v}
        if not active:
            self._visible = list(self._events)
            return
        self._visible = [
            ev
            for ev in self._events
            if all(str(ev.get(f) or "") == v for f, v in active.items())
        ]

    def on_select_changed(self, event: Select.Changed) -> None:
        """Narrow the loaded events as soon as a picker changes."""
        if self._suppress_filter_events:
            return
        if event.select.id not in {widget_id for widget_id, _ in _FILTER_FIELDS}:
            return
        if event.value == _TYPE_A_VALUE:
            self._prompt_for_value(event.select.id)
            return
        self._current_page = 0
        self._apply_filters()
        self._populate_table()
        self._update_pager()

    def _update_pager(self) -> None:
        total = self._total_pages
        page_info = self.query_one("#ct_page_info", Static)
        prev_btn = self.query_one("#ct_btn_prev", Button)
        next_btn = self.query_one("#ct_btn_next", Button)

        loaded = len(self._events)
        shown = len(self._visible)
        if not loaded:
            summary = ""
        elif shown != loaded:
            summary = f"{shown} of {loaded} loaded events"
        else:
            summary = f"{loaded} events"
        if self._loading_more:
            summary += " - loading more..." if summary else "loading more..."
        elif self._next_token:
            summary += " - more in this window, press Next"
        elif summary and self._cap_reached:
            summary += " (cap reached - narrow the range or filters, then Fetch)"

        # Next also reads the next page when one exists, so it stays live on
        # the last page of what is loaded.
        more_available = bool(self._next_token) and not self._loading_more
        if total <= 1:
            page_info.update(f"[dim]{summary}[/dim]" if summary else "")
            prev_btn.disabled = True
            next_btn.disabled = not more_available
        else:
            page_info.update(
                f"Page {self._current_page + 1} of {total}   [dim]{summary}[/dim]"
            )
            prev_btn.disabled = self._current_page == 0
            next_btn.disabled = self._current_page >= total - 1 and not more_available

    def _populate_table(self) -> None:
        table = self.query_one("#cloudtrail_table", DataTable)
        table.clear()
        # _s: scrub helper for PII fields; keeps taxonomy fields raw.
        def _s(x: str) -> str:
            if self.app.demo_mode and self.app.redaction_service:
                return self.app.redaction_service.scrub_stream(x)
            return x

        for ev in self._page_events:
            event_time = ev.get("event_time", "")
            if hasattr(event_time, "strftime"):
                event_time = event_time.strftime("%Y-%m-%d %H:%M:%S")
            table.add_row(
                str(event_time),
                ev.get("event_name", ""),       # public taxonomy — NOT scrubbed
                self._username_label(ev.get("username", "")),
                _s(ev.get("source_ip", "")),
                _s(ev.get("resource_name", "") or ev.get("resource_type", "")),
                ev.get("region", ""),            # public taxonomy — NOT scrubbed
                ev.get("error_code", "") or "",  # public taxonomy — NOT scrubbed
            )

    def action_next_page(self) -> None:
        if self._current_page < self._total_pages - 1:
            self._current_page += 1
            self._populate_table()
            self._update_pager()
        elif self._next_token and not self._loading_more:
            # Past the end with more in the window: read the next page rather
            # than making the reader wait for the whole window up front.
            self._loading_more = True
            self._update_pager()
            self.run_worker(self._load_more(), name="cloudtrail_more",
                            group="fetch", exclusive=True)

    async def _load_more(self) -> None:
        """Append the next page of events and keep the reader's place."""
        args = dict(self._fetch_args or {})
        token = self._next_token
        if not args or not token:
            self._loading_more = False
            self._update_pager()
            return
        try:
            page = await self.app.cloudtrail_service.lookup_page(
                resume_from=token, **args,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced to the operator
            self._loading_more = False
            self._update_pager()
            self.app.notify(
                f"Could not load more CloudTrail events: {exc}",
                severity="error", markup=False,
            )
            return

        before = len(self._events)
        self._events = self._events + page.events
        self._events.sort(
            key=lambda e: e.get("event_time") or datetime.min, reverse=True,
        )
        self._next_token = page.next_token
        self._cap_reached = False
        self._fleet_names_cache = None
        self._refresh_filter_options()
        self._apply_filters()
        self._loading_more = False
        if self._current_page < self._total_pages - 1:
            self._current_page += 1
        self._populate_table()
        self._update_pager()
        added = len(self._events) - before
        self.app.notify(
            f"Loaded {added} more events ({len(self._events)} total)."
            if added else "No further events in this window."
        )

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
        # _s: scrub PII fields; keep taxonomy (event_name, region, error) raw.
        def _s(x: str) -> str:
            if self.app.demo_mode and self.app.redaction_service:
                return self.app.redaction_service.scrub_stream(x)
            return x

        raw_event = event.get("raw_event", "")
        self.query_one("#event_detail_text", Static).update(
            f"[bold]Event:[/bold] {event.get('event_name', '')}\n"
            f"[bold]Time:[/bold] {event_time}\n"
            f"[bold]User:[/bold] {self._user_detail(event.get('username', ''))}\n"
            f"[bold]Source IP:[/bold] {_s(event.get('source_ip', ''))}\n"
            f"[bold]Resource Type:[/bold] {_s(event.get('resource_type', ''))}\n"
            f"[bold]Resource Name:[/bold] {_s(event.get('resource_name', ''))}\n"
            f"[bold]Region:[/bold] {event.get('region', '')}\n"
            f"[bold]Error:[/bold] {event.get('error_code', '') or '(none)'}\n\n"
            f"[bold]Raw Event:[/bold]\n{_s(raw_event)}"
        )

    # ------------------------------------------------------------------
    # Copy
    # ------------------------------------------------------------------

    def action_copy_output(self) -> None:
        # _s: mirror the scrub helper from _show_event_detail — scrub PII
        # fields when demo_mode is on; pass through otherwise.
        def _s(x: str) -> str:
            if self.app.demo_mode and self.app.redaction_service:
                return self.app.redaction_service.scrub_stream(x)
            return x

        if self._selected_row is not None and self._selected_row < len(self._events):
            event = self._events[self._selected_row]
            event_time = event.get("event_time", "")
            if hasattr(event_time, "strftime"):
                event_time = event_time.strftime("%Y-%m-%d %H:%M:%S")
            lines = [
                f"Event:          {event.get('event_name', '')}",
                f"Time:           {event_time}",
                f"User:           {self._u(event.get('username', ''))}",
                f"Source IP:      {_s(event.get('source_ip', ''))}",
                f"Resource Type:  {_s(event.get('resource_type', ''))}",
                f"Resource Name:  {_s(event.get('resource_name', ''))}",
                f"Region:         {event.get('region', '')}",
                f"Error:          {event.get('error_code', '') or '(none)'}",
            ]
            raw = event.get("raw_event", "")
            if raw:
                lines.append("")
                lines.append("Raw Event:")
                lines.append(_s(str(raw)))
            text = "\n".join(lines)
        else:
            text = "\n".join(
                f"{ev.get('event_name', '')} | {self._u(ev.get('username', ''))} | {_s(ev.get('source_ip', ''))}"
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

    def _user_detail(self, username: str) -> str:
        """Name and id together, where there is room for both."""
        label = self._username_label(username)
        shown = self._u(username)
        return label if label == shown else f"{label} ({shown})"

    def _fleet_names(self) -> Dict[str, str]:
        """Real instance id to real instance name, from the fleet.

        Reads the pre-redaction snapshot when demo mode is on, so the
        lookup key is the real id CloudTrail reports.
        """
        if getattr(self, "_fleet_names_cache", None) is None:
            rows = (
                getattr(self.app, "_instances_pristine", None)
                or getattr(self.app, "instances", None)
                or []
            )
            names: Dict[str, str] = {}
            for row in rows:
                if not isinstance(row, dict):
                    continue
                instance_id = str(row.get("id") or "")
                name = str(row.get("name") or "")
                if instance_id and name:
                    names[instance_id] = name
            self._fleet_names_cache = names
        return self._fleet_names_cache

    def _username_label(self, username: str) -> str:
        """Name the machine behind an instance-role session.

        CloudTrail names those sessions after the instance id, which reads
        as noise in a picker; the fleet already knows what that id is
        called. Anything it cannot resolve keeps its own display rules.
        """
        name = self._fleet_names().get(username or "")
        if not name:
            return self._u(username)
        if self.app.demo_mode and self.app.redaction_service:
            return self.app.redaction_service.redact_name(name)
        return name

    def _u(self, username: str) -> str:
        """Demo-mode username: instance-role sessions carry the instance id
        (same fake as the fleet table); human IAM names get a pool name."""
        if not (self.app.demo_mode and self.app.redaction_service):
            return username
        svc = self.app.redaction_service
        if _EC2_ID_RE.fullmatch(username or ""):
            return svc.redact_instance_id(username)
        return svc.redact_username(username)

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_fetch(self) -> None:
        region_select = self.query_one("#ct_select_region", Select)
        region = region_select.value
        if region is Select.NULL:
            region = ""

        time_select = self.query_one("#ct_select_time_range", Select)
        minutes = int(time_select.value) if time_select.value is not Select.NULL else 1440

        selections = self._filter_values()
        event_name = selections["event_name"]
        username = selections["username"]
        resource_type = selections["resource_type"]

        self.query_one("#ct_btn_fetch", Button).disabled = True
        self.query_one("#event_detail_text", Static).update("Loading...")
        self.query_one("#cloudtrail_table", DataTable).clear()
        self._events = []
        self._visible = []
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
            # Honour the configured cap (0 = everything in the window); a
            # busy account can hold thousands of events per hour.
            config = self.app.config_manager.get()
            max_events = int(getattr(config, "cloudtrail_max_events", 0) or 0)
            self._fetch_args = {
                "region": region,
                "start_time": start_time,
                "end_time": end_time,
                "event_name": event_name,
                "username": username,
                "resource_type": resource_type,
                "max_results": max_events,
            }
            page = await self.app.cloudtrail_service.lookup_page(**self._fetch_args)
            events = page.events
        except Exception as exc:
            self.app.notify(f"CloudTrail fetch failed: {exc}", severity="error")
            self.query_one("#ct_btn_fetch", Button).disabled = False
            return

        self._events = events
        self._next_token = page.next_token
        self._fleet_names_cache = None
        self._cap_reached = bool(max_events) and len(events) >= max_events
        self._refresh_filter_options()
        self._apply_filters()
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
