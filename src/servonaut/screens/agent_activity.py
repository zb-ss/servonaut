"""Read-only Agent Activity audit browser screen for Servonaut.

Displays local MCP, UI chat, relay, and proactive agent tool calls from
``~/.servonaut/mcp_audit.jsonl`` (and rotated ``.1`` … ``.5`` archives)
with filtering by time range, origin, remote scope, command category,
transport (SSH / SSM / SCP), and free-text search.
"""
from __future__ import annotations

import asyncio
import functools
import json
from typing import Any, Dict, List, Mapping, Optional, Tuple

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.timer import Timer
from textual.widgets import DataTable, Footer, Input, Label, Select, Static

from servonaut.mcp.audit_classifier import (
    CMD_BLOCKED,
    CMD_FILE_WRITE,
    CMD_NETWORK_FIREWALL,
    CMD_OTHER_MUTATING,
    CMD_PACKAGE_DEPLOY,
    CMD_READONLY_INSPECT,
    CMD_SERVICE_CONTROL,
    CMD_USER_PRIVILEGE,
    OP_CLOUD_API,
    OP_LOCAL_OR_META,
    OP_REMOTE_DB,
    OP_REMOTE_PROBE,
    OP_REMOTE_TRANSFER,
)
from servonaut.mcp.audit_query import (
    AuditFilter,
    AuditQueryPage,
    AuditQueryService,
    AuditSummary,
    entry_command_summary,
    entry_target_label,
    parse_since,
    parse_timestamp,
)
from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.action_button import ActionButton, ActionRow
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

_PAGE_SIZE = 100
_SEARCH_DEBOUNCE_SECONDS = 0.18

_TIME_OPTIONS: List[Tuple[str, str]] = [
    ("Last 1 hour", "1h"),
    ("Last 6 hours", "6h"),
    ("Last 24 hours", "24h"),
    ("Last 48 hours", "48h"),
    ("Last 7 days", "7d"),
    ("Last 30 days", "30d"),
    ("All time", "all"),
]

_ORIGIN_OPTIONS: List[Tuple[str, str]] = [
    ("All origins", ""),
    ("MCP (external)", "mcp"),
    ("UI (Chat)", "ui"),
    ("Relay", "relay"),
    ("Proactive", "proactive"),
]

_SCOPE_OPTIONS: List[Tuple[str, str]] = [
    ("All calls", "all"),
    ("Remote only", "remote"),
    ("Shell commands", "commands"),
    ("Denied / failed", "denied"),
]

_CATEGORY_OPTIONS: List[Tuple[str, str]] = [
    ("All types", ""),
    ("Inspect (read-only)", CMD_READONLY_INSPECT),
    ("Service control", CMD_SERVICE_CONTROL),
    ("File write", CMD_FILE_WRITE),
    ("Package / deploy", CMD_PACKAGE_DEPLOY),
    ("Network / firewall", CMD_NETWORK_FIREWALL),
    ("User / privilege", CMD_USER_PRIVILEGE),
    ("Other mutating", CMD_OTHER_MUTATING),
    ("Blocked", CMD_BLOCKED),
    ("Remote probe", OP_REMOTE_PROBE),
    ("File transfer (SCP)", OP_REMOTE_TRANSFER),
    ("Remote DB", OP_REMOTE_DB),
    ("Cloud API", OP_CLOUD_API),
    ("Local / meta", OP_LOCAL_OR_META),
]

_TRANSPORT_OPTIONS: List[Tuple[str, str]] = [
    ("All transports", ""),
    ("SSH", "ssh"),
    ("SSM", "ssm"),
    ("SCP", "scp"),
    ("API / local", "none"),
]

_ORIGIN_DISPLAY: Dict[str, str] = {
    "mcp": "MCP",
    "ui": "UI",
    "relay": "Relay",
    "proactive": "Proactive",
}

_CATEGORY_SHORT: Dict[str, str] = {
    CMD_READONLY_INSPECT: "inspect",
    CMD_SERVICE_CONTROL: "service",
    CMD_FILE_WRITE: "write",
    CMD_PACKAGE_DEPLOY: "pkg/deploy",
    CMD_NETWORK_FIREWALL: "net/fw",
    CMD_USER_PRIVILEGE: "priv/user",
    CMD_OTHER_MUTATING: "mutating",
    CMD_BLOCKED: "blocked",
    OP_REMOTE_PROBE: "probe",
    OP_REMOTE_TRANSFER: "scp",
    OP_REMOTE_DB: "db",
    OP_CLOUD_API: "cloud-api",
    OP_LOCAL_OR_META: "local",
}


class AgentActivityScreen(WorkspaceScreen):
    """Read-only browser for MCP, UI chat, relay, and proactive agent activity."""

    CHAT_REFLOW = True
    CHAT_MIN_CONTENT_WIDTH = 80
    CONTENT_NARROW_WIDTH = 125

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("slash", "focus_search", "Search", show=True),
        Binding("c", "clear_filters", "Clear", show=True),
        Binding("y", "copy_detail", "Copy JSON", show=True),
        Binding("n", "next_page", "Next", show=True),
        Binding("p", "prev_page", "Prev", show=True),
    ]

    HORIZONTAL_BREAKPOINTS = [(0, "-narrow"), (150, "-wide")]
    VERTICAL_BREAKPOINTS = [(0, "-short"), (40, "-tall")]

    def __init__(self, *, audit_path: Optional[str] = None) -> None:
        super().__init__()
        self._audit_path_override = audit_path
        self._current_page: int = 0
        self._page_result: Optional[AuditQueryPage] = None
        self._selected_entry: Optional[Dict[str, Any]] = None
        self._suppress_filter_events: bool = False
        self._search_timer: Optional[Timer] = None
        self._query_generation: int = 0

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if self.navigation_focused:
            return super().check_action(action, parameters)
        return check_action_passthrough(self, action)

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield WorkspaceControls("Agent activity")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            with Container(id="agent_activity_container", classes="workspace-content"):
                yield Horizontal(
                    Label("[bold]Agent activity[/bold]", id="aa_title", classes="screen-title"),
                    Static("Loading activity...", id="aa_context", classes="screen-status"),
                    id="aa_heading",
                )
                yield Static("", id="aa_summary_bar")
                yield Container(
                    Vertical(
                        Label("Time range"),
                        Select(
                            _TIME_OPTIONS,
                            value="24h",
                            allow_blank=False,
                            id="aa_select_time",
                        ),
                        id="aa_filter_time",
                    ),
                    Vertical(
                        Label("Origin"),
                        Select(
                            _ORIGIN_OPTIONS,
                            value="",
                            allow_blank=False,
                            id="aa_select_origin",
                        ),
                        id="aa_filter_origin",
                    ),
                    Vertical(
                        Label("Scope"),
                        Select(
                            _SCOPE_OPTIONS,
                            value="all",
                            allow_blank=False,
                            id="aa_select_scope",
                        ),
                        id="aa_filter_scope",
                    ),
                    Vertical(
                        Label("Command / type"),
                        Select(
                            _CATEGORY_OPTIONS,
                            value="",
                            allow_blank=False,
                            id="aa_select_category",
                        ),
                        id="aa_filter_category",
                    ),
                    Vertical(
                        Label("Transport"),
                        Select(
                            _TRANSPORT_OPTIONS,
                            value="",
                            allow_blank=False,
                            id="aa_select_transport",
                        ),
                        id="aa_filter_transport",
                    ),
                    Vertical(
                        Label("Search (host, command, tool, client, reason)"),
                        Input(
                            placeholder="e.g. prod-web, systemctl, ssm, claude-code...",
                            id="aa_search_input",
                        ),
                        id="aa_filter_search",
                    ),
                    ActionRow(
                        ActionButton("Refresh", "r", role="primary", id="aa_btn_refresh"),
                        ActionButton("Clear", "c", id="aa_btn_clear"),
                        ActionButton("Back", "esc", id="aa_btn_back"),
                        id="aa_filter_actions",
                    ),
                    id="aa_filters",
                )
                with Horizontal(id="aa_workspace"):
                    yield Vertical(
                        DataTable(id="aa_table"),
                        Horizontal(
                            ActionButton("Previous", "p", short="Prev", compact=True, id="aa_btn_prev"),
                            Static("", id="aa_page_info"),
                            ActionButton("Next", "n", compact=True, id="aa_btn_next"),
                            id="aa_pager",
                        ),
                        id="aa_results",
                    )
                    yield VerticalScroll(
                        Static(
                            "Select an entry to inspect full execution details.",
                            id="aa_detail_text",
                        ),
                        id="aa_detail",
                    )
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#aa_results").border_title = "Activity log (read-only)"
        self.query_one("#aa_detail").border_title = "Selected call"
        table = self.query_one("#aa_table", DataTable)
        table.add_columns(
            "Time", "Origin", "Status", "Via", "Target", "Type", "Command / Tool",
        )
        table.cursor_type = "row"
        self._schedule_load(reset_page=True)

    # ------------------------------------------------------------------
    # Query execution (non-blocking worker)
    # ------------------------------------------------------------------

    def _audit_path(self) -> str:
        if self._audit_path_override:
            return self._audit_path_override
        cfg_mgr = getattr(self.app, "config_manager", None)
        if cfg_mgr is not None:
            try:
                return cfg_mgr.get().mcp.audit_path
            except Exception:  # noqa: BLE001
                pass
        return "~/.servonaut/mcp_audit.jsonl"

    def _build_filter(self) -> AuditFilter:
        time_val = str(self.query_one("#aa_select_time", Select).value or "24h")
        origin_val = str(self.query_one("#aa_select_origin", Select).value or "")
        scope_val = str(self.query_one("#aa_select_scope", Select).value or "all")
        category_val = str(self.query_one("#aa_select_category", Select).value or "")
        transport_val = str(self.query_one("#aa_select_transport", Select).value or "")
        search_val = self.query_one("#aa_search_input", Input).value.strip()

        since_dt = parse_since(time_val)
        return AuditFilter(
            since=since_dt,
            origin=origin_val,
            scope=scope_val,
            category=category_val,
            transport=transport_val,
            search=search_val,
            denied_only=(scope_val == "denied"),
        )

    def _schedule_load(self, *, reset_page: bool = False) -> None:
        if reset_page:
            self._current_page = 0
        self._query_generation += 1
        generation = self._query_generation
        flt = self._build_filter()
        page = self._current_page
        audit_path = self._audit_path()
        self.run_worker(
            functools.partial(self._load_entries, audit_path, flt, page, generation),
            group="agent_activity_load",
            exclusive=True,
            exit_on_error=False,
        )

    async def _load_entries(
        self,
        audit_path: str,
        flt: AuditFilter,
        page: int,
        generation: int,
    ) -> None:
        service = AuditQueryService(audit_path)
        result = await asyncio.to_thread(
            service.query, flt, page=page, page_size=_PAGE_SIZE,
        )
        if generation != self._query_generation or not self.is_mounted:
            return
        self._page_result = result
        self._render_page(result)

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def scrub_text(self, text: str) -> str:
        """Redact sensitive text when demo mode is active."""
        if not text:
            return text
        if getattr(self.app, "demo_mode", False):
            redactor = getattr(self.app, "redaction_service", None)
            if redactor is not None:
                return redactor.redact_text(text)
        return text

    def refresh_after_demo_toggle(self) -> None:
        """Redraw already-loaded audit rows and inspector after toggling demo mode."""
        if self._page_result is None or not self.is_mounted:
            return
        selected = self._selected_entry
        self._render_page(self._page_result)
        if selected is not None:
            self._selected_entry = selected
            self._render_detail(selected)

    def _render_page(self, result: AuditQueryPage) -> None:
        summary = result.summary
        self._render_header_and_summary(summary)

        table = self.query_one("#aa_table", DataTable)
        table.clear()

        for idx, entry in enumerate(result.entries):
            table.add_row(
                self._fmt_time(entry),
                self._fmt_origin_cell(entry),
                self._fmt_status_cell(entry),
                self._fmt_transport_cell(entry),
                escape(self.scrub_text(self._fmt_short_target(entry))),
                self._fmt_category_cell(entry),
                escape(self.scrub_text(self._fmt_command_col(entry))),
                key=str(idx),
            )

        self._update_pager(result)

        if result.entries:
            self._selected_entry = result.entries[0]
            self._render_detail(result.entries[0])
        else:
            self._selected_entry = None
            empty_msg = (
                "No audit entries match the current filters."
                if AuditQueryService(self._audit_path()).log_files()
                else "No MCP / agent activity has been recorded yet."
            )
            self.query_one("#aa_detail_text", Static).update(self.scrub_text(empty_msg))

    def _render_header_and_summary(self, summary: AuditSummary) -> None:
        ssh_n = summary.by_transport.get("ssh", 0)
        ssm_n = summary.by_transport.get("ssm", 0)
        scp_n = summary.by_transport.get("scp", 0)
        context_parts = [
            f"{summary.total} calls",
            f"{summary.remote_exec} remote",
        ]
        if ssh_n or ssm_n or scp_n:
            t_parts = []
            if ssh_n:
                t_parts.append(f"SSH {ssh_n}")
            if ssm_n:
                t_parts.append(f"SSM {ssm_n}")
            if scp_n:
                t_parts.append(f"SCP {scp_n}")
            context_parts.append(" / ".join(t_parts))
        if summary.denied:
            context_parts.append(f"{summary.denied} denied/err")
        context_parts.append(f"{summary.elapsed_ms:.1f}ms")
        self.query_one("#aa_context", Static).update(" · ".join(context_parts))

        origin_bits = []
        for key in ("mcp", "ui", "relay", "proactive"):
            count = summary.by_origin.get(key, 0)
            if count:
                origin_bits.append(f"{_ORIGIN_DISPLAY[key]}: {count}")
        origin_text = " · ".join(origin_bits) if origin_bits else "none"

        cat_items = sorted(summary.by_category.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
        cat_bits = [f"{_CATEGORY_SHORT.get(k, k)}: {v}" for k, v in cat_items]
        cat_text = " · ".join(cat_bits) if cat_bits else "none"

        bar_text = f"[bold]Origins: [/bold]{escape(origin_text)}   |   [bold]Types: [/bold]{escape(cat_text)}"
        self.query_one("#aa_summary_bar", Static).update(bar_text)

    def _update_pager(self, result: AuditQueryPage) -> None:
        total_pages = result.total_pages
        page_label = (
            f"Page {result.page + 1} of {total_pages} ({result.total_matches} matches)"
            if total_pages > 0
            else "0 matches"
        )
        self.query_one("#aa_page_info", Static).update(page_label)
        self.query_one("#aa_btn_prev", ActionButton).disabled = result.page <= 0
        self.query_one("#aa_btn_next", ActionButton).disabled = (
            total_pages == 0 or result.page >= total_pages - 1
        )

    @staticmethod
    def _fmt_time(entry: Mapping[str, Any]) -> str:
        ts = parse_timestamp(entry.get("timestamp"))
        if ts is None:
            return str(entry.get("timestamp") or "-")[:11]
        return ts.strftime("%m-%d %H:%M")

    @staticmethod
    def _fmt_short_target(entry: Mapping[str, Any], *, max_len: int = 16) -> str:
        target = entry.get("target")
        label = ""
        if isinstance(target, Mapping):
            label = str(target.get("name") or target.get("id") or target.get("host") or "").strip()
        if not label:
            label = entry_target_label(entry)
        if len(label) > max_len:
            return label[: max_len - 1] + "…"
        return label

    @staticmethod
    def _fmt_command_col(entry: Mapping[str, Any], *, max_len: int = 44) -> str:
        tool = str(entry.get("tool") or "-")
        summary = entry_command_summary(entry, max_len=max_len)
        if tool == "run_command" and summary != "-":
            return summary
        if summary == "-":
            return tool
        combined = f"{tool}: {summary}"
        if len(combined) > max_len:
            return combined[: max_len - 1] + "…"
        return combined

    @staticmethod
    def _fmt_origin_cell(entry: Mapping[str, Any]) -> Text:
        origin = str(entry.get("origin") or "mcp").lower()
        label = _ORIGIN_DISPLAY.get(origin, origin)
        style_map = {
            "mcp": "bold cyan",
            "ui": "bold green",
            "relay": "bold magenta",
            "proactive": "bold yellow",
        }
        return Text(label, style=style_map.get(origin, ""))

    @staticmethod
    def _fmt_status_cell(entry: Mapping[str, Any]) -> Text:
        allowed = bool(entry.get("allowed", True))
        rc = entry.get("exit_code")
        if not allowed:
            return Text("DENY", style="bold red")
        if isinstance(rc, int) and rc != 0:
            return Text(f"rc={rc}", style="bold yellow")
        return Text("OK", style="green")

    @staticmethod
    def _fmt_transport_cell(entry: Mapping[str, Any]) -> Text:
        via = str(entry.get("transport_used") or "-")
        if entry.get("ssh_fell_back"):
            return Text("ssm*", style="bold yellow")
        if via == "ssm":
            return Text("ssm", style="cyan")
        if via == "ssh":
            return Text("ssh", style="green")
        if via == "scp":
            return Text("scp", style="magenta")
        return Text(via, style="dim")

    @staticmethod
    def _fmt_category_cell(entry: Mapping[str, Any]) -> Text:
        cat = str(entry.get("command_category") or entry.get("op_class") or "-")
        short = _CATEGORY_SHORT.get(cat, cat)
        if cat == CMD_BLOCKED:
            return Text(short, style="bold red")
        if cat in (CMD_FILE_WRITE, CMD_USER_PRIVILEGE, CMD_NETWORK_FIREWALL, CMD_SERVICE_CONTROL):
            return Text(short, style="yellow")
        if cat == CMD_READONLY_INSPECT:
            return Text(short, style="green")
        return Text(short, style="dim")

    @staticmethod
    def _fmt_duration(entry: Mapping[str, Any]) -> str:
        dur = entry.get("duration_ms")
        if not isinstance(dur, (int, float)):
            return "-"
        if dur >= 1000:
            return f"{dur / 1000.0:.1f}s"
        return f"{int(dur)}ms"

    def _render_detail(self, entry: Mapping[str, Any]) -> None:
        lines: List[str] = []

        def _row(label: str, value: Any) -> None:
            if value is None or value == "":
                return
            lines.append(f"[bold]{escape(label)}: [/bold]{escape(self.scrub_text(str(value)))}")

        _row("Timestamp", entry.get("timestamp"))
        origin = str(entry.get("origin") or "mcp")
        origin_text = _ORIGIN_DISPLAY.get(origin, origin)
        if entry.get("source") and entry.get("source") != origin:
            origin_text += f" (source={entry['source']})"
        _row("Origin", origin_text)
        _row("Client", entry.get("client"))
        _row("Session ID", entry.get("session_id"))
        _row("Conversation", entry.get("conversation_id"))
        _row("Tool", entry.get("tool"))

        allowed = bool(entry.get("allowed", True))
        status_str = "Allowed (OK)" if allowed else "Denied / Failed"
        if isinstance(entry.get("exit_code"), int):
            status_str += f"  [exit_code={entry['exit_code']}]"
        _row("Status", status_str)
        _row("Reason", entry.get("reason"))
        if isinstance(entry.get("duration_ms"), (int, float)):
            _row("Duration", f"{int(entry['duration_ms'])} ms")
        _row("Result length", f"{entry.get('result_length', 0)} chars")

        via = entry.get("transport_used")
        if via:
            via_str = str(via)
            if entry.get("ssh_fell_back"):
                via_str += " (SSH unreachable -> fell back to SSM)"
            _row("Transport", via_str)
        _row("SSM Command ID", entry.get("ssm_command_id"))
        _row("Key source", entry.get("key_source"))

        target = entry.get("target")
        if isinstance(target, Mapping) and target:
            t_bits = [
                f"{k}={v}"
                for k, v in target.items()
                if v
            ]
            _row("Target", ", ".join(t_bits))
        else:
            lbl = entry_target_label(entry)
            if lbl != "-":
                _row("Target", lbl)

        cat = entry.get("command_category") or entry.get("op_class")
        if cat:
            cat_str = str(cat)
            if entry.get("used_sudo"):
                cat_str += " (sudo)"
            _row("Command type", cat_str)
        stems = entry.get("command_stems")
        if isinstance(stems, list) and stems:
            _row("Command stems", ", ".join(str(s) for s in stems))

        args = entry.get("args")
        if isinstance(args, Mapping) and args.get("command"):
            lines.append("")
            lines.append("[bold]Command:[/bold]")
            lines.append(escape(self.scrub_text(str(args["command"]))))

        lines.append("")
        lines.append("[bold]Raw JSON:[/bold]")
        raw_json = json.dumps(entry, indent=2, default=str)
        lines.append(escape(self.scrub_text(raw_json)))

        self.query_one("#aa_detail_text", Static).update("\n".join(lines))

    # ------------------------------------------------------------------
    # Events & Actions
    # ------------------------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        if self._suppress_filter_events:
            return
        if event.select.id in {
            "aa_select_time",
            "aa_select_origin",
            "aa_select_scope",
            "aa_select_category",
            "aa_select_transport",
        }:
            self._schedule_load(reset_page=True)

    def on_input_changed(self, event: Input.Changed) -> None:
        if self._suppress_filter_events or event.input.id != "aa_search_input":
            return
        if self._search_timer is not None:
            self._search_timer.stop()
        self._search_timer = self.set_timer(
            _SEARCH_DEBOUNCE_SECONDS,
            lambda: self._schedule_load(reset_page=True),
        )

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "aa_search_input":
            if self._search_timer is not None:
                self._search_timer.stop()
                self._search_timer = None
            self._schedule_load(reset_page=True)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._select_row_index(event.cursor_row)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self._select_row_index(event.cursor_row)

    def _select_row_index(self, row_idx: int) -> None:
        if self._page_result is None:
            return
        entries = self._page_result.entries
        if 0 <= row_idx < len(entries):
            self._selected_entry = entries[row_idx]
            self._render_detail(entries[row_idx])

    def on_button_pressed(self, event: ActionButton.Pressed) -> None:
        bid = event.button.id
        if bid == "aa_btn_refresh":
            self.action_refresh()
        elif bid == "aa_btn_clear":
            self.action_clear_filters()
        elif bid == "aa_btn_back":
            self.action_back()
        elif bid == "aa_btn_prev":
            self.action_prev_page()
        elif bid == "aa_btn_next":
            self.action_next_page()

    def action_refresh(self) -> None:
        self._schedule_load(reset_page=False)

    def action_focus_search(self) -> None:
        self.query_one("#aa_search_input", Input).focus()

    def action_clear_filters(self) -> None:
        self._suppress_filter_events = True
        try:
            self.query_one("#aa_select_time", Select).value = "24h"
            self.query_one("#aa_select_origin", Select).value = ""
            self.query_one("#aa_select_scope", Select).value = "all"
            self.query_one("#aa_select_category", Select).value = ""
            self.query_one("#aa_select_transport", Select).value = ""
            self.query_one("#aa_search_input", Input).value = ""
        finally:
            self._suppress_filter_events = False
        self._schedule_load(reset_page=True)

    def action_next_page(self) -> None:
        if self._page_result is None:
            return
        if self._current_page + 1 < self._page_result.total_pages:
            self._current_page += 1
            self._schedule_load(reset_page=False)

    def action_prev_page(self) -> None:
        if self._current_page > 0:
            self._current_page -= 1
            self._schedule_load(reset_page=False)

    def action_copy_detail(self) -> None:
        if self._selected_entry is None:
            self.notify("No entry selected.", severity="warning")
            return
        raw = self.scrub_text(json.dumps(self._selected_entry, indent=2, default=str))
        copy_fn = getattr(self.app, "copy_to_clipboard", None)
        if callable(copy_fn):
            copy_fn(raw)
        self.notify("Copied audit entry JSON to clipboard.", severity="information")

    def action_back(self) -> None:
        from servonaut.screens.instance_list import InstanceListScreen

        if len(self.app.screen_stack) > 1:
            self.app.pop_screen()
        else:
            self.app.switch_screen(InstanceListScreen())
