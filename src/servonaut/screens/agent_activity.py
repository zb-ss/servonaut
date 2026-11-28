"""Read-only Agent Activity audit browser screen for Servonaut.

Displays local MCP, UI chat, relay, proactive, and CLI tool calls from
``~/.servonaut/mcp_audit.jsonl`` (and rotated ``.1`` … ``.5`` archives)
with filtering by time range, origin, remote scope, command category,
transport (SSH / SSM / SCP), and free-text search.
"""
from __future__ import annotations

import asyncio
import functools
import json
from typing import Any, Dict, List, Mapping, Optional, Tuple

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.content import Content
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
    CMD_UNKNOWN,
    CMD_USER_PRIVILEGE,
    OP_CLOUD_API,
    OP_LOCAL_OR_META,
    OP_REMOTE_DB,
    OP_REMOTE_PROBE,
    OP_REMOTE_TRANSFER,
    is_entry_failed_or_denied,
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
from servonaut.utils.markup import cell, literal
from servonaut.widgets.action_button import ActionButton, ActionRow
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

_PAGE_SIZE = 100
_SELECT_DEBOUNCE_SECONDS = 0.06
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
    ("UI (chat)", "ui"),
    ("Relay", "relay"),
    ("Proactive", "proactive"),
    ("CLI", "cli"),
    ("Unknown", "unknown"),
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
    ("Unknown / dynamic", CMD_UNKNOWN),
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
    "cli": "CLI",
    "unknown": "Unknown",
}

_CATEGORY_SHORT: Dict[str, str] = {
    CMD_READONLY_INSPECT: "inspect",
    CMD_SERVICE_CONTROL: "service",
    CMD_FILE_WRITE: "write",
    CMD_PACKAGE_DEPLOY: "pkg/deploy",
    CMD_NETWORK_FIREWALL: "net/fw",
    CMD_USER_PRIVILEGE: "priv/user",
    CMD_OTHER_MUTATING: "mutating",
    CMD_UNKNOWN: "unknown",
    CMD_BLOCKED: "blocked",
    OP_REMOTE_PROBE: "probe",
    OP_REMOTE_TRANSFER: "scp",
    OP_REMOTE_DB: "db",
    OP_CLOUD_API: "cloud-api",
    OP_LOCAL_OR_META: "local",
}


class AgentActivityScreen(WorkspaceScreen):
    """Read-only browser for MCP, UI chat, relay, proactive, and CLI agent activity."""

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

    HORIZONTAL_BREAKPOINTS = [(0, "-narrow"), (90, "-wide")]
    VERTICAL_BREAKPOINTS = [(0, "-short"), (40, "-tall")]

    def __init__(self, *, audit_path: Optional[str] = None) -> None:
        super().__init__()
        self._audit_path_override = audit_path
        self._current_page: int = 0
        self._page_result: Optional[AuditQueryPage] = None
        self._selected_entry: Optional[Dict[str, Any]] = None
        # Suppress initial Select.Changed notifications fired during mount so
        # only a single initial scan runs.
        self._suppress_filter_events: bool = True
        self._filter_timer: Optional[Timer] = None
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
                        Label("Search"),
                        Input(
                            placeholder="Host, command, tool, client, or reason...",
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
            "Time", "Origin", "Status", "Via", "Target", "Type", "Command / tool",
        )
        table.cursor_type = "row"
        # Let mount-time Select.Changed events drain before enabling live filter triggers.
        self.call_after_refresh(self._finish_mount_init)
        self._schedule_load(reset_page=True)

    def _finish_mount_init(self) -> None:
        self._suppress_filter_events = False

    # ------------------------------------------------------------------
    # Query execution (non-blocking worker with mid-scan cancellation)
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

    def _debounce_load(self, delay: float) -> None:
        if self._filter_timer is not None:
            self._filter_timer.stop()
        self._filter_timer = self.set_timer(
            delay,
            lambda: self._schedule_load(reset_page=True),
        )

    def _schedule_load(self, *, reset_page: bool = False) -> None:
        if self._filter_timer is not None:
            self._filter_timer.stop()
            self._filter_timer = None
        if reset_page:
            self._current_page = 0
        self._query_generation += 1
        generation = self._query_generation
        flt = self._build_filter()
        page = self._current_page
        audit_path = self._audit_path()

        self._set_loading_state(True)
        self.run_worker(
            functools.partial(self._load_entries, audit_path, flt, page, generation),
            group="agent_activity_load",
            exclusive=True,
            exit_on_error=False,
        )

    def _set_loading_state(self, loading: bool) -> None:
        if not self.is_mounted:
            return
        if loading:
            self.query_one("#aa_context", Static).update("Loading activity...")
        try:
            self.query_one("#aa_table", DataTable).loading = loading
        except Exception:  # noqa: BLE001
            pass

    async def _load_entries(
        self,
        audit_path: str,
        flt: AuditFilter,
        page: int,
        generation: int,
    ) -> None:
        service = AuditQueryService(audit_path)
        try:
            result = await asyncio.to_thread(
                service.query,
                flt,
                page=page,
                page_size=_PAGE_SIZE,
                cancel_check=lambda: generation != self._query_generation,
            )
        finally:
            if generation == self._query_generation and self.is_mounted:
                try:
                    self.query_one("#aa_table", DataTable).loading = False
                except Exception:  # noqa: BLE001
                    pass

        if generation != self._query_generation or result.summary.cancelled or not self.is_mounted:
            return
        self._page_result = result
        self._render_page(result)

    # ------------------------------------------------------------------
    # Demo-mode redaction & theme helpers
    # ------------------------------------------------------------------

    def _redactor(self):
        if getattr(self.app, "demo_mode", False):
            return getattr(self.app, "redaction_service", None)
        return None

    def scrub_text(self, text: str) -> str:
        """Redact free text (IPs, hostnames, EC2 IDs, ARNs, emails, paths) in demo mode."""
        if not text:
            return text
        redactor = self._redactor()
        if redactor is None:
            return text
        scrub_stream = getattr(redactor, "scrub_stream", None)
        if callable(scrub_stream):
            return scrub_stream(text)
        return redactor.redact_text(text)

    def scrub_target(self, target: Mapping[str, Any]) -> Dict[str, Any]:
        """Redact structured target metadata fields in demo mode."""
        redactor = self._redactor()
        if redactor is None:
            return dict(target)
        out: Dict[str, Any] = {}
        for k, v in target.items():
            if not v:
                continue
            s = str(v)
            if k == "name" and hasattr(redactor, "redact_name"):
                out[k] = redactor.redact_name(s)
            elif k == "id" and hasattr(redactor, "redact_instance_id"):
                out[k] = redactor.redact_instance_id(s)
            elif k == "host":
                if hasattr(redactor, "redact_host"):
                    out[k] = redactor.redact_host(s)
                elif hasattr(redactor, "redact_hostname"):
                    out[k] = redactor.redact_hostname(s)
                else:
                    out[k] = self.scrub_text(s)
            elif k == "account" and hasattr(redactor, "redact_account_label"):
                out[k] = redactor.redact_account_label(s)
            else:
                out[k] = self.scrub_text(s)
        return out

    def _scrub_entry_for_display(self, entry: Mapping[str, Any]) -> Dict[str, Any]:
        """Return a deep-scrubbed copy of *entry* suitable for JSON inspector & copy."""
        redactor = self._redactor()
        if redactor is None:
            return dict(entry)

        def _scrub_value(val: Any, key: str = "") -> Any:
            if isinstance(val, Mapping):
                if key == "target":
                    return self.scrub_target(val)
                return {k: _scrub_value(v, str(k)) for k, v in val.items()}
            if isinstance(val, list):
                return [_scrub_value(item) for item in val]
            if isinstance(val, str):
                if key in ("instance_id", "identifier") and hasattr(redactor, "redact_instance_id"):
                    return redactor.redact_instance_id(val)
                if key == "host" and hasattr(redactor, "redact_host"):
                    return redactor.redact_host(val)
                if key == "account" and hasattr(redactor, "redact_account_label"):
                    return redactor.redact_account_label(val)
                return self.scrub_text(val)
            return val

        return _scrub_value(entry)

    def _theme_color(self, token: str, *, bold: bool = False) -> str:
        """Resolve a Textual theme variable to a Rich style string."""
        variables = getattr(self.app, "theme_variables", None) or {}
        color = variables.get(token) or ""
        if bold and color:
            return f"bold {color}"
        if bold:
            return "bold"
        return color

    def refresh_after_demo_toggle(self) -> None:
        """Redraw already-loaded audit rows and inspector after toggling demo mode."""
        if self._page_result is None or not self.is_mounted:
            return
        selected = self._selected_entry
        self._render_page(self._page_result)
        if selected is not None:
            self._selected_entry = selected
            self._render_detail(selected)

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render_page(self, result: AuditQueryPage) -> None:
        summary = result.summary
        self._render_header_and_summary(summary)

        table = self.query_one("#aa_table", DataTable)
        table.clear()

        for idx, entry in enumerate(result.entries):
            table.add_row(
                cell(self._fmt_time(entry)),
                self._fmt_origin_cell(entry),
                self._fmt_status_cell(entry),
                self._fmt_transport_cell(entry),
                cell(self.scrub_text(self._fmt_short_target(entry))),
                self._fmt_category_cell(entry),
                cell(self.scrub_text(self._fmt_command_col(entry))),
                key=str(idx),
            )

        self._update_pager(result)

        if result.entries:
            self._selected_entry = result.entries[0]
            self._render_detail(result.entries[0])
        else:
            self._selected_entry = None
            if summary.read_errors:
                empty_msg = "Audit log warning:\n" + "\n".join(summary.read_errors)
            elif AuditQueryService(self._audit_path()).log_files():
                empty_msg = "No audit entries match the current filters."
            else:
                empty_msg = "No MCP / agent activity has been recorded yet."
            self.query_one("#aa_detail_text", Static).update(literal(self.scrub_text(empty_msg)))

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
        if summary.read_errors:
            context_parts.append(f"{len(summary.read_errors)} log warning(s)")
        context_parts.append(f"{summary.elapsed_ms:.1f}ms")
        self.query_one("#aa_context", Static).update(literal(" · ".join(context_parts)))

        origin_bits = []
        for key in ("mcp", "ui", "relay", "proactive", "cli", "unknown"):
            count = summary.by_origin.get(key, 0)
            if count:
                origin_bits.append(f"{_ORIGIN_DISPLAY[key]}: {count}")
        origin_text = " · ".join(origin_bits) if origin_bits else "none"

        cat_items = sorted(summary.by_category.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
        cat_bits = [f"{_CATEGORY_SHORT.get(k, k)}: {v}" for k, v in cat_items]
        cat_text = " · ".join(cat_bits) if cat_bits else "none"

        self.query_one("#aa_summary_bar", Static).update(
            Content.assemble(
                literal("Origins: ", "bold"),
                literal(origin_text),
                literal("   |   "),
                literal("Types: ", "bold"),
                literal(cat_text),
            )
        )

    def _update_pager(self, result: AuditQueryPage) -> None:
        total_pages = result.total_pages
        page_label = (
            f"Page {result.page + 1} of {total_pages} ({result.total_matches} matches)"
            if total_pages > 0
            else "0 matches"
        )
        self.query_one("#aa_page_info", Static).update(literal(page_label))
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

    def _fmt_short_target(self, entry: Mapping[str, Any], *, max_len: int = 16) -> str:
        target = entry.get("target")
        label = ""
        if isinstance(target, Mapping):
            scrubbed = self.scrub_target(target)
            label = str(scrubbed.get("name") or scrubbed.get("id") or scrubbed.get("host") or "").strip()
        if not label:
            raw_lbl = entry_target_label(entry)
            redactor = self._redactor()
            if redactor is not None and raw_lbl != "-" and hasattr(redactor, "redact_instance_id"):
                label = redactor.redact_instance_id(raw_lbl)
            else:
                label = raw_lbl
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

    def _fmt_origin_cell(self, entry: Mapping[str, Any]) -> Text:
        origin = str(entry.get("origin") or "unknown").lower()
        label = _ORIGIN_DISPLAY.get(origin, origin)
        token_map = {
            "mcp": ("text-accent", True),
            "ui": ("text-success", True),
            "relay": ("primary", True),
            "proactive": ("text-warning", True),
            "cli": ("text-secondary", False),
            "unknown": ("text-muted", False),
        }
        token, bold = token_map.get(origin, ("text-muted", False))
        return cell(label, style=self._theme_color(token, bold=bold))

    def _fmt_status_cell(self, entry: Mapping[str, Any]) -> Text:
        allowed = bool(entry.get("allowed", True))
        tool_allowed = entry.get("tool_allowed")
        status_field = str(entry.get("status") or "").lower()
        rc = entry.get("exit_code")
        if not allowed or status_field == "denied":
            return cell("DENY", style=self._theme_color("text-error", bold=True))
        if tool_allowed is False or status_field in ("error", "timeout"):
            return cell("ERR", style=self._theme_color("text-error", bold=True))
        if isinstance(rc, int) and rc != 0:
            return cell(f"rc={rc}", style=self._theme_color("text-warning", bold=True))
        return cell("OK", style=self._theme_color("text-success"))

    def _fmt_transport_cell(self, entry: Mapping[str, Any]) -> Text:
        via = str(entry.get("transport_used") or "-")
        if entry.get("ssh_fell_back"):
            return cell("ssm*", style=self._theme_color("text-warning", bold=True))
        if via == "ssm":
            return cell("ssm", style=self._theme_color("text-accent"))
        if via == "ssh":
            return cell("ssh", style=self._theme_color("text-success"))
        if via == "scp":
            return cell("scp", style=self._theme_color("primary"))
        return cell(via, style=self._theme_color("text-muted"))

    def _fmt_category_cell(self, entry: Mapping[str, Any]) -> Text:
        cat = str(entry.get("command_category") or entry.get("op_class") or "-")
        short = _CATEGORY_SHORT.get(cat, cat)
        if cat == CMD_BLOCKED:
            return cell(short, style=self._theme_color("text-error", bold=True))
        if cat in (CMD_FILE_WRITE, CMD_USER_PRIVILEGE, CMD_NETWORK_FIREWALL, CMD_SERVICE_CONTROL, CMD_UNKNOWN):
            return cell(short, style=self._theme_color("text-warning"))
        if cat == CMD_READONLY_INSPECT:
            return cell(short, style=self._theme_color("text-success"))
        return cell(short, style=self._theme_color("text-muted"))

    def _render_detail(self, entry: Mapping[str, Any]) -> None:
        parts: List[Any] = []

        def _row(label: str, value: Any, *, scrub_val: bool = True) -> None:
            if value is None or value == "":
                return
            text = self.scrub_text(str(value)) if scrub_val else str(value)
            parts.append(Content.assemble(literal(f"{label}: ", "bold"), literal(text), "\n"))

        _row("Timestamp", entry.get("timestamp"), scrub_val=False)
        origin = str(entry.get("origin") or "unknown")
        origin_text = _ORIGIN_DISPLAY.get(origin, origin)
        if entry.get("source") and entry.get("source") != origin:
            origin_text += f" (source={entry['source']})"
        _row("Origin", origin_text, scrub_val=False)
        _row("Client", entry.get("client"))
        _row("Session ID", entry.get("session_id"))
        _row("Conversation", entry.get("conversation_id"))
        _row("Tool", entry.get("tool"), scrub_val=False)

        failed = is_entry_failed_or_denied(entry)
        status_str = "Denied / failed" if failed else "Allowed (OK)"
        if isinstance(entry.get("exit_code"), int):
            status_str += f"  [exit_code={entry['exit_code']}]"
        _row("Status", status_str, scrub_val=False)
        _row("Reason", entry.get("reason"))
        if entry.get("tool_reason") and entry.get("tool_reason") != entry.get("reason"):
            _row("Tool reason", entry.get("tool_reason"))
        if isinstance(entry.get("duration_ms"), (int, float)):
            _row("Duration", f"{int(entry['duration_ms'])} ms", scrub_val=False)
        _row("Result length", f"{entry.get('result_length', 0)} chars", scrub_val=False)

        via = entry.get("transport_used")
        if via:
            via_str = str(via)
            if entry.get("ssh_fell_back"):
                via_str += " (SSH unreachable -> fell back to SSM)"
            _row("Transport", via_str, scrub_val=False)
        _row("SSM command ID", entry.get("ssm_command_id"))
        _row("Key source", entry.get("key_source"), scrub_val=False)

        target = entry.get("target")
        if isinstance(target, Mapping) and target:
            scrubbed_target = self.scrub_target(target)
            t_bits = [f"{k}={v}" for k, v in scrubbed_target.items() if v]
            _row("Target", ", ".join(t_bits), scrub_val=False)
        else:
            lbl = entry_target_label(entry)
            if lbl != "-":
                redactor = self._redactor()
                if redactor is not None and hasattr(redactor, "redact_instance_id"):
                    lbl = redactor.redact_instance_id(lbl)
                _row("Target", lbl)

        cat = entry.get("command_category") or entry.get("op_class")
        if cat:
            cat_str = str(cat)
            if entry.get("used_sudo"):
                cat_str += " (sudo)"
            _row("Command type", cat_str, scrub_val=False)
        stems = entry.get("command_stems")
        if isinstance(stems, list) and stems:
            _row("Command stems", ", ".join(str(s) for s in stems), scrub_val=False)

        args = entry.get("args")
        if isinstance(args, Mapping) and args.get("command"):
            parts.append(Content.assemble(
                "\n",
                literal("Command:\n", "bold"),
                literal(self.scrub_text(str(args["command"]))),
                "\n",
            ))

        scrubbed_entry = self._scrub_entry_for_display(entry)
        raw_json = json.dumps(scrubbed_entry, indent=2, default=str)
        parts.append(Content.assemble(
            "\n",
            literal("Raw JSON:\n", "bold"),
            literal(raw_json),
        ))

        self.query_one("#aa_detail_text", Static).update(Content.assemble(*parts))

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
            self._debounce_load(_SELECT_DEBOUNCE_SECONDS)

    def on_input_changed(self, event: Input.Changed) -> None:
        if self._suppress_filter_events or event.input.id != "aa_search_input":
            return
        self._debounce_load(_SEARCH_DEBOUNCE_SECONDS)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "aa_search_input":
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
        scrubbed = self._scrub_entry_for_display(self._selected_entry)
        raw = json.dumps(scrubbed, indent=2, default=str)
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
