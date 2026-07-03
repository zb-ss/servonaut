"""Findings inbox + detail — thin renderer for proactive monitoring.

Two screens:

- :class:`FindingsScreen` — the findings inbox. Fleet-wide when opened
  from the sidebar, instance-scoped when opened from
  :class:`ServerActionsScreen` (pass the instance dict). Lists finding
  cards from the gated API, cycles status/severity filters, and
  triggers manual scans with live SSE progress.
- :class:`FindingDetailScreen` — one finding: description, evidence,
  and remediation options (DISPLAY-ONLY — the CLI never executes a
  remediation; execution is a future server-driven capability), plus
  the triage actions (acknowledge / resolve / suppress).

Pinned invariants:

- The CLI renders cards and calls the API. It never computes, detects,
  or analyses anything — all of that is server-side and must stay out
  of this public repository.
- Findings are server-controlled data: every string is passed through
  ``rich.markup.escape`` before interpolation into Rich markup, and
  ``notify(..., markup=False)`` is used whenever a server string or
  exception is embedded.
- The free tier gets the upgrade card (mirrors the secrets screen),
  driven by the ``proactive_monitoring`` entitlement flag locally and
  by the server's 402 authoritatively.
"""
from __future__ import annotations

import asyncio
import logging
import webbrowser
from typing import Any, Dict, List, Optional

from rich.markup import escape
from textual.binding import Binding
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.services.findings_service import (
    FINDING_SEVERITIES,
    FINDING_STATUSES,
    DEFAULT_PAGE_SIZE,
)
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)

# App-level pointers (not per-render strings) — one-line patch if the
# pricing/docs pages ever move. The server's 402 payload carries its own
# upgrade_url/doc_url which take precedence when present.
_UPGRADE_URL = "https://servonaut.dev/pricing"
_DOCS_URL = "https://servonaut.dev/docs/proactive-monitoring"

# Severity → Rich-markup pill (worst first for summary ordering).
_SEVERITY_CELL: Dict[str, str] = {
    "critical": "[bold red]critical[/bold red]",
    "high": "[red]high[/red]",
    "medium": "[yellow]medium[/yellow]",
    "low": "[cyan]low[/cyan]",
    "info": "[dim]info[/dim]",
}

_STATUS_CELL: Dict[str, str] = {
    "detected": "[yellow]detected[/yellow]",
    "acked": "[cyan]acked[/cyan]",
    "remediating": "[magenta]remediating[/magenta]",
    "resolved": "[green]resolved[/green]",
    "suppressed": "[dim]suppressed[/dim]",
}

# Severity order for the summary line, worst first.
_SEVERITY_ORDER = tuple(reversed(FINDING_SEVERITIES))


def redact_demo_text(app, value: str) -> str:
    """Demo-mode scrub for server-authored strings (titles, evidence).

    Findings content describes the user's servers and can carry
    hostnames / IPs — run it through the demo redaction pipeline before
    it reaches the screen when demo mode is on.
    """
    rs = getattr(app, "redaction_service", None)
    if getattr(app, "demo_mode", False) and rs is not None:
        try:
            return rs.scrub_stream(value)
        except Exception:  # noqa: BLE001 — redaction is best-effort
            return value
    return value


def redact_demo_instance(app, value: str) -> str:
    """Demo-mode redaction for instance identifiers."""
    rs = getattr(app, "redaction_service", None)
    if getattr(app, "demo_mode", False) and rs is not None:
        try:
            return rs.redact_instance_id(value)
        except Exception:  # noqa: BLE001 — redaction is best-effort
            return value
    return value


def _severity_markup(severity: str) -> str:
    return _SEVERITY_CELL.get(severity, escape(severity or "unknown"))


def _status_markup(status: str) -> str:
    return _STATUS_CELL.get(status, escape(status or "unknown"))


class FindingsScreen(Screen):
    """Findings inbox — fleet-wide, or scoped to one instance."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("s", "scan_now", "Scan Now", show=True),
        Binding("enter", "open_selected", "Open", show=True),
        Binding("f", "cycle_status", "Status Filter", show=True),
        Binding("v", "cycle_severity", "Severity Filter", show=True),
        Binding("n", "next_page", "Next Page", show=False),
        Binding("p", "prev_page", "Prev Page", show=False),
        Binding("u", "open_upgrade", "Upgrade", show=False),
        Binding("o", "open_docs", "Docs", show=False),
        Binding("l", "open_login", "Sign in", show=False),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def __init__(self, instance: Optional[dict] = None) -> None:
        """``instance``: scope the inbox to one server (from
        ServerActionsScreen); ``None`` renders the fleet-wide inbox."""
        super().__init__()
        self._instance = instance
        self._rows: List[Dict[str, Any]] = []
        self._total = 0
        self._offset = 0
        # None = no filter; cycled via ``f`` / ``v``.
        self._status_filter: Optional[str] = None
        self._severity_filter: Optional[str] = None
        self._scanning = False
        # Server-supplied upgrade URL from a 402 (takes precedence over
        # the static pricing pointer when present).
        self._upgrade_url_override: Optional[str] = None

    # ------------------------------------------------------------------
    # Compose / mount
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        scope = ""
        if self._instance is not None:
            name = self._display_name(self._instance)
            scope = f" — [dim]{escape(name)}[/dim]"
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static(f"🛡 [bold]Findings[/bold]{scope}", id="findings_title"),
                Static(
                    "Proactive monitoring findings from server-side scans. "
                    "The CLI renders and triages — detection runs in the "
                    "Servonaut cloud over your connected relay.",
                    id="findings_subtitle",
                ),
                Static("", id="findings_status_pill"),
                Static("", id="findings_filter_line"),
                # Live scan progress — hidden while idle.
                Static("", id="findings_progress", classes="hidden"),
                # State cards (sign-in / upgrade / error) swap in here;
                # hidden while the table is active.
                VerticalScroll(id="findings_state_body", classes="hidden"),
                Container(
                    DataTable(id="findings_table"),
                    id="findings_table_card",
                ),
                Horizontal(
                    Button("s. Scan Now", id="btn_findings_scan", variant="primary"),
                    Button("r. Refresh", id="btn_findings_refresh"),
                    Button("enter. Open", id="btn_findings_open"),
                    Button("f. Status Filter", id="btn_findings_status_filter"),
                    Button("v. Severity Filter", id="btn_findings_severity_filter"),
                    id="findings_actions",
                ),
                id="findings_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings_table", DataTable)
        table.cursor_type = "row"
        table.add_column("Severity", key="severity", width=10)
        table.add_column("Status", key="status", width=12)
        if self._instance is None:
            table.add_column("Instance", key="instance", width=22)
        table.add_column("Detector", key="detector", width=18)
        table.add_column("Title", key="title")
        table.add_column("Detected", key="detected", width=20)
        self._render_gate()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _display_name(instance: dict) -> str:
        return str(
            instance.get("name") or instance.get("id") or "unknown"
        )

    @property
    def _instance_id(self) -> Optional[str]:
        if self._instance is None:
            return None
        return str(self._instance.get("id") or self._instance.get("name") or "")

    def _instance_label(self, instance_id: str) -> str:
        """Best-effort name for an instance id from the shared list."""
        for inst in getattr(self.app, "instances", None) or []:
            if inst.get("id") == instance_id:
                name = inst.get("name")
                if name:
                    return f"{name}"
        return instance_id

    def _card(
        self,
        title: str,
        *children,
        primary: bool = False,
        warning: bool = False,
    ) -> Container:
        classes = "findings_card"
        if primary:
            classes += " findings_card_primary"
        elif warning:
            classes += " findings_card_warning"
        return Container(
            Static(title, classes="findings_card_title"),
            Vertical(*children, classes="findings_card_body"),
            classes=classes,
        )

    def _actions_list(self, *items: tuple[str, str]) -> Vertical:
        return Vertical(
            *[
                Horizontal(
                    Static(key, classes="findings_action_key"),
                    Static(label, classes="findings_action_label"),
                    classes="findings_action_row",
                )
                for key, label in items
            ],
            classes="findings_actions_list",
        )

    def _show_state_body(self, show: bool) -> None:
        """Toggle between the state-card body and the findings table."""
        state = self.query_one("#findings_state_body", VerticalScroll)
        table_card = self.query_one("#findings_table_card", Container)
        actions = self.query_one("#findings_actions", Horizontal)
        state.set_class(not show, "hidden")
        table_card.display = not show
        actions.display = not show
        if show:
            state.remove_children()

    # ------------------------------------------------------------------
    # Gate + state cards
    # ------------------------------------------------------------------

    def _render_gate(self) -> None:
        """Decide which state to render, then load if entitled.

        Local entitlement knowledge is the fast path; the server's 402
        stays authoritative (a stale cache that says "entitled" just
        means one API call that lands on the upgrade card anyway).
        """
        pill = self.query_one("#findings_status_pill", Static)
        auth = getattr(self.app, "auth_service", None)
        svc = getattr(self.app, "findings_service", None)

        if auth is None or not getattr(auth, "is_authenticated", False):
            self._render_unauthenticated(pill)
            return
        if not auth.has_feature("proactive_monitoring"):
            self._render_upgrade(pill, reason=None)
            return
        if svc is None:
            pill.update("[bold red]✕ Unavailable[/bold red]")
            self._show_state_body(True)
            self.query_one("#findings_state_body", VerticalScroll).mount(
                self._card(
                    "Unavailable",
                    Static(
                        "Findings need the API client (httpx). Install "
                        "with: pip install 'servonaut[pro]' and sign in.",
                    ),
                    warning=True,
                ),
            )
            return
        self._show_state_body(False)
        self.action_refresh()

    def _render_unauthenticated(self, pill: Static) -> None:
        pill.update("[bold yellow]⚪ Not signed in[/bold yellow]")
        self._show_state_body(True)
        body = self.query_one("#findings_state_body", VerticalScroll)
        body.mount(self._card(
            "Sign in required",
            Static(
                "Sign in to your Servonaut account to see proactive "
                "monitoring findings for your fleet.",
            ),
            primary=True,
        ))
        body.mount(self._card(
            "Actions",
            self._actions_list(
                ("l", "Open Login"),
                ("o", "Open docs"),
            ),
        ))

    def _render_upgrade(self, pill: Static, reason: Optional[str]) -> None:
        """Free-tier empty state — mirrors the secrets upgrade card."""
        pill.update("[bold yellow]⚠ Upgrade required[/bold yellow]")
        self._show_state_body(True)
        body = self.query_one("#findings_state_body", VerticalScroll)
        children = [
            Static(
                "Proactive monitoring is available on the Solo and "
                "Teams plans.",
            ),
            Static(
                "  • Server-side detectors scan your fleet over your "
                "connected relay.",
            ),
            Static(
                "  • Findings arrive as triageable cards with suggested "
                "remediations.",
            ),
        ]
        if reason:
            children.append(Static(
                f"[dim]{escape(reason)}[/dim]",
                classes="findings_card_note",
            ))
        body.mount(self._card("Upgrade required", *children, primary=True))
        body.mount(self._card(
            "Actions",
            self._actions_list(
                ("u", "Open Pricing"),
                ("o", "Open docs"),
            ),
        ))

    def _handle_payment_required(self, exc: Any) -> None:
        """Server said 402 — authoritative upgrade card."""
        self._upgrade_url_override = getattr(exc, "upgrade_url", "") or None
        pill = self.query_one("#findings_status_pill", Static)
        self._render_upgrade(pill, reason=str(exc))

    # ------------------------------------------------------------------
    # Load / populate
    # ------------------------------------------------------------------

    def action_refresh(self) -> None:
        self.run_worker(
            self._load_worker(),
            name="findings_load",
            group="findings_load",
            exclusive=True,
        )

    async def _load_worker(self) -> None:
        from servonaut.services.api_client import APIError, PaymentRequiredError

        svc = getattr(self.app, "findings_service", None)
        if svc is None:
            return
        pill = self.query_one("#findings_status_pill", Static)
        pill.update("[dim]Loading findings…[/dim]")
        try:
            payload = await svc.list_findings(
                instance=self._instance_id,
                status=self._status_filter,
                severity=self._severity_filter,
                limit=DEFAULT_PAGE_SIZE,
                offset=self._offset,
            )
        except PaymentRequiredError as exc:
            self._handle_payment_required(exc)
            return
        except APIError as exc:
            pill.update("[bold red]✕ Load failed[/bold red]")
            self.app.notify(
                f"Could not load findings: {exc}",
                severity="error", markup=False,
            )
            return
        except Exception as exc:  # noqa: BLE001 — network layer surprises
            logger.exception("Findings load failed: %s", exc)
            pill.update("[bold red]✕ Load failed[/bold red]")
            self.app.notify(
                f"Could not load findings: {exc}",
                severity="error", markup=False,
            )
            return

        self._show_state_body(False)
        self._rows = list(payload.get("findings") or [])
        try:
            self._total = int(payload.get("total") or len(self._rows))
        except (TypeError, ValueError):
            self._total = len(self._rows)
        self._populate_table()

    def _populate_table(self) -> None:
        table = self.query_one("#findings_table", DataTable)
        table.clear()
        for finding in self._rows:
            severity = str(finding.get("severity") or "")
            status = str(finding.get("status") or "")
            detector = escape(str(finding.get("detector") or ""))
            title = escape(redact_demo_text(
                self.app, str(finding.get("title") or "(untitled)"),
            ))
            detected = escape(str(finding.get("detected_at") or ""))
            row = [_severity_markup(severity), _status_markup(status)]
            if self._instance is None:
                instance_id = str(finding.get("instance_id") or "")
                label = redact_demo_instance(
                    self.app, self._instance_label(instance_id),
                )
                row.append(escape(label))
            row.extend([detector, title, detected])
            table.add_row(*row)
        self._update_pill()
        self._update_filter_line()

    def _update_pill(self) -> None:
        pill = self.query_one("#findings_status_pill", Static)
        if not self._rows:
            pill.update("[green]● No findings — all clear[/green]")
            return
        counts: Dict[str, int] = {}
        for finding in self._rows:
            sev = str(finding.get("severity") or "unknown")
            counts[sev] = counts.get(sev, 0) + 1
        parts = [
            f"{_severity_markup(sev)} {counts[sev]}"
            for sev in _SEVERITY_ORDER if sev in counts
        ]
        for sev in counts:
            if sev not in FINDING_SEVERITIES:
                parts.append(f"{escape(sev)} {counts[sev]}")
        pill.update("  ".join(parts) + f"  [dim]· {self._total} total[/dim]")

    def _update_filter_line(self) -> None:
        line = self.query_one("#findings_filter_line", Static)
        status = self._status_filter or "all"
        severity = self._severity_filter or "all"
        shown = len(self._rows)
        start = self._offset + 1 if shown else 0
        end = self._offset + shown
        line.update(
            f"[dim]status: [b]{escape(status)}[/b] · severity: "
            f"[b]{escape(severity)}[/b] · showing {start}–{end} of "
            f"{self._total} ([b]f[/b]/[b]v[/b] filter, [b]n[/b]/[b]p[/b] page)[/dim]"
        )

    # ------------------------------------------------------------------
    # Filters + paging
    # ------------------------------------------------------------------

    def action_cycle_status(self) -> None:
        cycle: List[Optional[str]] = [None, *FINDING_STATUSES]
        idx = cycle.index(self._status_filter)
        self._status_filter = cycle[(idx + 1) % len(cycle)]
        self._offset = 0
        self.action_refresh()

    def action_cycle_severity(self) -> None:
        cycle: List[Optional[str]] = [None, *reversed(FINDING_SEVERITIES)]
        idx = cycle.index(self._severity_filter)
        self._severity_filter = cycle[(idx + 1) % len(cycle)]
        self._offset = 0
        self.action_refresh()

    def action_next_page(self) -> None:
        if self._offset + DEFAULT_PAGE_SIZE < self._total:
            self._offset += DEFAULT_PAGE_SIZE
            self.action_refresh()

    def action_prev_page(self) -> None:
        if self._offset > 0:
            self._offset = max(0, self._offset - DEFAULT_PAGE_SIZE)
            self.action_refresh()

    # ------------------------------------------------------------------
    # Scan now (+ SSE progress)
    # ------------------------------------------------------------------

    def action_scan_now(self) -> None:
        if self._scanning:
            self.app.notify("A scan is already running.", severity="warning")
            return
        self.run_worker(
            self._scan_worker(),
            name="findings_scan",
            group="findings_scan",
            exclusive=True,
        )

    def _set_progress(self, markup: Optional[str]) -> None:
        progress = self.query_one("#findings_progress", Static)
        if markup is None:
            progress.update("")
            progress.add_class("hidden")
        else:
            progress.update(markup)
            progress.remove_class("hidden")

    async def _scan_worker(self) -> None:
        from servonaut.services.api_client import APIError, PaymentRequiredError

        svc = getattr(self.app, "findings_service", None)
        if svc is None:
            return
        self._scanning = True
        self._set_progress("[cyan]Scan requested…[/cyan]")
        # Best-effort live progress: open the SSE stream alongside the
        # blocking POST. The POST result is authoritative; the stream
        # only feeds the progress line and is cancelled when it lands.
        stream_task = asyncio.create_task(self._consume_scan_stream())
        try:
            result = await svc.scan(instance_id=self._instance_id)
        except PaymentRequiredError as exc:
            # On the scan path a 402 can also mean "monitoring budget
            # exhausted" — notify rather than replacing a working list
            # with the upgrade card.
            self.app.notify(str(exc), severity="warning", markup=False)
            return
        except APIError as exc:
            if exc.code == "cli_not_connected":
                self.app.notify(
                    exc.message
                    or "Connect your CLI (servonaut connect) to enable "
                       "monitoring.",
                    severity="warning", markup=False,
                )
            else:
                self.app.notify(
                    f"Scan failed: {exc}",
                    severity="error", markup=False,
                )
            return
        except Exception as exc:  # noqa: BLE001
            logger.exception("Findings scan failed: %s", exc)
            self.app.notify(
                f"Scan failed: {exc}", severity="error", markup=False,
            )
            return
        finally:
            stream_task.cancel()
            self._scanning = False
            self._set_progress(None)

        findings = list(result.get("findings") or [])
        skipped = list(result.get("skipped") or [])
        summary = f"Scan complete — {len(findings)} finding(s)"
        if skipped:
            summary += f", {len(skipped)} detector(s) skipped"
        self.app.notify(summary, severity="information", markup=False)
        self._offset = 0
        self.action_refresh()

    async def _consume_scan_stream(self) -> None:
        """Feed the progress line from the scan SSE stream (best-effort)."""
        from servonaut.services.ai_sse import SSEStreamDead, SSEStreamError

        svc = getattr(self.app, "findings_service", None)
        if svc is None:
            return
        detected = 0
        try:
            async for event in svc.stream_scan(instance=self._instance_id):
                name = event.get("event")
                data = event.get("data") or {}
                if name == "scan.started":
                    self._set_progress("[cyan]Scan started…[/cyan]")
                elif name == "probe.started":
                    detector = escape(str(data.get("detector") or ""))
                    self._set_progress(f"[cyan]Probing:[/cyan] {detector}…")
                elif name == "finding.detected":
                    detected += 1
                    self._set_progress(
                        f"[yellow]{detected} finding(s) so far…[/yellow]"
                    )
                elif name == "scan.completed":
                    count = data.get("findings_count", detected)
                    self._set_progress(
                        f"[green]Scan completed — {count} finding(s).[/green]"
                    )
                    return
        except (SSEStreamError, SSEStreamDead) as exc:
            # cli_not_connected etc. also surfaces on the POST — the
            # stream is progress-only, so degrade quietly.
            logger.debug("Scan progress stream ended: %s", exc)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — progress is optional
            logger.debug("Scan progress stream failed: %s", exc)

    # ------------------------------------------------------------------
    # Navigation / actions
    # ------------------------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        event.stop()
        self.action_open_selected()

    def action_open_selected(self) -> None:
        table = self.query_one("#findings_table", DataTable)
        row = table.cursor_row
        if row is None or not (0 <= row < len(self._rows)):
            return
        finding = self._rows[row]
        self.app.push_screen(
            FindingDetailScreen(finding),
            self._on_detail_closed,
        )

    def _on_detail_closed(self, changed: Optional[bool]) -> None:
        if changed:
            self.action_refresh()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn_findings_scan":
            self.action_scan_now()
        elif button_id == "btn_findings_refresh":
            self.action_refresh()
        elif button_id == "btn_findings_open":
            self.action_open_selected()
        elif button_id == "btn_findings_status_filter":
            self.action_cycle_status()
        elif button_id == "btn_findings_severity_filter":
            self.action_cycle_severity()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_open_upgrade(self) -> None:
        # The override comes from the server's 402 payload — only trust
        # it into webbrowser.open when it is a plain https URL.
        url = self._upgrade_url_override or _UPGRADE_URL
        if not url.startswith("https://"):
            url = _UPGRADE_URL
        webbrowser.open(url)
        self.notify(f"Opened {url}", markup=False)

    def action_open_docs(self) -> None:
        webbrowser.open(_DOCS_URL)
        self.notify(f"Opened {_DOCS_URL}", markup=False)

    def action_open_login(self) -> None:
        from servonaut.screens.login import LoginScreen
        self.app.switch_screen(LoginScreen())


class FindingDetailScreen(Screen[bool]):
    """One finding, full detail + triage.

    Dismisses with ``True`` when a triage action changed the finding so
    the inbox can refresh. Remediation options are DISPLAY-ONLY: the
    CLI never executes a remediation — there is no execution endpoint,
    and rendering must never grow one client-side.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("a", "ack", "Acknowledge", show=True),
        Binding("r", "resolve", "Resolve", show=True),
        Binding("x", "suppress", "Suppress", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def __init__(self, finding: Dict[str, Any]) -> None:
        super().__init__()
        # Raw server dict — additive-only wire contract, .get() access.
        self._finding = dict(finding)
        self._changed = False

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static("", id="finding_detail_title"),
                Static("", id="finding_detail_pill"),
                VerticalScroll(id="finding_detail_body"),
                Horizontal(
                    Button("a. Acknowledge", id="btn_finding_ack", variant="primary"),
                    Button("r. Resolve", id="btn_finding_resolve", variant="success"),
                    Button("x. Suppress", id="btn_finding_suppress"),
                    Button("esc. Back", id="btn_finding_back"),
                    id="finding_detail_actions",
                ),
                id="finding_detail_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        self._render_finding()

    def _card(self, title: str, *children, warning: bool = False) -> Container:
        classes = "findings_card"
        if warning:
            classes += " findings_card_warning"
        return Container(
            Static(title, classes="findings_card_title"),
            Vertical(*children, classes="findings_card_body"),
            classes=classes,
        )

    def _render_finding(self) -> None:
        f = self._finding
        title = self.query_one("#finding_detail_title", Static)
        pill = self.query_one("#finding_detail_pill", Static)
        body = self.query_one("#finding_detail_body", VerticalScroll)
        body.remove_children()

        safe_title = escape(redact_demo_text(
            self.app, str(f.get("title") or "(untitled)"),
        ))
        title.update(f"🛡 [bold]{safe_title}[/bold]")
        severity = str(f.get("severity") or "")
        status = str(f.get("status") or "")
        scope = "team" if f.get("team_scoped") else "personal"
        pill.update(
            f"{_severity_markup(severity)} · {_status_markup(status)} · "
            f"[dim]{scope}[/dim]"
        )

        rows = [
            ("Instance", escape(redact_demo_instance(
                self.app, str(f.get("instance_id") or "—"),
            ))),
            ("Detector", escape(str(f.get("detector") or "—"))),
            ("Rule", escape(str(f.get("rule") or "—"))),
            ("Detected", escape(str(f.get("detected_at") or "—"))),
            ("Last seen", escape(str(f.get("last_seen_at") or "—"))),
            ("Finding id", f"[dim]{escape(str(f.get('id') or '—'))}[/dim]"),
        ]
        body.mount(self._card(
            "Details",
            Vertical(
                *[
                    Horizontal(
                        Static(label, classes="findings_kv_label"),
                        Static(value, classes="findings_kv_value"),
                        classes="findings_kv_row",
                    )
                    for label, value in rows
                ],
                classes="findings_kv_grid",
            ),
        ))

        description = str(f.get("description") or "")
        if description:
            body.mount(self._card(
                "Description",
                Static(escape(redact_demo_text(self.app, description))),
            ))

        evidence = f.get("evidence") or []
        if isinstance(evidence, list) and evidence:
            body.mount(self._card(
                "Evidence",
                *[
                    Static(
                        "[dim]"
                        + escape(redact_demo_text(self.app, str(item)))
                        + "[/dim]",
                        classes="finding_evidence_line",
                    )
                    for item in evidence
                ],
            ))

        remediations = f.get("remediations") or []
        if isinstance(remediations, list) and remediations:
            children = []
            for rem in remediations:
                if not isinstance(rem, dict):
                    continue
                label = escape(str(rem.get("label") or "(unnamed)"))
                desc = escape(str(rem.get("description") or ""))
                action = escape(str(rem.get("action") or ""))
                risk = escape(str(rem.get("risk_tier") or "unknown"))
                reversible = "reversible" if rem.get("reversible") else "not reversible"
                children.append(Static(
                    f"[bold]{label}[/bold]  "
                    f"[dim]({risk} risk · {reversible})[/dim]",
                    classes="finding_remediation_label",
                ))
                if desc:
                    children.append(Static(
                        f"  {desc}", classes="finding_remediation_desc",
                    ))
                if action:
                    children.append(Static(
                        f"  [dim]{action}[/dim]",
                        classes="finding_remediation_action",
                    ))
            children.append(Static(
                "[dim]Suggested remediations are shown for reference "
                "only — the CLI does not execute them.[/dim]",
                classes="findings_card_note",
            ))
            body.mount(self._card("Suggested remediations", *children))

    # ------------------------------------------------------------------
    # Triage
    # ------------------------------------------------------------------

    def action_ack(self) -> None:
        self._launch_triage("ack")

    def action_resolve(self) -> None:
        self._launch_triage("resolve")

    def action_suppress(self) -> None:
        self._launch_triage("suppress")

    def _launch_triage(self, action: str) -> None:
        self.run_worker(
            self._triage_worker(action),
            name=f"finding_triage_{action}",
            group="findings_triage",
            exclusive=True,
        )

    async def _triage_worker(self, action: str) -> None:
        from servonaut.services.api_client import APIError, NotFoundError

        svc = getattr(self.app, "findings_service", None)
        if svc is None:
            self.app.notify(
                "Triage unavailable — sign in first.", severity="warning",
            )
            return
        finding_id = str(self._finding.get("id") or "")
        try:
            if action == "ack":
                result = await svc.acknowledge(finding_id)
            elif action == "resolve":
                result = await svc.resolve(finding_id)
            else:
                result = await svc.suppress(finding_id)
        except NotFoundError:
            self.app.notify("Finding not found.", severity="warning")
            return
        except (APIError, ValueError) as exc:
            self.app.notify(
                f"Triage failed: {exc}", severity="error", markup=False,
            )
            return
        new_status = str(result.get("status") or "")
        if new_status:
            self._finding["status"] = new_status
        self._changed = True
        self.app.notify(
            f"Finding marked {new_status or action}.",
            severity="information", markup=False,
        )
        self._render_finding()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn_finding_ack":
            self.action_ack()
        elif button_id == "btn_finding_resolve":
            self.action_resolve()
        elif button_id == "btn_finding_suppress":
            self.action_suppress()
        elif button_id == "btn_finding_back":
            self.action_back()

    def action_back(self) -> None:
        self.dismiss(self._changed)
