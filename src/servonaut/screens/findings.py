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


def evidence_lines(evidence: Any) -> List[str]:
    """Flatten a finding's evidence payload into display lines.

    The wire contract says bounded strings, but live findings also ship
    dict-shaped evidence (``{key: [lines] | scalar}``) — render both,
    plus a bare scalar, rather than silently dropping the card.
    """
    if isinstance(evidence, list):
        return [str(item) for item in evidence]
    if isinstance(evidence, dict):
        lines: List[str] = []
        for key, value in evidence.items():
            if isinstance(value, list):
                lines.append(f"{key}:")
                lines.extend(f"  {item}" for item in value)
            else:
                lines.append(f"{key}: {value}")
        return lines
    if evidence:
        return [str(evidence)]
    return []


def _recon_note(recon: Any) -> str:
    """Human note for the additive scan ``recon`` block.

    When the server used the box's memory profile to select detectors,
    say so — a thin result then explains itself ("stack-aware" beats
    "why did it only run two detectors?").
    """
    if not isinstance(recon, dict) or not recon.get("profile_used"):
        return ""
    note = " · stack-aware scan"
    skipped = recon.get("skipped_by_recon")
    if isinstance(skipped, list) and skipped:
        note += f" ({len(skipped)} detector(s) not applicable to this stack)"
    return note


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

    # Actions that only make sense when the findings table is active —
    # hidden from the footer (and inert) on the sign-in / upgrade /
    # unavailable cards so the UI never advertises a dead key.
    _DATA_ACTIONS = frozenset({
        "scan_now", "cycle_status", "cycle_severity", "open_selected",
        "next_page", "prev_page",
    })

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action in self._DATA_ACTIONS and self._gate_state != "active":
            return False
        if action == "open_upgrade" and self._gate_state != "upgrade":
            return False
        if action == "open_login" and self._gate_state != "unauth":
            return False
        return check_action_passthrough(self, action)

    def __init__(self, instance: Optional[dict] = None) -> None:
        """``instance``: scope the inbox to one server (from
        ServerActionsScreen); ``None`` renders the fleet-wide inbox."""
        super().__init__()
        # Which state the gate resolved to: loading | unauth | upgrade |
        # unavailable | active. Drives check_action's binding gating.
        self._gate_state = "loading"
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
            self._set_gate_state("unauth")
            self._render_unauthenticated(pill)
            return
        if not auth.has_feature("proactive_monitoring"):
            self._set_gate_state("upgrade")
            self._render_upgrade(pill, reason=None)
            return
        if svc is None:
            self._set_gate_state("unavailable")
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
        self._set_gate_state("active")
        self._show_state_body(False)
        self.action_refresh()

    def _set_gate_state(self, state: str) -> None:
        """Record the gate state and re-evaluate footer bindings."""
        self._gate_state = state
        self.refresh_bindings()

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
        self._set_gate_state("upgrade")
        pill = self.query_one("#findings_status_pill", Static)
        self._render_upgrade(pill, reason=str(exc))

    # ------------------------------------------------------------------
    # Load / populate
    # ------------------------------------------------------------------

    def action_refresh(self) -> None:
        if self._gate_state != "active":
            # From a card state, refresh re-evaluates the whole gate —
            # sign-in or a plan upgrade takes effect without leaving
            # and re-entering the screen.
            self._render_gate()
            return
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
        from servonaut.services.ai_sse import SSEStreamDead, SSEStreamError

        svc = getattr(self.app, "findings_service", None)
        if svc is None:
            return
        self._scanning = True
        self._set_progress("[cyan]Scan requested…[/cyan]")
        # CONTRACT: GET /scan/stream is the SSE VARIANT of the scan —
        # opening it STARTS a scan and streams that scan's own progress.
        # It is NOT a passive observer, so scan-now uses the stream XOR
        # the buffered POST — never both (two calls would launch two
        # scans, take two concurrency slots, and spend budget twice).
        try:
            try:
                await self._scan_via_stream(svc)
            except RuntimeError:
                # SSE machinery unavailable (httpx-sse not installed) —
                # run the buffered POST variant instead.
                await self._scan_via_post(svc)
        except PaymentRequiredError as exc:
            # 402 on the scan path can also mean "monitoring budget
            # exhausted" — notify rather than replacing a working list
            # with the upgrade card.
            self.app.notify(str(exc), severity="warning", markup=False)
        except (SSEStreamError, APIError) as exc:
            code = getattr(exc, "code", "")
            message = getattr(exc, "message", "") or str(exc)
            if code == "cli_not_connected":
                self.app.notify(
                    message
                    or "Connect your CLI (servonaut connect) to enable "
                       "monitoring.",
                    severity="warning", markup=False,
                )
            else:
                self.app.notify(
                    f"Scan failed: {message}",
                    severity="error", markup=False,
                )
        except SSEStreamDead:
            self.app.notify(
                "Scan stream went silent — the scan may still be running "
                "server-side. Refresh in a minute to see its findings.",
                severity="warning",
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Findings scan failed: %s", exc)
            self.app.notify(
                f"Scan failed: {exc}", severity="error", markup=False,
            )
        finally:
            self._scanning = False
            self._set_progress(None)

    async def _scan_via_stream(self, svc) -> None:
        """Run the scan through its SSE variant, narrating live progress."""
        detected = 0
        probes_failed = 0
        completed = False
        async for event in svc.stream_scan(instance=self._instance_id):
            name = event.get("event")
            data = event.get("data") or {}
            if name == "scan.started":
                self._set_progress("[cyan]Scan started…[/cyan]")
            elif name == "probe.started":
                detector = escape(str(data.get("detector") or ""))
                self._set_progress(f"[cyan]Probing:[/cyan] {detector}…")
            elif name == "probe.completed":
                if data.get("ok") is False:
                    probes_failed += 1
            elif name == "finding.detected":
                detected += 1
                self._set_progress(
                    f"[yellow]{detected} finding(s) so far…[/yellow]"
                )
            elif name == "scan.completed":
                completed = True
                count = data.get("findings_count", detected)
                summary = f"Scan complete — {count} finding(s)"
                if probes_failed:
                    summary += f", {probes_failed} probe(s) returned no data"
                summary += _recon_note(data.get("recon"))
                if data.get("partial"):
                    summary += " (partial — some detectors did not finish)"
                self.app.notify(summary, severity="information", markup=False)
                break
        if not completed:
            # Graceful close without a terminal event — the findings
            # list is the source of truth either way.
            self.app.notify(
                "Scan stream ended without a completion event — "
                "refreshing the list.",
                severity="warning",
            )
        self._offset = 0
        self.action_refresh()

    async def _scan_via_post(self, svc) -> None:
        """Buffered POST variant — fallback when SSE is unavailable."""
        result = await svc.scan(instance_id=self._instance_id)
        findings = list(result.get("findings") or [])
        skipped = list(result.get("skipped") or [])
        summary = f"Scan complete — {len(findings)} finding(s)"
        if skipped:
            # Surface WHY detectors were skipped (e.g. "no db configured",
            # dockerized workload) — a bare count reads as "all clear"
            # when coverage was actually thin.
            reasons = "; ".join(
                f"{s.get('detector', '?')}: {s.get('reason', '?')}"
                for s in skipped[:4] if isinstance(s, dict)
            )
            if len(skipped) > 4:
                reasons += f"; +{len(skipped) - 4} more"
            summary += f". Skipped {len(skipped)} detector(s) — {reasons}"
        summary += _recon_note(result.get("recon"))
        self.app.notify(summary, severity="information", markup=False)
        self._offset = 0
        self.action_refresh()

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
    """One finding, full detail + triage + guarded remediation.

    Dismisses with ``True`` when a triage or remediation changed the
    finding so the inbox can refresh. Remediation execution is strictly
    two-step and server-signed: the CLI fetches a preview (the exact
    structured command plus a confirm token signed over it), renders it
    byte-for-byte, and only POSTs the execute call after the user types
    the confirmation phrase. The CLI never composes or chooses a
    command client-side.
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
        # button_id -> remediation dict, rebuilt on every render.
        self._remediation_buttons: Dict[str, Dict[str, Any]] = {}
        # True while a mutating remediation execute worker is in flight —
        # blocks a second launch from cancelling it (shared worker group).
        self._remediating = False

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
        # Rebuilt below alongside the DOM buttons — clear here so a
        # re-render with no remediations can't leave a stale mapping.
        self._remediation_buttons = {}

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

        lines = evidence_lines(f.get("evidence"))
        if lines:
            body.mount(self._card(
                "Evidence",
                *[
                    Static(
                        "[dim]"
                        + escape(redact_demo_text(self.app, line))
                        + "[/dim]",
                        classes="finding_evidence_line",
                    )
                    for line in lines
                ],
            ))

        remediations = f.get("remediations") or []
        if isinstance(remediations, list) and remediations:
            can_remediate = (
                str(f.get("status") or "") in ("detected", "acked")
                and getattr(self.app, "findings_service", None) is not None
            )
            children = []
            any_runnable = False
            for index, rem in enumerate(remediations):
                if not isinstance(rem, dict):
                    continue
                label = escape(str(rem.get("label") or "(unnamed)"))
                desc = escape(str(rem.get("description") or ""))
                action = str(rem.get("action") or "")
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
                        f"  [dim]{escape(action)}[/dim]",
                        classes="finding_remediation_action",
                    ))
                # "investigate" is advisory prose — there is nothing to
                # execute. Every other playbook action gets a Run button
                # that starts the server-signed preview → confirm flow;
                # the server enforces the risk-tier allowlist on its end.
                if can_remediate and action and action != "investigate":
                    button_id = f"btn_finding_remediate_{index}"
                    self._remediation_buttons[button_id] = dict(rem)
                    # Button labels are Rich-markup parsed — escape the
                    # server-authored label (slice first so escape can't
                    # be split mid-tag).
                    run_label = escape(str(rem.get("label") or action)[:40])
                    children.append(Button(
                        f"Run: {run_label}…",
                        id=button_id,
                        classes="finding_remediation_run",
                        variant="warning",
                    ))
                    any_runnable = True
            if any_runnable:
                note = (
                    "[dim]Run… fetches a server-signed preview of the exact "
                    "command. Nothing executes until you confirm it.[/dim]"
                )
            else:
                note = (
                    "[dim]Suggested remediations are shown for reference — "
                    "run them manually or via a supported Run action.[/dim]"
                )
            children.append(Static(note, classes="findings_card_note"))
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
        elif button_id in self._remediation_buttons:
            self._launch_remediation(
                self._remediation_buttons[button_id], dry_run=False,
            )

    # ------------------------------------------------------------------
    # Remediation (Phase 3): preview → typed confirm → execute
    # ------------------------------------------------------------------

    def _launch_remediation(
        self, remediation: Dict[str, Any], *, dry_run: bool,
    ) -> None:
        # A mutating execute worker shares this group and would be
        # cancelled by a new exclusive launch — refuse while one is live.
        if self._remediating:
            self.app.notify(
                "A remediation is already running — wait for it to finish.",
                severity="warning",
            )
            return
        self.run_worker(
            self._remediation_preview_worker(remediation, dry_run),
            name="finding_remediation_preview",
            group="findings_remediation",
            exclusive=True,
        )

    async def _remediation_preview_worker(
        self, remediation: Dict[str, Any], dry_run: bool,
    ) -> None:
        from servonaut.services.api_client import (
            APIError, NotFoundError, PaymentRequiredError,
        )

        svc = getattr(self.app, "findings_service", None)
        if svc is None:
            self.app.notify(
                "Remediation unavailable — sign in first.", severity="warning",
            )
            return
        finding_id = str(self._finding.get("id") or "")
        action = str(remediation.get("action") or "")
        try:
            preview = await svc.remediate_preview(
                finding_id, action, dry_run=dry_run,
            )
        except NotFoundError:
            self.app.notify(
                "Remediation execution isn't available on the server yet.",
                severity="warning",
            )
            return
        except PaymentRequiredError as exc:
            self.app.notify(
                f"Remediation requires an upgraded plan: {exc}",
                severity="warning", markup=False,
            )
            return
        except (APIError, ValueError) as exc:
            self.app.notify(
                f"Preview failed: {exc}", severity="error", markup=False,
            )
            return

        from servonaut.screens.remediation_confirm import (
            RemediationConfirmModal,
        )

        def _on_decision(decision: Optional[str]) -> None:
            if decision == "confirm":
                token = str(preview.get("confirm_token") or "")
                self.run_worker(
                    self._remediation_execute_worker(
                        finding_id, action, token, dry_run=dry_run,
                    ),
                    name="finding_remediation_execute",
                    group="findings_remediation",
                    exclusive=True,
                )
            elif decision == "dry_run":
                self._launch_remediation(remediation, dry_run=True)

        self.app.push_screen(
            RemediationConfirmModal(preview, dry_run=dry_run),
            _on_decision,
        )

    async def _remediation_execute_worker(
        self, finding_id: str, action: str, confirm_token: str,
        *, dry_run: bool,
    ) -> None:
        from servonaut.services.api_client import APIError, NotFoundError

        svc = getattr(self.app, "findings_service", None)
        if svc is None or not confirm_token:
            self.app.notify(
                "Remediation preview expired — re-open the preview.",
                severity="warning",
            )
            return
        self.app.notify(
            ("Running the dry-run test on the server…" if dry_run else
             "Executing remediation… the server dispatches it to your "
             "connected CLI and re-checks the finding."),
            severity="information",
        )
        # Guard the whole mutating round-trip: a concurrent launch in the
        # shared worker group must not cancel it (ISSUE-2).
        self._remediating = True
        try:
            result = await svc.remediate(
                finding_id, action, confirm_token, dry_run=dry_run,
            )
        except NotFoundError:
            self.app.notify("Finding not found.", severity="warning")
            return
        except APIError as exc:
            # A relay/infra failure (502 remediation_dispatch_error) is
            # transient — the server restores the finding's prior status
            # and it's safe to retry — so message it distinctly from a
            # command failure (which comes back 200 with ok=false).
            if getattr(exc, "code", "") == "remediation_dispatch_error" or (
                getattr(exc, "is_retryable", False)
            ):
                self.app.notify(
                    f"Remediation couldn't be dispatched (transient): {exc}. "
                    "The finding is unchanged — try again.",
                    severity="warning", markup=False,
                )
            else:
                self.app.notify(
                    f"Remediation failed: {exc}",
                    severity="error", markup=False,
                )
            return
        except ValueError as exc:
            self.app.notify(
                f"Remediation failed: {exc}", severity="error", markup=False,
            )
            return
        finally:
            self._remediating = False
        # Contract §F.3 response: {ok, dry_run, exit_code, slug,
        # stdout_tail, stderr_tail, finding_id, finding_status}.
        ok = bool(result.get("ok"))
        slug = str(result.get("slug") or "")
        new_status = str(result.get("finding_status") or "")
        is_dry_run = bool(result.get("dry_run", dry_run))
        if new_status:
            self._finding["status"] = new_status
            self._changed = True
        elif ok and not is_dry_run:
            # A successful LIVE run with async-pending verification (no
            # finding_status yet) still changed server state — make sure
            # the inbox refreshes on back (ISSUE-4).
            self._changed = True
        if is_dry_run:
            # A dry run never changes the finding — report the outcome.
            if ok:
                message = ("Dry run succeeded — the live remediation "
                           "should work. Nothing changed on the box.")
                severity = "information"
            else:
                message = f"Dry run failed: {slug or 'see server evidence'}"
                severity = "warning"
        elif ok and new_status == "resolved":
            message = "Remediation succeeded — finding resolved."
            severity = "information"
        elif ok:
            message = ("Remediation command succeeded — the server is "
                       "verifying the fix.")
            severity = "information"
        else:
            message = (
                "Remediation did not resolve the finding: "
                f"{slug or 'the server re-check still sees the issue'}"
            )
            severity = "warning"
        self.app.notify(message, severity=severity, markup=False)
        self._render_finding()

    def action_back(self) -> None:
        self.dismiss(self._changed)
