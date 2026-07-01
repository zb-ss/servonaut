"""DbCoverageScreen — DB-vault coverage + search (Layer B4).

Scale-management view: across hundreds of instances, which have a stored
DB credential (a DBProfile whose secret exists in the active store) and
which are GAPS. A search box filters by server / secret name. Read-only —
lists NAMES only (``list_secrets``), never values.
"""
from __future__ import annotations

import logging
from typing import List

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.services.db_coverage import (
    DbCoverageRow,
    compute_db_coverage,
    coverage_summary,
    filter_coverage,
)
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


class DbCoverageScreen(Screen):
    """Coverage table: which instances have a vaulted DB credential, which don't."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._rows: List[DbCoverageRow] = []

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static("🔐 DB-vault coverage", id="db_cov_title"),
                Static(
                    "Which instances have a stored DB credential, and which "
                    "are gaps. Names only — values are never shown.",
                    id="db_cov_subtitle",
                ),
                Input(placeholder="Filter by server or secret…", id="db_cov_filter"),
                Static("", id="db_cov_summary"),
                VerticalScroll(
                    DataTable(id="db_cov_table", cursor_type="row"),
                    id="db_cov_body",
                ),
                id="db_cov_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#db_cov_table", DataTable)
        table.add_columns("Server", "Profile", "Secret", "In store", "Status")
        self._set_summary("[dim]Loading…[/dim]")
        self.run_worker(
            self._load_worker(), group="db_coverage", exclusive=True,
        )

    def _set_summary(self, text: str) -> None:
        # Single write point for the summary line; demo mode scrubs any
        # IP/host/path that reached a status/error string.
        if self.app.demo_mode and self.app.redaction_service:
            text = self.app.redaction_service.scrub_stream(text)
        try:
            self.query_one("#db_cov_summary", Static).update(text)
        except Exception:  # noqa: BLE001
            pass

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._set_summary("[dim]Loading…[/dim]")
        self.run_worker(
            self._load_worker(), group="db_coverage", exclusive=True,
        )

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "db_cov_filter":
            self._repaint()

    # ------------------------------------------------------------------
    # Worker + render
    # ------------------------------------------------------------------

    async def _load_worker(self) -> None:
        auth = getattr(self.app, "auth_service", None)
        guard = getattr(self.app, "entitlement_guard", None)
        cm = getattr(self.app, "config_manager", None)
        if auth is None or guard is None or cm is None:
            self._set_summary("[red]Not ready — sign in first.[/red]")
            return
        names: List[str] = []
        try:
            from servonaut.services.secret_provider_resolver import (
                resolve_secret_provider,
            )
            provider = resolve_secret_provider(auth, guard)
            if provider is not None:
                names = await provider.list_secrets()
        except Exception as exc:  # noqa: BLE001
            # A provider read failure shouldn't hide the profile side of
            # coverage — surface it but still render "secret missing" rows.
            logger.warning("Coverage: list_secrets failed: %s", exc)
        instances = list(getattr(self.app, "instances", []) or [])
        config = cm.get()
        self._rows = compute_db_coverage(instances, config, names)
        self._repaint()

    def _current_filter(self) -> str:
        try:
            value = self.query_one("#db_cov_filter", Input).value
        except Exception:  # noqa: BLE001
            return ""
        return value if isinstance(value, str) else ""

    def _repaint(self) -> None:
        table = self.query_one("#db_cov_table", DataTable)
        table.clear()
        rows = filter_coverage(self._rows, self._current_filter())
        demo = self.app.demo_mode and self.app.redaction_service
        for r in rows:
            # Demo mode: server + secret names are workspace identifiers.
            name = r.instance_name
            secret_label = r.secret_name or "—"
            if demo:
                name = self.app.redaction_service.redact_name(name)
                if r.secret_name:
                    secret_label = self.app.redaction_service.redact_name(r.secret_name)
            table.add_row(
                escape(name),
                "yes" if r.has_profile else "—",
                escape(secret_label),
                "yes" if r.secret_present else "—",
                escape(r.status),
                key=r.instance_id,
            )
        s = coverage_summary(self._rows)
        shown = len(rows)
        suffix = f" (showing {shown})" if shown != s["total"] else ""
        self._set_summary(
            f"[bold]{s['covered']}[/bold] covered · "
            f"[bold]{s['gap']}[/bold] gap · {s['total']} total{suffix}"
        )
