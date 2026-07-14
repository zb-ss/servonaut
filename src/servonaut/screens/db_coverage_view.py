"""DbCoverageScreen — DB-vault coverage + search (Layer B4).

Scale-management view: across hundreds of instances, which have a stored
DB credential (a DBProfile whose secret exists in the active store) and
which are GAPS. A search box filters by server / secret name. Read-only —
lists NAMES only (``list_secrets``), never values.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button, Checkbox, DataTable, Footer, Header, Input, Static,
)

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.services.db_coverage import (
    DbCoverageRow,
    compute_db_coverage,
    coverage_summary,
    filter_coverage,
)
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


class ConfirmDbRemoveModal(ModalScreen[Optional[bool]]):
    """Confirm removal of one stored DB credential.

    Dismisses with ``None`` on cancel, or a bool = "also delete the secret from
    the vault" (checkbox) on confirm. Kept separate from a plain yes/no confirm
    because the vault-delete is a second, independently-consequential choice.
    """

    DEFAULT_CSS = """
    ConfirmDbRemoveModal { align: center middle; }
    ConfirmDbRemoveModal #db_remove_modal_container {
        width: 66; height: auto; max-width: 90%;
        padding: 1 2; border: round $error; background: $surface;
    }
    ConfirmDbRemoveModal #db_remove_buttons { height: auto; margin-top: 1; }
    ConfirmDbRemoveModal Button { margin-right: 1; }
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]

    def __init__(self, *, site: str, has_secret: bool) -> None:
        super().__init__()
        self._site = site
        self._has_secret = has_secret

    def compose(self) -> ComposeResult:
        body = (
            f"Remove the stored DB credential for [b]{escape(self._site)}[/b]?\n\n"
            "This deletes the connection profile from your config so "
            "db_processlist / db_top_queries can no longer resolve it by name."
        )
        yield Container(
            Static("[bold]Remove DB credential[/bold]", id="db_remove_modal_title"),
            Static(body, id="db_remove_modal_body"),
            Checkbox(
                "Also delete the secret from the vault",
                value=self._has_secret,
                id="db_remove_delete_secret",
                # No secret in the store → nothing to delete; disable the toggle.
                disabled=not self._has_secret,
            ),
            Horizontal(
                Button("Remove", variant="error", id="btn_db_remove_confirm"),
                Button("Cancel", id="btn_db_remove_cancel"),
                id="db_remove_buttons",
            ),
            id="db_remove_modal_container",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_db_remove_confirm":
            delete_secret = self.query_one(
                "#db_remove_delete_secret", Checkbox,
            ).value
            self.dismiss(bool(delete_secret))
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class DbCoverageScreen(Screen):
    """Coverage table: which instances have a vaulted DB credential, which don't."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("d", "remove", "Remove", show=True),
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
        table.add_columns("Server", "Site", "Profile", "Secret", "In store", "Status")
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
    # Remove a stored credential
    # ------------------------------------------------------------------

    def _selected_row(self) -> Optional[DbCoverageRow]:
        """The DbCoverageRow under the cursor, resolved via the composite key."""
        table = self.query_one("#db_cov_table", DataTable)
        if table.row_count == 0 or table.cursor_row is None:
            return None
        try:
            key = table.coordinate_to_cell_key((table.cursor_row, 0)).row_key.value
        except Exception:  # noqa: BLE001
            return None
        instance_id, _, label = (key or "").partition("\0")
        return next(
            (r for r in self._rows
             if r.instance_id == instance_id and r.label == label),
            None,
        )

    def action_remove(self) -> None:
        row = self._selected_row()
        if row is None or not row.has_profile:
            self.notify(
                "No stored DB credential on this row to remove.",
                severity="warning",
            )
            return
        site = row.label or row.instance_id

        def _after(delete_secret: Optional[bool]) -> None:
            if delete_secret is None:
                return  # cancelled
            self.run_worker(
                self._do_remove(row.instance_id, row.label, bool(delete_secret)),
                group="db_coverage", exclusive=True,
            )

        self.app.push_screen(
            ConfirmDbRemoveModal(
                site=site, has_secret=row.secret_present,
            ),
            _after,
        )

    async def _do_remove(
        self, instance_id: str, label: str, delete_secret: bool,
    ) -> None:
        tools = getattr(self.app, "servonaut_tools", None)
        if tools is None:
            self.notify("DB tooling unavailable.", severity="error")
            return
        try:
            out = await tools.db_setup_remove(
                instance_id, app=label, delete_secret=delete_secret,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("db_setup_remove failed: %s", exc)
            self.notify(f"Remove failed: {exc}", severity="error", markup=False)
            return
        ok = isinstance(out, str) and out.startswith("Removed db_profile")
        self.notify(
            str(out), severity="information" if ok else "warning", markup=False,
        )
        # Reflect the mutation — re-read config + secret names and repaint.
        await self._load_worker()

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
            # Demo mode: server + secret names AND the per-site label are all
            # workspace identifiers (site labels are hostnames/domains), so the
            # Site column is scrubbed alongside Server and Secret.
            name = r.instance_name
            secret_label = r.secret_name or "—"
            site_label = r.label
            if demo:
                name = self.app.redaction_service.redact_name(name)
                if r.secret_name:
                    secret_label = self.app.redaction_service.redact_name(r.secret_name)
                if r.label:
                    site_label = self.app.redaction_service.redact_name(r.label)
            table.add_row(
                escape(name),
                escape(site_label) or "—",
                "yes" if r.has_profile else "—",
                escape(secret_label),
                "yes" if r.secret_present else "—",
                escape(r.status),
                # One instance now yields multiple rows (one per site); a
                # bare instance_id key would collide, so compose with label.
                key=f"{r.instance_id}\0{r.label}",
            )
        s = coverage_summary(self._rows)
        shown = len(rows)
        suffix = f" (showing {shown})" if shown != s["total"] else ""
        self._set_summary(
            f"[bold]{s['covered']}[/bold] covered · "
            f"[bold]{s['gap']}[/bold] gap · {s['total']} total{suffix}"
        )
