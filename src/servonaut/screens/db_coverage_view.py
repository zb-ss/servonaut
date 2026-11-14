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
from textual.screen import ModalScreen
from textual.widgets import (
    Button, Checkbox, DataTable, Footer, Input, Static,
)

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.services.db_coverage import (
    DbCoverageRow,
    compute_db_coverage,
    coverage_summary,
    filter_coverage,
)
from servonaut.widgets.dialogs import (
    DialogActions,
    DialogBody,
    DialogFrame,
    DialogNotificationSpace,
)
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

logger = logging.getLogger(__name__)


class ConfirmDbRemoveModal(ModalScreen[Optional[bool]]):
    """Confirm removal of one stored DB credential.

    Dismisses with ``None`` on cancel, or a bool = "also delete the secret from
    the vault" (checkbox) on confirm. Kept separate from a plain yes/no confirm
    because the vault-delete is a second, independently-consequential choice.
    """

    DEFAULT_CLASSES = "dialog-screen"

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
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static("[bold]Remove DB credential[/bold]", id="db_remove_modal_title"),
            body=DialogBody(Static(body, id="db_remove_modal_body")),
            # The second, independent choice stays beside the actions.
            status=Checkbox(
                "Also delete the secret from the vault",
                value=self._has_secret,
                id="db_remove_delete_secret",
                # No secret in the store → nothing to delete; disable the toggle.
                disabled=not self._has_secret,
            ),
            actions=DialogActions(
                Button("Remove", variant="error", id="btn_db_remove_confirm"),
                Button("Cancel", id="btn_db_remove_cancel"),
                id="db_remove_buttons",
            ),
            id="db_remove_modal_container",
            size="compact",
            severity="danger",
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


class DbCoverageScreen(WorkspaceScreen):
    """Coverage table: which instances have a vaulted DB credential, which don't."""

    AUTO_FOCUS = "#db_cov_filter"
    CHAT_REFLOW = True
    # Body padding and scrollbar plus the server / secret coverage
    # table columns beside the chat column.
    CHAT_MIN_CONTENT_WIDTH = 64
    CONTENT_NARROW_WIDTH = 80

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("d", "remove", "Remove", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._rows: List[DbCoverageRow] = []

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if self.navigation_focused:
            return super().check_action(action, parameters)
        return check_action_passthrough(self, action)

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield WorkspaceControls("DB coverage")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            yield Container(
                Container(
                    Static("Database coverage", id="db_cov_title"),
                    Static(
                        "Find stored credentials and gaps across your servers. "
                        "Only names are shown; secret values stay hidden.",
                        id="db_cov_subtitle",
                    ),
                    classes="db-view-heading",
                ),
                Horizontal(
                    VerticalScroll(
                        Static("Find and manage", classes="db-section-title"),
                        Horizontal(
                            Input(placeholder="Filter by server or secret…", id="db_cov_filter"),
                            Button("Refresh", id="db_cov_refresh"),
                            classes="db-filter-row",
                        ),
                        Static("", id="db_cov_summary", classes="db-status-band"),
                        Horizontal(
                            Static("Select a stored credential to remove its profile.", classes="db-action-hint"),
                            Button("Remove selected", id="db_cov_remove", variant="error"),
                            classes="db-action-row",
                        ),
                        id="db_cov_review",
                        classes="db-review-tools",
                    ),
                    Container(
                        Static("Loading credential coverage…", id="db_cov_empty"),
                        DataTable(id="db_cov_table", cursor_type="row", zebra_stripes=True),
                        id="db_cov_body",
                        classes="db-records",
                    ),
                    id="db_cov_workspace",
                    classes="db-review-workspace",
                ),
                id="db_cov_container",
                classes="workspace-content",
            )
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#db_cov_body", Container).border_title = "Stored credentials and gaps"
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
            if not self._rows:
                self.query_one("#db_cov_empty", Static).update(text)
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

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "db_cov_refresh":
            self.action_refresh()
        elif event.button.id == "db_cov_remove":
            self.action_remove()

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
            self._set_summary("[$text-error]Not ready — sign in first.[/$text-error]")
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
        empty = self.query_one("#db_cov_empty", Static)
        empty.display = not rows
        empty.update(
            "No servers or credentials match this filter."
            if self._current_filter()
            else "No servers are available for credential coverage."
        )
