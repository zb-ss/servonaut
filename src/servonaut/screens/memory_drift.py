"""Memory Drift screen — fleet-wide drift event list and diff viewer.

Shows configuration drift events across all synced server instances.
Tier-gated on ``memory_drift`` entitlement.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Header, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)

_SEVERITY_CELL: Dict[str, str] = {
    "high": "[bold red]high[/bold red]",
    "medium": "[yellow]medium[/yellow]",
    "low": "[dim]low[/dim]",
}


class DriftDiffScreen(ModalScreen[None]):
    """Modal showing a unified diff of the old vs. new envelope payload.

    Args:
        drift_event: DriftEvent dict with at least ``old_payload`` and
            ``new_payload`` keys (both are plain dicts).
    """

    DEFAULT_CSS = """
    DriftDiffScreen {
        align: center middle;
    }

    #drift-diff-container {
        width: 90%;
        height: 80%;
        border: round $primary;
        background: $surface;
        padding: 1 2;
    }

    #drift-diff-title {
        text-style: bold;
        margin-bottom: 1;
    }

    #drift-diff-body {
        height: 1fr;
        overflow: auto;
        border: round $panel;
        padding: 0 1;
    }

    #drift-diff-close-row {
        height: auto;
        align: right middle;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "close", "Close", show=True),
    ]

    def __init__(self, drift_event: Any, retrieval_service: Any = None) -> None:
        super().__init__()
        self._event = drift_event
        self._retrieval_service = retrieval_service

    def compose(self) -> ComposeResult:
        instance_id = escape(str(getattr(self._event, "instance_id", "?")))
        module = escape(str(getattr(self._event, "module", "?")))
        old_hash = str(getattr(self._event, "old_hash", "") or "")[:12]
        new_hash = str(getattr(self._event, "new_hash", "") or "")[:12]
        header = (
            f"[bold cyan]Drift Diff: {instance_id} / {module}[/bold cyan]\n"
            f"[dim]old: {escape(old_hash)} → new: {escape(new_hash)}[/dim]"
        )
        yield Container(
            Static(header, id="drift-diff-title"),
            VerticalScroll(
                Static("[dim]Loading snapshot diff…[/dim]", id="drift-diff-content"),
                id="drift-diff-body",
            ),
            Horizontal(
                Button("Close", variant="default", id="drift-diff-close"),
                id="drift-diff-close-row",
            ),
            id="drift-diff-container",
        )

    def on_mount(self) -> None:
        self.run_worker(self._fetch_and_render(), group="memory_drift")

    async def _fetch_and_render(self) -> None:
        content = self.query_one("#drift-diff-content", Static)
        if self._retrieval_service is None:
            content.update("[red]Retrieval service unavailable — cannot fetch snapshots.[/red]")
            return
        try:
            instance_id = getattr(self._event, "instance_id", "")
            module = getattr(self._event, "module", "")
            old_id = getattr(self._event, "old_envelope_id", None)
            new_id = getattr(self._event, "new_envelope_id", None)
            if not new_id:
                content.update("[red]Drift event missing new_envelope_id.[/red]")
                return
            old_env = None
            if old_id:
                try:
                    old_env = await self._retrieval_service.get_snapshot(
                        instance_id, module, old_id,
                    )
                except Exception as exc:
                    logger.warning("Could not fetch old snapshot %s: %s", old_id, exc)
            new_env = await self._retrieval_service.get_snapshot(
                instance_id, module, new_id,
            )
            diff_text = self._build_diff_text(old_env, new_env)
            # Scrub the raw JSON payload diff — it may contain hostnames,
            # paths, ports, package versions, and account IDs.
            if self.app.demo_mode and self.app.redaction_service:
                diff_text = self.app.redaction_service.scrub_stream(diff_text)
            content.update(diff_text)
        except Exception as exc:
            logger.exception("Drift diff fetch failed: %s", exc)
            content.update(f"[red]Diff fetch failed: {escape(str(exc))}[/red]")

    def _build_diff_text(self, old_env: Any, new_env: Any) -> str:
        import json
        import difflib
        old_payload = getattr(old_env, "plaintext", {}) if old_env is not None else {}
        new_payload = getattr(new_env, "plaintext", {}) if new_env is not None else {}
        old_lines = json.dumps(old_payload, indent=2, sort_keys=True).splitlines()
        new_lines = json.dumps(new_payload, indent=2, sort_keys=True).splitlines()
        diff = list(difflib.unified_diff(old_lines, new_lines, lineterm=""))
        if not diff:
            return "[dim](no textual differences)[/dim]"
        parts: List[str] = []
        for line in diff:
            if line.startswith("+") and not line.startswith("+++"):
                parts.append(f"[green]{escape(line)}[/green]")
            elif line.startswith("-") and not line.startswith("---"):
                parts.append(f"[red]{escape(line)}[/red]")
            elif line.startswith("@@"):
                parts.append(f"[cyan]{escape(line)}[/cyan]")
            else:
                parts.append(escape(line))
        return "\n".join(parts)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()

    def action_close(self) -> None:
        self.dismiss()


class MemoryDriftScreen(Screen):
    """Screen for viewing and managing memory drift events.

    Lists drift events from the ``DriftService`` with columns:
    When, Instance, Module, Severity, Hash Delta, Status.

    Tier-gated on ``memory_drift`` — pushes ``UpsellModal`` on mount if
    the entitlement is missing.
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("a", "ack_selected", "Ack", show=True),
        Binding("u", "toggle_unack", "Unack only", show=True),
        Binding("enter", "view_diff", "Diff", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def __init__(self) -> None:
        super().__init__()
        self._show_unack_only: bool = False
        self._events: List[Any] = []

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static(
                    "[bold cyan]Memory Drift Events[/bold cyan]",
                    id="drift-title",
                ),
                Static(
                    "",
                    id="drift-filter-label",
                ),
                DataTable(id="drift-table"),
                Horizontal(
                    Button("r. Refresh", id="btn-drift-refresh"),
                    Button("a. Acknowledge", id="btn-drift-ack"),
                    Button("u. Unack Only", id="btn-drift-unack"),
                    id="drift-actions",
                ),
                id="drift-container",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Mount
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        auth = getattr(self.app, "auth_service", None)
        if auth and not auth.has_feature("memory_drift"):
            from servonaut.widgets.upsell_modal import UpsellModal
            self.app.push_screen(UpsellModal("memory_drift"))
            return
        table = self.query_one("#drift-table", DataTable)
        table.cursor_type = "row"
        table.add_column("When", key="when")
        table.add_column("Instance", key="instance")
        table.add_column("Module", key="module")
        table.add_column("Severity", key="severity")
        table.add_column("Status", key="status")
        self._load_drift_events()

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _load_drift_events(self) -> None:
        self.run_worker(
            self._do_load(),
            group="memory_drift",
            name="drift_load",
        )

    async def _do_load(self) -> None:
        drift_service = getattr(self.app, "drift_service", None)
        if drift_service is None:
            self.app.notify("Drift service not available.", severity="warning")
            return
        try:
            events = await drift_service.list_drift()
        except Exception as exc:
            logger.error("Failed to load drift events: %s", exc)
            self.app.notify(f"Drift load failed: {exc}", severity="error")
            return
        self._events = events
        self._render_table()

    def _render_table(self) -> None:
        table = self.query_one("#drift-table", DataTable)
        table.clear()
        events = self._events
        if self._show_unack_only:
            events = [e for e in events if getattr(e, "acknowledged_at", None) is None]
        label = self.query_one("#drift-filter-label", Static)
        label.update(
            "[dim]Showing: unacknowledged only[/dim]"
            if self._show_unack_only
            else "[dim]Showing: all events[/dim]"
        )
        for idx, evt in enumerate(events):
            raw_instance_id = str(getattr(evt, "instance_id", "?"))
            # Use the sharper redact_instance_id primitive — instance IDs are
            # more identifying than freeform text and deserve precise masking.
            if self.app.demo_mode and self.app.redaction_service:
                raw_instance_id = self.app.redaction_service.redact_instance_id(
                    raw_instance_id
                )
            instance_id = escape(raw_instance_id)
            module = escape(str(getattr(evt, "module", "?")))
            severity = str(getattr(evt, "severity", "low"))
            status = "acknowledged" if getattr(evt, "acknowledged_at", None) else "open"
            status = escape(status)
            detected_at = str(getattr(evt, "detected_at", ""))[:19].replace("T", " ")
            severity_cell = _SEVERITY_CELL.get(severity, severity)
            table.add_row(
                detected_at,
                instance_id,
                module,
                severity_cell,
                status,
                key=str(idx),
            )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._load_drift_events()

    def action_ack_selected(self) -> None:
        table = self.query_one("#drift-table", DataTable)
        if table.row_count == 0:
            self.app.notify("No events to acknowledge.", severity="warning")
            return
        try:
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate)
            idx = int(row_key.row_key.value or -1)
        except Exception:
            self.app.notify("Select an event row first.", severity="warning")
            return
        if idx < 0 or idx >= len(self._events):
            return
        evt = self._events[idx]
        self.run_worker(
            self._do_ack(evt),
            group="memory_drift",
            name="drift_ack",
        )

    async def _do_ack(self, evt: Any) -> None:
        drift_service = getattr(self.app, "drift_service", None)
        if drift_service is None:
            return
        try:
            drift_id = getattr(evt, "id", None)
            await drift_service.acknowledge_drift(drift_id)
            self.app.notify("Drift event acknowledged.")
            await self._do_load()
        except Exception as exc:
            logger.error("Acknowledge failed: %s", exc)
            self.app.notify(f"Acknowledge failed: {exc}", severity="error")

    def action_toggle_unack(self) -> None:
        self._show_unack_only = not self._show_unack_only
        self._render_table()

    def action_view_diff(self) -> None:
        table = self.query_one("#drift-table", DataTable)
        if table.row_count == 0:
            return
        try:
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate)
            idx = int(row_key.row_key.value or -1)
        except Exception:
            return
        if idx < 0 or idx >= len(self._events):
            return
        evt = self._events[idx]
        retrieval = getattr(self.app, "memory_retrieval_service", None)
        self.app.push_screen(DriftDiffScreen(evt, retrieval_service=retrieval))

    # ------------------------------------------------------------------
    # Button handler
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_map = {
            "btn-drift-refresh": self.action_refresh,
            "btn-drift-ack": self.action_ack_selected,
            "btn-drift-unack": self.action_toggle_unack,
        }
        handler = btn_map.get(event.button.id)
        if handler:
            handler()
