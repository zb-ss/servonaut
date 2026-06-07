"""Fleet Memory screen — fleet-wide overview of server memory status.

Discoverability surface for the server-memory subsystem.  Users land here
from the sidebar ("Fleet Memory") and can see every managed instance at
a glance: whether memory has been built, how stale it is, and bulk-run
actions (Scan All / Refresh Stale / Clear) without needing to drill into
individual servers.

Failure UX: after a bulk scan any instance whose probe produced zero
modules is surfaced in a post-scan summary modal so operators don't have
to hunt row-by-row for failures.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Header, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:  # pragma: no cover
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)


# Status codes + icons rendered in the Memory column.  Kept as module
# constants so the instance_list widget can reuse the same vocabulary.
STATUS_FRESH = "fresh"
STATUS_STALE = "stale"
STATUS_NONE = "none"
STATUS_OPT_OUT = "opted-out"

_STATUS_CELL: Dict[str, str] = {
    STATUS_FRESH: "[green]● Fresh[/green]",
    STATUS_STALE: "[yellow]● Stale[/yellow]",
    STATUS_NONE: "[dim]○ Not probed[/dim]",
    STATUS_OPT_OUT: "[red]⛔ Opted-out[/red]",
}

# Source column rendering (width 8)
_SOURCE_CELL: Dict[str, str] = {
    "local": "[dim]local[/dim]",
    "remote": "[blue]cloud[/blue]",
    "merged": "[green]synced[/green]",
}


# Cap on parallel probes during a fleet-wide scan.  Each probe opens its
# own SSH session, so we keep the ceiling well below the per-instance
# semaphore (8) in MemoryService to avoid hammering shared bastions.
_MAX_PARALLEL_FLEET_PROBES = 4


# ---------------------------------------------------------------------------
# Helpers (memory status + formatting)
# ---------------------------------------------------------------------------


def _human_age(probed_at_str: str) -> str:
    """Return a short age string like ``5m ago`` / ``3d ago`` for UI display."""
    if not probed_at_str:
        return "—"
    try:
        probed_at = datetime.fromisoformat(probed_at_str.rstrip("Z"))
        if not probed_at.tzinfo:
            probed_at = probed_at.replace(tzinfo=timezone.utc)
        age = (datetime.now(tz=timezone.utc) - probed_at).total_seconds()
        if age < 60:
            return f"{int(age)}s ago"
        if age < 3600:
            return f"{int(age // 60)}m ago"
        if age < 86400:
            return f"{int(age // 3600)}h ago"
        return f"{int(age // 86400)}d ago"
    except (ValueError, TypeError):
        return "—"


def compute_memory_status(
    instance: Dict[str, Any],
    memory_service: Any,
) -> str:
    """Return one of the STATUS_* codes for *instance*.

    A server's whole memory is reported ``STATUS_STALE`` once its newest
    probe is older than the server-level threshold
    (``MemoryService.snapshot_stale_seconds``). This is deliberately
    decoupled from per-module TTLs — volatile modules (containers, disk)
    re-probe fast by design and must not drag the whole-server badge.

    Reuses the memory service's public API only — no ``_store`` reach-in.
    Defensive against missing services so callers (instance_list column,
    fleet table) never raise from UI code paths.
    """
    if memory_service is None:
        return STATUS_NONE

    iid = instance.get("id") or instance.get("name", "")
    iname = instance.get("name", "")
    provider = instance.get("provider", "custom")
    if not iid:
        return STATUS_NONE

    try:
        if memory_service.is_memory_disabled(iid, iname):
            return STATUS_OPT_OUT
    except Exception:
        pass

    try:
        modules = memory_service.get_all_modules(iid, provider)
    except Exception:
        modules = {}
    if not modules:
        return STATUS_NONE

    age = snapshot_age_seconds(modules)
    threshold = _resolve_stale_threshold(memory_service)
    if age is None or age > threshold:
        return STATUS_STALE
    return STATUS_FRESH


def _latest_probed_at(modules: Dict[str, Any]) -> str:
    """Return the most recent ``probed_at`` across *modules*, or ``""``."""
    latest = ""
    for mod in modules.values():
        probed_at = mod.get("probed_at", "") if isinstance(mod, dict) else ""
        if probed_at and probed_at > latest:
            latest = probed_at
    return latest


def snapshot_age_seconds(modules: Dict[str, Any]) -> Optional[float]:
    """Return the age in seconds of the most recent probe across *modules*.

    Returns ``None`` when *modules* is empty or carries no parseable
    ``probed_at`` timestamp — callers treat that as "stale / unknown".
    """
    latest = _latest_probed_at(modules)
    if not latest:
        return None
    try:
        probed_at = datetime.fromisoformat(latest.rstrip("Z"))
        if not probed_at.tzinfo:
            probed_at = probed_at.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    return (datetime.now(tz=timezone.utc) - probed_at).total_seconds()


def _resolve_stale_threshold(memory_service: Any) -> float:
    """Return the server-level staleness threshold in seconds.

    Reads ``MemoryService.snapshot_stale_seconds`` and falls back to the
    schema default when the service does not expose a usable numeric value
    (e.g. lightweight test doubles).
    """
    from servonaut.config.schema import DEFAULT_SNAPSHOT_STALE_SECONDS

    val = getattr(memory_service, "snapshot_stale_seconds", None)
    if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
        return float(val)
    return float(DEFAULT_SNAPSHOT_STALE_SECONDS)


# ---------------------------------------------------------------------------
# Post-scan summary modal
# ---------------------------------------------------------------------------


class FleetScanSummaryModal(ModalScreen[None]):
    """Summary of a fleet-wide scan: ``X succeeded, Y failed — view details``.

    Option (b) from the UX brief: one aggregate modal instead of per-row
    popups, so the fleet table stays scannable even when a handful of
    probes fail.
    """

    DEFAULT_CSS = """
    FleetScanSummaryModal {
        align: center middle;
    }
    FleetScanSummaryModal #fleet-scan-modal {
        width: 80;
        max-width: 90%;
        height: auto;
        max-height: 80%;
        padding: 1 2;
        background: $surface;
        border: round $primary;
    }
    FleetScanSummaryModal #fleet-scan-title {
        text-style: bold;
        margin-bottom: 1;
    }
    FleetScanSummaryModal #fleet-scan-failures {
        height: auto;
        max-height: 20;
        margin-bottom: 1;
    }
    FleetScanSummaryModal Button {
        margin-left: 1;
    }
    """

    def __init__(
        self,
        succeeded: List[str],
        failed: List[Dict[str, Any]],
    ) -> None:
        """Initialise the summary.

        Args:
            succeeded: Instance identifiers whose scan produced ≥1 module.
            failed: ``[{"instance": <name>, "reason": <code>, "failures":
                [{module, reason, message}, …]}]`` for failed scans.
        """
        super().__init__()
        self._succeeded = succeeded
        self._failed = failed

    def compose(self) -> ComposeResult:
        total = len(self._succeeded) + len(self._failed)
        yield Container(
            Static(
                f"[bold cyan]Fleet scan complete[/bold cyan] — "
                f"[green]{len(self._succeeded)} succeeded[/green], "
                f"[red]{len(self._failed)} failed[/red] "
                f"({total} total)",
                id="fleet-scan-title",
            ),
            VerticalScroll(
                Static(self._render_body(), id="fleet-scan-body"),
                id="fleet-scan-failures",
            ),
            Horizontal(
                Button("OK", id="btn_close", variant="primary"),
            ),
            id="fleet-scan-modal",
        )

    def _render_body(self) -> str:
        """Format succeeded + failed lists for the modal body."""
        # _s: scrub PII (IPs, hostnames, paths) from exception messages BEFORE
        # escape() so malformed IPs are never visible in demo recordings.
        # Order: scrub → escape → embed (avoids Rich-markup injection).
        def _s(x: str) -> str:
            try:
                if self.app.demo_mode and self.app.redaction_service:
                    return self.app.redaction_service.scrub_stream(x)
            except Exception:
                pass
            return x

        lines: List[str] = []
        if self._succeeded:
            lines.append("[green]Succeeded[/green]:")
            for name in self._succeeded:
                lines.append(f"  • {escape(name)}")
            lines.append("")
        if self._failed:
            lines.append("[red]Failed[/red]:")
            for entry in self._failed:
                reason = _s(entry.get("reason", "unknown"))
                lines.append(
                    f"  • {escape(entry['instance'])}  "
                    f"[dim](reason: {escape(reason)})[/dim]"
                )
                for failure in entry.get("failures", [])[:3]:
                    msg = _s(failure.get("message", ""))
                    lines.append(
                        f"      ↳ {escape(failure.get('module', ''))}: "
                        f"{escape(msg)}"
                    )
                extra = len(entry.get("failures", [])) - 3
                if extra > 0:
                    lines.append(f"      [dim]… and {extra} more[/dim]")
        if not lines:
            lines.append("[dim]No activity.[/dim]")
        return "\n".join(lines)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_close":
            self.dismiss(None)

    def key_escape(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------------------
# Fleet Memory screen
# ---------------------------------------------------------------------------


class FleetMemoryScreen(Screen):
    """Fleet-wide view of memory status + bulk memory operations.

    Discoverability tier 1: a dedicated sidebar entry that makes the memory
    feature visible without needing to drill into a server.  All rows are
    linked to the per-instance :class:`MemoryScreen` via ``enter``.
    """

    CSS_PATH = ["../app.css", "../memory_screen.tcss"]

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh_view", "Refresh View", show=True),
        Binding("s", "scan_all", "Scan All", show=True),
        Binding("S", "share_selected", "Share", show=True),
        Binding("f", "refresh_stale", "Refresh Stale", show=True),
        Binding("enter", "open_selected", "Open", show=True),
        Binding("x", "clear_selected", "Clear", show=True),
    ]

    @property
    def app(self) -> "ServonautApp":  # type: ignore[override]
        return super().app  # type: ignore

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def __init__(self) -> None:
        super().__init__()
        self._rows: List[Dict[str, Any]] = []
        self._scanning = False

    # ------------------------------------------------------------------
    # Compose / mount
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield Container(
                Static(
                    "[bold]Fleet Memory[/bold]",
                    id="memory-title",
                ),
                Static(
                    "AI-queryable server memory across your fleet.",
                    id="memory-subtitle",
                ),
                Static(
                    "[dim]Memory stores OS / runtime / service / log facts for "
                    "each server so the chat agent and MCP clients can answer "
                    "questions instantly without an SSH round-trip. Pick a "
                    "row and press [b]enter[/b] to inspect, [b]s[/b] to scan "
                    "every server, or [b]f[/b] to refresh only stale "
                    "modules.[/dim]",
                    id="fleet-memory-help",
                ),
                Static("", id="fleet-memory-status"),
                # Live progress line for bulk scans — hidden when idle so
                # it never competes with the status summary above.
                Static("", id="fleet-memory-progress", classes="hidden"),
                # Wrap the table in a sub-container so the rounded card
                # treatment can be applied via CSS without affecting the
                # DataTable's own selection styling.
                Container(
                    DataTable(id="fleet-memory-table"),
                    id="fleet-memory-table-card",
                ),
                Horizontal(
                    Button("s. Scan All", id="btn_scan_all", variant="primary"),
                    Button("f. Refresh Stale", id="btn_refresh_stale"),
                    Button("enter. Open", id="btn_open"),
                    Button("x. Clear", id="btn_clear", variant="error"),
                    id="memory-actions",
                ),
                id="memory-container",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#fleet-memory-table", DataTable)
        table.cursor_type = "row"
        table.add_column("Name", key="name")
        table.add_column("ID", key="id", width=20)
        table.add_column("Provider", key="provider", width=10)
        table.add_column("Source", key="source", width=8)
        table.add_column("Memory", key="status", width=16)
        table.add_column("Modules", key="modules", width=10)
        table.add_column("Drift 7d", key="drift_7d", width=6)
        table.add_column("Last probed", key="age", width=14)
        self._launch_populate()

    # ------------------------------------------------------------------
    # Data / populate
    # ------------------------------------------------------------------

    def _launch_populate(self) -> None:
        """Launch async populate if fleet_service is available; else sync fallback."""
        fleet_service = getattr(self.app, "fleet_service", None)
        if fleet_service is not None:
            self.run_worker(
                self._load_fleet_async(),
                name="fleet_memory_populate",
                group="memory_fleet",
                exclusive=True,
            )
        else:
            self._populate_table()

    async def _load_fleet_async(self) -> None:
        """Worker: fetch merged fleet and populate table rows.

        Falls back to local-only populate on BackendMaintenance or UpsellRequired.
        """
        from servonaut.services.memory.interfaces import BackendMaintenance, UpsellRequired
        fleet_service = getattr(self.app, "fleet_service", None)
        if fleet_service is None:
            self._populate_table()
            return

        try:
            merged = await fleet_service.get_merged_fleet()
        except BackendMaintenance:
            self.app.notify(
                "Memory cloud sync is in maintenance — showing local data only.",
                severity="warning",
            )
            self._populate_table()
            return
        except UpsellRequired:
            self.app.notify(
                "Memory cloud sync requires a paid plan — showing local data only.",
                severity="information",
            )
            self._populate_table()
            return
        except Exception as exc:
            logger.warning("Fleet async load failed: %s", exc)
            self._populate_table()
            return

        self._populate_table_from_merged(merged)

    def _populate_table_from_merged(self, merged: List[Dict[str, Any]]) -> None:
        """Populate the table from get_merged_fleet() rows."""
        memory_service = getattr(self.app, "memory_service", None)
        instances = self.app.instances or []

        # Build a lookup of instances by id for memory status
        inst_by_id = {
            (inst.get("id") or inst.get("name", "")): inst
            for inst in instances
        }

        # Demo-mode redaction helper for remote rows (which are NOT in-place
        # redacted by on_mount unlike self.app.instances). Use the same typed
        # primitives as the local _populate_table path for consistency.
        _rs = getattr(self.app, "redaction_service", None)
        _demo = self.app.demo_mode and _rs is not None

        def _rname(v: str) -> str:
            return _rs.redact_name(v) if _demo else v

        def _rid(v: str) -> str:
            return _rs.redact_instance_id(v) if _demo else v

        def _rprovider(v: str) -> str:
            return _rs.redact_provider(v) if _demo else v

        self._rows = []
        fresh = stale = none_count = opt_out = 0
        source_counts = {"local": 0, "remote": 0, "merged": 0}

        for fleet_row in merged:
            # Keep raw values for internal lookups (inst_by_id, memory_service)
            # where redacted IDs would fail to resolve. Apply redaction only to
            # the display values stored in _rows and rendered in the table.
            raw_iid = fleet_row.get("id", "")
            raw_iname = fleet_row.get("name", raw_iid)
            raw_provider = fleet_row.get("provider", "custom")

            iid = _rid(raw_iid)
            iname = _rname(raw_iname)
            provider = _rprovider(raw_provider)
            source = fleet_row.get("source", "local")
            drift_7d = fleet_row.get("drift_7d", 0)

            # Find the matching instance for memory status computation using
            # the raw ID (inst_by_id keys are redacted by on_mount for local
            # instances, but remote rows need raw key for the fallback dict).
            inst = inst_by_id.get(iid) or inst_by_id.get(raw_iid, {
                "id": iid, "name": iname, "provider": provider,
            })
            status = compute_memory_status(inst, memory_service)

            if status == STATUS_FRESH:
                fresh += 1
            elif status == STATUS_STALE:
                stale += 1
            elif status == STATUS_OPT_OUT:
                opt_out += 1
            else:
                none_count += 1

            source_counts[source] = source_counts.get(source, 0) + 1

            modules_count = fleet_row.get("modules", 0)
            age_text = "—"
            if memory_service is not None and status in (STATUS_FRESH, STATUS_STALE):
                try:
                    # Use raw_iid and raw_provider for memory store lookups:
                    # memory keys are stored under the real (un-redacted) IDs.
                    mods = memory_service.get_all_modules(raw_iid, raw_provider)
                except Exception:
                    mods = {}
                if mods:
                    modules_count = len(mods)
                    age_text = _human_age(_latest_probed_at(mods))

            self._rows.append({
                "instance": inst,
                "id": iid,
                "name": iname,
                "provider": provider,
                "source": source,
                "status": status,
                "modules": modules_count,
                "drift_7d": drift_7d,
                "age": age_text,
            })

        table = self.query_one("#fleet-memory-table", DataTable)
        table.clear()
        for row in self._rows:
            source_cell = _SOURCE_CELL.get(row.get("source", "local"), "[dim]local[/dim]")
            table.add_row(
                escape(str(row["name"])),
                escape(str(row["id"])),
                escape(str(row["provider"])),
                source_cell,
                _STATUS_CELL.get(row["status"], "—"),
                str(row["modules"]) if row["modules"] else "—",
                str(row["drift_7d"]) if row.get("drift_7d") else "—",
                row["age"],
            )

        total = len(self._rows)
        status_line = (
            f"[dim]{total} instances  ·  "
            f"[green]{fresh} fresh[/green]  ·  "
            f"[yellow]{stale} stale[/yellow]  ·  "
            f"{none_count} not probed  ·  "
            f"[red]{opt_out} opted-out[/red][/dim]"
        )
        self.query_one("#fleet-memory-status", Static).update(status_line)

    def _populate_table(self) -> None:
        """Rebuild table rows + status footer from local app state (no remote)."""
        memory_service = getattr(self.app, "memory_service", None)
        instances = self.app.instances or []

        self._rows = []
        fresh = stale = none_count = opt_out = 0
        for inst in instances:
            iid = inst.get("id") or inst.get("name", "")
            iname = inst.get("name", iid)
            provider = inst.get("provider", "custom") or "custom"
            status = compute_memory_status(inst, memory_service)
            if status == STATUS_FRESH:
                fresh += 1
            elif status == STATUS_STALE:
                stale += 1
            elif status == STATUS_OPT_OUT:
                opt_out += 1
            else:
                none_count += 1

            modules_count = 0
            age_text = "—"
            if memory_service is not None and status in (STATUS_FRESH, STATUS_STALE):
                try:
                    modules = memory_service.get_all_modules(iid, provider)
                except Exception:
                    modules = {}
                modules_count = len(modules)
                age_text = _human_age(_latest_probed_at(modules))

            self._rows.append({
                "instance": inst,
                "id": iid,
                "name": iname,
                "provider": provider,
                "source": "local",
                "status": status,
                "modules": modules_count,
                "drift_7d": 0,
                "age": age_text,
            })

        table = self.query_one("#fleet-memory-table", DataTable)
        table.clear()
        for row in self._rows:
            table.add_row(
                escape(str(row["name"])),
                escape(str(row["id"])),
                escape(str(row["provider"])),
                _SOURCE_CELL.get(row.get("source", "local"), "[dim]local[/dim]"),
                _STATUS_CELL.get(row["status"], "—"),
                str(row["modules"]) if row["modules"] else "—",
                "—",
                row["age"],
            )

        # Status footer — one glance tells the operator where to act.
        status_line = (
            f"[dim]{len(instances)} instances  ·  "
            f"[green]{fresh} fresh[/green]  ·  "
            f"[yellow]{stale} stale[/yellow]  ·  "
            f"{none_count} not probed  ·  "
            f"[red]{opt_out} opted-out[/red][/dim]"
        )
        self.query_one("#fleet-memory-status", Static).update(status_line)

    def _selected_row(self) -> Optional[Dict[str, Any]]:
        table = self.query_one("#fleet-memory-table", DataTable)
        cursor = table.cursor_row
        if cursor is None or cursor < 0 or cursor >= len(self._rows):
            return None
        return self._rows[cursor]

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh_view(self) -> None:
        """Rebuild the table from cached memory state — no SSH probing."""
        self._launch_populate()
        self.app.notify("Fleet memory view refreshed.")

    def action_open_selected(self) -> None:
        row = self._selected_row()
        if not row:
            self.app.notify("Select a row first.", severity="warning")
            return
        from servonaut.screens.memory import MemoryScreen
        self.app.push_screen(MemoryScreen(row["instance"]))

    def action_share_selected(self) -> None:
        row = self._selected_row()
        if not row:
            self.app.notify("Select a row first.", severity="warning")
            return
        auth = getattr(self.app, "auth_service", None)
        if auth is None or not auth.has_feature("memory_team_share"):
            from servonaut.widgets.upsell_modal import UpsellModal
            self.app.push_screen(UpsellModal("memory_team_share"))
            return
        from servonaut.screens.memory_share import ShareInstanceScreen
        self.app.push_screen(ShareInstanceScreen(row["instance"]))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Open the per-instance Memory screen on row-activate (Enter / click).

        DataTable consumes the ``enter`` key to fire its own RowSelected
        event, so the screen-level binding would never reach
        :meth:`action_open_selected` on its own.  Handling the event
        explicitly here is the idiomatic Textual path and also handles
        mouse activation for free.
        """
        if event.data_table.id != "fleet-memory-table":
            return
        event.stop()
        self.action_open_selected()

    def action_clear_selected(self) -> None:
        row = self._selected_row()
        if not row:
            self.app.notify("Select a row first.", severity="warning")
            return
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            self.app.notify("Memory subsystem not wired.", severity="error")
            return
        try:
            memory_service.clear(row["id"], provider=row["provider"])
        except Exception as exc:  # noqa: BLE001 — UI helper, always recover
            self.app.notify(f"Clear failed: {exc}", severity="error")
            return
        self.app.notify(f"Cleared memory for {row['name']}.")
        self._populate_table()

    def action_scan_all(self) -> None:
        self._launch_bulk_scan(stale_only=False)

    def action_refresh_stale(self) -> None:
        self._launch_bulk_scan(stale_only=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        mapping = {
            "btn_scan_all": self.action_scan_all,
            "btn_refresh_stale": self.action_refresh_stale,
            "btn_open": self.action_open_selected,
            "btn_clear": self.action_clear_selected,
        }
        handler = mapping.get(event.button.id or "")
        if handler:
            event.stop()
            handler()

    # ------------------------------------------------------------------
    # Bulk scan worker
    # ------------------------------------------------------------------

    def _launch_bulk_scan(self, stale_only: bool) -> None:
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            self.app.notify("Memory subsystem not wired.", severity="error")
            return
        if self._scanning:
            self.app.notify("A fleet scan is already in progress.", severity="warning")
            return

        instances = self._eligible_instances(stale_only, memory_service)
        if not instances:
            msg = (
                "No stale memory to refresh."
                if stale_only
                else "No instances available to scan."
            )
            self.app.notify(msg)
            return

        self._scanning = True
        self.app.notify(
            f"Scanning {len(instances)} instance(s) — watch the progress "
            "line above the table for updates."
        )
        self._set_progress(
            f"[cyan]Scanning 0 / {len(instances)}[/cyan]  "
            f"[dim](parallel: {_MAX_PARALLEL_FLEET_PROBES})[/dim]"
        )
        logger.info("Fleet scan launched: %d instance(s), stale_only=%s",
                    len(instances), stale_only)
        self.run_worker(
            self._do_bulk_scan(instances, memory_service),
            name="fleet_memory_scan",
            group="memory_refresh",
            exclusive=True,
        )

    def _set_progress(self, markup: str) -> None:
        """Update the in-screen progress line; empty markup hides the row."""
        try:
            widget = self.query_one("#fleet-memory-progress", Static)
        except Exception:
            return
        if not markup:
            widget.add_class("hidden")
            widget.update("")
        else:
            widget.remove_class("hidden")
            widget.update(markup)

    def _eligible_instances(
        self, stale_only: bool, memory_service: Any
    ) -> List[Dict[str, Any]]:
        """Return instances the scan should actually probe.

        ``stale_only=True`` skips fresh and never-probed servers so refresh
        does only what the operator intended — targeted, not fleet-wide.
        Opted-out instances are always skipped.
        """
        eligible: List[Dict[str, Any]] = []
        for inst in (self.app.instances or []):
            status = compute_memory_status(inst, memory_service)
            if status == STATUS_OPT_OUT:
                continue
            if stale_only and status != STATUS_STALE:
                continue
            eligible.append(inst)
        return eligible

    async def _do_bulk_scan(
        self,
        instances: List[Dict[str, Any]],
        memory_service: Any,
    ) -> None:
        """Probe every instance in *instances* concurrently (capped).

        Drives ``#fleet-memory-progress`` as each probe finishes so the
        user sees forward motion even when an individual SSH session
        takes a minute. ``self._scanning`` is reset in ``finally`` so a
        crash can't leave the screen permanently "busy".
        """
        semaphore = asyncio.Semaphore(_MAX_PARALLEL_FLEET_PROBES)
        succeeded: List[str] = []
        failed: List[Dict[str, Any]] = []
        total = len(instances)
        completed = 0

        def refresh_progress(just_finished: str, ok: bool) -> None:
            colour = "green" if ok else "red"
            self._set_progress(
                f"[cyan]Scanning {completed} / {total}[/cyan]  "
                f"·  [{colour}]last: {escape(just_finished)} "
                f"{'✓' if ok else '✗'}[/{colour}]"
            )

        async def scan_one(inst: Dict[str, Any]) -> None:
            nonlocal completed
            name = inst.get("name") or inst.get("id") or "unknown"
            # Scrub at source so every downstream consumer (succeeded/failed
            # lists, refresh_progress footer, and the modal render) is safe.
            if self.app.demo_mode and self.app.redaction_service:
                name = self.app.redaction_service.redact_name(name)
            logger.info("Fleet scan: probing %s", name)
            async with semaphore:
                ok = False
                try:
                    if hasattr(memory_service, "build_report"):
                        report = await memory_service.build_report(inst)
                        if report.has_any_success:
                            succeeded.append(name)
                            ok = True
                        else:
                            failed.append({
                                "instance": name,
                                "reason": report.overall_reason or "unknown",
                                "failures": [
                                    {"module": f.module, "reason": f.reason,
                                     "message": f.message}
                                    for f in report.failures
                                ],
                            })
                    else:
                        # Fallback for older service instances.
                        results = await memory_service.refresh(inst)
                        if results:
                            succeeded.append(name)
                            ok = True
                        else:
                            failed.append({
                                "instance": name,
                                "reason": "no_modules_returned",
                                "failures": [],
                            })
                except asyncio.CancelledError:
                    # Propagate so asyncio.gather can unwind cleanly.
                    raise
                except Exception as exc:  # noqa: BLE001
                    logger.exception("Fleet scan probe failed for %s", name)
                    failed.append({
                        "instance": name,
                        "reason": "exception",
                        "failures": [{
                            "module": "—",
                            "reason": "exception",
                            "message": str(exc)[:240],
                        }],
                    })
                finally:
                    completed += 1
                    refresh_progress(name, ok)

        try:
            await asyncio.gather(*(scan_one(i) for i in instances))
        except asyncio.CancelledError:
            logger.info("Fleet scan cancelled after %d/%d", completed, total)
            self._set_progress("")
            self._scanning = False
            self.app.notify("Fleet scan cancelled.", severity="warning")
            return
        except Exception as exc:  # noqa: BLE001 — worker must not disappear
            logger.exception("Fleet scan crashed")
            self._set_progress("")
            self._scanning = False
            self.app.notify(
                f"Fleet scan crashed: {exc}",
                severity="error",
            )
            return
        finally:
            # Even if a rogue exception slips past, unstick the screen.
            if self._scanning:
                self._scanning = False

        self._set_progress("")
        self._launch_populate()
        self.app.notify(
            f"Fleet scan done: {len(succeeded)} ok, {len(failed)} failed."
        )
        if failed:
            self.app.push_screen(FleetScanSummaryModal(succeeded, failed))
