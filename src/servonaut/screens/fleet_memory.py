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
import dataclasses
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from servonaut.styles import CSS_FILES as _APP_CSS_FILES

from rich.markup import escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.coordinate import Coordinate
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Header, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar

# Status constants and classifier live in the dependency-free service module
# so that both the fleet scan service and this screen share one implementation.
# Re-exported here so existing importers (widgets/instance_table, tests, …)
# that do ``from servonaut.screens.fleet_memory import STATUS_*`` keep working.
from servonaut.services.memory.status import (
    STATUS_FRESH,
    STATUS_STALE,
    STATUS_NONE,
    STATUS_OPT_OUT,
    compute_memory_status,
    snapshot_age_seconds,
    _latest_probed_at,
    _resolve_stale_threshold,
)

if TYPE_CHECKING:  # pragma: no cover
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)

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
# Helpers (formatting — screen-local only)
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

    CSS_PATH = [*_APP_CSS_FILES, Path(__file__).parent.parent / "memory_screen.tcss"]

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("r", "refresh_view", "Refresh View", show=True),
        Binding("s", "scan_all", "Scan All", show=True),
        Binding("S", "share_selected", "Share", show=True),
        Binding("f", "refresh_stale", "Refresh Stale", show=True),
        Binding("enter", "open_selected", "Open", show=True),
        Binding("x", "clear_selected", "Clear", show=True),
        Binding("a", "toggle_auto_scan", "Toggle Auto-scan", show=True),
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
                # Auto-scan state indicator — updated on mount, after
                # manual scans, and after a refresh-view.
                Static("", id="fleet-auto-scan-status"),
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
                    Button("r. Refresh", id="btn_refresh_view"),
                    Button("enter. Open", id="btn_open"),
                    Button("x. Clear", id="btn_clear", variant="error"),
                    Button("a. Toggle Auto-scan", id="btn_toggle_auto_scan"),
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
        self._refresh_auto_scan_status()
        self._launch_populate()
        # Memory Sync unlock is offered HERE (on entering a memory section),
        # not on app boot — a passphrase modal on startup is too intrusive.
        # The app method is a no-op for free users, the unentitled, those who
        # never enrolled, and anyone who declined the prompt this session.
        # Run it as an app-owned worker so the modal survives navigating away
        # from this screen.
        prompt_unlock = getattr(self.app, "prompt_memory_sync_unlock", None)
        if prompt_unlock is not None:
            self.app.run_worker(
                prompt_unlock(),
                name="memory_sync_unlock_prompt",
                group="memory_reactivate",
                exclusive=True,
            )
        # If an app-owned manual scan is still running (e.g. the user left
        # this panel mid-scan and came back), surface it — the scan keeps
        # going in the background and routes progress here while mounted.
        if getattr(self.app, "_fleet_manual_scan_in_progress", False):
            self._scanning = True
            self._set_progress("[cyan]Fleet scan in progress…[/cyan]")

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
                # raw_id / raw_provider preserve the un-redacted keys for
                # memory-store lookups and for matching incoming progress
                # events (which carry the real instance_id).
                "raw_id": raw_iid,
                "raw_provider": raw_provider,
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

        self.query_one("#fleet-memory-status", Static).update(
            self._summary_line_from_rows(self._rows)
        )

    def _populate_table(self) -> None:
        """Rebuild table rows + status footer from local app state (no remote)."""
        memory_service = getattr(self.app, "memory_service", None)
        instances = self.app.instances or []

        self._rows = []
        for inst in instances:
            iid = inst.get("id") or inst.get("name", "")
            iname = inst.get("name", iid)
            provider = inst.get("provider", "custom") or "custom"
            status = compute_memory_status(inst, memory_service)

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
                # raw_id / raw_provider are the un-redacted keys used for
                # memory-store lookups (keyed by real IDs, not display IDs).
                # In the local path the instance dict is never redacted in-
                # place, so raw == display; we record them explicitly so the
                # live-update helper can always use the right key regardless
                # of which populate path populated the row.
                "raw_id": iid,
                "raw_provider": provider,
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
        self.query_one("#fleet-memory-status", Static).update(
            self._summary_line_from_rows(self._rows)
        )

    # ------------------------------------------------------------------
    # Summary helpers (shared between populate paths and live updater)
    # ------------------------------------------------------------------

    @staticmethod
    def _summary_line_from_rows(rows: List[Dict[str, Any]]) -> str:
        """Return the Rich-markup summary footer from the current ``_rows`` list.

        Counts statuses directly from the rows so the live-update path and
        the post-populate path can't drift.
        """
        fresh = stale = none_count = opt_out = 0
        for row in rows:
            s = row.get("status", STATUS_NONE)
            if s == STATUS_FRESH:
                fresh += 1
            elif s == STATUS_STALE:
                stale += 1
            elif s == STATUS_OPT_OUT:
                opt_out += 1
            else:
                none_count += 1
        total = len(rows)
        return (
            f"[dim]{total} instances  ·  "
            f"[green]{fresh} fresh[/green]  ·  "
            f"[yellow]{stale} stale[/yellow]  ·  "
            f"{none_count} not probed  ·  "
            f"[red]{opt_out} opted-out[/red][/dim]"
        )

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
        self._refresh_auto_scan_status()
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
            self.app.notify(f"Clear failed: {exc}", severity="error", markup=False)
            return
        self.app.notify(f"Cleared memory for {row['name']}.", markup=False)
        self._populate_table()

    def action_scan_all(self) -> None:
        self._launch_bulk_scan(stale_only=False)

    def action_refresh_stale(self) -> None:
        self._launch_bulk_scan(stale_only=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        mapping = {
            "btn_scan_all": self.action_scan_all,
            "btn_refresh_stale": self.action_refresh_stale,
            "btn_refresh_view": self.action_refresh_view,
            "btn_open": self.action_open_selected,
            "btn_clear": self.action_clear_selected,
            "btn_toggle_auto_scan": self.action_toggle_auto_scan,
        }
        handler = mapping.get(event.button.id or "")
        if handler:
            event.stop()
            handler()

    # ------------------------------------------------------------------
    # Bulk scan worker (C6: delegates to FleetScanService)
    # ------------------------------------------------------------------

    def _eligible_instances(
        self, stale_only: bool, memory_service: Any
    ) -> List[Dict[str, Any]]:
        """Return instances the scan should actually probe.

        Delegates to ``FleetScanService.eligible_instances`` when the service
        is available so the screen and service can't diverge on eligibility
        rules.  Falls back to an inline computation (same logic) when the
        service is not wired — used by pre-scan count display and legacy paths.
        """
        fleet_scan_service = getattr(self.app, "fleet_scan_service", None)
        instances = self.app.instances or []
        if fleet_scan_service is not None:
            return fleet_scan_service.eligible_instances(
                instances, stale_only=stale_only
            )
        # Inline fallback that mirrors the service logic.
        eligible: List[Dict[str, Any]] = []
        for inst in instances:
            status = compute_memory_status(inst, memory_service)
            if status == STATUS_OPT_OUT:
                continue
            if stale_only and status != STATUS_STALE:
                continue
            eligible.append(inst)
        return eligible

    def _launch_bulk_scan(self, stale_only: bool) -> None:
        memory_service = getattr(self.app, "memory_service", None)
        if memory_service is None:
            self.app.notify("Memory subsystem not wired.", severity="error")
            return
        if getattr(self.app, "_fleet_manual_scan_in_progress", False):
            self.app.notify("A fleet scan is already in progress.", severity="warning")
            return

        # Show a pre-scan count using eligible_instances so the user knows
        # what is about to be probed before the worker starts.
        # NOTE: start_fleet_manual_scan → fleet_scan_service.scan() will
        # call eligible_instances() a second time internally.  The double
        # pass is intentional: the count here is purely for the notification
        # toast; avoiding it would require passing the pre-filtered list
        # through start_fleet_manual_scan's interface, which adds API surface
        # for a minor optimisation (disk reads, not SSH).  If this becomes
        # measurable on very large fleets, hoist the list and thread it through.
        instances = self._eligible_instances(stale_only, memory_service)
        if not instances:
            msg = (
                "No stale memory to refresh."
                if stale_only
                else "No instances available to scan."
            )
            self.app.notify(msg)
            return

        self._set_progress(
            f"[cyan]Scanning 0 / {len(instances)}[/cyan]  "
            f"[dim](parallel: {_MAX_PARALLEL_FLEET_PROBES})[/dim]"
        )
        logger.info("Fleet scan launched: %d instance(s), stale_only=%s",
                    len(instances), stale_only)
        # The scan is APP-owned (group "memory_manual_scan") so it SURVIVES
        # leaving this panel and finishes in the background; progress and the
        # completion hook are routed back to whichever Fleet Memory screen is
        # mounted via the app's _fleet_manual_scan_progress / on_fleet_manual_scan_done.
        started = self.app.start_fleet_manual_scan(
            self.app.instances or [], stale_only=stale_only
        )
        if not started:
            self._set_progress("")
            self.app.notify("A fleet scan is already in progress.", severity="warning")
            return
        self._scanning = True
        self.app.notify(
            f"Scanning {len(instances)} instance(s) in the background — "
            "you can leave this panel and it will finish."
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

    def _on_scan_progress(
        self,
        progress: Any,  # FleetScanProgress from fleet_scan_service
    ) -> None:
        """Progress callback fired by FleetScanService after each probe.

        Applies demo-mode name redaction (the service uses raw names; redaction
        is a UI concern), updates the in-page progress line, and triggers a
        live cell update for the completed instance's row.
        """
        name = progress.instance_name
        # Demo-mode: scrub the instance name before displaying it.
        if self.app.demo_mode and self.app.redaction_service:
            try:
                name = self.app.redaction_service.redact_name(name)
            except Exception:
                pass
        colour = "green" if progress.succeeded else "red"
        self._set_progress(
            f"[cyan]Scanning {progress.completed} / {progress.total}[/cyan]  "
            f"·  [{colour}]last: {escape(name)} "
            f"{'✓' if progress.succeeded else '✗'}[/{colour}]"
        )
        # Live row update — flip Memory/Modules/Age cells for the just-probed
        # instance without waiting for the full scan to complete.
        self._update_row_for_instance(progress.instance_id)

    def _update_row_for_instance(self, instance_id: str) -> None:
        """Recompute and live-update the table cells for one instance's row.

        Called from :meth:`_on_scan_progress` after each probe completes so
        the Memory status column flips from Stale→Fresh (or Not probed→Fresh)
        in real time rather than waiting for the full scan to rebuild the table.

        Args:
            instance_id: The raw ``id`` value emitted by :class:`FleetScanProgress`.
                If empty or not found in ``_rows``, the method is a no-op.
        """
        if not instance_id or not self._rows:
            return

        # Find the row index whose raw_id matches the completed instance.
        # raw_id is stored un-redacted so matching against the service's
        # instance_id (also un-redacted) is always correct.
        # ASSUMPTION: raw_id is unique across rows.  Two custom servers with
        # no id and the same name would both have raw_id == name and only the
        # first would receive the live update.  The instance-list enforces
        # unique IDs (AWS: instance-id; custom: user-assigned name), so this
        # degenerate case should never arise in practice.
        row_index: Optional[int] = None
        for i, row in enumerate(self._rows):
            if row.get("raw_id", row.get("id", "")) == instance_id:
                row_index = i
                break
        if row_index is None:
            return

        memory_service = getattr(self.app, "memory_service", None)
        row = self._rows[row_index]
        inst = row.get("instance") or {"id": instance_id}
        raw_id = row.get("raw_id", row.get("id", instance_id))
        raw_provider = row.get("raw_provider", row.get("provider", "custom"))

        # Recompute status using the same helper as the populate paths.
        new_status = compute_memory_status(inst, memory_service)

        new_modules: Any = row.get("modules", 0)
        new_age: str = row.get("age", "—")
        if memory_service is not None and new_status in (STATUS_FRESH, STATUS_STALE):
            try:
                mods = memory_service.get_all_modules(raw_id, raw_provider)
            except Exception:
                mods = {}
            if mods:
                new_modules = len(mods)
                new_age = _human_age(_latest_probed_at(mods))

        # Update the in-memory row dict so subsequent summary recomputes and
        # a later action_refresh_view see the current state.
        row["status"] = new_status
        row["modules"] = new_modules
        row["age"] = new_age

        # Update visible table cells (columns 4=status, 5=modules, 7=age).
        try:
            table = self.query_one("#fleet-memory-table", DataTable)
            table.update_cell_at(
                Coordinate(row_index, 4),
                _STATUS_CELL.get(new_status, "—"),
            )
            table.update_cell_at(
                Coordinate(row_index, 5),
                str(new_modules) if new_modules else "—",
            )
            table.update_cell_at(
                Coordinate(row_index, 7),
                new_age,
            )
        except Exception:
            # Widget may be gone (screen navigated away during scan) — ignore.
            pass

        # Recompute the summary count line so fresh/stale totals track live.
        try:
            self.query_one("#fleet-memory-status", Static).update(
                self._summary_line_from_rows(self._rows)
            )
        except Exception:
            pass

    async def _do_bulk_scan(self, stale_only: bool, *_legacy_args: Any) -> None:
        """Delegate the fleet probe to FleetScanService (screen-scoped variant).

        NOTE: the production "Scan All" path is now app-owned via
        ``ServonautApp.start_fleet_manual_scan`` (so it survives navigation);
        this method is retained because the demo-mode redaction coverage test
        drives it directly to exercise the ``_on_scan_progress`` redaction path.

        The service handles concurrency (semaphore) and per-instance error
        recovery.  This method owns the screen lifecycle around the scan:
        progress display, scanning flag, post-scan modal, and table refresh.

        ``*_legacy_args`` is accepted but ignored.  It exists solely so that
        existing unit tests written against an earlier signature (which took
        ``instances`` and ``memory_service`` as positional args) continue to
        pass after the scanning logic was extracted into
        :class:`~servonaut.services.memory.fleet_scan_service.FleetScanService`.
        """
        fleet_scan_service = getattr(self.app, "fleet_scan_service", None)
        if fleet_scan_service is None:
            self._scanning = False
            self.app.notify("Fleet scan service not available.", severity="error")
            return

        try:
            result = await fleet_scan_service.scan(
                self.app.instances or [],
                stale_only=stale_only,
                on_progress=self._on_scan_progress,
            )
        except asyncio.CancelledError:
            logger.info("Fleet scan cancelled")
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
                markup=False,
            )
            return
        finally:
            # Even if a rogue exception slips past, unstick the screen.
            if self._scanning:
                self._scanning = False

        self._set_progress("")
        self._refresh_auto_scan_status()
        self._launch_populate()
        self.app.notify(
            f"Fleet scan done: {len(result.succeeded)} ok, "
            f"{len(result.failed)} failed."
        )
        if result.failed:
            self.app.push_screen(
                FleetScanSummaryModal(result.succeeded, result.failed)
            )

    def on_fleet_manual_scan_done(self, result: Any) -> None:
        """Completion hook invoked by the app-owned manual scan worker.

        The app calls this (duck-typed) when an app-owned manual fleet scan
        finishes AND this screen is the one currently mounted — so a scan the
        user launched then navigated away from still updates the table when
        they return.  The app already emits the "scan done" toast; this only
        refreshes the view and surfaces the failure summary.
        """
        self._scanning = False
        self._set_progress("")
        self._refresh_auto_scan_status()
        self._launch_populate()
        if getattr(result, "failed", None):
            self.app.push_screen(
                FleetScanSummaryModal(result.succeeded, result.failed)
            )

    # ------------------------------------------------------------------
    # C5: Auto-scan status indicator + quick toggle
    # ------------------------------------------------------------------

    def _auto_scan_status_text(self) -> str:
        """Return the Rich-markup string describing current auto-scan state.

        ON:  ``[green]● Auto-scan on · next in ~Xh[/green]``
             (or ``· scheduled`` when never run).
        OFF: ``[dim]○ Auto-scan off[/dim]``.

        No live-ticking timer — recomputed on mount, after refresh-view,
        and after a manual scan.
        """
        config_manager = getattr(self.app, "config_manager", None)
        if config_manager is None:
            return "[dim]○ Auto-scan off[/dim]"
        cfg = config_manager.get()
        memory_cfg = getattr(cfg, "memory", None)
        if memory_cfg is None or not memory_cfg.enabled or not memory_cfg.auto_scan_enabled:
            return "[dim]○ Auto-scan off[/dim]"

        last_run = getattr(self.app, "_fleet_auto_scan_last_run", 0.0)
        interval = getattr(memory_cfg, "auto_scan_interval_seconds", 86400)

        if last_run == 0.0:
            return "[green]● Auto-scan on · scheduled[/green]"

        seconds_until = max(0.0, (last_run + interval) - time.time())
        hours_until = int(seconds_until // 3600)
        return f"[green]● Auto-scan on · next in ~{hours_until}h[/green]"

    def _refresh_auto_scan_status(self) -> None:
        """Update the ``#fleet-auto-scan-status`` widget with current state."""
        try:
            widget = self.query_one("#fleet-auto-scan-status", Static)
        except Exception:
            return
        widget.update(self._auto_scan_status_text())

    def action_toggle_auto_scan(self) -> None:
        """Flip ``config.memory.auto_scan_enabled`` and persist.

        On enable: calls ``app._refresh_fleet_auto_scan_loop()`` which spawns
        the loop worker (idempotent via exclusive=True group).
        On disable: calls ``app._refresh_fleet_auto_scan_loop()`` which cancels
        the ``memory_auto_scan`` worker group promptly.
        """
        config_manager = getattr(self.app, "config_manager", None)
        if config_manager is None:
            self.app.notify("Configuration not available.", severity="error")
            return

        cfg = config_manager.get()
        memory_cfg = getattr(cfg, "memory", None)
        if memory_cfg is None:
            self.app.notify("Memory config not available.", severity="error")
            return

        new_enabled = not memory_cfg.auto_scan_enabled
        updated_memory = dataclasses.replace(
            memory_cfg, auto_scan_enabled=new_enabled
        )
        try:
            config_manager.update(memory=updated_memory)
        except Exception as exc:  # noqa: BLE001
            self.app.notify(f"Failed to save config: {exc}", severity="error", markup=False)
            return

        if new_enabled:
            interval_h = max(1, getattr(updated_memory, "auto_scan_interval_seconds", 86400) // 3600)
            self.app.notify(f"Auto-scan enabled — runs every ~{interval_h}h.")
        else:
            self.app.notify("Auto-scan disabled.")

        # Start or cancel the loop promptly based on the new flag.
        refresh_loop = getattr(self.app, "_refresh_fleet_auto_scan_loop", None)
        if refresh_loop is not None:
            refresh_loop()

        self._refresh_auto_scan_status()
