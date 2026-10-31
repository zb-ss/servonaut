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
from textual.widgets import Button, DataTable, Footer, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens._demo_resolve import connection_instance, real_instance_id
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.sidebar import Sidebar
from servonaut.services.memory.fleet_scan_service import row_reason_text
from servonaut.services.memory.provider import instance_provider
from servonaut.services.memory.team_fold import folded_share_ids, memory_fleet_rows
from servonaut.utils.instance_resolver import display_name

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

#: Status of a team's shared server that has no local record: its age and
#: module count come from the team's list. Local to this screen, because it
#: is not a state the scan service produces.
STATUS_SHARED = "shared"

_STATUS_CELL: Dict[str, str] = {
    STATUS_FRESH: "[green]● Fresh[/green]",
    STATUS_STALE: "[yellow]● Stale[/yellow]",
    STATUS_NONE: "[dim]○ Not probed[/dim]",
    STATUS_OPT_OUT: "[red]⛔ Opted-out[/red]",
    # A server a team shares, read from the team's copy (read-only).
    STATUS_SHARED: "[blue]● Shared[/blue]",
}

# Source column rendering (width 8)
_SOURCE_CELL: Dict[str, str] = {
    "local": "[dim]local[/dim]",
    "remote": "[blue]cloud[/blue]",
    "merged": "[green]synced[/green]",
    "team": "[blue]team[/blue]",
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

    # Nothing skipped unless the summary says so: a modal built without the
    # argument (or by an older caller) still renders.
    _skipped: List[str] = []

    def __init__(
        self,
        succeeded: List[str],
        failed: List[Dict[str, Any]],
        skipped: Optional[List[str]] = None,
    ) -> None:
        """Initialise the summary.

        Args:
            succeeded: Instance identifiers whose scan produced ≥1 module.
            failed: ``[{"instance": <name>, "reason": <code>, "failures":
                [{module, reason, message}, …]}]`` for failed scans.
            skipped: Servers not probed because they are stopped.
        """
        super().__init__()
        self._succeeded = succeeded
        self._failed = failed
        self._skipped = skipped or []

    def compose(self) -> ComposeResult:
        total = len(self._succeeded) + len(self._failed) + len(self._skipped)
        skipped_text = (
            f", [dim]{len(self._skipped)} skipped: stopped[/dim]" if self._skipped else ""
        )
        yield Container(
            Static(
                f"[bold $text-accent]Fleet scan complete[/bold $text-accent] — "
                f"[$text-success]{len(self._succeeded)} succeeded[/$text-success], "
                f"[$text-error]{len(self._failed)} failed[/$text-error]"
                f"{skipped_text} ({total} total)",
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
            lines.append("[$text-success]Succeeded[/$text-success]:")
            for name in self._succeeded:
                lines.append(f"  • {escape(name)}")
            lines.append("")
        if self._failed:
            lines.append("[$text-error]Failed[/$text-error]:")
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
        if self._skipped:
            lines.append("")
            lines.append("[dim]Skipped: stopped[/dim]:")
            for name in self._skipped:
                lines.append(f"  • {escape(name)}")
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
        yield SafeHeader()
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
        table.add_column("Last scan", key="reason", width=20)
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
            self._set_progress("[$text-accent]Fleet scan in progress…[/$text-accent]")

    # ------------------------------------------------------------------
    # Data / populate
    # ------------------------------------------------------------------

    def refresh_after_demo_toggle(self) -> None:
        """Re-populate the fleet rows so names and ids follow the demo toggle."""
        self._launch_populate()

    _SHARED_KEYS = ("source", "status", "modules", "age")

    def _shared_fields(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Row fields from a team's list, for a shared server with no local record.

        Reads only what the reader already holds: a redraw never asks the
        service. Empty when the server has a local record or no team lists it.
        """
        inst = row.get("instance") or {}
        reader = getattr(self.app, "shared_memory_reader", None)
        if reader is None or row.get("status") in (STATUS_FRESH, STATUS_STALE):
            return {}
        candidates = row.get("grant_candidates") or []
        if not candidates and (own := self._share_candidate(inst)) is not None:
            candidates = [own]
        listings = [
            found for c in candidates
            if (found := reader.cached_listing(c.team_slug, c.instance_id)) is not None
        ]
        if not listings:
            return {}
        # Every grant adds what it covers: count each module once.
        names = {m for found in listings for m in found.modules}
        count = len(names) if names else max(found.module_count for found in listings)
        newest = max((found.last_probe_at for found in listings), default="")
        return {
            "source": "team",
            "status": STATUS_SHARED,
            "modules": count,
            "age": _human_age(newest) if newest else "—",
        }

    def _share_candidate(self, inst: Dict[str, Any]) -> Any:
        """The team and owner's instance id behind a shared row, else None."""
        from servonaut.services.memory.shared_view import share_candidates

        real = connection_instance(self.app, inst)
        if not isinstance(real, dict) or real.get("is_shared") is not True:
            return None
        found = share_candidates(real, [])
        return found[0] if found else None

    async def _prefetch_shared_listings(self) -> None:
        """Ask once per team what it shares, then bring the rows in line.

        Runs when the screen fills or refreshes, never on a redraw; the
        service call is reused for ``memory.team_memory_cache_seconds``.
        """
        reader = getattr(self.app, "shared_memory_reader", None)
        if reader is None:
            return
        slugs = {
            c.team_slug
            for row in self._rows
            if not row.get("memory_only")
            and (c := self._share_candidate(row.get("instance") or {})) is not None
        }
        await reader.prefetch_all(extra_slugs=sorted(slugs))
        self._sync_shared_rows()

    def _sync_shared_rows(self) -> None:
        """Make the rows match the reader's listings, revocations included.

        Existing rows gain, update or lose their shared look; a grant with no
        row of its own gets a read-only, memory-only row; there is one row
        per server however many teams list it.
        """
        reader = getattr(self.app, "shared_memory_reader", None)
        if reader is None:
            return
        from servonaut.services.memory.shared_view import ShareCandidate

        listings = reader.cached_listings()
        by_id: Dict[str, List[Any]] = {}
        for (_slug, instance_id), listing in sorted(listings.items()):
            if instance_id:
                by_id.setdefault(instance_id, []).append(ShareCandidate(
                    listing.team_slug, listing.team_name, instance_id))
        self._rows = [r for r in self._rows if not r.get("memory_only")]
        seen: set = set()
        for row in self._rows:
            inst = row.get("instance") or {}
            own = self._share_candidate(inst)
            ids = {str(row.get("raw_id") or ""), str(inst.get("instance_id") or "")}
            if own is not None:
                ids.add(own.instance_id)
            # Every grant that covers this server stays on its one row.
            found = [c for i in sorted(ids) for c in by_id.get(i, [])]
            if found:
                row["grant_candidates"] = found
            else:
                row.pop("grant_candidates", None)
            self._decorate_shared(row)
            seen.update(i for i in ids if i)
        for instance_id, candidates in by_id.items():
            if instance_id not in seen:
                first = listings[(candidates[0].team_slug, instance_id)]
                self._rows.append(self._memory_only_row(first, candidates))
        self._redraw_table()

    def _decorate_shared(self, row: Dict[str, Any]) -> None:
        """Give *row* its shared look, or take it away, keeping its own fields.

        The row's own fields are captured before the first decoration, so a
        revoked share restores what the row really was (local or cloud).
        """
        fields = self._shared_fields(row)
        if fields:
            row.setdefault("_before_share", {k: row.get(k) for k in self._SHARED_KEYS})
            for key, value in fields.items():
                row[key] = value
        elif "_before_share" in row:
            for key, value in row.pop("_before_share").items():
                row[key] = value

    def _memory_only_row(self, listing: Any, candidates: List[Any]) -> Dict[str, Any]:
        """A read-only row for a server a team shares that the user does not list."""
        from servonaut.services.memory.shared_view import apply_display_names

        real_id = listing.instance_id
        instance: Dict[str, Any] = {
            "is_shared": True, "state": "shared", "memory_only": True,
            # The real values; what is shown is derived from them (and from
            # demo mode) by apply_display_names, also while a screen is open.
            "real_id": real_id,
            "real_name": str(listing.instance.get("display_name") or real_id),
            "real_provider": str(listing.instance.get("provider") or "shared"),
            "team_slug": listing.team_slug, "team_name": listing.team_name,
            "instance_id": real_id, "grant_candidates": list(candidates),
        }
        apply_display_names(instance, self.app)
        shown_id, name, provider = instance["id"], instance["name"], instance["provider"]
        return {
            "grant_candidates": list(candidates),
            "instance": instance, "id": shown_id, "name": name, "provider": provider,
            "raw_id": real_id, "raw_provider": "shared", "source": "team",
            "status": STATUS_SHARED,
            "modules": len({m for c in candidates
                            if (found := self.app.shared_memory_reader.cached_listing(
                                c.team_slug, c.instance_id)) is not None
                            for m in found.modules}) or listing.module_count,
            "drift_7d": 0,
            "age": _human_age(listing.last_probe_at) if listing.last_probe_at else "—",
            "reason": "—", "memory_only": True,
        }

    def _redraw_table(self) -> None:
        """Draw ``self._rows`` again (cursor kept), without rebuilding them."""
        try:
            table = self.query_one("#fleet-memory-table", DataTable)
            cursor = table.cursor_row
            table.clear()
            for row in self._rows:
                table.add_row(
                    escape(str(row["name"])),
                    escape(str(row["id"])),
                    escape(str(row["provider"])),
                    _SOURCE_CELL.get(row.get("source", "local"), "[dim]local[/dim]"),
                    _STATUS_CELL.get(row["status"], "—"),
                    str(row["modules"]) if row["modules"] else "—",
                    str(row["drift_7d"]) if row.get("drift_7d") else "—",
                    row["age"],
                    row["reason"],
                )
            if self._rows and cursor is not None:
                table.move_cursor(row=min(cursor, len(self._rows) - 1))
            self.query_one("#fleet-memory-status", Static).update(
                self._summary_line_from_rows(self._rows)
            )
        except Exception:  # noqa: BLE001 — the screen was left meanwhile
            return

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
            merged = await fleet_service.get_merged_fleet(
                hidden_ids=folded_share_ids(self.app)
            )
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

    def _reason_cell(self, raw_id: str) -> str:
        """Cell text for why the row's latest scan did not succeed, or ``—``.

        The reason stays on the scan service until that row is probed again,
        so it survives table rebuilds and leaving the panel.
        """
        scan_service = getattr(self.app, "fleet_scan_service", None)
        reasons = getattr(scan_service, "last_reasons", None)
        if not isinstance(reasons, dict):
            return "—"
        # The scan files a reason under the id of the row it probed, which in
        # demo mode is a stand-in; the merged table asks with the real id.
        # Both are compared by their real id, so no path needs the other's.
        wanted = real_instance_id(self.app, raw_id)
        code = reasons.get(raw_id, "") or next(
            (
                value for key, value in reasons.items()
                if real_instance_id(self.app, key) == wanted
            ),
            "",
        )
        text = row_reason_text(code)
        return f"[red]{text}[/red]" if text else "—"

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
            if inst.get("account_qualified"):
                # A listed server of a provider with several accounts.
                iname = display_name(inst)
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

            row = {
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
                "reason": self._reason_cell(raw_iid),
            }
            self._decorate_shared(row)
            self._rows.append(row)

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
                row["reason"],
            )

        self.query_one("#fleet-memory-status", Static).update(
            self._summary_line_from_rows(self._rows)
        )
        self._start_shared_prefetch()

    def _start_shared_prefetch(self) -> None:
        """Look up the team-shared rows without blocking the table."""
        if getattr(self.app, "shared_memory_reader", None) is None:
            return
        self.run_worker(
            self._prefetch_shared_listings(),
            name="fleet_memory_shared",
            group="memory_shared_listing",
            exclusive=True,
        )

    def _populate_table(self) -> None:
        """Rebuild table rows + status footer from local app state (no remote)."""
        memory_service = getattr(self.app, "memory_service", None)
        instances = memory_fleet_rows(self.app)

        self._rows = []
        for inst in instances:
            iid = inst.get("id") or inst.get("name", "")
            iname = display_name(inst) if inst.get("account_qualified") else inst.get("name", iid)
            provider = instance_provider(inst)
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

            row = {
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
                "reason": self._reason_cell(iid),
            }
            self._decorate_shared(row)
            self._rows.append(row)

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
                row["reason"],
            )

        # Status footer — one glance tells the operator where to act.
        self.query_one("#fleet-memory-status", Static).update(
            self._summary_line_from_rows(self._rows)
        )
        self._start_shared_prefetch()

    # ------------------------------------------------------------------
    # Summary helpers (shared between populate paths and live updater)
    # ------------------------------------------------------------------

    @staticmethod
    def _summary_line_from_rows(rows: List[Dict[str, Any]]) -> str:
        """Return the Rich-markup summary footer from the current ``_rows`` list.

        Counts statuses directly from the rows so the live-update path and
        the post-populate path can't drift.
        """
        fresh = stale = none_count = opt_out = shared = 0
        for row in rows:
            s = row.get("status", STATUS_NONE)
            if s == STATUS_SHARED:
                shared += 1
            elif s == STATUS_FRESH:
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
            f"[$text-success]{fresh} fresh[/$text-success]  ·  "
            f"[$text-warning]{stale} stale[/$text-warning]  ·  "
            f"{none_count} not probed  ·  "
            f"[$text-error]{opt_out} opted-out[/$text-error]"
            + (f"  ·  {shared} shared by a team" if shared else "")
            + "[/dim]"
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
        # The app's own record, so demo mode keeps redacting what the screen
        # shows; the grants found for it ride along separately.
        self.app.push_screen(
            MemoryScreen(row["instance"], grant_candidates=row.get("grant_candidates"))
        )

    def action_share_selected(self) -> None:
        row = self._selected_row()
        if not row:
            self.app.notify("Select a row first.", severity="warning")
            return
        if row.get("memory_only"):
            self.app.notify("This server is shared by a team and is read-only.", severity="warning")
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
        if row.get("memory_only"):
            self.app.notify("This server is shared by a team and is read-only.", severity="warning")
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
        instances = memory_fleet_rows(self.app)
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

    def _only_stopped_candidates(self, stale_only: bool) -> bool:
        """True when the fleet has servers the scan would skip as stopped."""
        scan_service = getattr(self.app, "fleet_scan_service", None)
        skipped = getattr(scan_service, "skipped_instances", None)
        if not callable(skipped):
            return False
        return bool(skipped(memory_fleet_rows(self.app), stale_only=stale_only))

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
        if not instances and self._only_stopped_candidates(stale_only):
            # Nothing to probe, but the scan still records which servers it
            # skipped and why; it starts no connection.
            self._scanning = self.app.start_fleet_manual_scan(
                memory_fleet_rows(self.app), stale_only=stale_only
            )
            return
        if not instances:
            msg = (
                "No stale memory to refresh."
                if stale_only
                else "No instances available to scan."
            )
            self.app.notify(msg, markup=False)
            return

        self._set_progress(
            f"[$text-accent]Scanning 0 / {len(instances)}[/$text-accent]  "
            f"[dim](parallel: {_MAX_PARALLEL_FLEET_PROBES})[/dim]"
        )
        logger.info("Fleet scan launched: %d instance(s), stale_only=%s",
                    len(instances), stale_only)
        # The scan is APP-owned (group "memory_manual_scan") so it SURVIVES
        # leaving this panel and finishes in the background; progress and the
        # completion hook are routed back to whichever Fleet Memory screen is
        # mounted via the app's _fleet_manual_scan_progress / on_fleet_manual_scan_done.
        started = self.app.start_fleet_manual_scan(
            memory_fleet_rows(self.app), stale_only=stale_only
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
        colour = "$text-success" if progress.succeeded else "$text-error"
        self._set_progress(
            f"[$text-accent]Scanning {progress.completed} / {progress.total}[/$text-accent]  "
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
        if row.get("status") == STATUS_SHARED and new_status not in (STATUS_FRESH, STATUS_STALE):
            return  # still only the team's copy: nothing new to show

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
        row["reason"] = self._reason_cell(raw_id)

        # Update visible table cells (columns 4=status, 5=modules, 7=age, 8=last scan).
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
            table.update_cell_at(Coordinate(row_index, 8), row["reason"])
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
                memory_fleet_rows(self.app),
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
            f"Fleet scan done: {result.summary_text()}.",
            markup=False,
        )
        if result.failed:
            self.app.push_screen(
                FleetScanSummaryModal(
                    result.succeeded, result.failed, getattr(result, "skipped", None)
                )
            )

    def on_fleet_auto_scan_done(self, result: Any) -> None:
        """Quiet completion hook for a background auto-scan cycle.

        Called (duck-typed) by ``app._refresh_fleet_panels_after_scan`` when a
        background cycle finishes and this screen is mounted.  Unlike
        :meth:`on_fleet_manual_scan_done` it never pushes the summary modal — a
        background cycle must not interrupt the user with a dialog — it only
        clears the progress line, updates the auto-scan status line (so the
        countdown reflects the just-completed run), and repopulates the table.
        """
        self._set_progress("")
        self._refresh_auto_scan_status()
        self._launch_populate()

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
                FleetScanSummaryModal(
                    result.succeeded, result.failed, getattr(result, "skipped", None)
                )
            )

    # ------------------------------------------------------------------
    # C5: Auto-scan status indicator + quick toggle
    # ------------------------------------------------------------------

    def _auto_scan_status_text(self) -> str:
        """Return the markup string describing current auto-scan state.

        ON:  ``[$text-success]● Auto-scan on · next in ~Xh[/$text-success]``
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
            return "[$text-success]● Auto-scan on · scheduled[/$text-success]"

        seconds_until = max(0.0, (last_run + interval) - time.time())
        hours_until = int(seconds_until // 3600)
        return f"[$text-success]● Auto-scan on · next in ~{hours_until}h[/$text-success]"

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
