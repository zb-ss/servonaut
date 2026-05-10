"""Per-provider manager screen for Hetzner Cloud servers.

Mirrors :class:`servonaut.screens.snapshot_manager.SnapshotManagerScreen`
in shape — table + action toolbar + keyboard bindings — but scoped to
Hetzner instances and their lifecycle actions:

* Refresh
* New (opens :class:`HetznerCreateScreen`)
* Power on (boot a stopped server)
* Shutdown (graceful ACPI halt)
* Power off (hard cut)
* Reboot
* Delete (with typed-confirm modal)

Design intent: ``InstanceListScreen`` stays the unified "search and
SSH" surface across every provider. This screen is the per-provider
admin home — the place an operator goes to manage Hetzner inventory.
The two screens share no state; this one re-fetches via
``HetznerService.fetch_instances_cached`` so it always reflects fresh
truth even when the unified table's cache is stale.
"""

from __future__ import annotations

import logging
from typing import List, Optional, TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:
    from servonaut.app import ServonautApp


logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# State -> action eligibility
#
# Hetzner statuses we map to:
# * running        — power_off / shutdown / reboot allowed
# * stopped (off)  — power_on allowed
# * pending        — none allowed (transient state)
# * unknown/error  — none allowed
# ----------------------------------------------------------------------

_RUNNING = {"running"}
_STOPPED = {"stopped", "off"}


class HetznerManagerScreen(Screen):
    """Hetzner Cloud server manager — list + lifecycle toolbar."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("f5", "refresh", "Refresh", show=True),
        Binding("n", "new", "New", show=True),
        Binding("s", "power_on", "Start", show=True),
        Binding("t", "shutdown", "Shutdown", show=True),
        Binding("b", "reboot", "Reboot", show=True),
        Binding("d", "delete", "Delete", show=True),
    ]

    @property
    def app(self) -> "ServonautApp":  # type: ignore[override]
        return super().app  # type: ignore[return-value]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def __init__(self) -> None:
        super().__init__()
        self._instances: List[dict] = []
        self._loading: bool = False

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static(
                    "[bold cyan]Hetzner Cloud Manager[/bold cyan]",
                    id="hetzner_mgr_header",
                ),
                Static(
                    "[dim]Click a row, then use the keys below or the action "
                    "buttons. State-aware: Start only enables on stopped "
                    "servers, Stop/Reboot only on running ones.[/dim]",
                    id="hetzner_mgr_hint",
                ),
                DataTable(
                    id="hetzner_mgr_table",
                    zebra_stripes=True,
                    cursor_type="row",
                ),
                Static("", id="hetzner_mgr_status"),
                Horizontal(
                    Button("Refresh (F5)", id="btn_hetzner_mgr_refresh"),
                    Button(
                        "+ New (n)", variant="primary",
                        id="btn_hetzner_mgr_new",
                    ),
                    Button(
                        "Start (s)", id="btn_hetzner_mgr_power_on",
                        disabled=True,
                    ),
                    Button(
                        "Shutdown (t)", id="btn_hetzner_mgr_shutdown",
                        disabled=True,
                    ),
                    Button(
                        "Power off",
                        id="btn_hetzner_mgr_power_off",
                        disabled=True,
                    ),
                    Button(
                        "Reboot (b)", id="btn_hetzner_mgr_reboot",
                        disabled=True,
                    ),
                    Button(
                        "Delete (d)", variant="error",
                        id="btn_hetzner_mgr_delete",
                        disabled=True,
                    ),
                    id="hetzner_mgr_actions",
                ),
                id="hetzner_mgr_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#hetzner_mgr_table", DataTable)
        table.add_columns(
            "#", "Name", "ID", "Type", "State", "Public IP",
            "Region", "Created",
        )
        self._refresh()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if self._loading:
            return
        svc = getattr(self.app, "hetzner_service", None)
        if svc is None:
            self._set_status(
                "[red]Hetzner Cloud is not configured. "
                "Visit Settings → Hetzner Cloud to set up a token.[/red]"
            )
            return
        self._loading = True
        self._set_status("[dim]Loading servers…[/dim]")
        self.run_worker(
            self._load_instances(),
            exclusive=True,
            name="hetzner_mgr_load",
        )

    async def _load_instances(self) -> None:
        svc = self.app.hetzner_service
        try:
            instances = await svc.fetch_instances_cached(force_refresh=True)
            self._instances = list(instances)
            self._render_table()
            n = len(instances)
            if n == 0:
                self._set_status(
                    "[dim]No servers in this project. Press [b]n[/b] to "
                    "create one.[/dim]"
                )
            else:
                self._set_status(
                    f"[dim]{n} server{'s' if n != 1 else ''}.[/dim]"
                )
        except Exception as exc:
            logger.error("Failed to load Hetzner servers: %s", exc)
            self._set_status(
                f"[red]Failed to load servers: {self._short_err(exc)}[/red]"
            )
        finally:
            self._loading = False

    def _render_table(self) -> None:
        table = self.query_one("#hetzner_mgr_table", DataTable)
        table.clear()
        for idx, inst in enumerate(self._instances, start=1):
            table.add_row(
                str(idx),
                str(inst.get("name", "")),
                str(inst.get("id", "")),
                str(inst.get("type", "")),
                self._colorize_state(str(inst.get("state", ""))),
                str(inst.get("public_ip", "") or "—"),
                str(inst.get("region", "")),
                str(inst.get("created_at", "") or "—")[:19],
                key=str(inst.get("id", idx)),
            )
        self._sync_action_buttons()

    @staticmethod
    def _colorize_state(state: str) -> str:
        s = state.lower()
        if s in _RUNNING:
            return f"[green]{state}[/green]"
        if s in _STOPPED:
            return f"[yellow]{state}[/yellow]"
        if s in {"pending", "starting", "stopping", "rebuilding"}:
            return f"[blue]{state}[/blue]"
        if s == "error":
            return f"[red]{state}[/red]"
        return state

    # ------------------------------------------------------------------
    # Selection-driven button enablement
    # ------------------------------------------------------------------

    def on_data_table_row_highlighted(self, event) -> None:
        self._sync_action_buttons()

    def _selected_instance(self) -> Optional[dict]:
        table = self.query_one("#hetzner_mgr_table", DataTable)
        row = table.cursor_row
        if row < 0 or row >= len(self._instances):
            return None
        return self._instances[row]

    def _sync_action_buttons(self) -> None:
        """Toggle button enabled state based on the selected row's state.

        State machine (Hetzner statuses):
        * ``running``  → shutdown / power_off / reboot enabled
        * ``stopped``  → power_on enabled
        * other        → only delete enabled (and not always — pending
                         servers reject delete with a transient error,
                         but we let the user try; the audit row will
                         capture the failure cleanly).
        """
        inst = self._selected_instance()
        state = (inst.get("state", "") if inst else "").lower()

        is_running = state in _RUNNING
        is_stopped = state in _STOPPED

        for btn_id, enable in (
            ("btn_hetzner_mgr_power_on", inst is not None and is_stopped),
            ("btn_hetzner_mgr_shutdown", inst is not None and is_running),
            ("btn_hetzner_mgr_power_off", inst is not None and is_running),
            ("btn_hetzner_mgr_reboot", inst is not None and is_running),
            ("btn_hetzner_mgr_delete", inst is not None),
        ):
            try:
                self.query_one(f"#{btn_id}", Button).disabled = not enable
            except Exception:  # pragma: no cover - defensive
                pass

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        mapping = {
            "btn_hetzner_mgr_refresh": self.action_refresh,
            "btn_hetzner_mgr_new": self.action_new,
            "btn_hetzner_mgr_power_on": self.action_power_on,
            "btn_hetzner_mgr_shutdown": self.action_shutdown,
            "btn_hetzner_mgr_power_off": self.action_power_off,
            "btn_hetzner_mgr_reboot": self.action_reboot,
            "btn_hetzner_mgr_delete": self.action_delete,
        }
        handler = mapping.get(event.button.id or "")
        if handler is not None:
            handler()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._refresh()

    def action_new(self) -> None:
        if getattr(self.app, "hetzner_service", None) is None:
            self.notify(
                "Hetzner is not configured. Visit Settings → Hetzner Cloud.",
                severity="warning", markup=False,
            )
            return
        from servonaut.screens.hetzner_create import HetznerCreateScreen
        self.app.push_screen(HetznerCreateScreen())

    def action_power_on(self) -> None:
        self._run_lifecycle("power_on", "Starting", "started")

    def action_shutdown(self) -> None:
        self._run_lifecycle("shutdown", "Shutting down", "shutdown sent")

    def action_power_off(self) -> None:
        self._run_lifecycle("power_off", "Powering off", "powered off")

    def action_reboot(self) -> None:
        self._run_lifecycle("reboot", "Rebooting", "reboot sent")

    def action_delete(self) -> None:
        inst = self._selected_instance()
        if inst is None:
            return
        self.run_worker(
            self._do_delete(inst),
            exclusive=True,
            name="hetzner_mgr_delete",
        )

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    def _run_lifecycle(
        self, method: str, in_progress_verb: str, done_verb: str,
    ) -> None:
        inst = self._selected_instance()
        if inst is None:
            return
        identifier = str(inst.get("id") or inst.get("name") or "")
        if not identifier:
            self.notify(
                "Selected row has no id/name to act on.",
                severity="warning", markup=False,
            )
            return
        self._set_status(
            f"[dim]{in_progress_verb} {inst.get('name', identifier)}…[/dim]"
        )
        self.run_worker(
            self._do_lifecycle(method, identifier, done_verb),
            exclusive=False,
            name=f"hetzner_mgr_{method}",
        )

    async def _do_lifecycle(
        self, method: str, identifier: str, done_verb: str,
    ) -> None:
        svc = self.app.hetzner_service
        try:
            await getattr(svc, method)(identifier)
        except Exception as exc:
            logger.error(
                "Hetzner %s failed for %s: %s", method, identifier, exc,
            )
            self._set_status(
                f"[red]{method} failed: {self._short_err(exc)}[/red]"
            )
            self.notify(
                f"{method} failed: {exc}",
                severity="error", markup=False,
            )
            return
        self.notify(
            f"Server {identifier}: {done_verb}.",
            severity="information", markup=False,
        )
        # Re-fetch so the table reflects the new state (running/stopped).
        await self._load_instances()

    async def _do_delete(self, inst: dict) -> None:
        identifier = str(inst.get("id") or inst.get("name") or "")
        from servonaut.screens.confirm_action import ConfirmActionScreen
        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Delete Hetzner Server",
                description=(
                    f"Delete [bold]{inst.get('name', identifier)}[/bold] "
                    f"([bold]{inst.get('type', '')}[/bold]) in "
                    f"[bold]{inst.get('region', '')}[/bold]?"
                ),
                consequences=[
                    "All data on the server will be permanently destroyed",
                    "Any associated public IPs will be released",
                    "Billing for this server stops immediately",
                ],
                confirm_text="delete",
                action_label="Delete Server",
                severity="danger",
            )
        )
        if not confirmed:
            return

        self._set_status(
            f"[dim]Deleting {inst.get('name', identifier)}…[/dim]"
        )
        svc = self.app.hetzner_service
        try:
            await svc.delete_server(identifier)
        except Exception as exc:
            logger.error(
                "Hetzner delete failed for %s: %s", identifier, exc,
            )
            self._set_status(
                f"[red]Delete failed: {self._short_err(exc)}[/red]"
            )
            self.notify(
                f"Delete failed: {exc}",
                severity="error", markup=False,
            )
            return
        self.notify(
            f"Server {identifier} deleted.",
            severity="information", markup=False,
        )
        await self._load_instances()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_status(self, text: str) -> None:
        try:
            self.query_one("#hetzner_mgr_status", Static).update(text)
        except Exception:  # pragma: no cover - defensive
            pass

    @staticmethod
    def _short_err(exc: Exception) -> str:
        msg = str(exc)
        return msg if len(msg) <= 200 else msg[:197] + "…"
