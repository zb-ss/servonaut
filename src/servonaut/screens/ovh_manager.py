"""Per-provider manager screen for OVHcloud instances.

Mirrors :class:`servonaut.screens.hetzner_manager.HetznerManagerScreen`
in shape and intent, but adapts to OVH's three resource types:

* ``cloud``     — Public Cloud instances (start / stop / reboot / delete /
                  create supported)
* ``vps``       — Managed VPS (start / stop / reboot — no create / delete
                  in this UI; lifecycle is owned by OVH's billing flow)
* ``dedicated`` — bare-metal (reboot only — start/stop don't apply)

The toolbar enables actions per row based on the row's
``provider_type`` and ``state``. Routing through OVH's API surface is
done by :class:`servonaut.services.ovh_service.OVHService` which already
encodes the per-type endpoints; this screen is thin glue + UX state.

Why not a single all-providers manager? OVH's lifecycle surface is
genuinely different per resource type (no one-size endpoint), and the
``cloud`` subset is what most users churn day-to-day. A dedicated
screen keeps the per-row eligibility logic readable.
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


_RUNNING = {"running", "active"}
_STOPPED = {"stopped", "shutoff", "off"}

# Which OVH provider types support which actions. Drives toolbar
# enablement so the user never tries an action the API will reject.
_SUPPORTS_START_STOP = {"vps", "cloud"}
_SUPPORTS_REBOOT = {"vps", "cloud", "dedicated"}
_SUPPORTS_DELETE = {"cloud"}
_SUPPORTS_CREATE_HERE = "cloud"


class OVHManagerScreen(Screen):
    """OVHcloud instance manager — list + lifecycle toolbar."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("f5", "refresh", "Refresh", show=True),
        Binding("n", "new", "New", show=True),
        Binding("s", "start", "Start", show=True),
        Binding("t", "stop", "Stop", show=True),
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
                    "[bold cyan]OVHcloud Manager[/bold cyan]",
                    id="ovh_mgr_header",
                ),
                Static(
                    "[dim]Click a row, then use the keys below or the action "
                    "buttons. State-aware: Start/Stop/Reboot only enable on "
                    "VPS and Cloud rows; Reboot also works on dedicated. "
                    "Create is Cloud-only and starts new billing immediately.[/dim]",
                    id="ovh_mgr_hint",
                ),
                DataTable(
                    id="ovh_mgr_table",
                    zebra_stripes=True,
                    cursor_type="row",
                ),
                Static("", id="ovh_mgr_status"),
                Horizontal(
                    Button("Refresh (F5)", id="btn_ovh_mgr_refresh"),
                    Button(
                        "+ New Cloud (n)", variant="primary",
                        id="btn_ovh_mgr_new",
                    ),
                    Button(
                        "Start (s)", id="btn_ovh_mgr_start", disabled=True,
                    ),
                    Button(
                        "Stop (t)", id="btn_ovh_mgr_stop", disabled=True,
                    ),
                    Button(
                        "Reboot (b)", id="btn_ovh_mgr_reboot",
                        disabled=True,
                    ),
                    Button(
                        "Delete (d)", variant="error",
                        id="btn_ovh_mgr_delete",
                        disabled=True,
                    ),
                    id="ovh_mgr_actions",
                ),
                id="ovh_mgr_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#ovh_mgr_table", DataTable)
        table.add_columns(
            "#", "Name", "ID", "Type", "Kind", "State", "Public IP",
            "Region",
        )
        self._refresh()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if self._loading:
            return
        svc = getattr(self.app, "ovh_service", None)
        if svc is None:
            self._set_status(
                "[red]OVHcloud is not configured. "
                "Visit Settings → OVHcloud to set up credentials.[/red]"
            )
            return
        self._loading = True
        self._set_status("[dim]Loading instances…[/dim]")
        self.run_worker(
            self._load_instances(),
            exclusive=True,
            name="ovh_mgr_load",
        )

    async def _load_instances(self) -> None:
        svc = self.app.ovh_service
        try:
            instances = await svc.fetch_instances_cached(force_refresh=True)
            self._instances = list(instances)
            # Redact the fresh list in-place; OVH names are often FQDNs
            # (ns1.bigcorp.com) which are especially identifying.
            # Mirrors the app-startup redact_instances pattern.
            if self.app.demo_mode and self.app.redaction_service:
                self.app.redaction_service.redact_instances(self._instances)
            self._render_table()
            n = len(instances)
            if n == 0:
                self._set_status(
                    "[dim]No OVH instances. Press [b]n[/b] to create a "
                    "Public Cloud instance.[/dim]"
                )
            else:
                self._set_status(
                    f"[dim]{n} instance{'s' if n != 1 else ''}.[/dim]"
                )
        except Exception as exc:
            logger.error("Failed to load OVH instances: %s", exc)
            err_msg = self._short_err(exc)
            if self.app.demo_mode and self.app.redaction_service:
                err_msg = self.app.redaction_service.scrub_stream(err_msg)
            self._set_status(
                f"[red]Failed to load instances: {err_msg}[/red]"
            )
        finally:
            self._loading = False

    def _render_table(self) -> None:
        table = self.query_one("#ovh_mgr_table", DataTable)
        table.clear()
        for idx, inst in enumerate(self._instances, start=1):
            table.add_row(
                str(idx),
                str(inst.get("name", "")),
                str(inst.get("id", "")),
                str(inst.get("type", "")),
                str(inst.get("provider_type", "—")),
                self._colorize_state(str(inst.get("state", ""))),
                str(inst.get("public_ip", "") or "—"),
                str(inst.get("region", "")),
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
        if s in {"pending", "starting", "stopping", "rebuilding", "building"}:
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
        table = self.query_one("#ovh_mgr_table", DataTable)
        row = table.cursor_row
        if row < 0 or row >= len(self._instances):
            return None
        return self._instances[row]

    def _sync_action_buttons(self) -> None:
        """Toggle button enabled state per row's provider_type + state.

        Per-type rules (matches what OVHService routes through):
        * cloud:     start (when stopped), stop / reboot / delete (when running)
        * vps:       start (when stopped), stop / reboot (when running)
        * dedicated: reboot only — start/stop don't apply
        * other:     all disabled
        """
        inst = self._selected_instance()
        ptype = (inst.get("provider_type", "") if inst else "").lower()
        state = (inst.get("state", "") if inst else "").lower()

        is_running = state in _RUNNING
        is_stopped = state in _STOPPED

        for btn_id, enable in (
            ("btn_ovh_mgr_start",
             inst is not None and ptype in _SUPPORTS_START_STOP and is_stopped),
            ("btn_ovh_mgr_stop",
             inst is not None and ptype in _SUPPORTS_START_STOP and is_running),
            ("btn_ovh_mgr_reboot",
             inst is not None and ptype in _SUPPORTS_REBOOT
             and (is_running or ptype == "dedicated")),
            ("btn_ovh_mgr_delete",
             inst is not None and ptype in _SUPPORTS_DELETE),
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
            "btn_ovh_mgr_refresh": self.action_refresh,
            "btn_ovh_mgr_new": self.action_new,
            "btn_ovh_mgr_start": self.action_start,
            "btn_ovh_mgr_stop": self.action_stop,
            "btn_ovh_mgr_reboot": self.action_reboot,
            "btn_ovh_mgr_delete": self.action_delete,
        }
        handler = mapping.get(event.button.id or "")
        if handler is not None:
            handler()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._refresh()

    def action_new(self) -> None:
        if getattr(self.app, "ovh_cloud_service", None) is None:
            self.notify(
                "OVH Cloud service is not available.",
                severity="warning", markup=False,
            )
            return
        from servonaut.screens.ovh_cloud_create import OVHCloudCreateScreen
        self.app.push_screen(OVHCloudCreateScreen())

    def action_start(self) -> None:
        self._run_lifecycle("start_instance", "Starting", "started")

    def action_stop(self) -> None:
        self._run_lifecycle("stop_instance", "Stopping", "stop sent")

    def action_reboot(self) -> None:
        self._run_lifecycle("reboot_instance", "Rebooting", "reboot sent")

    def action_delete(self) -> None:
        inst = self._selected_instance()
        if inst is None:
            return
        ptype = (inst.get("provider_type", "") or "").lower()
        if ptype not in _SUPPORTS_DELETE:
            self.notify(
                f"Delete is not supported for OVH {ptype or 'unknown'} "
                "instances from this screen.",
                severity="warning", markup=False,
            )
            return
        self.run_worker(
            self._do_delete(inst),
            exclusive=True,
            name="ovh_mgr_delete",
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
        ptype = (inst.get("provider_type", "") or "").lower()
        identifier = str(inst.get("id") or "")
        if not identifier or not ptype:
            self.notify(
                "Selected row is missing id/provider_type to act on.",
                severity="warning", markup=False,
            )
            return

        # Pre-flight: catch the cases the underlying service would
        # reject anyway, but surface them with a clearer message here.
        if method in {"start_instance", "stop_instance"} and ptype not in _SUPPORTS_START_STOP:
            self.notify(
                f"{method[:-9]} is not supported for OVH {ptype}.",
                severity="warning", markup=False,
            )
            return
        if method == "reboot_instance" and ptype not in _SUPPORTS_REBOOT:
            self.notify(
                f"reboot is not supported for OVH {ptype}.",
                severity="warning", markup=False,
            )
            return

        self._set_status(
            f"[dim]{in_progress_verb} {inst.get('name', identifier)}…[/dim]"
        )
        self.run_worker(
            self._do_lifecycle(method, identifier, ptype, done_verb),
            exclusive=False,
            name=f"ovh_mgr_{method}",
        )

    async def _do_lifecycle(
        self, method: str, identifier: str, ptype: str, done_verb: str,
    ) -> None:
        svc = self.app.ovh_service
        try:
            await getattr(svc, method)(identifier, ptype)
        except Exception as exc:
            logger.error(
                "OVH %s failed for %s (%s): %s",
                method, identifier, ptype, exc,
            )
            err_msg = self._short_err(exc)
            if self.app.demo_mode and self.app.redaction_service:
                err_msg = self.app.redaction_service.scrub_stream(err_msg)
            self._set_status(
                f"[red]{method} failed: {err_msg}[/red]"
            )
            self.notify(
                f"{method} failed: {exc}",
                severity="error", markup=False,
            )
            return

        self._audit_action(method, identifier, ptype, success=True)
        self.notify(
            f"OVH {ptype} {identifier}: {done_verb}.",
            severity="information", markup=False,
        )
        await self._load_instances()

    async def _do_delete(self, inst: dict) -> None:
        ptype = (inst.get("provider_type", "") or "").lower()
        composite_id = str(inst.get("id") or "")
        # Cloud composite id is "<project_id>/<inst_id>" — split for the
        # OVHCloudService call which takes them separately.
        project_id, _, inst_id = composite_id.partition("/")
        if not project_id or not inst_id:
            self.notify(
                f"Cannot parse OVH cloud id {composite_id!r}.",
                severity="error", markup=False,
            )
            return

        from servonaut.screens.confirm_action import ConfirmActionScreen
        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Delete OVH Cloud Instance",
                description=(
                    f"Delete [bold]{inst.get('name', inst_id)}[/bold] "
                    f"([bold]{inst.get('type', '')}[/bold]) in project "
                    f"[bold]{project_id}[/bold]?"
                ),
                consequences=[
                    "All data on the instance will be permanently destroyed",
                    "Any attached IPs may be released and re-billed if not "
                    "previously reserved",
                    "Billing for this instance stops immediately",
                ],
                confirm_text="delete",
                action_label="Delete Instance",
                severity="danger",
            )
        )
        self._audit_action("cloud_delete", composite_id, ptype,
                           success=False, confirmed=bool(confirmed))
        if not confirmed:
            return

        self._set_status(
            f"[dim]Deleting {inst.get('name', inst_id)}…[/dim]"
        )
        cloud_svc = getattr(self.app, "ovh_cloud_service", None)
        if cloud_svc is None:
            self.notify(
                "OVH Cloud service is not available.",
                severity="error", markup=False,
            )
            return
        try:
            await cloud_svc.delete_instance(project_id, inst_id)
        except Exception as exc:
            logger.error("OVH delete failed for %s: %s", composite_id, exc)
            self._audit_action("cloud_delete", composite_id, ptype,
                               success=False, confirmed=True,
                               error=str(exc)[:200])
            err_msg = self._short_err(exc)
            if self.app.demo_mode and self.app.redaction_service:
                err_msg = self.app.redaction_service.scrub_stream(err_msg)
            self._set_status(
                f"[red]Delete failed: {err_msg}[/red]"
            )
            self.notify(
                f"Delete failed: {exc}",
                severity="error", markup=False,
            )
            return

        self._audit_action("cloud_delete", composite_id, ptype,
                           success=True, confirmed=True)
        self.notify(
            f"OVH instance {composite_id} deleted.",
            severity="information", markup=False,
        )
        await self._load_instances()

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def _audit_action(
        self,
        action: str,
        target: str,
        provider_type: str,
        *,
        success: bool,
        confirmed: bool = True,
        error: str = "",
    ) -> None:
        """Forward to the app's :class:`OVHAuditLogger` if present.

        Mirrors the pattern :class:`OVHCloudCreateScreen` already uses
        for ``cloud_create`` so the OVH audit trail captures the full
        lifecycle (create → start/stop/reboot/delete) in one log file.
        """
        ovh_audit = getattr(self.app, "ovh_audit", None)
        if ovh_audit is None:
            return
        details = {
            "provider_type": provider_type,
            "success": success,
        }
        if error:
            details["error"] = error
        try:
            ovh_audit.log_action(
                action=action,
                target=target,
                details=details,
                confirmed=confirmed,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to write OVH audit row: %s", exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_status(self, text: str) -> None:
        try:
            self.query_one("#ovh_mgr_status", Static).update(text)
        except Exception:  # pragma: no cover - defensive
            pass

    @staticmethod
    def _short_err(exc: Exception) -> str:
        msg = str(exc)
        return msg if len(msg) <= 200 else msg[:197] + "…"
