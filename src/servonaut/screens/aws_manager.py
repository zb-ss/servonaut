"""Per-provider manager screen for AWS EC2 instances.

Mirrors :class:`servonaut.screens.hetzner_manager.HetznerManagerScreen`
in shape and intent — table + action toolbar + keyboard bindings — but
adapts to EC2's lifecycle surface:

* Refresh
* New (opens :class:`AWSCreateScreen`)
* Start (boot a stopped instance)
* Stop (EBS-backed — graceful ACPI halt; instance-store NOT supported)
* Reboot (in-place reboot; instance keeps its IP)
* Terminate (permanent — data destroyed, billing stops)

Key difference from Hetzner: every EC2 lifecycle call requires BOTH the
``instance_id`` AND the ``region`` (EC2 API is region-scoped, unlike
Hetzner's global endpoint). :meth:`_do_lifecycle` reads the region from
the selected instance dict so it is never lost across the call boundary.

Terminated instances linger in the EC2 console for ~1 h with state
``terminated`` or ``shutting-down``; the toolbar disables all actions
for those rows so the user cannot double-terminate.

Design intent: :class:`InstanceListScreen` is the unified search-and-SSH
surface. This screen is the EC2 admin home — the place an operator goes
to manage EC2 inventory beyond what the instance list offers.
"""

from __future__ import annotations

import logging
from typing import List, Optional, TYPE_CHECKING

from rich.markup import escape as markup_escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.utils.formatting import escape_cell
from servonaut.widgets.sidebar import Sidebar

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# State → action eligibility
#
# EC2 statuses we map to:
# * running                — stop / reboot allowed
# * stopped                — start allowed
# * terminated/shutting-down — no actions (terminal state; linger ~1 h)
# * pending/stopping/...  — none allowed (transient state)
# ---------------------------------------------------------------------------

_RUNNING = {"running"}
_STOPPED = {"stopped"}
# Terminal states — disable every action button
_TERMINAL = {"terminated", "shutting-down"}


class AWSManagerScreen(Screen):
    """AWS EC2 instance manager — list + lifecycle toolbar."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("f5", "refresh", "Refresh", show=True),
        Binding("n", "new", "New", show=True),
        Binding("s", "start", "Start", show=True),
        Binding("t", "stop", "Stop", show=True),
        Binding("b", "reboot", "Reboot", show=True),
        Binding("d", "terminate", "Terminate", show=True),
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
                    "[bold cyan]AWS EC2 Manager[/bold cyan]",
                    id="aws_mgr_header",
                ),
                Static(
                    "[dim]Click a row, then use the keys below or the action "
                    "buttons. State-aware: Start only enables on stopped "
                    "instances; Stop/Reboot only on running ones. Terminated "
                    "rows disable all actions.[/dim]",
                    id="aws_mgr_hint",
                ),
                DataTable(
                    id="aws_mgr_table",
                    zebra_stripes=True,
                    cursor_type="row",
                ),
                Static("", id="aws_mgr_status"),
                Horizontal(
                    Button("Refresh (F5)", id="btn_aws_mgr_refresh"),
                    Button(
                        "+ New (n)", variant="primary",
                        id="btn_aws_mgr_new",
                    ),
                    Button(
                        "Start (s)", id="btn_aws_mgr_start",
                        disabled=True,
                    ),
                    Button(
                        "Stop (t)", id="btn_aws_mgr_stop",
                        disabled=True,
                    ),
                    Button(
                        "Reboot (b)", id="btn_aws_mgr_reboot",
                        disabled=True,
                    ),
                    Button(
                        "Terminate (d)", variant="error",
                        id="btn_aws_mgr_terminate",
                        disabled=True,
                    ),
                    id="aws_mgr_actions",
                ),
                id="aws_mgr_container",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#aws_mgr_table", DataTable)
        table.add_columns(
            "#", "Name", "ID", "Type", "State", "Public IP", "Region",
        )
        self._refresh()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if self._loading:
            return
        svc = getattr(self.app, "aws_service", None)
        if svc is None:
            self._set_status(
                "[red]AWS is not configured. "
                "Ensure boto3 credentials are available (env vars, ~/.aws/, "
                "or an IAM role).[/red]"
            )
            return
        self._loading = True
        self._set_status("[dim]Loading EC2 instances…[/dim]")
        self.run_worker(
            self._load_instances(),
            exclusive=True,
            name="aws_mgr_load",
        )

    async def _load_instances(self) -> None:
        svc = self.app.aws_service  # safe: guard ran in _refresh
        try:
            instances = await svc.fetch_instances_cached(force_refresh=True)
            self._instances = list(instances)
            # Redact the fresh list in-place so _render_table never sees raw
            # names / IPs — mirrors the app-startup redact_instances pattern.
            if self.app.demo_mode and self.app.redaction_service:
                self.app.redaction_service.redact_instances(self._instances)
            self._render_table()
            n = len(instances)
            if n == 0:
                self._set_status(
                    "[dim]No EC2 instances found. Press [b]n[/b] to "
                    "launch one.[/dim]"
                )
            else:
                self._set_status(
                    f"[dim]{n} instance{'s' if n != 1 else ''}.[/dim]"
                )
        except Exception as exc:
            logger.error("Failed to load EC2 instances: %s", exc)
            err_msg = self._short_err(exc)
            if self.app.demo_mode and self.app.redaction_service:
                err_msg = self.app.redaction_service.scrub_stream(err_msg)
            self._set_status(
                f"[red]Failed to load instances: {err_msg}[/red]"
            )
        finally:
            self._loading = False

    def _render_table(self) -> None:
        table = self.query_one("#aws_mgr_table", DataTable)
        table.clear()
        for idx, inst in enumerate(self._instances, start=1):
            table.add_row(
                str(idx),
                escape_cell(str(inst.get("name", ""))),
                escape_cell(str(inst.get("id", ""))),
                escape_cell(str(inst.get("type", ""))),
                self._colorize_state(str(inst.get("state", ""))),
                escape_cell(str(inst.get("public_ip", "") or "—")),
                escape_cell(str(inst.get("region", ""))),
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
        if s in {"pending", "starting", "stopping", "rebooting"}:
            return f"[blue]{state}[/blue]"
        if s in _TERMINAL:
            return f"[dim]{state}[/dim]"
        return state

    # ------------------------------------------------------------------
    # Selection-driven button enablement
    # ------------------------------------------------------------------

    def on_data_table_row_highlighted(self, event) -> None:  # noqa: ANN001
        self._sync_action_buttons()

    def _selected_instance(self) -> Optional[dict]:
        table = self.query_one("#aws_mgr_table", DataTable)
        row = table.cursor_row
        if row < 0 or row >= len(self._instances):
            return None
        return self._instances[row]

    def _sync_action_buttons(self) -> None:
        """Toggle button enabled state based on the selected row's EC2 state.

        EC2 lifecycle rules:
        * ``running``                   → stop / reboot / terminate enabled
        * ``stopped``                   → start / terminate enabled
        * ``terminated``/``shutting-down`` → all disabled (terminal)
        * other (transient)             → only terminate enabled (allows
                                          force-stop of a stuck instance)
        """
        inst = self._selected_instance()
        state = (inst.get("state", "") if inst else "").lower()

        is_running = state in _RUNNING
        is_stopped = state in _STOPPED
        is_terminal = state in _TERMINAL
        has_inst = inst is not None and not is_terminal

        for btn_id, enable in (
            ("btn_aws_mgr_start", has_inst and is_stopped),
            ("btn_aws_mgr_stop", has_inst and is_running),
            ("btn_aws_mgr_reboot", has_inst and is_running),
            ("btn_aws_mgr_terminate", has_inst),
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
            "btn_aws_mgr_refresh": self.action_refresh,
            "btn_aws_mgr_new": self.action_new,
            "btn_aws_mgr_start": self.action_start,
            "btn_aws_mgr_stop": self.action_stop,
            "btn_aws_mgr_reboot": self.action_reboot,
            "btn_aws_mgr_terminate": self.action_terminate,
        }
        handler = mapping.get(event.button.id or "")
        if handler is not None:
            handler()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_refresh(self) -> None:
        self._refresh()

    def action_new(self) -> None:
        if getattr(self.app, "aws_service", None) is None:
            self.notify(
                "AWS is not configured. Ensure credentials are available.",
                severity="warning", markup=False,
            )
            return
        from servonaut.screens.aws_create import AWSCreateScreen
        self.app.push_screen(AWSCreateScreen())

    def action_start(self) -> None:
        inst = self._selected_instance()
        if inst is None:
            return
        state = str(inst.get("state", "")).lower()
        if state not in _STOPPED:
            self.notify(
                "Start is only available for stopped instances.",
                severity="warning", markup=False,
            )
            return
        self._run_lifecycle("start_instance", "Starting", "started")

    def action_stop(self) -> None:
        inst = self._selected_instance()
        if inst is None:
            return
        state = str(inst.get("state", "")).lower()
        if state not in _RUNNING:
            self.notify(
                "Stop is only available for running instances.",
                severity="warning", markup=False,
            )
            return
        self._run_lifecycle("stop_instance", "Stopping", "stop sent")

    def action_reboot(self) -> None:
        inst = self._selected_instance()
        if inst is None:
            return
        state = str(inst.get("state", "")).lower()
        if state not in _RUNNING:
            self.notify(
                "Reboot is only available for running instances.",
                severity="warning", markup=False,
            )
            return
        self._run_lifecycle("reboot_instance", "Rebooting", "reboot sent")

    def action_terminate(self) -> None:
        inst = self._selected_instance()
        if inst is None:
            return
        state = str(inst.get("state", "")).lower()
        if state in _TERMINAL:
            self.notify(
                "Instance is already in a terminal state (terminated/shutting-down).",
                severity="warning", markup=False,
            )
            return
        self.run_worker(
            self._do_terminate(inst),
            exclusive=True,
            name="aws_mgr_terminate",
        )

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    def _run_lifecycle(
        self, method: str, in_progress_verb: str, done_verb: str,
    ) -> None:
        """Fire a lifecycle worker for start / stop / reboot."""
        inst = self._selected_instance()
        if inst is None:
            return
        instance_id = str(inst.get("id") or "")
        region = str(inst.get("region") or "")
        if not instance_id or not region:
            self.notify(
                "Selected row is missing instance ID or region.",
                severity="warning", markup=False,
            )
            return
        self._set_status(
            f"[dim]{in_progress_verb} {inst.get('name', instance_id)}…[/dim]"
        )
        self.run_worker(
            self._do_lifecycle(method, instance_id, region, done_verb),
            exclusive=False,
            name=f"aws_mgr_{method}",
        )

    async def _do_lifecycle(
        self,
        method: str,
        instance_id: str,
        region: str,
        done_verb: str,
    ) -> None:
        """Call the EC2 lifecycle method (start/stop/reboot) with region.

        EC2 lifecycle methods on AWSService require BOTH instance_id and
        region — the region-scoped boto3 client cannot be inferred from
        instance_id alone (unlike Hetzner, which uses a global endpoint).
        """
        svc = self.app.aws_service
        try:
            await getattr(svc, method)(instance_id, region)
        except Exception as exc:
            logger.error(
                "EC2 %s failed for %s in %s: %s",
                method, instance_id, region, exc,
            )
            err_msg = self._short_err(exc)
            if self.app.demo_mode and self.app.redaction_service:
                err_msg = self.app.redaction_service.scrub_stream(err_msg)
            self._set_status(f"[red]{method} failed: {err_msg}[/red]")
            self.notify(
                f"{method} failed: {err_msg}",
                severity="error", markup=False,
            )
            return

        audit = getattr(self.app, "aws_audit", None)
        if audit is not None:
            try:
                audit.log_action(
                    action=method,
                    target=instance_id,
                    details={"region": region},
                    confirmed=True,
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("Failed to write AWS audit row: %s", exc)

        self.notify(
            f"EC2 {instance_id}: {done_verb}.",
            severity="information", markup=False,
        )
        # Re-fetch so the table reflects the new state.
        await self._load_instances()

    async def _do_terminate(self, inst: dict) -> None:
        """Prompt with typed confirmation then terminate the instance."""
        instance_id = str(inst.get("id") or "")
        region = str(inst.get("region") or "")
        name = inst.get("name", instance_id) or instance_id

        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Terminate EC2 Instance",
                description=(
                    f"Terminate [bold]{markup_escape(name)}[/bold] "
                    f"([bold]{markup_escape(str(inst.get('type', '')))}[/bold]) in "
                    f"[bold]{markup_escape(region)}[/bold]?"
                ),
                consequences=[
                    "All data on instance-store volumes will be permanently destroyed",
                    "EBS root volume will be deleted (unless configured otherwise)",
                    "Billing for this instance stops immediately",
                    "The instance ID will become invalid after ~1 hour",
                ],
                confirm_text="terminate",
                action_label="Terminate Instance",
                severity="danger",
            )
        )

        audit = getattr(self.app, "aws_audit", None)
        if audit is not None:
            try:
                audit.log_action(
                    action="terminate_instance",
                    target=instance_id,
                    details={"region": region, "name": name},
                    confirmed=bool(confirmed),
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("Failed to write AWS audit row: %s", exc)

        if not confirmed:
            return

        self._set_status(f"[dim]Terminating {name}…[/dim]")
        svc = self.app.aws_service
        try:
            await svc.terminate_instance(instance_id, region)
        except Exception as exc:
            logger.error(
                "EC2 terminate failed for %s in %s: %s",
                instance_id, region, exc,
            )
            err_msg = self._short_err(exc)
            if self.app.demo_mode and self.app.redaction_service:
                err_msg = self.app.redaction_service.scrub_stream(err_msg)
            self._set_status(f"[red]Terminate failed: {err_msg}[/red]")
            self.notify(
                f"Terminate failed: {err_msg}",
                severity="error", markup=False,
            )
            return

        self.notify(
            f"EC2 instance {instance_id} terminating.",
            severity="information", markup=False,
        )
        await self._load_instances()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_status(self, text: str) -> None:
        try:
            self.query_one("#aws_mgr_status", Static).update(text)
        except Exception:  # pragma: no cover - defensive
            pass

    @staticmethod
    def _short_err(exc: Exception) -> str:
        msg = str(exc)
        return msg if len(msg) <= 200 else msg[:197] + "…"
