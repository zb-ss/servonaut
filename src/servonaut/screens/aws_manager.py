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

With several AWS accounts configured the table lists the instances of
every account (names shown as ``account/name``) and each action runs in
the account the selected instance belongs to.

Design intent: :class:`InstanceListScreen` is the unified search-and-SSH
surface. This screen is the EC2 admin home — the place an operator goes
to manage EC2 inventory beyond what the instance list offers.
"""

from __future__ import annotations

import logging
from typing import List, Optional, TYPE_CHECKING, Union

from rich.markup import escape as markup_escape
from rich.text import Text
from textual.app import ComposeResult
from textual.content import Content
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, DataTable, Footer, Static

from servonaut.utils.markup import literal, with_bold_values
from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens._provider_actions import (
    ActionSpec, ProviderActionsMixin, action_rail, action_unavailable,
)
from servonaut.screens._demo_resolve import (
    DemoRowsMixin,
    display_text,
    reconcile_team_memory,
    replace_instances,
)
from servonaut.screens._provider_accounts import (
    UnknownAccountError,
    account_ref,
    account_service,
    fetched_row,
    inventory,
    with_account,
)
from servonaut.screens._table_cursor import keep_selected_row
from servonaut.screens.power_confirm import PowerActionText, confirm_and_run_power_action
from servonaut.utils.formatting import escape_cell
from servonaut.utils.instance_resolver import display_name
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

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

# Power actions that interrupt a running instance ask first (yes/no);
# starting a stopped one does not. Values: (verb shown, consequence).
_CONFIRM_POWER = {
    "stop_instance": (
        "Stop",
        "The instance shuts down and its services stay unavailable until it "
        "is started again. Data on instance-store volumes is lost.",
    ),
    "reboot_instance": (
        "Reboot",
        "The instance restarts and its services are unavailable until it is "
        "back up.",
    ),
}

# What each power action tells the user, naming the instance as its row does.
_POWER_TEXT = {
    "start_instance": PowerActionText(
        "Starting", "Start sent to {server}.", "Could not start {server}",
    ),
    "stop_instance": PowerActionText(
        "Stopping", "Stop sent to {server}.", "Could not stop {server}",
    ),
    "reboot_instance": PowerActionText(
        "Rebooting", "Reboot sent to {server}.", "Could not reboot {server}",
    ),
}


class AWSManagerScreen(ProviderActionsMixin, DemoRowsMixin, WorkspaceScreen):
    """AWS EC2 instance manager — list + lifecycle toolbar."""

    CHAT_REFLOW = True
    CHAT_MIN_CONTENT_WIDTH = 64
    CONTENT_NARROW_WIDTH = 104

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
        if self.navigation_focused:
            return super().check_action(action, parameters)
        return check_action_passthrough(self, action)

    def __init__(self) -> None:
        super().__init__()
        self._raw_instances: List[dict] = []
        self._instances: List[dict] = []
        self._api_ids: dict = {}
        self._loading: bool = False

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield WorkspaceControls("AWS servers")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            inventory_panel = Vertical(
                Static("", id="aws_mgr_status"),
                DataTable(
                    id="aws_mgr_table",
                    zebra_stripes=True,
                    cursor_type="row",
                ),
                classes="provider-manager-inventory",
            )
            inventory_panel.border_title = "EC2 inventory"
            selection = Vertical(
                Static("Selected resource", classes="provider-manager-selection-label"),
                Static(
                    "No server selected", id="aws_mgr_selection",
                    classes="provider-manager-selection-name", markup=False,
                ),
                Static(
                    "Choose a row to see its full ID and address.",
                    id="aws_mgr_identity",
                    classes="provider-manager-selection-identity", markup=False,
                ),
                classes="provider-manager-selection",
            )
            actions = action_rail(
                "aws_mgr_actions",
                inventory=(
                    ActionSpec("btn_aws_mgr_refresh", "Refresh", "f5", disabled=False),
                    ActionSpec("btn_aws_mgr_new", "+ Launch", "n", role="primary", disabled=False),
                ),
                selection=selection,
                power=(
                    ActionSpec("btn_aws_mgr_start", "Start", "s", role="primary"),
                    ActionSpec("btn_aws_mgr_stop", "Stop", "t"),
                    ActionSpec("btn_aws_mgr_reboot", "Reboot", "b"),
                ),
                danger=(
                    ActionSpec("btn_aws_mgr_terminate", "Terminate", "d", role="error"),
                ),
            )
            actions.border_title = "Resource actions"
            rail = Vertical(actions, classes="provider-manager-rail")
            rail.border_title = "Resource workspace"
            yield ScrollableContainer(
                Vertical(
                    Horizontal(
                        Static("AWS EC2 instances", id="aws_mgr_header"),
                        Static(
                            "Inventory", id="aws_mgr_overview",
                            classes="provider-manager-overview", markup=False,
                        ),
                        classes="provider-manager-heading-row",
                    ),
                    Static(
                        "Select an instance to manage its power. Start requires a "
                        "stopped instance; Stop and Reboot require a running one. "
                        "Terminated rows have no actions.",
                        id="aws_mgr_hint",
                    ),
                    classes="provider-manager-heading",
                ),
                Horizontal(
                    inventory_panel, rail, classes="provider-manager-body",
                ),
                id="aws_mgr_container",
                classes="workspace-content provider-manager-content",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#aws_mgr_table", DataTable)
        table.add_columns(
            "#", "Name", "ID", "Type", "State", "Public IP", "Region",
        )
        self.sync_compact_actions()
        self._refresh()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if self._loading:
            return
        if inventory(self.app, "aws") is None:
            self._set_status(
                "[$text-error]AWS is not configured. "
                "Ensure boto3 credentials are available (env vars, ~/.aws/, "
                "or an IAM role).[/$text-error]"
            )
            return
        self._loading = True
        self._set_status("[dim]Loading EC2 instances…[/dim]")
        self.run_worker(
            self._load_instances(),
            exclusive=True,
            name="aws_mgr_load",
        )

    async def _load_instances(self, *, update_fleet: bool = False) -> None:
        """Fetch every account's servers into the table.

        *update_fleet* also puts them in the server list, after this screen
        changed the fleet (a server deleted here must leave it too).
        """
        # Every AWS account's instances: a refresh after acting on one
        # account must never leave the table showing that account alone.
        fleet = inventory(self.app, "aws")  # guard ran in _refresh
        try:
            instances = await fleet.fetch_instances_cached(force_refresh=True)
            # Keep the fetched rows untouched; what the table draws is
            # derived from them (demo-mode fakes when demo mode is on).
            self._raw_instances = list(instances)
            if update_fleet:
                replace_instances(self.app, "aws", instances)
                reconcile_team_memory(self.app)
            self._apply_display_rows()
            self._render_table()
            n = len(instances)
            if n == 0:
                status = (
                    "[dim]No EC2 instances found. Press [b]n[/b] to "
                    "launch one.[/dim]"
                )
            else:
                status = f"[dim]{n} instance{'s' if n != 1 else ''}.[/dim]"
            self._set_status(status + self._incomplete_refresh_note(fleet))
        except Exception as exc:
            logger.error("Failed to load EC2 instances: %s", exc)
            err_msg = self._short_err(exc)
            if self.app.demo_mode and self.app.redaction_service:
                err_msg = self.app.redaction_service.scrub_stream(err_msg)
            self._set_status(
                f"[$text-error]Failed to load instances: {err_msg}[/$text-error]"
            )
        finally:
            self._loading = False

    @staticmethod
    def _incomplete_refresh_note(fleet) -> str:  # noqa: ANN001
        """Which accounts failed to refresh, when there are several accounts.

        A failed account lists its cached instances (or none), which would
        otherwise pass for its current state. A single account keeps the
        status line it always had. (The status line swaps account labels
        for their stand-ins in demo mode.)
        """
        error = getattr(fleet, "last_fetch_error", None)
        if getattr(fleet, "multi", False) is not True or not isinstance(error, str):
            return ""
        return f" [$text-warning]Refresh incomplete: {markup_escape(error)}[/$text-warning]" if error else ""

    def _render_table(self) -> None:
        table = self.query_one("#aws_mgr_table", DataTable)
        # The next action must reach the server the user picked, not row 1.
        with keep_selected_row(table):
            table.clear()
            for idx, inst in enumerate(self._instances, start=1):
                table.add_row(
                    str(idx),
                    escape_cell(display_name(inst)),
                    escape_cell(str(inst.get("id", ""))),
                    escape_cell(str(inst.get("type", ""))),
                    self._colorize_state(str(inst.get("state", ""))),
                    escape_cell(str(inst.get("public_ip", "") or "—")),
                    escape_cell(str(inst.get("region", ""))),
                    key=str(inst.get("id", idx)),
                )
        self._sync_action_buttons()
        self._update_resource_context()

    @staticmethod
    def _colorize_state(state: str) -> Content:
        s = state.lower()
        if s in _RUNNING:
            return literal(state, "$text-success")
        if s in _STOPPED:
            return literal(state, "$text-warning")
        if s in {"pending", "starting", "stopping", "rebooting"}:
            return literal(state, "$text-accent")
        if s in _TERMINAL:
            return literal(state, "dim")
        return literal(state)

    # ------------------------------------------------------------------
    # Selection-driven button enablement
    # ------------------------------------------------------------------

    def _update_resource_context(self) -> None:
        """Show the drawn row's identity beside its existing resource actions."""
        try:
            selection = self.query_one("#aws_mgr_selection", Static)
            identity = self.query_one("#aws_mgr_identity", Static)
            overview = self.query_one("#aws_mgr_overview", Static)
        except NoMatches:
            return
        count = len(self._instances)
        accounts = {str(row.get("account") or "") for row in self._instances}
        summary = f"{count} instance{'s' if count != 1 else ''}"
        if len(accounts) > 1:
            summary += f" across {len(accounts)} accounts"
        overview.update(summary)
        instance = self._selected_instance()
        if instance is None:
            selection.update("No server selected")
            identity.update("Choose a row to see its full ID and address.")
            return
        selection.update(Text(self._row_label(instance), style="bold"))
        details = Text()
        for index, (label, key) in enumerate((
            ("State", "state"), ("ID", "id"), ("Address", "public_ip"),
        )):
            if index:
                details.append("\n")
            details.append(f"{label}: ", style="dim")
            details.append(str(instance.get(key) or "—"))
        identity.update(details)

    def on_data_table_row_highlighted(self, event) -> None:  # noqa: ANN001
        self._sync_action_buttons()
        self._update_resource_context()

    def _selected_instance(self) -> Optional[dict]:
        table = self.query_one("#aws_mgr_table", DataTable)
        row = table.cursor_row
        if row < 0 or row >= len(self._instances):
            return None
        return self._instances[row]

    def _api_id(self, inst: dict) -> str:
        """Real provider id for an API call; the row may carry a demo-mode fake."""
        shown = str(inst.get("id") or "")
        return getattr(self, "_api_ids", {}).get(shown, shown)

    @staticmethod
    def _row_label(inst: dict) -> str:
        """What to call a row's server: its name, else the id the table shows.

        ``account/name`` when there are several AWS accounts, as the table
        shows it. The fallback is the row's id, never the API id: in demo
        mode the row carries a placeholder and the real id stays off the
        screen.
        """
        return display_name(inst) or str(inst.get("id") or "")

    def _row_account(self, inst: dict) -> Optional[str]:
        """Real label of the account a row belongs to; None (reported) when gone.

        Every action runs in the row's own account, read from the fetched
        row: in demo mode the drawn row carries a stand-in label. An account
        removed in Settings since the table was loaded is refused rather
        than guessed.
        """
        fetched = fetched_row(self._instances, self._raw_instances, inst)
        account = str(fetched.get("account") or "")
        try:
            ref = account_ref(self.app, "aws", account)
        except UnknownAccountError as exc:
            # The message names the real account; demo mode keeps it off
            # the screen (a removed account has no stand-in to swap in).
            reason = "its AWS account is not available" if self.app.demo_mode else str(exc)
            self.notify(
                f"{self._row_label(inst)}: {reason}. Refresh the list and try again.",
                severity="error", markup=False,
            )
            return None
        return ref.label if ref is not None else account

    def _sync_action_buttons(self) -> None:
        self.sync_action_buttons()

    def unavailable_actions(self) -> dict[str, str | None]:
        """Why each action cannot run on the selected row, from its EC2 state.

        * ``running``                      -> stop / reboot / terminate
        * ``stopped``                      -> start / terminate
        * ``terminated`` / ``shutting-down`` -> nothing (terminal)
        * other (transient)                -> only terminate (force-stop of a stuck instance)
        """
        inst = self._selected_instance()
        state = (inst.get("state", "") if inst else "").lower()
        has_row = inst is not None
        live = has_row and state not in _TERMINAL
        return {
            "btn_aws_mgr_start": action_unavailable(has_row, live and state in _STOPPED, "Start needs a stopped instance."),
            "btn_aws_mgr_stop": action_unavailable(has_row, live and state in _RUNNING, "Stop needs a running instance."),
            "btn_aws_mgr_reboot": action_unavailable(has_row, live and state in _RUNNING, "Reboot needs a running instance."),
            "btn_aws_mgr_terminate": action_unavailable(has_row, live, "This instance is already terminated."),
        }

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
        if not self.refuse_unavailable("btn_aws_mgr_start"):
            self._run_lifecycle("start_instance")

    def action_stop(self) -> None:
        if not self.refuse_unavailable("btn_aws_mgr_stop"):
            self._run_lifecycle("stop_instance")

    def action_reboot(self) -> None:
        if not self.refuse_unavailable("btn_aws_mgr_reboot"):
            self._run_lifecycle("reboot_instance")

    def action_terminate(self) -> None:
        if self.refuse_unavailable("btn_aws_mgr_terminate"):
            return
        self.run_worker(
            self._do_terminate(self._selected_instance()),
            exclusive=True,
            name="aws_mgr_terminate",
        )

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    def _run_lifecycle(self, method: str) -> None:
        """Fire a lifecycle worker for start / stop / reboot."""
        inst = self._selected_instance()
        if inst is None:
            return
        instance_id = self._api_id(inst)
        region = str(inst.get("region") or "")
        if not instance_id or not region:
            self.notify(
                "Selected row is missing instance ID or region.",
                severity="warning", markup=False,
            )
            return
        account = self._row_account(inst)
        if account is None:
            return
        label = self._row_label(inst)
        self.run_worker(
            confirm_and_run_power_action(
                self.app,
                prompt=_CONFIRM_POWER.get(method),
                server_name=label,
                provider=f"AWS EC2, {region}",
                in_progress_verb=_POWER_TEXT[method].in_progress,
                set_status=self._set_status,
                run=lambda: self._do_lifecycle(
                    method, instance_id, region, label, account=account,
                ),
            ),
            exclusive=False,
            name=f"aws_mgr_{method}",
        )

    async def _do_lifecycle(
        self,
        method: str,
        instance_id: str,
        region: str,
        label: str,
        account: str = "",
    ) -> None:
        """Call the EC2 lifecycle method (start/stop/reboot) with region.

        EC2 lifecycle methods on AWSService require BOTH instance_id and
        region — the region-scoped boto3 client cannot be inferred from
        instance_id alone (unlike Hetzner, which uses a global endpoint).
        The call runs in *account* (its label; "" = the default account).
        The notices name the instance *label*, the name its row shows, so
        demo mode never shows the real one.
        """
        text = _POWER_TEXT[method]
        try:
            svc = account_service(self.app, "aws", account)
            await getattr(svc, method)(instance_id, region)
        except Exception as exc:
            logger.error(
                "EC2 %s failed for %s in %s: %s",
                method, instance_id, region, exc,
            )
            err_msg = self._short_err(exc)
            if self.app.demo_mode and self.app.redaction_service:
                err_msg = self.app.redaction_service.scrub_stream(err_msg)
            message = text.failed_message(label, err_msg)
            self._set_status(f"[$text-error]{markup_escape(message)}[/$text-error]")
            self.notify(message, severity="error", markup=False)
            return

        audit = getattr(self.app, "aws_audit", None)
        if audit is not None:
            try:
                audit.log_action(
                    action=method,
                    target=instance_id,
                    details=with_account(self.app, "aws", account, {"region": region}),
                    confirmed=True,
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("Failed to write AWS audit row: %s", exc)

        self.notify(text.done_message(label), severity="information", markup=False)
        # Re-fetch so the table reflects the new state.
        await self._load_instances()

    async def _do_terminate(self, inst: dict) -> None:
        """Prompt with typed confirmation then terminate the instance."""
        instance_id = self._api_id(inst)
        region = str(inst.get("region") or "")
        name = self._row_label(inst)
        account = self._row_account(inst)
        if account is None:
            return

        from servonaut.screens.confirm_action import ConfirmActionScreen

        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Terminate EC2 Instance",
                description=with_bold_values(
                    "Terminate {} ({}) in {}?", name, inst.get('type', ''), region,
                ),
                consequences=[
                    "All data on instance-store volumes will be permanently destroyed",
                    "EBS root volume will be deleted (unless configured otherwise)",
                    "Billing for this instance stops immediately",
                    "The instance ID will become invalid after ~1 hour",
                ],
                confirm_text="terminate",
                action_label="Terminate instance",
                severity="danger",
            )
        )

        audit = getattr(self.app, "aws_audit", None)
        if audit is not None:
            try:
                audit.log_action(
                    action="terminate_instance",
                    target=instance_id,
                    details=with_account(
                        self.app, "aws", account, {"region": region, "name": name},
                    ),
                    confirmed=bool(confirmed),
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("Failed to write AWS audit row: %s", exc)

        if not confirmed:
            return

        self._set_status(f"[dim]Terminating {markup_escape(name)}…[/dim]")
        try:
            svc = account_service(self.app, "aws", account)
            await svc.terminate_instance(instance_id, region)
        except Exception as exc:
            logger.error(
                "EC2 terminate failed for %s in %s: %s",
                instance_id, region, exc,
            )
            err_msg = self._short_err(exc)
            if self.app.demo_mode and self.app.redaction_service:
                err_msg = self.app.redaction_service.scrub_stream(err_msg)
            self._set_status(f"[$text-error]Terminate failed: {err_msg}[/$text-error]")
            self.notify(
                f"Terminate failed: {err_msg}",
                severity="error", markup=False,
            )
            return

        self.notify(f"EC2 instance {name} terminating.", severity="information", markup=False)
        await self._load_instances(update_fleet=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_status(self, text: Union[str, Content]) -> None:
        # Provider errors quote real ids and names: demo mode shows stand-ins.
        text = display_text(self.app, text)
        try:
            self.query_one("#aws_mgr_status", Static).update(text)
        except Exception:  # pragma: no cover - defensive
            pass

    @staticmethod
    def _short_err(exc: Exception) -> str:
        msg = str(exc)
        return msg if len(msg) <= 200 else msg[:197] + "…"
