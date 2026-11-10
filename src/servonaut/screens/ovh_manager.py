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

The table lists every configured OVH account; each action goes to the
account the selected row belongs to.
"""

from __future__ import annotations

import logging
from typing import List, Optional, TYPE_CHECKING, Union

from rich.text import Text
from textual.app import ComposeResult
from textual.content import Content
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, DataTable, Footer, Static

from rich.markup import escape

from servonaut.utils.markup import inert_text, with_bold_values
from servonaut.utils.theme_text import follow_theme, themed_text
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
    fetched_row,
    inventory,
    ovh_services,
    provider_accounts,
    row_ovh_services,
    row_service,
    with_account,
)
from servonaut.screens._table_cursor import keep_selected_row
from servonaut.screens.power_confirm import PowerActionText, confirm_and_run_power_action
from servonaut.services.accounts import AccountFleet
from servonaut.utils.instance_resolver import display_name
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

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

_PRODUCT_LABELS = {
    "vps": "OVHcloud VPS",
    "cloud": "OVHcloud Public Cloud",
    "dedicated": "OVHcloud dedicated server",
}

# Power actions that interrupt a running server ask first (yes/no); starting
# a stopped one does not. Values: (verb shown to the user, consequence).
_CONFIRM_POWER = {
    "stop_instance": (
        "Stop",
        "The server shuts down and its services stay unavailable until it "
        "is started again.",
    ),
    "reboot_instance": (
        "Reboot",
        "The server restarts and its services are unavailable until it is "
        "back up.",
    ),
}

# What each power action tells the user, naming the server as its row does.
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


class OVHManagerScreen(ProviderActionsMixin, DemoRowsMixin, WorkspaceScreen):
    """OVHcloud instance manager — list + lifecycle toolbar."""

    CHAT_REFLOW = True
    # Container padding and scrollbar plus the leading table columns and the
    # first toolbar buttons beside the chat column (as the Hetzner manager).
    CHAT_MIN_CONTENT_WIDTH = 64
    # Keep the full action row only where labels, spacing and scrollbar fit.
    CONTENT_NARROW_WIDTH = 105

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
        yield WorkspaceControls("OVH servers")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            inventory_panel = Vertical(
                Static("", id="ovh_mgr_status"),
                DataTable(
                    id="ovh_mgr_table",
                    zebra_stripes=True,
                    cursor_type="row",
                ),
                classes="provider-manager-inventory",
            )
            inventory_panel.border_title = "VPS, Public Cloud and dedicated inventory"
            selection = Vertical(
                Static("Selected resource", classes="provider-manager-selection-label"),
                Static(
                    "No server selected", id="ovh_mgr_selection",
                    classes="provider-manager-selection-name", markup=False,
                ),
                Static(
                    "Choose a row to see its full ID and address.",
                    id="ovh_mgr_identity",
                    classes="provider-manager-selection-identity", markup=False,
                ),
                classes="provider-manager-selection",
            )
            actions = action_rail(
                "ovh_mgr_actions",
                inventory=(
                    ActionSpec("btn_ovh_mgr_refresh", "Refresh", "f5", disabled=False),
                    ActionSpec("btn_ovh_mgr_new", "+ New cloud", "n", role="primary", short="+ New", disabled=False),
                ),
                selection=selection,
                power=(
                    ActionSpec("btn_ovh_mgr_start", "Start", "s", role="primary"),
                    ActionSpec("btn_ovh_mgr_stop", "Stop", "t"),
                    ActionSpec("btn_ovh_mgr_reboot", "Reboot", "b"),
                ),
                danger=(
                    ActionSpec("btn_ovh_mgr_delete", "Delete", "d", role="error"),
                ),
            )
            actions.border_title = "Resource actions"
            rail = Vertical(actions, classes="provider-manager-rail")
            rail.border_title = "Resource workspace"
            yield ScrollableContainer(
                Vertical(
                    Horizontal(
                        Static("OVHcloud servers", id="ovh_mgr_header", classes="screen-title"),
                        Static(
                            "Inventory", id="ovh_mgr_overview",
                            classes="provider-manager-overview", markup=False,
                        ),
                        classes="provider-manager-heading-row",
                    ),
                    Static(
                        "Select a VPS or Public Cloud server for power actions; "
                        "dedicated servers support Reboot. New and Delete apply "
                        "to Public Cloud only. Creating a server starts billing immediately.",
                        id="ovh_mgr_hint",
                    ),
                    classes="provider-manager-heading",
                ),
                Horizontal(
                    inventory_panel, rail, classes="provider-manager-body",
                ),
                id="ovh_mgr_container",
                classes="workspace-content provider-manager-content",
            )
        yield Footer()

    def on_mount(self) -> None:
        follow_theme(self, "#ovh_mgr_table", self._render_table)
        table = self.query_one("#ovh_mgr_table", DataTable)
        # Keep state and addressing visible when a cloud composite ID is long.
        for label, width in (("#", 3), ("Name", 22), ("Type", 18), ("Kind", 9),
                             ("State", 10), ("Public IP", 15), ("Region", 9), ("ID", 70)):
            table.add_column(label, width=width)
        self.sync_compact_actions()
        self._refresh()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if self._loading:
            return
        if inventory(self.app, "ovh") is None:
            self._set_status(
                "[$text-error]OVHcloud is not configured. "
                "Visit Settings → OVHcloud to set up credentials.[/$text-error]"
            )
            return
        self._loading = True
        self._set_status("[dim]Loading instances…[/dim]")
        self.run_worker(
            self._load_instances(),
            exclusive=True,
            name="ovh_mgr_load",
        )

    async def _load_instances(self, *, update_fleet: bool = False) -> None:
        """Fetch every account's instances into the table.

        *update_fleet* also puts them in the server list, after this screen
        changed the fleet (an instance deleted here must leave it too).
        """
        svc = inventory(self.app, "ovh")
        try:
            instances = await svc.fetch_instances_cached(force_refresh=True)
            # Keep the fetched rows untouched; what the table draws is
            # derived from them (demo-mode fakes when demo mode is on).
            self._raw_instances = list(instances)
            self._apply_display_rows()
            self._render_table()
            n = len(instances)
            cred_error: Optional[str] = None
            if n == 0:
                # fetch_instances() swallows API errors and returns [], so an
                # empty list can't tell "no instances" from "credentials
                # revoked" — a /me check disambiguates the two.
                cred_error = await self._credential_error(svc)
                if cred_error:
                    if self.app.demo_mode and self.app.redaction_service:
                        cred_error = self.app.redaction_service.scrub_stream(
                            cred_error
                        )
                    self._set_status(f"[$text-error]⚠ {escape(cred_error)}[/$text-error]")
                else:
                    self._set_status(
                        "[dim]No OVH instances. Press [b]n[/b] to create a "
                        "Public Cloud instance.[/dim]"
                    )
            else:
                self._set_status(
                    f"[dim]{n} instance{'s' if n != 1 else ''}.[/dim]"
                    + self._account_errors(svc)
                )
            # An empty answer from refused credentials is not an empty fleet.
            if update_fleet and not cred_error:
                replace_instances(self.app, "ovh", instances)
                reconcile_team_memory(self.app)
        except Exception as exc:
            logger.error("Failed to load OVH instances: %s", exc)
            err_msg = escape(self._provider_error(exc))
            self._set_status(
                f"[$text-error]Failed to load instances: {err_msg}[/$text-error]"
            )
        finally:
            self._loading = False

    @staticmethod
    async def _credential_error(svc) -> Optional[str]:
        """Why the listed accounts' credentials fail, or None when they work.

        With several accounts, each one is checked and named in the message.
        """
        if not isinstance(svc, AccountFleet):
            return await svc.check_credentials()
        errors = []
        for binding in svc.bindings:
            error = await binding.service.check_credentials()
            if error:
                errors.append(f"{binding.ref.label}: {error}" if svc.multi else error)
        return "; ".join(errors) or None

    def _account_errors(self, svc) -> str:
        """Status suffix naming accounts whose instances could not be refreshed.

        Only several accounts are reported here: one failing account among
        others still lists theirs, so the table alone would not show it.
        """
        error = getattr(svc, "last_fetch_error", None)
        if not getattr(svc, "multi", False) or not isinstance(error, str) or not error:
            return ""
        if self.app.demo_mode and self.app.redaction_service:
            error = self.app.redaction_service.scrub_stream(error)
        return f"\n[$text-warning]⚠ {escape(error)}[/$text-warning]"

    def _render_table(self) -> None:
        table = self.query_one("#ovh_mgr_table", DataTable)
        # The next action must reach the server the user picked, not row 1.
        with keep_selected_row(table):
            table.clear()
            for idx, inst in enumerate(self._instances, start=1):
                table.add_row(
                    str(idx),
                    Text(inert_text(display_name(inst))),
                    Text(inert_text(str(inst.get("type", "")))),
                    Text(inert_text(str(inst.get("provider_type", "—")))),
                    self._colorize_state(str(inst.get("state", ""))),
                    Text(inert_text(str(inst.get("public_ip", "") or "—"))),
                    Text(inert_text(str(inst.get("region", "")))),
                    Text(inert_text(str(inst.get("id", "")))),
                    key=str(inst.get("id", idx)),
                )
        self._sync_action_buttons()
        self._update_resource_context()

    def _colorize_state(self, state: str) -> Text:
        s = state.lower()
        if s in _RUNNING:
            return themed_text(self.app, state, "$text-success")
        if s in _STOPPED:
            return themed_text(self.app, state, "$text-warning")
        if s in {"pending", "starting", "stopping", "rebuilding", "building"}:
            return themed_text(self.app, state, "$text-accent")
        if s == "error":
            return themed_text(self.app, state, "$text-error")
        return Text(inert_text(state))

    # ------------------------------------------------------------------
    # Selection-driven button enablement
    # ------------------------------------------------------------------

    def _update_resource_context(self) -> None:
        """Show the drawn row's identity beside its existing resource actions."""
        try:
            selection = self.query_one("#ovh_mgr_selection", Static)
            identity = self.query_one("#ovh_mgr_identity", Static)
            overview = self.query_one("#ovh_mgr_overview", Static)
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

    def on_data_table_row_highlighted(self, event) -> None:
        self._sync_action_buttons()
        self._update_resource_context()

    def _selected_instance(self) -> Optional[dict]:
        table = self.query_one("#ovh_mgr_table", DataTable)
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

        The name is account-qualified when several accounts are listed.
        The fallback is the row's id, never the API id: in demo mode the row
        carries a placeholder and the real id stays off the screen.
        """
        return display_name(inst) or str(inst.get("id") or "")

    def _row_account(self, inst: dict) -> str:
        """The real account label of a drawn row (the fetched row keeps it)."""
        fetched = fetched_row(self._instances, self._raw_instances, inst)
        return str(fetched.get("account") or "")

    def _owning(self, resolve, inst: dict):
        """*resolve* the row's account (service or bundle), or None after telling why."""
        try:
            return resolve(self.app, fetched_row(self._instances, self._raw_instances, inst))
        except UnknownAccountError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return None

    def _sync_action_buttons(self) -> None:
        self.sync_action_buttons()

    def unavailable_actions(self) -> dict[str, str | None]:
        """Why each action cannot run on the selected row, per product type and state.

        * cloud:     start (stopped), stop / reboot (running), delete
        * vps:       start (stopped), stop / reboot (running)
        * dedicated: reboot only
        * other:     nothing
        """
        inst = self._selected_instance()
        ptype = (inst.get("provider_type", "") if inst else "").lower()
        state = (inst.get("state", "") if inst else "").lower()
        has_row = inst is not None
        start_stop = ptype in _SUPPORTS_START_STOP
        if ptype in _SUPPORTS_REBOOT:
            reboot_reason = "Reboot needs a running server."
        else:
            reboot_reason = "Reboot is not available for this server type."
        return {
            "btn_ovh_mgr_start": action_unavailable(
                has_row, start_stop and state in _STOPPED,
                "Start needs a stopped VPS or cloud instance.",
            ),
            "btn_ovh_mgr_stop": action_unavailable(
                has_row, start_stop and state in _RUNNING,
                "Stop needs a running VPS or cloud instance.",
            ),
            "btn_ovh_mgr_reboot": action_unavailable(
                has_row,
                ptype in _SUPPORTS_REBOOT and (state in _RUNNING or ptype == "dedicated"),
                reboot_reason,
            ),
            "btn_ovh_mgr_delete": action_unavailable(
                has_row, ptype in _SUPPORTS_DELETE,
                "Only cloud instances can be deleted here.",
            ),
        }

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
        # The wizard picks the account itself; it starts on the first usable
        # one, which is not the primary account when that one cannot connect.
        usable = provider_accounts(self.app, "ovh")
        account = usable[0].label if usable else None
        try:
            cloud = ovh_services(self.app, account).cloud
        except UnknownAccountError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return
        if cloud is None:
            self.notify(
                "OVH Cloud service is not available.",
                severity="warning", markup=False,
            )
            return
        from servonaut.screens.ovh_cloud_create import OVHCloudCreateScreen
        self.app.push_screen(
            OVHCloudCreateScreen(account=account), callback=self._on_create_closed,
        )

    def _on_create_closed(self, created: Optional[bool]) -> None:
        """Reload the list once the wizard has created an instance."""
        if created:
            self._refresh()

    def action_start(self) -> None:
        if not self.refuse_unavailable("btn_ovh_mgr_start"):
            self._run_lifecycle("start_instance")

    def action_stop(self) -> None:
        if not self.refuse_unavailable("btn_ovh_mgr_stop"):
            self._run_lifecycle("stop_instance")

    def action_reboot(self) -> None:
        if not self.refuse_unavailable("btn_ovh_mgr_reboot"):
            self._run_lifecycle("reboot_instance")

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

    def _run_lifecycle(self, method: str) -> None:
        """Run power action *method* on the selected server, asking first if it interrupts."""
        inst = self._selected_instance()
        if inst is None:
            return
        ptype = (inst.get("provider_type", "") or "").lower()
        identifier = self._api_id(inst)
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
        svc = self._owning(row_service, inst)
        if svc is None:
            return
        account = self._row_account(inst)
        label = self._row_label(inst)

        self.run_worker(
            confirm_and_run_power_action(
                self.app,
                prompt=_CONFIRM_POWER.get(method),
                server_name=label,
                provider=_PRODUCT_LABELS.get(ptype, "OVHcloud"),
                in_progress_verb=_POWER_TEXT[method].in_progress,
                set_status=self._set_status,
                run=lambda: self._do_lifecycle(
                    svc, method, identifier, ptype, label, account=account,
                ),
                # Declined stops and reboots are recorded like declined
                # deletes, so the audit log shows every answered question.
                on_declined=lambda: self._audit_action(
                    method, identifier, ptype, success=False, confirmed=False,
                    account=account,
                ),
            ),
            exclusive=False,
            name=f"ovh_mgr_{method}",
        )

    async def _do_lifecycle(
        self, svc, method: str, identifier: str, ptype: str, label: str,
        *, account: str = "",
    ) -> None:
        """Send *method* for *identifier* (the API id); the notices say *label*.

        *label* is the name the row shows, so demo mode never shows the real one.
        """
        text = _POWER_TEXT[method]
        try:
            await getattr(svc, method)(identifier, ptype)
        except Exception as exc:
            logger.error(
                "OVH %s failed for %s (%s): %s",
                method, identifier, ptype, exc,
            )
            message = text.failed_message(label, self._provider_error(exc))
            self._set_status(f"[$text-error]{escape(message)}[/$text-error]")
            self.notify(message, severity="error", markup=False)
            return

        self._audit_action(method, identifier, ptype, success=True, account=account)
        self.notify(text.done_message(label), severity="information", markup=False)
        await self._load_instances()

    async def _do_delete(self, inst: dict) -> None:
        ptype = (inst.get("provider_type", "") or "").lower()
        composite_id = self._api_id(inst)
        # Cloud composite id is "<project_id>/<inst_id>" — split for the
        # OVHCloudService call which takes them separately.
        project_id, _, inst_id = composite_id.partition("/")
        project_label = "Hidden" if self.app.demo_mode else project_id
        label = self._row_label(inst)
        if not project_id or not inst_id:
            self.notify(
                f"Cannot parse OVH cloud id {self._display_id(composite_id)!r}.",
                severity="error", markup=False,
            )
            return
        services = self._owning(row_ovh_services, inst)
        if services is None:
            return
        account = self._row_account(inst)

        from servonaut.screens.confirm_action import ConfirmActionScreen
        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Delete OVH Cloud Instance",
                description=with_bold_values(
                    "Delete {} ({}) in project {}?",
                    label, inst.get('type', ''), project_label,
                ),
                consequences=[
                    "All data on the instance will be permanently destroyed",
                    "Any attached IPs may be released and re-billed if not "
                    "previously reserved",
                    "Billing for this instance stops immediately",
                ],
                confirm_text="delete",
                action_label="Delete instance",
                severity="danger",
            )
        )
        self._audit_action("cloud_delete", composite_id, ptype,
                           success=False, confirmed=bool(confirmed), account=account)
        if not confirmed:
            return

        self._set_status(f"[dim]Deleting {escape(label)}…[/dim]")
        cloud_svc = services.cloud
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
                               error=str(exc)[:200], account=account)
            err_msg = escape(self._provider_error(exc))
            self._set_status(
                f"[$text-error]Delete failed: {err_msg}[/$text-error]"
            )
            self.notify(
                f"Delete failed: {self._provider_error(exc)}",
                severity="error", markup=False,
            )
            return

        self._audit_action("cloud_delete", composite_id, ptype,
                           success=True, confirmed=True, account=account)
        self.notify(f"OVH instance {label} deleted.", severity="information", markup=False)
        await self._load_instances(update_fleet=True)

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
        account: str = "",
    ) -> None:
        """Forward to the app's :class:`OVHAuditLogger` if present.

        Mirrors the pattern :class:`OVHCloudCreateScreen` already uses
        for ``cloud_create`` so the OVH audit trail captures the full
        lifecycle (create → start/stop/reboot/delete) in one log file.
        *account* (the row's real account label) is recorded when OVH has
        several accounts.
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
                details=with_account(self.app, "ovh", account, details),
                confirmed=confirmed,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to write OVH audit row: %s", exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _display_id(self, value: str) -> str:
        if not self.app.demo_mode:
            return value
        redactor = self.app.redaction_service
        return redactor.redact_instance_id(value) if redactor else "Hidden"

    def _provider_error(self, error: Exception) -> str:
        if self.app.demo_mode:
            return "Provider request failed. See logs for details."
        return self._short_err(error)

    def _set_status(self, text: Union[str, Content]) -> None:
        # Provider errors quote real ids and names: demo mode shows stand-ins.
        text = display_text(self.app, text)
        try:
            self.query_one("#ovh_mgr_status", Static).update(text)
        except Exception:  # pragma: no cover - defensive
            pass

    @staticmethod
    def _short_err(exc: Exception) -> str:
        msg = str(exc)
        return msg if len(msg) <= 200 else msg[:197] + "…"
