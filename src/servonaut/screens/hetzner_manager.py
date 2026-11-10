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
The two screens share no state; this one re-fetches every Hetzner
project through the provider inventory so it always reflects fresh
truth even when the unified table's cache is stale. Each lifecycle
action goes to the project the server belongs to.
"""

from __future__ import annotations

import logging
from typing import List, Optional, TYPE_CHECKING, Union

from rich.markup import escape
from rich.text import Text
from textual.app import ComposeResult
from textual.content import Content
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, DataTable, Footer, Static

from servonaut.utils.markup import inert_text, with_bold_values
from servonaut.utils.theme_text import themed_text
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
    row_service,
)
from servonaut.screens._table_cursor import keep_selected_row
from servonaut.screens.power_confirm import PowerActionText, confirm_and_run_power_action
from servonaut.utils.instance_resolver import display_name
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen

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

# Power actions that interrupt a running server ask first (yes/no); starting
# a stopped server does not. Values: (verb shown to the user, consequence).
_CONFIRM_POWER = {
    "shutdown": (
        "Shut down",
        "The operating system shuts down and the server's services stop "
        "until it is started again.",
    ),
    "power_off": (
        "Power off",
        "Power is cut at once, like pulling the plug: the operating system "
        "gets no chance to shut down and unsaved data can be lost.",
    ),
    "reboot": (
        "Reboot",
        "The server restarts and its services are unavailable until it is "
        "back up.",
    ),
}

# What each power action tells the user, naming the server as its row does.
_POWER_TEXT = {
    "power_on": PowerActionText(
        "Starting", "Start sent to {server}.", "Could not start {server}",
    ),
    "shutdown": PowerActionText(
        "Shutting down", "Shutdown sent to {server}.", "Could not shut down {server}",
    ),
    "power_off": PowerActionText(
        "Powering off", "Power off sent to {server}.", "Could not power off {server}",
    ),
    "reboot": PowerActionText(
        "Rebooting", "Reboot sent to {server}.", "Could not reboot {server}",
    ),
}


class HetznerManagerScreen(ProviderActionsMixin, DemoRowsMixin, WorkspaceScreen):
    """Hetzner Cloud server manager — list + lifecycle toolbar."""

    CHAT_REFLOW = True
    CHAT_MIN_CONTENT_WIDTH = 64
    CONTENT_NARROW_WIDTH = 117

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
        yield WorkspaceControls("Hetzner servers")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            inventory_panel = Vertical(
                Static("", id="hetzner_mgr_status"),
                DataTable(
                    id="hetzner_mgr_table",
                    zebra_stripes=True,
                    cursor_type="row",
                ),
                classes="provider-manager-inventory",
            )
            inventory_panel.border_title = "Cloud inventory"
            selection = Vertical(
                Static("Selected resource", classes="provider-manager-selection-label"),
                Static(
                    "No server selected", id="hetzner_mgr_selection",
                    classes="provider-manager-selection-name", markup=False,
                ),
                Static(
                    "Choose a row to see its full ID and address.",
                    id="hetzner_mgr_identity",
                    classes="provider-manager-selection-identity", markup=False,
                ),
                classes="provider-manager-selection",
            )
            actions = action_rail(
                "hetzner_mgr_actions",
                inventory=(
                    ActionSpec("btn_hetzner_mgr_refresh", "Refresh", "f5", disabled=False),
                    ActionSpec("btn_hetzner_mgr_new", "+ New", "n", role="primary", disabled=False),
                ),
                selection=selection,
                power=(
                    ActionSpec("btn_hetzner_mgr_power_on", "Start", "s", role="primary"),
                    ActionSpec("btn_hetzner_mgr_shutdown", "Shutdown", "t"),
                    ActionSpec("btn_hetzner_mgr_reboot", "Reboot", "b"),
                    ActionSpec(
                        "btn_hetzner_mgr_power_off", "Power off", role="warning",
                        tooltip="Hard power cut (like pulling the plug).",
                    ),
                ),
                danger=(
                    ActionSpec("btn_hetzner_mgr_delete", "Delete", "d", role="error"),
                ),
            )
            actions.border_title = "Resource actions"
            rail = Vertical(actions, classes="provider-manager-rail")
            rail.border_title = "Resource workspace"
            yield ScrollableContainer(
                Vertical(
                    Horizontal(
                        Static("Hetzner Cloud servers", id="hetzner_mgr_header"),
                        Static(
                            "Inventory", id="hetzner_mgr_overview",
                            classes="provider-manager-overview", markup=False,
                        ),
                        classes="provider-manager-heading-row",
                    ),
                    Static(
                        "Select a server to manage its power. Start requires a "
                        "stopped server; Shutdown, Power off and Reboot require "
                        "a running one.",
                        id="hetzner_mgr_hint",
                    ),
                    classes="provider-manager-heading",
                ),
                Horizontal(
                    inventory_panel, rail, classes="provider-manager-body",
                ),
                id="hetzner_mgr_container",
                classes="workspace-content provider-manager-content",
            )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#hetzner_mgr_table", DataTable)
        table.add_columns(
            "#", "Name", "ID", "Type", "State", "Public IP",
            "Region", "Created",
        )
        self.sync_compact_actions()
        self._refresh()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if self._loading:
            return
        if inventory(self.app, "hetzner") is None:
            self._set_status(
                "[$text-error]Hetzner Cloud is not configured. "
                "Visit Settings → Hetzner Cloud to set up a token.[/$text-error]"
            )
            return
        self._loading = True
        self._set_status("[dim]Loading servers…[/dim]")
        self.run_worker(
            self._load_instances(),
            exclusive=True,
            name="hetzner_mgr_load",
        )

    async def _load_instances(self, *, update_fleet: bool = False) -> None:
        """Fetch every account's servers into the table.

        *update_fleet* also puts them in the server list, after this screen
        changed the fleet (a server deleted here must leave it too).
        """
        # Every project at once: the table lists all of them.
        svc = inventory(self.app, "hetzner")
        try:
            instances = await svc.fetch_instances_cached(force_refresh=True)
            # Keep the fetched rows untouched; what the table draws is
            # derived from them (demo-mode fakes when demo mode is on).
            self._raw_instances = list(instances)
            if update_fleet:
                replace_instances(self.app, "hetzner", instances)
                reconcile_team_memory(self.app)
            self._apply_display_rows()
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
                    + self._project_errors(svc)
                )
        except Exception as exc:
            logger.error("Failed to load Hetzner servers: %s", exc)
            err_msg = self._short_err(exc)
            if self.app.demo_mode and self.app.redaction_service:
                err_msg = self.app.redaction_service.scrub_stream(err_msg)
            self._set_status(
                f"[$text-error]Failed to load servers: {err_msg}[/$text-error]"
            )
        finally:
            self._loading = False

    def _render_table(self) -> None:
        table = self.query_one("#hetzner_mgr_table", DataTable)
        # The next action must reach the server the user picked, not row 1.
        with keep_selected_row(table):
            table.clear()
            for idx, inst in enumerate(self._instances, start=1):
                table.add_row(
                    str(idx),
                    Text(inert_text(display_name(inst))),
                    Text(inert_text(str(inst.get("id", "")))),
                    Text(inert_text(str(inst.get("type", "")))),
                    self._colorize_state(str(inst.get("state", ""))),
                    Text(inert_text(str(inst.get("public_ip", "") or "—"))),
                    Text(inert_text(str(inst.get("region", "")))),
                    Text(inert_text(str(inst.get("created_at", "") or "—")[:19])),
                    key=str(inst.get("id", idx)),
                )
        self._sync_action_buttons()
        self._update_resource_context()

    def _colorize_state(self, state: str) -> Text:
        s = state.lower()
        if s in _RUNNING:
            return themed_text(self.app, state, "text-success")
        if s in _STOPPED:
            return themed_text(self.app, state, "text-warning")
        if s in {"pending", "starting", "stopping", "rebuilding"}:
            return themed_text(self.app, state, "text-accent")
        if s == "error":
            return themed_text(self.app, state, "text-error")
        return Text(inert_text(state))

    # ------------------------------------------------------------------
    # Selection-driven button enablement
    # ------------------------------------------------------------------

    def _update_resource_context(self) -> None:
        """Show the drawn row's identity beside its existing resource actions."""
        try:
            selection = self.query_one("#hetzner_mgr_selection", Static)
            identity = self.query_one("#hetzner_mgr_identity", Static)
            overview = self.query_one("#hetzner_mgr_overview", Static)
        except NoMatches:
            return
        count = len(self._instances)
        accounts = {str(row.get("account") or "") for row in self._instances}
        summary = f"{count} server{'s' if count != 1 else ''}"
        if len(accounts) > 1:
            summary += f" across {len(accounts)} projects"
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
        table = self.query_one("#hetzner_mgr_table", DataTable)
        row = table.cursor_row
        if row < 0 or row >= len(self._instances):
            return None
        return self._instances[row]

    def _api_id(self, inst: dict) -> str:
        """Real provider id for an API call; the row may carry a demo-mode fake."""
        shown = str(inst.get("id") or "")
        return getattr(self, "_api_ids", {}).get(shown, shown)

    def _owning_service(self, inst: dict):
        """The service of the project *inst* belongs to, or None after telling why."""
        try:
            return row_service(
                self.app, fetched_row(self._instances, self._raw_instances, inst),
            )
        except UnknownAccountError as exc:
            self.notify(str(exc), severity="error", markup=False)
            return None

    @staticmethod
    def _row_label(inst: dict) -> str:
        """What to call a row's server: its name, else the id the table shows.

        The name is project-qualified when several projects are listed.
        The fallback is the row's id, never the API id: in demo mode the row
        carries a placeholder and the real id stays off the screen.
        """
        return display_name(inst) or str(inst.get("id") or "")

    def _project_errors(self, svc) -> str:
        """Status suffix naming projects whose servers could not be refreshed.

        Only several projects are reported here: one failing project among
        others still lists theirs, so the table alone would not show it.
        """
        error = getattr(svc, "last_fetch_error", None)
        if not getattr(svc, "multi", False) or not isinstance(error, str) or not error:
            return ""
        if self.app.demo_mode and self.app.redaction_service:
            error = self.app.redaction_service.scrub_stream(error)
        return f"\n[$text-warning]⚠ {escape(error)}[/$text-warning]"

    def _sync_action_buttons(self) -> None:
        self.sync_action_buttons()

    def unavailable_actions(self) -> dict[str, str | None]:
        """Why each action cannot run on the selected row, from its Hetzner status.

        * ``running`` -> shutdown / power off / reboot
        * ``stopped`` / ``off`` -> power on
        * anything else (transient) -> only delete; a server being created or
          deleted may reject it, and the audit row records the failure.
        """
        inst = self._selected_instance()
        state = (inst.get("state", "") if inst else "").lower()
        has_row = inst is not None
        running = state in _RUNNING
        return {
            "btn_hetzner_mgr_power_on": action_unavailable(has_row, state in _STOPPED, "Start needs a stopped server."),
            "btn_hetzner_mgr_shutdown": action_unavailable(has_row, running, "Shutdown needs a running server."),
            "btn_hetzner_mgr_power_off": action_unavailable(
                has_row, running, "Power off needs a running server.",
            ),
            "btn_hetzner_mgr_reboot": action_unavailable(has_row, running, "Reboot needs a running server."),
            "btn_hetzner_mgr_delete": action_unavailable(has_row, True, ""),
        }

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
        if inventory(self.app, "hetzner") is None:
            self.notify(
                "Hetzner is not configured. Visit Settings → Hetzner Cloud.",
                severity="warning", markup=False,
            )
            return
        from servonaut.screens.hetzner_create import HetznerCreateScreen
        self.app.push_screen(HetznerCreateScreen(), callback=self._on_create_closed)

    def _on_create_closed(self, created: Optional[bool]) -> None:
        """Reload the list once the wizard has created a server."""
        if created:
            self._refresh()

    def action_power_on(self) -> None:
        if not self.refuse_unavailable("btn_hetzner_mgr_power_on"):
            self._run_lifecycle("power_on")

    def action_shutdown(self) -> None:
        if not self.refuse_unavailable("btn_hetzner_mgr_shutdown"):
            self._run_lifecycle("shutdown")

    def action_power_off(self) -> None:
        if not self.refuse_unavailable("btn_hetzner_mgr_power_off"):
            self._run_lifecycle("power_off")

    def action_reboot(self) -> None:
        if not self.refuse_unavailable("btn_hetzner_mgr_reboot"):
            self._run_lifecycle("reboot")

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

    def _run_lifecycle(self, method: str) -> None:
        """Run power action *method* on the selected server, asking first if it interrupts."""
        inst = self._selected_instance()
        if inst is None:
            return
        identifier = self._api_id(inst) or str(inst.get("name") or "")
        if not identifier:
            self.notify(
                "Selected row has no id/name to act on.",
                severity="warning", markup=False,
            )
            return
        svc = self._owning_service(inst)
        if svc is None:
            return
        label = self._row_label(inst)
        self.run_worker(
            confirm_and_run_power_action(
                self.app,
                prompt=_CONFIRM_POWER.get(method),
                server_name=label,
                provider="Hetzner Cloud",
                in_progress_verb=_POWER_TEXT[method].in_progress,
                set_status=self._set_status,
                run=lambda: self._do_lifecycle(svc, method, identifier, label),
            ),
            exclusive=False,
            name=f"hetzner_mgr_{method}",
        )

    async def _do_lifecycle(
        self, svc, method: str, identifier: str, label: str,
    ) -> None:
        """Send *method* for *identifier* (the API id); the notices say *label*.

        *label* is the name the row shows, so demo mode never shows the real one.
        """
        text = _POWER_TEXT[method]
        try:
            await getattr(svc, method)(identifier)
        except Exception as exc:
            logger.error(
                "Hetzner %s failed for %s: %s", method, identifier, exc,
            )
            err_msg = self._short_err(exc)
            if self.app.demo_mode and self.app.redaction_service:
                err_msg = self.app.redaction_service.scrub_stream(err_msg)
            message = text.failed_message(label, err_msg)
            self._set_status(f"[$text-error]{escape(message)}[/$text-error]")
            self.notify(message, severity="error", markup=False)
            return
        self.notify(text.done_message(label), severity="information", markup=False)
        # Re-fetch so the table reflects the new state (running/stopped).
        await self._load_instances()

    async def _do_delete(self, inst: dict) -> None:
        identifier = self._api_id(inst) or str(inst.get("name") or "")
        label = self._row_label(inst)
        svc = self._owning_service(inst)
        if svc is None:
            return
        from servonaut.screens.confirm_action import ConfirmActionScreen
        confirmed = await self.app.push_screen_wait(
            ConfirmActionScreen(
                title="Delete Hetzner server",
                description=with_bold_values(
                    "Delete {} ({}) in {}?",
                    label, inst.get('type', ''), inst.get('region', ''),
                ),
                consequences=[
                    "All data on the server will be permanently destroyed",
                    "Any associated public IPs will be released",
                    "Billing for this server stops immediately",
                ],
                confirm_text="delete",
                action_label="Delete server",
                severity="danger",
            )
        )
        if not confirmed:
            return

        self._set_status(f"[dim]Deleting {escape(label)}…[/dim]")
        try:
            await svc.delete_server(identifier)
        except Exception as exc:
            logger.error(
                "Hetzner delete failed for %s: %s", identifier, exc,
            )
            err_msg = self._short_err(exc)
            if self.app.demo_mode and self.app.redaction_service:
                err_msg = self.app.redaction_service.scrub_stream(err_msg)
            self._set_status(
                f"[$text-error]Delete failed: {err_msg}[/$text-error]"
            )
            self.notify(
                f"Delete failed: {err_msg}",
                severity="error", markup=False,
            )
            return
        self.notify(f"Server {label} deleted.", severity="information", markup=False)
        await self._load_instances(update_fleet=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_status(self, text: Union[str, Content]) -> None:
        # Provider errors quote real ids and names: demo mode shows stand-ins.
        text = display_text(self.app, text)
        try:
            self.query_one("#hetzner_mgr_status", Static).update(text)
        except Exception:  # pragma: no cover - defensive
            pass

    @staticmethod
    def _short_err(exc: Exception) -> str:
        msg = str(exc)
        return msg if len(msg) <= 200 else msg[:197] + "…"
