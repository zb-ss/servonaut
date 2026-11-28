"""Custom servers management screen for Servonaut v2.0."""

from __future__ import annotations

from collections.abc import Mapping
from functools import partial
from pathlib import Path
from typing import Any, Optional

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Grid, Horizontal, ScrollableContainer, Vertical
from textual.screen import ModalScreen

from servonaut.widgets.action_button import ActionButton, ActionRow
from servonaut.widgets.dialogs import (
    DialogActions,
    DialogBody,
    DialogFrame,
    DialogNotificationSpace,
)
from servonaut.screens._busy_work import BusyWork
from servonaut.widgets.busy_indicator import BusyIndicator
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen
from textual.widgets import Button, DataTable, Footer, Input, Label, Select, Static, TextArea

from servonaut.config.schema import CustomServer
from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens._demo_resolve import (
    display_text,
    real_fleet_rows,
    reconcile_team_memory,
    replace_instances,
    team_rows,
)
from servonaut.screens._vault_bind import apply_vault_binding, format_vault_bind_error
from servonaut.utils.markup import cell


class _CustomRenameConfirmModal(ModalScreen[bool]):
    """Confirm renaming a custom server when linked state cannot move automatically."""

    DEFAULT_CLASSES = "dialog-screen"
    AUTO_FOCUS = "#custom_rename_cancel"
    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]
    DEFAULT_CSS = """
    _CustomRenameConfirmModal #custom_rename_modal {
        width: 72;
        max-width: 92%;
        height: auto;
        border: round $warning;
        background: transparent;
        padding: 1 2;
    }
    _CustomRenameConfirmModal #custom_rename_title {
        text-style: bold;
        color: $text-warning;
    }
    _CustomRenameConfirmModal #custom_rename_body {
        margin-top: 1;
        height: auto;
    }
    _CustomRenameConfirmModal #custom_rename_cancel,
    _CustomRenameConfirmModal #custom_rename_confirm {
        width: auto;
        min-width: 12;
    }
    """

    def __init__(self, old_name: str, new_name: str, consequences: list[str]) -> None:
        super().__init__()
        self._old_name = old_name
        self._new_name = new_name
        self._consequences = list(consequences)

    def _body_text(self, *, redacted: bool) -> Text:
        if redacted and self.app.redaction_service:
            old_shown = self.app.redaction_service.redact_name(self._old_name)
            new_shown = self.app.redaction_service.redact_name(self._new_name)
            items = [self.app.redaction_service.scrub_stream(display_text(self.app, item)) for item in self._consequences]
        else:
            old_shown = self._old_name
            new_shown = self._new_name
            items = list(self._consequences)
        lines = [
            f"Renaming {old_shown} to {new_shown} migrates local key overrides, "
            "memory opt-outs, custom log paths, DB scan roots, and keyword results.",
            "",
            "These linked references will not follow automatically:",
            *[f"  • {item}" for item in items],
        ]
        return Text("\n".join(lines))

    def _render_body(self) -> None:
        if self.app.demo_mode and self.app.redaction_service:
            text = self._body_text(redacted=True)
        else:
            text = self._body_text(redacted=False)
        self.query_one("#custom_rename_body", Static).update(text)

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        yield DialogNotificationSpace()
        yield DialogFrame(
            heading=Static("[bold]Confirm server rename[/bold]", id="custom_rename_title"),
            body=DialogBody(
                Static(
                    self._body_text(redacted=bool(self.app.demo_mode and self.app.redaction_service)),
                    id="custom_rename_body",
                )
            ),
            actions=DialogActions(
                Button("Cancel", id="custom_rename_cancel"),
                Button("Rename anyway", variant="primary", id="custom_rename_confirm"),
            ),
            severity="warning",
            size="compact",
            id="custom_rename_modal",
        )

    def refresh_after_demo_toggle(self) -> None:
        self._render_body()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "custom_rename_confirm")

    def action_cancel(self) -> None:
        self.dismiss(False)


class CustomServersScreen(WorkspaceScreen):
    """CRUD screen for managing non-AWS custom servers."""

    CHAT_REFLOW = True
    # Body padding and scrollbar (4) plus the Add / Remove Selected / Back
    # button row at the global button minimum and Back's own margins.
    CHAT_MIN_CONTENT_WIDTH = 58
    # Two labelled form columns need room beyond the single-column minimum.
    CONTENT_NARROW_WIDTH = 80

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("n", "add_server", "Add", show=True),
        Binding("e", "edit_server", "Edit", show=True),
        Binding("d", "remove_server", "Remove", show=True),
    ]

    DEFAULT_CSS = """
    CustomServersScreen #custom_post_save_row {
        height: auto;
        margin: 1 0;
        padding: 0 1;
        border: round $border-blurred;
        background: transparent;
    }
    CustomServersScreen #custom_post_save_text {
        width: 100%;
        height: auto;
        color: $text-muted;
    }
    CustomServersScreen .custom_post_save_actions {
        width: 100%;
        height: auto;
    }
    CustomServersScreen #btn_edit_server {
        width: auto;
    }
    CustomServersScreen #select_custom_ssh_key {
        width: 100%;
        margin: 0 0 1 0;
    }
    CustomServersScreen #btn_custom_open_server,
    CustomServersScreen #btn_custom_bind_vault,
    CustomServersScreen #btn_custom_share_team {
        width: auto;
        min-width: 0;
        margin: 0 1 0 0;
    }
    """

    def __init__(self, open_add_form: bool = False) -> None:
        super().__init__()
        self._open_add_form = open_add_form
        self._editing_name: Optional[str] = None
        self._last_saved_name: Optional[str] = None
        self._busy = BusyWork(self, "#custom_busy")
        self._manageable_teams: Optional[list[dict[str, Any]]] = None

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if self.navigation_focused:
            return super().check_action(action, parameters)
        return check_action_passthrough(self, action)

    def compose(self) -> ComposeResult:
        """Keep the saved inventory and connection editor visually distinct."""
        yield SafeHeader()
        yield WorkspaceControls("Custom servers")
        with Horizontal(id="main-layout", classes="workspace-chat-layout"):
            yield self.workspace_sidebar()
            with Container(id="custom_servers_workspace", classes="workspace-content"):
                with ScrollableContainer(id="custom_servers_container"):
                    yield Static("Custom servers", id="custom_servers_header")
                    yield Static(
                        "Your SSH hosts, available alongside cloud servers in Instances.",
                        id="custom_servers_intro",
                    )
                    with Container(id="custom_servers_records"):
                        with Horizontal(id="custom_servers_toolbar"):
                            yield Static("Saved hosts", classes="custom-section-title")
                            with ActionRow(classes="add_row"):
                                yield ActionButton("Add server", "n", short="Add", role="primary", id="btn_add_server")
                                yield ActionButton("Edit selected", "e", short="Edit", id="btn_edit_server")
                                yield ActionButton(
                                    "Remove selected", "d", short="Remove", role="error", id="btn_remove_server"
                                )
                                yield ActionButton("Back", "esc", id="btn_back")
                        yield DataTable(id="custom_servers_table")
                        yield Static(
                            "Use the arrow keys to choose a host, or press e / Enter to edit. Scroll sideways for all connection fields.",
                            classes="custom-record-note",
                        )
                    yield BusyIndicator(id="custom_busy")
                    with Vertical(id="custom_post_save_row"):
                        yield Static("", id="custom_post_save_text", markup=False)
                        with Horizontal(classes="custom_post_save_actions"):
                            yield Button("Open server", variant="primary", compact=True, id="btn_custom_open_server")
                            yield Button("Bind vault key", compact=True, id="btn_custom_bind_vault")
                            yield Button("Share with team", compact=True, id="btn_custom_share_team")
                    with Container(id="add_form"):
                        yield Static("Server details", classes="custom-section-title")
                        yield Static("Connection", classes="custom-form-group-title")
                        with Grid(classes="custom-field-grid"):
                            with Vertical(classes="custom-field"):
                                yield Label("Name")
                                yield Input(placeholder="web-1", id="input_name")
                            with Vertical(classes="custom-field"):
                                yield Label("Host or IP address")
                                yield Input(placeholder="192.168.1.1", id="input_host")
                            with Vertical(classes="custom-field"):
                                yield Label("Username")
                                yield Input(placeholder="root", id="input_username")
                            with Vertical(classes="custom-field"):
                                yield Label("SSH key path (optional)")
                                yield Select(
                                    [],
                                    prompt="Pick a local SSH key (optional)…",
                                    allow_blank=True,
                                    id="select_custom_ssh_key",
                                )
                                yield Input(placeholder="~/.ssh/id_rsa", id="input_ssh_key")
                            with Vertical(classes="custom-field"):
                                yield Label("SSH port")
                                yield Input(placeholder="22", id="input_port")
                        yield Static("Organization", classes="custom-form-group-title")
                        with Grid(classes="custom-field-grid"):
                            with Vertical(classes="custom-field"):
                                yield Label("Provider")
                                yield Input(placeholder="Hosting provider", id="input_provider")
                            with Vertical(classes="custom-field"):
                                yield Label("Group")
                                yield Input(placeholder="web-servers", id="input_group")
                        yield Static("Advanced SSH", classes="custom-form-group-title")
                        yield Label("Extra SSH options, one KEY=VALUE per line")
                        yield TextArea("", id="input_extra_ssh_options", classes="extra_ssh_options")
                        yield Static(
                            "Passed to ssh -o. Example: HostKeyAlgorithms=+ssh-rsa for legacy hosts.",
                            classes="note",
                        )
                with ActionRow(id="add_form_actions"):
                    yield ActionButton("Save", role="primary", id="btn_save_server")
                    yield ActionButton("Cancel", id="btn_cancel_form")
        yield Footer()

    def on_mount(self) -> None:
        """Set up table and hide form on mount."""
        self._setup_table()
        self._populate_table()
        self.query_one("#custom_post_save_row").display = False
        self._refresh_ssh_key_select()
        self._hide_form()
        if self._open_add_form:
            self._show_form()

    def refresh_after_demo_toggle(self) -> None:
        """Redraw the table; close an open form when demo mode turns on.

        An open form is bound to the real record, so its fields hold the
        real host, key path and SSH options — the same reason editing is
        refused in demo mode.
        """
        self._populate_table()
        self._refresh_ssh_key_select()
        if self.app.demo_mode and self.query_one("#add_form").display:
            self._show_form()  # resets every field to the blank "add" state
            self._hide_form()

    def _refresh_ssh_key_select(self) -> None:
        try:
            select = self.query_one("#select_custom_ssh_key", Select)
        except Exception:
            return
        if self.app.demo_mode and self.app.redaction_service:
            select.display = False
            select.set_options([])
            return
        ssh_svc = getattr(self.app, "ssh_service", None)
        from servonaut.services.ssh_host_keys import home_relative

        keys = ssh_svc.list_available_keys() if ssh_svc is not None and hasattr(ssh_svc, "list_available_keys") else []
        options: list[tuple[str, str]] = []
        check_perms = getattr(ssh_svc, "check_key_permissions", None) if ssh_svc is not None else None
        for raw_key in keys:
            shown = home_relative(str(raw_key))
            label = shown
            if callable(check_perms) and Path(str(raw_key)).expanduser().exists():
                try:
                    if not check_perms(str(raw_key)):
                        label = f"{shown} (insecure permissions: expected 0600)"
                except Exception:
                    pass
            options.append((label, shown))
        select.set_options(options)
        select.display = bool(options)

    def _setup_table(self) -> None:
        """Configure DataTable columns."""
        table = self.query_one("#custom_servers_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Name", "Host", "Port", "Username", "Key", "Provider", "Group")

    def _populate_table(self, select_name: Optional[str] = None) -> None:
        """Populate DataTable with current custom servers.

        Demo mode routes every cell through the same per-field redactors
        ``RedactionService.redact_instance`` applies to the Instances table,
        so a server carries one fake identity across both views.  A stream
        scrub is not enough here: server names, bare hostnames, key paths and
        group names have no stream rule and would render verbatim.
        """
        table = self.query_one("#custom_servers_table", DataTable)
        prev_row = table.cursor_row
        table.clear()

        redaction = None
        if self.app.demo_mode and self.app.redaction_service:
            redaction = self.app.redaction_service

        servers = list(self.app.custom_server_service.list_servers())
        for server in servers:
            table.add_row(*(cell(value) for value in self._display_row(server, redaction)))

        if not servers:
            return
        target_row = None
        if select_name is not None:
            for idx, server in enumerate(servers):
                if server.name == select_name:
                    target_row = idx
                    break
        if target_row is None and isinstance(prev_row, int) and prev_row >= 0:
            target_row = min(prev_row, len(servers) - 1)
        if target_row is not None:
            table.move_cursor(row=target_row)

    @staticmethod
    def _display_row(server: CustomServer, redaction) -> tuple:
        """Cells for one table row, redacted when ``redaction`` is set."""
        if redaction is None:
            return (
                server.name,
                server.host,
                str(server.port),
                server.username,
                server.ssh_key or "-",
                server.provider or "-",
                server.group or "-",
            )
        return (
            redaction.redact_name(server.name),
            redaction.redact_host(server.host),
            str(server.port),
            redaction.redact_username(server.username),
            redaction.redact_key_name(server.ssh_key) if server.ssh_key else "-",
            redaction.redact_provider(server.provider) if server.provider else "-",
            redaction.redact_group(server.group) if server.group else "-",
        )

    def _hide_form(self) -> None:
        """Hide the add/edit form AND its docked Save/Cancel row."""
        self._editing_name = None
        self.query_one("#add_form").display = False
        self.query_one("#add_form_actions").display = False
        self.query_one("#btn_save_server").disabled = True
        self.query_one("#btn_cancel_form").disabled = True

    def _show_form(self, server: CustomServer = None) -> None:
        """Show the add/edit form, optionally pre-filled.

        The bottom-docked action row is mirrored: when the form is
        visible the row is too, so Save / Cancel are always reachable.
        """
        if server is not None and self.app.demo_mode and self.app.redaction_service:
            # The form is bound to the real record; pre-filling it would put
            # the raw host, key path and SSH options on screen.
            self.app.notify(
                "Editing is disabled in demo mode — the form would show "
                "the real values. Press ctrl+shift+d to turn demo mode off.",
                severity="warning",
            )
            return

        self._editing_name = server.name if server is not None else None
        self.query_one("#custom_post_save_row").display = False
        self._refresh_ssh_key_select()
        form = self.query_one("#add_form")
        form.display = True
        self.query_one("#add_form_actions").display = True
        self.query_one("#btn_save_server").disabled = False
        self.query_one("#btn_cancel_form").disabled = False

        extras_area = self.query_one("#input_extra_ssh_options", TextArea)
        key_select = self.query_one("#select_custom_ssh_key", Select)
        key_select.clear()
        if server:
            self.query_one("#input_name", Input).value = server.name
            self.query_one("#input_host", Input).value = server.host
            self.query_one("#input_username", Input).value = server.username
            self.query_one("#input_ssh_key", Input).value = server.ssh_key
            self.query_one("#input_port", Input).value = str(server.port)
            self.query_one("#input_provider", Input).value = server.provider
            self.query_one("#input_group", Input).value = server.group
            extras_area.text = "\n".join(server.extra_ssh_options)
        else:
            self.query_one("#input_name", Input).value = ""
            self.query_one("#input_host", Input).value = ""
            self.query_one("#input_username", Input).value = "root"
            self.query_one("#input_ssh_key", Input).value = ""
            self.query_one("#input_port", Input).value = "22"
            self.query_one("#input_provider", Input).value = ""
            self.query_one("#input_group", Input).value = ""
            extras_area.text = ""

        self.query_one("#input_name", Input).focus()
        if getattr(self, "is_attached", False):
            self.call_after_refresh(self._scroll_form_top)

    def _scroll_form_top(self) -> None:
        form = self.query_one("#add_form")
        if form.display:
            form.scroll_visible(animate=False, top=True)
            name_input = self.query_one("#input_name", Input)
            name_input.scroll_visible(animate=False, top=True)
            name_input.focus()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "select_custom_ssh_key" and isinstance(event.value, str) and event.value:
            self.query_one("#input_ssh_key", Input).value = event.value
            ssh_svc = getattr(self.app, "ssh_service", None)
            check_perms = getattr(ssh_svc, "check_key_permissions", None) if ssh_svc is not None else None
            if callable(check_perms) and Path(event.value).expanduser().exists():
                try:
                    if not check_perms(event.value):
                        self.app.notify(
                            f"{event.value} has overly open permissions; run chmod 600 on it.",
                            severity="warning",
                            markup=False,
                        )
                except Exception:
                    pass

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "custom_servers_table":
            self.action_edit_server()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events."""
        button_id = event.button.id

        if button_id == "btn_add_server":
            self.action_add_server()
        elif button_id == "btn_edit_server":
            self.action_edit_server()
        elif button_id == "btn_remove_server":
            self.action_remove_server()
        elif button_id == "btn_save_server":
            self._save_server()
        elif button_id == "btn_cancel_form":
            self._hide_form()
        elif button_id == "btn_custom_open_server":
            self._open_saved_server()
        elif button_id == "btn_custom_bind_vault":
            self._bind_saved_server_vault()
        elif button_id == "btn_custom_share_team":
            self._share_saved_server_team()
        elif button_id == "btn_back":
            self.action_back()

    def action_add_server(self) -> None:
        """Show form to add a new server."""
        self._show_form()

    def action_edit_server(self) -> None:
        """Show form to edit the selected server."""
        table = self.query_one("#custom_servers_table", DataTable)
        row = table.cursor_row
        servers = self.app.custom_server_service.list_servers()
        if row < 0 or row >= len(servers):
            self.app.notify("No server selected", severity="warning")
            return
        self._show_form(servers[row])

    def action_remove_server(self) -> None:
        """Remove the selected server from the table."""
        table = self.query_one("#custom_servers_table", DataTable)
        row = table.cursor_row
        servers = self.app.custom_server_service.list_servers()

        if row < 0 or row >= len(servers):
            self.app.notify("No server selected", severity="warning")
            return

        name = servers[row].name
        shown = name
        if self.app.demo_mode and self.app.redaction_service:
            # The toast is on screen too: show the same fake name as the row.
            shown = self.app.redaction_service.redact_name(name)
        if self.app.custom_server_service.remove_server(name):
            self._populate_table()
            self._refresh_app_instances()
            self.app.notify(f"Removed server: {shown}", severity="information", markup=False)
        else:
            self.app.notify(f"Server '{shown}' not found", severity="error", markup=False)

    def _save_server(self) -> None:
        """Validate form and save the server."""
        name = self.query_one("#input_name", Input).value.strip()
        host = self.query_one("#input_host", Input).value.strip()
        username = self.query_one("#input_username", Input).value.strip() or "root"
        ssh_key = self.query_one("#input_ssh_key", Input).value.strip()
        port_str = self.query_one("#input_port", Input).value.strip() or "22"
        provider = self.query_one("#input_provider", Input).value.strip()
        group = self.query_one("#input_group", Input).value.strip()
        extras_raw = self.query_one("#input_extra_ssh_options", TextArea).text
        extra_ssh_options = [
            line.strip() for line in extras_raw.splitlines() if line.strip()
        ]

        if not name:
            self.app.notify("Name is required", severity="error")
            self.query_one("#input_name", Input).focus()
            return

        if not host:
            self.app.notify("Host is required", severity="error")
            self.query_one("#input_host", Input).focus()
            return

        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError()
        except ValueError:
            self.app.notify("Port must be a number between 1 and 65535", severity="error")
            self.query_one("#input_port", Input).focus()
            return

        editing_name = getattr(self, "_editing_name", None)
        svc = self.app.custom_server_service
        existing_raw = svc.get_server(editing_name) if editing_name else None
        existing_old = existing_raw if isinstance(existing_raw, CustomServer) else None
        if editing_name is None:
            if isinstance(svc.get_server(name), CustomServer):
                self.app.notify(
                    f"Custom server '{name}' already exists. Select it and press Edit to modify it.",
                    severity="error",
                    markup=False,
                )
                self.query_one("#input_name", Input).focus()
                return
        elif editing_name != name:
            if isinstance(svc.get_server(name), CustomServer):
                self.app.notify(f"Custom server '{name}' already exists", severity="error", markup=False)
                self.query_one("#input_name", Input).focus()
                return

        server = CustomServer(
            name=name,
            host=host,
            username=username,
            ssh_key=ssh_key,
            port=port,
            provider=provider,
            group=group,
            tags=dict(existing_old.tags) if existing_old is not None else {},
            extra_ssh_options=extra_ssh_options,
        )

        # Demo mode: what the operator typed on camera renders as typed.
        if self.app.demo_mode and self.app.redaction_service:
            self.app.redaction_service.keep_as_authored(
                name, host, username, ssh_key, provider, group,
            )

        if editing_name and editing_name != name:
            sync_consequences = self._rename_orphan_consequences(editing_name, server, existing_old)
            needs_vault_check = bool(
                getattr(self.app, "vault_available", False)
                or callable(getattr(getattr(self.app, "vault_command_service", None), "personal_binding", None))
            )
            if sync_consequences or needs_vault_check:
                self.run_worker(
                    self._confirm_and_commit_rename(editing_name, server, existing_old, sync_consequences),
                    group="custom_server_save",
                    exclusive=True,
                )
                return

        self._commit_save_server(editing_name, server)

    def _rename_orphan_consequences(
        self,
        old_name: str,
        new_server: CustomServer,
        old_server: Optional[CustomServer],
    ) -> list[str]:
        """Return user-visible descriptions of links referencing *old_name* that cannot follow."""
        from servonaut.utils.match_utils import matches_conditions

        consequences: list[str] = []
        old_id = f"custom-{old_name}"
        svc = self.app.custom_server_service
        old_dict = (
            svc.to_instance_dict(old_server)
            if old_server is not None and hasattr(svc, "to_instance_dict")
            else {
                "id": old_id,
                "name": old_name,
                "public_ip": new_server.host,
                "private_ip": new_server.host,
                "provider": new_server.provider or "custom",
                "group": new_server.group,
                "tags": dict(new_server.tags),
                "is_custom": True,
            }
        )
        new_dict = (
            svc.to_instance_dict(new_server)
            if hasattr(svc, "to_instance_dict")
            else {
                **old_dict,
                "id": f"custom-{new_server.name}",
                "name": new_server.name,
            }
        )

        config_manager = getattr(self.app, "config_manager", None)
        config = config_manager.get() if config_manager is not None else None
        if config is not None:
            broken_conn = [
                rule.name or "(unnamed rule)"
                for rule in (getattr(config, "connection_rules", None) or [])
                if matches_conditions(old_dict, rule.match_conditions)
                and not matches_conditions(new_dict, rule.match_conditions)
            ]
            if broken_conn:
                consequences.append(
                    f"Connection rules ({', '.join(broken_conn)}) match '{old_name}' and will stop matching."
                )
            broken_scan = [
                rule.name or "(unnamed rule)"
                for rule in (getattr(config, "scan_rules", None) or [])
                if matches_conditions(old_dict, rule.match_conditions)
                and not matches_conditions(new_dict, rule.match_conditions)
            ]
            if broken_scan:
                consequences.append(
                    f"Scan rules ({', '.join(broken_scan)}) match '{old_name}' and will stop matching."
                )
            keyed_names = {old_name.casefold(), old_id.casefold()}
            db_matches = [
                prof.name or prof.instance
                for prof in (getattr(config, "db_profiles", None) or [])
                if str(getattr(prof, "instance", "")).casefold() in keyed_names
            ]
            if db_matches:
                consequences.append(
                    f"Database profiles ({', '.join(db_matches)}) target '{old_name}' and must be updated."
                )

        shared_teams = [
            str(row.get("team_name") or row.get("team_slug") or "team")
            for row in (team_rows(self.app) or [])
            if str(row.get("instance_id") or "") == old_id
        ]
        if shared_teams:
            consequences.append(
                f"Team shared server entries in {', '.join(shared_teams)} keep their original server record."
            )
        return consequences

    async def _confirm_and_commit_rename(
        self,
        old_name: str,
        new_server: CustomServer,
        old_server: Optional[CustomServer],
        base_consequences: list[str],
    ) -> None:
        consequences = list(base_consequences)
        vault_svc = getattr(self.app, "vault_command_service", None)
        old_row = {
            "id": f"custom-{old_name}",
            "name": old_name,
            "is_custom": True,
            "provider": (old_server.provider if old_server else new_server.provider) or "custom",
            "public_ip": old_server.host if old_server else new_server.host,
            "private_ip": old_server.host if old_server else new_server.host,
        }
        has_personal_lookup = callable(getattr(vault_svc, "personal_binding", None))
        if has_personal_lookup:
            try:
                binding = await vault_svc.personal_binding(old_row)
            except Exception:
                binding = None
                if getattr(self.app, "vault_available", False):
                    consequences.insert(
                        0,
                        f"Any personal Vault key binding for '{old_name}' won't follow; rebind after renaming.",
                    )
            else:
                if isinstance(binding, Mapping) and binding:
                    consequences.insert(
                        0,
                        f"The personal Vault key binding for '{old_name}' won't follow; rebind after renaming.",
                    )
        elif getattr(self.app, "vault_available", False):
            consequences.insert(
                0,
                f"Any personal Vault key binding for '{old_name}' won't follow; rebind after renaming.",
            )

        if consequences:
            confirmed = await self.app.push_screen_wait(
                _CustomRenameConfirmModal(old_name, new_server.name, consequences)
            )
            if not confirmed:
                return
        self._commit_save_server(old_name, new_server)

    def _migrate_local_rename_state(self, old_name: str, new_name: str) -> None:
        """Move local-only state keyed by *old_name* / ``custom-<old_name>``."""
        old_id = f"custom-{old_name}"
        new_id = f"custom-{new_name}"
        config_manager = getattr(self.app, "config_manager", None)
        if config_manager is not None:
            config = config_manager.get()
            dirty = False
            key_pairs = ((old_id, new_id), (old_name, new_name))
            instance_keys = getattr(config, "instance_keys", None)
            if isinstance(instance_keys, dict):
                if old_id in instance_keys:
                    val = instance_keys.pop(old_id)
                    instance_keys.setdefault(new_id, val)
                    dirty = True
                if old_name in instance_keys:
                    val = instance_keys.pop(old_name)
                    instance_keys.setdefault(new_name, val)
                    dirty = True
            mem = getattr(config, "memory", None)
            overrides = getattr(mem, "per_server_overrides", None) if mem is not None else None
            if isinstance(overrides, dict):
                for src, dst in key_pairs:
                    if src in overrides:
                        val = overrides.pop(src)
                        overrides.setdefault(dst, val)
                        dirty = True
            for attr in ("log_viewer_custom_paths", "db_scan_roots"):
                mapping = getattr(config, attr, None)
                if isinstance(mapping, dict):
                    for src, dst in key_pairs:
                        if src in mapping:
                            val = mapping.pop(src)
                            mapping.setdefault(dst, val)
                            dirty = True
            if dirty:
                config_manager.save(config)
        keyword_store = getattr(self.app, "keyword_store", None)
        rename_kw = getattr(keyword_store, "rename_server_id", None)
        if callable(rename_kw):
            rename_kw(old_id, new_id)

    def _commit_save_server(self, editing_name: Optional[str], server: CustomServer) -> None:
        svc = self.app.custom_server_service
        name = server.name
        if editing_name and editing_name != name:
            try:
                updated = svc.update_server(editing_name, server)
                if not updated:
                    svc.add_server(server)
                    svc.remove_server(editing_name)
            except ValueError as e:
                self.app.notify(str(e), severity="error", markup=False)
                return
            self._migrate_local_rename_state(editing_name, name)
        elif editing_name:
            if not svc.update_server(editing_name, server):
                try:
                    svc.add_server(server)
                except ValueError as e:
                    self.app.notify(str(e), severity="error", markup=False)
                    return
        else:
            try:
                svc.add_server(server)
            except ValueError as e:
                self.app.notify(str(e), severity="error", markup=False)
                return

        self._populate_table(select_name=name)
        self._refresh_app_instances()
        self._hide_form()
        self._show_post_save_row(name)
        shown = name
        if self.app.demo_mode and self.app.redaction_service:
            shown = self.app.redaction_service.redact_name(name)
        self.app.notify(f"Saved server: {shown}", severity="information", markup=False)

    def _show_post_save_row(self, name: str) -> None:
        self._last_saved_name = name
        auth_svc = getattr(self.app, "auth_service", None)
        can_team = bool(
            auth_svc is not None
            and getattr(auth_svc, "is_authenticated", False)
            and auth_svc.has_feature("team_workspaces")
            and getattr(self.app, "team_service", None) is not None
        )
        can_vault = bool(getattr(self.app, "vault_available", False) and getattr(self.app, "vault_command_service", None) is not None)
        self.query_one("#custom_post_save_text", Static).update(
            "Server saved. Choose your next step:"
        )
        self.query_one("#btn_custom_bind_vault", Button).display = can_vault
        share_btn = self.query_one("#btn_custom_share_team", Button)
        share_btn.display = False
        open_btn = self.query_one("#btn_custom_open_server", Button)
        row = self.query_one("#custom_post_save_row")
        row.display = True
        self.set_focus(open_btn)
        if getattr(self, "is_attached", False):
            self.call_after_refresh(self._reveal_post_save_row)
            self.call_later(self._reveal_post_save_row)
        if can_team:
            self.run_worker(
                self._probe_post_save_share_teams(),
                group="custom_share_gate",
                exclusive=True,
            )

    def _reveal_post_save_row(self) -> None:
        if not getattr(self, "is_attached", True):
            return
        row = self.query_one("#custom_post_save_row")
        if row.display:
            row.scroll_visible(animate=False, top=True)
            btn = self.query_one("#btn_custom_open_server", Button)
            if btn.display:
                self.set_focus(btn)

    async def _probe_post_save_share_teams(self) -> None:
        from servonaut.screens._team_share import resolve_manageable_teams

        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        try:
            manageable, _ = await resolve_manageable_teams(self.app, team_svc)
        except Exception:
            return
        self._manageable_teams = manageable
        if not self.is_attached:
            return
        try:
            self.query_one("#btn_custom_share_team", Button).display = bool(manageable)
        except Exception:
            pass

    def _saved_display_row(self) -> Optional[dict]:
        name = self._last_saved_name
        if not name:
            return None
        for row in getattr(self.app, "instances", None) or []:
            if row.get("is_custom") is True and row.get("name") == name:
                return row
        for row in real_fleet_rows(self.app) or []:
            if row.get("is_custom") is True and row.get("name") == name:
                return row
        return None

    def _saved_real_row(self) -> Optional[dict]:
        name = self._last_saved_name
        if not name:
            return None
        for row in real_fleet_rows(self.app) or []:
            if row.get("is_custom") is True and row.get("name") == name:
                return row
        return None

    def _open_saved_server(self) -> None:
        row = self._saved_display_row()
        if row is None:
            self.app.notify("Saved server row is not loaded in Instances yet.", severity="warning")
            return
        from servonaut.screens.server_actions import ServerActionsScreen

        self.app.push_screen(ServerActionsScreen(row))

    def _bind_saved_server_vault(self) -> None:
        service = getattr(self.app, "vault_command_service", None)
        if service is None:
            self.app.notify("Vault services are unavailable.", severity="warning", markup=False)
            return
        row = self._saved_real_row()
        if row is None:
            self.app.notify("Save the server first, or bind from Instances.", severity="warning")
            return

        async def _flow() -> None:
            from servonaut.screens.server_actions import VaultBindingModal

            values = await self.app.push_screen_wait(VaultBindingModal(service, row))
            if not values:
                return
            try:
                await apply_vault_binding(self.app, service, row, values)
            except Exception as exc:
                self.app.notify(
                    f"Vault key binding failed: {format_vault_bind_error(exc)}",
                    severity="error",
                    markup=False,
                )
                return
            self.app.notify("Vault key bound.", markup=False)

        self.run_worker(_flow(), group="vault", exclusive=True)

    def _share_saved_server_team(self) -> None:
        if self._busy.holds("#btn_custom_share_team"):
            self.app.notify(
                "Sharing this server with a team is still in progress: wait for it to finish.",
                severity="warning",
                markup=False,
            )
            return
        team_svc = getattr(self.app, "team_service", None)
        row = self._saved_real_row()
        if team_svc is None:
            self.app.notify("Team services are unavailable.", severity="warning")
            return
        if row is None:
            self.app.notify("Save the server first before sharing it.", severity="warning")
            return

        from servonaut.screens._team_share import share_server_with_team_flow

        self.run_worker(
            share_server_with_team_flow(
                self,
                row,
                team_svc,
                busy=self._busy,
                hold_selector="#btn_custom_share_team",
                manageable_teams=self._manageable_teams,
            ),
            group="team_share",
            exclusive=True,
        )

    def _refresh_app_instances(self) -> None:
        """Replace the custom-server rows in ``app.instances``.

        In demo mode the fresh rows are kept aside as the real records and
        listed redacted, like every other row — otherwise a save or remove
        would put real names back on the fleet table.
        """
        replace_instances(
            self.app, "custom", self.app.custom_server_service.list_as_instances()
        )
        reconcile_team_memory(self.app)

    def action_back(self) -> None:
        """Navigate back to main menu."""
        self.app.pop_screen()
