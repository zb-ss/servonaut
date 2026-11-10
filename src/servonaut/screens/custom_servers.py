"""Custom servers management screen for Servonaut v2.0."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Grid, Horizontal, ScrollableContainer, Vertical

from servonaut.widgets.action_button import ActionButton, ActionRow
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.workspace import WorkspaceControls, WorkspaceScreen
from textual.widgets import Button, DataTable, Footer, Input, Label, Static, TextArea

from servonaut.config.schema import CustomServer
from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens._demo_resolve import reconcile_team_memory, replace_instances


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
        Binding("d", "remove_server", "Remove", show=True),
    ]

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
                                yield ActionButton("Add server", "n", role="primary", id="btn_add_server")
                                yield ActionButton(
                                    "Remove selected", "d", short="Remove", role="error", id="btn_remove_server"
                                )
                                yield ActionButton("Back", "esc", id="btn_back")
                        yield DataTable(id="custom_servers_table")
                        yield Static(
                            "Use the arrow keys to choose a host. Scroll sideways for all connection fields.",
                            classes="custom-record-note",
                        )
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
                                yield Label("SSH key path")
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
        self._hide_form()

    def refresh_after_demo_toggle(self) -> None:
        """Redraw the table; close an open form when demo mode turns on.

        An open form is bound to the real record, so its fields hold the
        real host, key path and SSH options — the same reason editing is
        refused in demo mode.
        """
        self._populate_table()
        if self.app.demo_mode and self.query_one("#add_form").display:
            self._show_form()  # resets every field to the blank "add" state
            self._hide_form()

    def _setup_table(self) -> None:
        """Configure DataTable columns."""
        table = self.query_one("#custom_servers_table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Name", "Host", "Port", "Username", "Key", "Provider", "Group")

    def _populate_table(self) -> None:
        """Populate DataTable with current custom servers.

        Demo mode routes every cell through the same per-field redactors
        ``RedactionService.redact_instance`` applies to the Instances table,
        so a server carries one fake identity across both views.  A stream
        scrub is not enough here: server names, bare hostnames, key paths and
        group names have no stream rule and would render verbatim.
        """
        table = self.query_one("#custom_servers_table", DataTable)
        table.clear()

        redaction = None
        if self.app.demo_mode and self.app.redaction_service:
            redaction = self.app.redaction_service

        for server in self.app.custom_server_service.list_servers():
            table.add_row(*self._display_row(server, redaction))

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
        self.query_one("#add_form").display = False
        self.query_one("#add_form_actions").display = False

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

        form = self.query_one("#add_form")
        form.display = True
        self.query_one("#add_form_actions").display = True

        extras_area = self.query_one("#input_extra_ssh_options", TextArea)
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

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press events."""
        button_id = event.button.id

        if button_id == "btn_add_server":
            self.action_add_server()
        elif button_id == "btn_remove_server":
            self.action_remove_server()
        elif button_id == "btn_save_server":
            self._save_server()
        elif button_id == "btn_cancel_form":
            self._hide_form()
        elif button_id == "btn_back":
            self.action_back()

    def action_add_server(self) -> None:
        """Show form to add a new server."""
        self._show_form()

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
            self.app.notify(f"Removed server: {shown}", severity="information")
        else:
            self.app.notify(f"Server '{shown}' not found", severity="error")

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

        server = CustomServer(
            name=name,
            host=host,
            username=username,
            ssh_key=ssh_key,
            port=port,
            provider=provider,
            group=group,
            extra_ssh_options=extra_ssh_options,
        )

        # Demo mode: what the operator typed on camera renders as typed.
        if self.app.demo_mode and self.app.redaction_service:
            self.app.redaction_service.keep_as_authored(
                name, host, username, ssh_key, provider, group,
            )

        # Try update first (if name already exists), else add
        if not self.app.custom_server_service.update_server(name, server):
            try:
                self.app.custom_server_service.add_server(server)
            except ValueError as e:
                self.app.notify(str(e), severity="error", markup=False)
                return

        self._populate_table()
        self._refresh_app_instances()
        self._hide_form()
        self.app.notify(f"Saved server: {name}", severity="information")

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
