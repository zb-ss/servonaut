"""Custom servers management screen for Servonaut v2.0."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer

from servonaut.widgets.sidebar import Sidebar
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Static, TextArea

from servonaut.config.schema import CustomServer
from servonaut.screens._binding_guard import check_action_passthrough


class CustomServersScreen(Screen):
    """CRUD screen for managing non-AWS custom servers."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("n", "add_server", "Add", show=True),
        Binding("d", "remove_server", "Remove", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def compose(self) -> ComposeResult:
        """Compose the custom servers UI."""
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static("[bold cyan]Custom Servers[/bold cyan]", id="custom_servers_header"),
            Static(
                "[dim]Manage non-AWS servers (DigitalOcean, Hetzner, bare-metal, etc.)[/dim]",
                classes="note",
            ),

            # Server table
            DataTable(id="custom_servers_table"),

            # Action buttons
            Horizontal(
                Button("Add Server", id="btn_add_server", variant="primary"),
                Button("Remove Selected", id="btn_remove_server", variant="error"),
                Button("Back", id="btn_back", variant="default"),
                classes="add_row",
            ),

            # Add/Edit form (hidden by default). The Save/Cancel row is
            # NOT inside this Container — it's a sibling below, docked
            # to the screen bottom so it stays visible no matter how
            # far the user has scrolled through the form fields. Pre-
            # restructure, the action row sat at the end of the form
            # and was clipped on small terminals (#1387).
            Container(
                Static("[bold]Server Details[/bold]", classes="section_header"),
                Label("Name:"),
                Input(placeholder="my-vps", id="input_name"),
                Label("Host (IP or hostname):"),
                Input(placeholder="192.168.1.1", id="input_host"),
                Label("Username:"),
                Input(placeholder="root", id="input_username"),
                Label("SSH Key Path:"),
                Input(placeholder="~/.ssh/id_rsa", id="input_ssh_key"),
                Label("SSH Port:"),
                Input(placeholder="22", id="input_port"),
                Label("Provider:"),
                Input(placeholder="DigitalOcean", id="input_provider"),
                Label("Group:"),
                Input(placeholder="web-servers", id="input_group"),
                Label("Extra SSH options (one per line, KEY=VALUE):"),
                TextArea(
                    "",
                    id="input_extra_ssh_options",
                    classes="extra_ssh_options",
                ),
                Static(
                    "[dim]Used verbatim as ssh -o. Example: "
                    "HostKeyAlgorithms=+ssh-rsa for legacy hosts.[/dim]",
                    classes="note",
                ),
                id="add_form",
            ),

            # Bottom-docked action row, visible only while #add_form is.
            Horizontal(
                Button("Save", id="btn_save_server", variant="primary"),
                Button("Cancel", id="btn_cancel_form", variant="default"),
                id="add_form_actions",
            ),

            id="custom_servers_container",
        )
        yield Footer()

    def on_mount(self) -> None:
        """Set up table and hide form on mount."""
        self._setup_table()
        self._populate_table()
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
                "the real values.",
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
                self.app.notify(str(e), severity="error")
                return

        self._populate_table()
        self._refresh_app_instances()
        self._hide_form()
        self.app.notify(f"Saved server: {name}", severity="information")

    def _refresh_app_instances(self) -> None:
        """Rebuild app.instances to include updated custom servers.

        Demo mode: the fresh custom rows are raw, so they go into the
        pre-redaction snapshot first and are then redacted in place like the
        rest of the list — otherwise a save or remove would put real names
        back on the fleet table.
        """
        import copy
        other_instances = [i for i in self.app.instances if not i.get('is_custom')]
        custom = self.app.custom_server_service.list_as_instances()
        pristine = getattr(self.app, "_instances_pristine", None)
        if pristine is not None:
            self.app._instances_pristine = [
                i for i in pristine if not i.get('is_custom')
            ] + copy.deepcopy(custom)
        if self.app.demo_mode and self.app.redaction_service:
            self.app.redaction_service.redact_instances(custom)
        self.app.instances = other_instances + custom

    def action_back(self) -> None:
        """Navigate back to main menu."""
        self.app.pop_screen()
