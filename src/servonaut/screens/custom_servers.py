"""Custom servers management screen for Servonaut v2.0."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Static

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

            # Add/Edit form (hidden by default)
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
                Horizontal(
                    Button("Save", id="btn_save_server", variant="primary"),
                    Button("Cancel", id="btn_cancel_form", variant="default"),
                    classes="add_row",
                ),
                id="add_form",
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
        """Populate DataTable with current custom servers."""
        table = self.query_one("#custom_servers_table", DataTable)
        table.clear()
        for server in self.app.custom_server_service.list_servers():
            table.add_row(
                server.name,
                server.host,
                str(server.port),
                server.username,
                server.ssh_key or "-",
                server.provider or "-",
                server.group or "-",
            )

    def _hide_form(self) -> None:
        """Hide the add/edit form."""
        self.query_one("#add_form").display = False

    def _show_form(self, server: CustomServer = None) -> None:
        """Show the add/edit form, optionally pre-filled."""
        form = self.query_one("#add_form")
        form.display = True

        if server:
            self.query_one("#input_name", Input).value = server.name
            self.query_one("#input_host", Input).value = server.host
            self.query_one("#input_username", Input).value = server.username
            self.query_one("#input_ssh_key", Input).value = server.ssh_key
            self.query_one("#input_port", Input).value = str(server.port)
            self.query_one("#input_provider", Input).value = server.provider
            self.query_one("#input_group", Input).value = server.group
        else:
            self.query_one("#input_name", Input).value = ""
            self.query_one("#input_host", Input).value = ""
            self.query_one("#input_username", Input).value = "root"
            self.query_one("#input_ssh_key", Input).value = ""
            self.query_one("#input_port", Input).value = "22"
            self.query_one("#input_provider", Input).value = ""
            self.query_one("#input_group", Input).value = ""

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
        if self.app.custom_server_service.remove_server(name):
            self._populate_table()
            self._refresh_app_instances()
            self.app.notify(f"Removed server: {name}", severity="information")
        else:
            self.app.notify(f"Server '{name}' not found", severity="error")

    def _save_server(self) -> None:
        """Validate form and save the server."""
        name = self.query_one("#input_name", Input).value.strip()
        host = self.query_one("#input_host", Input).value.strip()
        username = self.query_one("#input_username", Input).value.strip() or "root"
        ssh_key = self.query_one("#input_ssh_key", Input).value.strip()
        port_str = self.query_one("#input_port", Input).value.strip() or "22"
        provider = self.query_one("#input_provider", Input).value.strip()
        group = self.query_one("#input_group", Input).value.strip()

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
        """Rebuild app.instances to include updated custom servers."""
        aws_instances = [i for i in self.app.instances if not i.get('is_custom')]
        self.app.instances = aws_instances + self.app.custom_server_service.list_as_instances()

    def action_back(self) -> None:
        """Navigate back to main menu."""
        self.app.pop_screen()
