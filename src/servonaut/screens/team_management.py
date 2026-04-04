"""Team Management screen for Servonaut."""

from __future__ import annotations

import logging
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)


class TeamManagementScreen(Screen):
    """Team management: list teams, manage members, share servers."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def __init__(self) -> None:
        super().__init__()
        self._current_team_slug: Optional[str] = None
        self._current_team_name: Optional[str] = None
        # Cache member list for remove operations (row index → user_id)
        self._members: list[dict] = []

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static("[bold cyan]Team Management[/bold cyan]"),

                # No-auth notice (shown when not authenticated)
                Static(
                    "Login required to manage teams. Go to Settings > Account.",
                    id="no_auth_notice",
                ),

                # --- Team list section ---
                Static("[bold]Your Teams[/bold]", id="section_teams", classes="section_header"),
                DataTable(id="teams_table"),
                Horizontal(
                    Button("Create Team", variant="primary", id="btn_create_team"),
                    Button("View Team", variant="default", id="btn_view_team"),
                    classes="add_row",
                    id="team_actions_row",
                ),

                # --- Team detail section (hidden until a team is selected) ---
                Static("", id="team_header"),

                Static("[bold]Members[/bold]", id="section_members", classes="section_header"),
                DataTable(id="members_table"),
                Horizontal(
                    Button("Invite Member", variant="primary", id="btn_invite"),
                    Button("Remove Member", variant="error", id="btn_remove"),
                    classes="add_row",
                    id="member_actions_row",
                ),

                Static("[bold]Shared Servers[/bold]", id="section_servers", classes="section_header"),
                DataTable(id="servers_table"),
                Horizontal(
                    Button("Share Server", variant="primary", id="btn_share"),
                    classes="add_row",
                    id="server_actions_row",
                ),

                # --- Create team form (hidden) ---
                Container(
                    Static("[bold]Create Team[/bold]", classes="section_header"),
                    Input(placeholder="Team Name", id="input_team_name"),
                    Button("Save Team", variant="primary", id="btn_save_team"),
                    id="create_team_form",
                ),

                # --- Invite member form (hidden) ---
                Container(
                    Static("[bold]Invite Member[/bold]", classes="section_header"),
                    Input(placeholder="Email", id="input_invite_email"),
                    Input(placeholder="member, admin", id="input_invite_role"),
                    Button("Send Invite", variant="primary", id="btn_send_invite"),
                    id="invite_form",
                ),

                Button("Back", variant="default", id="btn_back"),

                id="team_management_container",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Mount
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._setup_tables()
        self._hide_detail_section()
        self._hide_create_form()
        self._hide_invite_form()

        auth_svc = getattr(self.app, "auth_service", None)
        if auth_svc is None or not auth_svc.is_authenticated:
            self._show_no_auth_state()
            return

        self._hide_no_auth_notice()
        self.run_worker(self._load_teams(), exclusive=True, name="load_teams")

    # ------------------------------------------------------------------
    # Table setup
    # ------------------------------------------------------------------

    def _setup_tables(self) -> None:
        teams_tbl = self.query_one("#teams_table", DataTable)
        teams_tbl.cursor_type = "row"
        teams_tbl.add_columns("Name", "Role", "Members")

        members_tbl = self.query_one("#members_table", DataTable)
        members_tbl.cursor_type = "row"
        members_tbl.add_columns("Email", "Role", "Status")

        servers_tbl = self.query_one("#servers_table", DataTable)
        servers_tbl.cursor_type = "row"
        servers_tbl.add_columns("Name", "Host", "Provider")

    # ------------------------------------------------------------------
    # Visibility helpers
    # ------------------------------------------------------------------

    def _show_no_auth_state(self) -> None:
        self.query_one("#no_auth_notice").display = True
        self.query_one("#section_teams").display = False
        self.query_one("#teams_table").display = False
        self.query_one("#team_actions_row").display = False

    def _hide_no_auth_notice(self) -> None:
        self.query_one("#no_auth_notice").display = False

    def _hide_detail_section(self) -> None:
        for widget_id in (
            "team_header",
            "section_members",
            "members_table",
            "member_actions_row",
            "section_servers",
            "servers_table",
            "server_actions_row",
        ):
            self.query_one(f"#{widget_id}").display = False

    def _show_detail_section(self) -> None:
        for widget_id in (
            "team_header",
            "section_members",
            "members_table",
            "member_actions_row",
            "section_servers",
            "servers_table",
            "server_actions_row",
        ):
            self.query_one(f"#{widget_id}").display = True

    def _hide_create_form(self) -> None:
        self.query_one("#create_team_form").display = False

    def _show_create_form(self) -> None:
        self.query_one("#create_team_form").display = True
        self.query_one("#input_team_name", Input).value = ""
        self.query_one("#input_team_name", Input).focus()

    def _hide_invite_form(self) -> None:
        self.query_one("#invite_form").display = False

    def _show_invite_form(self) -> None:
        self.query_one("#invite_form").display = True
        self.query_one("#input_invite_email", Input).value = ""
        self.query_one("#input_invite_role", Input).value = ""
        self.query_one("#input_invite_email", Input).focus()

    # ------------------------------------------------------------------
    # Async workers
    # ------------------------------------------------------------------

    async def _load_teams(self) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            self.notify("Team service not available.", severity="warning")
            return
        try:
            teams = await team_svc.list_teams()
            self._populate_teams_table(teams)
        except Exception as exc:
            logger.error("Failed to load teams: %s", exc)
            self.notify(f"Failed to load teams: {exc}", severity="error")

    async def _load_team_detail(self, slug: str) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        try:
            team = await team_svc.get_team(slug)
            members = team.get("members", [])
            self._members = members
            self._populate_members_table(members)

            servers = await team_svc.list_shared_servers(slug)
            self._populate_servers_table(servers)

            self._show_detail_section()
            team_name = team.get("name", slug)
            self._current_team_name = team_name
            self.query_one("#team_header", Static).update(f"[bold]Team: {team_name}[/bold]")
        except Exception as exc:
            logger.error("Failed to load team detail: %s", exc)
            self.notify(f"Failed to load team: {exc}", severity="error")

    async def _do_create_team(self, name: str) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        try:
            await team_svc.create_team(name)
            self._hide_create_form()
            self.notify(f"Team '{name}' created.", severity="information")
            await self._load_teams()
        except Exception as exc:
            logger.error("Failed to create team: %s", exc)
            self.notify(f"Failed to create team: {exc}", severity="error")

    async def _do_invite_member(self, slug: str, email: str, role: str) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        try:
            await team_svc.invite_member(slug, email, role)
            self._hide_invite_form()
            self.notify(f"Invite sent to {email}.", severity="information")
            await self._load_team_detail(slug)
        except Exception as exc:
            logger.error("Failed to invite member: %s", exc)
            self.notify(f"Failed to invite member: {exc}", severity="error")

    async def _do_remove_member(self, slug: str, user_id: str, email: str) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        try:
            await team_svc.remove_member(slug, user_id)
            self.notify(f"Removed {email}.", severity="information")
            await self._load_team_detail(slug)
        except Exception as exc:
            logger.error("Failed to remove member: %s", exc)
            self.notify(f"Failed to remove member: {exc}", severity="error")

    async def _do_push_server(self, slug: str, server_data: dict) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        try:
            await team_svc.push_server(slug, server_data)
            self.notify(
                f"Server '{server_data.get('name', '')}' shared with team.",
                severity="information",
            )
            await self._load_team_detail(slug)
        except Exception as exc:
            logger.error("Failed to share server: %s", exc)
            self.notify(f"Failed to share server: {exc}", severity="error")

    # ------------------------------------------------------------------
    # Table population
    # ------------------------------------------------------------------

    def _populate_teams_table(self, teams: list[dict]) -> None:
        table = self.query_one("#teams_table", DataTable)
        table.clear()
        for team in teams:
            table.add_row(
                team.get("name", ""),
                team.get("role", ""),
                str(team.get("member_count", "")),
                key=team.get("slug", ""),
            )

    def _populate_members_table(self, members: list[dict]) -> None:
        table = self.query_one("#members_table", DataTable)
        table.clear()
        for member in members:
            table.add_row(
                member.get("email", ""),
                member.get("role", ""),
                member.get("status", ""),
            )

    def _populate_servers_table(self, servers: list[dict]) -> None:
        table = self.query_one("#servers_table", DataTable)
        table.clear()
        for server in servers:
            table.add_row(
                server.get("name", ""),
                server.get("host", ""),
                server.get("provider", ""),
            )

    # ------------------------------------------------------------------
    # Button handler
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id

        if button_id == "btn_create_team":
            self._show_create_form()

        elif button_id == "btn_view_team":
            self._action_view_team()

        elif button_id == "btn_save_team":
            self._submit_create_team()

        elif button_id == "btn_invite":
            if self._current_team_slug:
                self._show_invite_form()
            else:
                self.notify("Select a team first.", severity="warning")

        elif button_id == "btn_send_invite":
            self._submit_invite_member()

        elif button_id == "btn_remove":
            self._action_remove_member()

        elif button_id == "btn_share":
            self._action_share_server()

        elif button_id == "btn_back":
            self.action_back()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _action_view_team(self) -> None:
        table = self.query_one("#teams_table", DataTable)
        row = table.cursor_row
        # Retrieve slug from row key
        try:
            row_key = table.get_row_at(row)
        except Exception:
            self.notify("No team selected.", severity="warning")
            return

        # Use DataTable coordinate to get the slug key
        cell_key = table.coordinate_to_cell_key(table.cursor_coordinate)
        slug = cell_key.row_key.value if cell_key and cell_key.row_key else None
        if not slug:
            self.notify("No team selected.", severity="warning")
            return

        self._current_team_slug = slug
        self.run_worker(
            self._load_team_detail(slug),
            exclusive=True,
            name="load_team_detail",
        )

    def _submit_create_team(self) -> None:
        name = self.query_one("#input_team_name", Input).value.strip()
        if not name:
            self.notify("Team name is required.", severity="error")
            self.query_one("#input_team_name", Input).focus()
            return
        self.run_worker(self._do_create_team(name), exclusive=True, name="create_team")

    def _submit_invite_member(self) -> None:
        if not self._current_team_slug:
            self.notify("No team selected.", severity="warning")
            return
        email = self.query_one("#input_invite_email", Input).value.strip()
        role = self.query_one("#input_invite_role", Input).value.strip() or "member"
        if not email:
            self.notify("Email is required.", severity="error")
            self.query_one("#input_invite_email", Input).focus()
            return
        self.run_worker(
            self._do_invite_member(self._current_team_slug, email, role),
            exclusive=True,
            name="invite_member",
        )

    def _action_remove_member(self) -> None:
        if not self._current_team_slug:
            self.notify("Select a team first.", severity="warning")
            return

        table = self.query_one("#members_table", DataTable)
        row = table.cursor_row
        if row < 0 or row >= len(self._members):
            self.notify("No member selected.", severity="warning")
            return

        member = self._members[row]
        email = member.get("email", "unknown")
        user_id = member.get("id", "")

        slug = self._current_team_slug

        async def _confirm_and_remove() -> None:
            confirmed = await self.app.push_screen_wait(
                ConfirmActionScreen(
                    title="Remove Member",
                    description=f"Remove [bold]{email}[/bold] from the team?",
                    consequences=["Member will lose access to all shared servers"],
                    confirm_text=email,
                    action_label="Remove",
                    severity="warning",
                )
            )
            if confirmed:
                await self._do_remove_member(slug, user_id, email)

        self.run_worker(_confirm_and_remove(), exclusive=True, name="remove_member")

    def _action_share_server(self) -> None:
        if not self._current_team_slug:
            self.notify("Select a team first.", severity="warning")
            return

        instances = getattr(self.app, "instances", [])
        if not instances:
            self.notify("No servers available to share.", severity="warning")
            return

        # Share the first instance as a simple default; a full picker would
        # require an additional modal which is out of scope for this screen.
        instance = instances[0]
        server_data = {
            "name": instance.get("name", ""),
            "host": instance.get("public_ip") or instance.get("private_ip", ""),
            "provider": instance.get("provider", "aws"),
            "username": instance.get("username", "ec2-user"),
            "port": instance.get("port", 22),
        }
        self.run_worker(
            self._do_push_server(self._current_team_slug, server_data),
            exclusive=True,
            name="push_server",
        )

    # ------------------------------------------------------------------
    # Binding actions
    # ------------------------------------------------------------------

    def action_back(self) -> None:
        self.app.pop_screen()
