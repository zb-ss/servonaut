"""Team management screen for Servonaut."""
from __future__ import annotations

import logging
from typing import List, Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Select, Static

from servonaut.widgets.progress_indicator import ProgressIndicator

logger = logging.getLogger(__name__)


class TeamManagementScreen(Screen):
    """Screen for managing teams, members, and shared servers."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._teams: List[dict] = []
        self._current_team: Optional[dict] = None
        self._current_slug: str = ""

    def compose(self) -> ComposeResult:
        yield Header()
        yield ScrollableContainer(
            Static("[bold cyan]Team Management[/bold cyan]", id="team_header"),

            # Team list section
            Static("[bold]Your Teams[/bold]", classes="section_header"),
            DataTable(id="teams_table"),
            Horizontal(
                Button("View Team", id="btn_view_team", variant="primary"),
                Button("Create Team", id="btn_create_team", variant="default"),
                classes="add_row",
            ),

            # Team details section (hidden by default)
            Container(
                Static("", id="team_detail_header"),

                # Members
                Static("[bold]Members[/bold]", classes="section_header"),
                DataTable(id="members_table"),
                Horizontal(
                    Button("Remove Member", id="btn_remove_member", variant="error"),
                    Button("Change Role", id="btn_change_role", variant="default"),
                    classes="add_row",
                ),

                # Invite form
                Static("[bold]Invite Member[/bold]", classes="section_header"),
                Horizontal(
                    Label("Email:"),
                    Input(placeholder="user@example.com", id="input_invite_email"),
                    classes="setting_row",
                ),
                Horizontal(
                    Label("Role:"),
                    Select(
                        options=[
                            ("Admin", "admin"),
                            ("Member", "member"),
                            ("Viewer", "viewer"),
                        ],
                        value="member",
                        id="select_invite_role",
                    ),
                    classes="setting_row",
                ),
                Button("Send Invite", id="btn_send_invite", variant="primary"),

                # Shared servers
                Static("[bold]Shared Servers[/bold]", classes="section_header"),
                DataTable(id="shared_servers_table"),

                id="team_detail_container",
            ),

            # Create team form (hidden by default)
            Container(
                Static("[bold]Create New Team[/bold]", classes="section_header"),
                Horizontal(
                    Label("Team Name:"),
                    Input(placeholder="my-team", id="input_team_name"),
                    classes="setting_row",
                ),
                Horizontal(
                    Button("Create", id="btn_do_create_team", variant="primary"),
                    Button("Cancel", id="btn_cancel_create", variant="default"),
                    classes="add_row",
                ),
                id="create_team_container",
            ),

            ProgressIndicator(),
            Static("", id="team_status"),
            Button("Back", id="btn_back", variant="error"),
            id="team_container",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#team_detail_container").display = False
        self.query_one("#create_team_container").display = False
        self._setup_tables()
        self.run_worker(self._load_teams(), name="load_teams", exclusive=True)

    def _setup_tables(self) -> None:
        teams_table = self.query_one("#teams_table", DataTable)
        teams_table.cursor_type = "row"
        teams_table.add_columns("Name", "Slug", "Role", "Members")

        members_table = self.query_one("#members_table", DataTable)
        members_table.cursor_type = "row"
        members_table.add_columns("Email", "Role", "Joined")

        servers_table = self.query_one("#shared_servers_table", DataTable)
        servers_table.cursor_type = "row"
        servers_table.add_columns("Name", "Host", "Provider", "Added By")

    async def _load_teams(self) -> None:
        progress = self.query_one(ProgressIndicator)
        progress.start("Loading teams...")
        try:
            self._teams = await self.app.team_service.list_teams()
            self._populate_teams_table()
        except Exception as e:
            self.query_one("#team_status", Static).update(f"[red]Error: {e}[/red]")
        finally:
            progress.stop()

    def _populate_teams_table(self) -> None:
        table = self.query_one("#teams_table", DataTable)
        table.clear()
        for team in self._teams:
            table.add_row(
                team.get("name", ""),
                team.get("slug", ""),
                team.get("role", ""),
                str(team.get("member_count", 0)),
            )

    async def _load_team_details(self, slug: str) -> None:
        progress = self.query_one(ProgressIndicator)
        progress.start("Loading team details...")
        try:
            self._current_team = await self.app.team_service.get_team(slug)
            self._current_slug = slug

            # Update header
            self.query_one("#team_detail_header", Static).update(
                f"[bold cyan]{self._current_team.get('name', slug)}[/bold cyan]"
            )

            # Populate members
            members_table = self.query_one("#members_table", DataTable)
            members_table.clear()
            for member in self._current_team.get("members", []):
                members_table.add_row(
                    member.get("email", ""),
                    member.get("role", ""),
                    member.get("joined_at", "")[:10] if member.get("joined_at") else "",
                )

            # Populate shared servers
            servers = await self.app.team_service.list_shared_servers(slug)
            servers_table = self.query_one("#shared_servers_table", DataTable)
            servers_table.clear()
            for server in servers:
                servers_table.add_row(
                    server.get("name", ""),
                    server.get("host", ""),
                    server.get("provider", ""),
                    server.get("added_by", ""),
                )

            self.query_one("#team_detail_container").display = True
        except Exception as e:
            self.query_one("#team_status", Static).update(f"[red]Error: {e}[/red]")
        finally:
            progress.stop()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn_view_team":
            self._view_selected_team()
        elif bid == "btn_create_team":
            self.query_one("#create_team_container").display = True
            self.query_one("#input_team_name", Input).focus()
        elif bid == "btn_do_create_team":
            self.run_worker(self._create_team(), name="create_team", exclusive=True)
        elif bid == "btn_cancel_create":
            self.query_one("#create_team_container").display = False
        elif bid == "btn_send_invite":
            self.run_worker(self._send_invite(), name="invite", exclusive=True)
        elif bid == "btn_remove_member":
            self.run_worker(self._remove_selected_member(), name="remove_member", exclusive=True)
        elif bid == "btn_back":
            self.action_back()

    def _view_selected_team(self) -> None:
        table = self.query_one("#teams_table", DataTable)
        if table.row_count == 0:
            self.notify("No teams available", severity="warning")
            return
        try:
            row = table.get_row_at(table.cursor_row)
            slug = str(row[1])
            self.run_worker(self._load_team_details(slug), name="load_detail", exclusive=True)
        except Exception:
            self.notify("Select a team first", severity="warning")

    async def _create_team(self) -> None:
        name = self.query_one("#input_team_name", Input).value.strip()
        if not name:
            self.notify("Team name is required", severity="error")
            return
        try:
            await self.app.team_service.create_team(name)
            self.notify(f"Team '{name}' created", severity="information")
            self.query_one("#create_team_container").display = False
            await self._load_teams()
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    async def _send_invite(self) -> None:
        if not self._current_slug:
            return
        email = self.query_one("#input_invite_email", Input).value.strip()
        role_value = self.query_one("#select_invite_role", Select).value
        role = str(role_value) if role_value is not Select.NULL else "member"

        if not email:
            self.notify("Email is required", severity="error")
            return
        try:
            await self.app.team_service.invite_member(self._current_slug, email, role)
            self.notify(f"Invited {email} as {role}", severity="information")
            self.query_one("#input_invite_email", Input).value = ""
            await self._load_team_details(self._current_slug)
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    async def _remove_selected_member(self) -> None:
        if not self._current_slug or not self._current_team:
            return
        table = self.query_one("#members_table", DataTable)
        if table.row_count == 0:
            return
        try:
            row = table.get_row_at(table.cursor_row)
            email = str(row[0])
            members = self._current_team.get("members", [])
            member = next((m for m in members if m.get("email") == email), None)
            if member:
                await self.app.team_service.remove_member(
                    self._current_slug, member.get("id", "")
                )
                self.notify(f"Removed {email}", severity="information")
                await self._load_team_details(self._current_slug)
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_back(self) -> None:
        self.app.pop_screen()
