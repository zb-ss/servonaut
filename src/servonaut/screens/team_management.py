"""Team Management screen for Servonaut."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from functools import partial
from typing import Any, List, Optional, Tuple

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Input, Select, SelectionList, Static
from textual.widgets.selection_list import Selection

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens._batch_status import failure_details
from servonaut.screens._demo_resolve import UNRESOLVED_MESSAGE, real_fleet_rows
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.bulk_action import BulkActionModal
from servonaut.screens.team_share_confirm import ShareServersConfirmModal, server_address
from servonaut.services.api_client import APIError
from servonaut.services.team_sharing import already_shared, share_candidates, share_payload
from servonaut.services.team_service import ALREADY_SHARED, FAILED, SHARED, ShareResult
from servonaut.services.vault.display import markup_literal, terminal_safe
from servonaut.services.team_rules_view import (
    TITLE as AGENT_RULES_TITLE,
    agent_rules_lines,
    agent_rules_view,
)
from servonaut.widgets.safe_header import SafeHeader
from servonaut.widgets.busy_indicator import BusyIndicator
from servonaut.widgets.sidebar import Sidebar

logger = logging.getLogger(__name__)

# Roles assignable via the API. Owner is set on team creation only and is
# rejected by the invite/update endpoints. See services/team_service.py and
# backend src/Entity/TeamMember.php.
_ROLE_OPTIONS: List[Tuple[str, str]] = [
    ("Viewer", "viewer"),
    ("Member", "member"),
    ("Admin", "admin"),
]

# Roles that grant MANAGE_MEMBERS on the team (can invite/remove/change role).
_MANAGE_MEMBERS_ROLES = frozenset({"owner", "admin"})
# Only the owner can promote/demote admins (MANAGE_ADMINS).
_MANAGE_ADMINS_ROLES = frozenset({"owner"})
# Shown only while a team is open.
_DETAIL_SECTIONS = (
    "team_header", "members_section", "configs_section", "servers_section",
    "agent_rules_section",
)


def _kept_key_paths_text(count: int) -> str:
    """How many pulled entries keep the user's own SSH key path (a push never carries one)."""
    return "1 entry keeps your own SSH key path" if count == 1 else f"{count} entries keep your own SSH key paths"


class TeamManagementScreen(Screen):
    """Team management: list teams, manage members, share servers."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    # Below 120 columns the five member buttons wrap onto a grid (see the
    # ``-narrow`` rules in the styles); on one row the last ones were cut off.
    HORIZONTAL_BREAKPOINTS = [(0, "-narrow"), (120, "-wide")]

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if self._server_busy:
            return False
        return check_action_passthrough(self, action)

    def __init__(self) -> None:
        super().__init__()
        self._current_team_slug: Optional[str] = None
        self._current_team_name: Optional[str] = None
        # Caller's role on the currently-viewed team (owner/admin/member/viewer).
        # Drives mutation-button visibility.
        self._current_team_role: Optional[str] = None
        # Cache slug -> caller_role from the list response. GET /teams/{slug}
        # doesn't echo the caller's role today, so the list is the source of truth.
        self._team_roles: dict[str, str] = {}
        # Cache member list (parallel to row index) for remove/resend/role/copy.
        self._members: list[dict] = []
        # Cache currently-shared servers — used by Share All to dedupe before POST.
        self._shared_servers: list[dict] = []
        # Cache team-shared config versions, latest first per backend ordering.
        self._team_configs: list[dict] = []
        # Holds the parsed remote payload between "Pull Latest" and Apply confirm.
        self._pending_pull_payload: Optional[dict] = None
        # Team-list rows by slug: a team's agent rules are fetched by its id.
        self._teams_by_slug: dict[str, dict] = {}
        # Custom-server names the open push form offers (ticked or not).
        self._push_server_names: list[str] = []
        self._server_busy = False
        self._loaded_team_slug: Optional[str] = None
        self._team_load_generation = 0
        self._has_team_detail = False
        self._team_seat_line = ""
        self._share_form_username = ("", "")

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield SafeHeader()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static("[bold $text-accent]Team Management[/bold $text-accent]", id="team_mgmt_header"),

                # No-auth notice (shown when not authenticated)
                Static(
                    "Login required to manage teams. Use the Login / Account button in the sidebar.",
                    id="no_auth_notice",
                ),

                # --- Teams section (curved card) ---
                Container(
                    Static("[bold]Your Teams[/bold]", id="section_teams", classes="section_header"),
                    DataTable(id="teams_table"),
                    Horizontal(
                        Button("Create Team", variant="primary", id="btn_create_team"),
                        Button("View Team", variant="default", id="btn_view_team"),
                        classes="add_row",
                        id="team_actions_row",
                    ),
                    Container(
                        Static("[bold]Create Team[/bold]", classes="section_header"),
                        Input(placeholder="Team Name", id="input_team_name"),
                        Horizontal(
                            Button("Save Team", variant="primary", id="btn_save_team"),
                            Button("Cancel", variant="default", id="btn_cancel_create_team"),
                            classes="form_actions_row",
                        ),
                        id="create_team_form",
                    ),
                    id="teams_section",
                    classes="settings_section",
                ),

                # --- Active team banner (shown after View Team) ---
                Static("", id="team_header"),

                # --- Members section (curved card) ---
                Container(
                    Static("[bold]Members[/bold]", id="section_members", classes="section_header"),
                    DataTable(id="members_table"),
                    Horizontal(
                        Button("Invite Member", variant="primary", id="btn_invite"),
                        Button("Change Role", variant="default", id="btn_change_role"),
                        Button("Resend Invite", variant="default", id="btn_resend"),
                        Button("Copy Accept URL", variant="default", id="btn_copy_url"),
                        Button("Remove Member", variant="error", id="btn_remove"),
                        classes="add_row",
                        id="member_actions_row",
                    ),
                    Container(
                        Static("[bold]Invite Member[/bold]", classes="section_header"),
                        Input(placeholder="Email", id="input_invite_email"),
                        Select(
                            options=_ROLE_OPTIONS,
                            value="member",
                            allow_blank=False,
                            id="select_invite_role",
                        ),
                        Horizontal(
                            Button("Send Invite", variant="primary", id="btn_send_invite"),
                            Button("Cancel", variant="default", id="btn_cancel_invite"),
                            classes="form_actions_row",
                        ),
                        id="invite_form",
                    ),
                    Container(
                        Static("[bold]Change Role[/bold]", id="change_role_header", classes="section_header"),
                        Select(
                            options=_ROLE_OPTIONS,
                            value="member",
                            allow_blank=False,
                            id="select_change_role",
                        ),
                        Horizontal(
                            Button("Save Role", variant="primary", id="btn_save_role"),
                            Button("Cancel", variant="default", id="btn_cancel_change_role"),
                            classes="form_actions_row",
                        ),
                        id="change_role_form",
                    ),
                    id="members_section",
                    classes="settings_section",
                ),

                # --- Shared Configs section (curved card) ---
                Container(
                    Static("[bold]Shared Configs[/bold]", id="section_configs", classes="section_header"),
                    Static(
                        "[dim]Push a sanitised snapshot of your local config "
                        "(connection profiles, scan rules, custom servers) so "
                        "teammates can pull it as a baseline.[/dim]",
                        id="configs_hint",
                    ),
                    DataTable(id="configs_table"),
                    Horizontal(
                        Button("Push Current", variant="primary", id="btn_push_config"),
                        Button("Pull Latest", variant="default", id="btn_pull_config"),
                        classes="add_row",
                        id="config_actions_row",
                    ),
                    Container(
                        Static("[bold]Push Current Config[/bold]", classes="section_header"),
                        Static("", id="push_config_servers_label"),
                        SelectionList(id="push_config_servers"),
                        Horizontal(
                            Button("Select All", variant="default", id="btn_push_servers_all"),
                            Button("Select None", variant="default", id="btn_push_servers_none"),
                            classes="form_actions_row",
                            id="push_config_server_actions",
                        ),
                        Static("", id="push_config_profiles"),
                        Static("", id="push_config_preview"),
                        Input(
                            placeholder="Description (optional — e.g. 'Adds staging bastion')",
                            id="input_push_description",
                        ),
                        Horizontal(
                            Button("Push", variant="primary", id="btn_confirm_push_config"),
                            Button("Cancel", variant="default", id="btn_cancel_push_config"),
                            classes="form_actions_row",
                        ),
                        id="push_config_form",
                    ),
                    Container(
                        Static("[bold]Pull Latest Config[/bold]", classes="section_header"),
                        Static("", id="pull_config_preview"),
                        Static(
                            "[$text-warning]Pulling REPLACES your local connection profiles, "
                            "connection rules, scan rules, and custom servers with the "
                            "team's version. AI / cloud-provider / personal settings are "
                            "untouched.[/$text-warning]",
                            id="pull_config_warning",
                        ),
                        Horizontal(
                            Button("Apply", variant="warning", id="btn_confirm_pull_config"),
                            Button("Cancel", variant="default", id="btn_cancel_pull_config"),
                            classes="form_actions_row",
                        ),
                        id="pull_config_form",
                    ),
                    id="configs_section",
                    classes="settings_section",
                ),

                # --- Shared Servers section (curved card) ---
                Container(
                    Static("[bold]Shared Servers[/bold]", id="section_servers", classes="section_header"),
                    BusyIndicator(id="team_servers_busy"),
                    DataTable(id="servers_table"),
                    Horizontal(
                        Button("Connect", variant="success", id="btn_connect_shared"),
                        Button("Share Server", variant="primary", id="btn_share"),
                        Button("Share All", variant="default", id="btn_share_all"),
                        classes="add_row",
                        id="server_actions_row",
                    ),
                    Horizontal(
                        Button("Remove server", variant="error", id="btn_remove_server"),
                        Button("Remove multiple", variant="error", id="btn_remove_servers"),
                        classes="add_row",
                        id="server_remove_actions_row",
                    ),
                    Container(
                        Static("[bold]Share Server[/bold]", classes="section_header"),
                        Select(
                            options=[("(no servers available)", Select.BLANK)],
                            value=Select.BLANK,
                            allow_blank=True,
                            id="select_share_instance",
                        ),
                        Input(
                            placeholder="SSH username (optional — leave blank for cloud default)",
                            id="input_share_username",
                        ),
                        Input(
                            placeholder="SSH port (default 22)",
                            id="input_share_port",
                            type="integer",
                        ),
                        Horizontal(
                            Button("Share", variant="primary", id="btn_confirm_share"),
                            Button("Cancel", variant="default", id="btn_cancel_share"),
                            classes="form_actions_row",
                        ),
                        id="share_server_form",
                    ),
                    id="servers_section",
                    classes="settings_section",
                ),

                # --- Agent rules section (curved card, read-only) ---
                Container(
                    Static(
                        f"[bold]{AGENT_RULES_TITLE}[/bold]",
                        id="section_agent_rules", classes="section_header",
                    ),
                    Static("", id="agent_rules_body"),
                    id="agent_rules_section",
                    classes="settings_section",
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
        self._hide_change_role_form()

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
        servers_tbl.add_columns("Name", "Hostname", "Region")

        configs_tbl = self.query_one("#configs_table", DataTable)
        configs_tbl.cursor_type = "row"
        configs_tbl.add_columns("Version", "Description", "Pushed", "Pushed By")

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
        # Detail-only sections are wrapped in .settings_section cards;
        # collapse the whole card so the empty curved border doesn't render.
        for widget_id in _DETAIL_SECTIONS:
            self.query_one(f"#{widget_id}").display = False

    def _show_detail_section(self) -> None:
        for widget_id in _DETAIL_SECTIONS:
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
        role_select = self.query_one("#select_invite_role", Select)
        # Reset to "member" and gate the Admin option behind owner status.
        role_select.set_options(self._role_options_for_caller())
        role_select.value = "member"
        self.query_one("#input_invite_email", Input).focus()

    def _hide_change_role_form(self) -> None:
        self.query_one("#change_role_form").display = False

    def _hide_share_server_form(self) -> None:
        self.query_one("#share_server_form").display = False

    def _show_share_server_form(self, instances: list[dict]) -> None:
        """Open the share-server form populated with the user's instances.

        Builds Select options from the merged AWS + custom server list. Each
        option's label is the instance's human name (id fallback) annotated
        with the hostname so the user can disambiguate similarly-named rows;
        the value is the instance id so we can look up the source dict on
        submit without depending on label collision behaviour.
        """
        form = self.query_one("#share_server_form")
        form.display = True
        # Clear any stale connection-detail input from a previous open so the
        # pre-fill from the next-selected instance always wins.
        self.query_one("#input_share_username", Input).value = ""
        self.query_one("#input_share_port", Input).value = ""
        select = self.query_one("#select_share_instance", Select)
        candidates, _, _ = share_candidates(instances, self._shared_servers)
        by_id = {str(row.get("id")): row for row in candidates}
        options = [(Text(self._share_option_label(by_id[key])), key)
                   for _label, key in self._build_share_options(candidates)]
        if not options:
            select.set_options([("(no servers available)", Select.BLANK)])
            select.value = Select.BLANK
            self.notify("No servers available to share.", severity="warning")
            return
        select.set_options(options)
        # Default to the first instance with a usable hostname.
        select.value = options[0][1]
        self._prefill_share_connection_inputs(options[0][1])
        select.focus()

    def _prefill_share_connection_inputs(self, instance_id: str) -> None:
        """Pre-populate the username / port inputs from the selected instance.

        Custom servers carry ``username`` and ``port`` directly on the instance
        dict (see ``CustomServerService.to_instance_dict``); AWS instances do
        not. Leaving inputs blank → backend receives null/22 default, which the
        consumer's CLI will then fall back on per the cloud-specific default.
        """
        instances = self._share_inventory()
        instance = next((i for i in instances if str(i.get("id")) == instance_id), None)
        if instance is None:
            return
        defaults = self._share_defaults(instance)
        username = defaults.get("username") or ""
        port = defaults.get("port")
        displayed = username
        if self.app.demo_mode and self.app.redaction_service and username:
            displayed = self.app.redaction_service.redact_username(username)
        self._share_form_username = (username, displayed)
        self.query_one("#input_share_username", Input).value = displayed
        self.query_one("#input_share_port", Input).value = str(port) if port and port != 22 else ""

    def _share_defaults(self, instance: dict) -> dict:
        """Share only a server's own login or an explicitly matched rule login."""
        result = dict(instance)
        connection = getattr(self.app, "connection_service", None)
        profile = connection.resolve_profile(instance) if connection is not None else None
        from servonaut.services.connection_service import rule_username

        own_username = instance.get("username") if instance.get("is_custom") is True else ""
        result["username"] = instance.get("login_user") or rule_username(instance, profile) or own_username or ""
        result["port"] = instance.get("port") or 22
        return result

    def _share_inventory(self) -> list[dict]:
        rows = real_fleet_rows(self.app)
        if rows is None:
            self.notify(UNRESOLVED_MESSAGE, severity="error", markup=False)
            return []
        return rows

    def _share_option_label(self, instance: dict) -> str:
        name = self._display_server_name(instance.get("name") or instance.get("id") or "?")
        host = self._display_server_address(server_address(instance))
        return f"{name} ({host})"

    def on_select_changed(self, event: Select.Changed) -> None:
        """React to share-form instance switches by re-prefilling connection inputs."""
        if event.select.id != "select_share_instance":
            return
        value = event.value
        if value == Select.BLANK or not isinstance(value, str):
            return
        self._prefill_share_connection_inputs(value)

    @staticmethod
    def _build_share_options(instances: list[dict]) -> List[Tuple[str, str]]:
        """Return (label, instance_id) pairs for instances with a routable IP.

        Instances with neither public nor private IP are dropped — the backend
        requires ``hostname`` and we don't want a Select entry that's guaranteed
        to fail on submit.
        """
        options: List[Tuple[str, str]] = []
        for instance in share_candidates(instances, [])[0]:
            instance_id = instance.get("id")
            if not instance_id:
                continue
            hostname = instance.get("public_ip") or instance.get("private_ip")
            if not hostname:
                continue
            name = instance.get("name") or instance_id
            label = f"{name} ({hostname})"
            options.append((label, str(instance_id)))
        return options

    def _show_change_role_form(self, member: dict) -> None:
        form = self.query_one("#change_role_form")
        form.display = True
        email = self._member_display_email(member)
        display_email = (
            self.app.redaction_service.scrub_stream(email)
            if self.app.demo_mode and self.app.redaction_service
            else email
        )
        self.query_one("#change_role_header", Static).update(
            Text(f"Change Role: {terminal_safe(display_email)}", style="bold")
        )
        role_select = self.query_one("#select_change_role", Select)
        role_select.set_options(self._role_options_for_caller())
        current_role = member.get("role", "member")
        # Owner rows must not be editable via this form (server 400s anyway).
        role_select.value = current_role if current_role in {"admin", "member", "viewer"} else "member"
        role_select.focus()

    # ------------------------------------------------------------------
    # Role / permission helpers
    # ------------------------------------------------------------------

    def _can_manage_members(self) -> bool:
        """Owner or admin on the currently-viewed team."""
        return (self._current_team_role or "").lower() in _MANAGE_MEMBERS_ROLES

    def _can_manage_admins(self) -> bool:
        """Only owners can promote/demote admins."""
        return (self._current_team_role or "").lower() in _MANAGE_ADMINS_ROLES

    def _role_options_for_caller(self) -> List[Tuple[str, str]]:
        """Available roles for the current caller — drop Admin for non-owners."""
        if self._can_manage_admins():
            return list(_ROLE_OPTIONS)
        return [(label, value) for label, value in _ROLE_OPTIONS if value != "admin"]

    def _refresh_member_buttons(self) -> None:
        """Show/hide mutation buttons based on caller's role on the team."""
        can_manage = self._can_manage_members()
        for btn_id in ("btn_invite", "btn_change_role", "btn_resend", "btn_copy_url", "btn_remove"):
            self.query_one(f"#{btn_id}").display = can_manage
        # Share Server / Share All require MANAGE_MEMBERS too.
        self.query_one("#btn_share").display = can_manage
        self.query_one("#btn_share_all").display = can_manage
        self.query_one("#btn_remove_server").display = can_manage
        self.query_one("#btn_remove_servers").display = can_manage
        # Push Current = admin-only on the backend (hasAdminAccess). Pull is
        # readable by any member, so it stays visible regardless.
        self.query_one("#btn_push_config").display = can_manage
        if not can_manage:
            # Hide any open forms that the caller can't action anyway.
            self._hide_invite_form()
            self._hide_change_role_form()
            self._hide_share_server_form()

    # ------------------------------------------------------------------
    # Member field helpers (handle backend GET shape variance)
    # ------------------------------------------------------------------

    @staticmethod
    def _member_display_email(member: dict) -> str:
        """Extract a human-readable label for a member row.

        Backend ``GET /teams/{slug}`` returns ``invitation_email`` on every row
        (pending and accepted), plus an optional ``user`` object with ``name``.
        Older shapes used ``email`` directly — we tolerate both.
        """
        return (
            member.get("invitation_email")
            or member.get("email")
            or (member.get("user") or {}).get("name")
            or (member.get("user") or {}).get("email")
            or "unknown"
        )

    @staticmethod
    def _format_seat_line(team: dict, members: list[dict]) -> str:
        """Render the "Seats: used / cap" indicator under the team name.

        Backend semantics (PR #66):
          - ``max_seats`` is derived live from the owner's Stripe Teams
            subscription seat_count, NOT the stale Team column.
          - ``used`` = accepted + pending (both reserve a seat).
          - When the owner has no active sub, ``max_seats`` is 0; we render a
            no-subscription notice so the user knows why every invite 402s.
        """
        used = len(members)
        cap = team.get("max_seats") or 0
        if cap <= 0:
            return f"Seats: {used} (no active Teams subscription)"
        return f"Seats: {used} / {cap}"

    @staticmethod
    def _format_status(member: dict) -> str:
        """Derive Status from ``is_accepted`` + ``invitation_expires_at``."""
        if member.get("is_accepted"):
            return "Active"
        expires = member.get("invitation_expires_at")
        if not expires:
            return "Invited"
        try:
            expires_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            remaining = expires_dt - datetime.now(timezone.utc)
            days = remaining.days
            if remaining.total_seconds() <= 0:
                return "Invited (expired)"
            if days >= 1:
                return f"Invited (expires in {days}d)"
            hours = max(int(remaining.total_seconds() // 3600), 1)
            return f"Invited (expires in {hours}h)"
        except (ValueError, AttributeError):
            return "Invited"

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
            self.notify(f"Failed to load teams: {exc}", severity="error", markup=False)

    async def _load_team_detail(self, slug: str) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None or self._current_team_slug not in (None, slug):
            return
        keep_view = self._current_team_slug == slug and self._has_team_detail
        positions = [(table, table.cursor_coordinate, table.scroll_offset)
                     for table in self.query(DataTable)] if keep_view else []
        if keep_view:
            self._team_load_generation += 1
            self._loaded_team_slug = None
            self._render_team_header("Refreshing team details…")
        else:
            self._invalidate_team_detail(slug)
        generation = self._team_load_generation
        try:
            team = await team_svc.get_team(slug)
            members = team.get("members", [])
            servers = await team_svc.list_shared_servers(slug)
            try:
                configs = await team_svc.list_team_configs(slug)
            except Exception:
                if keep_view:
                    raise
                logger.warning("Could not load shared configurations", exc_info=True)
                configs = []
            if generation != self._team_load_generation:
                return
            self._members, self._shared_servers, self._team_configs = members, servers, configs
            self._current_team_role = team.get("role") or self._team_roles.get(slug) or self._infer_caller_role(members)
            self._populate_members_table(members)
            self._populate_servers_table(servers)
            self._list_shared_servers(self._team_record(slug, team), servers)
            self._populate_configs_table(configs)
            self._hide_push_config_form()
            self._hide_pull_config_form()
            self._current_team_name = team.get("name", slug)
            self._team_seat_line = self._format_seat_line(team, members)
            self._has_team_detail = True
            self._loaded_team_slug = slug
            self._render_team_header()
            self._show_detail_section()
            self._restore_table_positions(positions)
            self._refresh_member_buttons()
            await self._show_agent_rules(slug, team, servers)
        except Exception as exc:
            if generation != self._team_load_generation:
                return
            self._loaded_team_slug = None
            if keep_view:
                self._render_team_header("Could not refresh. Showing the last view; refresh before making server changes.")
            else:
                self._invalidate_team_detail(slug)
            logger.error("Failed to load team detail", exc_info=True)
            self.notify(f"Failed to load team: {exc}", severity="error", markup=False)

    def _render_team_header(self, status: str = "") -> None:
        name = terminal_safe(self._current_team_name or self._current_team_slug or "")
        if self.app.demo_mode and self.app.redaction_service:
            name = self.app.redaction_service.redact_name(name)
        text = Text.assemble((f"Team: {name}", "bold"), f"\n{self._team_seat_line}")
        if status:
            text.append(f"\n{status}")
        self.query_one("#team_header", Static).update(text)

    def _restore_table_positions(self, positions: list) -> None:
        for table, cursor, offset in positions:
            if table.row_count:
                table.move_cursor(row=min(cursor.row, table.row_count - 1), column=cursor.column)
                self.call_after_refresh(table.scroll_to, x=offset.x, y=offset.y, animate=False, force=True)

    def _invalidate_team_detail(self, slug: str) -> int:
        self._team_load_generation += 1
        self._current_team_slug = slug
        self._has_team_detail = False
        self._loaded_team_slug = None
        self._current_team_role = None
        self._shared_servers = []
        self._members = []
        self._team_configs = []
        for selector in ("#servers_table", "#members_table", "#configs_table"):
            self.query_one(selector, DataTable).clear()
        self._hide_invite_form()
        self._hide_change_role_form()
        self._hide_share_server_form()
        self._hide_push_config_form()
        self._hide_pull_config_form()
        if not self._server_busy:
            self._hide_detail_section()
        self._refresh_member_buttons()
        return self._team_load_generation

    async def _show_agent_rules(self, slug: str, team: dict, servers: list[dict]) -> None:
        """Show what agents may do on the team's servers: what this device has, then fresh.

        Without the app's refresher (no team service) only the rules this
        device has are shown.
        """
        from servonaut.services.shared_servers import team_id_text
        from servonaut.services.team_policy import team_policy_store

        refresher = getattr(self.app, "team_policy", None)
        store = refresher.store if refresher is not None else team_policy_store()
        if self.app.demo_mode and self.app.redaction_service:
            # Server names are identifiers, as in the servers table.
            redact = self.app.redaction_service.redact_name
            servers = [dict(server, name=redact(str(server.get("name") or ""))) for server in servers]

        row = self._team_record(slug, team)
        # By id: another team may have used this slug before a rename.
        team_id = team_id_text(row) or None

        def show() -> None:
            self._render_agent_rules(agent_rules_view(
                slug, store.status(slug, team_id), servers, self._current_team_role,
            ))

        show()
        if refresher is None:
            return
        # Never raises: a failed fetch shows as the readonly fallback.
        await refresher.refresh([row])
        show()

    def _render_agent_rules(self, view: dict) -> None:
        """Show *view* (``team_rules_view.agent_rules_view``) in the agent rules card."""
        lines = agent_rules_lines(view)
        if self.app.demo_mode and self.app.redaction_service:
            lines = [self.app.redaction_service.scrub_stream(line) for line in lines]
        body = [markup_literal(line) for line in lines]
        if not view["in_force"]:
            # The fallback (and why) is the line that matters.
            body[0] = f"[$text-warning]{body[0]}[/$text-warning]"
        elif view["unusable_pattern"]:
            body = [
                f"[$text-warning]{line}[/$text-warning]" if raw.startswith("No command can run")
                else line
                for raw, line in zip(lines, body)
            ]
        body[-1] = f"[dim]{body[-1]}[/dim]"
        self.query_one("#agent_rules_body", Static).update("\n".join(body))

    def _team_record(self, slug: str, team: dict) -> dict:
        """Team *slug* as the team list describes it, filled in from its detail *team*.

        Its id and the caller's role must reach the shared rows: Auto-bind,
        Use Vault Key and the team agent rules read them there.
        """
        record = dict(self._teams_by_slug.get(slug) or {})
        record["slug"] = slug
        if not record.get("id") and team.get("id"):
            record["id"] = team.get("id")
        record["name"] = team.get("name") or record.get("name") or slug
        if self._current_team_role:
            record["role"] = self._current_team_role
        return record

    def _list_shared_servers(self, team: dict, servers: list[dict]) -> None:
        """Make *team*'s shared servers in the server list the ones listed here.

        *team* is the full team record (``_team_record``). The other teams'
        shared servers stay as they are.
        """
        from servonaut.screens._demo_resolve import replace_instances
        from servonaut.services.shared_servers import shared_row

        slug = team["slug"]
        # The real records (the list shows them redacted in demo mode).
        current = getattr(self.app, "_instances_pristine", None)
        if not isinstance(current, list):
            current = list(getattr(self.app, "instances", None) or [])
        others = [
            row for row in current
            if row.get("is_shared") is True and row.get("team_slug") != slug
        ]
        replace_instances(
            self.app, "shared",
            others + [shared_row(server, team) for server in servers if isinstance(server, dict)],
        )

    def _selected_shared_row(self) -> Optional[dict]:
        """The server-list row of the shared server selected in the table, after saying why not."""
        from servonaut.screens._demo_resolve import real_instance_id

        if not self._shared_servers:
            self.notify("This team shares no servers yet.", severity="warning")
            return None
        index = self.query_one("#servers_table", DataTable).cursor_row
        if not 0 <= index < len(self._shared_servers):
            self.notify("Select a shared server first.", severity="warning")
            return None
        server_id = str(self._shared_servers[index].get("id") or "")
        for row in getattr(self.app, "instances", None) or []:
            if (
                row.get("is_shared") is True
                and row.get("team_slug") == self._current_team_slug
                and real_instance_id(self.app, row.get("id")) == server_id
            ):
                return row
        self.notify(
            "That server is not in the server list yet: open the team again.",
            severity="warning",
        )
        return None

    def _action_connect_shared_server(self) -> None:
        """Open the selected shared server's actions and start an SSH session to it."""
        from servonaut.screens.server_actions import ServerActionsScreen

        row = self._selected_shared_row()
        if row is None:
            return
        screen = ServerActionsScreen(row)
        self.app.push_screen(screen)
        # The connect action runs once the screen has mounted.
        self.app.call_later(screen.action_action_3)

    def _infer_caller_role(self, members: list[dict]) -> Optional[str]:
        """Fallback when GET /teams/{slug} omits a top-level ``role`` field.

        Walks the member list looking for the authenticated user's row.
        """
        auth_svc = getattr(self.app, "auth_service", None)
        my_id = getattr(auth_svc, "user_id", None) if auth_svc else None
        my_email = getattr(auth_svc, "user_email", None) if auth_svc else None
        for member in members:
            user = member.get("user") or {}
            if my_id and str(user.get("id")) == str(my_id):
                return member.get("role")
            if my_email and member.get("invitation_email") == my_email:
                return member.get("role")
        return None

    async def _do_create_team(self, name: str) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        try:
            await team_svc.create_team(name)
            self._hide_create_form()
            self.notify(f"Team '{name}' created.", severity="information")
            await self._load_teams()
        except APIError as exc:
            # 403 from POST /api/v1/teams has two distinct messages from backend:
            # "Only Teams-plan subscribers can create a team workspace..." and
            # "You already own a team workspace...". Both are user-actionable —
            # surface the message verbatim rather than the generic stringified exc.
            logger.error("Failed to create team: %s", exc.message)
            self.notify(exc.message, severity="error", timeout=10, markup=False)
        except Exception as exc:
            logger.error("Failed to create team: %s", exc)
            self.notify(f"Failed to create team: {exc}", severity="error", markup=False)

    async def _do_invite_member(self, slug: str, email: str, role: str) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        try:
            response = await team_svc.invite_member(slug, email, role)
            self._hide_invite_form()
            self._notify_invite_outcome(email, response, action="Invite")
            await self._load_team_detail(slug)
        except APIError as exc:
            self._notify_member_write_error(exc, fallback="Failed to invite member")
        except Exception as exc:
            logger.error("Failed to invite member: %s", exc)
            self.notify(f"Failed to invite member: {exc}", severity="error", markup=False)

    async def _do_resend_invite(self, slug: str, member_id: str, email: str) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        try:
            response = await team_svc.resend_invite(slug, member_id)
            self._notify_invite_outcome(email, response, action="Resend")
            await self._load_team_detail(slug)
        except APIError as exc:
            self._notify_member_write_error(exc, fallback="Failed to resend invite")
        except Exception as exc:
            logger.error("Failed to resend invite: %s", exc)
            self.notify(f"Failed to resend invite: {exc}", severity="error", markup=False)

    def _notify_member_write_error(self, exc: APIError, *, fallback: str) -> None:
        """Render a context-aware notification for invite/resend API errors.

        Backend may now return:
          - 402 — team owner's Teams subscription has lapsed
          - 422 — seat cap reached
          - 4xx — any other validation failure (already a member, bad email, …)
        For 402 we steer to the billing page when the caller IS the owner, and
        to "ask the owner" when they're not. The server's `message` is always
        user-readable so we surface it verbatim with appended actionable hint.
        """
        logger.error("Member write failed (%s): %s", exc.status, exc.message)
        if exc.status == 402:
            if self._can_manage_admins():
                # Owner sees the direct billing CTA.
                hint = "Manage your subscription at https://servonaut.dev/account/billing."
            else:
                hint = "Ask the team owner to renew the Teams subscription."
            self.notify(f"{exc.message} {hint}", severity="warning", timeout=12, markup=False)
            return
        if exc.status == 422:
            self.notify(
                f"{exc.message} Remove an existing member, or upgrade the seat cap.",
                severity="warning",
                timeout=12,
                markup=False,
            )
            return
        # All other 4xx — show the server's message rather than the wrapped repr.
        self.notify(f"{fallback}: {exc.message}", severity="error", markup=False)

    async def _do_remove_member(self, slug: str, member_id: str, email: str) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        try:
            await team_svc.remove_member(slug, member_id)
            self.notify(f"Removed {email}.", severity="information")
            await self._load_team_detail(slug)
        except Exception as exc:
            logger.error("Failed to remove member: %s", exc)
            self.notify(f"Failed to remove member: {exc}", severity="error", markup=False)

    async def _do_update_role(self, slug: str, member_id: str, email: str, role: str) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        try:
            await team_svc.update_role(slug, member_id, role)
            self._hide_change_role_form()
            self.notify(f"{email} is now {role.capitalize()}.", severity="information")
            await self._load_team_detail(slug)
        except Exception as exc:
            logger.error("Failed to update role: %s", exc)
            self.notify(f"Failed to update role: {exc}", severity="error", markup=False)

    def _notify_invite_outcome(self, email: str, response: dict, *, action: str) -> None:
        """Render a context-aware notification for invite/resend responses.

        The backend returns ``email_sent: bool`` — when ``False`` the row was
        persisted with a valid token but mailer delivery failed. Steer the
        user toward "Copy Accept URL" rather than silently claiming success.
        """
        if isinstance(response, dict) and response.get("email_sent") is False:
            self.notify(
                f"{action} recorded for {email} — email delivery failed. "
                "Use 'Copy Accept URL' to share the link manually.",
                severity="warning",
                timeout=10,
            )
        else:
            verb = "sent" if action == "Invite" else "resent"
            self.notify(f"Invite {verb} to {email}.", severity="information")

    async def _do_push_server(self, slug: str, server_data: dict) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        try:
            await team_svc.push_server(slug, server_data)
            self._hide_share_server_form()
            self.notify(
                f"Server '{server_data.get('name', '')}' shared with team.",
                severity="information",
                markup=False,
            )
            await self._load_team_detail(slug)
        except APIError as exc:
            logger.error("Failed to share server (%s): %s", exc.status, exc.message)
            # Backend 409 example: "A server with this hostname is already shared."
            self.notify(f"Failed to share server: {exc.message}", severity="error", markup=False)
        except Exception as exc:
            logger.error("Failed to share server: %s", exc)
            self.notify(f"Failed to share server: {exc}", severity="error", markup=False)

    # ------------------------------------------------------------------
    # Table population
    # ------------------------------------------------------------------

    def _populate_teams_table(self, teams: list[dict]) -> None:
        table = self.query_one("#teams_table", DataTable)
        table.clear()

        def _s(x: str) -> str:
            # Team names are identifiers — use redact_name for deterministic substitution.
            if self.app.demo_mode and self.app.redaction_service:
                return self.app.redaction_service.redact_name(x)
            return x

        self._team_roles.clear()
        self._teams_by_slug.clear()
        owned_count = 0
        for team in teams:
            slug = team.get("slug", "")
            role = (team.get("role") or "").lower()
            if slug:
                self._team_roles[slug] = role
                self._teams_by_slug[slug] = dict(team)
            if role == "owner":
                owned_count += 1
            table.add_row(
                markup_literal(terminal_safe(_s(team.get("name", "")))),
                markup_literal(terminal_safe(role)),
                markup_literal(terminal_safe(team.get("member_count", ""))),
                key=slug,
            )
        # Backend caps team creation at one-team-per-Teams-subscription. Hide
        # the CTA when we know the user already owns one — server still 403s
        # if they bypass the UI.
        self.query_one("#btn_create_team").display = owned_count == 0

    def _populate_members_table(self, members: list[dict]) -> None:
        table = self.query_one("#members_table", DataTable)
        table.clear()

        def _s(x: str) -> str:
            if self.app.demo_mode and self.app.redaction_service:
                return self.app.redaction_service.scrub_stream(x)
            return x

        for member in members:
            table.add_row(
                markup_literal(terminal_safe(_s(self._member_display_email(member)))),
                markup_literal(terminal_safe(member.get("role", ""))),
                self._format_status(member),
            )

    def _populate_configs_table(self, configs: list[dict]) -> None:
        """Render the Shared Configs version list.

        Backend ordering is latest-first; we render as-received. Description
        truncated to 40 chars to keep the row readable in narrow terminals;
        the full text shows in the push/pull preview.
        """
        table = self.query_one("#configs_table", DataTable)
        table.clear()

        def _s(x: str) -> str:
            # Descriptions are user-typed free text — scrub in demo mode.
            if self.app.demo_mode and self.app.redaction_service:
                return self.app.redaction_service.scrub_stream(x)
            return x

        for cfg in configs:
            version = cfg.get("version", "?")
            description = terminal_safe(cfg.get("description") or "")[:40]
            pushed_by = terminal_safe(self._config_author(cfg))
            if self.app.demo_mode and self.app.redaction_service:
                pushed_by = self.app.redaction_service.redact_name(pushed_by)
            created = (cfg.get("created_at") or "")[:10]  # YYYY-MM-DD portion
            table.add_row(str(version), markup_literal(_s(description)), created, markup_literal(pushed_by), key=str(cfg.get("id", "")))

    def _config_author(self, config: dict) -> str:
        author = config.get("pushed_by")
        if isinstance(author, dict):
            return str(author.get("name") or author.get("display_name") or author.get("email") or "Unknown member")
        if config.get("pushed_by_name"):
            return str(config["pushed_by_name"])
        for member in self._members:
            user = member.get("user") or {}
            user_id = user.get("id", member.get("user_id"))
            if user_id is not None and str(user_id) == str(author):
                return str(user.get("name") or user.get("email") or self._member_display_email(member))
        if isinstance(author, str) and author and not author.isdecimal():
            return author
        return "Former member" if author is not None else "Unknown member"

    def _hide_push_config_form(self) -> None:
        self.query_one("#push_config_form").display = False

    def _hide_pull_config_form(self) -> None:
        self.query_one("#pull_config_form").display = False

    def _show_push_config_form(self) -> None:
        """Open the push form with every custom server listed and none ticked.

        Only the custom servers the user ticks are pushed. Connection
        profiles, connection rules and scan rules go out whole, so the
        profiles are listed by name and bastion host for review.
        """
        config_manager = getattr(self.app, "config_manager", None)
        config = config_manager.get() if config_manager is not None else None
        if config is None:
            self.notify("Local config not available.", severity="error")
            return
        servers = list(config.custom_servers)
        self._push_server_names = [server.name for server in servers]
        self._render_push_config_servers(servers, selected=set())
        self._render_push_config_preview(config)
        self.query_one("#input_push_description", Input).value = ""
        form = self.query_one("#push_config_form")
        form.display = True
        if servers:
            self.query_one("#push_config_servers", SelectionList).focus()
        else:
            self.query_one("#input_push_description", Input).focus()
        # The form opens at the foot of the page: bring all of it into view once
        # it is laid out, so the summary and Push are not below the fold.
        self.call_after_refresh(form.scroll_visible, top=True, animate=False)

    def _render_push_config_servers(self, servers: list, *, selected: set) -> None:
        """List the custom servers by name and host, ticking the ones named in *selected*."""
        demo = self.app.demo_mode and self.app.redaction_service

        def _name(x: str) -> str:
            return self.app.redaction_service.redact_name(x) if demo else x

        def _host(x: str) -> str:
            return self.app.redaction_service.scrub_stream(x) if demo else x

        names = [_name(server.name) for server in servers]
        # Names padded to the longest one, so the hosts line up in a column.
        width = max((len(name) for name in names), default=0)
        listing = self.query_one("#push_config_servers", SelectionList)
        listing.clear_options()
        listing.add_options([
            Selection(
                f"{markup_literal(name.ljust(width))}  [dim]{markup_literal(_host(server.host))}[/dim]",
                server.name,
                server.name in selected,
            )
            for name, server in zip(names, servers)
        ])
        if servers:
            listing.highlighted = 0  # so Space ticks the first row straight away
        listing.display = bool(servers)
        self.query_one("#push_config_server_actions").display = bool(servers)
        self.query_one("#push_config_servers_label", Static).update(
            "[bold]Custom servers[/bold] [dim]— only the ticked ones are shared[/dim]"
            if servers
            else "[dim]No custom servers in your config.[/dim]"
        )

    def _push_selected_servers(self) -> list[str]:
        """Names of the custom servers ticked in the push form."""
        return list(self.query_one("#push_config_servers", SelectionList).selected)

    def _render_push_config_preview(self, config) -> None:
        """Show what Push sends with the current ticks: profiles, counts, stripped paths."""
        from servonaut.services.team_config_subset import build_shareable_subset

        payload, summary = build_shareable_subset(
            config, custom_servers=self._push_selected_servers()
        )
        demo = self.app.demo_mode and self.app.redaction_service

        def _name(x: str) -> str:
            return self.app.redaction_service.redact_name(x) if demo else x

        def _host(x: str) -> str:
            return self.app.redaction_service.scrub_stream(x) if demo else x

        profiles = payload["connection_profiles"]
        if profiles:
            names = [_name(profile["name"]) for profile in profiles]
            width = max(len(name) for name in names)
            lines = ["[bold]Connection profiles[/bold] [dim]— all of them are shared[/dim]"]
            lines += [
                f"  • {markup_literal(name.ljust(width))}  "
                f"[dim]{markup_literal(_host(self._profile_route(profile)))}[/dim]"
                for name, profile in zip(names, profiles)
            ]
        else:
            lines = ["[dim]No connection profiles in your config.[/dim]"]
        self.query_one("#push_config_profiles", Static).update("\n".join(lines))

        preview = (
            f"Will share: [bold]{summary['custom_servers']}[/bold] of "
            f"{len(self._push_server_names)} custom servers, "
            f"[bold]{summary['connection_profiles']}[/bold] connection profiles, "
            f"[bold]{summary['connection_rules']}[/bold] connection rules, "
            f"[bold]{summary['scan_rules']}[/bold] scan rules."
        )
        if summary["stripped_paths"]:
            preview += (
                f"\n[$text-warning]{summary['stripped_paths']} local SSH key path(s) will be "
                "stripped — teammates must re-bind them locally.[/$text-warning]"
            )
        self.query_one("#push_config_preview", Static).update(preview)

    @staticmethod
    def _profile_route(profile: dict) -> str:
        """How a connection profile reaches its servers, as the push sends it."""
        bastion = profile.get("bastion_host") or ""
        if bastion:
            user = profile.get("bastion_user") or ""
            return f"bastion {user}@{bastion}" if user else f"bastion {bastion}"
        if profile.get("proxy_command"):
            return f"proxy command {profile['proxy_command']}"
        return "no bastion"

    def on_selection_list_selected_changed(self, event: SelectionList.SelectedChanged) -> None:
        """Keep the push preview in step with the ticked custom servers."""
        if event.selection_list.id != "push_config_servers":
            return
        config_manager = getattr(self.app, "config_manager", None)
        config = config_manager.get() if config_manager is not None else None
        if config is not None:
            self._render_push_config_preview(config)

    def _show_pull_config_form(self, remote_payload: dict) -> None:
        from servonaut.services.team_config_subset import diff_against_local
        config_manager = getattr(self.app, "config_manager", None)
        config = config_manager.get() if config_manager is not None else None
        if config is None:
            self.notify("Local config not available.", severity="error")
            return
        diff = diff_against_local(config, remote_payload)
        lines = ["Pull will replace these sections (current → after):"]
        for section in ("connection_profiles", "connection_rules", "scan_rules", "custom_servers"):
            d = diff[section]
            change_hint = "[$text-success]no change[/$text-success]" if d["local"] == d["after"] else f"[bold]{d['local']} → {d['after']}[/bold]"
            lines.append(f"  • {section.replace('_', ' ').title()}: {change_hint}")
        if diff["kept_key_paths"]:
            lines.append(f"  {_kept_key_paths_text(diff['kept_key_paths'])}: a team config never carries key paths.")
        self.query_one("#pull_config_preview", Static).update("\n".join(lines))
        self._pending_pull_payload = remote_payload
        form = self.query_one("#pull_config_form")
        form.display = True

    def _populate_servers_table(self, servers: list[dict]) -> None:
        table = self.query_one("#servers_table", DataTable)
        table.clear()

        def _name(x: str) -> str:
            # Server names are identifiers — use redact_name for deterministic substitution.
            if self.app.demo_mode and self.app.redaction_service:
                return self.app.redaction_service.redact_name(x)
            return x

        def _host(x: str) -> str:
            # Hostnames may be IPs or DNS names — scrub_stream handles both.
            if self.app.demo_mode and self.app.redaction_service:
                return self.app.redaction_service.scrub_stream(x)
            return x

        for server in servers:
            table.add_row(
                markup_literal(terminal_safe(_name(server.get("name", "")))),
                # Backend field is "hostname"; tolerate legacy "host" key for back-compat.
                markup_literal(terminal_safe(_host(server.get("hostname") or server.get("host", "")))),
                markup_literal(terminal_safe(server.get("region", "") or "")),
            )

    # ------------------------------------------------------------------
    # Button handler
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if self._server_busy:
            event.stop()
            return
        button_id = event.button.id

        if button_id == "btn_create_team":
            self._show_create_form()

        elif button_id == "btn_view_team":
            self._action_view_team()

        elif button_id == "btn_save_team":
            self._submit_create_team()

        elif button_id == "btn_cancel_create_team":
            self._hide_create_form()

        elif button_id == "btn_invite":
            if self._current_team_slug:
                self._show_invite_form()
            else:
                self.notify("Select a team first.", severity="warning")

        elif button_id == "btn_send_invite":
            self._submit_invite_member()

        elif button_id == "btn_cancel_invite":
            self._hide_invite_form()

        elif button_id == "btn_remove":
            self._action_remove_member()

        elif button_id == "btn_resend":
            self._action_resend_invite()

        elif button_id == "btn_copy_url":
            self._action_copy_accept_url()

        elif button_id == "btn_change_role":
            self._action_change_role()

        elif button_id == "btn_save_role":
            self._submit_change_role()

        elif button_id == "btn_cancel_change_role":
            self._hide_change_role_form()

        elif button_id == "btn_connect_shared":
            self._action_connect_shared_server()

        elif button_id == "btn_share":
            self._action_share_server()

        elif button_id == "btn_share_all":
            self._action_share_all_servers()

        elif button_id == "btn_remove_server":
            self._action_remove_shared_server()

        elif button_id == "btn_remove_servers":
            self._action_remove_shared_servers()

        elif button_id == "btn_confirm_share":
            self._submit_share_server()

        elif button_id == "btn_cancel_share":
            self._hide_share_server_form()

        elif button_id == "btn_push_config":
            self._action_push_config()

        elif button_id == "btn_confirm_push_config":
            self._submit_push_config()

        elif button_id == "btn_push_servers_all":
            self.query_one("#push_config_servers", SelectionList).select_all()

        elif button_id == "btn_push_servers_none":
            self.query_one("#push_config_servers", SelectionList).deselect_all()

        elif button_id == "btn_cancel_push_config":
            self._hide_push_config_form()

        elif button_id == "btn_pull_config":
            self._action_pull_config()

        elif button_id == "btn_confirm_pull_config":
            self._submit_pull_config()

        elif button_id == "btn_cancel_pull_config":
            self._hide_pull_config_form()
            self._pending_pull_payload = None

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

        if slug != self._current_team_slug or not self._has_team_detail:
            self._invalidate_team_detail(slug)
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
        if not self._can_manage_members():
            self.notify("Only owners and admins can invite members.", severity="warning")
            return
        email = self.query_one("#input_invite_email", Input).value.strip()
        role_value = self.query_one("#select_invite_role", Select).value
        role = role_value if isinstance(role_value, str) else "member"
        if not email:
            self.notify("Email is required.", severity="error")
            self.query_one("#input_invite_email", Input).focus()
            return
        self.run_worker(
            self._do_invite_member(self._current_team_slug, email, role),
            exclusive=True,
            name="invite_member",
        )

    def _selected_member(self) -> Optional[dict]:
        """Return the member dict for the currently-highlighted members table row."""
        table = self.query_one("#members_table", DataTable)
        row = table.cursor_row
        if row is None or row < 0 or row >= len(self._members):
            return None
        return self._members[row]

    def _action_remove_member(self) -> None:
        if not self._current_team_slug:
            self.notify("Select a team first.", severity="warning")
            return
        if not self._can_manage_members():
            self.notify("Only owners and admins can remove members.", severity="warning")
            return

        member = self._selected_member()
        if member is None:
            self.notify("No member selected.", severity="warning")
            return

        if (member.get("role") or "").lower() == "owner":
            self.notify("The owner cannot be removed.", severity="warning")
            return

        email = self._member_display_email(member)
        member_id = member.get("id", "")
        if not member_id:
            self.notify("Cannot resolve member id; refresh the team and try again.", severity="error")
            return

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
                await self._do_remove_member(slug, member_id, email)

        self.run_worker(_confirm_and_remove(), exclusive=True, name="remove_member")

    def _action_resend_invite(self) -> None:
        if not self._current_team_slug:
            self.notify("Select a team first.", severity="warning")
            return
        if not self._can_manage_members():
            self.notify("Only owners and admins can resend invites.", severity="warning")
            return
        member = self._selected_member()
        if member is None:
            self.notify("No member selected.", severity="warning")
            return
        if member.get("is_accepted"):
            self.notify("This member has already accepted — nothing to resend.", severity="warning")
            return
        member_id = member.get("id", "")
        if not member_id:
            self.notify("Cannot resolve member id; refresh the team and try again.", severity="error")
            return
        email = self._member_display_email(member)
        self.run_worker(
            self._do_resend_invite(self._current_team_slug, member_id, email),
            exclusive=True,
            name="resend_invite",
        )

    def _action_copy_accept_url(self) -> None:
        member = self._selected_member()
        if member is None:
            self.notify("No member selected.", severity="warning")
            return
        if member.get("is_accepted"):
            self.notify("This member has already accepted.", severity="warning")
            return
        accept_url = member.get("accept_url")
        if not accept_url:
            # accept_url is only populated for owners/admins on pending rows.
            if not self._can_manage_members():
                self.notify("Only owners and admins can copy accept URLs.", severity="warning")
            else:
                self.notify(
                    "No accept URL available — refresh the team or resend the invite first.",
                    severity="warning",
                )
            return
        try:
            self.app.copy_to_clipboard(accept_url)
        except Exception as exc:  # noqa: BLE001
            logger.warning("copy_to_clipboard failed: %s", exc)
            self.notify(f"Could not copy to clipboard: {exc}", severity="error", markup=False)
            return
        email = self._member_display_email(member)
        self.notify(f"Accept URL for {email} copied to clipboard.", severity="information")

    def _action_change_role(self) -> None:
        if not self._current_team_slug:
            self.notify("Select a team first.", severity="warning")
            return
        if not self._can_manage_members():
            self.notify("Only owners and admins can change roles.", severity="warning")
            return
        member = self._selected_member()
        if member is None:
            self.notify("No member selected.", severity="warning")
            return
        if (member.get("role") or "").lower() == "owner":
            self.notify("The owner role cannot be changed via the API.", severity="warning")
            return
        if (member.get("role") or "").lower() == "admin" and not self._can_manage_admins():
            self.notify("Only the owner can demote an admin.", severity="warning")
            return
        self._show_change_role_form(member)

    def _submit_change_role(self) -> None:
        if not self._current_team_slug:
            self.notify("Select a team first.", severity="warning")
            return
        member = self._selected_member()
        if member is None:
            self.notify("No member selected.", severity="warning")
            return
        member_id = member.get("id", "")
        if not member_id:
            self.notify("Cannot resolve member id; refresh the team and try again.", severity="error")
            return
        role_value = self.query_one("#select_change_role", Select).value
        new_role = role_value if isinstance(role_value, str) else "member"
        # Server-side: only owners can assign 'admin'; mirror as a floor.
        if new_role == "admin" and not self._can_manage_admins():
            self.notify("Only the owner can assign the admin role.", severity="warning")
            return
        email = self._member_display_email(member)
        self.run_worker(
            self._do_update_role(self._current_team_slug, member_id, email, new_role),
            exclusive=True,
            name="update_role",
        )

    def _action_share_server(self) -> None:
        """Open the share-server picker form."""
        if self._server_busy:
            return
        if not self._current_team_slug:
            self.notify("Select a team first.", severity="warning")
            return
        if not self._can_manage_members():
            self.notify("Only owners and admins can share servers.", severity="warning")
            return
        instances = self._share_inventory()
        if not instances:
            self.notify("No servers available to share.", severity="warning")
            return
        self._show_share_server_form(instances)

    def _action_push_config(self) -> None:
        """Open the push-config form. Only owners/admins reach this button."""
        if not self._current_team_slug:
            self.notify("Select a team first.", severity="warning")
            return
        if not self._can_manage_members():
            self.notify("Only owners and admins can push team configs.", severity="warning")
            return
        self._show_push_config_form()

    def _submit_push_config(self) -> None:
        if not self._current_team_slug:
            self.notify("Select a team first.", severity="warning")
            return
        if not self._can_manage_members():
            self.notify("Only owners and admins can push team configs.", severity="warning")
            return
        config_manager = getattr(self.app, "config_manager", None)
        config = config_manager.get() if config_manager is not None else None
        if config is None:
            self.notify("Local config not available.", severity="error")
            return
        from servonaut.services.team_config_subset import build_shareable_subset
        payload, _summary = build_shareable_subset(
            config, custom_servers=self._push_selected_servers()
        )
        description = self.query_one("#input_push_description", Input).value.strip() or None
        self.run_worker(
            self._do_push_config(self._current_team_slug, payload, description),
            exclusive=True,
            name="push_team_config",
        )

    async def _do_push_config(self, slug: str, payload: dict, description: Optional[str]) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        try:
            result = await team_svc.push_team_config(slug, payload, description)
            self._hide_push_config_form()
            version = result.get("version", "?") if isinstance(result, dict) else "?"
            self.notify(f"Pushed config version {version}.", severity="information")
            await self._load_team_detail(slug)
        except APIError as exc:
            logger.error("Push team config failed (%s): %s", exc.status, exc.message)
            if exc.status == 403:
                self.notify(
                    "Only team owners and admins can push configs.",
                    severity="error",
                )
            else:
                self.notify(f"Push failed: {exc.message}", severity="error", markup=False)
        except Exception as exc:  # noqa: BLE001
            logger.error("Push team config failed: %s", exc)
            self.notify(f"Push failed: {exc}", severity="error", markup=False)

    def _action_pull_config(self) -> None:
        """Fetch the team's latest config and open the apply-confirmation form."""
        if not self._current_team_slug:
            self.notify("Select a team first.", severity="warning")
            return
        self.run_worker(
            self._do_pull_config(self._current_team_slug),
            exclusive=True,
            name="pull_team_config",
        )

    async def _do_pull_config(self, slug: str) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        try:
            latest = await team_svc.get_latest_team_config(slug)
        except APIError as exc:
            logger.error("Pull team config failed (%s): %s", exc.status, exc.message)
            self.notify(f"Pull failed: {exc.message}", severity="error", markup=False)
            return
        except Exception as exc:  # noqa: BLE001
            logger.error("Pull team config failed: %s", exc)
            self.notify(f"Pull failed: {exc}", severity="error", markup=False)
            return
        if latest is None:
            self.notify("No team config has been pushed yet.", severity="warning")
            return
        config_data = latest.get("config_data") if isinstance(latest, dict) else None
        if not isinstance(config_data, dict):
            self.notify("Team config payload is malformed; cannot apply.", severity="error")
            return
        # Surface the apply preview inline; user confirms via the form's Apply button.
        self._show_pull_config_form(config_data)

    def _submit_pull_config(self) -> None:
        """Apply the previously-fetched remote payload over the local config."""
        if self._pending_pull_payload is None:
            self.notify("Click 'Pull Latest' first to fetch the team config.", severity="warning")
            return
        config_manager = getattr(self.app, "config_manager", None)
        config = config_manager.get() if config_manager is not None else None
        if config is None or config_manager is None:
            self.notify("Local config manager not available — cannot apply.", severity="error")
            return
        from servonaut.services.team_config_apply import apply_team_config
        payload = self._pending_pull_payload
        try:
            kept = apply_team_config(config, payload)
            config_manager.save(config)
        except Exception as exc:  # noqa: BLE001
            logger.error("Apply team config failed: %s", exc)
            self.notify(f"Apply failed: {exc}", severity="error", markup=False)
            return
        self._pending_pull_payload = None
        self._hide_pull_config_form()
        self.notify(
            "Team config applied"
            + (f"; {_kept_key_paths_text(kept)}. " if kept else ". ")
            + "Restart Servonaut for connection-profile changes to take full effect.",
            severity="information",
            timeout=10,
        )

    def _action_share_all_servers(self) -> None:
        """Offer every eligible instance not yet on the team, then share the ones confirmed.

        Eligible = has a hostname (public or private IP). Dedupe uses stable
        provider ids and unambiguous host/port matches. Nothing is
        sent until the user confirms the list in ShareServersConfirmModal.
        """
        if self._server_busy:
            return
        if not self._current_team_slug:
            self.notify("Select a team first.", severity="warning")
            return
        if not self._can_manage_members():
            self.notify("Only owners and admins can share servers.", severity="warning")
            return
        instances = self._share_inventory()
        if not instances:
            self.notify("No servers available to share.", severity="warning")
            return

        candidates, skipped_existing, skipped_no_ip = share_candidates(instances, self._shared_servers)
        to_share = [self._share_defaults(instance) for instance in candidates]

        if not to_share:
            self.notify(
                f"Nothing to share. Already shared: {skipped_existing}. No IP: {skipped_no_ip}.",
                severity="information",
            )
            return

        slug = self._current_team_slug
        self.app.push_screen(
            ShareServersConfirmModal(
                self._current_team_name or slug,
                to_share,
                skipped_existing=skipped_existing,
                skipped_no_address=skipped_no_ip,
            ),
            callback=partial(
                self._share_all_confirmed, slug, len(to_share), skipped_existing, skipped_no_ip
            ),
        )

    def _share_all_confirmed(
        self,
        slug: str,
        offered: int,
        skipped_existing: int,
        skipped_no_ip: int,
        chosen: Optional[list[dict]],
    ) -> None:
        """Share the servers ticked in Share All's confirmation; nothing when it was cancelled."""
        if not chosen:
            return
        if slug != self._loaded_team_slug or slug != self._current_team_slug:
            self.notify("Team data changed or is refreshing. Reload the team and reopen Share All.", severity="warning")
            return
        self._start_server_operation(
            partial(self._do_share_all, slug, chosen, skipped_existing, skipped_no_ip,
                    left_out=offered - len(chosen)),
            "Preparing to share servers…",
        )

    async def _do_share_all(
        self,
        slug: str,
        instances: list[dict],
        skipped_existing: int,
        skipped_no_ip: int,
        *,
        left_out: int = 0,
    ) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        indicator = self.query_one("#team_servers_busy", BusyIndicator)
        indicator.start(f"Sharing 1/{len(instances)} servers…")

        def progress(index: int, total: int, _result: ShareResult) -> None:
            indicator.start(f"Sharing {min(index + 1, total)}/{total} servers…")

        results = await team_svc.push_servers(slug, [share_payload(row) for row in instances], on_progress=progress)
        succeeded = sum(result.status == SHARED for result in results)
        skipped_existing += sum(result.status == ALREADY_SHARED for result in results)
        failed = [f"{self._display_server_name(result.payload.get('name', ''))} ({result.error})"
                  for result in results if result.status == FAILED]

        parts = [f"Shared {succeeded}"]
        if left_out:
            parts.append(f"left out {left_out}")
        if skipped_existing:
            parts.append(f"skipped {skipped_existing} already shared")
        if skipped_no_ip:
            parts.append(f"skipped {skipped_no_ip} without IP")
        if failed:
            parts.append(f"failed {len(failed)}")
        summary = "Share All: " + ", ".join(parts) + "."
        severity = "warning" if failed else "information"
        self.notify(summary, severity=severity, timeout=12 if failed else 6, markup=False)
        if failed:
            for line in failed:
                logger.warning("Share All failure detail: %s", line)
            for line in failure_details(self.app, failed):
                self.notify(line, severity="error", markup=False)
        await self._load_team_detail(slug)

    def _submit_share_server(self) -> None:
        """Submit the share form: build payload from selected instance."""
        if self._server_busy:
            return
        if not self._current_team_slug:
            self.notify("Select a team first.", severity="warning")
            return
        if not self._can_manage_members():
            self.notify("Only owners and admins can share servers.", severity="warning")
            return
        selected_value = self.query_one("#select_share_instance", Select).value
        if selected_value == Select.BLANK or not isinstance(selected_value, str):
            self.notify("Pick a server to share.", severity="warning")
            return
        instance = next(
            (i for i in self._share_inventory() if str(i.get("id")) == selected_value),
            None,
        )
        if instance is None:
            self.notify("Selected server is no longer in your inventory; refresh and try again.", severity="error")
            return
        if instance.get("is_shared") is True or already_shared(instance, self._shared_servers):
            self.notify("This server is already shared with the team.", severity="warning")
            return
        hostname = instance.get("public_ip") or instance.get("private_ip") or ""
        if not hostname:
            # Defensive — _build_share_options should have filtered this row out,
            # but the inventory may have changed since the form was opened.
            self.notify(
                f"Instance '{instance.get('name', '?')}' has no public or private IP — cannot share.",
                severity="warning",
            )
            return
        # Read connection-detail inputs. Both optional — null/22 are the
        # backend defaults and the consumer's CLI applies a cloud-specific
        # username fallback when the stored value is null.
        username = self.query_one("#input_share_username", Input).value.strip()
        raw_username, displayed_username = self._share_form_username
        if username == displayed_username:
            username = raw_username
        port_raw = self.query_one("#input_share_port", Input).value.strip()
        port: Optional[int] = None
        if port_raw:
            try:
                port = int(port_raw)
            except ValueError:
                self.notify("Port must be a number between 1 and 65535.", severity="error")
                return
            if not 1 <= port <= 65535:
                self.notify("Port must be between 1 and 65535.", severity="error")
                return
        # Backend contract (Api/Team/SharedServerController::create):
        #   required: name, hostname
        #   optional: instance_id, region, tags, status, username, port
        server_data: dict = {
            "name": instance.get("name") or instance.get("id", ""),
            "hostname": hostname,
        }
        if instance.get("id"):
            server_data["instance_id"] = instance["id"]
        if instance.get("region"):
            server_data["region"] = instance["region"]
        if username:
            server_data["username"] = username
        if port is not None and port != 22:
            server_data["port"] = port
        self._start_server_operation(
            partial(self._do_push_server, self._current_team_slug, server_data), "Sharing the server…",
        )

    def _start_server_operation(self, operation: Callable[[], Awaitable[None]], message: str) -> None:
        """Hold the screen's controls from the first click through the final reload."""
        if self._server_busy:
            return
        self._server_busy = True
        focused = self.focused
        controls = [(widget, widget.disabled) for widget in self.query("Button, DataTable, Select, Input")]
        for widget, _ in controls:
            widget.disabled = True
        indicator = self.query_one("#team_servers_busy", BusyIndicator)
        indicator.start(message)
        self.call_after_refresh(indicator.scroll_visible, animate=False)

        async def run() -> None:
            try:
                await operation()
            except Exception as exc:
                logger.exception("Shared server operation failed")
                self.notify(f"Could not update the shared servers: {exc}", severity="error", markup=False)
            finally:
                indicator.stop()
                for widget, was_disabled in controls:
                    widget.disabled = was_disabled
                self._server_busy = False
                if focused is not None and focused.is_mounted:
                    self.call_after_refresh(focused.focus)

        self.run_worker(run(), group="team_servers", exclusive=True, name="team_servers")

    def _can_remove_servers(self) -> bool:
        if self._server_busy:
            return False
        if not self._current_team_slug:
            self.notify("Select a team first.", severity="warning")
        elif self._loaded_team_slug != self._current_team_slug:
            self.notify("Load the selected team's shared inventory first.", severity="warning")
        elif not self._can_manage_members():
            self.notify("Only owners and admins can remove shared servers.", severity="warning")
        elif not self._shared_servers:
            self.notify("No shared servers to remove.", severity="information")
        else:
            return True
        return False

    def _action_remove_shared_server(self) -> None:
        if not self._can_remove_servers():
            return
        row = self.query_one("#servers_table", DataTable).cursor_row
        if not 0 <= row < len(self._shared_servers):
            self.notify("Select a shared server first.", severity="warning")
            return
        slug = self._current_team_slug
        server = dict(self._shared_servers[row])
        label = self._display_server_name(server.get("name") or "Unnamed server")

        async def confirm() -> None:
            if await self.app.push_screen_wait(ConfirmActionScreen(
                "Remove shared server", f"Remove {markup_literal(label)} from the team's shared inventory?",
                ["remove this server from the team's shared inventory", "keep your local server and its configuration"],
                "REMOVE", "Remove", severity="warning",
            )):
                self._start_server_operation(partial(self._do_remove_shared_servers, slug, [server]), "Removing the shared server…")

        self.run_worker(confirm(), group="team_server_confirm", exclusive=True)

    def _action_remove_shared_servers(self) -> None:
        if not self._can_remove_servers():
            return
        slug = self._current_team_slug
        servers = [dict(server) for server in self._shared_servers]

        def selected(indices: list[str] | None) -> None:
            if not indices:
                return
            if slug != self._current_team_slug:
                self.notify("The selected team changed. Reopen removal and try again.", severity="warning")
                return
            if slug != self._loaded_team_slug:
                self.notify("Team data is not current. Reload the team before retrying removal.", severity="warning")
                return
            chosen = [servers[int(index)] for index in indices]
            self._start_server_operation(partial(self._do_remove_shared_servers, slug, chosen), "Removing shared servers…")

        self.app.push_screen(BulkActionModal(
            "Remove shared servers",
            "Remove the selected servers from the team's shared inventory. Hosts and your local configuration stay in place.",
            [(str(index), f"{server.get('name') or '?'}  {server_address(server)}")
             for index, server in enumerate(servers)],
            action_label="Remove", confirm_text="REMOVE",
            label_builder=lambda key: f"{self._display_server_name(servers[int(key)].get('name') or '?')}  "
                                      f"{self._display_server_address(server_address(servers[int(key)]))}",
        ), callback=selected)

    async def _do_remove_shared_servers(self, slug: str, servers: list[dict]) -> None:
        service = getattr(self.app, "team_service", None)
        if service is None:
            return
        removed = 0
        failures: list[str] = []
        for index, server in enumerate(servers, start=1):
            self.query_one("#team_servers_busy", BusyIndicator).start(f"Removing {index}/{len(servers)} shared servers…")
            failure = await self._remove_one_shared_server(service, slug, server)
            if failure is None:
                removed += 1
            else:
                failures.append(failure)
                logger.warning("Shared server removal failed: %s", failure)
        self.notify(
            f"Removed {removed} shared server(s)." + (f" Failed: {len(failures)}." if failures else ""),
            severity="warning" if failures else "information", markup=False,
        )
        for failure in failure_details(self.app, failures):
            self.notify(failure, severity="error", markup=False)
        await self._load_team_detail(slug)

    async def _remove_one_shared_server(self, service: Any, slug: str, server: dict) -> str | None:
        name = self._display_server_name(server.get("name") or "")
        try:
            if slug != self._loaded_team_slug or slug != self._current_team_slug:
                raise ValueError("the selected team's inventory changed; reload and try again")
            server_id = str(server.get("id") or "")
            if not server_id:
                raise ValueError("the shared server has no ID; reload and try again")
            await service.remove_shared_server(slug, server_id)
        except APIError as exc:
            if exc.status == 404:
                try:
                    remaining = await service.list_shared_servers(slug)
                except Exception:
                    return f"{name}: the team's inventory could not be checked; reload and try again"
                if not any(str(row.get("id")) == server_id for row in remaining):
                    return None
            return f"{name}: {exc.message}"
        except Exception as exc:
            logger.warning("Shared server removal failed", exc_info=exc)
            return f"{name}: {exc}"
        return None

    def _display_server_name(self, name: object) -> str:
        label = terminal_safe(name)
        if self.app.demo_mode and self.app.redaction_service:
            return self.app.redaction_service.redact_name(label)
        return label

    def _display_server_address(self, address: str) -> str:
        if self.app.demo_mode and self.app.redaction_service:
            return self.app.redaction_service.redact_host(address)
        return terminal_safe(address)

    # ------------------------------------------------------------------
    # Binding actions
    # ------------------------------------------------------------------

    def action_back(self) -> None:
        if self._server_busy:
            return
        self.app.pop_screen()

    def navigation_hold_reason(self) -> str | None:
        return "Wait for the server changes to finish before leaving." if self._server_busy else None
