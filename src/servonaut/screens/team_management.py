"""Team Management screen for Servonaut."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Select, Static

from servonaut.screens._binding_guard import check_action_passthrough
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.services.api_client import APIError
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

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static("[bold cyan]Team Management[/bold cyan]", id="team_mgmt_header"),

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
                            "[yellow]Pulling REPLACES your local connection profiles, "
                            "connection rules, scan rules, and custom servers with the "
                            "team's version. AI / cloud-provider / personal settings are "
                            "untouched.[/yellow]",
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
                    DataTable(id="servers_table"),
                    Horizontal(
                        Button("Share Server", variant="primary", id="btn_share"),
                        Button("Share All", variant="default", id="btn_share_all"),
                        classes="add_row",
                        id="server_actions_row",
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
        for widget_id in ("team_header", "members_section", "configs_section", "servers_section"):
            self.query_one(f"#{widget_id}").display = False

    def _show_detail_section(self) -> None:
        for widget_id in ("team_header", "members_section", "configs_section", "servers_section"):
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
        options = self._build_share_options(instances)
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
        instances = getattr(self.app, "instances", [])
        instance = next((i for i in instances if str(i.get("id")) == instance_id), None)
        if instance is None:
            return
        username = instance.get("username") or ""
        port = instance.get("port")
        self.query_one("#input_share_username", Input).value = username
        self.query_one("#input_share_port", Input).value = str(port) if port and port != 22 else ""

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
        for instance in instances:
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
            f"[bold]Change Role: {display_email}[/bold]"
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
            self.notify(f"Failed to load teams: {exc}", severity="error")

    async def _load_team_detail(self, slug: str) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        try:
            team = await team_svc.get_team(slug)
            members = team.get("members", [])
            self._members = members
            # Caller role drives mutation-button visibility. Prefer the
            # top-level ``role`` field (set per-caller by the backend) and
            # fall back to scanning members for the authenticated user.
            self._current_team_role = (
                team.get("role")
                or self._team_roles.get(slug)
                or self._infer_caller_role(members)
            )
            self._populate_members_table(members)

            servers = await team_svc.list_shared_servers(slug)
            self._shared_servers = servers
            self._populate_servers_table(servers)

            try:
                configs = await team_svc.list_team_configs(slug)
            except Exception as exc:  # noqa: BLE001 — list failure shouldn't abort the whole detail load
                logger.warning("Failed to list team configs for %s: %s", slug, exc)
                configs = []
            self._team_configs = configs
            self._populate_configs_table(configs)
            self._hide_push_config_form()
            self._hide_pull_config_form()

            self._show_detail_section()
            team_name = team.get("name", slug)
            self._current_team_name = team_name
            display_team_name = (
                self.app.redaction_service.redact_name(team_name)
                if self.app.demo_mode and self.app.redaction_service
                else team_name
            )
            seat_line = self._format_seat_line(team, members)
            self.query_one("#team_header", Static).update(
                f"[bold]Team: {display_team_name}[/bold]\n{seat_line}"
            )
            self._refresh_member_buttons()
        except Exception as exc:
            logger.error("Failed to load team detail: %s", exc)
            self.notify(f"Failed to load team: {exc}", severity="error")

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
            self.notify(exc.message, severity="error", timeout=10)
        except Exception as exc:
            logger.error("Failed to create team: %s", exc)
            self.notify(f"Failed to create team: {exc}", severity="error")

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
            self.notify(f"Failed to invite member: {exc}", severity="error")

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
            self.notify(f"Failed to resend invite: {exc}", severity="error")

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
            self.notify(f"{exc.message} {hint}", severity="warning", timeout=12)
            return
        if exc.status == 422:
            self.notify(
                f"{exc.message} Remove an existing member, or upgrade the seat cap.",
                severity="warning",
                timeout=12,
            )
            return
        # All other 4xx — show the server's message rather than the wrapped repr.
        self.notify(f"{fallback}: {exc.message}", severity="error")

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
            self.notify(f"Failed to remove member: {exc}", severity="error")

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
            self.notify(f"Failed to update role: {exc}", severity="error")

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
            )
            await self._load_team_detail(slug)
        except APIError as exc:
            logger.error("Failed to share server (%s): %s", exc.status, exc.message)
            # Backend 409 example: "A server with this hostname is already shared."
            self.notify(f"Failed to share server: {exc.message}", severity="error")
        except Exception as exc:
            logger.error("Failed to share server: %s", exc)
            self.notify(f"Failed to share server: {exc}", severity="error")

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
        owned_count = 0
        for team in teams:
            slug = team.get("slug", "")
            role = (team.get("role") or "").lower()
            if slug:
                self._team_roles[slug] = role
            if role == "owner":
                owned_count += 1
            table.add_row(
                _s(team.get("name", "")),
                role,
                str(team.get("member_count", "")),
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
                _s(self._member_display_email(member)),
                member.get("role", ""),
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
            description = (cfg.get("description") or "")[:40]
            pushed_by = str(cfg.get("pushed_by", ""))
            created = (cfg.get("created_at") or "")[:10]  # YYYY-MM-DD portion
            table.add_row(str(version), _s(description), created, pushed_by, key=str(cfg.get("id", "")))

    def _hide_push_config_form(self) -> None:
        self.query_one("#push_config_form").display = False

    def _hide_pull_config_form(self) -> None:
        self.query_one("#pull_config_form").display = False

    def _show_push_config_form(self) -> None:
        from servonaut.services.team_config_subset import build_shareable_subset
        config = getattr(self.app, "config", None)
        if config is None:
            self.notify("Local config not available.", severity="error")
            return
        _payload, summary = build_shareable_subset(config)
        preview = (
            f"Will share: [bold]{summary['connection_profiles']}[/bold] connection profiles, "
            f"[bold]{summary['connection_rules']}[/bold] connection rules, "
            f"[bold]{summary['scan_rules']}[/bold] scan rules, "
            f"[bold]{summary['custom_servers']}[/bold] custom servers."
        )
        if summary["stripped_paths"]:
            preview += (
                f"\n[yellow]{summary['stripped_paths']} local SSH key path(s) will be "
                "stripped — teammates must re-bind them locally.[/yellow]"
            )
        self.query_one("#push_config_preview", Static).update(preview)
        self.query_one("#input_push_description", Input).value = ""
        form = self.query_one("#push_config_form")
        form.display = True
        self.query_one("#input_push_description", Input).focus()

    def _show_pull_config_form(self, remote_payload: dict) -> None:
        from servonaut.services.team_config_subset import diff_against_local
        config = getattr(self.app, "config", None)
        if config is None:
            self.notify("Local config not available.", severity="error")
            return
        diff = diff_against_local(config, remote_payload)
        lines = ["Pull will replace these sections (current → after):"]
        for section in ("connection_profiles", "connection_rules", "scan_rules", "custom_servers"):
            d = diff[section]
            change_hint = "[green]no change[/green]" if d["local"] == d["after"] else f"[bold]{d['local']} → {d['after']}[/bold]"
            lines.append(f"  • {section.replace('_', ' ').title()}: {change_hint}")
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
                _name(server.get("name", "")),
                # Backend field is "hostname"; tolerate legacy "host" key for back-compat.
                _host(server.get("hostname") or server.get("host", "")),
                server.get("region", "") or "",
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

        elif button_id == "btn_share":
            self._action_share_server()

        elif button_id == "btn_share_all":
            self._action_share_all_servers()

        elif button_id == "btn_confirm_share":
            self._submit_share_server()

        elif button_id == "btn_cancel_share":
            self._hide_share_server_form()

        elif button_id == "btn_push_config":
            self._action_push_config()

        elif button_id == "btn_confirm_push_config":
            self._submit_push_config()

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

        self._current_team_slug = slug
        # Close any open inline forms so they don't leak context across teams.
        self._hide_invite_form()
        self._hide_change_role_form()
        self._hide_share_server_form()
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
            self.notify(f"Could not copy to clipboard: {exc}", severity="error")
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
        if not self._current_team_slug:
            self.notify("Select a team first.", severity="warning")
            return
        if not self._can_manage_members():
            self.notify("Only owners and admins can share servers.", severity="warning")
            return
        instances = getattr(self.app, "instances", [])
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
        config = getattr(self.app, "config", None)
        if config is None:
            self.notify("Local config not available.", severity="error")
            return
        from servonaut.services.team_config_subset import build_shareable_subset
        payload, _summary = build_shareable_subset(config)
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
                self.notify(f"Push failed: {exc.message}", severity="error")
        except Exception as exc:  # noqa: BLE001
            logger.error("Push team config failed: %s", exc)
            self.notify(f"Push failed: {exc}", severity="error")

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
            self.notify(f"Pull failed: {exc.message}", severity="error")
            return
        except Exception as exc:  # noqa: BLE001
            logger.error("Pull team config failed: %s", exc)
            self.notify(f"Pull failed: {exc}", severity="error")
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
        config = getattr(self.app, "config", None)
        config_manager = getattr(self.app, "config_manager", None)
        if config is None or config_manager is None:
            self.notify("Local config manager not available — cannot apply.", severity="error")
            return
        from servonaut.services.team_config_apply import apply_team_config
        payload = self._pending_pull_payload
        try:
            apply_team_config(config, payload)
            config_manager.save()
        except Exception as exc:  # noqa: BLE001
            logger.error("Apply team config failed: %s", exc)
            self.notify(f"Apply failed: {exc}", severity="error")
            return
        self._pending_pull_payload = None
        self._hide_pull_config_form()
        self.notify(
            "Team config applied. Restart Servonaut for connection-profile changes to take full effect.",
            severity="information",
            timeout=10,
        )

    def _action_share_all_servers(self) -> None:
        """Bulk-share every eligible instance, skipping ones already on the team.

        Eligible = has a routable hostname (public or private IP). Dedupe is
        applied client-side via instance_id first (most reliable), then by
        hostname (handles non-cloud custom servers without an id).
        """
        if not self._current_team_slug:
            self.notify("Select a team first.", severity="warning")
            return
        if not self._can_manage_members():
            self.notify("Only owners and admins can share servers.", severity="warning")
            return
        instances = getattr(self.app, "instances", [])
        if not instances:
            self.notify("No servers available to share.", severity="warning")
            return

        # Build dedupe sets from the team's currently-shared list. Both lookups
        # tolerate the server returning either or both fields.
        already_shared_ids = {
            s.get("instance_id") for s in self._shared_servers if s.get("instance_id")
        }
        already_shared_hosts = {
            s.get("hostname") for s in self._shared_servers if s.get("hostname")
        }

        to_share: list[dict] = []
        skipped_existing = 0
        skipped_no_ip = 0
        for instance in instances:
            hostname = instance.get("public_ip") or instance.get("private_ip")
            if not hostname:
                skipped_no_ip += 1
                continue
            if instance.get("id") and instance["id"] in already_shared_ids:
                skipped_existing += 1
                continue
            if hostname in already_shared_hosts:
                skipped_existing += 1
                continue
            to_share.append(instance)

        if not to_share:
            self.notify(
                f"Nothing to share. Already shared: {skipped_existing}. No IP: {skipped_no_ip}.",
                severity="information",
            )
            return

        slug = self._current_team_slug
        self.run_worker(
            self._do_share_all(slug, to_share, skipped_existing, skipped_no_ip),
            exclusive=True,
            name="share_all_servers",
        )

    async def _do_share_all(
        self,
        slug: str,
        instances: list[dict],
        skipped_existing: int,
        skipped_no_ip: int,
    ) -> None:
        team_svc = getattr(self.app, "team_service", None)
        if team_svc is None:
            return
        succeeded = 0
        failed: list[str] = []
        for instance in instances:
            payload: dict = {
                "name": instance.get("name") or instance.get("id", ""),
                "hostname": instance.get("public_ip") or instance.get("private_ip"),
            }
            if instance.get("id"):
                payload["instance_id"] = instance["id"]
            if instance.get("region"):
                payload["region"] = instance["region"]
            if instance.get("username"):
                payload["username"] = instance["username"]
            port = instance.get("port")
            if port and port != 22:
                payload["port"] = port
            try:
                await team_svc.push_server(slug, payload)
                succeeded += 1
            except APIError as exc:
                logger.warning("Bulk share failed for %s (%s): %s", payload["name"], exc.status, exc.message)
                failed.append(f"{payload['name']} ({exc.message})")
            except Exception as exc:  # noqa: BLE001
                logger.warning("Bulk share failed for %s: %s", payload["name"], exc)
                failed.append(f"{payload['name']} ({exc})")

        parts = [f"Shared {succeeded}"]
        if skipped_existing:
            parts.append(f"skipped {skipped_existing} already shared")
        if skipped_no_ip:
            parts.append(f"skipped {skipped_no_ip} without IP")
        if failed:
            parts.append(f"failed {len(failed)}")
        summary = "Share All: " + ", ".join(parts) + "."
        severity = "warning" if failed else "information"
        self.notify(summary, severity=severity, timeout=12 if failed else 6)
        if failed:
            # Surface the first 3 failure reasons so the user has something to act on.
            for line in failed[:3]:
                logger.warning("Share All failure detail: %s", line)
        await self._load_team_detail(slug)

    def _submit_share_server(self) -> None:
        """Submit the share form: build payload from selected instance."""
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
            (i for i in getattr(self.app, "instances", []) if str(i.get("id")) == selected_value),
            None,
        )
        if instance is None:
            self.notify("Selected server is no longer in your inventory; refresh and try again.", severity="error")
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
