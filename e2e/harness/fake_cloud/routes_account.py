"""Account data routes: teams, their members and shared servers, and the SSH-verify sidecar.

The data is neutral and scenario-driven through :class:`AccountData`
(``FakeCloud.account``). Every route needs a current access token, so a
client with an expired token has to refresh before it sees anything.
A shared-server row carries the team SSH CA's view of that server
(``ssh_ca``), which the Vault fake supplies.

There are two kinds of team. *Scenario rows* (``configure(teams=...)``) are
served exactly as given, to the scenario's account only. *Managed teams*
(``create_team``, or ``POST /api/v1/teams``; see ``teams.py``) keep their
members: each member sees the team through their own role, and owners and
admins invite (``POST …/members``), resend (``…/members/{id}/resend``),
change roles (``PUT …/members/{id}``) and remove members (``DELETE``), as
the CLI's ``TeamService`` calls them. Shared servers (``POST`` and ``DELETE
…/servers``), their SSH-verify results (``…/servers/{id}/ssh-verify-*``) and
shared configs (``…/configs``) work for both kinds.
"""

from __future__ import annotations

import copy
import datetime as dt
import threading
import uuid
from typing import Any, Callable, Optional

from aiohttp import web

from e2e.harness.fake_cloud.routes_auth import (
    bearer_ok,
    json_body,
    unauthorized,
    validation_failed,
)
from e2e.harness.fake_cloud.state import ScenarioStore
from e2e.harness.fake_cloud.teams import (
    DEFAULT_MAX_SEATS,
    INVITE_PATH,
    MANAGERS,
    ManagedTeam,
    Refusal,
    slugify,
)
from e2e.harness.fake_cloud.users import current_account

VERIFY_STATUSES = frozenset({"verified", "not_found", "auth_failed"})

_DEFAULT_TEAMS: tuple[dict[str, Any], ...] = (
    {"slug": "ops", "name": "Ops", "role": "owner", "member_count": 2},
)

_VAULT_SHARED_SERVER = {
    "id": "c2a4e6f8-1b3d-4f5a-9c7e-0a2b4c6d8e1f",
    "name": "server-1",
    "hostname": "server-1.example.test",
    "port": 22,
    "login_user": "deploy",
}

# The shared server's host key, as a user verifies and passes it with --host-key.
VAULT_SHARED_SERVER_HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk"

# Who the scenario's account is when a managed team lists it (its
# entitlements carry no e-mail address).
SCENARIO_ACCOUNT_EMAIL = "owner@example.com"
SCENARIO_ACCOUNT_NAME = "Team owner"


def _not_found() -> Refusal:
    return Refusal(404, "not_found", "Team not found.")


class AccountData:
    """Thread-safe account records the routes serve."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._teams = copy.deepcopy(list(_DEFAULT_TEAMS))
            self._shared: dict[str, list[dict[str, Any]]] = {
                "example-team": [copy.deepcopy(_VAULT_SHARED_SERVER)],
            }
            self._verify: dict[tuple[str, str], dict[str, Any]] = {}
            self._managed: dict[str, ManagedTeam] = {}
            self._configs: dict[str, list[dict[str, Any]]] = {}
            self._team_verify: dict[tuple[str, str], dict[str, Any]] = {}
            # True: invitations are recorded but their e-mail "fails" (email_sent false).
            self.mail_delivery_fails = False

    def configure(
        self,
        *,
        teams: Optional[list[dict[str, Any]]] = None,
        shared_servers: Optional[dict[str, list[dict[str, Any]]]] = None,
    ) -> None:
        """Replace the teams and/or the shared-server inventory (per team slug)."""
        with self._lock:
            if teams is not None:
                self._teams = copy.deepcopy(teams)
            if shared_servers is not None:
                self._shared = copy.deepcopy(shared_servers)

    def place_shared_server(self, slug: str, server_id: str, **changes: Any) -> None:
        """Change one shared server's row (e.g. point it at a loopback host and port)."""
        with self._lock:
            for row in self._shared.get(slug, []):
                if row.get("id") == server_id:
                    row.update(copy.deepcopy(changes))
                    return
        raise KeyError(server_id)

    def shared_servers(self, slug: str) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._shared.get(slug, []))

    def set_verify_status(
        self, provider: str, instance_id: str, status: str, *, verified_at: Optional[str] = None
    ) -> None:
        """Record an SSH-verify result for one instance (as a probe would)."""
        if status not in VERIFY_STATUSES:
            raise ValueError(f"status must be one of {sorted(VERIFY_STATUSES)}")
        if status == "verified" and verified_at is None:
            verified_at = dt.datetime.now(dt.timezone.utc).isoformat()
        with self._lock:
            self._verify[(provider, instance_id)] = {
                "provider": provider,
                "instance_id": instance_id,
                "ssh_credential_provider": "bitwarden",
                "ssh_verify_status": status,
                # The service only keeps a timestamp for a verified key.
                "ssh_verified_at": verified_at if status == "verified" else None,
                "checked_by_client": None,
                "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            }

    def teams(self) -> list[dict[str, Any]]:
        """The scenario rows (managed teams are listed per caller: :meth:`teams_for`)."""
        with self._lock:
            return copy.deepcopy(self._teams)

    # -- managed teams: controls ------------------------------------------------

    def create_team(
        self, *, name: str, owner_user_id: int, owner_email: str = SCENARIO_ACCOUNT_EMAIL,
        owner_name: str = SCENARIO_ACCOUNT_NAME, slug: Optional[str] = None,
        team_id: Optional[str] = None, max_seats: int = DEFAULT_MAX_SEATS,
    ) -> dict[str, Any]:
        """A managed team owned by *owner_user_id*; replaces a scenario row with its slug."""
        with self._lock:
            slug = slug or self._free_slug(slugify(name))
            if slug in self._managed:
                raise ValueError(f"the team {slug} already exists")
            team = ManagedTeam(team_id or str(uuid.uuid4()), slug, name, max_seats)
            team.add_owner(owner_user_id, owner_email, owner_name)
            self._managed[slug] = team
            self._teams = [row for row in self._teams if row.get("slug") != slug]
            return team.summary(owner_user_id)

    def _free_slug(self, base: str) -> str:
        taken = set(self._managed) | {str(row.get("slug")) for row in self._teams}
        slug, number = base, 1
        while slug in taken:
            number += 1
            slug = f"{base}-{number}"
        return slug

    def team_members(self, slug: str) -> Optional[list[dict[str, Any]]]:
        """The active members of managed team *slug*; None for a scenario row (or no team)."""
        with self._lock:
            team = self._managed.get(slug)
            if team is None:
                return None
            return [
                {"user_id": m.user_id, "email": m.user_email, "name": m.name, "role": m.role,
                 "joined_at": m.accepted_at}
                for m in team.accepted()
            ]

    def members(self, slug: str) -> list[dict[str, Any]]:
        """Every member row of managed team *slug*, pending ones included (a journey's read)."""
        with self._lock:
            return [m.row("", manager=True) for m in self._managed[slug].members]

    def accept_invitation(
        self, email: str, *, user_id: int, name: str, user_email: str, slug: Optional[str] = None,
    ) -> dict[str, Any]:
        """The invitee opened the invitation sent to *email* and accepted it as *user_id*."""
        with self._lock:
            teams = [self._managed[slug]] if slug is not None else list(self._managed.values())
            for team in teams:
                if any(not m.accepted and m.email.lower() == email.lower() for m in team.members):
                    member = team.accept(email, user_id=user_id, name=name, user_email=user_email)
                    return {"team": team.slug, **member.row("", manager=False)}
        raise KeyError(f"no pending invitation for {email}")

    # -- every team, as each caller sees it ---------------------------------------

    def teams_for(self, user_id: int, *, scenario_account: bool) -> list[dict[str, Any]]:
        """``GET /api/v1/teams`` for *user_id*."""
        with self._lock:
            rows = copy.deepcopy(self._teams) if scenario_account else []
            rows += [t.summary(user_id) for t in self._managed.values() if t.role_of(user_id)]
            return rows

    def team_detail(self, slug: str, user_id: int, *, scenario_account: bool,
                    base_url: str) -> Optional[dict[str, Any]]:
        """``GET /api/v1/teams/{slug}`` for *user_id*; None when they cannot see it."""
        with self._lock:
            team = self._managed.get(slug)
            if team is not None:
                return team.detail(user_id, base_url) if team.role_of(user_id) else None
            row = next((t for t in self._teams if t.get("slug") == slug), None)
            if row is None or not scenario_account:
                return None
            return copy.deepcopy({**row, "members": row.get("members", [])})

    def caller_role(self, slug: str, user_id: int, *, scenario_account: bool) -> Optional[str]:
        """*user_id*'s role on team *slug*, or None when they cannot see the team."""
        with self._lock:
            team = self._managed.get(slug)
            if team is not None:
                return team.role_of(user_id)
            row = next((t for t in self._teams if t.get("slug") == slug), None)
            if row is None or not scenario_account:
                return None
            return str(row.get("role") or "member")

    # -- changes (each raises Refusal for what the service refuses) ---------------

    def create_team_as(self, user_id: int, *, name: object, plan: str, scenario_account: bool,
                       email: str, person: str) -> dict[str, Any]:
        """``POST /api/v1/teams``: Teams plan only, one owned team per subscription."""
        if plan != "teams":
            raise Refusal(403, "forbidden", "Only Teams-plan subscribers can create a team workspace.")
        if not isinstance(name, str) or not name.strip():
            raise Refusal(422, "validation_failed", "A team name is required.")
        if any(t.get("role") == "owner" for t in self.teams_for(user_id, scenario_account=scenario_account)):
            raise Refusal(403, "forbidden", "You already own a team workspace.")
        summary = self.create_team(name=name.strip(), owner_user_id=user_id, owner_email=email,
                                   owner_name=person)
        return {**summary, "max_seats": DEFAULT_MAX_SEATS}

    def _managed_for(self, slug: str, user_id: int) -> ManagedTeam:
        """Managed team *slug* if *user_id* is a member (call with the lock held)."""
        team = self._managed.get(slug)
        if team is None or team.role_of(user_id) is None:
            raise _not_found()
        return team

    def _sent(self, row: dict[str, Any]) -> dict[str, Any]:
        return {**row, "email_sent": not self.mail_delivery_fails}

    def invite(self, slug: str, user_id: int, email: object, role: object, base_url: str) -> dict[str, Any]:
        with self._lock:
            member = self._managed_for(slug, user_id).invite(user_id, email, role)
            return self._sent(member.row(base_url, manager=True))

    def resend(self, slug: str, user_id: int, member_id: str, base_url: str) -> dict[str, Any]:
        with self._lock:
            member = self._managed_for(slug, user_id).resend(user_id, member_id)
            return self._sent(member.row(base_url, manager=True))

    def change_role(self, slug: str, user_id: int, member_id: str, role: object,
                    base_url: str) -> dict[str, Any]:
        with self._lock:
            member = self._managed_for(slug, user_id).change_role(user_id, member_id, role)
            return member.row(base_url, manager=True)

    def remove_member(self, slug: str, user_id: int, member_id: str) -> dict[str, Any]:
        with self._lock:
            member = self._managed_for(slug, user_id).remove(user_id, member_id)
            return {"removed": True, "id": member.id}

    def _require_manager(self, slug: str, user_id: int, *, scenario_account: bool) -> None:
        role = self.caller_role(slug, user_id, scenario_account=scenario_account)
        if role is None:
            raise _not_found()
        if role not in MANAGERS:
            raise Refusal(403, "forbidden", "Only team owners and admins can manage this team.")

    def share_server(self, slug: str, user_id: int, body: dict[str, Any], *,
                     scenario_account: bool) -> dict[str, Any]:
        """``POST /api/v1/teams/{slug}/servers``: name and hostname required, both unique."""
        self._require_manager(slug, user_id, scenario_account=scenario_account)
        name, hostname, port = body.get("name"), body.get("hostname"), body.get("port", 22)
        if not all(isinstance(value, str) and value.strip() for value in (name, hostname)):
            raise Refusal(422, "validation_failed", "name and hostname are required.")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise Refusal(422, "validation_failed", "port must be between 1 and 65535.")
        name, hostname = str(name).strip(), str(hostname).strip()
        username = body.get("username") if isinstance(body.get("username"), str) else None
        with self._lock:
            rows = self._shared.setdefault(slug, [])
            if any(row.get("hostname") == hostname for row in rows):
                raise Refusal(409, "already_shared", "A server with this hostname is already shared.")
            if any(row.get("name") == name for row in rows):
                raise Refusal(409, "already_shared", "A server with this name is already shared.")
            row = {
                "id": str(uuid.uuid4()), "name": name, "hostname": hostname, "port": port,
                "login_user": username, "username": username,
                "instance_id": body.get("instance_id"), "region": body.get("region"),
                "tags": body.get("tags") if isinstance(body.get("tags"), list) else [],
                "status": "active", "shared_by_user_id": user_id,
                "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            }
            rows.append(row)
            return copy.deepcopy(row)

    def unshare_server(self, slug: str, user_id: int, name: str, *, scenario_account: bool) -> dict[str, Any]:
        """``DELETE /api/v1/teams/{slug}/servers/{name}``."""
        self._require_manager(slug, user_id, scenario_account=scenario_account)
        with self._lock:
            rows = self._shared.get(slug, [])
            row = next((r for r in rows if r.get("name") == name), None)
            if row is None:
                raise Refusal(404, "not_found", "Shared server not found.")
            rows.remove(row)
            return {"deleted": True, "name": name}

    def report_team_verify(self, slug: str, user_id: int, server_id: str, body: dict[str, Any], *,
                           scenario_account: bool) -> dict[str, Any]:
        """``POST …/servers/{server_id}/ssh-verify-report`` from a member who connected."""
        if self.caller_role(slug, user_id, scenario_account=scenario_account) is None:
            raise _not_found()
        if not any(str(row.get("id")) == server_id for row in self.shared_servers(slug)):
            raise Refusal(404, "not_found", "Shared server not found.")
        status = body.get("status")
        if status not in VERIFY_STATUSES:
            raise Refusal(422, "validation_failed", f"status must be one of {sorted(VERIFY_STATUSES)}")
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        row = {
            "server_id": server_id, "ssh_verify_status": status,
            # The service only keeps a timestamp for a verified key.
            "ssh_verified_at": now if status == "verified" else None,
            "checked_by_client": body.get("checked_by_client"),
            "resolution_tier": body.get("resolution_tier"), "updated_at": now,
        }
        with self._lock:
            self._team_verify[(slug, server_id)] = row
            return dict(row)

    def team_verify(self, slug: str, user_id: int, server_id: str, *, scenario_account: bool) -> dict[str, Any]:
        """``GET …/servers/{server_id}/ssh-verify-status`` (any member reads)."""
        if self.caller_role(slug, user_id, scenario_account=scenario_account) is None:
            raise _not_found()
        with self._lock:
            row = self._team_verify.get((slug, server_id))
        if row is None:
            raise Refusal(404, "not_found", "No SSH verification recorded for this server.")
        return dict(row)

    def team_configs(self, slug: str, user_id: int, *, scenario_account: bool) -> list[dict[str, Any]]:
        """Every shared-config version of *slug*, latest first (any member reads)."""
        if self.caller_role(slug, user_id, scenario_account=scenario_account) is None:
            raise _not_found()
        with self._lock:
            return copy.deepcopy(list(reversed(self._configs.get(slug, []))))

    def push_team_config(self, slug: str, user_id: int, body: dict[str, Any], *,
                         scenario_account: bool) -> dict[str, Any]:
        """A new shared-config version (owners and admins only)."""
        self._require_manager(slug, user_id, scenario_account=scenario_account)
        if not isinstance(body.get("config_data"), dict):
            raise Refusal(400, "validation_failed", "config_data must be an object.")
        with self._lock:
            versions = self._configs.setdefault(slug, [])
            row = {
                "id": len(versions) + 1, "version": len(versions) + 1,
                "config_data": copy.deepcopy(body["config_data"]),
                "description": body.get("description") if isinstance(body.get("description"), str) else None,
                "pushed_by": user_id, "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            }
            versions.append(row)
            return copy.deepcopy(row)

    def verify_rows(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self._verify.values()]

    def verify_row(self, provider: str, instance_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._verify.get((provider, instance_id))
            return dict(row) if row else None


def add_routes(
    app: web.Application,
    store: ScenarioStore,
    data: AccountData,
    ssh_ca: Optional[Callable[[str, str], Optional[dict[str, Any]]]] = None,
    base_url: Callable[[], str] = lambda: "",
) -> None:
    """Register the account data routes on *app*.

    *ssh_ca* answers a shared server's ``ssh_ca`` field from the team's SSH
    CA state; without it every row says ``null`` (no CA). *base_url* is
    where invitation accept URLs point.
    """

    def guarded(handler: Any) -> Any:
        async def wrapper(request: web.Request) -> web.StreamResponse:
            if not bearer_ok(request, store):
                return unauthorized()
            return await handler(request)

        return wrapper

    def caller() -> tuple[int, bool]:
        """The requesting user's id, and whether they are the scenario's account."""
        return store.snapshot().user_id, current_account() is None

    def answer(change: Callable[[], dict[str, Any]], status: int = 200) -> web.Response:
        try:
            return web.json_response(change(), status=status)
        except Refusal as refusal:
            return web.json_response(refusal.body(), status=refusal.status)

    async def list_teams(request: web.Request) -> web.Response:
        user_id, scenario_account = caller()
        return web.json_response({"teams": data.teams_for(user_id, scenario_account=scenario_account)})

    async def create_team(request: web.Request) -> web.Response:
        user_id, scenario_account = caller()
        account = current_account()
        body = await json_body(request)
        return answer(lambda: data.create_team_as(
            user_id, name=body.get("name"), plan=store.snapshot().plan, scenario_account=scenario_account,
            email=account.email if account else SCENARIO_ACCOUNT_EMAIL,
            person=account.name if account else SCENARIO_ACCOUNT_NAME,
        ), status=201)

    async def team_detail(request: web.Request) -> web.Response:
        user_id, scenario_account = caller()
        team = data.team_detail(request.match_info["slug"], user_id, scenario_account=scenario_account,
                                base_url=base_url())
        if team is None:
            return web.json_response({"error": {"code": "not_found"}}, status=404)
        return web.json_response(team)

    async def invite(request: web.Request) -> web.Response:
        user_id, _ = caller()
        body = await json_body(request)
        return answer(lambda: data.invite(
            request.match_info["slug"], user_id, body.get("email"), body.get("role", "member"), base_url(),
        ), status=201)

    async def resend(request: web.Request) -> web.Response:
        user_id, _ = caller()
        return answer(lambda: data.resend(
            request.match_info["slug"], user_id, request.match_info["member_id"], base_url(),
        ))

    async def change_role(request: web.Request) -> web.Response:
        user_id, _ = caller()
        body = await json_body(request)
        return answer(lambda: data.change_role(
            request.match_info["slug"], user_id, request.match_info["member_id"], body.get("role"), base_url(),
        ))

    async def remove_member(request: web.Request) -> web.Response:
        user_id, _ = caller()
        return answer(lambda: data.remove_member(
            request.match_info["slug"], user_id, request.match_info["member_id"],
        ))

    async def share_server(request: web.Request) -> web.Response:
        user_id, scenario_account = caller()
        body = await json_body(request)
        return answer(lambda: data.share_server(
            request.match_info["slug"], user_id, body, scenario_account=scenario_account,
        ), status=201)

    async def unshare_server(request: web.Request) -> web.Response:
        user_id, scenario_account = caller()
        return answer(lambda: data.unshare_server(
            request.match_info["slug"], user_id, request.match_info["name"], scenario_account=scenario_account,
        ))

    async def team_verify_report(request: web.Request) -> web.Response:
        user_id, scenario_account = caller()
        body = await json_body(request)
        return answer(lambda: data.report_team_verify(
            request.match_info["slug"], user_id, request.match_info["server_id"], body,
            scenario_account=scenario_account,
        ))

    async def team_verify_status(request: web.Request) -> web.Response:
        user_id, scenario_account = caller()
        return answer(lambda: data.team_verify(
            request.match_info["slug"], user_id, request.match_info["server_id"],
            scenario_account=scenario_account,
        ))

    async def team_configs(request: web.Request) -> web.Response:
        user_id, scenario_account = caller()
        return answer(lambda: {"data": data.team_configs(
            request.match_info["slug"], user_id, scenario_account=scenario_account,
        )})

    async def latest_team_config(request: web.Request) -> web.Response:
        user_id, scenario_account = caller()
        try:
            versions = data.team_configs(request.match_info["slug"], user_id, scenario_account=scenario_account)
        except Refusal as refusal:
            return web.json_response(refusal.body(), status=refusal.status)
        if not versions:
            return web.json_response({"error": "No configuration found"}, status=404)
        return web.json_response({"data": versions[0]})

    async def push_team_config(request: web.Request) -> web.Response:
        user_id, scenario_account = caller()
        body = await json_body(request)
        return answer(lambda: {"data": data.push_team_config(
            request.match_info["slug"], user_id, body, scenario_account=scenario_account,
        )}, status=201)

    async def invitation_page(request: web.Request) -> web.Response:
        return web.Response(text="FakeCloud team invitation page", content_type="text/plain")

    async def team_servers(request: web.Request) -> web.Response:
        slug = request.match_info["slug"]
        user_id, scenario_account = caller()
        if data.caller_role(slug, user_id, scenario_account=scenario_account) is None:
            return web.json_response({"error": {"code": "not_found"}}, status=404)
        # The team inventory API uses account authentication; native-vault
        # mutations against a selected server are separately device-signed.
        servers = data.shared_servers(slug)
        for row in servers:
            row["ssh_ca"] = ssh_ca(slug, str(row.get("id"))) if ssh_ca is not None else None
        return web.json_response({"data": servers})

    async def verify_list(request: web.Request) -> web.Response:
        return web.json_response({"instances": data.verify_rows()})

    async def verify_status(request: web.Request) -> web.Response:
        row = data.verify_row(request.match_info["provider"], request.match_info["instance_id"])
        if row is None:
            return web.json_response({"error": {"code": "not_found"}}, status=404)
        return web.json_response(row)

    async def verify_report(request: web.Request) -> web.Response:
        provider = request.match_info["provider"]
        instance_id = request.match_info["instance_id"]
        body = await json_body(request)
        try:
            data.set_verify_status(provider, instance_id, str(body.get("status")))
        except ValueError as exc:
            return validation_failed(str(exc))
        return web.json_response(data.verify_row(provider, instance_id))

    instance = "/api/v1/me/instances/{provider}/{instance_id}"
    team = "/api/v1/teams/{slug}"
    member = f"{team}/members/{{member_id}}"
    app.router.add_get("/api/v1/teams", guarded(list_teams))
    app.router.add_post("/api/v1/teams", guarded(create_team))
    app.router.add_get(f"{team}/servers", guarded(team_servers))
    app.router.add_post(f"{team}/servers", guarded(share_server))
    app.router.add_delete(f"{team}/servers/{{name}}", guarded(unshare_server))
    app.router.add_post(f"{team}/servers/{{server_id}}/ssh-verify-report", guarded(team_verify_report))
    app.router.add_get(f"{team}/servers/{{server_id}}/ssh-verify-status", guarded(team_verify_status))
    app.router.add_post(f"{team}/members", guarded(invite))
    app.router.add_put(member, guarded(change_role))
    app.router.add_delete(member, guarded(remove_member))
    app.router.add_post(f"{member}/resend", guarded(resend))
    app.router.add_get(f"{team}/configs", guarded(team_configs))
    app.router.add_get(f"{team}/configs/latest", guarded(latest_team_config))
    app.router.add_post(f"{team}/configs", guarded(push_team_config))
    app.router.add_get(team, guarded(team_detail))
    app.router.add_get(f"{INVITE_PATH}/{{token}}", invitation_page)
    app.router.add_get("/api/v1/me/instances", guarded(verify_list))
    app.router.add_get(f"{instance}/ssh-verify-status", guarded(verify_status))
    app.router.add_post(f"{instance}/ssh-verify-report", guarded(verify_report))
