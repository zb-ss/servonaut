"""Account data routes: teams, their shared servers and the SSH-verify sidecar.

The data is neutral and scenario-driven through :class:`AccountData`
(``FakeCloud.account``). Every route needs the current access token, so a
client with an expired token has to refresh before it sees anything.
A shared-server row carries the team SSH CA's view of that server
(``ssh_ca``), which the Vault fake supplies.
"""

from __future__ import annotations

import copy
import datetime as dt
import threading
from typing import Any, Callable, Optional

from aiohttp import web

from e2e.harness.fake_cloud.routes_auth import (
    bearer_ok,
    json_body,
    unauthorized,
    validation_failed,
)
from e2e.harness.fake_cloud.state import ScenarioStore

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
        with self._lock:
            return copy.deepcopy(self._teams)

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
) -> None:
    """Register the account data routes on *app*.

    *ssh_ca* answers a shared server's ``ssh_ca`` field from the team's SSH
    CA state; without it every row says ``null`` (no CA).
    """

    def guarded(handler: Any) -> Any:
        async def wrapper(request: web.Request) -> web.StreamResponse:
            if not bearer_ok(request, store):
                return unauthorized()
            return await handler(request)

        return wrapper

    async def list_teams(request: web.Request) -> web.Response:
        return web.json_response({"teams": data.teams()})

    async def team_detail(request: web.Request) -> web.Response:
        slug = request.match_info["slug"]
        team = next((t for t in data.teams() if t.get("slug") == slug), None)
        if team is None:
            return web.json_response({"error": {"code": "not_found"}}, status=404)
        return web.json_response({**team, "members": team.get("members", [])})

    async def team_servers(request: web.Request) -> web.Response:
        slug = request.match_info["slug"]
        if not any(team.get("slug") == slug for team in data.teams()):
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
    app.router.add_get("/api/v1/teams", guarded(list_teams))
    app.router.add_get("/api/v1/teams/{slug}/servers", guarded(team_servers))
    app.router.add_get("/api/v1/teams/{slug}", guarded(team_detail))
    app.router.add_get("/api/v1/me/instances", guarded(verify_list))
    app.router.add_get(f"{instance}/ssh-verify-status", guarded(verify_status))
    app.router.add_post(f"{instance}/ssh-verify-report", guarded(verify_report))
