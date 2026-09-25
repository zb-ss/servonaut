"""Account data routes: teams and the SSH-verify sidecar.

The data is neutral and scenario-driven through :class:`AccountData`
(``FakeCloud.account``). Every route needs the current access token, so a
client with an expired token has to refresh before it sees anything.
"""

from __future__ import annotations

import copy
import datetime as dt
import threading
from typing import Any, Optional

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


class AccountData:
    """Thread-safe account records the routes serve."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._teams = copy.deepcopy(list(_DEFAULT_TEAMS))
            self._verify: dict[tuple[str, str], dict[str, Any]] = {}

    def configure(self, *, teams: Optional[list[dict[str, Any]]] = None) -> None:
        with self._lock:
            if teams is not None:
                self._teams = copy.deepcopy(teams)

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


def add_routes(app: web.Application, store: ScenarioStore, data: AccountData) -> None:
    """Register the account data routes on *app*."""

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
    app.router.add_get("/api/v1/teams/{slug}", guarded(team_detail))
    app.router.add_get("/api/v1/me/instances", guarded(verify_list))
    app.router.add_get(f"{instance}/ssh-verify-status", guarded(verify_status))
    app.router.add_post(f"{instance}/ssh-verify-report", guarded(verify_report))
