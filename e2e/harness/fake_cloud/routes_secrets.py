"""Secrets routes: where the secret store lives and which vault item holds a key.

This module owns:

* ``GET``/``PUT /api/v1/me/secrets-config``: the personal secret-store
  choice (``{provider, config, updated_at}``; 404 until one is saved);
* ``GET /api/v1/teams/{slug}/secrets-config``: a team's choice (404 unless
  a journey sets one);
* ``GET``/``PUT``/``DELETE /api/v1/me/instances/{provider}/{instance_id}/ssh-ref``:
  the Bitwarden item that holds an instance's SSH key.

Like the service, the secret-store config carries pointers only: a
``project_id`` and the *name* of the variable holding the access token. A
``PUT`` with any other key (a token value, say) is refused with 422, so a
client that tried to upload a credential would fail its journey. State lives
in :class:`SecretsData` (``FakeCloud.secrets``); every route needs the
current access token.
"""

from __future__ import annotations

import copy
import datetime as dt
import re
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

PERSONAL_PATH = "/api/v1/me/secrets-config"
SECRET_PROVIDERS = frozenset({"bitwarden", "local"})
# The only keys a secret-store config may carry: pointers, never values.
CONFIG_KEYS = frozenset({"project_id", "token_env_var"})
_TOKEN_VARIABLE = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
# The credential-provider value for a Bitwarden Password Manager item.
SSH_REF_PROVIDER = "bitwarden_pm"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _not_found() -> web.Response:
    return web.json_response(
        {"error": {"code": "not_found", "message": "No configuration on file"}}, status=404
    )


def config_problem(provider: object, config: object) -> Optional[str]:
    """Why the service would refuse this secret-store config, or None."""
    if provider not in SECRET_PROVIDERS:
        return f"provider must be one of {sorted(SECRET_PROVIDERS)}"
    if not isinstance(config, dict):
        return "config must be an object"
    extra = set(config) - CONFIG_KEYS
    if extra:
        return f"config may only contain {sorted(CONFIG_KEYS)}; got {sorted(extra)}"
    if provider == "bitwarden":
        if not isinstance(config.get("project_id"), str) or not config["project_id"]:
            return "config.project_id is required"
        if not _TOKEN_VARIABLE.match(str(config.get("token_env_var", ""))):
            return "config.token_env_var must be an environment variable name"
    return None


class SecretsData:
    """Thread-safe secret-store configs and SSH key references."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._personal: Optional[dict[str, Any]] = None
            self._teams: dict[str, dict[str, Any]] = {}
            self._refs: dict[tuple[str, str], dict[str, Any]] = {}

    def set_personal(self, provider: str, config: dict[str, Any]) -> dict[str, Any]:
        """Save the personal config (as a ``PUT`` from a client would)."""
        problem = config_problem(provider, config)
        if problem:
            raise ValueError(problem)
        with self._lock:
            created = self._personal is None
            self._personal = {
                "provider": provider,
                "config": copy.deepcopy(config),
                "updated_at": _now(),
            }
            return {**copy.deepcopy(self._personal), "created": created}

    def personal(self) -> Optional[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._personal)

    def set_team(self, slug: str, provider: str, config: dict[str, Any]) -> None:
        problem = config_problem(provider, config)
        if problem:
            raise ValueError(problem)
        with self._lock:
            self._teams[slug] = {
                "provider": provider,
                "config": copy.deepcopy(config),
                "updated_at": _now(),
                "team_slug": slug,
            }

    def team(self, slug: str) -> Optional[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._teams.get(slug))

    def set_ssh_ref(self, provider: str, instance_id: str, item_id: str) -> None:
        """Point an instance's SSH key at a Bitwarden item."""
        with self._lock:
            self._refs[(provider, instance_id)] = {
                "ssh_credential_provider": SSH_REF_PROVIDER,
                "ssh_credential_ref": {
                    "item_id": item_id,
                    "vault_url": None,
                    "collection_id": None,
                },
            }

    def ssh_ref(self, provider: str, instance_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._refs.get((provider, instance_id)))

    def delete_ssh_ref(self, provider: str, instance_id: str) -> bool:
        with self._lock:
            return self._refs.pop((provider, instance_id), None) is not None


def add_routes(app: web.Application, store: ScenarioStore, data: SecretsData) -> None:
    """Register the secrets routes on *app*."""

    def guarded(handler: Any) -> Any:
        async def wrapper(request: web.Request) -> web.StreamResponse:
            if not bearer_ok(request, store):
                return unauthorized()
            return await handler(request)

        return wrapper

    async def get_personal(request: web.Request) -> web.Response:
        body = data.personal()
        return web.json_response(body) if body else _not_found()

    async def put_personal(request: web.Request) -> web.Response:
        body = await json_body(request)
        try:
            saved = data.set_personal(body.get("provider"), body.get("config"))
        except ValueError as exc:
            return validation_failed(str(exc))
        return web.json_response(saved)

    async def get_team(request: web.Request) -> web.Response:
        body = data.team(request.match_info["slug"])
        return web.json_response(body) if body else _not_found()

    def _key(request: web.Request) -> tuple[str, str]:
        return request.match_info["provider"], request.match_info["instance_id"]

    async def get_ref(request: web.Request) -> web.Response:
        ref = data.ssh_ref(*_key(request))
        return web.json_response(ref) if ref else _not_found()

    async def put_ref(request: web.Request) -> web.Response:
        body = await json_body(request)
        ref = body.get("ssh_credential_ref")
        if body.get("ssh_credential_provider") != SSH_REF_PROVIDER or not isinstance(ref, dict):
            return validation_failed(f"a {SSH_REF_PROVIDER} ssh_credential_ref is required")
        if not isinstance(ref.get("item_id"), str) or not ref["item_id"]:
            return validation_failed("ssh_credential_ref.item_id is required")
        data.set_ssh_ref(*_key(request), ref["item_id"])
        return web.json_response(data.ssh_ref(*_key(request)))

    async def delete_ref(request: web.Request) -> web.Response:
        if not data.delete_ssh_ref(*_key(request)):
            return _not_found()
        return web.Response(status=204)

    ref_path = "/api/v1/me/instances/{provider}/{instance_id}/ssh-ref"
    app.router.add_get(PERSONAL_PATH, guarded(get_personal))
    app.router.add_put(PERSONAL_PATH, guarded(put_personal))
    app.router.add_get("/api/v1/teams/{slug}/secrets-config", guarded(get_team))
    app.router.add_get(ref_path, guarded(get_ref))
    app.router.add_put(ref_path, guarded(put_ref))
    app.router.add_delete(ref_path, guarded(delete_ref))
