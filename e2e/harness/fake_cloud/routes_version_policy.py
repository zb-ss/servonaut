"""Client version policy endpoint and HTTP 426 enforcement gate.

Serves ``GET /api/v1/client/version-policy`` (unauthenticated, cacheable) and
applies the configured minimum version to the phase-one API prefixes.
"""

from __future__ import annotations

import copy
from typing import Any, Optional

from aiohttp import web

from e2e.harness.fake_cloud.state import Scenario, ScenarioStore
from servonaut.services.version_policy import (
    DEFAULT_UPDATE_URL,
    VERSION_POLICY_PATH,
    is_version_allowed,
    parse_client_signal,
    parse_contract_version,
)

BELOW_MINIMUM = web.RequestKey("below_minimum", bool)

_GATED_PREFIXES = (
    "/api/v1/teams/",
    "/api/v1/vault/",
    "/api/v1/vaults",
    "/api/v1/me/instances/",
    "/api/v1/me/credential-bindings",
    "/api/ai/",
    "/api/v1/findings",
    "/api/v1/ssh-ca/",
    "/api/v1/memory",
    "/api/cli/",
)
_NEVER_GATED_PATHS = frozenset({
    "/api/cli/status",
    "/api/entitlements",
    "/api/v1/me",
    "/api/v1/health",
    "/api/bug-report",
    VERSION_POLICY_PATH,
})

DEFAULT_UPDATE_HINTS: dict[str, str] = {
    "pipx": "pipx upgrade servonaut",
    "pip": "pip install --upgrade servonaut",
    "apt": "sudo apt update && sudo apt install --only-upgrade servonaut",
    "desktop": DEFAULT_UPDATE_URL,
}


def is_gated_path(path: str) -> bool:
    """Match the phase-one gated prefixes and exact route exceptions."""
    if path in _NEVER_GATED_PATHS or path.startswith("/api/oauth/"):
        return False
    return path.startswith(_GATED_PREFIXES)


def _latest_versions(scenario: Scenario) -> dict[str, Optional[str]]:
    if scenario.client_latest is not None:
        return scenario.client_latest
    version = parse_contract_version(scenario.pypi_version)
    if version is None:
        return {"stable": None, "rc": None}
    if version.is_prerelease:
        return {"stable": None, "rc": version.text}
    return {"stable": version.text, "rc": None}


def policy_payload(store: ScenarioStore) -> dict[str, Any]:
    """Build the ``GET /api/v1/client/version-policy`` document for the active scenario."""
    scenario = store.snapshot()
    hints = (
        dict(scenario.client_update_hints)
        if scenario.client_update_hints is not None
        else dict(DEFAULT_UPDATE_HINTS)
    )
    return {
        "mode": scenario.client_version_mode,
        "minimum_version": scenario.client_minimum_version,
        "upcoming": copy.deepcopy(scenario.client_upcoming),
        "latest": _latest_versions(scenario),
        "update_url": scenario.client_update_url,
        "update_hints": hints,
    }


def check_client_version(request: web.Request, store: ScenarioStore) -> Optional[web.Response]:
    """Mark a log-mode violation or return the enforce-mode refusal."""
    if not is_gated_path(request.path):
        return None
    scenario = store.snapshot()
    mode = scenario.client_version_mode
    minimum_version = scenario.client_minimum_version
    if mode not in ("log", "enforce") or not minimum_version:
        return None

    client_version, channel, _kind = parse_client_signal(
        request.headers.get("X-Servonaut-Client"),
        request.headers.get("User-Agent"),
    )
    if is_version_allowed(client_version, minimum_version):
        return None
    if mode == "log":
        request[BELOW_MINIMUM] = True
        return None

    update_url = scenario.client_update_url
    return web.json_response(
        {
            "error": {
                "code": "client_update_required",
                "http": 426,
                "message": (
                    f"This version of Servonaut ({client_version}) is too old for team and cloud features. "
                    f"Update to {minimum_version} or later: {update_url}"
                ),
                "details": {
                    "client_version": client_version,
                    "minimum_version": minimum_version,
                    "latest_version": _latest_versions(scenario).get("stable"),
                    "channel": channel or "stable",
                    "update_url": update_url,
                },
                "retry_after_seconds": None,
            }
        },
        status=426,
        headers={
            "Upgrade": f"servonaut/{minimum_version}",
            "Cache-Control": "no-store",
        },
    )


def add_routes(app: web.Application, store: ScenarioStore) -> None:
    """Register the public version-policy endpoint on *app*."""

    async def version_policy(_request: web.Request) -> web.Response:
        return web.json_response(
            policy_payload(store),
            headers={"Cache-Control": "public, max-age=300"},
        )

    app.router.add_get(VERSION_POLICY_PATH, version_policy)
