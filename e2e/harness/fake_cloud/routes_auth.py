"""Account routes: OAuth device flow, token refresh/revoke, entitlements.

Refresh rotates the pair and retires the refresh token presented (see
``session.TokenSession``); protected routes accept only the current,
unexpired access token.
"""

from __future__ import annotations

from typing import Any, Callable

from aiohttp import web

from e2e.harness.fake_cloud.state import USER_CODE, ScenarioStore


def bearer_ok(request: web.Request, store: ScenarioStore) -> bool:
    """True when the request carries the account's current access token."""
    return store.session.bearer_valid(request.headers.get("Authorization"))


def unauthorized() -> web.Response:
    return web.json_response({"error": "unauthorized"}, status=401)


def entitlements_payload(store: ScenarioStore) -> dict[str, Any]:
    """The ``/api/entitlements`` document for the current scenario."""
    scenario = store.snapshot()
    return {
        "plan": scenario.plan,
        "user_id": scenario.user_id,
        "email": "",
        "premium_ai": scenario.premium_ai,
        "mcp_connections": scenario.mcp_connections,
        "quota": scenario.quota,
    }


def _token_payload(store: ScenarioStore, pair: tuple[str, str]) -> dict[str, Any]:
    scenario = store.snapshot()
    access, refresh = pair
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": 3600,
        "plan": scenario.plan,
        "user_id": scenario.user_id,
        "email": "",
    }


def add_routes(
    app: web.Application, store: ScenarioStore, base_url: Callable[[], str]
) -> None:
    """Register the account routes on *app*."""

    async def device(request: web.Request) -> web.Response:
        scenario = store.snapshot()
        verification = f"{base_url()}/device"
        return web.json_response(
            {
                "device_code": store.next_device_code(),
                "user_code": USER_CODE,
                "verification_uri": verification,
                "verification_uri_complete": f"{verification}?user_code={USER_CODE}",
                "interval": scenario.device_interval,
                "expires_in": scenario.device_expires_in,
            }
        )

    async def token(request: web.Request) -> web.Response:
        outcome = store.next_token_outcome()
        if outcome == "pending":
            return web.json_response({"error": "authorization_pending"}, status=400)
        if outcome == "slow_down":
            return web.json_response({"error": "slow_down"}, status=400)
        if outcome == "expired":
            return web.json_response({"error": "expired_token"}, status=410)
        if outcome == "denied":
            return web.json_response({"error": "access_denied"}, status=400)
        return web.json_response(_token_payload(store, store.session.issue_login()))

    async def refresh(request: web.Request) -> web.Response:
        body = await _json_body(request)
        pair = store.session.rotate(body.get("refresh_token"))
        if pair is None:
            return web.json_response({"error": "invalid_grant"}, status=400)
        return web.json_response(_token_payload(store, pair))

    async def revoke(request: web.Request) -> web.Response:
        body = await _json_body(request)
        store.session.revoke_token(body.get("token"))
        return web.json_response({"revoked": True})

    async def entitlements(request: web.Request) -> web.Response:
        if not bearer_ok(request, store):
            return unauthorized()
        return web.json_response(entitlements_payload(store))

    async def me(request: web.Request) -> web.Response:
        if not bearer_ok(request, store):
            return unauthorized()
        return web.json_response({"user_id": store.snapshot().user_id})

    async def verification_page(request: web.Request) -> web.Response:
        return web.Response(text="FakeCloud device verification page", content_type="text/plain")

    app.router.add_post("/api/oauth/device", device)
    app.router.add_post("/api/oauth/token", token)
    app.router.add_post("/api/oauth/refresh", refresh)
    app.router.add_post("/api/oauth/revoke", revoke)
    app.router.add_get("/api/entitlements", entitlements)
    app.router.add_get("/api/v1/me", me)
    app.router.add_get("/device", verification_page)


async def _json_body(request: web.Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}
