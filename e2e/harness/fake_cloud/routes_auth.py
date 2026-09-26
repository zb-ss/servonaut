"""Account routes: OAuth device flow, token refresh/revoke, entitlements."""

from __future__ import annotations

from typing import Any, Callable

from aiohttp import web

from e2e.harness.fake_cloud.state import (
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    USER_CODE,
    ScenarioStore,
)


def _bearer_ok(request: web.Request) -> bool:
    return request.headers.get("Authorization", "") == f"Bearer {ACCESS_TOKEN}"


def _token_payload(store: ScenarioStore) -> dict[str, Any]:
    scenario = store.snapshot()
    return {
        "access_token": ACCESS_TOKEN,
        "refresh_token": REFRESH_TOKEN,
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
        return web.json_response(_token_payload(store))

    async def refresh(request: web.Request) -> web.Response:
        return web.json_response(_token_payload(store))

    async def revoke(request: web.Request) -> web.Response:
        return web.json_response({"revoked": True})

    async def entitlements(request: web.Request) -> web.Response:
        if not _bearer_ok(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        scenario = store.snapshot()
        return web.json_response(
            {
                "plan": scenario.plan,
                "user_id": scenario.user_id,
                "email": "",
                "premium_ai": scenario.premium_ai,
                "quota": scenario.quota,
            }
        )

    async def me(request: web.Request) -> web.Response:
        if not _bearer_ok(request):
            return web.json_response({"error": "unauthorized"}, status=401)
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
