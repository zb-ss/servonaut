"""Tests for the T8 top-up flow.

Covers:
1. ``ServonautProvider.topup_checkout`` rejects invalid pack names.
2. ``topup_checkout`` returns the URL for valid packs.
3. ``AuthService.schedule_post_topup_refresh`` schedules two delayed
   refreshes (30s, 60s) tracked in ``_post_topup_tasks``.

The schedule test uses ``asyncio.sleep(0)`` to yield control once so
``create_task`` actually runs the task into its first ``await
asyncio.sleep`` — that's enough to confirm the tasks were created and
tracked, without waiting 30+ seconds in the test suite.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import AIProviderConfig
from servonaut.services.ai_providers import ServonautProvider
from servonaut.services.ai_providers.servonaut_provider import (
    is_valid_stripe_checkout_url,
)
from servonaut.services.api_client import APIClient
from servonaut.services.auth_service import AuthService, AuthToken


def run(coro):
    return asyncio.run(coro)


def _make_provider(*, post_response=None) -> tuple[ServonautProvider, MagicMock]:
    api = MagicMock(spec=APIClient)
    api.post = AsyncMock(
        return_value=post_response if post_response is not None
        else {"checkout_url": "https://checkout.stripe.com/abc"}
    )
    auth = MagicMock()
    auth.is_authenticated = True
    auth.has_feature = MagicMock(return_value=True)
    return ServonautProvider(api_client=api, auth_service=auth), api


# ---------------------------------------------------------------------------
# 1. Invalid pack rejection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_pack", ["", "huge", "premium", "small_extra", " small "])
def test_topup_checkout_invalid_pack_raises(bad_pack):
    provider, _ = _make_provider()
    with pytest.raises(ValueError):
        run(provider.topup_checkout(bad_pack))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 2. Valid pack returns the URL
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pack", ["small", "medium", "large"])
def test_topup_checkout_returns_url_for_valid_pack(pack):
    provider, api = _make_provider(
        post_response={"checkout_url": f"https://checkout.stripe.com/{pack}"},
    )
    url = run(provider.topup_checkout(pack))  # type: ignore[arg-type]
    assert url == f"https://checkout.stripe.com/{pack}"
    api.post.assert_awaited_once_with("/api/ai/topup/checkout", json={"pack": pack})


def test_topup_checkout_raises_runtime_error_when_url_missing():
    provider, _ = _make_provider(post_response={})
    with pytest.raises(RuntimeError):
        run(provider.topup_checkout("small"))


def test_topup_checkout_raises_runtime_error_when_url_empty():
    provider, _ = _make_provider(post_response={"checkout_url": ""})
    with pytest.raises(RuntimeError):
        run(provider.topup_checkout("medium"))


# ---------------------------------------------------------------------------
# 3. schedule_post_topup_refresh creates two tracked tasks
# ---------------------------------------------------------------------------


def test_post_topup_refresh_schedules_two_tracked_tasks():
    """``schedule_post_topup_refresh`` must create exactly two asyncio tasks
    and store them on a per-instance set so the GC doesn't collect them
    mid-flight."""

    async def _exercise() -> set:
        # Fresh AuthService — _load_token is a no-op without a file.
        # Build a logged-in token so fetch_entitlements gets called
        # (we still mock it).
        auth = AuthService.__new__(AuthService)
        # Bypass __init__ so we don't touch the real ~/.servonaut/auth.json.
        auth._token = AuthToken(
            access_token="fake",
            refresh_token="fake_refresh",
            expires_at=2 ** 31,  # ~2038
            plan="solo",
        )
        auth.fetch_entitlements = AsyncMock(return_value=None)  # type: ignore[method-assign]

        await auth.schedule_post_topup_refresh()

        # Yield once so the create_task closures actually start (each
        # one awaits asyncio.sleep right away — they don't complete in
        # this tick).
        await asyncio.sleep(0)
        return set(auth._post_topup_tasks)

    tasks = run(_exercise())
    # Two delayed refreshes (30s + 60s).
    assert len(tasks) == 2
    # Each is a still-running asyncio.Task on the schedule_post_topup_refresh
    # event loop. We asserted creation; the asyncio.sleep(30/60) inside
    # them is far longer than this test runs.
    for t in tasks:
        assert isinstance(t, asyncio.Task)


# ---------------------------------------------------------------------------
# A4 — Stripe URL validation + CLI rejects non-Stripe URLs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://checkout.stripe.com/pay/cs_test_abc",
        "https://checkout.stripe.com/c/pay/foo",
    ],
)
def test_is_valid_stripe_checkout_url_accepts_stripe_origins(url):
    assert is_valid_stripe_checkout_url(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/login",
        "http://checkout.stripe.com/pay/spoof",  # http not https
        "https://checkout.stripe.com.evil.example/pay",  # subdomain spoof
        "https://checkout-stripe.com/pay/foo",  # typosquat
        "",
        None,
    ],
)
def test_is_valid_stripe_checkout_url_rejects_non_stripe(url):
    assert is_valid_stripe_checkout_url(url) is False  # type: ignore[arg-type]


def test_topup_rejects_non_stripe_url(monkeypatch, capsys):
    """A4 — ``servonaut ai topup`` does NOT auto-launch a non-Stripe URL.

    Drives the CLI handler with a provider mock that returns a
    ``https://evil.example/login`` checkout_url and asserts:

    1. ``webbrowser.open`` is NOT called.
    2. The user-facing message tells them to open it manually.
    """
    from unittest.mock import AsyncMock, MagicMock

    from servonaut.cli import ai as cli_ai
    from servonaut.services.api_client import APIClient

    auth = MagicMock()
    auth.is_authenticated = True
    auth.has_feature = MagicMock(return_value=True)
    auth.fetch_entitlements = AsyncMock(return_value=None)
    auth.await_post_topup_refresh = AsyncMock(return_value=None)
    auth._token = MagicMock()
    auth._token.entitlements = {}

    api_client = MagicMock(spec=APIClient)
    api_client.post = AsyncMock()

    provider = MagicMock()
    provider.topup_checkout = AsyncMock(
        return_value="https://evil.example/login",
    )

    convs = MagicMock()
    pref = MagicMock()
    config_manager = MagicMock()
    services = (config_manager, auth, api_client, provider, convs, pref)
    monkeypatch.setattr(cli_ai, "_init_headless_services", lambda: services)

    opened: list = []
    monkeypatch.setattr(
        cli_ai.webbrowser, "open",
        lambda url: (opened.append(url), True)[1],
    )

    import argparse
    args = argparse.Namespace(ai_command="topup", pack="small")
    rc = cli_ai.handle_ai_command(args)

    assert rc == 0
    # Critical: the browser was NEVER opened with the malicious URL.
    assert opened == [], (
        f"Non-Stripe URL leaked through to webbrowser.open: {opened!r}"
    )
    captured = capsys.readouterr()
    # User instructed to open manually — message visible on stderr.
    assert "manually" in captured.err.lower() or "manually" in captured.out.lower()


def test_post_topup_refresh_tasks_self_discard_on_completion():
    """When a delayed task completes, it removes itself from the tracking set.

    To exercise this without sleeping 30s we monkeypatch ``asyncio.sleep``
    inside the auth_service module to a no-op so the tasks finish
    immediately, then yield until the loop drains them.
    """
    import servonaut.services.auth_service as auth_module

    async def _exercise() -> int:
        auth = AuthService.__new__(AuthService)
        auth._token = AuthToken(
            access_token="fake",
            refresh_token="fake_refresh",
            expires_at=2 ** 31,
            plan="solo",
        )
        auth.fetch_entitlements = AsyncMock(return_value=None)  # type: ignore[method-assign]

        # Patch the module's asyncio reference to a near-instant sleep.
        original_sleep = auth_module.asyncio.sleep

        async def _instant_sleep(_delay):
            return await original_sleep(0)

        auth_module.asyncio.sleep = _instant_sleep  # type: ignore[assignment]
        try:
            await auth.schedule_post_topup_refresh()
            # Drain the loop a few times to let the tasks finish.
            for _ in range(5):
                await original_sleep(0)
            return len(auth._post_topup_tasks)
        finally:
            auth_module.asyncio.sleep = original_sleep  # type: ignore[assignment]

    leftover = run(_exercise())
    # Tasks self-discarded on completion → empty set.
    assert leftover == 0
