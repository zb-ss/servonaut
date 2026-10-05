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
from textual.app import App
from textual.widgets import Button

from servonaut.config.schema import AIProviderConfig
from servonaut.services.ai_balance import AITopupPack
from servonaut.services.ai_providers import ServonautProvider
from servonaut.services.ai_providers.servonaut_provider import (
    is_valid_stripe_checkout_url,
)
from servonaut.services.api_client import APIClient
from servonaut.services.auth_service import AuthService, AuthToken
from servonaut.styles import CSS_FILES


def run(coro):
    return asyncio.run(coro)


class _TopupModalApp(App):
    """Mount the real modal with the production stylesheet."""

    CSS_PATH = CSS_FILES

    def __init__(
        self,
        packs,
        *,
        reason: str = "",
        show_billing_action: bool = False,
    ) -> None:
        super().__init__()
        self._packs = packs
        self._reason = reason
        self._show_billing_action = show_billing_action
        self.dismissed: list[str | None] = []

    def on_mount(self) -> None:
        from servonaut.screens.ai_topup_modal import AITopUpModal

        self.push_screen(
            AITopUpModal(
                packs=self._packs,
                reason=self._reason,
                show_billing_action=self._show_billing_action,
            ),
            callback=self.dismissed.append,
        )


def _rendered_screen_text(app) -> str:
    """Return the compositor output, which excludes clipped widget lines."""
    import io

    from rich.console import Console

    update = app.screen._compositor.render_update(
        full=True, screen_stack=app._background_screens, simplify=True,
    )
    console = Console(
        width=app.size.width,
        height=app.size.height,
        file=io.StringIO(),
        force_terminal=True,
        color_system="truecolor",
        record=True,
        legacy_windows=False,
        safe_box=False,
    )
    console.print(update)
    return console.export_text()


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


@pytest.mark.parametrize("bad_pack", ["", " small ", None])
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


def test_topup_modal_cancel_button_dismisses_without_selecting_a_pack():
    """The visible Cancel button follows the same path as Escape."""
    from types import SimpleNamespace

    from servonaut.screens.ai_topup_modal import AITopUpModal

    modal = AITopUpModal()
    modal.dismiss = MagicMock()
    modal.on_button_pressed(SimpleNamespace(button=SimpleNamespace(id="btn_topup_cancel")))

    modal.dismiss.assert_called_once_with(None)


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
        "https://user:pass@checkout.stripe.com/pay/cs_test",  # leak-guard:allow
        "https://checkout.stripe.com:443/pay/cs_test",
        "https://checkout.stripe.com/pay/cs_test\x1b]52;unsafe\x07\x9b",
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
    provider.topup_packs = AsyncMock(return_value=[
        type("Pack", (), {"key": "small", "label": "Small", "display_price": ""})(),
    ])

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

    assert rc == 1
    # Critical: the browser was NEVER opened with the malicious URL.
    assert opened == [], (
        f"Non-Stripe URL leaked through to webbrowser.open: {opened!r}"
    )
    captured = capsys.readouterr()
    assert "invalid Stripe checkout URL" in captured.err
    assert "https://evil.example/login" not in captured.err


def test_topup_modal_scrubs_catalog_controls_before_markup_rendering():
    from servonaut.screens.ai_topup_modal import AITopUpModal

    pack = AITopupPack(
        key="starter",
        label="追加\x1b]52;label\x07\x9b",
        currency="GBP",
        display_price="£5\x1b]52;price\x07",
        display_credit="£5\x9b",
    )

    catalog = AITopUpModal._catalog_text([pack])

    assert "追加]52;label" in catalog
    assert "£5]52;price" in catalog
    assert "adds £5" in catalog
    assert "\x1b" not in catalog
    assert "\x07" not in catalog
    assert "\x9b" not in catalog


@pytest.mark.parametrize("size", [(100, 30), (160, 37), (160, 50)])
@pytest.mark.asyncio
async def test_topup_catalog_prices_and_credit_are_visibly_rendered(size):
    """Price and credit live in a visible catalog, not clipped button labels."""
    packs = [
        AITopupPack("starter", "Starter", "GBP", "£5.00", "£5.00"),
        AITopupPack("extended", "Extended", "GBP", "£20.00", "£20.00"),
    ]
    app = _TopupModalApp(packs, reason="Your AI balance is used up. Top up to keep going.")

    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        container = app.screen.query_one("#ai_topup_container")
        catalog = app.screen.query_one("#ai_topup_catalog")
        assert container.region.height <= 24
        assert catalog.region.height >= len(packs)
        # Let Textual finish the catalog layout before capturing the viewport.
        await asyncio.sleep(0.1)
        rendered = _rendered_screen_text(app)
        screenshot = app.export_screenshot(title="top-up catalog visibility")

    assert "Cancel" in rendered
    for amount in ("£5.00", "£20.00"):
        assert amount in rendered
        assert amount in screenshot


@pytest.mark.asyncio
async def test_topup_cancel_is_painted_and_clickable_with_billing_action():
    """Billing stays reachable through the catalog without covering Cancel."""
    app = _TopupModalApp(
        [
            AITopupPack("starter", "Starter", "GBP", "£5", "£5.00"),
            AITopupPack("extended", "Extended", "GBP", "£20", "£20.00"),
        ],
        reason="Your AI balance is used up. Top up to keep going.",
        show_billing_action=True,
    )

    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        await asyncio.sleep(0.1)
        cancel = app.screen.query_one("#btn_topup_cancel", Button)
        region = cancel.region
        hit, _ = app.get_widget_at(
            region.x + region.width // 2,
            region.y + region.height // 2,
        )
        assert hit is cancel
        assert _rendered_screen_text(app).count("Cancel") >= 2
        assert await pilot.click(
            cancel,
            offset=(region.width // 2, region.height // 2),
        )
        await pilot.pause()

    assert app.dismissed == [None]


@pytest.mark.asyncio
async def test_topup_catalog_scrolls_to_every_runtime_pack_with_cancel_pinned():
    """A long server catalog scrolls to its final action without hiding Cancel."""
    packs = [
        AITopupPack(
            f"pack-{number}", f"Pack {number}", "GBP",
            f"£{number}.00", f"£{number}.00",
        )
        for number in range(1, 21)
    ]
    app = _TopupModalApp(packs, reason="Your AI balance is used up. Top up to keep going.")

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        catalog = app.screen.query_one("#ai_topup_catalog")
        container = app.screen.query_one("#ai_topup_container")
        cancel = app.screen.query_one("#btn_topup_cancel", Button)
        first = app.screen.query_one("#btn_topup_0", Button)
        last = app.screen.query_one("#btn_topup_19", Button)
        assert len(list(catalog.query(Button))) == len(packs)
        assert catalog.virtual_size.height > catalog.size.height
        assert cancel.region.bottom <= container.region.bottom
        await asyncio.sleep(0.1)

        app.screen.set_focus(first)
        for _ in range(len(packs) - 1):
            await pilot.press("tab")
        await pilot.pause()

        assert app.focused is last
        assert catalog.scroll_y > 0
        assert cancel.region.bottom <= container.region.bottom
        assert last.region.y >= catalog.region.y
        assert last.region.bottom <= catalog.region.bottom
        await pilot.press("enter")
        await pilot.pause()

    assert app.dismissed == ["pack-20"]



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
