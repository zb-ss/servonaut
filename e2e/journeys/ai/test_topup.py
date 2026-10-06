"""Journey: run out of tokens mid-chat and top up.

The service ends a turn with ``quota_exhausted`` (the recorded stream). The
chat offers the top-up packs; picking one asks the service for a checkout
page and opens it in the browser, but only when it is a Stripe checkout
URL. Anything else is shown for the user to open by hand, and the browser
is never started, so a tampered answer cannot send the user to a lookalike
payment page.
"""

from __future__ import annotations

import pytest

from e2e.harness.ai_chat import (
    open_chat,
    plain,
    replies,
    seed_hosted,
    send,
    wait_for_literal_toast,
    wait_for_reply,
)
from e2e.harness.fake_cloud.chat_script import ChatTurn, error, usage
from e2e.harness.fake_cloud.routes_ai import STRIPE_CHECKOUT_URL

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


async def _out_of_tokens(t, fake_cloud):
    fake_cloud.ai.script(ChatTurn.fixture("error_quota_exhausted"))
    if not t.find("#chat-panel"):
        await open_chat(t)
    await send(t, "Summarise the fleet")
    modal = await t.wait_for_screen("AITopUpModal")
    assert "Top up" in plain(modal.query_one("#ai_topup_reason"))
    def rendered_cancel_action():
        text = t.rendered_text(screen_only=True)
        return text if text.count("Cancel") >= 2 else None

    await t.wait_until(
        rendered_cancel_action,
        desc="the rendered top-up Cancel action",
    )
    # The half-streamed reply is not kept.
    await wait_for_reply(t)
    assert replies(t) == []
    return modal


async def test_topup_opens_the_stripe_checkout(tui, seed, fake_cloud, journey):
    seed_hosted(seed, fake_cloud)
    async with tui() as t:
        await _out_of_tokens(t, fake_cloud)
        await t.click("#btn_topup_0")
        await t.wait_until(lambda: journey.shims.calls("browser"), desc="the browser to open")

        assert [call.argv[-1] for call in journey.shims.calls("browser")] == [
            STRIPE_CHECKOUT_URL
        ]
        assert [row["pack"] for row in fake_cloud.ai.topups()] == ["pack_small"]
        assert not any("manually" in message for _, message in t.toasts())


# Checkout URLs that must never reach the browser, by the trick they use.
# The check is exact: only https://checkout.stripe.com/... opens, so even the
# real host spelled in capitals is shown rather than opened.
LOOKALIKES = {
    "other-hosts": [
        "https://billing.example.test/pay/e2e",
        "https://checkout.stripe.com.example.test/c/pay/e2e",
        "http://checkout.stripe.com/c/pay/e2e",
    ],
    # The markers keep the leak guard from reading user@host as an address.
    "userinfo": [
        "https://checkout.stripe.com@billing.example.test/c/pay/e2e",  # leak-guard:allow
        "https://checkout.stripe.com:443@billing.example.test/c/pay/e2e",  # leak-guard:allow
        "https://user:pass@checkout.stripe.com/c/pay/e2e",  # leak-guard:allow
    ],
    "case-and-idn": [
        "HTTPS://CHECKOUT.STRIPE.COM/c/pay/e2e",
        "https://checkout.str\u0456pe.com/c/pay/e2e",  # Cyrillic i
        "https://checkout.xn--strpe-p2e.com/c/pay/e2e",  # the same, as punycode
        "https://xn--heckout-xjg.stripe.com/c/pay/e2e",  # Cyrillic c, as punycode
    ],
    "scheme-and-backslash": [
        "javascript:alert(1)//https://checkout.stripe.com/c/pay/e2e",
        "https:\\\\checkout.stripe.com\\c\\pay\\e2e",
        "https://checkout.stripe.com\\@billing.example.test/c/pay/e2e",  # leak-guard:allow
    ],
    "embedded": [
        "https://billing.example.test/https://checkout.stripe.com/c/pay/e2e",
        "https://billing.example.test/?next=https://checkout.stripe.com/c/pay/e2e",
        "https://billing.example.test/pay#https://checkout.stripe.com/",
    ],
    "markup": [
        "https://billing.example.test/[b]pay[/b] [/]",
        "https://billing.example.test/[link=https://checkout.stripe.com/]pay[/link]",
    ],
}


@pytest.mark.parametrize("group", sorted(LOOKALIKES))
async def test_other_checkout_urls_are_never_opened(tui, seed, fake_cloud, journey, group):
    """Invalid checkout URLs are never opened or exposed in the TUI."""
    seed_hosted(seed, fake_cloud)
    async with tui() as t:
        for number, url in enumerate(LOOKALIKES[group], start=1):
            fake_cloud.ai.configure(topup_url=url)
            await _out_of_tokens(t, fake_cloud)
            await t.click("#btn_topup_1")
            await wait_for_literal_toast(
                t,
                "Top-up checkout returned an invalid Stripe checkout URL.",
                severity="warning",
            )
            assert len(fake_cloud.ai.topups()) == number
            assert journey.shims.calls("browser") == [], url
            assert all(url not in message for _, message in t.toasts())


async def test_dismissing_the_offer_leaves_the_chat_usable(tui, seed, fake_cloud):
    seed_hosted(seed, fake_cloud)
    async with tui() as t:
        await _out_of_tokens(t, fake_cloud)
        await t.click("#btn_topup_cancel")
        await t.wait_until(lambda: t.screen_name() == "InstanceListScreen", desc="offer closed")
        assert fake_cloud.ai.topups() == []

        # The input has the focus back.
        fake_cloud.ai.script(ChatTurn.fixture("tokens_only"))
        await send(t, "Try again")
        assert await wait_for_reply(t) == ["Hello world, how are you?"]


async def test_member_limit_refusal_does_not_offer_checkout(tui, seed, fake_cloud):
    seed_hosted(seed, fake_cloud)
    fake_cloud.ai.script(ChatTurn.of(
        error(
            "budget_exhausted", "Blocked", details={
                "reason": "member_limit_reached", "topup_helps": False,
            },
        ),
        usage(),
    ))
    async with tui() as t:
        await open_chat(t)
        await send(t, "Summarise the fleet")
        await wait_for_literal_toast(
            t,
            "Your team member limit has been reached. Ask a team owner to raise it or wait for the next period.",
            severity="warning",
        )
        assert t.screen_name() == "InstanceListScreen"
        assert fake_cloud.ai.topups() == []


async def test_valid_refusal_billing_route_opens_first_party_page(
    tui, seed, fake_cloud, journey,
):
    seed_hosted(seed, fake_cloud)
    fake_cloud.ai.script(ChatTurn.of(
        error(
            "quota_exhausted", "Blocked", details={
                "topup_helps": True,
                "topup_url": "https://servonaut.dev/account/billing/topup",
            },
        ),
        usage(),
    ))
    async with tui() as t:
        await open_chat(t)
        await send(t, "Summarise the fleet")
        modal = await t.wait_for_screen("AITopUpModal")
        assert journey.shims.calls("browser") == []
        assert modal.query_one("#btn_topup_billing")
        await t.click("#btn_topup_billing")
        await t.wait_until(lambda: journey.shims.calls("browser"), desc="billing browser open")
        assert [call.argv[-1] for call in journey.shims.calls("browser")] == [
            "https://servonaut.dev/account/billing/topup",
        ]
        assert fake_cloud.ai.topups() == []
