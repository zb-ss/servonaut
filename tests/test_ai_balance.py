"""Hosted AI money values remain distinct from legacy token quota data."""
from __future__ import annotations

import pytest

from servonaut.services.ai_balance import (
    AIHostedBalance,
    AITopupPack,
    display_debit,
    format_micros,
    parse_topup_packs,
    safe_terminal_text,
)


def test_balance_uses_server_display_without_currency_math() -> None:
    balance = AIHostedBalance.from_dict({
        "remaining_micros": 4_500_000,
        "state": "degraded",
        "approx_requests_remaining": 3,
        "display": {"remaining": "£4.50"},
    })

    assert balance is not None
    assert balance.display_value("remaining") == "£4.50"
    assert balance.state == "degraded"
    assert balance.approx_requests_remaining == 3


def test_balance_rejects_malformed_money_and_never_coerces_boolean() -> None:
    balance = AIHostedBalance.from_dict({
        "approx_requests_remaining": True,
        "display": {"remaining": 450},
    })

    assert balance is not None
    assert balance.approx_requests_remaining is None
    assert balance.display_value("remaining") == ""


@pytest.mark.parametrize("state", [[], {}, 1, True, "unrecognised"])
def test_balance_ignores_malformed_or_unknown_state(state) -> None:
    balance = AIHostedBalance.from_dict({"state": state})

    assert balance is not None
    assert balance.state == ""


def test_balance_human_display_uses_exact_money_fallback_without_mutating_raw() -> None:
    raw = {"currency": "GBP", "remaining_micros": 1_234_560_000}
    balance = AIHostedBalance.from_dict(raw)

    assert balance is not None
    assert balance.display_value("remaining") == ""
    assert balance.human_display("remaining") == "£1,234.56"
    assert balance.raw == raw


@pytest.mark.parametrize(("name", "micros_field"), [
    ("remaining", "remaining_micros"),
    ("allowance_remaining", "allowance_remaining_micros"),
])
def test_balance_human_display_clamps_negative_available_money_fallbacks(
    name: str, micros_field: str,
) -> None:
    raw = {"currency": "GBP", micros_field: -120_000}
    balance = AIHostedBalance.from_dict(raw)

    assert balance is not None
    assert balance.human_display(name) == "£0.00"
    assert balance.raw == raw


def test_balance_human_display_keeps_a_sanitized_server_display_preferred() -> None:
    raw = {
        "currency": "GBP",
        "remaining_micros": -120_000,
        "display": {"remaining": "-£0.12\x1b]52;unsafe\x07"},
    }
    balance = AIHostedBalance.from_dict(raw)

    assert balance is not None
    assert balance.human_display("remaining") == "-£0.12]52;unsafe"
    assert balance.raw == raw


def test_balance_human_display_requires_valid_currency_and_integer_micros() -> None:
    balance = AIHostedBalance.from_dict({
        "currency": "GBP", "remaining_micros": True,
        "display": {"remaining": 450},
    })

    assert balance is not None
    assert balance.human_display("remaining") == ""


def test_pack_inventory_requires_unique_non_empty_server_keys() -> None:
    packs = parse_topup_packs({"packs": [
        {"key": "pack_small", "label": "Starter", "currency": "GBP"},
        {"key": "pack_small", "label": "Duplicate", "currency": "GBP"},
        {"key": "", "label": "Broken"},
    ]})

    assert [(pack.key, pack.label) for pack in packs] == [("pack_small", "Starter")]


def test_turn_debit_formats_exact_micros_without_float_rounding() -> None:
    assert format_micros(1_629, "GBP") == "< £0.01"
    assert format_micros(5_000, "GBP") == "£0.01"
    assert format_micros(-1_629, "GBP") == "£0.00"
    assert format_micros(1_629, "USD") == "< $0.01"
    assert display_debit(1_629, "GBP", "£0.01") == "£0.01"
    assert format_micros(True, "GBP") == ""


def test_terminal_text_strips_c0_and_c1_controls_without_losing_unicode() -> None:
    raw = "追加 £4.50\x1b]52;unsafe\x07\x9b"

    assert safe_terminal_text(raw) == "追加 £4.50]52;unsafe"
    assert raw == "追加 £4.50\x1b]52;unsafe\x07\x9b"


def test_currency_protocol_shape_rejects_controls_and_non_ascii() -> None:
    balance = AIHostedBalance.from_dict({"currency": "G\x1bBP"})

    assert balance is not None
    assert balance.currency == ""
    assert format_micros(1_629, "G\x1bBP") == ""
    assert format_micros(1_629, "EUR\x9b") == ""
    assert format_micros(1_629, "€€€") == ""
    assert format_micros(1_629, "gbp") == "< £0.01"


def test_server_pack_display_wins_with_a_money_fallback_for_older_servers() -> None:
    server_display = AITopupPack.from_dict({
        "key": "pack_small", "label": "Starter", "currency": "GBP",
        "price_minor": 500, "credit_micros": 5_000_000,
        "display": {"price": "£5", "credit": "£5.00"},
    })
    fallback = AITopupPack.from_dict({
        "key": "pack_large", "label": "Large", "currency": "GBP",
        "price_minor": 2_050, "credit_micros": 20_500_000,
    })

    assert server_display is not None
    assert (server_display.display_price, server_display.display_credit) == ("£5", "£5.00")
    assert fallback is not None
    assert (fallback.display_price, fallback.display_credit) == ("£20.50", "£20.50")

    grouped = AITopupPack.from_dict({
        "key": "pack_grouped", "label": "Grouped", "currency": "GBP",
        "price_minor": 123_400, "credit_micros": 1_234_560_000,
    })
    assert grouped is not None
    assert (grouped.display_price, grouped.display_credit) == ("£1,234", "£1,234.56")


_CAPPED_MEMBER = {
    "currency": "GBP", "payer_type": "team", "state": "ok",
    "remaining_micros": 72_496_738, "member_limit_micros": 2_000_000, "member_spent_micros": 3_262,
    "display": {"remaining": "£72.50", "member_limit": "£2.00", "member_spent": "< £0.01"},
}


def test_capped_team_member_sees_their_limit_and_the_pool_named_as_the_team() -> None:
    balance = AIHostedBalance.from_dict(_CAPPED_MEMBER)

    assert balance is not None
    assert balance.member_limit_summary() == "£2.00 (< £0.01 used)"
    assert balance.payer_is_team is True
    assert balance.remaining_label == "Team balance remaining"


def test_member_limit_summary_falls_back_to_exact_micros_and_is_empty_without_a_limit() -> None:
    fallback = AIHostedBalance.from_dict({
        "currency": "GBP", "member_limit_micros": 2_000_000, "member_spent_micros": 500_000,
    })
    personal = AIHostedBalance.from_dict({"currency": "GBP", "payer_type": "user", "remaining_micros": 1})

    assert fallback is not None and fallback.member_limit_summary() == "£2.00 (£0.50 used)"
    assert personal is not None and personal.member_limit_summary() == ""
    assert personal.remaining_label == "Balance remaining"
