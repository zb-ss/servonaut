"""Tests for ``servonaut ai`` CLI subcommand handlers (Wave 3 / Agent H).

Drives :func:`servonaut.cli.ai.handle_ai_command` directly with constructed
:class:`argparse.Namespace` objects — bypassing ``main.py`` entirely so we
don't need to fork a subprocess for every assertion.

Service construction inside ``cli/ai.py._init_headless_services`` is patched
to return mocks via ``monkeypatch.setattr`` so no real network or filesystem
I/O happens.
"""
from __future__ import annotations

import argparse
import asyncio
import io
import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.cli import ai as cli_ai
from servonaut.services.ai_balance import AITopupPack
from servonaut.services.api_client import APIClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_services(
    *,
    authenticated: bool = True,
    premium: bool = True,
    quota: dict | None = None,
):
    """Build a 6-tuple matching ``_init_headless_services``'s return shape."""
    config_manager = MagicMock()
    auth = MagicMock()
    auth.is_authenticated = authenticated
    auth.has_feature = MagicMock(return_value=premium)
    auth.fetch_entitlements = AsyncMock(return_value=None)
    auth.await_post_topup_refresh = AsyncMock(return_value=None)

    # Stash a token snapshot so quota can be reached via ``auth._token``.
    token = MagicMock()
    token.entitlements = {"quota": quota} if quota is not None else {}
    auth._token = token

    api_client = MagicMock(spec=APIClient)
    api_client.get = AsyncMock()
    api_client.post = AsyncMock()
    api_client.patch = AsyncMock()
    api_client.delete = AsyncMock()
    api_client.get_bytes = AsyncMock()
    api_client.stream_sse = MagicMock()  # async-generator-shaped per-test

    provider = MagicMock()
    provider.chat = AsyncMock()
    provider._chat_internal = AsyncMock()
    provider.stream_chat = MagicMock()
    provider.topup_checkout = AsyncMock()
    provider.topup_packs = AsyncMock(return_value=[
        AITopupPack(key="small", label="Small", currency="GBP"),
    ])

    convs = MagicMock()
    convs.list = AsyncMock()
    convs.get = AsyncMock()
    convs.patch = AsyncMock()
    convs.delete = AsyncMock()
    convs.export_md = AsyncMock()
    convs.export_json = AsyncMock()

    pref = MagicMock()
    pref.reset = MagicMock()

    return (config_manager, auth, api_client, provider, convs, pref)


def _patch_init(monkeypatch, services):
    """Make ``_init_headless_services`` return *services* unconditionally."""
    monkeypatch.setattr(cli_ai, "_init_headless_services", lambda: services)


def _ns(**kwargs) -> argparse.Namespace:
    """Convenience constructor for an ``argparse.Namespace`` test stub."""
    return argparse.Namespace(**kwargs)


# ---------------------------------------------------------------------------
# 1. quota --json
# ---------------------------------------------------------------------------


def test_ai_quota_json(monkeypatch, capsys):
    """`servonaut ai quota --json` emits valid JSON of the AIQuota dict."""
    canonical = {
        "tokens_used": 123_456,
        "tokens_limit": 15_000_000,
        "tokens_topup_remaining": 500_000,
        "resets_at": "2026-05-01T00:00:00+00:00",
        "soft_capped": False,
        "hard_capped": False,
        "rpm_limit": 30,
        "tokens_per_minute_limit": 600_000,
    }
    services = _make_services(quota=canonical)
    _patch_init(monkeypatch, services)

    args = _ns(ai_command="quota", json=True)
    rc = cli_ai.handle_ai_command(args)

    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data == canonical


def test_ai_quota_terminal_output_strips_controls_but_json_preserves_raw(
    monkeypatch, capsys
):
    raw_balance = {
        "state": "ok",
        "currency": "G\x1bBP",
        "display": {
            "remaining": "追加 £4.50\x1b]52;unsafe\x07",
            "spent_this_period": "£1.20\x9b",
        },
    }
    services = _make_services()
    services[1]._token.entitlements["balance"] = raw_balance
    _patch_init(monkeypatch, services)

    assert cli_ai.handle_ai_command(_ns(ai_command="quota", json=False)) == 0
    terminal = capsys.readouterr().out
    assert "追加 £4.50]52;unsafe" in terminal
    assert "£1.20" in terminal
    assert "\x1b" not in terminal
    assert "\x9b" not in terminal

    assert cli_ai.handle_ai_command(_ns(ai_command="quota", json=True)) == 0
    assert json.loads(capsys.readouterr().out)["balance"] == raw_balance


def test_ai_quota_falls_back_to_exact_micros_when_server_display_is_missing(
    monkeypatch, capsys
):
    services = _make_services()
    services[1]._token.entitlements["balance"] = {
        "currency": "GBP", "remaining_micros": 1_234_560_000,
    }
    _patch_init(monkeypatch, services)

    assert cli_ai.handle_ai_command(_ns(ai_command="quota", json=False)) == 0
    output = capsys.readouterr().out
    assert "Balance remaining: £1,234.56" in output
    assert "Tokens remaining:" not in output


def test_ai_quota_explains_when_a_balance_payload_is_unusable(monkeypatch, capsys):
    services = _make_services(quota={
        "tokens_used": 0, "tokens_limit": 1_000_000,
        "tokens_topup_remaining": 0, "resets_at": "",
        "soft_capped": False, "hard_capped": False,
        "rpm_limit": 30, "tokens_per_minute_limit": 600_000,
    })
    services[1]._token.entitlements["balance"] = {
        "display": {"remaining": 450},
    }
    _patch_init(monkeypatch, services)

    assert cli_ai.handle_ai_command(_ns(ai_command="quota", json=False)) == 0
    output = capsys.readouterr().out
    assert "Balance: unavailable; refresh entitlements and try again." in output
    assert "Tokens remaining:" not in output


def test_ai_quota_human_output_includes_money_breakdown_and_renewals(
    monkeypatch, capsys
):
    services = _make_services()
    services[1]._token.entitlements["balance"] = {
        "state": "degraded",
        "display": {
            "remaining": "£4.50",
            "spent_this_period": "£1.25",
            "allowance_remaining": "£1.00",
            "topup_remaining": "£2.50",
            "credit_remaining": "£1.00",
        },
        "next_grant_at": "2026-11-01T00:00:00Z",
        "next_topup_expiry": "2026-12-01T00:00:00Z",
        "next_credit_expiry": "2026-10-15T00:00:00Z",
    }
    _patch_init(monkeypatch, services)

    assert cli_ai.handle_ai_command(_ns(ai_command="quota", json=False)) == 0
    output = capsys.readouterr().out
    assert "Status: Running low (faster model)" in output
    assert "Allowance remaining: £1.00" in output
    assert "Top-ups remaining: £2.50" in output
    assert "Credit remaining: £1.00" in output
    assert "Allowance renews: 2026-11-01T00:00:00Z" in output
    assert "Top-up expires: 2026-12-01T00:00:00Z" in output
    assert "Credit expires: 2026-10-15T00:00:00Z" in output


def test_ai_topup_catalog_strips_controls_and_keeps_unicode_labels(
    monkeypatch, capsys
):
    services = _make_services()
    _config, _auth, _api, provider, _convs, _pref = services
    provider.topup_packs.return_value = [
        AITopupPack(
            key="starter\x1b]52;unsafe\x07",
            label="追加 £5\x9b",
            currency="GBP",
            display_price="£5.00\x07",
        )
    ]
    _patch_init(monkeypatch, services)

    assert cli_ai.handle_ai_command(_ns(ai_command="topup", pack=None)) == 0
    terminal = capsys.readouterr().out
    assert "starter]52;unsafe" in terminal
    assert "追加 £5" in terminal
    assert "£5.00" in terminal
    assert "\x1b" not in terminal
    assert "\x9b" not in terminal


def test_ai_topup_errors_strip_terminal_controls(monkeypatch, capsys):
    from servonaut.services.api_client import APIError

    services = _make_services()
    _config, _auth, _api, provider, _convs, _pref = services
    failure = APIError(
        code="unknown", message="Failure £4\x1b]52;unsafe\x07\x9b", status=400,
    )
    provider.topup_packs.side_effect = failure
    _patch_init(monkeypatch, services)

    assert cli_ai.handle_ai_command(_ns(ai_command="topup", pack=None)) == 1
    catalog_error = capsys.readouterr().err
    assert "Failure £4]52;unsafe" in catalog_error
    assert "\x1b" not in catalog_error
    assert "\x07" not in catalog_error
    assert "\x9b" not in catalog_error

    provider.topup_packs.side_effect = None
    provider.topup_checkout.side_effect = failure
    assert cli_ai.handle_ai_command(_ns(ai_command="topup", pack="small")) == 1
    checkout_error = capsys.readouterr().err
    assert "Failure £4]52;unsafe" in checkout_error
    assert "\x1b" not in checkout_error
    assert "\x07" not in checkout_error
    assert "\x9b" not in checkout_error


# ---------------------------------------------------------------------------
# 2. chat (buffered)
# ---------------------------------------------------------------------------


def test_ai_chat_buffered(monkeypatch, capsys):
    """`servonaut ai chat "hello"` calls provider.chat and prints content."""
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services
    provider.chat.return_value = {"content": "hi back!"}

    args = _ns(
        ai_command="chat",
        prompt="hello",
        stream=False,
        no_tools=False,
        ai_provider=None,
        task="chat",
    )
    rc = cli_ai.handle_ai_command(args)

    assert rc == 0
    captured = capsys.readouterr()
    assert "hi back!" in captured.out
    provider.chat.assert_awaited_once()
    # Buffered mode defaults tools OFF (no headless executor exists) and
    # says so on stderr; --tools opts back in.
    kwargs = provider.chat.call_args.kwargs
    assert kwargs["allow_tools"] is False
    assert "tool execution is disabled" in captured.err
    assert kwargs["task"] == "chat"


def test_ai_chat_buffered_tools_flag_opts_in(monkeypatch, capsys):
    """`--tools` re-enables tool execution in buffered mode."""
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services
    provider.chat.return_value = {"content": "ok"}

    rc = cli_ai.handle_ai_command(_chat_args(tools=True))

    assert rc == 0
    captured = capsys.readouterr()
    assert provider.chat.call_args.kwargs["allow_tools"] is True
    assert "tool execution is disabled" not in captured.err


def test_ai_chat_no_tools_beats_tools_flag(monkeypatch):
    """`--no-tools` wins when both flags are given."""
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services
    provider.chat.return_value = {"content": "ok"}

    rc = cli_ai.handle_ai_command(_chat_args(tools=True, no_tools=True))

    assert rc == 0
    assert provider.chat.call_args.kwargs["allow_tools"] is False


def _chat_args(**overrides) -> argparse.Namespace:
    base = dict(
        ai_command="chat",
        prompt="how many instances?",
        stream=False,
        no_tools=False,
        ai_provider=None,
        task="chat",
    )
    base.update(overrides)
    return _ns(**base)


def test_ai_chat_buffered_tool_use_empty_content_errors(monkeypatch, capsys):
    """Empty content + tool_use must NOT exit 0 silently — the field bug:
    a prompt needing a tool returned content="" and the CLI printed nothing."""
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services
    provider.chat.return_value = {
        "content": "",
        "tool_calls_count": 1,
        "stop_reason": "tool_use",
    }

    rc = cli_ai.handle_ai_command(_chat_args())

    assert rc == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "tool call" in captured.err
    assert "--no-tools" in captured.err


def test_ai_chat_buffered_empty_content_errors(monkeypatch, capsys):
    """Empty content without tool calls is still an error, not a silent 0."""
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services
    provider.chat.return_value = {"content": ""}

    rc = cli_ai.handle_ai_command(_chat_args())

    assert rc == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "empty response" in captured.err


def test_ai_chat_buffered_warning_surfaced(monkeypatch, capsys):
    """A non-empty `warning` field is printed to stderr alongside content."""
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services
    provider.chat.return_value = {"content": "hi back!", "warning": "fallback model used"}

    rc = cli_ai.handle_ai_command(_chat_args())

    assert rc == 0
    captured = capsys.readouterr()
    assert "hi back!" in captured.out
    assert "fallback model used" in captured.err


def test_ai_chat_buffered_sanitises_server_metadata_without_mutating_raw(
    monkeypatch, capsys
):
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services
    raw_result = {
        "content": "hi back!",
        "warning": "notice\x1b]52;warning\x07\x9b",
        "balance": {
            "currency": "GBP",
            "display": {"remaining": "£4.50"},
        },
        "debit_micros": 1_629,
        "debit_display": "£0.01\x1b]52;debit\x07\x9b",
    }
    provider.chat.return_value = raw_result

    assert cli_ai.handle_ai_command(_chat_args()) == 0
    terminal = capsys.readouterr().err
    assert "£0.01]52;debit" in terminal
    assert "notice]52;warning" in terminal
    assert "\x1b" not in terminal
    assert "\x9b" not in terminal
    assert raw_result["debit_display"] == "£0.01\x1b]52;debit\x07\x9b"


def test_ai_chat_buffered_sanitises_server_error_code_and_message(monkeypatch, capsys):
    from servonaut.services.api_client import APIError

    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services
    provider.chat.side_effect = APIError(
        code="quota\x1b]52;code\x07\x9b",
        message="blocked\x1b]52;message\x07\x9b",
        status=402,
    )

    assert cli_ai.handle_ai_command(_chat_args()) == 1
    terminal = capsys.readouterr().err
    assert "Error [quota]52;code]: blocked]52;message" in terminal
    assert "\x1b" not in terminal
    assert "\x9b" not in terminal


@pytest.mark.parametrize(
    ("code", "reason", "topup_helps", "expected", "has_topup_hint"),
    [
        (
            "budget_exhausted", "member_limit_reached", False,
            "Ask a team owner to raise it or wait for the next period.", False,
        ),
        (
            "quota_exhausted", "team_pool_exhausted", True,
            "Your team's AI balance is used up.", True,
        ),
        (
            "budget_exhausted", "balance_exhausted", True,
            "Your AI balance is used up.", True,
        ),
        ("unknown", "unknown_reason", False, "Blocked]52;unsafe", False),
    ],
)
def test_ai_chat_buffered_maps_known_spend_reasons_and_keeps_unknown_safe(
    monkeypatch, capsys, code, reason, topup_helps, expected, has_topup_hint,
):
    from servonaut.services.api_client import APIError

    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services
    provider.chat.side_effect = APIError(
        code=code,
        message="Blocked\x1b]52;unsafe\x07\x9b",
        status=402,
        details={"reason": reason, "topup_helps": topup_helps},
    )

    assert cli_ai.handle_ai_command(_chat_args()) == 1
    terminal = capsys.readouterr().err
    assert expected in terminal
    assert ("servonaut ai topup" in terminal) is has_topup_hint
    assert "\x1b" not in terminal
    assert "\x07" not in terminal
    assert "\x9b" not in terminal


# ---------------------------------------------------------------------------
# 3. --no-tools propagation
# ---------------------------------------------------------------------------


def test_ai_chat_instance_flag_prepends_memory_block(monkeypatch, capsys):
    """`servonaut ai chat --instance srv-a "..."` prepends a synthetic user
    message carrying a <CONTEXT> block before the user's prompt."""
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services
    provider.chat.return_value = {"content": "ok"}

    # Stub the helper so we don't actually load disk-backed memory.
    monkeypatch.setattr(
        cli_ai, "_build_cli_memory_block",
        lambda prompt, ids: '<CONTEXT name="server_memory:srv-a" '
        'snapshot_at="2026-01-01T00:00:00+00:00">\n{"os": {}}\n</CONTEXT>',
    )

    args = _ns(
        ai_command="chat",
        prompt="what services are running?",
        stream=False,
        no_tools=False,
        ai_provider=None,
        task="chat",
        instance=["srv-a"],
    )
    rc = cli_ai.handle_ai_command(args)

    assert rc == 0
    sent_messages = provider.chat.call_args.kwargs["messages"]
    # Two messages: the synthetic memory message first, then the user.
    assert len(sent_messages) == 2
    assert sent_messages[0]["role"] == "user"
    # This test stubs _build_cli_memory_block, so it verifies prepend
    # mechanics, not the trust framing (which build_memory_context applies in
    # production and is covered in test_ai_memory_injector / test_ai_tool_bridge).
    assert sent_messages[0]["content"].startswith('<CONTEXT name="server_memory:srv-a"')
    assert sent_messages[1]["content"] == "what services are running?"


def test_ai_chat_no_instance_flag_keeps_stateless_messages(monkeypatch):
    """Without --instance, behaviour is unchanged: a single user message."""
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services
    provider.chat.return_value = {"content": "ok"}

    args = _ns(
        ai_command="chat",
        prompt="hello",
        stream=False,
        no_tools=False,
        ai_provider=None,
        task="chat",
        instance=[],
    )
    rc = cli_ai.handle_ai_command(args)

    assert rc == 0
    sent_messages = provider.chat.call_args.kwargs["messages"]
    assert len(sent_messages) == 1
    assert sent_messages[0]["content"] == "hello"


def test_ai_chat_skips_memory_bootstrap_when_no_instance(monkeypatch):
    """Without --instance the heavy memory-service stack (AWS / SSH /
    CustomServer / OVH wiring) must not be constructed.  Stateless
    one-shot prompts shouldn't pay for memory-service init."""
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services
    provider.chat.return_value = {"content": "ok"}

    bootstrap_calls = []

    def _spy_init(*args, **kwargs):
        bootstrap_calls.append(True)
        raise AssertionError(
            "memory headless bootstrap must not run without --instance"
        )

    # Patch the cli.memory._init_headless_services that
    # _build_cli_memory_block imports lazily.
    import servonaut.cli.memory as cli_memory
    monkeypatch.setattr(cli_memory, "_init_headless_services", _spy_init)

    args = _ns(
        ai_command="chat",
        prompt="hello",
        stream=False,
        no_tools=False,
        ai_provider=None,
        task="chat",
        instance=[],
    )
    rc = cli_ai.handle_ai_command(args)
    assert rc == 0
    assert bootstrap_calls == []


def test_ai_chat_no_tools_flag(monkeypatch):
    """`--no-tools` propagates to provider.chat as allow_tools=False."""
    # Ensure a stale env-var doesn't poison the assertion.
    monkeypatch.delenv("SERVONAUT_AI_NO_TOOLS", raising=False)

    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services
    provider.chat.return_value = {"content": "ok"}

    args = _ns(
        ai_command="chat",
        prompt="probe",
        stream=False,
        no_tools=True,
        ai_provider=None,
        task="chat",
    )
    rc = cli_ai.handle_ai_command(args)

    assert rc == 0
    provider.chat.assert_awaited_once()
    kwargs = provider.chat.call_args.kwargs
    assert kwargs["allow_tools"] is False


# ---------------------------------------------------------------------------
# 4. streaming chat — tokens line-buffered to stdout
# ---------------------------------------------------------------------------


def test_ai_chat_stream_writes_tokens_line_buffered(monkeypatch, capsys):
    """Streaming mode writes each token to stdout as it arrives.

    We mock ``provider.stream_chat`` to return an async generator that yields
    three token events, a usage event, then a done event — and assert the
    captured stdout contains the concatenated token text.
    """
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services

    async def _fake_stream(*_a, **_kw):
        for text in ("Hello", " ", "world"):
            yield {"event": "token", "data": {"text": text}}
        yield {
            "event": "usage",
            "data": {
                "model": "gemini-2-flash-002",
                "input_tokens": 10,
                "output_tokens": 3,
            },
        }
        yield {"event": "done", "data": {}}

    provider.stream_chat = _fake_stream

    args = _ns(
        ai_command="chat",
        prompt="say hi",
        stream=True,
        no_tools=False,
        ai_provider=None,
        task="chat",
    )
    rc = cli_ai.handle_ai_command(args)

    assert rc == 0
    captured = capsys.readouterr()
    # Stdout has the concatenated tokens then a trailing newline.
    assert "Hello world" in captured.out
    # Trailer goes to stderr so it doesn't pollute the stdout body.
    assert "model=gemini-2-flash-002" in captured.err
    assert "tokens=13" in captured.err


def test_ai_chat_stream_sanitises_info_tool_and_terminal_error_metadata(
    monkeypatch, capsys
):
    from servonaut.services.api_client import APIError

    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services

    async def _fake_stream(*_a, **_kw):
        yield {
            "event": "info",
            "data": {
                "code": "limit\x1b]52;code\x07\x9b",
                "message": "wait\x1b]52;message\x07\x9b",
            },
        }
        yield {
            "event": "tool_call",
            "data": {"tool": "inspect\x1b]52;tool\x07\x9b"},
        }
        raise APIError(
            code="quota\x1b]52;error-code\x07\x9b",
            message="blocked\x1b]52;error-message\x07\x9b",
            status=402,
        )
        yield  # pragma: no cover

    provider.stream_chat = _fake_stream

    assert cli_ai.handle_ai_command(_chat_args(stream=True)) == 1
    terminal = capsys.readouterr().err
    assert "[limit]52;code] wait]52;message" in terminal
    assert "[tool_call] inspect]52;tool" in terminal
    assert "Error [quota]52;error-code]: blocked]52;error-message" in terminal
    assert "\x1b" not in terminal
    assert "\x9b" not in terminal


def test_ai_chat_stream_terminal_member_refusal_keeps_final_accounting(
    monkeypatch, capsys,
):
    from servonaut.services.api_client import APIError

    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services

    async def _stream(*_args, **_kwargs):
        yield {
            "event": "usage",
            "data": {
                "model": "hosted-proof",
                "input_tokens": 1,
                "output_tokens": 1,
                "balance": {"currency": "GBP", "display": {"remaining": "£4.38"}},
                "debit_micros": 120_000,
                "debit_display": "£0.13",
            },
        }
        raise APIError(
            code="budget_exhausted",
            message="Blocked",
            status=402,
            details={"reason": "member_limit_reached", "topup_helps": False},
        )

    provider.stream_chat = _stream

    assert cli_ai.handle_ai_command(_chat_args(stream=True)) == 1
    terminal = capsys.readouterr().err
    assert "Ask a team owner to raise it or wait for the next period." in terminal
    assert "Turn debit: £0.13" in terminal
    assert "Balance remaining: £4.38" in terminal
    assert "servonaut ai topup" not in terminal


# ---------------------------------------------------------------------------
# 5. provider reset
# ---------------------------------------------------------------------------


def test_ai_provider_reset_clears_preference(monkeypatch, capsys):
    """`servonaut ai provider reset` calls ProviderPreferenceResolver.reset()."""
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, _provider, _convs, pref = services

    args = _ns(ai_command="provider", provider_command="reset")
    rc = cli_ai.handle_ai_command(args)

    assert rc == 0
    pref.reset.assert_called_once()
    captured = capsys.readouterr()
    assert "OK" in captured.out


# ---------------------------------------------------------------------------
# 6. topup — opens browser and returns without guessed refresh timing
# ---------------------------------------------------------------------------


def test_ai_topup_opens_browser_and_returns_without_refresh(monkeypatch):
    """A browser launch returns immediately; checkout completion is external."""
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, auth, _api, provider, _convs, _pref = services

    provider.topup_checkout.return_value = (
        "https://checkout.stripe.com/pay/cs_test_abc"
    )
    auth.await_post_topup_refresh = AsyncMock(return_value=None)

    opened_with: list = []

    def fake_open(url: str) -> bool:
        opened_with.append(url)
        return True

    monkeypatch.setattr(cli_ai.webbrowser, "open", fake_open)

    args = _ns(ai_command="topup", pack="small")
    rc = cli_ai.handle_ai_command(args)

    assert rc == 0
    provider.topup_checkout.assert_awaited_once_with("small")
    assert opened_with == ["https://checkout.stripe.com/pay/cs_test_abc"]
    auth.await_post_topup_refresh.assert_not_called()


def test_ai_topup_exits_without_waiting_for_checkout_completion(monkeypatch, capsys):
    """The one-shot command cannot know when an external checkout completes."""
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, auth, _api, provider, _convs, _pref = services

    provider.topup_checkout.return_value = (
        "https://checkout.stripe.com/pay/cs_test_abc"
    )
    auth.await_post_topup_refresh = AsyncMock()
    monkeypatch.setattr(cli_ai.webbrowser, "open", lambda url: True)

    rc = cli_ai.handle_ai_command(_ns(ai_command="topup", pack="small"))

    assert rc == 0
    err = capsys.readouterr().err
    assert "After checkout completes" in err
    assert "servonaut ai quota" in err
    auth.await_post_topup_refresh.assert_not_called()


def test_ai_topup_does_not_fetch_entitlements_before_external_checkout(monkeypatch):
    """A browser launch is not evidence that checkout has completed."""
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, auth, _api, provider, _convs, _pref = services

    provider.topup_checkout.return_value = (
        "https://checkout.stripe.com/pay/cs_test_abc"
    )

    auth.await_post_topup_refresh = AsyncMock()

    monkeypatch.setattr(cli_ai.webbrowser, "open", lambda _u: True)

    args = _ns(ai_command="topup", pack="small")
    rc = cli_ai.handle_ai_command(args)

    assert rc == 0
    auth.await_post_topup_refresh.assert_not_called()
    auth.fetch_entitlements.assert_not_called()


# ---------------------------------------------------------------------------
# 7. unauthenticated → exit 2
# ---------------------------------------------------------------------------


def test_unauthenticated_exits_2(monkeypatch, capsys):
    """When the user is not authenticated, exit 2 with the login hint."""
    services = _make_services(authenticated=False)
    _patch_init(monkeypatch, services)

    args = _ns(ai_command="quota", json=False)
    rc = cli_ai.handle_ai_command(args)

    assert rc == 2
    captured = capsys.readouterr()
    assert "Log in" in captured.err


# ---------------------------------------------------------------------------
# 8. free user → exit 3
# ---------------------------------------------------------------------------


def test_free_user_exits_3(monkeypatch, capsys):
    """When the user lacks ``premium_ai``, exit 3 with the upgrade hint."""
    services = _make_services(authenticated=True, premium=False)
    _patch_init(monkeypatch, services)

    args = _ns(ai_command="quota", json=False)
    rc = cli_ai.handle_ai_command(args)

    assert rc == 3
    captured = capsys.readouterr()
    assert "Solo" in captured.err or "pricing" in captured.err


# ---------------------------------------------------------------------------
# 9. conversations list (smoke — no JSON, exercises tabulate fallback path)
# ---------------------------------------------------------------------------


def test_servonaut_ai_provider_env_var_overrides_config(monkeypatch, capsys):
    """``SERVONAUT_AI_PROVIDER=servonaut`` env var works as a per-process override.

    D2 — covers the env-var precedence path in ``_resolve_per_session_provider``.
    The ``ai_provider`` argparse flag is None, so the env var wins. With
    value ``"servonaut"`` the chat handler still routes through the
    Servonaut provider and exits 0.
    """
    monkeypatch.setenv("SERVONAUT_AI_PROVIDER", "servonaut")
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, provider, _convs, _pref = services
    provider.chat.return_value = {"content": "ok"}

    args = _ns(
        ai_command="chat",
        prompt="hello",
        stream=False,
        no_tools=False,
        ai_provider=None,
        task="chat",
    )
    rc = cli_ai.handle_ai_command(args)

    assert rc == 0
    # The handler honoured the env var (didn't error out with "only TUI").
    provider.chat.assert_awaited_once()


def test_servonaut_ai_provider_env_var_non_servonaut_rejected(monkeypatch):
    """``SERVONAUT_AI_PROVIDER=openai`` is rejected by the headless CLI.

    The headless one-shot command only knows how to drive the Servonaut
    provider; we surface a usage error rather than silently ignoring the
    user's intent.
    """
    monkeypatch.setenv("SERVONAUT_AI_PROVIDER", "openai")
    services = _make_services()
    _patch_init(monkeypatch, services)

    args = _ns(
        ai_command="chat",
        prompt="hello",
        stream=False,
        no_tools=False,
        ai_provider=None,
        task="chat",
    )
    rc = cli_ai.handle_ai_command(args)
    # Usage error → exit 4 per cli_ai exit code convention.
    assert rc == 4


def test_ai_conversations_list_json(monkeypatch, capsys):
    """`servonaut ai conversations list --json` emits a JSON array."""
    from servonaut.services.ai_conversations import ConversationSummary

    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, _auth, _api, _provider, convs, _pref = services
    convs.list.return_value = [
        ConversationSummary(
            id="conv-1",
            title="why is nginx 502ing?",
            status="active",
            created_at="2026-04-15T10:00:00Z",
            updated_at="2026-04-15T10:30:00Z",
            message_count=4,
            last_model="gemini-2-flash-002",
        )
    ]

    args = _ns(
        ai_command="conversations",
        conversations_command="list",
        limit=25,
        before=None,
        status="active",
        json=True,
    )
    rc = cli_ai.handle_ai_command(args)

    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert data[0]["id"] == "conv-1"
    assert data[0]["status"] == "active"
