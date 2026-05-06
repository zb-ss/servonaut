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
    # allow_tools defaults to True when --no-tools is absent.
    kwargs = provider.chat.call_args.kwargs
    assert kwargs["allow_tools"] is True
    assert kwargs["task"] == "chat"


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
# 6. topup — opens browser + schedules entitlements refresh
# ---------------------------------------------------------------------------


def test_ai_topup_opens_browser_and_schedules_refresh(monkeypatch, capsys):
    """`servonaut ai topup small` opens Stripe Checkout AND awaits refresh.

    B3 — switched ``schedule_post_topup_refresh`` (async-but-fire-and-forget,
    dies when CLI exits) for the new ``await_post_topup_refresh``
    blocking variant. We assert the new method was awaited so a future
    regression that drops the await is caught.
    """
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
    auth.await_post_topup_refresh.assert_awaited_once()


def test_ai_topup_blocks_for_post_checkout_refresh(monkeypatch):
    """B3 — the CLI handler awaits the refresh; the entitlements actually fetch.

    Drives the topup handler with a real ``await_post_topup_refresh``
    that calls ``fetch_entitlements`` so we can assert the lifecycle
    isn't truncated by ``asyncio.run`` exiting.
    """
    services = _make_services()
    _patch_init(monkeypatch, services)
    _config, auth, _api, provider, _convs, _pref = services

    provider.topup_checkout.return_value = (
        "https://checkout.stripe.com/pay/cs_test_abc"
    )

    fetch_called = MagicMock()

    async def _await_refresh(progress_callback=None, *, wait_seconds=45.0):
        fetch_called(wait_seconds)
        await auth.fetch_entitlements()

    auth.await_post_topup_refresh = _await_refresh

    monkeypatch.setattr(cli_ai.webbrowser, "open", lambda _u: True)

    args = _ns(ai_command="topup", pack="small")
    rc = cli_ai.handle_ai_command(args)

    assert rc == 0
    fetch_called.assert_called_once()
    auth.fetch_entitlements.assert_awaited_once()


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
