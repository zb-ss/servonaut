"""Chat panel status surfaces: the stats-bar tool note and error toasts.

- A bring-your-own provider chat runs tools at the chat guard level, so
  the stats bar must say which level (not that tools need Servonaut AI).
- A rate-limited turn is not retried, so the toast must say when to try
  again rather than promise a retry.

Same construction pattern as ``test_ai_provider_chain.py``: the panel is
built via ``__new__`` with a mocked ``app``; no Textual app is mounted.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.ai_sse import SSEStreamDead
from servonaut.services.api_client import RateLimitedError
from servonaut.services.chat_service import ChatService


def _make_panel(app: MagicMock, captured: list):
    """Minimal unmounted ChatPanel whose stats bar writes into *captured*."""
    from servonaut.widgets.chat_panel import ChatPanel

    # A per-call subclass carries the mocked ``app`` so the real class is
    # left untouched for other tests.
    class _Panel(ChatPanel):
        app = property(lambda _self: app)

    panel = _Panel.__new__(_Panel)
    panel._upstream_failures = []
    panel._session_provider_override = None
    panel._last_fallback_used = False
    panel._last_debit_micros = None
    panel._last_debit_display = None
    panel._last_soft_capped = False
    panel._last_hard_capped = False
    panel._total_tokens = 0
    panel._total_cost = 0.0
    panel._model = "gpt-4o-mini"
    panel._session = None
    panel._recording = False
    panel._transcribing = False
    panel._speaking = False
    panel._conversation_state = "off"
    panel._spinner_frame = 0
    panel.query_one = lambda *a, **kw: SimpleNamespace(update=captured.append)
    panel._update_quota_footer = lambda: None
    panel._update_provider_indicator = lambda: None
    return panel


def _stats_text(*, provider: str, guard_level) -> str:
    app = MagicMock()
    app.chat_service = SimpleNamespace(tool_guard_level=guard_level)
    captured: list = []
    panel = _make_panel(app, captured)
    panel._session_provider_override = provider
    panel._update_stats()
    assert captured, "stats bar was not updated"
    return captured[-1]


# ---------------------------------------------------------------------------
# Stats-bar tool note
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "guard_level, label",
    [("readonly", "read-only"), ("standard", "standard"), ("dangerous", "dangerous")],
)
def test_byo_stats_bar_names_the_tool_guard_level(guard_level, label):
    text = _stats_text(provider="openai", guard_level=guard_level)
    assert "requires Servonaut AI" not in text
    assert f"[dim]Tools:[/dim] {label}" in text


def test_byo_stats_bar_says_tools_off_without_a_tool_executor():
    text = _stats_text(provider="anthropic", guard_level=None)
    assert "Tools off" in text
    assert "requires Servonaut AI" not in text


def test_servonaut_stats_bar_has_no_byo_tool_note():
    text = _stats_text(provider="servonaut", guard_level="readonly")
    assert "Tools:" not in text
    assert "Tools off" not in text


def _hosted_stats_panel() -> tuple[object, list[str]]:
    app = MagicMock()
    app.auth_service = SimpleNamespace(
        _token=SimpleNamespace(entitlements={
            "balance": {"currency": "GBP", "remaining_micros": 4_380_000},
        }),
    )
    captured: list[str] = []
    panel = _make_panel(app, captured)
    panel._session_provider_override = "servonaut"
    panel._remote_conversation_id = None
    return panel, captured


def test_hosted_stats_prefer_the_server_turn_debit_display() -> None:
    panel, captured = _hosted_stats_panel()

    panel._consume_usage_event({
        "debit_micros": 120_000,
        "debit_display": "£0.13",
    })

    assert panel._last_debit_display == "£0.13"
    assert "Last turn debit:" in captured[-1]
    assert "£0.13" in captured[-1]
    assert "£0.12" not in captured[-1]


def test_hosted_stats_sanitize_and_rich_escape_server_turn_debit_display() -> None:
    panel, captured = _hosted_stats_panel()

    panel._consume_usage_event({
        "debit_micros": 50_000,
        "debit_display": "£0.05 [bold]shown[/bold]\x1b]52;c;unsafe\x07\x9b",
    })

    assert r"\[bold]shown\[/bold]" in captured[-1]
    assert "\x1b" not in captured[-1]
    assert "\x07" not in captured[-1]
    assert "\x9b" not in captured[-1]


def test_hosted_stats_render_a_zero_debit() -> None:
    panel, captured = _hosted_stats_panel()

    panel._consume_usage_event({"debit_micros": 0})

    assert "Last turn debit:" in captured[-1]
    assert "£0.00" in captured[-1]


@pytest.mark.parametrize("debit", [True, "120000", -120_000, None])
def test_hosted_stats_exclude_malformed_debits_without_reusing_a_prior_turn(debit) -> None:
    panel, captured = _hosted_stats_panel()
    panel._last_debit_micros = 120_000

    panel._consume_usage_event({"debit_micros": debit})

    assert panel._last_debit_micros is None
    assert panel._last_debit_display is None
    assert "Last turn debit:" not in captured[-1]


def test_byo_and_legacy_stats_do_not_render_a_hosted_turn_debit() -> None:
    panel, captured = _hosted_stats_panel()
    panel._last_debit_micros = 120_000
    panel._session_provider_override = "openai"
    panel._total_tokens = 120
    panel._total_cost = 0.0123
    panel._update_stats()
    assert "Tokens:" in captured[-1]
    assert "Cost:" in captured[-1]
    assert "Last turn debit:" not in captured[-1]

    panel._session_provider_override = "servonaut"
    panel.app.auth_service._token.entitlements = {"quota": {"tokens_used": 120}}
    panel._update_stats()
    assert "Last turn debit:" not in captured[-1]


def test_error_then_usage_renders_the_final_accounted_turn_debit() -> None:
    panel, captured = _hosted_stats_panel()
    panel._handle_stream_error(
        RateLimitedError(
            code="rate_limited", message="Slow down", status=429,
            response_headers={"retry-after": "1"},
        ),
        accumulated="",
    )

    panel._consume_usage_event({"debit_micros": 120_000})

    assert "Last turn debit:" in captured[-1]
    assert "£0.12" in captured[-1]


def _replacement_panel() -> tuple[object, list[str], object]:
    panel, captured = _hosted_stats_panel()
    panel._last_debit_micros = 120_000
    panel._last_debit_display = "£0.13"
    session = lambda: SimpleNamespace(
        id="fixture-session", remote_conversation_id=None, messages=[],
    )
    service = SimpleNamespace(
        create_session=session,
        load_session=lambda _session_id: session(),
        delete_session=lambda _session_id: None,
    )
    panel._session = session()
    panel._get_chat_service = lambda: service
    panel._refresh_messages = lambda: panel._update_stats()
    panel._do_focus_input = lambda: None
    panel._populate_history = lambda: None
    stats_widget = SimpleNamespace(update=captured.append)
    history_widget = SimpleNamespace(add_class=lambda _name: None)
    panel.query_one = lambda selector, *args: (
        stats_widget if selector == "#chat-stats" else history_widget
    )
    return panel, captured, session


@pytest.mark.parametrize("transition", [
    "new_chat", "load_session", "delete_current", "load_remote",
])
def test_conversation_replacements_clear_turn_debit_but_preserve_balance_cache(
    transition: str,
) -> None:
    panel, captured, session = _replacement_panel()
    balance_before = dict(panel.app.auth_service._token.entitlements["balance"])

    if transition == "new_chat":
        panel._new_chat()
    elif transition == "load_session":
        panel._load_session("fixture-session")
    elif transition == "delete_current":
        panel._delete_session("fixture-session")
    else:
        class Client:
            async def get(self, _uuid):
                return {"id": "fixture-remote", "messages": []}

        jobs = []
        panel.app.ai_conversations_client = Client()
        panel.run_worker = lambda coroutine, **kwargs: jobs.append(coroutine)
        panel.call_after_refresh = lambda callback: callback()
        panel.load_remote_conversation("fixture-remote")
        asyncio.run(jobs.pop())

    assert panel._last_debit_micros is None
    assert panel._last_debit_display is None
    assert "Last turn debit:" not in captured[-1]
    assert panel.app.auth_service._token.entitlements["balance"] == balance_before


def test_empty_remote_conversation_repaints_cleared_debit_after_welcome() -> None:
    panel, captured = _hosted_stats_panel()
    panel._last_debit_micros = 50_000
    panel._last_debit_display = "£0.05"
    panel._update_stats()
    assert "Last turn debit:" in captured[-1]
    balance_before = dict(panel.app.auth_service._token.entitlements["balance"])

    message_container = SimpleNamespace(
        remove_children=MagicMock(), mount=MagicMock(),
    )
    stats_widget = SimpleNamespace(update=captured.append)
    panel.query_one = lambda selector, *args: (
        message_container if selector == "#chat-messages" else stats_widget
    )

    class Client:
        async def get(self, _uuid):
            return {"id": "fixture-remote", "messages": []}

    jobs = []
    panel.app.ai_conversations_client = Client()
    panel.run_worker = lambda coroutine, **kwargs: jobs.append(coroutine)
    panel.call_after_refresh = lambda callback: callback()

    panel.load_remote_conversation("fixture-remote")
    asyncio.run(jobs.pop())

    message_container.remove_children.assert_called_once()
    message_container.mount.assert_called_once()
    assert panel._last_debit_micros is None
    assert panel._last_debit_display is None
    assert "Last turn debit:" not in captured[-1]
    assert panel.app.auth_service._token.entitlements["balance"] == balance_before


def test_stats_sanitize_and_rich_escape_server_model_metadata() -> None:
    panel, captured = _hosted_stats_panel()
    panel._model = "[bold red]hosted[/bold red]\x1b]52;c;unsafe\x07\x9b"
    panel._last_debit_micros = 120_000

    panel._update_stats()

    assert r"\[bold red]hosted\[/bold red]" in captured[-1]
    assert "\x1b" not in captured[-1]
    assert "\x07" not in captured[-1]
    assert "\x9b" not in captured[-1]


def _chat_service(*, ai_service, tool_executor) -> ChatService:
    service = ChatService.__new__(ChatService)
    service._ai_service = ai_service
    service._tool_executor = tool_executor
    return service


def test_chat_service_reports_its_tool_executor_guard_level():
    executor = SimpleNamespace(guard_level="readonly")
    service = _chat_service(ai_service=object(), tool_executor=executor)
    assert service.tool_guard_level == "readonly"


@pytest.mark.parametrize(
    "ai_service, tool_executor",
    [(object(), None), (None, SimpleNamespace(guard_level="standard"))],
)
def test_chat_service_reports_no_guard_level_when_tools_cannot_run(
    ai_service, tool_executor,
):
    service = _chat_service(ai_service=ai_service, tool_executor=tool_executor)
    assert service.tool_guard_level is None


def test_chat_tool_executor_exposes_its_guard_level():
    from servonaut.services.chat_tools import ChatToolExecutor

    tools = MagicMock()
    tools.config_manager.get.return_value.mcp.command_blocklist = []
    tools.config_manager.get.return_value.mcp.command_allowlist = []
    executor = ChatToolExecutor(tools=tools, guard_level="readonly")
    assert executor.guard_level == "readonly"


# ---------------------------------------------------------------------------
# Error toasts do not promise retries
# ---------------------------------------------------------------------------


def _error_panel():
    app = MagicMock()
    panel = _make_panel(app, [])
    panel._record_upstream_failure = MagicMock()
    panel._maybe_offer_fallback = MagicMock()
    panel._set_banner = MagicMock()
    return panel, app


def test_rate_limited_turn_says_when_to_try_again():
    panel, app = _error_panel()
    exc = RateLimitedError(
        code="rate_limited",
        message="Too many requests",
        status=429,
        response_headers={"retry-after": "12"},
    )

    panel._handle_stream_error(exc, accumulated="")

    app.notify.assert_called_once_with(
        "Rate limited — try again in 12 s.", severity="warning", markup=False,
    )


def test_hosted_balance_footer_scrubs_controls_before_rich_escaping():
    panel, app = _error_panel()
    footer = MagicMock()
    panel.query_one = lambda *args, **kwargs: footer
    del panel._update_quota_footer
    panel._active_provider_name = lambda: "servonaut"
    app.auth_service = MagicMock()
    app.auth_service._token = MagicMock()
    app.auth_service._token.entitlements = {
        "balance": {
            "display": {"remaining": "追加 £4.50\x1b]52;unsafe\x07\x9b"},
        },
    }

    panel._update_quota_footer()

    rendered = footer.update.call_args.args[0]
    assert "追加 £4.50]52;unsafe" in rendered
    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert "\x9b" not in rendered


def test_hosted_balance_footer_uses_money_fallback_or_refresh_guidance():
    def render(balance):
        panel, app = _error_panel()
        footer = MagicMock()
        panel.query_one = lambda *args, **kwargs: footer
        del panel._update_quota_footer
        panel._active_provider_name = lambda: "servonaut"
        app.auth_service = MagicMock()
        app.auth_service._token = MagicMock()
        app.auth_service._token.entitlements = {"balance": balance}
        panel._update_quota_footer()
        return footer.update.call_args.args[0]

    assert "£1,234.56" in render({
        "currency": "GBP", "remaining_micros": 1_234_560_000,
    })
    assert "unavailable — refresh to retry" in render({
        "display": {"remaining": 450},
    })


def test_hosted_balance_footer_shows_a_capped_members_limit_and_team_pool():
    panel, app = _error_panel()
    footer = MagicMock()
    panel.query_one = lambda *args, **kwargs: footer
    del panel._update_quota_footer
    panel._active_provider_name = lambda: "servonaut"
    app.auth_service = MagicMock()
    app.auth_service._token = MagicMock()
    app.auth_service._token.entitlements = {"balance": {
        "currency": "GBP", "payer_type": "team", "state": "ok",
        "display": {"remaining": "£72.50", "member_limit": "£2.00", "member_spent": "< £0.01"},
    }}

    panel._update_quota_footer()

    rendered = footer.update.call_args.args[0]
    assert rendered.index("Your limit:") < rendered.index("Team balance:")
    assert "£2.00 (< £0.01 used)" in rendered
    assert "£72.50" in rendered


def test_topup_errors_scrub_controls_before_tui_notification():
    from servonaut.services.api_client import APIError

    failure = APIError(
        code="unknown", message="Failure £4\x1b]52;unsafe\x07\x9b", status=400,
    )
    panel, app = _error_panel()
    app.servonaut_provider = MagicMock()
    app.servonaut_provider.topup_packs = AsyncMock(side_effect=failure)

    asyncio.run(panel._load_topup_modal("Blocked"))
    catalog_message = app.notify.call_args.args[0]
    assert "Failure £4]52;unsafe" in catalog_message
    assert "\x1b" not in catalog_message
    assert "\x07" not in catalog_message
    assert "\x9b" not in catalog_message

    app.notify.reset_mock()
    app.servonaut_provider.topup_checkout = AsyncMock(side_effect=failure)
    asyncio.run(panel._do_topup_checkout("pack_small"))
    checkout_message = app.notify.call_args.args[0]
    assert "Failure £4]52;unsafe" in checkout_message
    assert "\x1b" not in checkout_message
    assert "\x07" not in checkout_message
    assert "\x9b" not in checkout_message


def test_lost_connection_banner_asks_the_user_to_resend():
    panel, _app = _error_panel()

    panel._handle_stream_error(SSEStreamDead("silence"), accumulated="")

    banner = panel._set_banner.call_args.args[0]
    assert "Retrying" not in banner
    assert "send your message again" in banner


def test_malformed_retry_after_cannot_crash_the_error_handler():
    panel, app = _error_panel()
    exc = RateLimitedError(
        code="rate_limited", message="slow down", status=429,
        details={"retry_after": float("inf")},
    )

    panel._handle_stream_error(exc, accumulated="")

    app.notify.assert_called_once_with(
        "Rate limited — wait a moment, then try again.",
        severity="warning", markup=False,
    )


def test_refusal_offers_only_a_valid_first_party_billing_route(monkeypatch):
    from servonaut.services.api_client import APIError

    panel, app = _error_panel()
    panel._push_topup_modal = MagicMock()
    opened = []
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url) or True)
    panel._handle_stream_error(
        APIError(
            code="quota_exhausted",
            message="blocked",
            status=402,
            details={
                "topup_helps": True,
                "topup_url": "https://servonaut.dev/account/billing#topup",
            },
        ),
        accumulated="",
    )

    assert opened == []
    panel._push_topup_modal.assert_called_once_with(
        reason="blocked",
        billing_url="https://servonaut.dev/account/billing#topup",
    )


def test_external_refusal_url_cannot_auto_open(monkeypatch):
    from servonaut.services.api_client import APIError

    panel, _app = _error_panel()
    panel._push_topup_modal = MagicMock()
    opened = []
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url) or True)
    panel._handle_stream_error(
        APIError(
            code="quota_exhausted",
            message="blocked",
            status=402,
            details={"topup_helps": True, "topup_url": "https://bad.example/billing"},
        ),
        accumulated="",
    )

    assert opened == []
    panel._push_topup_modal.assert_called_once_with(
        reason="blocked",
        billing_url="",
    )


def test_catalog_failure_preserves_the_valid_billing_action():
    panel, app = _error_panel()
    app.servonaut_provider = MagicMock()
    app.servonaut_provider.topup_packs = AsyncMock(side_effect=RuntimeError("offline"))

    asyncio.run(panel._load_topup_modal(  # noqa: SLF001
        "Blocked", "https://servonaut.dev/account/billing/topup",
    ))

    modal, callback = app.push_screen.call_args.args
    assert modal._packs == []  # noqa: SLF001
    assert modal._show_billing_action is True  # noqa: SLF001
    opened = []
    panel._open_billing_topup = lambda url: opened.append(url)
    callback(modal.BILLING_ACTION)
    assert opened == ["https://servonaut.dev/account/billing/topup"]


def test_spend_info_opens_the_same_topup_path_as_a_402():
    panel, _app = _error_panel()
    panel._push_topup_modal = MagicMock()

    asyncio.run(panel._servonaut_handle_event({  # noqa: SLF001
        "event": "info",
        "data": {
            "code": "balance_exhausted",
            "message": "Stopped before the next tool round.",
            "details": {
                "topup_helps": True,
                "topup_url": "https://servonaut.dev/account/billing#topup",
            },
        },
    }, "partial"))

    panel._push_topup_modal.assert_called_once_with(
        reason="Stopped before the next tool round.",
        billing_url="https://servonaut.dev/account/billing#topup",
    )


# ---------------------------------------------------------------------------
# The tool call keeps the service's guard label as sent
# ---------------------------------------------------------------------------


def _tool_call_panel():
    from unittest.mock import AsyncMock

    app = MagicMock()
    bridge = MagicMock()
    bridge.handle_tool_call = AsyncMock(return_value=SimpleNamespace(skipped=False))
    bridge.post_tool_result = AsyncMock()
    app.ai_tool_bridge = bridge
    panel = _make_panel(app, [])
    panel._turn_tool_calls = 0
    panel._remote_conversation_id = "conv-1"
    return panel, bridge


@pytest.mark.parametrize("sent, expected", [(None, ""), ("ReadOnly", "ReadOnly")])
def test_streamed_tool_call_records_guard_label_as_sent(sent, expected):
    import asyncio

    panel, bridge = _tool_call_panel()
    data = {"tool_call_id": "tc-1", "tool": "list_instances", "args": {}}
    if sent is not None:
        data["guard_level"] = sent

    asyncio.run(panel._handle_streamed_tool_call(data))

    call = bridge.handle_tool_call.call_args.args[0]
    assert call.server_guard_level == expected
