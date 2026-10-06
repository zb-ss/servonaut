"""Vault hints refresh trusted state without entering command execution."""
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.relay_listener import RelayListener


def make_listener(handler=None):
    return RelayListener(
        executors=MagicMock(execute=AsyncMock()),
        base_url="https://api.example.com",
        mercure_url="https://api.example.com/.well-known/mercure",
        auth_token="test-token", user_id="42", vault_event_handler=handler,
    )


def test_legacy_topics_remain_compatible_and_native_topic_is_opt_in():
    unconfigured = make_listener()
    assert unconfigured._topic_urls() == ["/cli/42/commands", "/cli/42/ai-tool-calls"]
    assert "supports_vault_events" not in unconfigured._build_handshake()["capabilities"]
    listener = make_listener(AsyncMock())
    assert listener._topic_urls() == ["/cli/42/commands", "/cli/42/ai-tool-calls"]
    listener._vault_topic_advertised = True
    assert listener._topic_urls()[-1] == "/cli/42/vault-events"
    assert listener._build_handshake()["capabilities"]["supports_vault_events"] is True


@pytest.mark.parametrize("topics,expected", [
    (["/cli/42/vault-events"], True), (["/cli/43/vault-events"], False), (None, False),
])
def test_subscriber_topics_require_server_advertisement(topics, expected):
    listener = make_listener(AsyncMock())
    response = MagicMock()
    response.json.return_value = {"token": "test-subscriber-token", "topics": topics}
    listener._authed_request = AsyncMock(return_value=response)
    asyncio.run(listener._fetch_mercure_jwt())
    assert ("/cli/42/vault-events" in listener._topic_urls()) is expected


def test_contract_hint_without_user_id_refreshes_once_and_never_executes():
    handler = AsyncMock()
    listener = make_listener(handler)
    event = {"event_id": "hint-1", "type": "vault.recipient_pending", "data": {"vault_id": "vault-1"}}
    asyncio.run(listener._handle_event(json.dumps(event)))
    asyncio.run(listener._handle_event(json.dumps(event)))
    handler.assert_awaited_once_with(event)
    listener._executors.execute.assert_not_awaited()


@pytest.mark.parametrize("event", [
    {"type": "vault.rotated", "user_id": "43", "data": {}},
    {"type": "vault.rotated", "data": "invalid"},
    {"type": "vault.unknown", "data": {}},
    ["invalid"],
])
def test_invalid_or_foreign_hints_cannot_refresh_or_execute(event):
    handler = AsyncMock()
    listener = make_listener(handler)
    asyncio.run(listener._handle_event(json.dumps(event)))
    handler.assert_not_awaited()
    listener._executors.execute.assert_not_awaited()


def test_verification_failure_is_contained_and_does_not_log_sensitive_detail(caplog):
    handler = AsyncMock(side_effect=ValueError("private material"))
    listener = make_listener(handler)
    asyncio.run(listener._handle_event(json.dumps({"type": "vault.rotated", "data": {}})))
    assert "ValueError" in caplog.text
    assert "private material" not in caplog.text
    listener._executors.execute.assert_not_awaited()
