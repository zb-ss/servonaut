"""Tests for RelayListener SSE event handling, heartbeat, and reconnect logic."""
from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Guard: skip all tests in this file if httpx/httpx-sse are not installed
httpx = pytest.importorskip("httpx")
pytest.importorskip("httpx_sse")

from servonaut.models.relay_messages import CommandRequest, CommandResponse, CommandType
from servonaut.services.relay_listener import RelayListener

from .relay_fake_server import (
    BASE_URL, MERCURE_URL, FakeRelayServer, HubReply, finishes_within,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_listener(user_id="user-123", executors=None):
    """Return a RelayListener with mocked executors and a fake httpx client."""
    if executors is None:
        executors = MagicMock()
        executors.execute = AsyncMock(
            return_value=CommandResponse(request_id="req-1", status="success", output="ok")
        )
    listener = RelayListener(
        executors=executors,
        base_url="https://app.example.com",
        mercure_url="https://hub.example.com/.well-known/mercure",
        auth_token="tok-abc",
        user_id=user_id,
        heartbeat_interval=30,
    )
    # Attach a mock client so _handle_event / _post_result can be called directly
    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=MagicMock(status_code=200, text=""))
    listener._client = mock_client
    return listener


def make_event_payload(
    req_id="req-1",
    user_id="user-123",
    cmd_type="run_command",
    target="i-abc123",
    payload=None,
    ttl_seconds=60,
):
    """Build a JSON string matching what the Mercure hub would send."""
    data = {
        "id": req_id,
        "user_id": user_id,
        "type": cmd_type,
        "target_server_id": target,
        "payload": payload or {"command": "ls"},
        "ttl_seconds": ttl_seconds,
    }
    return json.dumps(data)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# _handle_event — user_id validation
# ---------------------------------------------------------------------------

class TestHandleEventUserIdValidation:
    def test_matching_user_id_dispatches_to_executor(self):
        listener = make_listener(user_id="user-123")
        data = make_event_payload(user_id="user-123")
        run(listener._handle_event(data))
        listener._executors.execute.assert_called_once()

    def test_mismatched_user_id_rejects_event(self):
        listener = make_listener(user_id="user-123")
        data = make_event_payload(user_id="attacker-456")
        run(listener._handle_event(data))
        listener._executors.execute.assert_not_called()

    def test_missing_user_id_rejects_event(self):
        listener = make_listener(user_id="user-123")
        raw = {
            "id": "req-1",
            # "user_id" intentionally omitted → defaults to ""
            "type": "run_command",
            "target_server_id": "i-abc123",
            "payload": {"command": "ls"},
        }
        run(listener._handle_event(json.dumps(raw)))
        listener._executors.execute.assert_not_called()

    def test_empty_string_user_id_rejects_event(self):
        listener = make_listener(user_id="user-123")
        data = make_event_payload(user_id="")
        run(listener._handle_event(data))
        listener._executors.execute.assert_not_called()


# ---------------------------------------------------------------------------
# _handle_event — valid event dispatching
# ---------------------------------------------------------------------------

class TestHandleEventDispatch:
    def test_valid_event_calls_executor_with_correct_request(self):
        listener = make_listener(user_id="user-123")
        data = make_event_payload(
            req_id="req-42",
            user_id="user-123",
            cmd_type="get_logs",
            target="i-server",
            payload={"log_path": "/var/log/syslog", "lines": 50},
        )
        run(listener._handle_event(data))
        call_args = listener._executors.execute.call_args
        request: CommandRequest = call_args[0][0]
        assert request.id == "req-42"
        assert request.type == CommandType.GET_LOGS
        assert request.target_server_id == "i-server"
        assert request.payload == {"log_path": "/var/log/syslog", "lines": 50}

    def test_post_result_called_after_execution(self):
        listener = make_listener(user_id="user-123")
        data = make_event_payload(user_id="user-123")
        run(listener._handle_event(data))
        listener._client.post.assert_called_once()

    def test_post_result_called_with_correct_url(self):
        listener = make_listener(user_id="user-123")
        listener._executors.execute = AsyncMock(
            return_value=CommandResponse(request_id="req-77", status="success")
        )
        data = make_event_payload(req_id="req-77", user_id="user-123")
        run(listener._handle_event(data))
        post_call = listener._client.post.call_args
        url_arg = post_call[0][0]
        assert url_arg == "https://app.example.com/api/cli/command-result/req-77"

    def test_post_result_called_with_auth_header(self):
        listener = make_listener(user_id="user-123")
        data = make_event_payload(user_id="user-123")
        run(listener._handle_event(data))
        post_call = listener._client.post.call_args
        headers = post_call[1].get("headers", {})
        assert headers.get("Authorization") == "Bearer tok-abc"

    def test_post_result_body_contains_response_fields(self):
        listener = make_listener(user_id="user-123")
        listener._executors.execute = AsyncMock(
            return_value=CommandResponse(
                request_id="req-1", status="success", output="hello"
            )
        )
        data = make_event_payload(user_id="user-123")
        run(listener._handle_event(data))
        post_call = listener._client.post.call_args
        body = post_call[1].get("json", {})
        assert body["status"] == "success"
        assert body["output"] == "hello"

    def test_execution_time_ms_is_set_on_response(self):
        """execution_time_ms must be set via dataclasses.replace after timing the call."""
        captured = []

        async def capture_post(url, *, json, headers, timeout):
            captured.append(json)
            return MagicMock(status_code=200, text="")

        listener = make_listener(user_id="user-123")
        listener._client.post = capture_post
        # Executor returns 0 by default; after replace it should be >= 0
        data = make_event_payload(user_id="user-123")
        run(listener._handle_event(data))
        assert len(captured) == 1
        assert captured[0]["execution_time_ms"] >= 0

    def test_execution_time_ms_nonzero_for_slow_executor(self):
        """For a slow executor, execution_time_ms should be positive."""
        import time

        async def slow_execute(request):
            await asyncio.sleep(0.01)
            return CommandResponse(request_id=request.id, status="success")

        captured = []

        async def capture_post(url, *, json, headers, timeout):
            captured.append(json)
            return MagicMock(status_code=200, text="")

        executors = MagicMock()
        executors.execute = slow_execute
        listener = make_listener(user_id="user-123", executors=executors)
        listener._client.post = capture_post
        data = make_event_payload(user_id="user-123")
        run(listener._handle_event(data))
        assert captured[0]["execution_time_ms"] > 0


# ---------------------------------------------------------------------------
# _handle_event — ttl_seconds parsing
# ---------------------------------------------------------------------------

class TestHandleEventTTLParsing:
    def test_non_integer_ttl_defaults_to_60(self):
        listener = make_listener(user_id="user-123")
        captured_requests = []

        async def capture_execute(request):
            captured_requests.append(request)
            return CommandResponse(request_id=request.id, status="success")

        listener._executors.execute = capture_execute
        raw = {
            "id": "req-1",
            "user_id": "user-123",
            "type": "run_command",
            "target_server_id": "i-abc123",
            "payload": {"command": "ls"},
            "ttl_seconds": "not-a-number",
        }
        run(listener._handle_event(json.dumps(raw)))
        assert captured_requests[0].ttl_seconds == 60

    def test_float_string_ttl_defaults_to_60(self):
        listener = make_listener(user_id="user-123")
        captured_requests = []

        async def capture_execute(request):
            captured_requests.append(request)
            return CommandResponse(request_id=request.id, status="success")

        listener._executors.execute = capture_execute
        raw = {
            "id": "req-1",
            "user_id": "user-123",
            "type": "run_command",
            "target_server_id": "i-abc123",
            "payload": {"command": "ls"},
            "ttl_seconds": "30.5",
        }
        run(listener._handle_event(json.dumps(raw)))
        assert captured_requests[0].ttl_seconds == 60

    def test_none_ttl_defaults_to_60(self):
        listener = make_listener(user_id="user-123")
        captured_requests = []

        async def capture_execute(request):
            captured_requests.append(request)
            return CommandResponse(request_id=request.id, status="success")

        listener._executors.execute = capture_execute
        raw = {
            "id": "req-1",
            "user_id": "user-123",
            "type": "run_command",
            "target_server_id": "i-abc123",
            "payload": {"command": "ls"},
            "ttl_seconds": None,
        }
        run(listener._handle_event(json.dumps(raw)))
        assert captured_requests[0].ttl_seconds == 60

    def test_valid_integer_ttl_used_as_is(self):
        listener = make_listener(user_id="user-123")
        captured_requests = []

        async def capture_execute(request):
            captured_requests.append(request)
            return CommandResponse(request_id=request.id, status="success")

        listener._executors.execute = capture_execute
        data = make_event_payload(user_id="user-123", ttl_seconds=120)
        run(listener._handle_event(data))
        assert captured_requests[0].ttl_seconds == 120


# ---------------------------------------------------------------------------
# _post_result
# ---------------------------------------------------------------------------

class TestPostResult:
    def test_posts_to_correct_endpoint(self):
        listener = make_listener()
        response = CommandResponse(request_id="req-999", status="success")
        run(listener._post_result(response))
        listener._client.post.assert_called_once()
        url_arg = listener._client.post.call_args[0][0]
        assert url_arg == "https://app.example.com/api/cli/command-result/req-999"

    def test_includes_all_response_fields_in_body(self):
        listener = make_listener()
        response = CommandResponse(
            request_id="req-5",
            status="error",
            output="",
            error_message="SSH failed",
            execution_time_ms=150,
        )
        run(listener._post_result(response))
        body = listener._client.post.call_args[1]["json"]
        assert body["request_id"] == "req-5"
        assert body["status"] == "error"
        assert body["error_message"] == "SSH failed"
        assert body["execution_time_ms"] == 150

    def test_does_not_raise_on_http_error(self):
        """A failed POST must be silently swallowed (logged, not raised)."""
        listener = make_listener()
        listener._client.post = AsyncMock(side_effect=Exception("network error"))
        response = CommandResponse(request_id="req-1", status="success")
        # Should not raise
        run(listener._post_result(response))

    def test_does_not_raise_on_4xx_status(self):
        listener = make_listener()
        mock_resp = MagicMock(status_code=404, text="Not found")
        listener._client.post = AsyncMock(return_value=mock_resp)
        response = CommandResponse(request_id="req-1", status="success")
        run(listener._post_result(response))  # no exception raised


# ---------------------------------------------------------------------------
# stop() / _running flag
# ---------------------------------------------------------------------------

class TestStop:
    def test_stop_sets_running_false(self):
        listener = make_listener()
        listener._running = True
        listener.stop()
        assert listener._running is False

    def test_stop_is_idempotent(self):
        listener = make_listener()
        listener.stop()
        listener.stop()
        assert listener._running is False


# ---------------------------------------------------------------------------
# Token-source contract: callable provider must be re-invoked every call so
# OAuth refresh rotations are picked up live (was capturing-at-construction,
# which produced 401s ~30 min into a session and caused the server's
# cli_connected key to expire — surfacing as "CLI not connected" to chat).
# ---------------------------------------------------------------------------


class TestHeartbeatSessionExpired:
    """A 401/403 from the heartbeat means the OAuth bearer is bad —
    rotated past validity, revoked, or the user logged out elsewhere.
    The listener must fire on_session_expired so the indicator stops
    showing 'connected' instead of just logging warnings forever
    (that was the user-reported bug)."""

    def _listener_with_hook(self, hook):
        listener = RelayListener(
            executors=MagicMock(),
            base_url="https://app.example.com",
            mercure_url="https://hub.example.com/.well-known/mercure",
            auth_token="tok-abc",
            user_id="user-123",
            # 0s interval so the 2xx-loop test doesn't hang waiting for
            # the next heartbeat tick after we set _running=False.
            heartbeat_interval=0,
            on_session_expired=hook,
        )
        listener._client = MagicMock()
        return listener

    def test_401_fires_session_expired_hook(self):
        fired = asyncio.Event()
        async def hook():
            fired.set()
        listener = self._listener_with_hook(hook)
        listener._client.post = AsyncMock(
            return_value=MagicMock(status_code=401, text="Access Denied"),
        )
        listener._running = True

        async def run_one_tick():
            # Drive a single iteration of the heartbeat loop and ensure
            # it returns instead of looping forever.
            await asyncio.wait_for(listener._heartbeat_loop(), timeout=2)

        run(run_one_tick())
        assert fired.is_set(), "on_session_expired must be fired on 401"

    def test_403_fires_session_expired_hook(self):
        fired = asyncio.Event()
        async def hook():
            fired.set()
        listener = self._listener_with_hook(hook)
        listener._client.post = AsyncMock(
            return_value=MagicMock(status_code=403, text="Forbidden"),
        )
        listener._running = True
        run(asyncio.wait_for(listener._heartbeat_loop(), timeout=2))
        assert fired.is_set()

    def test_session_expired_returns_from_loop(self):
        """The heartbeat must STOP the loop after firing the hook —
        otherwise it'd keep posting a known-bad bearer at 30s intervals."""
        async def hook():
            pass
        listener = self._listener_with_hook(hook)
        listener._client.post = AsyncMock(
            return_value=MagicMock(status_code=401, text="Unauthenticated"),
        )
        listener._running = True
        # If the loop didn't return, this would hit the 2s wait_for timeout.
        run(asyncio.wait_for(listener._heartbeat_loop(), timeout=2))

    def test_session_expired_hook_fires_only_once(self):
        """Multiple 401s in the same listener lifetime must not bombard
        the manager with repeat callbacks."""
        call_count = 0
        async def hook():
            nonlocal call_count
            call_count += 1
        listener = self._listener_with_hook(hook)
        listener._client.post = AsyncMock(
            return_value=MagicMock(status_code=401, text="bad"),
        )
        listener._running = True
        run(asyncio.wait_for(listener._heartbeat_loop(), timeout=2))
        # Manually invoke the helper a second time as if the loop had
        # iterated further before returning.
        run(listener._safe_fire_session_expired())
        assert call_count == 1

    def test_401_with_successful_refresh_does_not_fire_session_expired(self):
        """When a refresh_callback rotates the bearer successfully on a
        401, the retried heartbeat with the new token wins and the
        listener stays connected. This is the bug that caused users to
        see "session expired" on CLI restart after the 1h access TTL —
        the listener fired the hook before refresh got a chance."""
        fired = asyncio.Event()
        async def hook():
            fired.set()

        # Token provider rotates as if AuthService.refresh_token() ran.
        current = {"tok": "stale"}
        async def refresh():
            current["tok"] = "fresh"
            return True

        listener = RelayListener(
            executors=MagicMock(),
            base_url="https://app.example.com",
            mercure_url="https://hub.example.com/.well-known/mercure",
            auth_token=lambda: current["tok"],
            user_id="user-123",
            heartbeat_interval=0,
            on_session_expired=hook,
            refresh_callback=refresh,
        )
        listener._client = MagicMock()
        # First call: 401 (stale token). Subsequent calls: 200 (fresh
        # token). The loop is interval=0 so it iterates many times before
        # we cancel — keeping 200s flowing after the retry avoids
        # spurious "Heartbeat failed" warnings tripping the test.
        call_log: list[int] = []

        async def post_response(*_args, **kwargs):
            call_log.append(kwargs["headers"]["Authorization"])
            if len(call_log) == 1:
                return MagicMock(status_code=401, text="Access Denied")
            return MagicMock(status_code=200, text="")

        listener._client.post = AsyncMock(side_effect=post_response)
        listener._on_connected = AsyncMock()
        listener._running = True

        async def driver():
            async def stop_after_retry():
                # Give the heartbeat one tick to fire (401 + retry 200),
                # then end the loop so the test doesn't hang.
                await asyncio.sleep(0.05)
                listener._running = False
            await asyncio.gather(listener._heartbeat_loop(), stop_after_retry())

        run(driver())
        assert not fired.is_set(), (
            "on_session_expired must NOT fire when the refresh succeeded "
            "and the retried request returned 2xx"
        )
        # First request carried the stale bearer; the retry (and every
        # subsequent tick) carried the rotated bearer.
        assert call_log[0] == "Bearer stale"
        assert call_log[1] == "Bearer fresh"

    def test_401_with_failed_refresh_still_fires_session_expired(self):
        """If refresh_callback reports False (refresh_token revoked), the
        listener must still fire on_session_expired — a stuck listener is
        a worse bug than the original."""
        fired = asyncio.Event()
        async def hook():
            fired.set()
        async def refresh():
            return False  # invalid_grant or transient — caller stops.

        listener = RelayListener(
            executors=MagicMock(),
            base_url="https://app.example.com",
            mercure_url="https://hub.example.com/.well-known/mercure",
            auth_token=lambda: "stale",
            user_id="user-123",
            heartbeat_interval=0,
            on_session_expired=hook,
            refresh_callback=refresh,
        )
        listener._client = MagicMock()
        listener._client.post = AsyncMock(
            return_value=MagicMock(status_code=401, text="bad"),
        )
        listener._running = True
        run(asyncio.wait_for(listener._heartbeat_loop(), timeout=2))
        assert fired.is_set()

    def test_2xx_does_not_fire_session_expired(self):
        called = False
        async def hook():
            nonlocal called
            called = True
        listener = self._listener_with_hook(hook)
        listener._client.post = AsyncMock(
            return_value=MagicMock(status_code=200, text=""),
        )
        listener._on_connected = AsyncMock()
        listener._running = True

        async def driver():
            async def stop_after_one():
                await asyncio.sleep(0.01)
                listener._running = False
            await asyncio.gather(listener._heartbeat_loop(), stop_after_one())
        run(driver())
        assert called is False


class TestTokenProviderRotation:
    def _listener_with_provider(self, provider):
        listener = RelayListener(
            executors=MagicMock(),
            base_url="https://app.example.com",
            mercure_url="https://hub.example.com/.well-known/mercure",
            auth_token=provider,
            user_id="user-123",
            heartbeat_interval=30,
        )
        listener._client = MagicMock()
        listener._client.post = AsyncMock(
            return_value=MagicMock(status_code=200, text="")
        )
        listener._client.get = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                json=lambda: {"token": "mercure-jwt"},
            )
        )
        # `_fetch_mercure_jwt` calls `raise_for_status()` on the response.
        listener._client.get.return_value.raise_for_status = MagicMock()
        return listener

    def test_string_token_remains_supported_for_headless_callers(self):
        """The headless `--relay` launcher passes a string from an env
        var. That path must keep working — the change is additive."""
        listener = make_listener()  # uses auth_token="tok-abc"
        assert listener._get_auth_token() == "tok-abc"

    def test_callable_provider_invoked_on_each_call(self):
        """Each call to `_get_auth_token()` must re-invoke the provider
        so a token rotation between heartbeats is picked up."""
        tokens = ["token-1", "token-2", "token-3"]
        provider = MagicMock(side_effect=lambda: tokens.pop(0))
        listener = self._listener_with_provider(provider)

        assert listener._get_auth_token() == "token-1"
        assert listener._get_auth_token() == "token-2"
        assert listener._get_auth_token() == "token-3"
        assert provider.call_count == 3

    def test_heartbeat_picks_up_rotated_token(self):
        """The acceptance test for the bug: send two heartbeats with a
        rotation between them; the second POST's Authorization header
        must reflect the rotated bearer."""
        current = {"token": "old-token"}
        provider = lambda: current["token"]
        listener = self._listener_with_provider(provider)

        async def one_heartbeat():
            url = f"{listener._base_url}/api/cli/heartbeat"
            await listener._client.post(
                url,
                json={"client_id": listener._client_id},
                headers={"Authorization": f"Bearer {listener._get_auth_token()}"},
                timeout=10.0,
            )

        run(one_heartbeat())
        first_auth = listener._client.post.call_args.kwargs["headers"]["Authorization"]
        assert first_auth == "Bearer old-token"

        # Simulate OAuth refresh rotating the access token.
        current["token"] = "new-token"

        run(one_heartbeat())
        second_auth = listener._client.post.call_args.kwargs["headers"]["Authorization"]
        assert second_auth == "Bearer new-token"

    def test_post_result_uses_current_token(self):
        """`_post_result` reads through the provider too — same fix."""
        current = {"token": "initial"}
        listener = self._listener_with_provider(lambda: current["token"])

        response = CommandResponse(request_id="req-1", status="success")
        run(listener._post_result(response))
        first_auth = listener._client.post.call_args.kwargs["headers"]["Authorization"]
        assert first_auth == "Bearer initial"

        current["token"] = "rotated"
        run(listener._post_result(response))
        second_auth = listener._client.post.call_args.kwargs["headers"]["Authorization"]
        assert second_auth == "Bearer rotated"

    def test_mercure_jwt_fetch_uses_current_token(self):
        """The JWT-mint endpoint authenticates with the OAuth bearer
        too. Without this, the Mercure SSE subscription would lose its
        ability to refresh JWTs after rotation."""
        current = {"token": "first-bearer"}
        listener = self._listener_with_provider(lambda: current["token"])

        async def fetch():
            await listener._fetch_mercure_jwt()

        run(fetch())
        first_auth = listener._client.get.call_args.kwargs["headers"]["Authorization"]
        assert first_auth == "Bearer first-bearer"

        current["token"] = "second-bearer"
        run(fetch())
        second_auth = listener._client.get.call_args.kwargs["headers"]["Authorization"]
        assert second_auth == "Bearer second-bearer"

    def test_empty_token_raises_runtime_error(self):
        """When the user logs out (provider returns None) we surface a
        clear error instead of sending `Bearer None` to the backend."""
        listener = self._listener_with_provider(lambda: None)
        with pytest.raises(RuntimeError, match="auth token is empty"):
            listener._get_auth_token()

    def test_provider_exception_wrapped_in_runtime_error(self):
        listener = self._listener_with_provider(
            MagicMock(side_effect=ValueError("boom"))
        )
        with pytest.raises(RuntimeError, match="token provider raised"):
            listener._get_auth_token()


# ---------------------------------------------------------------------------
# _handle_event — non-relay CommandType (AI tool calls mirrored onto channel)
# ---------------------------------------------------------------------------


class TestHandleEventUnknownCommandType:
    def test_ai_tool_call_type_is_skipped_silently_not_errored(self, caplog):
        # Backend currently publishes AI tool calls (ssh_exec_readonly, etc.) on
        # /cli/{user_id}/commands too. Those belong to ai_tool_bridge — relay
        # listener must skip them without raising an ERROR log line.
        listener = make_listener(user_id="user-123")
        data = make_event_payload(cmd_type="ssh_exec_readonly", payload={"command": "ls"})
        with caplog.at_level("DEBUG", logger="servonaut.services.relay_listener"):
            run(listener._handle_event(data))
        # Executor NOT invoked — this isn't ours to run.
        listener._executors.execute.assert_not_called()
        # No ERROR log either — the old behaviour was "Failed to handle event".
        error_records = [r for r in caplog.records if r.levelname == "ERROR"]
        assert not error_records, f"unexpected ERROR logs: {[r.message for r in error_records]}"

    def test_unknown_command_type_is_skipped_silently(self):
        # Future-proof: any type we don't yet recognise should be ignored, not
        # errored. Catches CLI-running-older-than-backend at a deploy boundary.
        listener = make_listener(user_id="user-123")
        data = make_event_payload(cmd_type="future_unknown_verb", payload={"foo": "bar"})
        run(listener._handle_event(data))
        listener._executors.execute.assert_not_called()


# ---------------------------------------------------------------------------
# Dual-topic subscription + dedup (PR #74 — servonaut.dev 2026-05-24)
# ---------------------------------------------------------------------------


class TestDualTopicSubscription:
    def test_topic_urls_includes_both_legacy_and_new(self):
        listener = make_listener(user_id="user-123")
        urls = listener._topic_urls()
        assert urls == [
            "/cli/user-123/commands",
            "/cli/user-123/ai-tool-calls",
        ]

    def test_topic_suffixes_are_locked(self):
        # Locked dual-publish contract — any reorder/rename here breaks
        # cross-team alignment with servonaut.dev's ToolDispatcher.
        from servonaut.services.relay_listener import RelayListener
        assert RelayListener._TOPIC_SUFFIXES == ("commands", "ai-tool-calls")


class TestExtractDedupKey:
    def test_prefers_top_level_tool_call_id(self):
        from servonaut.services.relay_listener import RelayListener
        key = RelayListener._extract_dedup_key(
            {"tool_call_id": "tc-1", "id": "req-1"}
        )
        assert key == "tcid:tc-1"

    def test_falls_back_to_payload_tool_call_id(self):
        from servonaut.services.relay_listener import RelayListener
        key = RelayListener._extract_dedup_key(
            {"id": "req-1", "payload": {"tool_call_id": "tc-2"}}
        )
        assert key == "tcid:tc-2"

    def test_falls_back_to_top_level_id_when_no_tool_call_id(self):
        from servonaut.services.relay_listener import RelayListener
        key = RelayListener._extract_dedup_key(
            {"id": "req-1", "type": "run_command"}
        )
        assert key == "id:req-1"

    def test_returns_none_when_no_idempotency_basis(self):
        from servonaut.services.relay_listener import RelayListener
        assert RelayListener._extract_dedup_key({"foo": "bar"}) is None

    def test_ignores_non_string_keys(self):
        from servonaut.services.relay_listener import RelayListener
        # tool_call_id wrapped in dict accidentally, id present
        assert (
            RelayListener._extract_dedup_key({"tool_call_id": 42, "id": "r-1"})
            == "id:r-1"
        )

    def test_ignores_empty_strings(self):
        from servonaut.services.relay_listener import RelayListener
        assert RelayListener._extract_dedup_key({"tool_call_id": "", "id": ""}) is None


class TestDedupShouldProcess:
    def test_new_key_is_processed(self):
        listener = make_listener()
        assert listener._dedup_should_process("tcid:fresh") is True

    def test_repeat_key_is_skipped(self):
        listener = make_listener()
        assert listener._dedup_should_process("tcid:x") is True
        assert listener._dedup_should_process("tcid:x") is False
        # Still skipped on a 3rd attempt (dual-publish + a rogue retry).
        assert listener._dedup_should_process("tcid:x") is False

    def test_none_key_always_processes(self):
        listener = make_listener()
        # No idempotency basis → better to execute once than zero times.
        assert listener._dedup_should_process(None) is True
        assert listener._dedup_should_process(None) is True

    def test_distinct_keys_dont_collide(self):
        listener = make_listener()
        assert listener._dedup_should_process("tcid:a") is True
        assert listener._dedup_should_process("tcid:b") is True
        assert listener._dedup_should_process("id:a") is True  # prefix matters

    def test_lru_evicts_oldest_when_over_cap(self):
        listener = make_listener()
        listener._DEDUP_MAX_ENTRIES = 3  # shrink for test
        listener._dedup_should_process("k1")
        listener._dedup_should_process("k2")
        listener._dedup_should_process("k3")
        listener._dedup_should_process("k4")  # evicts k1
        # k1 has been forgotten — would be processed again
        assert listener._dedup_should_process("k1") is True
        # k4 still in the set
        assert listener._dedup_should_process("k4") is False

    def test_ttl_eviction_forgets_old_entries(self):
        listener = make_listener()
        listener._DEDUP_TTL_SECONDS = 0  # immediate expiry
        listener._dedup_should_process("k1")
        # Force a non-zero monotonic delta before the next call so the
        # cutoff (= now - 0) strictly exceeds the recorded "first seen".
        import time as _t
        _t.sleep(0.001)
        # On the next call the TTL sweep drops k1, so it processes again.
        assert listener._dedup_should_process("k1") is True


class TestHandleEventDedup:
    def test_duplicate_event_executes_once(self):
        listener = make_listener(user_id="user-123")
        data = make_event_payload(req_id="req-dup")
        run(listener._handle_event(data))
        run(listener._handle_event(data))  # second arrival on the other topic
        assert listener._executors.execute.call_count == 1

    def test_distinct_events_both_execute(self):
        listener = make_listener(user_id="user-123")
        run(listener._handle_event(make_event_payload(req_id="req-1")))
        run(listener._handle_event(make_event_payload(req_id="req-2")))
        assert listener._executors.execute.call_count == 2

    def test_ai_tool_call_dedup_uses_tool_call_id(self):
        listener = make_listener(user_id="user-123")
        # An AI tool call event mirrored onto BOTH topics. The CommandType
        # is unknown so the executor is never called; the dedup record is
        # what we care about — second arrival must NOT log a second skip.
        ai_payload = json.dumps({
            "id": "req-mirror-1",
            "user_id": "user-123",
            "type": "ssh_exec_readonly",
            "target_server_id": "i-1",
            "tool_call_id": "tc-shared",
            "payload": {"command": "ls"},
        })
        run(listener._handle_event(ai_payload))
        # Second event with SAME tool_call_id but DIFFERENT top-level id —
        # demonstrates that tool_call_id is the idempotency anchor, not id.
        ai_payload_2 = json.dumps({
            "id": "req-mirror-2",  # different request id
            "user_id": "user-123",
            "type": "ssh_exec_readonly",
            "target_server_id": "i-1",
            "tool_call_id": "tc-shared",  # same tool call
            "payload": {"command": "ls"},
        })
        # The dedup gate fires on the second call (returns from
        # _dedup_should_process without proceeding to the
        # CommandType-skip path), but neither path invokes the executor
        # for an AI tool call anyway. The behaviour-under-test is that
        # the second event takes the "duplicate" code path, not the
        # "unknown command type" path.
        assert listener._dedup_should_process("tcid:tc-shared") is False
        run(listener._handle_event(ai_payload_2))
        listener._executors.execute.assert_not_called()


# ---------------------------------------------------------------------------
# Lifecycle against an idle hub: stop(), cancellation, rejected subscriptions
# ---------------------------------------------------------------------------


@pytest.fixture
def relay_log(tmp_path, monkeypatch):
    """Redirect the relay lifecycle log to a temp file and return its path."""
    from servonaut.utils import relay_log as relay_log_module

    path = tmp_path / "relay.log"
    monkeypatch.setattr(relay_log_module, "_DEFAULT_LOG_PATH", path)
    return path


def _relay_events(path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def _hub_listener(**kwargs) -> RelayListener:
    kwargs.setdefault("heartbeat_interval", 30)
    return RelayListener(
        executors=MagicMock(),
        base_url=BASE_URL,
        mercure_url=MERCURE_URL,
        auth_token="tok-abc",
        user_id="user-123",
        **kwargs,
    )


async def _stop_once_subscribed(listener, server, stop) -> asyncio.Task:
    """Start ``run()``, wait for the idle subscription, call ``stop``."""
    run_task = asyncio.ensure_future(listener.run())
    await asyncio.wait_for(server.subscribed.wait(), timeout=5)
    await stop()
    return run_task


class TestStopEndsRun:
    """``stop()`` must end ``run()`` even while the SSE read is idle."""

    def test_stop_returns_run_while_subscription_is_idle(self, monkeypatch):
        server = FakeRelayServer()
        server.install(monkeypatch)
        listener = _hub_listener()

        async def stop():
            listener.stop()

        async def scenario():
            run_task = await _stop_once_subscribed(listener, server, stop)
            return await finishes_within(run_task), run_task.cancelled()

        assert run(scenario()) == (True, False)

    def test_stop_from_another_thread_returns_run(self, monkeypatch):
        server = FakeRelayServer()
        server.install(monkeypatch)
        listener = _hub_listener()

        async def stop():
            await asyncio.to_thread(listener.stop)

        async def scenario():
            run_task = await _stop_once_subscribed(listener, server, stop)
            return await finishes_within(run_task)

        assert run(scenario()) is True

    def test_stop_before_run_makes_run_return_at_once(self, monkeypatch):
        server = FakeRelayServer()
        server.install(monkeypatch)
        listener = _hub_listener()
        listener.stop()

        assert run(finishes_within(listener.run())) is True
        assert server.hub_tokens == []
        assert server.heartbeats == 0

    def test_session_expired_hook_that_stops_ends_run(self, monkeypatch):
        """The headless CLI's hook stops the listener from inside the
        heartbeat task; ``run()`` must then return instead of idling."""
        server = FakeRelayServer(
            heartbeat_statuses=[401], heartbeat_waits_for_subscription=True,
        )
        server.install(monkeypatch)
        fired: list[bool] = []

        async def stop_on_expiry():
            fired.append(True)
            listener.stop()

        listener = _hub_listener(on_session_expired=stop_on_expiry)

        assert run(finishes_within(listener.run())) is True
        assert fired == [True]
        assert server.heartbeats == 1


class TestRunCancellation:
    """Cancelling the task that runs ``run()`` must not be swallowed."""

    def test_cancelled_run_ends_cancelled_for_its_awaiting_caller(self, monkeypatch):
        server = FakeRelayServer()
        server.install(monkeypatch)
        listener = _hub_listener()
        after_run: list[bool] = []

        async def owner():
            # Mirrors a manager task that awaits run() in the same task.
            await listener.run()
            after_run.append(True)

        async def scenario():
            owner_task = asyncio.ensure_future(owner())
            await asyncio.wait_for(server.subscribed.wait(), timeout=5)
            owner_task.cancel()
            await asyncio.wait({owner_task}, timeout=5)
            return owner_task.cancelled()

        assert run(scenario()) is True
        assert after_run == []
        assert listener._loop_tasks == ()


class TestHeartbeatTransientAuthFailure:
    """With a ``session_alive`` probe, a heartbeat 401 whose refresh failed
    is final only when the session is really gone."""

    @staticmethod
    def _listener(refresh, session_alive, **kwargs) -> RelayListener:
        return _hub_listener(
            heartbeat_interval=0,
            refresh_callback=refresh,
            session_alive=session_alive,
            **kwargs,
        )

    def test_transient_refresh_failure_keeps_running_and_retries(self, monkeypatch):
        server = FakeRelayServer(heartbeat_statuses=[401, 401, 200])
        server.install(monkeypatch)
        refresh = AsyncMock(return_value=False)  # network error, 429 or 5xx
        expired = AsyncMock()
        connected = asyncio.Event()

        async def on_connected():
            connected.set()

        listener = self._listener(
            refresh, lambda: True,
            on_session_expired=expired, on_connected=on_connected,
        )

        async def scenario():
            run_task = asyncio.ensure_future(listener.run())
            await asyncio.wait_for(connected.wait(), timeout=5)
            listener.stop()
            return await finishes_within(run_task)

        assert run(scenario()) is True
        expired.assert_not_awaited()
        assert server.heartbeat_replies[:3] == [401, 401, 200]
        assert refresh.await_count == 2
        # A handshake rejected by the transient failure is sent again until
        # accepted; only then do plain heartbeats follow.
        assert server.heartbeat_types[:3] == ["cli.handshake"] * 3
        assert "cli.handshake" not in server.heartbeat_types[3:]

    def test_revoked_session_fires_session_expired(self, monkeypatch):
        server = FakeRelayServer(heartbeat_statuses=[401])
        server.install(monkeypatch)
        session = {"alive": True}

        async def refresh():
            session["alive"] = False  # e.g. invalid_grant: the session is gone
            return False

        async def stop_on_expiry():
            listener.stop()

        listener = self._listener(
            refresh, lambda: session["alive"], on_session_expired=stop_on_expiry,
        )

        assert run(finishes_within(listener.run())) is True
        assert server.heartbeats == 1

    def test_session_revoked_elsewhere_fires_session_expired(self, monkeypatch):
        """Another request's refresh revoked the session, so the token
        provider is empty and the heartbeat cannot even be sent."""
        server = FakeRelayServer()
        server.install(monkeypatch)
        expired = asyncio.Event()

        async def on_expired():
            expired.set()
            listener.stop()

        listener = RelayListener(
            executors=MagicMock(),
            base_url=BASE_URL,
            mercure_url=MERCURE_URL,
            auth_token=lambda: None,
            user_id="user-123",
            heartbeat_interval=0,
            on_session_expired=on_expired,
            refresh_callback=AsyncMock(return_value=False),
            session_alive=lambda: False,
        )

        assert run(finishes_within(listener.run())) is True
        assert expired.is_set()
        assert server.heartbeats == 0


class TestHubSubscriptionStatus:
    """httpx-sse does not raise on an error status, so the listener must
    check the response before it reports "connected" or resets its backoff."""

    @staticmethod
    def _run_listen_loop(listener, server, monkeypatch, *, stop_after_waits):
        """Drive ``_listen_forever`` until it schedules ``stop_after_waits``
        reconnect waits; each wait is also added to ``server.timeline``."""
        waits: list[float] = []
        real_sleep = asyncio.sleep

        async def record_wait(delay, *args, **kwargs):
            waits.append(delay)
            server.timeline.append(("wait", delay))
            if len(waits) >= stop_after_waits:
                listener._running = False
            await real_sleep(0)

        async def scenario():
            async with httpx.AsyncClient(transport=server.transport) as client:
                listener._client = client
                listener._running = True
                monkeypatch.setattr(asyncio, "sleep", record_wait)
                return await finishes_within(listener._listen_forever())

        assert run(scenario()) is True
        return waits

    def test_hub_401_refetches_token_and_never_reports_connected(
        self, monkeypatch, capsys, caplog, relay_log,
    ):
        server = FakeRelayServer(hub_replies=[401])
        listener = _hub_listener()

        waits = self._run_listen_loop(
            listener, server, monkeypatch, stop_after_waits=2,
        )

        assert "Connected to relay" not in capsys.readouterr().out
        # Every attempt drops the rejected token and fetches a fresh one.
        assert server.hub_tokens == ["jwt-1", "jwt-2", "jwt-3"]
        assert server.tokens_issued == ["jwt-1", "jwt-2", "jwt-3"]
        assert listener._mercure_jwt is None
        # First rejection retries at once; later ones wait the full backoff
        # instead of restarting from 1 s as an accepted subscription would.
        assert waits == [30, 30]
        # A hub refusing fresh tokens is written to the relay log once.
        rejected = [e for e in _relay_events(relay_log) if e["event"] == "hub_rejected"]
        assert len(rejected) == 1 and rejected[0]["status"] == 401
        # The hub URL carries the token, so it must not reach the logs.
        assert not any(
            "jwt-" in record.getMessage()
            for record in caplog.records
            if record.name.startswith("servonaut")
        )

    def test_accepted_subscription_rearms_the_fresh_token_retry(
        self, monkeypatch, relay_log,
    ):
        server = FakeRelayServer(
            hub_replies=[401, HubReply(200, stays_open=False), 401],
        )
        listener = _hub_listener()

        self._run_listen_loop(listener, server, monkeypatch, stop_after_waits=2)

        assert server.timeline == [
            ("hub", 401, "jwt-1"),
            ("hub", 200, "jwt-2"),  # retried at once with a fresh token
            ("wait", 1),            # the stream ended; backoff was reset
            ("hub", 401, "jwt-2"),
            ("hub", 401, "jwt-3"),  # a new streak: retried at once again
            ("wait", 30),
        ]

    def test_hub_401_then_fresh_token_accepted_connects_once(
        self, monkeypatch, capsys,
    ):
        server = FakeRelayServer(hub_replies=[401, 200])
        server.install(monkeypatch)
        listener = _hub_listener()

        async def stop():
            listener.stop()

        async def scenario():
            run_task = await _stop_once_subscribed(listener, server, stop)
            return await finishes_within(run_task)

        assert run(scenario()) is True
        assert server.hub_tokens == ["jwt-1", "jwt-2"]
        assert capsys.readouterr().out.count("Connected to relay") == 1

    def test_hub_503_backs_off_and_never_reports_connected(
        self, monkeypatch, capsys,
    ):
        server = FakeRelayServer(hub_replies=[503])
        listener = _hub_listener()

        waits = self._run_listen_loop(
            listener, server, monkeypatch, stop_after_waits=2,
        )

        assert "Connected to relay" not in capsys.readouterr().out
        # Exponential backoff, never reset by the rejected attempts.
        assert waits == [1, 2]
        # A hub error is not a token problem: the cached token is reused.
        assert server.tokens_issued == ["jwt-1"]
        assert server.hub_tokens == ["jwt-1", "jwt-1"]

    def test_non_event_stream_200_backs_off_and_never_reports_connected(
        self, monkeypatch, capsys,
    ):
        server = FakeRelayServer(hub_replies=[HubReply(200, content_type="text/html")])
        listener = _hub_listener()

        waits = self._run_listen_loop(
            listener, server, monkeypatch, stop_after_waits=2,
        )

        assert "Connected to relay" not in capsys.readouterr().out
        assert waits == [1, 2]


class TestHeartbeatRejectionOnValidSession:
    """A heartbeat 401/403 that a successful refresh does not cure, on a
    session that stays valid, must not loop silently forever."""

    @staticmethod
    def _listener(**kwargs) -> RelayListener:
        kwargs.setdefault("refresh_callback", AsyncMock(return_value=True))
        return _hub_listener(
            heartbeat_interval=0, session_alive=lambda: True, **kwargs,
        )

    @staticmethod
    async def _run_until(listener, condition) -> bool:
        """Run the listener until ``condition()`` holds, then stop it."""
        run_task = asyncio.ensure_future(listener.run())

        async def reached() -> None:
            while not condition() and not run_task.done():
                await asyncio.sleep(0)

        await asyncio.wait_for(reached(), timeout=5)
        still_running = not run_task.done()
        listener.stop()
        assert await finishes_within(run_task)
        return still_running

    def test_persistent_rejection_is_logged_once_and_retried(
        self, monkeypatch, relay_log, caplog,
    ):
        server = FakeRelayServer(heartbeat_statuses=[200, 401])
        server.install(monkeypatch)
        refresh = AsyncMock(return_value=True)  # refreshes, but cures nothing
        expired = AsyncMock()
        listener = self._listener(
            refresh_callback=refresh, on_session_expired=expired,
        )

        still_running = run(self._run_until(
            listener, lambda: refresh.await_count >= 5,
        ))

        assert still_running is True
        expired.assert_not_awaited()
        rejected = [
            e for e in _relay_events(relay_log) if e["event"] == "heartbeat_rejected"
        ]
        assert len(rejected) == 1
        assert rejected[0]["status"] == 401
        assert rejected[0]["rejections"] == 3
        assert "not delivered" in rejected[0]["detail"]
        assert sum(
            "Relay is not delivering" in record.getMessage()
            for record in caplog.records
        ) == 1

    def test_not_delivering_relay_refreshes_on_every_nth_tick_only(
        self, monkeypatch,
    ):
        """Each refresh rotates the shared pair and spends the auth rate
        limit, so once the relay is reported as not delivering the heartbeat
        refreshes on every third rejected tick instead of on each one."""
        server = FakeRelayServer(heartbeat_statuses=[200, 401])
        server.install(monkeypatch)
        heartbeats_at_refresh: list[int] = []

        async def refresh() -> bool:
            heartbeats_at_refresh.append(server.heartbeats)
            return True

        listener = self._listener(refresh_callback=refresh)

        run(self._run_until(listener, lambda: len(heartbeats_at_refresh) >= 5))

        # Tick 1 is accepted. Ticks 2-4 each post, refresh and post again,
        # and tick 4 raises the alert. Ticks 5 and 6 post once without a
        # refresh; tick 7 refreshes again, then ticks 8 and 9 do not, and
        # tick 10 does.
        assert heartbeats_at_refresh[:5] == [2, 4, 6, 10, 14]

    def test_indicator_hooks_follow_each_streak_and_recovery(
        self, monkeypatch, relay_log,
    ):
        rejected_tick = [401, 401]  # the heartbeat and its post-refresh retry
        server = FakeRelayServer(heartbeat_statuses=(
            [200] + rejected_tick * 3 + [200] + rejected_tick * 3 + [200]
        ))
        server.install(monkeypatch)
        hooks: list[str] = []

        async def on_connected():
            hooks.append("connected")

        async def on_degraded():
            hooks.append("degraded")

        listener = self._listener(
            on_connected=on_connected, on_degraded=on_degraded,
        )

        run(self._run_until(listener, lambda: len(hooks) >= 5))

        assert hooks == [
            "connected", "degraded", "connected", "degraded", "connected",
        ]
        events = [e["event"] for e in _relay_events(relay_log)]
        assert events == [
            "heartbeat_rejected", "heartbeat_accepted",
            "heartbeat_rejected", "heartbeat_accepted",
        ]

    def test_accepted_heartbeat_resets_the_streak(self, monkeypatch, relay_log):
        server = FakeRelayServer(heartbeat_statuses=[
            401, 401, 200, 401, 401, 200,
        ])
        server.install(monkeypatch)
        degraded = AsyncMock()
        listener = self._listener(
            heartbeat_rejection_alert_after=2, on_degraded=degraded,
        )

        run(self._run_until(listener, lambda: server.heartbeats >= 8))

        degraded.assert_not_awaited()
        assert not any(
            e["event"] == "heartbeat_rejected" for e in _relay_events(relay_log)
        )

    @pytest.mark.parametrize("configured", [0, -4, "not-a-number", None])
    def test_invalid_threshold_is_coerced_to_a_usable_value(self, configured):
        listener = _hub_listener(heartbeat_rejection_alert_after=configured)

        assert listener._rejection_alert_after >= 1
