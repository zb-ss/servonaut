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
