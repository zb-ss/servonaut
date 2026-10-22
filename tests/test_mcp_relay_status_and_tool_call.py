"""Tests for the ``relay_status`` and ``mcp_tool_call`` MCP tools."""
from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

httpx = pytest.importorskip("httpx")

from servonaut.config.schema import AppConfig, MCPConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tools import ServonautTools


API_BASE = "https://api.staging.example.com"
MCP_BASE = "https://mcp.staging.example.com"


def _run(coro):
    return asyncio.run(coro)


def _make_tools(auth_service, guard_level=GuardLevel.STANDARD, **mcp_options):
    config = AppConfig(mcp=MCPConfig(guard_level=guard_level, **mcp_options))
    cm = MagicMock()
    cm.get.return_value = config
    audit = MagicMock()
    audit.log = MagicMock()
    return ServonautTools(
        config_manager=cm,
        aws_service=MagicMock(),
        custom_server_service=MagicMock(),
        cache_service=MagicMock(),
        ssh_service=MagicMock(),
        connection_service=MagicMock(),
        scp_service=MagicMock(),
        guard=CommandGuard(config.mcp),
        audit=audit,
        auth_service=auth_service,
    ), audit


def _authed_stub():
    svc = MagicMock()
    svc.is_authenticated = True
    svc.access_token = "tok"
    svc.plan = "solo"
    svc._token = SimpleNamespace(
        access_token="tok", refresh_token="r",
        expires_at=time.time() + 3600, email="a@b.c", plan="solo",
    )
    svc.refresh_token = AsyncMock(return_value=True)
    return svc


def _install_transport(monkeypatch, handler):
    real = httpx.AsyncClient

    class _Patched(real):
        def __init__(self, *a, **kw):
            kw.pop("transport", None)
            super().__init__(*a, transport=httpx.MockTransport(handler), **kw)

    monkeypatch.setattr(httpx, "AsyncClient", _Patched)


@pytest.fixture(autouse=True)
def _bases(monkeypatch):
    monkeypatch.setenv("SERVONAUT_API_URL", API_BASE)
    monkeypatch.setenv("SERVONAUT_MCP_URL", MCP_BASE)


# ---------------------------------------------------------------------------
# relay_status
# ---------------------------------------------------------------------------

class TestRelayStatus:
    def test_unwraps_backend_body(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/cli/status"
            return httpx.Response(
                200, headers={"Content-Type": "application/json"},
                json={"connected": True, "client_ids": ["host-ab"]},
            )
        _install_transport(monkeypatch, handler)
        tools, _ = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.relay_status()))
        assert result == {"connected": True, "client_ids": ["host-ab"]}

    def test_available_at_the_readonly_tier(self, monkeypatch):
        # A read of the relay's status must not need the api_request tier.
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, headers={"Content-Type": "application/json"},
                json={"connected": False},
            )
        _install_transport(monkeypatch, handler)
        tools, audit = _make_tools(
            auth_service=_authed_stub(), guard_level=GuardLevel.READONLY,
        )

        result = json.loads(_run(tools.relay_status()))

        assert result == {"connected": False}
        assert audit.log.call_args.args[0] == "relay_status"
        assert audit.log.call_args.args[3] is True

    def test_backend_error_propagates_envelope(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("dns boom", request=request)
        _install_transport(monkeypatch, handler)
        tools, _ = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.relay_status()))
        assert result["error"]["code"] == "network_error"

    def test_non_object_body_returns_structured_error(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, headers={"Content-Type": "application/json"},
                json=[1, 2, 3],
            )
        _install_transport(monkeypatch, handler)
        tools, _ = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.relay_status()))
        assert result["error"]["code"] == "unexpected_response"


# ---------------------------------------------------------------------------
# mcp_tool_call
# ---------------------------------------------------------------------------

class _HostedServer:
    """A MockTransport handler speaking the hosted server's MCP transports.

    With ``streamable`` it speaks only Streamable HTTP (so a client that took
    the event stream fails against it): ``POST /mcp`` takes one
    JSON-RPC message and answers it in the response. ``initialize`` answers
    with an ``Mcp-Session-Id`` header that every later request must send back
    with ``MCP-Protocol-Version`` (404 / 400 otherwise); a notification gets
    202; ``GET /mcp`` gets 405; ``DELETE /mcp`` ends the session with 204.

    Without it, ``POST /mcp`` answers ``missing_status`` as a server without
    the endpoint does (a redirect points at ``redirect_to``), and it speaks
    HTTP+SSE: ``GET /mcp/sse`` opens an event stream whose first event names
    ``endpoint``; ``POST /mcp/message`` needs that connection id (400
    otherwise), answers only ``{"status": "accepted"}`` and puts the JSON-RPC
    reply on the stream.

    The request that opens a session (the ``initialize`` POST, or the stream
    GET) answers ``open_statuses`` in turn, then 200.
    """

    CONNECTION_ID = "c1"
    SESSION_ID = "s-1"
    PROTOCOL_VERSION = "2025-06-18"

    def __init__(self, *, streamable=True, open_statuses=(), reply_text="ok", tool_error=None,
                 endpoint=None, silent=False, missing_status=404,
                 redirect_to="https://example.com/mcp"):
        self.streamable = streamable
        self.open_statuses = list(open_statuses)
        self.reply_text = reply_text
        self.tool_error = tool_error
        self.endpoint = endpoint or f"/mcp/message?connection_id={self.CONNECTION_ID}"
        self.silent = silent  # take messages but never answer a tools/call
        self.missing_status = missing_status
        self.redirect_to = redirect_to
        self.requests = []  # every request, in order
        self.opens = []     # the requests that opened (or tried to open) a session
        self.probes = []    # POST /mcp answered as a server without the endpoint
        self.messages = []
        self.sessions_opened = 0
        self.sessions_closed = 0
        self._outbox = None

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/mcp":
            if not self.streamable:
                return self._missing(request)
            return await self._streamable(request)
        if self.streamable:
            return httpx.Response(404)
        if request.method == "GET" and path == "/mcp/sse":
            return self._open_stream(request)
        if request.method == "POST" and path == "/mcp/message":
            return await self._stream_message(request)
        return httpx.Response(404)

    def methods(self):
        return [m.get("method") for m in self.messages]

    def other_hosts(self):
        return [r for r in self.requests if r.url.host != httpx.URL(MCP_BASE).host]

    # Streamable HTTP ----------------------------------------------------

    def _missing(self, request):
        if request.method == "POST":
            self.probes.append(request)
        if 300 <= self.missing_status < 400:
            return httpx.Response(self.missing_status, headers={"Location": self.redirect_to})
        return httpx.Response(self.missing_status, text="Not Found")

    async def _streamable(self, request):
        if request.method == "GET":
            return httpx.Response(405)
        if request.method == "DELETE":
            await asyncio.sleep(0)  # a real request yields; a cancelled one ends here
            if request.headers.get("mcp-session-id") != self.SESSION_ID:
                return httpx.Response(404)
            self.sessions_closed += 1
            return httpx.Response(204)
        message = json.loads(request.content)
        if message.get("method") == "initialize":
            self.opens.append(request)
            status = self.open_statuses.pop(0) if self.open_statuses else 200
            if status != 200:
                return httpx.Response(status, json={"error": "refused"})
        elif request.headers.get("mcp-session-id") != self.SESSION_ID:
            return httpx.Response(404, json={"error": "Unknown session"})
        elif request.headers.get("mcp-protocol-version") != self.PROTOCOL_VERSION:
            return httpx.Response(400, json={"error": "Unsupported protocol version"})
        self.messages.append(message)
        if "id" not in message:
            return httpx.Response(202)
        if message.get("method") == "tools/call" and self.silent:
            await asyncio.Event().wait()
        reply = self._answer(message)
        headers = {}
        if message.get("method") == "initialize":
            self.sessions_opened += 1
            headers["Mcp-Session-Id"] = self.SESSION_ID
        return httpx.Response(200, json=reply, headers=headers)

    # HTTP+SSE -----------------------------------------------------------

    def _open_stream(self, request):
        self.opens.append(request)
        status = self.open_statuses.pop(0) if self.open_statuses else 200
        if status != 200:
            return httpx.Response(status, json={"error": "refused"})
        self._outbox = asyncio.Queue()
        self.sessions_opened += 1
        return httpx.Response(
            200, headers={"Content-Type": "text/event-stream"}, stream=_EventStream(self),
        )

    async def _stream_message(self, request):
        if request.url.params.get("connection_id") != self.CONNECTION_ID:
            return httpx.Response(400, json={"error": "Invalid connection"})
        message = json.loads(request.content)
        self.messages.append(message)
        silent = self.silent and message.get("method") == "tools/call"
        reply = None if silent or "id" not in message else self._answer(message)
        if reply is not None:
            await self._outbox.put(reply)
        return httpx.Response(200, json={"status": "accepted"})

    def _answer(self, message):
        rid, method = message["id"], message.get("method")
        if method == "initialize":
            version = self.PROTOCOL_VERSION if self.streamable else "2024-11-05"
            result = {"protocolVersion": version, "capabilities": {"tools": {}},
                      "serverInfo": {"name": "hosted", "version": "1"}}
        elif method == "tools/call" and self.tool_error is not None:
            return {"jsonrpc": "2.0", "id": rid, "error": self.tool_error}
        elif method == "tools/call":
            result = {"content": [{"type": "text", "text": self.reply_text}], "isError": False}
        else:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32601, "message": "Method not found"}}
        return {"jsonrpc": "2.0", "id": rid, "result": result}


class _EventStream(httpx.AsyncByteStream):
    """The open event stream: the endpoint event, a heartbeat, then replies."""

    def __init__(self, server: _HostedServer) -> None:
        self._server = server

    async def __aiter__(self):
        yield f"event: endpoint\ndata: {self._server.endpoint}\n\n".encode()
        yield b": ping\n\n"
        while True:
            reply = await self._server._outbox.get()
            yield f"event: message\ndata: {json.dumps(reply)}\n\n".encode()

    async def aclose(self) -> None:
        self._server.sessions_closed += 1


@pytest.fixture(params=["streamable-http", "sse"])
def transport(request):
    """The transport the hosted server speaks: Streamable HTTP, or only HTTP+SSE."""
    return request.param


@pytest.fixture
def hosted(monkeypatch, transport):
    """Install a fresh :class:`_HostedServer` (configured by keyword) as the network."""
    pytest.importorskip("mcp")

    def install(**options):
        options.setdefault("streamable", transport == "streamable-http")
        server = _HostedServer(**options)
        _install_transport(monkeypatch, server)
        return server

    return install


class TestMcpToolCall:
    def test_calls_the_tool(self, hosted):
        server = hosted()
        tools, _ = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.mcp_tool_call("cost_report", {"scope": "month"})))

        assert result == {
            "status": 200,
            "response": {"result": {"content": [{"type": "text", "text": "ok"}],
                                    "isError": False}},
        }
        assert {r.headers["authorization"] for r in server.requests} == {"Bearer tok"}
        assert server.methods() == ["initialize", "notifications/initialized", "tools/call"]
        assert server.messages[-1]["params"] == {"name": "cost_report",
                                                 "arguments": {"scope": "month"}}
        # One session per call, closed once the answer is in.
        assert (server.sessions_opened, server.sessions_closed) == (1, 1)

    @pytest.mark.parametrize("transport", ["streamable-http"])
    def test_streamable_http_posts_every_message_to_one_session(self, hosted):
        server = hosted()
        tools, _ = _make_tools(auth_service=_authed_stub())

        _run(tools.mcp_tool_call("cost_report"))

        posts = [r for r in server.requests if r.method == "POST"]
        assert {str(r.url) for r in server.requests} == {f"{MCP_BASE}/mcp"}
        assert len(posts) == 3
        assert all(r.headers["mcp-session-id"] == "s-1" for r in posts[1:])
        assert [r.method for r in server.requests if r.method != "GET"][-1] == "DELETE"
        assert not any(r.url.path == "/mcp/sse" for r in server.requests)

    @pytest.mark.parametrize("transport", ["sse"])
    @pytest.mark.parametrize("missing_status", [404, 405, 308, 301])
    def test_server_without_the_endpoint_gets_the_event_stream(self, hosted, missing_status):
        server = hosted(missing_status=missing_status)
        tools, audit = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.mcp_tool_call("ping")))

        assert result["response"]["result"]["content"][0]["text"] == "ok"
        assert [str(r.url) for r in server.probes] == [f"{MCP_BASE}/mcp"]
        assert [str(r.url) for r in server.opens] == [f"{MCP_BASE}/mcp/sse"]
        # The redirect is not followed: nothing, the token least of all,
        # goes to the host it names.
        assert server.other_hosts() == []
        assert audit.log.call_args.args[3] is True

    @pytest.mark.parametrize("transport", ["streamable-http"])
    @pytest.mark.parametrize("status, code", [
        (402, "http_error"), (429, "connection_limit"),
        (500, "http_error"), (503, "http_error"),
    ])
    def test_other_refusals_of_the_session_do_not_fall_back(self, hosted, status, code):
        server = hosted(open_statuses=[status])
        tools, _ = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.mcp_tool_call("ping")))

        assert result["error"]["code"] == code
        assert not any(r.url.path.startswith("/mcp/sse") for r in server.requests)

    def test_a_redirect_within_the_origin_is_followed(self, monkeypatch):
        pytest.importorskip("mcp")
        import servonaut.mcp.hosted_call as hosted_call

        server = _HostedServer()

        async def handler(request):
            # A trailing-slash normalisation on the server's own origin.
            if request.url.path == "/mcp/":
                return httpx.Response(308, headers={"Location": f"{MCP_BASE}/mcp"})
            return await server(request)
        _install_transport(monkeypatch, handler)
        monkeypatch.setattr(hosted_call, "STREAMABLE_HTTP_PATH", "/mcp/")
        tools, _ = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.mcp_tool_call("ping")))

        assert result["response"]["result"]["isError"] is False
        assert {r.url.path for r in server.requests} == {"/mcp"}
        assert server.sessions_closed == 1

    def test_none_arguments_becomes_empty_object(self, hosted):
        server = hosted()
        tools, _ = _make_tools(auth_service=_authed_stub())

        _run(tools.mcp_tool_call("list_tools"))

        assert server.messages[-1]["params"]["arguments"] == {}

    @pytest.mark.parametrize("error", [
        {"code": -32602, "message": "Unknown tool: nope"},
        {"code": -32050, "message": "Capacity exceeded", "data": {"retry_after": 5}},
    ], ids=["unknown-tool", "capacity-refused"])
    def test_json_rpc_error_is_returned_not_raised(self, hosted, error):
        hosted(tool_error=error)
        tools, audit = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.mcp_tool_call("nope")))

        assert result == {"status": 200, "response": {"error": error}}
        args = audit.log.call_args.args
        assert args[1]["rpc_error"] == error["code"]
        assert args[3] is True  # the call ran; the server said no

    def test_401_on_opening_triggers_refresh_and_retry(self, hosted):
        server = hosted(open_statuses=[401])
        svc = _authed_stub()

        async def _refresh():
            svc.access_token = "tok2"
            return True
        svc.refresh_token = AsyncMock(side_effect=_refresh)
        tools, _ = _make_tools(auth_service=svc)

        result = json.loads(_run(tools.mcp_tool_call("ping")))

        assert result["response"]["result"]["content"][0]["text"] == "ok"
        svc.refresh_token.assert_awaited_once()
        assert [r.headers["authorization"] for r in server.opens] == [
            "Bearer tok", "Bearer tok2",
        ]
        assert server.methods().count("tools/call") == 1

    def test_401_when_the_refresh_fails(self, hosted):
        server = hosted(open_statuses=[401])
        svc = _authed_stub()
        svc.refresh_token = AsyncMock(return_value=False)
        tools, audit = _make_tools(auth_service=svc)

        result = json.loads(_run(tools.mcp_tool_call("ping")))

        assert result["error"]["code"] == "unauthorized"
        assert len(server.opens) == 1 and server.messages == []
        assert audit.log.call_args.args[3:] == (False, "unauthorized")

    @pytest.mark.parametrize("status, code", [
        (429, "connection_limit"), (503, "http_error"),
    ])
    def test_refused_session_is_a_structured_error(self, hosted, status, code):
        server = hosted(open_statuses=[status])
        tools, audit = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.mcp_tool_call("ping")))

        assert result["error"]["code"] == code
        # No session of this process was closing, so nothing is retried.
        assert len(server.opens) == 1
        assert audit.log.call_args.args[3:] == (False, code)

    def test_refused_session_leaves_no_channel_open(self, hosted):
        # The SDK's clients close every channel on a refused session from
        # 1.30.0 on, the floor the package declares.
        import gc
        import warnings

        hosted(open_statuses=[503])
        tools, _ = _make_tools(auth_service=_authed_stub())

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            _run(tools.mcp_tool_call("ping"))
            gc.collect()

        assert [str(w.message) for w in caught if w.category is ResourceWarning] == []

    def test_call_right_after_another_waits_for_the_freed_slot(self, hosted):
        server = hosted()
        tools, audit = _make_tools(
            auth_service=_authed_stub(),
            hosted_connect_retry_seconds=5.0, hosted_connect_retry_interval_seconds=0.01,
        )

        async def two_calls():
            first = await tools.mcp_tool_call("ping")
            # The service still counts the session the first call closed.
            server.open_statuses = [429, 429]
            return first, await tools.mcp_tool_call("ping")

        first, second = (json.loads(answer) for answer in _run(two_calls()))

        assert first["response"]["result"]["isError"] is False
        assert second["response"]["result"]["isError"] is False
        assert len(server.opens) == 4
        assert server.methods().count("tools/call") == 2
        assert audit.log.call_args.args[3] is True

    def test_slot_wait_gives_up_after_the_retry_window(self, hosted):
        server = hosted()
        tools, audit = _make_tools(
            auth_service=_authed_stub(),
            hosted_connect_retry_seconds=0.5, hosted_connect_retry_interval_seconds=0.05,
        )

        async def two_calls():
            await tools.mcp_tool_call("ping")
            server.open_statuses = [429] * 1000
            started = time.monotonic()
            return await tools.mcp_tool_call("ping"), time.monotonic() - started

        answer, took = _run(two_calls())

        assert json.loads(answer)["error"]["code"] == "connection_limit"
        assert len(server.opens) - 1 >= 2  # retried ...
        assert took < 3.0                  # ... but not past the window
        assert audit.log.call_args.args[3:] == (False, "connection_limit")

    def test_zero_retry_window_turns_the_slot_wait_off(self, hosted):
        server = hosted()
        tools, _ = _make_tools(auth_service=_authed_stub(), hosted_connect_retry_seconds=0)

        async def two_calls():
            await tools.mcp_tool_call("ping")
            server.open_statuses = [429]
            return await tools.mcp_tool_call("ping")

        assert json.loads(_run(two_calls()))["error"]["code"] == "connection_limit"
        assert len(server.opens) == 2

    def test_other_refusals_after_a_call_are_not_retried(self, hosted):
        server = hosted()
        tools, _ = _make_tools(
            auth_service=_authed_stub(), hosted_connect_retry_interval_seconds=0.01,
        )

        async def two_calls():
            await tools.mcp_tool_call("ping")
            server.open_statuses = [503]
            return await tools.mcp_tool_call("ping")

        assert json.loads(_run(two_calls()))["error"]["code"] == "http_error"
        assert len(server.opens) == 2

    def test_refreshed_token_also_waits_for_the_freed_slot(self, hosted):
        server = hosted()
        svc = _authed_stub()

        async def _refresh():
            svc.access_token = "tok2"
            return True
        svc.refresh_token = AsyncMock(side_effect=_refresh)
        tools, _ = _make_tools(auth_service=svc, hosted_connect_retry_interval_seconds=0.01)

        async def two_calls():
            await tools.mcp_tool_call("ping")
            server.open_statuses = [401, 429]
            return await tools.mcp_tool_call("ping")

        assert json.loads(_run(two_calls()))["response"]["result"]["isError"] is False
        svc.refresh_token.assert_awaited_once()
        assert [r.headers["authorization"] for r in server.opens] == [
            "Bearer tok", "Bearer tok", "Bearer tok2", "Bearer tok2",
        ]

    def test_no_answer_times_out_and_closes_the_session(self, hosted):
        server = hosted(silent=True)
        tools, _ = _make_tools(auth_service=_authed_stub(), hosted_call_timeout_seconds=0.5)

        started = time.monotonic()
        result = json.loads(_run(tools.mcp_tool_call("slow")))

        assert result["error"]["code"] == "timeout"
        assert "0.5 seconds" in result["error"]["message"]
        assert time.monotonic() - started < 3.0
        # Over Streamable HTTP that is the DELETE, which frees the slot at once.
        assert server.sessions_closed == server.sessions_opened == 1

    @pytest.mark.parametrize("transport", ["sse"])
    @pytest.mark.parametrize("endpoint", [
        pytest.param("https://collector.example.com/mcp/message?connection_id=c1", id="another-host"),
        pytest.param(f"{MCP_BASE}:8443/mcp/message?connection_id=c1", id="another-port"),
        pytest.param(
            MCP_BASE.replace("https://", "http://") + "/mcp/message?connection_id=c1",
            id="plain-http",
        ),
        pytest.param("//collector.example.com/mcp/message?connection_id=c1", id="scheme-relative"),
        pytest.param(
            MCP_BASE.replace("https://", "https://u:p@") + "/mcp/message?connection_id=c1",
            id="credentials",
        ),
    ])
    def test_endpoint_on_another_origin_gets_no_token(self, hosted, endpoint):
        server = hosted(endpoint=endpoint)
        tools, _ = _make_tools(auth_service=_authed_stub(), hosted_call_timeout_seconds=0.5)

        result = json.loads(_run(tools.mcp_tool_call("ping")))

        assert "error" in result
        assert [r for r in server.requests if r.url.path == "/mcp/message"] == []

    def test_network_error_is_structured(self, monkeypatch):
        pytest.importorskip("mcp")

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)
        _install_transport(monkeypatch, handler)
        tools, _ = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.mcp_tool_call("ping")))

        assert result["error"]["code"] == "network_error"

    def test_oversized_answer_is_refused(self, hosted, monkeypatch):
        import servonaut.mcp.tools as tools_module
        monkeypatch.setattr(tools_module, "_MAX_RESPONSE_BYTES", 1000)
        hosted(reply_text="x" * 2000)
        tools, _ = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.mcp_tool_call("cost_report")))

        assert result["error"]["code"] == "response_too_large"

    def test_not_logged_in(self):
        svc = MagicMock()
        svc.is_authenticated = False
        tools, _ = _make_tools(auth_service=svc)
        result = json.loads(_run(tools.mcp_tool_call("deploy")))
        assert result["error"]["code"] == "not_logged_in"

    def test_missing_mcp_package(self, monkeypatch):
        import sys
        monkeypatch.setitem(sys.modules, "mcp", None)
        tools, audit = _make_tools(auth_service=_authed_stub())

        result = json.loads(_run(tools.mcp_tool_call("ping")))

        assert result["error"]["code"] == "mcp_missing"
        assert audit.log.call_args.args[3:] == (False, "mcp_missing")

    def test_audit_entry_recorded_without_the_token(self, hosted):
        hosted()
        tools, audit = _make_tools(auth_service=_authed_stub())

        _run(tools.mcp_tool_call("cost_report"))

        audit.log.assert_called_once()
        args = audit.log.call_args.args
        assert args[0] == "mcp_tool_call"
        assert args[1]["name"] == "cost_report"
        assert args[1]["has_arguments"] is False
        assert args[1]["status"] == 200
        assert "rpc_error" not in args[1]
        assert args[3] is True
        assert "tok" not in json.dumps(audit.log.call_args, default=str)


class TestHostedCallSettings:
    @pytest.mark.parametrize("value, allow_zero, expected", [
        (2, False, 2.0), (0.25, False, 0.25), (0, True, 0.0),
        (0, False, 7.0), (-1, True, 7.0), (True, False, 7.0),
        ("5", False, 7.0), (None, False, 7.0),
    ])
    def test_unusable_values_fall_back_to_the_default(self, value, allow_zero, expected):
        from servonaut.mcp.tools import _seconds

        assert _seconds(value, 7.0, allow_zero=allow_zero) == expected


class TestHostedCallErrors:
    """``hosted_call`` flattens the SDK's task-group exception groups."""

    def test_status_error_inside_a_group_is_found(self):
        from servonaut.mcp.hosted_call import _classify, _ExceptionGroup

        request = httpx.Request("GET", f"{MCP_BASE}/mcp/sse")
        status_error = httpx.HTTPStatusError(
            "401", request=request, response=httpx.Response(401, request=request),
        )
        group = _ExceptionGroup("outer", [RuntimeError("x"), _ExceptionGroup("inner", [status_error])])

        error = _classify(group)

        assert (error.code, error.status) == ("unauthorized", 401)

    def test_anything_else_is_a_protocol_error(self):
        from servonaut.mcp.hosted_call import _classify

        assert _classify(RuntimeError("bad frame")).code == "protocol_error"
