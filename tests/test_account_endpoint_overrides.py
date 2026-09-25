"""``SERVONAUT_API_URL``, ``SERVONAUT_MCP_URL`` and the relay URLs follow the endpoint rule.

Requests to every one of them carry a token: the OAuth bearer for the API, the
hosted MCP server and the relay's ``base_url``, the Mercure subscriber token
for ``mercure_url``. So each must be ``https://``, or ``http://`` to a loopback
host, with no embedded credentials, whitespace or backslashes.

A refused value fails before any request is built: nothing is sent, the
production service is never used in its place, and the error names the
variable or config key, never the URL (which could carry credentials).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from types import SimpleNamespace
from typing import Any, Callable, List
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from textual.app import App
from textual.widgets import Button, Input

from servonaut.config.schema import AppConfig, MCPConfig, RelayConfig
from servonaut.mcp import remote_client
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tools import ServonautTools
from servonaut.services import api_client, auth_service
from servonaut.services.api_client import APIClient, APIError, EndpointConfigError
from servonaut.services.auth_service import AuthService, AuthToken
from servonaut.services.relay_manager import RelayManager, RelayState
from servonaut.utils.endpoints import (
    API_URL_ENV,
    MCP_URL_ENV,
    EndpointOverrideError,
    endpoint_override_errors,
    validate_relay_urls,
)
from tests._hermetic_app import run_hermetic_app

# A credential embedded in a refused URL. It must never reach an error message.
_SECRET = "hunter2"

# (value, normalised base) pairs every reader must accept.
_ACCEPTED = [
    ("https://staging.example.com", "https://staging.example.com"),
    ("https://staging.example.com/", "https://staging.example.com"),
    ("https://staging.example.com/api", "https://staging.example.com/api"),
    ("http://127.0.0.1:8000", "http://127.0.0.1:8000"),
    ("http://localhost:8000", "http://localhost:8000"),
    ("http://[::1]:8000", "http://[::1]:8000"),
]

# (value, fragment of the refusal) pairs every reader must refuse.
_REFUSED = [
    ("http://staging.example.com", "must be an https:// URL"),
    ("http://10.0.0.8:8000", "must be an https:// URL"),
    (f"https://deploy:{_SECRET}@staging.example.com", "must not contain credentials"),
    (f"http://deploy:{_SECRET}@127.0.0.1:8000", "must not contain credentials"),
    # urlsplit sees host 127.0.0.1; an HTTP client would connect to example.com.
    ("http://staging.example.com\\@127.0.0.1", "backslashes"),
    ("staging.example.com", "absolute URL with a host"),
    # Callers append paths: "?" or "#" would swallow them into a query/fragment.
    ("https://staging.example.com?tenant=a", "must not contain a query"),
    ("https://staging.example.com?", "must not contain a query"),
    ("https://staging.example.com#", "must not contain a fragment"),
    ("https://staging.example.com/api#v2", "must not contain a fragment"),
]

# Every function that turns an environment variable into a request base URL.
_READERS = [
    pytest.param(API_URL_ENV, auth_service._api_base, id="auth_service"),
    pytest.param(API_URL_ENV, api_client._api_base, id="api_client"),
    pytest.param(MCP_URL_ENV, remote_client._mcp_base, id="remote_mcp"),
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (API_URL_ENV, MCP_URL_ENV):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def sent(monkeypatch) -> List[httpx.Request]:
    """Route every ``httpx.AsyncClient`` to a recorder; return what it received."""
    requests: List[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={})

    real_client = httpx.AsyncClient

    class _RecordingClient(real_client):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            kwargs.pop("transport", None)
            super().__init__(*args, transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _RecordingClient)
    return requests


@pytest.fixture
def auth_file(tmp_path, monkeypatch):
    path = tmp_path / "auth.json"
    monkeypatch.setattr(auth_service, "AUTH_FILE", path)
    return path


def _signed_in(auth_file) -> AuthService:
    auth = AuthService()
    auth._token = AuthToken(
        access_token="access-token-value",
        refresh_token="refresh-token-value",
        expires_at=time.time() + 3600,
        plan="solo",
    )
    auth._save_token()
    assert auth_file.exists()
    return auth


def _assert_names_not_leaks(message: str, name: str, url: str) -> None:
    assert name in message
    assert url not in message
    assert _SECRET not in message


# ---------------------------------------------------------------------------
# The readers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("env_var", "reader"), _READERS)
@pytest.mark.parametrize(("value", "expected"), _ACCEPTED)
def test_readers_accept_https_and_loopback_http(monkeypatch, env_var, reader, value, expected):
    monkeypatch.setenv(env_var, value)
    assert reader() == expected


@pytest.mark.parametrize(("env_var", "reader"), _READERS)
@pytest.mark.parametrize(("value", "fragment"), _REFUSED)
def test_readers_refuse_everything_else_without_echoing_it(
    monkeypatch, env_var, reader, value, fragment
):
    monkeypatch.setenv(env_var, value)
    with pytest.raises(EndpointOverrideError) as excinfo:
        reader()
    assert fragment in str(excinfo.value)
    _assert_names_not_leaks(str(excinfo.value), env_var, value)


@pytest.mark.parametrize(("env_var", "reader"), _READERS)
def test_readers_never_fall_back_to_production(monkeypatch, env_var, reader):
    """A refused value raises; it is never quietly replaced by the default."""
    monkeypatch.setenv(env_var, "http://staging.example.com")
    with pytest.raises(EndpointOverrideError):
        reader()


def test_api_client_refusal_is_also_an_api_error(monkeypatch):
    """Callers that already report API failures show the variable's error."""
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")
    with pytest.raises(APIError) as excinfo:
        api_client._api_base()
    error = excinfo.value
    assert isinstance(error, EndpointConfigError)
    assert isinstance(error, EndpointOverrideError)
    assert error.code == "invalid_endpoint"
    assert error.message.startswith(f"{API_URL_ENV} must be an https:// URL")


def test_startup_check_reports_each_refused_variable(monkeypatch):
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")
    monkeypatch.setenv(MCP_URL_ENV, "https://mcp.example.com")
    assert endpoint_override_errors((API_URL_ENV, MCP_URL_ENV)) == [
        f"{API_URL_ENV} must be an https:// URL "
        "(http:// is accepted only for 127.0.0.1, ::1 or localhost)."
    ]


# ---------------------------------------------------------------------------
# No token leaves: the services that call the readers
# ---------------------------------------------------------------------------


def test_device_flow_uses_a_loopback_override(monkeypatch, sent, auth_file):
    monkeypatch.setenv(API_URL_ENV, "http://127.0.0.1:8000")
    asyncio.run(AuthService().start_device_flow())
    assert [str(r.url) for r in sent] == ["http://127.0.0.1:8000/api/oauth/device"]


def test_device_flow_with_a_refused_override_sends_nothing(monkeypatch, sent, auth_file):
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")
    with pytest.raises(EndpointOverrideError, match=API_URL_ENV):
        asyncio.run(AuthService().start_device_flow())
    assert sent == []


def test_signed_in_calls_never_send_the_bearer_to_a_refused_override(
    monkeypatch, sent, auth_file
):
    auth = _signed_in(auth_file)
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")

    assert asyncio.run(auth.fetch_entitlements()) is None
    assert asyncio.run(auth.list_teams(force_refresh=True)) == []
    assert asyncio.run(auth.refresh_token()) is False
    assert sent == []
    # A refusal is not a revoked session.
    assert auth.is_authenticated


def test_logout_with_a_refused_override_keeps_the_session_to_revoke_later(
    monkeypatch, sent, auth_file
):
    auth = _signed_in(auth_file)
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")

    with pytest.raises(EndpointOverrideError, match=API_URL_ENV):
        asyncio.run(auth.logout())

    assert sent == []
    assert auth.is_authenticated
    assert auth_file.exists()


def _api_client(requests: List[httpx.Request]) -> APIClient:
    auth = MagicMock()
    auth.access_token = "access-token-value"
    client = APIClient(auth)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    client.transport = httpx.MockTransport(handler)
    return client


def test_api_client_sends_to_a_loopback_override(monkeypatch):
    requests: List[httpx.Request] = []
    monkeypatch.setenv(API_URL_ENV, "http://localhost:8000")
    asyncio.run(_api_client(requests).get("/api/v1/teams"))
    assert [str(r.url) for r in requests] == ["http://localhost:8000/api/v1/teams"]
    assert requests[0].headers["Authorization"] == "Bearer access-token-value"


def test_api_client_refuses_before_attaching_the_token(monkeypatch):
    requests: List[httpx.Request] = []
    client = _api_client(requests)
    client._get_headers = MagicMock(side_effect=AssertionError("headers built"))
    monkeypatch.setenv(API_URL_ENV, f"https://deploy:{_SECRET}@staging.example.com")

    with pytest.raises(EndpointConfigError) as excinfo:
        asyncio.run(client.get("/api/v1/teams"))

    _assert_names_not_leaks(excinfo.value.message, API_URL_ENV, "staging.example.com")
    assert requests == []


def test_ai_stream_refuses_before_connecting(monkeypatch):
    requests: List[httpx.Request] = []
    client = _api_client(requests)
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")

    async def first_event():
        async for event in client.stream_sse("/api/ai/chat", {"messages": []}):
            return event

    with pytest.raises(EndpointConfigError, match=API_URL_ENV):
        asyncio.run(first_event())
    assert requests == []


def test_remote_mcp_client_refuses_before_connecting(monkeypatch, sent):
    monkeypatch.setenv(MCP_URL_ENV, "http://mcp.example.com")
    client = remote_client.RemoteMCPClient(MagicMock(access_token="access-token-value"))
    with pytest.raises(EndpointOverrideError, match=MCP_URL_ENV):
        asyncio.run(client.connect())
    assert sent == []
    assert not client.is_connected


def _connect_with_advertised_endpoint(monkeypatch, advertised: object) -> List[httpx.Request]:
    """Connect, with the server advertising *advertised*, then make one tool call.

    Returns every request sent, so a test can see where the bearer went.
    """
    requests: List[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/mcp/sse":
            return httpx.Response(200, json={"session_id": "s1", "message_endpoint": advertised})
        return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})

    real_client = httpx.AsyncClient

    class _Client(real_client):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    monkeypatch.setenv(MCP_URL_ENV, "https://mcp.example.com")
    client = remote_client.RemoteMCPClient(MagicMock(access_token="access-token-value"))
    assert asyncio.run(client.connect()) is True
    assert asyncio.run(client.call_tool("deploy", {})) == "ok"
    return requests


@pytest.mark.parametrize(
    "advertised",
    [
        pytest.param("https://collector.example.com/mcp/message", id="another-https-host"),
        pytest.param("https://mcp.example.com:8443/mcp/message", id="another-port"),
        pytest.param("http://mcp.example.com/mcp/message", id="plain-http"),
        pytest.param("//collector.example.com/mcp/message", id="scheme-relative"),
        pytest.param(f"https://u:{_SECRET}@mcp.example.com/m", id="credentials"),
        pytest.param("https://mcp.example.com/m#frag", id="fragment"),
        pytest.param(42, id="not-a-string"),
    ],
)
def test_remote_mcp_client_ignores_a_cross_origin_message_endpoint(
    monkeypatch, caplog, advertised
):
    """Tool calls carry the bearer: only the base's own origin may receive them."""
    requests = _connect_with_advertised_endpoint(monkeypatch, advertised)

    tool_call = requests[-1]
    assert str(tool_call.url) == "https://mcp.example.com/mcp/message"
    assert tool_call.headers["Authorization"] == "Bearer access-token-value"
    assert all(r.url.host == "mcp.example.com" and r.url.port is None for r in requests)
    assert "Using the default message endpoint" in caplog.text
    assert "collector" not in caplog.text and _SECRET not in caplog.text


@pytest.mark.parametrize(
    ("advertised", "expected"),
    [
        ("https://mcp.example.com/session/s1/message", "https://mcp.example.com/session/s1/message"),
        # Same origin once case and the default port are normalised.
        ("https://MCP.example.com:443/m?session_id=s1", "https://mcp.example.com/m?session_id=s1"),
        ("/session/s1/message", "https://mcp.example.com/session/s1/message"),
        ("", "https://mcp.example.com/mcp/message"),
    ],
)
def test_remote_mcp_client_uses_a_same_origin_message_endpoint(monkeypatch, advertised, expected):
    requests = _connect_with_advertised_endpoint(monkeypatch, advertised)
    assert str(requests[-1].url) == expected


def test_remote_mcp_reconnect_stops_on_a_refused_url(monkeypatch, sent, caplog):
    """Waiting cannot fix configuration: report once, then give up."""
    monkeypatch.setenv(MCP_URL_ENV, "http://mcp.example.com")
    sleeps: List[float] = []

    async def no_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(remote_client.asyncio, "sleep", no_sleep)
    client = remote_client.RemoteMCPClient(MagicMock(access_token="access-token-value"))

    assert asyncio.run(client.reconnect()) is False

    assert len(sleeps) == 1
    assert sent == []
    refusals = [r for r in caplog.records if "Not reconnecting" in r.getMessage()]
    assert len(refusals) == 1
    assert MCP_URL_ENV in refusals[0].getMessage()


# ---------------------------------------------------------------------------
# MCP tools: a structured error and an audit row, never a request
# ---------------------------------------------------------------------------


def _mcp_tools() -> tuple[ServonautTools, MagicMock]:
    config = AppConfig(mcp=MCPConfig(guard_level=GuardLevel.STANDARD))
    config_manager = MagicMock()
    config_manager.get.return_value = config
    audit = MagicMock()
    auth = MagicMock()
    auth.is_authenticated = True
    auth.access_token = "access-token-value"
    auth.plan = "solo"
    auth._token = SimpleNamespace(
        access_token="access-token-value", expires_at=time.time() + 3600, email="a@example.com"
    )
    auth.refresh_token = AsyncMock(return_value=True)
    tools = ServonautTools(
        config_manager=config_manager,
        aws_service=MagicMock(),
        custom_server_service=MagicMock(),
        cache_service=MagicMock(),
        ssh_service=MagicMock(),
        connection_service=MagicMock(),
        scp_service=MagicMock(),
        guard=CommandGuard(config.mcp),
        audit=audit,
        auth_service=auth,
    )
    return tools, audit


def test_mcp_api_request_reports_a_refused_api_url(monkeypatch, sent):
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")
    tools, audit = _mcp_tools()

    result = json.loads(asyncio.run(tools.api_request("GET", "/api/cli/status")))

    assert result["error"]["code"] == "invalid_endpoint"
    _assert_names_not_leaks(result["error"]["message"], API_URL_ENV, "staging.example.com")
    assert sent == []
    audit_args = audit.log.call_args.args
    assert audit_args[0] == "api_request"
    assert audit_args[1]["error_code"] == "invalid_endpoint"
    assert audit_args[3] is False


def test_mcp_tool_call_reports_a_refused_mcp_url(monkeypatch, sent):
    monkeypatch.setenv(MCP_URL_ENV, "http://mcp.example.com")
    tools, audit = _mcp_tools()

    result = json.loads(asyncio.run(tools.mcp_tool_call("deploy", {"x": 1})))

    assert result["error"]["code"] == "invalid_endpoint"
    _assert_names_not_leaks(result["error"]["message"], MCP_URL_ENV, "mcp.example.com")
    assert sent == []
    audit.log.assert_called_once()
    tool, _args, _result, allowed, reason = audit.log.call_args.args
    assert (tool, allowed, reason) == ("mcp_tool_call", False, "invalid_endpoint")


def test_mcp_whoami_reports_the_refusal_alongside_the_session(monkeypatch):
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")
    tools, _ = _mcp_tools()

    payload = json.loads(asyncio.run(tools.whoami()))

    assert payload["logged_in"] is True
    assert payload["base_url"] is None
    _assert_names_not_leaks(payload["base_url_error"], API_URL_ENV, "staging.example.com")
    assert "access-token-value" not in json.dumps(payload)


# ---------------------------------------------------------------------------
# CLI: an error naming the variable, exit code 1
# ---------------------------------------------------------------------------


def test_cli_login_names_the_variable_and_exits_1(monkeypatch, sent, auth_file, capsys):
    from servonaut.cli import login as cli_login

    monkeypatch.setattr(cli_login, "_load_env_overrides", lambda: None)
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")

    rc = cli_login.handle_login_command(argparse.Namespace(no_browser=True, force=True))

    err = capsys.readouterr().err
    assert rc == 1
    assert err.startswith(f"Error: {API_URL_ENV} must be an https:// URL")
    assert "staging.example.com" not in err
    assert sent == []


def test_cli_logout_names_the_variable_and_keeps_the_session(
    monkeypatch, sent, auth_file, capsys
):
    from servonaut.cli import login as cli_login

    _signed_in(auth_file)
    monkeypatch.setattr(cli_login, "_load_env_overrides", lambda: None)
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")

    rc = cli_login.handle_logout_command(argparse.Namespace())

    captured = capsys.readouterr()
    assert rc == 1
    assert captured.err.startswith(f"Error: {API_URL_ENV} must be an https:// URL")
    assert "servonaut logout --local" in captured.err
    assert "Signed out" not in captured.out
    assert auth_file.exists()
    assert sent == []


def test_cli_logout_local_signs_out_without_contacting_any_server(
    monkeypatch, sent, auth_file, capsys
):
    from servonaut.cli import login as cli_login

    _signed_in(auth_file)
    monkeypatch.setattr(cli_login, "_load_env_overrides", lambda: None)
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")

    rc = cli_login.handle_logout_command(argparse.Namespace(local=True))

    captured = capsys.readouterr()
    assert rc == 0
    assert "Signed out on this device" in captured.out
    assert "not revoked" in captured.err and "until it expires" in captured.err
    assert not auth_file.exists()
    assert not AuthService().is_authenticated
    assert sent == []


def test_cli_logout_parser_accepts_local():
    from servonaut.cli.login import add_logout_parser

    parser = argparse.ArgumentParser()
    add_logout_parser(parser.add_subparsers(dest="subcommand"))
    assert parser.parse_args(["logout", "--local"]).local is True
    assert parser.parse_args(["logout"]).local is False


def test_sign_out_locally_drops_the_cached_entitlements(auth_file):
    auth = _signed_in(auth_file)
    auth._token.entitlements = {"plan": "solo", "mcp_connections": 5}
    auth._save_token()

    auth.sign_out_locally()

    assert not auth_file.exists()
    assert auth._token is None
    # A new process finds neither the session nor its entitlement cache.
    fresh = AuthService()
    assert fresh._token is None and not fresh.is_authenticated


def test_cli_backstop_turns_an_unhandled_refusal_into_one_line(monkeypatch, capsys):
    import servonaut.main as main_mod

    monkeypatch.setenv(MCP_URL_ENV, "http://mcp.example.com")
    monkeypatch.setattr(main_mod, "_main", lambda: remote_client._mcp_base())

    with pytest.raises(SystemExit) as excinfo:
        main_mod.main()

    err = capsys.readouterr().err
    assert excinfo.value.code == 1
    assert err == (
        f"Error: {MCP_URL_ENV} must be an https:// URL "
        "(http:// is accepted only for 127.0.0.1, ::1 or localhost).\n"
    )


# ---------------------------------------------------------------------------
# Relay: config URLs, `servonaut connect`, the TUI manager, the listener, Settings
# ---------------------------------------------------------------------------

_RELAY_KEYS = [
    pytest.param("relay.base_url", 0, id="base_url"),
    pytest.param("relay.mercure_url", 1, id="mercure_url"),
]
_GOOD_RELAY = ("https://api.example.com", "https://example.com/.well-known/mercure")


def _relay_pair(position: int, value: str) -> tuple[str, str]:
    pair = list(_GOOD_RELAY)
    pair[position] = value
    return pair[0], pair[1]


def _relay_config(position: int, value: str) -> RelayConfig:
    base_url, mercure_url = _relay_pair(position, value)
    return RelayConfig(base_url=base_url, mercure_url=mercure_url)


@pytest.mark.parametrize(("key", "position"), _RELAY_KEYS)
@pytest.mark.parametrize(("value", "_expected"), _ACCEPTED)
def test_relay_urls_accept_https_and_loopback_http(key, position, value, _expected):
    validate_relay_urls(*_relay_pair(position, value))


@pytest.mark.parametrize(("key", "position"), _RELAY_KEYS)
@pytest.mark.parametrize(("value", "fragment"), _REFUSED)
def test_relay_urls_refuse_everything_else_naming_the_key(key, position, value, fragment):
    with pytest.raises(EndpointOverrideError) as excinfo:
        validate_relay_urls(*_relay_pair(position, value))
    assert str(excinfo.value).startswith(key)
    assert fragment in str(excinfo.value)
    _assert_names_not_leaks(str(excinfo.value), key, value)


class _LockReached(Exception):
    """Raised by the patched relay lock: every URL check before it passed."""


def _run_connect(relay: RelayConfig, env: dict) -> None:
    config_manager = MagicMock()
    config_manager.get.return_value = AppConfig(relay=relay)
    lock = MagicMock()
    lock.return_value.acquire.side_effect = _LockReached
    base_env = {"SERVONAUT_RELAY_TOKEN": "relay-token", "SERVONAUT_USER_ID": "user-1"}
    with patch("servonaut.config.manager.ConfigManager", return_value=config_manager), \
         patch("servonaut.services.relay_lock.RelayLock", lock), \
         patch.dict(os.environ, {**base_env, **env}, clear=False):
        from servonaut.main import _relay_run_foreground

        _relay_run_foreground()


def test_connect_accepts_loopback_http_relay_urls():
    """Previously refused: a local relay test server over plain http."""
    relay = RelayConfig(
        base_url="http://127.0.0.1:8000",
        mercure_url="http://localhost:3000/.well-known/mercure",
    )
    with pytest.raises(_LockReached):
        _run_connect(relay, {})


@pytest.mark.parametrize(("key", "position"), _RELAY_KEYS)
def test_connect_refuses_a_bad_relay_url_naming_the_key(key, position, capsys):
    value = f"http://deploy:{_SECRET}@relay.example.com"
    relay = _relay_config(position, value)
    with pytest.raises(SystemExit) as excinfo:
        _run_connect(relay, {})
    out = capsys.readouterr().out
    assert excinfo.value.code == 1
    assert out.startswith(f"Error: {key} must not contain credentials")
    _assert_names_not_leaks(out, key, "relay.example.com")


def test_connect_refuses_a_bad_api_url_before_anything_else(capsys):
    relay = RelayConfig(base_url="", mercure_url="")
    with pytest.raises(SystemExit) as excinfo:
        _run_connect(relay, {API_URL_ENV: "http://staging.example.com"})
    out = capsys.readouterr().out
    assert excinfo.value.code == 1
    assert out.startswith(f"Error: {API_URL_ENV} must be an https:// URL")
    assert "staging.example.com" not in out


def _relay_manager(relay: RelayConfig, tmp_path, factory: Callable[..., Any]) -> RelayManager:
    config_manager = MagicMock()
    config_manager.get.return_value = AppConfig(relay=relay)
    auth = MagicMock()
    auth.is_authenticated = True
    auth.access_token = "access-token-value"
    auth._token = SimpleNamespace(
        entitlements={"plan": "solo", "mcp_connections": 5, "user_id": "42"},
    )
    return RelayManager(
        config_manager=config_manager,
        auth_service=auth,
        lock_path=tmp_path / "relay.lock",
        listener_factory=factory,
    )


@pytest.mark.parametrize(("key", "position"), _RELAY_KEYS)
def test_tui_relay_refuses_a_bad_url_without_building_a_listener(key, position, tmp_path):
    factory = MagicMock()
    relay = _relay_config(position, "http://relay.example.com")
    manager = _relay_manager(relay, tmp_path, factory)

    result = asyncio.run(manager.start())

    assert result.state is RelayState.ERROR
    assert result.message.startswith(f"{key} must be an https:// URL")
    factory.assert_not_called()
    assert manager.state is RelayState.ERROR


@pytest.mark.parametrize(("key", "position"), _RELAY_KEYS)
def test_relay_listener_refuses_a_bad_url_itself(key, position):
    from servonaut.services.relay_listener import RelayListener

    base_url, mercure_url = _relay_pair(position, "http://relay.example.com")
    with pytest.raises(EndpointOverrideError, match=key):
        RelayListener(
            executors=MagicMock(),
            base_url=base_url,
            mercure_url=mercure_url,
            auth_token="access-token-value",
            user_id="42",
        )


def test_relay_listener_accepts_loopback_http():
    from servonaut.services.relay_listener import RelayListener

    listener = RelayListener(
        executors=MagicMock(),
        base_url="http://127.0.0.1:8000/",
        mercure_url="http://[::1]:3000/.well-known/mercure",
        auth_token="access-token-value",
        user_id="42",
    )
    assert listener._base_url == "http://127.0.0.1:8000"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field_id", "value", "fragment"),
    [
        ("relay_base_url", "http://relay.example.com", "relay.base_url must be an https:// URL"),
        ("relay_mercure_url", f"https://u:{_SECRET}@example.com/hub", "relay.mercure_url must not contain credentials"),
        ("relay_base_url", "http://relay.example.com\\@127.0.0.1", "relay.base_url must not contain spaces, backslashes"),
    ],
)
async def test_settings_refuses_to_save_a_bad_relay_url(tmp_path, field_id, value, fragment):
    from servonaut.screens.settings.base import ValidationError
    from servonaut.screens.settings.panels.relay import RelayPanel
    from tests.test_settings_panels_roundtrip import _PanelHost, _temp_config_manager

    manager = _temp_config_manager(tmp_path, AppConfig())
    app = _PanelHost(RelayPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        panel.query_one(f"#{field_id}", Input).value = value
        with pytest.raises(ValidationError) as excinfo:
            panel.collect()
    assert excinfo.value.field_id == field_id
    assert excinfo.value.message.startswith(fragment)
    assert _SECRET not in excinfo.value.message


@pytest.mark.asyncio
async def test_settings_saves_loopback_and_empty_relay_urls(tmp_path):
    from servonaut.screens.settings.panels.relay import RelayPanel
    from tests.test_settings_panels_roundtrip import _PanelHost, _temp_config_manager

    manager = _temp_config_manager(tmp_path, AppConfig())
    app = _PanelHost(RelayPanel, manager)
    async with app.run_test() as pilot:
        await pilot.pause()
        panel = app.panel
        panel.query_one("#relay_base_url", Input).value = "http://127.0.0.1:8000"
        panel.query_one("#relay_mercure_url", Input).value = ""
        fields = panel.collect()
    assert fields["base_url"] == "http://127.0.0.1:8000"
    assert fields["mercure_url"] == ""


# ---------------------------------------------------------------------------
# TUI: a notice naming the variable, no crash, no request to the refused host
# ---------------------------------------------------------------------------


def _endpoint_notices(report: dict) -> list:
    return [
        note
        for note in report["result"]["notifications"]
        if API_URL_ENV in note["message"]
    ]


def _remote_hosts(report: dict) -> list:
    """Hosts the child tried to reach that are not loopback (the guard's repr)."""
    loopback = {"'127.0.0.1'", "'::1'", "'localhost'"}
    return [host for _, host in report["network_attempts"] if host not in loopback]


def test_tui_boot_with_a_refused_api_url_shows_an_error_notice(tmp_path):
    report = run_hermetic_app(
        tmp_path, "signed-in-with-api-override", "http://staging.example.com"
    )

    assert report["error"] is None, report["error"]
    result = report["result"]
    assert result["screen"] == "InstanceListScreen"
    assert result["signed_in"] is True
    notices = _endpoint_notices(report)
    assert len(notices) == 1
    assert notices[0]["severity"] == "error"
    assert notices[0]["message"].startswith(f"{API_URL_ENV} must be an https:// URL")
    assert all("example.com" not in note["message"] for note in result["notifications"])
    # Neither the refused host nor the production API was contacted.
    assert _remote_hosts(report) == []


def test_tui_boot_with_a_loopback_api_url_uses_it_without_a_notice(tmp_path):
    report = run_hermetic_app(
        tmp_path, "signed-in-with-api-override", "http://127.0.0.1:9"
    )

    assert report["error"] is None, report["error"]
    assert _endpoint_notices(report) == []
    # Signed-in startup calls went to the override, not to production.
    assert report["network_attempts"]
    assert _remote_hosts(report) == []


def test_account_screen_reports_the_refusal_instead_of_a_revoked_session(monkeypatch):
    from servonaut.screens.login import LoginScreen

    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")
    auth = MagicMock()
    auth.validate_token = AsyncMock(return_value=False)
    screen = SimpleNamespace(app=SimpleNamespace(auth_service=auth), notify=MagicMock())

    asyncio.run(LoginScreen._validate_session(screen))

    auth.validate_token.assert_not_awaited()
    message = screen.notify.call_args.args[0]
    assert message.startswith(f"{API_URL_ENV} must be an https:// URL")
    assert screen.notify.call_args.kwargs["severity"] == "error"
    assert "Sign out on this device only" in message


# ---------------------------------------------------------------------------
# TUI: "Sign out on this device only"
# ---------------------------------------------------------------------------


class _AccountHost(App):
    """Mounts the Account screen over a real AuthService."""

    def __init__(self, auth: AuthService) -> None:
        super().__init__()
        self.auth_service = auth
        self.config_sync_service = None
        self.logout_hooks = 0

    def on_mount(self) -> None:
        from servonaut.screens.login import LoginScreen

        self.push_screen(LoginScreen())

    def on_user_logout(self) -> None:
        self.logout_hooks += 1


async def _press_local_sign_out(app: _AccountHost, pilot) -> Any:
    from servonaut.screens.confirm_action import ConfirmActionScreen

    await pilot.pause()
    account = app.screen
    button = account.query_one("#btn_logout_local", Button)
    assert button.display is True
    button.press()
    await pilot.pause()
    assert isinstance(app.screen, ConfirmActionScreen)
    return account


@pytest.mark.asyncio
async def test_tui_sign_out_on_this_device_only(monkeypatch, sent, auth_file):
    """With the API URL refused, the user can still sign out, and is warned."""
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")
    app = _AccountHost(_signed_in(auth_file))
    async with app.run_test(headless=True) as pilot:
        account = await _press_local_sign_out(app, pilot)
        confirm = app.screen
        confirm.query_one("#confirm_input", Input).value = "sign out"
        await pilot.pause()
        confirm.query_one("#btn_confirm", Button).press()
        await pilot.pause()

        assert app.screen is account
        assert account.query_one("#logged_out_container").display is True
        notes = [(n.message, n.severity) for n in app._notifications]

    assert not auth_file.exists()
    assert not app.auth_service.is_authenticated
    assert app.logout_hooks == 1
    assert sent == []
    # The refusal notice points at the action; the action warns afterwards.
    assert any(
        sev == "error" and "Sign out on this device only" in msg for msg, sev in notes
    )
    assert any(
        sev == "warning" and "not revoked" in msg and "until it expires" in msg
        for msg, sev in notes
    )


@pytest.mark.asyncio
async def test_tui_sign_out_on_this_device_only_can_be_cancelled(monkeypatch, sent, auth_file):
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")
    app = _AccountHost(_signed_in(auth_file))
    async with app.run_test(headless=True) as pilot:
        account = await _press_local_sign_out(app, pilot)
        app.screen.query_one("#btn_cancel", Button).press()
        await pilot.pause()
        assert app.screen is account

    assert auth_file.exists()
    assert app.logout_hooks == 0


@pytest.mark.asyncio
async def test_tui_logout_with_a_refused_api_url_points_to_local_sign_out(
    monkeypatch, sent, auth_file
):
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")
    app = _AccountHost(_signed_in(auth_file))
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        app.screen.query_one("#btn_logout", Button).press()
        await pilot.pause()
        await app.workers.wait_for_complete()
        notes = [n.message for n in app._notifications]

    assert auth_file.exists()
    assert any(
        msg.startswith(f"Logout error: {API_URL_ENV} must be an https:// URL")
        and "Sign out on this device only" in msg
        for msg in notes
    )
    assert sent == []


# ---------------------------------------------------------------------------
# Relay: no unchecked URL is printed or logged; the reason is kept and shown
# ---------------------------------------------------------------------------


def test_connect_checks_a_user_set_url_before_printing_or_saving(capsys):
    config_manager = MagicMock()
    config_manager.get.return_value = AppConfig(relay=RelayConfig(
        base_url=f"https://deploy:{_SECRET}@relay.example.com", mercure_url="",
    ))
    base_env = {"SERVONAUT_RELAY_TOKEN": "relay-token", "SERVONAUT_USER_ID": "user-1"}
    with patch("servonaut.config.manager.ConfigManager", return_value=config_manager), \
         patch.dict(os.environ, base_env, clear=False):
        from servonaut.main import _relay_run_foreground

        with pytest.raises(SystemExit) as excinfo:
            _relay_run_foreground()

    out = capsys.readouterr().out
    assert excinfo.value.code == 1
    assert out == "Error: relay.base_url must not contain credentials.\n"
    config_manager.save.assert_not_called()


def test_connect_prints_only_the_derived_relay_url(capsys):
    relay = RelayConfig(base_url="", mercure_url="https://hub.example.com/.well-known/mercure")
    with pytest.raises(_LockReached):
        _run_connect(relay, {})
    out = capsys.readouterr().out
    assert "Auto-populated relay.base_url=https://api.servonaut.dev\n" in out
    assert "hub.example.com" not in out


def test_relay_autofill_logs_only_derived_values(tmp_path, caplog):
    import logging

    caplog.set_level(logging.INFO, logger="servonaut.services.relay_manager")
    relay = RelayConfig(base_url=f"https://deploy:{_SECRET}@relay.example.com", mercure_url="")
    manager = _relay_manager(relay, tmp_path, MagicMock())

    assert manager.ensure_configured() is True

    assert "relay.mercure_url=https://servonaut.dev/.well-known/mercure" in caplog.text
    assert _SECRET not in caplog.text and "relay.example.com" not in caplog.text


def test_connect_bg_refuses_in_the_parent_before_spawning(tmp_path, capsys):
    config_manager = MagicMock()
    config_manager.get.return_value = AppConfig(relay=RelayConfig(
        base_url="http://192.168.1.20:8000", mercure_url="",
    ))
    spawn = MagicMock()
    with patch("servonaut.config.manager.ConfigManager", return_value=config_manager), \
         patch("servonaut.services.process_control.spawn_detached", spawn):
        from servonaut.main import _relay_start_background

        with pytest.raises(SystemExit) as excinfo:
            _relay_start_background(SimpleNamespace(data_root=tmp_path))

    out = capsys.readouterr().out
    assert excinfo.value.code == 1
    assert out.startswith("Error: relay.base_url must be an https:// URL")
    assert "started" not in out and "192.168" not in out
    spawn.assert_not_called()


def test_connect_bg_refuses_a_bad_api_url_before_spawning(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")
    spawn = MagicMock()
    with patch("servonaut.config.manager.ConfigManager", return_value=MagicMock(
        get=MagicMock(return_value=AppConfig()),
    )), patch("servonaut.services.process_control.spawn_detached", spawn):
        from servonaut.main import _relay_start_background

        with pytest.raises(SystemExit):
            _relay_start_background(SimpleNamespace(data_root=tmp_path))

    assert capsys.readouterr().out.startswith(f"Error: {API_URL_ENV} must be")
    spawn.assert_not_called()


def test_relay_manager_keeps_the_refusal_reason(tmp_path):
    relay = _relay_config(0, "http://192.168.1.20:8000")
    manager = _relay_manager(relay, tmp_path, MagicMock())

    asyncio.run(manager.start())

    assert manager.last_error.startswith("relay.base_url must be an https:// URL")
    manager._set_state(RelayState.STOPPED)
    assert manager.last_error is None


def test_relay_status_screen_shows_the_refusal_reason(tmp_path, monkeypatch):
    from servonaut.widgets.relay_indicator import RelayStatusScreen

    app = MagicMock()
    app.relay_state = RelayState.ERROR
    app.relay_lock_path = tmp_path / "relay.lock"
    app.relay_manager = SimpleNamespace(
        last_error="relay.base_url must be an https:// URL [not markup]"
    )
    monkeypatch.setattr(RelayStatusScreen, "app", property(lambda _self: app))
    screen = object.__new__(RelayStatusScreen)
    widget = MagicMock()
    screen.query_one = MagicMock(return_value=widget)

    screen._refresh_local()

    text = widget.update.call_args.args[0]
    assert "error" in text
    assert "relay.base_url must be an https:// URL \\[not markup]" in text


def test_tui_relay_toast_is_plain_text_and_stays_up(monkeypatch):
    from servonaut.app import ServonautApp
    from servonaut.services.relay_manager import StartResult

    reason = "relay.base_url must be an https:// URL [x]"
    stub = SimpleNamespace(
        relay_manager=SimpleNamespace(
            start=AsyncMock(return_value=StartResult(RelayState.ERROR, reason))
        ),
        notify=MagicMock(),
    )

    asyncio.run(ServonautApp._start_relay_with_toast(stub))

    message = stub.notify.call_args.args[0]
    kwargs = stub.notify.call_args.kwargs
    assert message == f"MCP relay failed to start: {reason}"
    assert kwargs["markup"] is False
    assert kwargs["severity"] == "error"
    assert kwargs["timeout"] >= 15


# ---------------------------------------------------------------------------
# Token refresh: a refusal has its own label and keeps the session
# ---------------------------------------------------------------------------


def test_refresh_with_a_refused_api_url_is_labelled_as_such(monkeypatch, sent, auth_file, caplog):
    auth = _signed_in(auth_file)
    monkeypatch.setenv(API_URL_ENV, "http://staging.example.com")

    assert asyncio.run(auth.refresh_token()) is False

    assert "Token refresh skipped: SERVONAUT_API_URL must be" in caplog.text
    assert "network error" not in caplog.text
    assert auth.is_authenticated and auth_file.exists()
    assert sent == []


# ---------------------------------------------------------------------------
# Query and fragment
# ---------------------------------------------------------------------------


def test_a_full_endpoint_may_carry_a_query_but_never_a_fragment():
    from servonaut.utils.endpoints import validate_endpoint_url

    url = "https://mcp.example.com/m?session_id=s1"
    assert validate_endpoint_url(url, source="X", allow_query=True) == url
    with pytest.raises(EndpointOverrideError, match="must not contain a query"):
        validate_endpoint_url(url, source="X")
    with pytest.raises(EndpointOverrideError, match="must not contain a fragment"):
        validate_endpoint_url("https://mcp.example.com/m#x", source="X", allow_query=True)


# ---------------------------------------------------------------------------
# Bring-your-own AI providers: a key never goes to a plain-http remote base
# ---------------------------------------------------------------------------

_KEYED_PROVIDERS = [
    pytest.param("OpenAIProvider", "openai", "OpenAI", id="openai"),
    pytest.param("AnthropicProvider", "anthropic", "Anthropic", id="anthropic"),
    pytest.param("GeminiProvider", "gemini", "Gemini", id="gemini"),
    pytest.param("OllamaProvider", "ollama", "Ollama", id="ollama-cloud-key"),
]
_AI_KEY = "sk-test-ai-key-value"


def _ai_config(provider: str, base_url: str, key: str = _AI_KEY):
    from servonaut.config.schema import AIProviderConfig

    return AIProviderConfig(provider=provider, base_url=base_url, **{f"{provider}_api_key": key})


async def _call_ai(provider_cls: str, method: str, config) -> None:
    from servonaut.services import ai_analysis_service

    provider = getattr(ai_analysis_service, provider_cls)()
    if method == "analyze":
        await provider.analyze("log text", "system", config)
    else:
        await provider.chat([{"role": "user", "content": "hi"}], "system", config)


@pytest.mark.parametrize("method", ["analyze", "chat"])
@pytest.mark.parametrize(("provider_cls", "provider", "label"), _KEYED_PROVIDERS)
@pytest.mark.parametrize(
    ("base_url", "fragment"),
    [
        ("http://192.168.1.20:8080", "must be an https:// URL"),
        ("http://ai-proxy.example.com", "must be an https:// URL"),
        ("http://192.168.1.20:8080\\@127.0.0.1", "backslashes"),
        ("https://ai-proxy.example.com?x=1", "must not contain a query"),
    ],
)
def test_ai_key_is_not_sent_to_an_unsafe_base(
    sent, provider_cls, provider, label, method, base_url, fragment
):
    with pytest.raises(EndpointOverrideError) as excinfo:
        asyncio.run(_call_ai(provider_cls, method, _ai_config(provider, base_url)))

    message = str(excinfo.value)
    assert message.startswith(f"The {label} API key was not sent: ai_provider.base_url")
    assert fragment in message
    assert _AI_KEY not in message and "192.168" not in message
    assert sent == []


@pytest.mark.parametrize("method", ["analyze", "chat"])
@pytest.mark.parametrize(("provider_cls", "provider", "label"), _KEYED_PROVIDERS)
@pytest.mark.parametrize(
    "base_url", ["http://127.0.0.1:8080", "http://localhost:8080", "https://192.168.1.20:8443"]
)
def test_ai_key_is_sent_over_https_or_to_loopback(sent, provider_cls, provider, label, method, base_url):
    import contextlib

    # The recorder's empty reply is not a valid completion; only the request matters.
    with contextlib.suppress(KeyError, IndexError, TypeError, AttributeError, RuntimeError, ValueError):
        asyncio.run(_call_ai(provider_cls, method, _ai_config(provider, base_url)))

    assert len(sent) == 1
    assert str(sent[0].url).startswith(base_url)


@pytest.mark.parametrize("method", ["analyze", "chat"])
def test_keyless_ollama_on_a_lan_http_base_keeps_working(sent, method):
    import contextlib

    config = _ai_config("ollama", "http://192.168.1.20:11434", key="")
    with contextlib.suppress(KeyError, IndexError, TypeError, AttributeError, RuntimeError, ValueError):
        asyncio.run(_call_ai("OllamaProvider", method, config))

    assert [str(r.url) for r in sent] == ["http://192.168.1.20:11434/api/chat"]
    assert "authorization" not in sent[0].headers


def test_ai_refusal_reaches_the_chat_as_an_error(sent, tmp_path):
    """The service surfaces the refusal to its callers instead of sending."""
    from servonaut.services.ai_analysis_service import AIAnalysisService

    config_manager = MagicMock()
    config_manager.get.return_value = AppConfig(
        ai_provider=_ai_config("openai", "http://192.168.1.20:8080")
    )
    service = AIAnalysisService(config_manager)

    with pytest.raises(EndpointOverrideError, match="The OpenAI API key was not sent"):
        asyncio.run(service.chat([{"role": "user", "content": "hi"}]))
    assert sent == []
