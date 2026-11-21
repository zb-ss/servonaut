"""Tests for client version identity, HTTP 426 handling, and version policy."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)
from servonaut.services.ai_error_handler import UserFacingAction, map_error_to_action
from servonaut.services.ai_sse import SSEStreamError
from servonaut.services.api_client import APIClient, APIError, ClientUpdateRequiredError
from servonaut.services.auth_service import AuthService, AuthToken
from servonaut.services.client_identity import (
    CLIENT_HEADER_NAME,
    client_header_value,
    client_request_headers,
    configure_client_identity,
    format_update_required_from_response,
    format_update_required_message,
    get_client_identity,
    is_apt_managed_install,
    parse_upgrade_header,
    reset_client_identity_for_tests,
    response_is_update_required,
)
from servonaut.services.relay_listener import RelayListener
from servonaut.services.relay_manager import RelayManager, RelayState
from servonaut.services.vault.errors import vault_failure_reason
from servonaut.services.version_policy import (
    DEFAULT_UPDATE_URL,
    VersionPolicy,
    VersionPolicyClient,
    compare_versions,
    is_version_allowed,
    load_cached_version_policy,
    normalize_public_version,
    parse_client_signal,
    parse_contract_version,
    save_cached_version_policy,
)


def _run(coro):
    return asyncio.run(coro)


def _fake_runtime(
    kind: DistributionKind,
    *,
    version: str = "2.34.0",
    release_channel: str = "stable",
) -> RuntimeLayout:
    return RuntimeLayout(
        kind=kind,
        product_version=version,
        build_revision=None,
        resource_root=Path("/tmp/resources"),
        executable_root=Path("/tmp/bin"),
        data_root=Path("/tmp/data"),
        executable=Path("/tmp/bin/python"),
        python_executable=None if kind in {DistributionKind.FROZEN_CLI, DistributionKind.PACKAGED_DESKTOP} else Path("/tmp/bin/python"),
        path_console=None,
        console_helper=Path("/tmp/bin/servonaut") if kind is DistributionKind.PACKAGED_DESKTOP else None,
        desktop_child=Path("/tmp/bin/child") if kind is DistributionKind.PACKAGED_DESKTOP else None,
        package_management=PackageManagementCapability(
            PackageManagementKind.UNSUPPORTED, (), False,
        ),
        is_frozen=kind in {DistributionKind.FROZEN_CLI, DistributionKind.PACKAGED_DESKTOP},
        release_channel=release_channel,
    )


@pytest.fixture(autouse=True)
def _reset_identity():
    reset_client_identity_for_tests()
    yield
    reset_client_identity_for_tests()


# ---------------------------------------------------------------------------
# PEP 440 contract comparison vectors & signal parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "left, op, right",
    [
        ("2.34.0rc3", "<", "2.34.0"),
        ("2.34.0.dev1", "<", "2.34.0a1"),
        ("2.34.0a1", "<", "2.34.0b1"),
        ("2.34.0b2", "<", "2.34.0rc1"),
        ("2.34.0rc1", "<", "2.34.0rc10"),
        ("2.34.0", "<", "2.34.0.post1"),
        ("2.33.1", "<", "2.34.0"),
        ("2.9.0", "<", "2.10.0"),
        ("2.34", "=", "2.34.0"),
        ("2.34.0.dev3", "<", "2.34.0rc1"),
        ("2.34.0rc1.dev2", "<", "2.34.0rc1"),
        ("2.34.0", "<", "2.34.0.post1.dev1"),
        ("2.34.0.post1.dev1", "<", "2.34.0.post1"),
        ("2.34.0rc1", "<", "2.34.0.post1"),
        ("2.31.0", "<", "2.34.0rc1"),
        ("2.35.0.dev0", ">", "2.34.0"),
        ("1.0", "=", "1.0.0.0"),
        ("2.34.0rc2", "=", "2.34.0rc2"),
    ],
)
def test_pep440_comparison_vectors(left: str, op: str, right: str) -> None:
    expected = {"<": -1, "=": 0, ">": 1}[op]
    assert compare_versions(left, right) == expected
    try:
        from packaging.version import Version
    except ImportError:
        return
    pv_left, pv_right = Version(left), Version(right)
    if op == "<":
        assert pv_left < pv_right
    elif op == "=":
        assert pv_left == pv_right
    else:
        assert pv_left > pv_right


@pytest.mark.parametrize(
    "floor, client, allowed",
    [
        ("2.34.0", "2.31.0", False),
        ("2.34.0", "2.34.0rc3", False),
        ("2.34.0rc1", "2.34.0rc3", True),
        ("2.34.0", "2.34.0", True),
        ("2.34.0", "2.34.0.post1", True),
        ("2.34.0", "2.35.0.dev0", True),
        ("2.34.0rc1", "2.34.0.dev5", False),
        ("2.34.0", "unknown", True),
        ("", "2.31.0", True),
        (None, "2.31.0", True),
        ("not-a-version", "2.31.0", True),
        ("2.34.0", "2.34.0+local.1", True),
    ],
)
def test_floor_decisions(floor, client: str, allowed: bool) -> None:
    assert is_version_allowed(client, floor) is allowed


@pytest.mark.parametrize(
    "raw",
    ["v2.34.0", "2.34.0-rc1", "2.34.0c1", "2.34.0rc", "", "2.34.0+", "abc", None, 123],
)
def test_non_normalized_versions_rejected(raw) -> None:
    assert parse_contract_version(raw) is None
    assert normalize_public_version(raw) is None


def test_local_suffix_stripped() -> None:
    assert normalize_public_version("2.34.0+local.1") == "2.34.0"
    assert compare_versions("2.34.0+local.1", "2.34.0") == 0


@pytest.mark.parametrize(
    "x_client, user_agent, expected",
    [
        ("2.35.0rc2; channel=rc; kind=relay", None, ("2.35.0rc2", "rc", "relay")),
        ("2.35.0", None, ("2.35.0", None, None)),
        ("v2.35.0", "servonaut-cli/2.33.1 (macOS 15)", ("2.33.1", None, None)),
        (None, "servonaut-cli/2.33.1 (macOS 15)", ("2.33.1", None, None)),
        (None, "servonaut-cli/2.34.0rc2", ("2.34.0rc2", None, None)),
        (None, "servonaut/2.35.0", ("2.35.0", None, None)),
        (None, "python-httpx/0.28.1", (None, None, None)),
        ("2.34.0+local.1; channel=stable; kind=cli", None, ("2.34.0", "stable", "cli")),
        (None, "servonaut-cli/2.34.0+local.1", ("2.34.0", None, None)),
    ],
)
def test_signal_parsing_vectors(x_client, user_agent, expected) -> None:
    assert parse_client_signal(x_client=x_client, user_agent=user_agent) == expected


# ---------------------------------------------------------------------------
# A1: Running client identity & X-Servonaut-Client header across HTTP clients
# ---------------------------------------------------------------------------


def test_identity_captures_version_once_and_ignores_later_metadata_changes(monkeypatch) -> None:
    import importlib.metadata

    configure_client_identity(kind="cli", version="2.34.0")
    before = client_header_value()
    assert before == "2.34.0; channel=stable; kind=cli"

    def _boom(_name: str) -> str:
        raise AssertionError("importlib.metadata.version must not be re-read per request")

    monkeypatch.setattr(importlib.metadata, "version", _boom)
    assert client_header_value() == before
    assert client_request_headers()["User-Agent"] == "servonaut-cli/2.34.0"


def test_identity_channel_and_kind_derivation() -> None:
    rc_id = configure_client_identity(kind="desktop", version="2.35.0rc2")
    assert rc_id.header_value() == "2.35.0rc2; channel=rc; kind=desktop"
    assert rc_id.header_value(kind="relay") == "2.35.0rc2; channel=rc; kind=relay"

    preview_runtime = _fake_runtime(
        DistributionKind.PACKAGED_DESKTOP, version="2.35.0", release_channel="preview",
    )
    preview_id = configure_client_identity(kind="tui", runtime=preview_runtime)
    assert preview_id.header_value() == "2.35.0; channel=rc; kind=cli"
    assert preview_id.install_kind is DistributionKind.PACKAGED_DESKTOP


def test_api_client_sends_x_servonaut_client_on_requests_and_signed() -> None:
    configure_client_identity(kind="desktop", version="2.34.0")
    seen_headers: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        return httpx.Response(200, json={"ok": True})

    auth = SimpleNamespace(access_token="tok-1", refresh_token=AsyncMock(return_value=False))
    client = APIClient(auth)
    client.transport = httpx.MockTransport(handler)
    _run(client.get("/api/v1/teams"))

    signer = SimpleNamespace(device_id="dev-1", sign=lambda _msg: b"sig")
    _run(client.request_signed("POST", "/api/v1/vault/items", json={"a": 1}, device=signer))

    assert len(seen_headers) == 2
    for hdrs in seen_headers:
        assert hdrs["x-servonaut-client"] == "2.34.0; channel=stable; kind=desktop"
        assert hdrs["user-agent"] == "servonaut-cli/2.34.0"


def test_auth_service_requests_include_x_servonaut_client(monkeypatch, tmp_path) -> None:
    import servonaut.services.auth_service as auth_mod

    configure_client_identity(kind="cli", version="2.34.0")
    recorded: list[tuple[str, dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        recorded.append((request.url.path, dict(request.headers)))
        if request.url.path == "/api/oauth/device":
            return httpx.Response(200, json={"device_code": "dc", "user_code": "ABCD"})
        if request.url.path == "/api/oauth/refresh":
            return httpx.Response(
                200,
                json={"access_token": "new-a", "refresh_token": "new-r", "expires_in": 3600},
            )
        if request.url.path == "/api/entitlements":
            return httpx.Response(200, json={"plan": "teams", "features": {}})
        if request.url.path == "/api/v1/teams":
            return httpx.Response(200, json={"teams": []})
        if request.url.path == "/api/v1/me":
            return httpx.Response(200, json={"id": 42})
        return httpx.Response(200, json={})

    transport = httpx.MockTransport(handler)
    real_async_client = httpx.AsyncClient

    class _Client(real_async_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    monkeypatch.setattr(auth_mod, "AUTH_FILE", tmp_path / "auth.json")

    svc = AuthService()
    svc._token = AuthToken(access_token="acc", refresh_token="ref", expires_at=9999999999.0)

    _run(svc.start_device_flow(client_kind="desktop"))
    _run(svc._post_refresh("https://api.servonaut.dev/api/oauth/refresh", "ref"))
    _run(svc.fetch_entitlements())
    _run(svc.list_teams(force_refresh=True))
    _run(svc.fetch_user_id())
    _run(svc.logout())

    paths = [path for path, _ in recorded]
    assert "/api/oauth/device" in paths
    assert "/api/oauth/refresh" in paths
    assert "/api/entitlements" in paths
    assert "/api/v1/teams" in paths
    assert "/api/v1/me" in paths
    assert "/api/oauth/revoke" in paths

    for path, hdrs in recorded:
        assert "x-servonaut-client" in hdrs, f"missing header on {path}"
        if path == "/api/oauth/device":
            assert hdrs["x-servonaut-client"] == "2.34.0; channel=stable; kind=desktop"
        else:
            assert hdrs["x-servonaut-client"] == "2.34.0; channel=stable; kind=cli"


def test_relay_listener_sends_relay_kind_and_stops_on_426_heartbeat(caplog) -> None:
    configure_client_identity(kind="cli", version="2.31.0", runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"))
    captured_headers: list[dict[str, str]] = []
    callback_messages: list[str] = []

    async def on_update_required(msg: str) -> None:
        callback_messages.append(msg)

    listener = RelayListener(
        executors=SimpleNamespace(),
        base_url="https://api.servonaut.dev",
        mercure_url="https://servonaut.dev/.well-known/mercure",
        auth_token="tok-1",
        user_id="42",
        heartbeat_interval=1,
        on_update_required=on_update_required,
        refresh_callback=AsyncMock(return_value=True),
    )

    async def fake_post(url, *, headers=None, **kwargs):
        captured_headers.append(dict(headers or {}))
        return httpx.Response(
            426,
            headers={"Upgrade": "servonaut/2.34.0"},
            json={
                "error": {
                    "code": "client_update_required",
                    "http": 426,
                    "message": "Too old",
                    "details": {
                        "client_version": "2.31.0",
                        "minimum_version": "2.34.0",
                        "latest_version": "2.34.0",
                        "channel": "stable",
                        "update_url": "https://servonaut.dev/download",
                    },
                }
            },
        )

    listener._client = SimpleNamespace(post=fake_post)
    listener._running = True

    with caplog.at_level(logging.ERROR, logger="servonaut.services.relay_listener"):
        _run(listener._heartbeat_loop())

    # Sent exactly once (no 401 refresh retry, no second heartbeat tick).
    assert len(captured_headers) == 1
    assert captured_headers[0][CLIENT_HEADER_NAME] == "2.31.0; channel=stable; kind=relay"
    assert captured_headers[0]["User-Agent"] == "servonaut-cli/2.31.0"
    listener._refresh_callback.assert_not_awaited()
    assert listener._running is False
    assert len(callback_messages) == 1
    assert "2.34.0" in callback_messages[0]
    assert "pipx upgrade servonaut" in callback_messages[0]
    # Logged exactly once.
    assert sum(1 for rec in caplog.records if "Relay stopped (HTTP 426)" in rec.message) == 1


def test_relay_listener_stops_on_426_mercure_token_without_retry(monkeypatch) -> None:
    configure_client_identity(kind="relay", version="2.31.0", runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"))
    callback_messages: list[str] = []
    seen_get_headers: list[dict[str, str]] = []
    sleep_calls = 0

    async def fake_sleep(_seconds):
        nonlocal sleep_calls
        sleep_calls += 1

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    async def on_update_required(msg: str) -> None:
        callback_messages.append(msg)

    listener = RelayListener(
        executors=SimpleNamespace(),
        base_url="https://api.servonaut.dev",
        mercure_url="https://servonaut.dev/.well-known/mercure",
        auth_token="tok-1",
        user_id="42",
        on_update_required=on_update_required,
    )

    async def fake_get(url, *, headers=None, **kwargs):
        seen_get_headers.append(dict(headers or {}))
        req = httpx.Request("GET", url)
        return httpx.Response(
            426,
            request=req,
            headers={"Upgrade": "servonaut/2.34.0"},
            json={
                "error": {
                    "code": "client_update_required",
                    "http": 426,
                    "message": "Too old",
                    "details": {"minimum_version": "2.34.0"},
                }
            },
        )

    listener._client = SimpleNamespace(get=fake_get)
    listener._running = True

    _run(listener._listen_forever())

    assert len(seen_get_headers) == 1
    assert seen_get_headers[0][CLIENT_HEADER_NAME] == "2.31.0; channel=stable; kind=relay"
    assert sleep_calls == 0
    assert listener._running is False
    assert len(callback_messages) == 1
    assert "2.34.0" in callback_messages[0]


def test_relay_manager_transitions_to_update_required() -> None:
    states: list[RelayState] = []
    mgr = RelayManager(
        config_manager=SimpleNamespace(get=lambda: SimpleNamespace()),
        auth_service=SimpleNamespace(is_authenticated=True),
        on_state_change=states.append,
    )
    msg = "This version of Servonaut is too old. Update to 2.34.0."
    _run(mgr._handle_update_required(msg))

    assert mgr.state is RelayState.UPDATE_REQUIRED
    assert mgr.update_required_message == msg
    assert states[-1] is RelayState.UPDATE_REQUIRED

    from servonaut.widgets.relay_indicator import _format

    assert "update required" in _format(RelayState.UPDATE_REQUIRED)


def test_mcp_hosted_call_sends_header_and_classifies_426() -> None:
    from servonaut.mcp import hosted_call

    configure_client_identity(kind="mcp", version="2.31.0", runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"))
    req = httpx.Request("POST", "https://mcp.servonaut.dev/mcp")
    resp = httpx.Response(
        426,
        request=req,
        headers={"Upgrade": "servonaut/2.34.0"},
        json={
            "error": {
                "code": "client_update_required",
                "http": 426,
                "message": "Too old",
                "details": {"minimum_version": "2.34.0"},
            }
        },
    )
    err = hosted_call._classify(httpx.HTTPStatusError("426", request=req, response=resp))
    assert err.code == "client_update_required"
    assert err.status == 426
    assert "2.34.0" in str(err)
    assert "pipx upgrade servonaut" in str(err)


def test_mcp_api_request_sends_client_header_and_blocks_override(monkeypatch) -> None:
    from servonaut.mcp.tools import ServonautTools

    configure_client_identity(kind="mcp", version="2.34.0")
    captured: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(dict(request.headers))
        return httpx.Response(200, json={"connected": True})

    transport = httpx.MockTransport(handler)
    real_async_client = httpx.AsyncClient

    class _Client(real_async_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    from collections import deque

    tools = ServonautTools.__new__(ServonautTools)
    tools._auth_service = SimpleNamespace(is_authenticated=True, access_token="tok-mcp")
    tools._api_request_window = deque()
    tools._api_base_url = lambda: "https://api.servonaut.dev"

    res = _run(
        tools._api_request_impl(
            "GET",
            "/api/cli/status",
            None,
            None,
            {"X-Servonaut-Client": "9.9.9; channel=stable; kind=cli"},
        )
    )
    assert res["status"] == 200
    assert captured[0]["x-servonaut-client"] == "2.34.0; channel=stable; kind=mcp"
    assert captured[0]["user-agent"] == "servonaut-cli/2.34.0"


# ---------------------------------------------------------------------------
# A2: 426 parsing, install-specific copy, AI/Vault/CLI presentation
# ---------------------------------------------------------------------------


def test_api_client_maps_426_and_never_retries() -> None:
    configure_client_identity(kind="cli", version="2.31.0", runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"))
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            426,
            headers={"Upgrade": "servonaut/2.34.0"},
            json={
                "error": {
                    "code": "client_update_required",
                    "http": 426,
                    "message": "Old server msg",
                    "details": {
                        "client_version": "2.31.0",
                        "minimum_version": "2.34.0",
                        "latest_version": "2.34.0",
                        "channel": "stable",
                        "update_url": "https://servonaut.dev/download",
                    },
                    "retry_after_seconds": None,
                }
            },
        )

    refresh = AsyncMock(return_value=True)
    auth = SimpleNamespace(access_token="tok", refresh_token=refresh)
    client = APIClient(auth)
    client.transport = httpx.MockTransport(handler)

    with pytest.raises(ClientUpdateRequiredError) as exc_info:
        _run(client.get("/api/v1/teams"))

    err = exc_info.value
    assert calls == 1
    refresh.assert_not_awaited()
    assert err.status == 426
    assert err.code == "client_update_required"
    assert err.is_retryable is False
    assert err.minimum_version == "2.34.0"
    assert err.latest_version == "2.34.0"
    assert err.client_version == "2.31.0"
    assert err.channel == "stable"
    assert err.update_url == "https://servonaut.dev/download"
    assert err.server_message == "Old server msg"
    assert "2.34.0" in err.message
    assert "pipx upgrade servonaut" in err.message


def test_api_client_426_plain_text_uses_upgrade_header() -> None:
    configure_client_identity(kind="cli", version="2.31.0", runtime=_fake_runtime(DistributionKind.PIP, version="2.31.0"))

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            426,
            headers={"Upgrade": "servonaut/2.35.0"},
            text="Upgrade Required",
        )

    auth = SimpleNamespace(access_token="tok", refresh_token=AsyncMock(return_value=False))
    client = APIClient(auth)
    client.transport = httpx.MockTransport(handler)

    with pytest.raises(ClientUpdateRequiredError) as exc_info:
        _run(client.get("/api/v1/teams"))

    assert exc_info.value.minimum_version == "2.35.0"
    assert "pip install --upgrade servonaut" in exc_info.value.message
    assert parse_upgrade_header("servonaut/2.35.0rc1") == "2.35.0rc1"
    assert parse_upgrade_header("servonaut/not-valid") == ""


@pytest.mark.parametrize(
    "install_kind, platform_name, apt_managed, expected_step",
    [
        (DistributionKind.PIPX, "linux", False, "pipx upgrade servonaut"),
        (DistributionKind.PIP, "linux", False, "pip install --upgrade servonaut"),
        # Today's shipped Linux .deb / AppImage has no APT repo yet -> download page.
        (DistributionKind.PACKAGED_DESKTOP, "linux", False, "https://servonaut.dev/download"),
        # Only when an APT repo is configured do we suggest apt with --only-upgrade.
        (DistributionKind.PACKAGED_DESKTOP, "linux", True, "sudo apt update && sudo apt install --only-upgrade servonaut"),
        ("apt", "linux", None, "sudo apt update && sudo apt install --only-upgrade servonaut"),
        (DistributionKind.PACKAGED_DESKTOP, "darwin", False, "https://servonaut.dev/download"),
        (DistributionKind.FROZEN_CLI, "darwin", False, "https://servonaut.dev/download"),
        (DistributionKind.SOURCE, "linux", False, "update your source checkout"),
    ],
)
def test_install_specific_update_required_messages(
    install_kind: DistributionKind | str,
    platform_name: str,
    apt_managed: bool | None,
    expected_step: str,
) -> None:
    msg = format_update_required_message(
        "2.34.0",
        install_kind=install_kind,
        platform_name=platform_name,
        apt_managed=apt_managed,
    )
    assert "2.34.0" in msg
    assert expected_step in msg
    assert "apt upgrade servonaut" not in msg


def test_is_apt_managed_install_checks_servonaut_repo_files(tmp_path) -> None:
    assert is_apt_managed_install(platform_name="linux", sources_dir=tmp_path) is False
    assert is_apt_managed_install(platform_name="darwin", sources_dir=tmp_path) is False
    (tmp_path / "other.list").write_text("deb https://example.com/ stable main\n", encoding="utf-8")
    assert is_apt_managed_install(platform_name="linux", sources_dir=tmp_path) is False
    (tmp_path / "servonaut.sources").write_text("Types: deb\n", encoding="utf-8")
    assert is_apt_managed_install(platform_name="linux", sources_dir=tmp_path) is True
    assert is_apt_managed_install(platform_name="darwin", sources_dir=tmp_path) is False


def test_format_update_required_prefers_sanitized_server_update_hints() -> None:
    configure_client_identity(
        kind="cli",
        version="2.31.0",
        runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"),
    )
    err = ClientUpdateRequiredError(
        code="client_update_required",
        message="Too old",
        status=426,
        details={
            "minimum_version": "2.35.0",
            "update_hints": {
                "pipx": "pipx upgrade\x1b[31m servonaut --force\u202e",
                "apt": "sudo apt update && sudo apt install --only-upgrade servonaut",
                "desktop": "https://servonaut.dev/download/desktop",
            },
        },
    )
    assert err.update_hints["pipx"] == "pipx upgrade[31m servonaut --force"
    assert "\x1b" not in err.message
    assert "\u202e" not in err.message
    assert "pipx upgrade[31m servonaut --force" in err.message

    apt_msg = format_update_required_message(
        err,
        install_kind=DistributionKind.PACKAGED_DESKTOP,
        platform_name="linux",
        apt_managed=True,
    )
    assert "sudo apt update && sudo apt install --only-upgrade servonaut" in apt_msg

    desktop_msg = format_update_required_message(
        err,
        install_kind=DistributionKind.PACKAGED_DESKTOP,
        platform_name="linux",
        apt_managed=False,
    )
    assert "https://servonaut.dev/download/desktop" in desktop_msg


def test_api_client_426_variants_plain_empty_missing_details_and_non_utf8() -> None:
    configure_client_identity(
        kind="cli",
        version="2.31.0",
        runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"),
    )
    auth = SimpleNamespace(access_token="tok", refresh_token=AsyncMock(return_value=False))
    client = APIClient(auth)

    # 1. Empty 426 body with NO Upgrade header -> clean fallback with empty minimum_version.
    client.transport = httpx.MockTransport(lambda _req: httpx.Response(426, content=b""))
    with pytest.raises(ClientUpdateRequiredError) as exc_empty:
        _run(client.get("/api/v1/teams"))
    assert exc_empty.value.minimum_version == ""
    assert "Update Servonaut to continue" in exc_empty.value.message

    # 2. JSON 426 whose details omit minimum_version falls back to Upgrade header.
    client.transport = httpx.MockTransport(
        lambda _req: httpx.Response(
            426,
            headers={"Upgrade": "servonaut/2.36.0"},
            json={"error": {"code": "client_update_required", "message": "Too old", "details": {}}},
        )
    )
    with pytest.raises(ClientUpdateRequiredError) as exc_details:
        _run(client.get("/api/v1/teams"))
    assert exc_details.value.minimum_version == "2.36.0"
    assert "2.36.0" in exc_details.value.message

    # 3. Non-UTF8 426 body + Upgrade header never leaks UnicodeDecodeError.
    client.transport = httpx.MockTransport(
        lambda _req: httpx.Response(
            426,
            headers={"Upgrade": "servonaut/2.37.0"},
            content=b"\xff\xfe\xfd",
        )
    )
    with pytest.raises(ClientUpdateRequiredError) as exc_bin:
        _run(client.get("/api/v1/teams"))
    assert exc_bin.value.minimum_version == "2.37.0"
    assert "2.37.0" in exc_bin.value.message


def test_mcp_api_request_blocks_case_insensitive_override_and_surfaces_426(monkeypatch) -> None:
    from collections import deque
    from servonaut.mcp.tools import ServonautTools

    configure_client_identity(
        kind="mcp",
        version="2.31.0",
        runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"),
    )
    seen_headers: list[list[tuple[str, str]]] = []
    next_response = [
        httpx.Response(200, json={"connected": True}),
        httpx.Response(
            426,
            headers={"Upgrade": "servonaut/2.35.0"},
            json={
                "error": {
                    "code": "client_update_required",
                    "message": "Raw server text",
                    "details": {
                        "minimum_version": "2.35.0",
                        "update_hints": {"pipx": "pipx upgrade servonaut"},
                    },
                }
            },
        ),
        httpx.Response(
            426,
            headers={"Upgrade": "TLS/1.2, HTTP/1.1"},
            text="Proxy upgrade required",
        ),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(list(request.headers.multi_items()))
        return next_response.pop(0)

    transport = httpx.MockTransport(handler)
    real_async_client = httpx.AsyncClient

    class _Client(real_async_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    tools = ServonautTools.__new__(ServonautTools)
    tools._auth_service = SimpleNamespace(is_authenticated=True, access_token="tok-mcp")
    tools._api_request_window = deque()
    tools._api_base_url = lambda: "https://api.servonaut.dev"
    tools._audit = MagicMock()

    # Case-insensitive override attempt must not replace or duplicate X-Servonaut-Client.
    res_ok = _run(
        tools._api_request_impl(
            "GET",
            "/api/cli/status",
            None,
            None,
            {
                "x-servonaut-client": "9.9.9; channel=stable; kind=cli",
                "X-SERVONAUT-CLIENT": "8.8.8; channel=stable; kind=cli",
                "user-agent": "evil-agent/1.0",
            },
        )
    )
    assert res_ok["status"] == 200
    x_vals = [v for k, v in seen_headers[0] if k.lower() == "x-servonaut-client"]
    assert x_vals == ["2.31.0; channel=stable; kind=mcp"]
    ua_vals = [v for k, v in seen_headers[0] if k.lower() == "user-agent"]
    assert ua_vals == ["servonaut-cli/2.31.0"]

    # Genuine 426 returns structured client_update_required with unified message via relay_status.
    status_out = json.loads(_run(tools.relay_status()))
    assert status_out["error"]["code"] == "client_update_required"
    assert "2.35.0" in status_out["error"]["message"]
    assert "pipx upgrade servonaut" in status_out["error"]["message"]

    # Bare/proxy 426 (no client_update_required, no Upgrade: servonaut/...) is not mapped.
    res_proxy = _run(tools._api_request_impl("GET", "/api/cli/status", None, None, None))
    assert "error" not in res_proxy
    assert res_proxy["status"] == 426


def test_hosted_call_does_not_misclassify_bare_proxy_426() -> None:
    from servonaut.mcp import hosted_call

    req = httpx.Request("POST", "https://mcp.servonaut.dev/mcp")
    bare_resp = httpx.Response(426, request=req, headers={"Upgrade": "TLS/1.2"}, text="Upgrade Required")
    assert response_is_update_required(bare_resp) is False
    err = hosted_call._classify(httpx.HTTPStatusError("426", request=req, response=bare_resp))
    assert err.code == "http_error"
    assert err.status == 426


def test_ai_error_handler_maps_426_and_sse_update_required_separately_from_subscriptions() -> None:
    configure_client_identity(kind="cli", version="2.31.0", runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"))
    api_err = ClientUpdateRequiredError(
        code="client_update_required",
        message="Too old",
        status=426,
        details={"minimum_version": "2.34.0", "update_url": "https://evil.example/phish"},
    )
    payload_api = map_error_to_action(api_err)
    assert payload_api.action is UserFacingAction.CLIENT_UPDATE_REQUIRED
    assert payload_api.action is not UserFacingAction.MODAL_UPGRADE_REQUIRED
    assert payload_api.code == "client_update_required"
    assert payload_api.upgrade_url == DEFAULT_UPDATE_URL
    assert "2.34.0" in payload_api.user_message
    assert "pipx upgrade servonaut" in payload_api.user_message

    sse_err = SSEStreamError(
        code="client_update_required",
        message="Too old",
        details={"minimum_version": "2.34.0"},
    )
    payload_sse = map_error_to_action(sse_err)
    assert payload_sse.action is UserFacingAction.CLIENT_UPDATE_REQUIRED
    assert "2.34.0" in payload_sse.user_message


def test_vault_failure_reason_surfaces_update_required() -> None:
    configure_client_identity(kind="cli", version="2.31.0", runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"))
    err = ClientUpdateRequiredError(
        code="client_update_required",
        message="Too old",
        status=426,
        details={"minimum_version": "2.34.0"},
    )
    reason = vault_failure_reason(err)
    assert "2.34.0" in reason
    assert "pipx upgrade servonaut" in reason
    assert "HTTP 426" not in reason


def test_cli_team_rules_surfaces_426_and_exits_nonzero(monkeypatch, capsys) -> None:
    from servonaut.cli import team as team_cli

    configure_client_identity(kind="cli", version="2.31.0", runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"))
    err = ClientUpdateRequiredError(
        code="client_update_required",
        message="Too old",
        status=426,
        details={"minimum_version": "2.34.0"},
    )

    fake_service = SimpleNamespace(
        list_teams=AsyncMock(side_effect=err),
    )
    monkeypatch.setattr(team_cli, "_service_factory", lambda: fake_service)

    args = SimpleNamespace(team_command="rules", team="ops", json=False)
    rc = team_cli.handle_team_command(args)
    captured = capsys.readouterr()

    assert rc != 0
    assert "2.34.0" in captured.err
    assert "pipx upgrade servonaut" in captured.err
    assert "(APIError)" not in captured.err


def test_cli_ai_buffered_surfaces_426_and_exits_nonzero(capsys) -> None:
    from servonaut.cli.ai import _do_chat_buffered

    configure_client_identity(kind="cli", version="2.31.0", runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"))
    err = ClientUpdateRequiredError(
        code="client_update_required",
        message="Too old",
        status=426,
        details={"minimum_version": "2.34.0"},
    )
    provider = SimpleNamespace(chat=AsyncMock(side_effect=err))
    rc = _run(_do_chat_buffered(provider, [{"role": "user", "content": "hi"}], SimpleNamespace(), "general", False))
    captured = capsys.readouterr()

    assert rc != 0
    assert "2.34.0" in captured.err
    assert "pipx upgrade servonaut" in captured.err


def test_cli_team_rules_shared_servers_426_exits_nonzero(monkeypatch, capsys) -> None:
    from servonaut.cli import team as team_cli

    configure_client_identity(kind="cli", version="2.31.0", runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"))
    err = ClientUpdateRequiredError(
        code="client_update_required",
        message="Too old",
        status=426,
        details={"minimum_version": "2.34.0"},
    )
    fake_service = SimpleNamespace(
        list_teams=AsyncMock(return_value=[{"slug": "ops", "name": "Ops", "id": "t1", "role": "member"}]),
        get_policy_with_headers=AsyncMock(return_value=({}, {})),
        list_shared_servers=AsyncMock(side_effect=err),
    )
    monkeypatch.setattr(team_cli, "_service_factory", lambda: fake_service)

    args = SimpleNamespace(team_command="rules", team="ops", json=False)
    rc = team_cli.handle_team_command(args)
    captured = capsys.readouterr()

    assert rc != 0
    assert "2.34.0" in captured.err
    assert "pipx upgrade servonaut" in captured.err
    assert "left out" not in captured.err


def test_cli_ai_stream_surfaces_426_and_sse_update_required(capsys) -> None:
    from servonaut.cli.ai import _do_chat_stream

    configure_client_identity(kind="cli", version="2.31.0", runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"))

    async def _fail_stream(*_args, **_kwargs):
        raise SSEStreamError(
            code="client_update_required",
            message="Too old",
            details={"minimum_version": "2.34.0"},
        )
        yield  # pragma: no cover

    provider = SimpleNamespace(stream_chat=_fail_stream)
    rc = _run(_do_chat_stream(provider, [{"role": "user", "content": "hi"}], SimpleNamespace(), "general", False))
    captured = capsys.readouterr()

    assert rc != 0
    assert "2.34.0" in captured.err
    assert "pipx upgrade servonaut" in captured.err


def test_sse_pre_stream_426_sends_header_and_raises_update_required() -> None:
    configure_client_identity(kind="desktop", version="2.31.0", runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"))
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.headers))
        return httpx.Response(
            426,
            headers={"Upgrade": "servonaut/2.34.0"},
            json={
                "error": {
                    "code": "client_update_required",
                    "http": 426,
                    "message": "Too old",
                    "details": {"minimum_version": "2.34.0"},
                }
            },
        )

    auth = SimpleNamespace(access_token="tok", refresh_token=AsyncMock(return_value=False))
    client = APIClient(auth)
    client.transport = httpx.MockTransport(handler)

    async def _consume() -> None:
        async for _ in client.stream_sse("/api/ai/chat/stream", {"messages": []}):
            pass

    with pytest.raises(ClientUpdateRequiredError) as exc_info:
        _run(_consume())

    assert seen[0]["x-servonaut-client"] == "2.31.0; channel=stable; kind=desktop"
    assert exc_info.value.minimum_version == "2.34.0"


def test_relay_listener_hub_426_keeps_retrying_and_carries_relay_header(monkeypatch) -> None:
    import servonaut.services.relay_listener as rl_mod

    configure_client_identity(kind="desktop", version="2.34.0")
    captured_sse_headers: list[dict[str, str]] = []
    callback_messages: list[str] = []
    sleeps: list[float] = []

    class _FakeSSEContext:
        def __init__(self, headers):
            captured_sse_headers.append(dict(headers or {}))
            self.response = httpx.Response(
                426,
                headers={"Upgrade": "servonaut/2.35.0"},
                json={"error": {"code": "client_update_required", "details": {"minimum_version": "2.35.0"}}},
            )

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False

    monkeypatch.setattr(
        rl_mod,
        "aconnect_sse",
        lambda _client, _method, _url, *, params=None, headers=None: _FakeSSEContext(headers),
    )

    async def on_update_required(msg: str) -> None:
        callback_messages.append(msg)

    listener = RelayListener(
        executors=SimpleNamespace(),
        base_url="https://api.servonaut.dev",
        mercure_url="https://servonaut.dev/.well-known/mercure",
        auth_token="tok-1",
        user_id="42",
        on_update_required=on_update_required,
    )
    listener._mercure_jwt = "jwt-token"
    listener._mercure_jwt_fetched_at = 10**12
    listener._running = True

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        listener._running = False  # stop after confirming normal backoff retry

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    _run(listener._listen_forever())

    assert len(captured_sse_headers) == 1
    assert captured_sse_headers[0][CLIENT_HEADER_NAME] == "2.34.0; channel=stable; kind=relay"
    assert captured_sse_headers[0]["User-Agent"] == "servonaut-cli/2.34.0"
    assert callback_messages == []
    assert sleeps == [1]


def test_relay_listener_bare_proxy_426_keeps_retrying_on_heartbeat_and_token(monkeypatch) -> None:
    configure_client_identity(kind="relay", version="2.31.0", runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"))
    callback_messages: list[str] = []
    hb_sleeps: list[float] = []
    token_sleeps: list[float] = []

    async def on_update_required(msg: str) -> None:
        callback_messages.append(msg)

    # 1. Heartbeat bare/proxy 426 must NOT stop the relay.
    listener_hb = RelayListener(
        executors=SimpleNamespace(),
        base_url="https://api.servonaut.dev",
        mercure_url="https://servonaut.dev/.well-known/mercure",
        auth_token="tok-1",
        user_id="42",
        heartbeat_interval=5,
        on_update_required=on_update_required,
    )

    async def fake_post(url, *, headers=None, **kwargs):
        return httpx.Response(
            426,
            request=httpx.Request("POST", url),
            headers={"Upgrade": "TLS/1.2"},
            text="Upgrade Required",
        )

    async def fake_hb_sleep(seconds: float) -> None:
        hb_sleeps.append(seconds)
        listener_hb._running = False

    listener_hb._client = SimpleNamespace(post=fake_post)
    listener_hb._running = True
    monkeypatch.setattr(asyncio, "sleep", fake_hb_sleep)
    _run(listener_hb._heartbeat_loop())

    assert callback_messages == []
    assert hb_sleeps == [5]

    # 2. Mercure token bare/proxy 426 must NOT stop the relay.
    listener_tok = RelayListener(
        executors=SimpleNamespace(),
        base_url="https://api.servonaut.dev",
        mercure_url="https://servonaut.dev/.well-known/mercure",
        auth_token="tok-1",
        user_id="42",
        on_update_required=on_update_required,
    )

    async def fake_get(url, *, headers=None, **kwargs):
        return httpx.Response(
            426,
            request=httpx.Request("GET", url),
            text="Proxy upgrade required",
        )

    async def fake_tok_sleep(seconds: float) -> None:
        token_sleeps.append(seconds)
        listener_tok._running = False

    listener_tok._client = SimpleNamespace(get=fake_get)
    listener_tok._running = True
    monkeypatch.setattr(asyncio, "sleep", fake_tok_sleep)
    _run(listener_tok._listen_forever())

    assert callback_messages == []
    assert token_sleeps == [1]


def test_relay_status_screen_surfaces_update_required_message() -> None:
    from servonaut.widgets.relay_indicator import RelayStatusScreen

    msg = "This version of Servonaut is too old for team and cloud features. Update to 2.35.0 or later to continue (run: pipx upgrade servonaut)."
    updated: list[object] = []
    screen = SimpleNamespace(
        app=SimpleNamespace(
            relay_state=RelayState.UPDATE_REQUIRED,
            relay_lock_path=Path("/nonexistent-relay-lock"),
            relay_manager=SimpleNamespace(last_error=None, update_required_message=msg),
            demo_mode=False,
        ),
        query_one=lambda _sel, _cls=None: SimpleNamespace(update=updated.append),
    )
    RelayStatusScreen._refresh_local(screen)
    assert updated and "2.35.0" in str(updated[0]) and "pipx upgrade servonaut" in str(updated[0])


def test_version_policy_handles_non_utf8_and_malformed_cache_control(tmp_path) -> None:
    configure_client_identity(kind="cli", version="2.34.0")
    cache_file = tmp_path / "version-policy.json"
    seed = VersionPolicy(mode="log", minimum_version="2.34.0")
    assert save_cached_version_policy(seed, cache_file) is True

    # Non-UTF8 response body fails open to disk cache without raising.
    bad_utf8 = VersionPolicyClient(
        cache_path=cache_file,
        transport=httpx.MockTransport(
            lambda _req: httpx.Response(200, content=b"\xff\xfe\x00\x80")
        ),
        base_url_provider=lambda: "https://api.servonaut.dev",
    )
    res_utf8 = _run(bad_utf8.fetch())
    assert res_utf8 is not None and res_utf8.minimum_version == "2.34.0"

    # Malformed / absurdly large Cache-Control max-age does not raise and falls back to default TTL.
    huge_age = "9" * 400
    seen_headers: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        return httpx.Response(
            200,
            headers={"Cache-Control": f"public, max-age={huge_age}"},
            json={
                "mode": "log",
                "minimum_version": "2.35.0",
                "latest": {"stable": "2.35.0", "rc": None},
                "update_url": "https://servonaut.dev/download",
            },
        )

    client = VersionPolicyClient(
        cache_path=cache_file,
        max_age_seconds=120.0,
        transport=httpx.MockTransport(handler),
        base_url_provider=lambda: "https://api.servonaut.dev",
    )
    res = _run(client.fetch(force_refresh=True))
    assert res is not None and res.minimum_version == "2.35.0"
    assert client._effective_ttl == 120.0
    assert seen_headers[0]["x-servonaut-client"] == seen_headers[0]["x-servonaut-client"].strip()


# ---------------------------------------------------------------------------
# A3: Version policy client, disk cache, offline fail-open, entitlements
# ---------------------------------------------------------------------------


def test_version_policy_parsing_and_hints() -> None:
    raw = {
        "mode": "enforce",
        "minimum_version": "2.34.0",
        "upcoming": {
            "minimum_version": "2.35.0",
            "effective_at": "2026-12-01T00:00:00+00:00",
        },
        "latest": {"stable": "2.34.0", "rc": "2.35.0rc1"},
        "update_url": "https://servonaut.dev/download",
        "update_hints": {
            "pipx": "pipx upgrade servonaut",
            "desktop": "https://servonaut.dev/download",
            "apt": "sudo apt upgrade servonaut",
            "future_kind": "some future hint",
        },
    }
    policy = VersionPolicy.from_dict(raw, fetched_at=1700000000.0)
    assert policy is not None
    assert policy.mode == "enforce"
    assert policy.minimum_version == "2.34.0"
    assert policy.upcoming is not None
    assert policy.upcoming.minimum_version == "2.35.0"
    assert policy.latest.stable == "2.34.0"
    assert policy.latest.rc == "2.35.0rc1"
    assert policy.is_enforced_below_floor("2.31.0") is True
    assert policy.is_enforced_below_floor("2.34.0") is False
    assert policy.is_enforced_below_floor("unknown") is False
    assert policy.hint_for("pipx") == "pipx upgrade servonaut"
    assert policy.hint_for("unrecognized") == "https://servonaut.dev/download"


def test_version_policy_client_caches_and_fails_open_offline(tmp_path) -> None:
    configure_client_identity(kind="cli", version="2.34.0")
    cache_file = tmp_path / "version-policy.json"
    calls = 0
    seen_headers: list[dict[str, str]] = []

    def ok_handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        seen_headers.append(dict(request.headers))
        assert request.url.path == "/api/v1/client/version-policy"
        assert "authorization" not in request.headers
        return httpx.Response(
            200,
            headers={"Cache-Control": "public, max-age=300"},
            json={
                "mode": "log",
                "minimum_version": "2.34.0",
                "upcoming": None,
                "latest": {"stable": "2.34.0", "rc": None},
                "update_url": "https://servonaut.dev/download",
                "update_hints": {"pipx": "pipx upgrade servonaut"},
            },
        )

    client = VersionPolicyClient(
        cache_path=cache_file,
        transport=httpx.MockTransport(ok_handler),
        base_url_provider=lambda: "https://api.servonaut.dev",
    )
    first = _run(client.fetch())
    second = _run(client.fetch())

    assert calls == 1
    assert first is not None and second == first
    assert seen_headers[0]["x-servonaut-client"] == "2.34.0; channel=stable; kind=cli"
    assert cache_file.is_file()
    if os.name == "posix":
        assert stat.S_IMODE(cache_file.stat().st_mode) == 0o600

    # A fresh client that is offline falls back to the disk cache.
    def offline_handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    offline_client = VersionPolicyClient(
        cache_path=cache_file,
        transport=httpx.MockTransport(offline_handler),
        base_url_provider=lambda: "https://api.servonaut.dev",
    )
    fallback = _run(offline_client.fetch())
    assert fallback is not None
    assert fallback.minimum_version == "2.34.0"
    assert fallback.mode == "log"

    # Offline with no cache returns None and never raises.
    cold_client = VersionPolicyClient(
        cache_path=tmp_path / "missing.json",
        transport=httpx.MockTransport(offline_handler),
        base_url_provider=lambda: "https://api.servonaut.dev",
    )
    assert _run(cold_client.fetch()) is None


def test_corrupt_version_policy_cache_returns_none(tmp_path) -> None:
    bad = tmp_path / "version-policy.json"
    bad.write_text("{not-json", encoding="utf-8")
    assert load_cached_version_policy(bad) is None

    policy = VersionPolicy(mode="log", minimum_version="2.34.0")
    assert save_cached_version_policy(policy, bad) is True
    loaded = load_cached_version_policy(bad)
    assert loaded is not None
    assert loaded.minimum_version == "2.34.0"


def test_entitlements_applies_and_caches_additive_client_version_policy(monkeypatch, tmp_path) -> None:
    import servonaut.services.auth_service as auth_mod

    monkeypatch.setattr(auth_mod, "AUTH_FILE", tmp_path / "auth.json")
    svc = AuthService()
    svc._token = AuthToken(access_token="acc", refresh_token="ref", expires_at=9999999999.0)

    svc._apply_entitlements(
        {
            "plan": "teams",
            "features": {"premium_ai": True},
            "client_version_policy": {
                "mode": "enforce",
                "minimum_version": "2.34.0",
                "upcoming": None,
                "latest": {"stable": "2.34.0", "rc": "2.35.0rc1"},
                "update_url": "https://servonaut.dev/download",
                "update_hints": {"pipx": "pipx upgrade servonaut"},
            },
        }
    )

    cached = svc.cached_version_policy()
    assert cached is not None
    assert cached.mode == "enforce"
    assert cached.minimum_version == "2.34.0"
    assert cached.latest.rc == "2.35.0rc1"
    # Also persisted to the shared disk cache under isolated HOME.
    disk = load_cached_version_policy()
    assert disk is not None
    assert disk.minimum_version == "2.34.0"


def test_chat_panel_handle_stream_error_for_426_sets_banner_and_notifies_without_entitlement_refresh() -> None:
    from servonaut.widgets.chat_panel import ChatPanel

    configure_client_identity(kind="cli", version="2.31.0", runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"))
    notifications: list[tuple[str, dict]] = []
    banners: list[str] = []
    workers: list[tuple] = []

    fake_app = SimpleNamespace(
        auth_service=SimpleNamespace(fetch_entitlements=AsyncMock()),
        notify=lambda msg, **kwargs: notifications.append((msg, kwargs)),
    )
    panel = SimpleNamespace(
        app=fake_app,
        _set_banner=banners.append,
        _push_topup_modal=MagicMock(),
        _record_upstream_failure=MagicMock(),
        _maybe_offer_fallback=MagicMock(),
        _update_stats=MagicMock(),
        run_worker=lambda *args, **kwargs: workers.append((args, kwargs)),
    )

    err = ClientUpdateRequiredError(
        code="client_update_required",
        message="Too old",
        status=426,
        details={"minimum_version": "2.34.0"},
    )
    ChatPanel._handle_stream_error(panel, err, "")

    assert len(banners) == 1
    assert "2.34.0" in banners[0]
    assert len(notifications) == 1
    assert "pipx upgrade servonaut" in notifications[0][0]
    assert notifications[0][1].get("markup") is False
    panel._push_topup_modal.assert_not_called()
    assert workers == []


def test_app_relay_state_change_notifies_once_on_update_required() -> None:
    from servonaut.app import ServonautApp

    notifications: list[tuple[str, dict]] = []
    msg = "This version of Servonaut is too old. Update to 2.34.0."
    stub = SimpleNamespace(
        relay_state=RelayState.CONNECTED,
        runtime_layout=_fake_runtime(DistributionKind.PIPX, version="2.31.0"),
        relay_manager=SimpleNamespace(update_required_message=msg),
        query=lambda _cls: [],
        notify=lambda text, **kwargs: notifications.append((text, kwargs)),
    )

    ServonautApp._on_relay_state_change(stub, RelayState.UPDATE_REQUIRED)
    ServonautApp._on_relay_state_change(stub, RelayState.UPDATE_REQUIRED)

    assert stub.relay_state is RelayState.UPDATE_REQUIRED
    assert len(notifications) == 1
    assert notifications[0][0] == msg
    assert notifications[0][1].get("markup") is False


def test_team_management_notifies_update_required_without_prefix() -> None:
    from servonaut.screens.team_management import TeamManagementScreen

    configure_client_identity(kind="cli", version="2.31.0", runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"))
    notifications: list[tuple[str, dict]] = []
    screen = SimpleNamespace(
        notify=lambda text, **kwargs: notifications.append((text, kwargs)),
        _can_manage_admins=lambda: True,
    )
    err = ClientUpdateRequiredError(
        code="client_update_required",
        message="Too old",
        status=426,
        details={"minimum_version": "2.34.0"},
    )
    TeamManagementScreen._notify_member_write_error(screen, err, fallback="Failed to invite member")

    assert len(notifications) == 1
    assert notifications[0][0] == err.message
    assert notifications[0][1].get("severity") == "warning"
    assert notifications[0][1].get("markup") is False


def test_oversized_version_digits_and_nested_cache_never_raise(tmp_path) -> None:
    from servonaut.utils.package_version import PackageVersion

    big = "2." + ("9" * 5000)
    assert parse_contract_version(big) is None
    assert PackageVersion.parse(big) is None
    assert is_version_allowed("2.34.0", big) is True

    policy = VersionPolicy.from_dict(
        {
            "mode": "enforce",
            "minimum_version": big,
            "upcoming": {"minimum_version": big, "effective_at": "2026-12-01T00:00:00Z"},
            "latest": {"stable": big, "rc": big},
            "update_url": "https://servonaut.dev/download",
        }
    )
    assert policy is not None
    assert policy.minimum_version is None
    assert policy.upcoming is None
    assert policy.latest.stable is None
    assert policy.latest.rc is None

    err_details = ClientUpdateRequiredError(
        code="client_update_required",
        message="Too old",
        status=426,
        details={"minimum_version": big},
    )
    assert err_details.minimum_version == ""
    assert "Update Servonaut to continue" in err_details.message

    err_header = ClientUpdateRequiredError(
        code="client_update_required",
        message="Too old",
        status=426,
        response_headers={"Upgrade": f"servonaut/{big}"},
    )
    assert err_header.minimum_version == ""
    assert "Update Servonaut to continue" in err_header.message

    msg = format_update_required_message(big, install_kind=DistributionKind.PIPX)
    assert "pipx upgrade servonaut" in msg

    nested = tmp_path / "version-policy.json"
    nested.write_text("[" * 60000, encoding="utf-8")
    assert load_cached_version_policy(nested) is None


def test_safe_update_url_rejects_markup_and_bidi_and_vault_auto_bind_escapes() -> None:
    from rich.text import Text
    from servonaut.screens.vault_auto_bind import VaultAutoBindScreen
    from servonaut.services.version_policy import safe_update_url

    assert safe_update_url("https://servonaut.dev/[bold]x") == DEFAULT_UPDATE_URL
    assert safe_update_url("https://servonaut.dev/\u202ex") == DEFAULT_UPDATE_URL
    assert safe_update_url("https://servonaut.dev/download here") == DEFAULT_UPDATE_URL
    assert safe_update_url("https://servonaut.dev/download") == "https://servonaut.dev/download"
    assert (
        safe_update_url("https://www.servonaut.dev/releases/v2.35.0?ref=cli")
        == "https://www.servonaut.dev/releases/v2.35.0?ref=cli"
    )

    updated: list[object] = []
    stub_screen = SimpleNamespace(
        _status_raw="",
        scrub_for_display=lambda text: text,
        query_one=lambda _sel, _cls=None: SimpleNamespace(update=updated.append),
    )
    VaultAutoBindScreen._status(stub_screen, "[bold red]boom[/bold red]")
    assert len(updated) == 1
    assert isinstance(updated[0], Text)
    assert updated[0].plain == "[bold red]boom[/bold red]"


def test_auth_service_fetch_teams_raises_update_required_and_team_screen_surfaces_it(
    monkeypatch, tmp_path,
) -> None:
    import servonaut.services.auth_service as auth_mod
    from rich.text import Text
    from servonaut.screens.team_management import TeamManagementScreen

    configure_client_identity(
        kind="cli",
        version="2.31.0",
        runtime=_fake_runtime(DistributionKind.PIPX, version="2.31.0"),
    )
    monkeypatch.setattr(auth_mod, "AUTH_FILE", tmp_path / "auth.json")
    svc = AuthService()
    svc._token = AuthToken(access_token="acc", refresh_token="ref", expires_at=9999999999.0)

    transport = httpx.MockTransport(
        lambda _req: httpx.Response(
            426,
            headers={"Upgrade": "servonaut/2.35.0"},
            json={
                "error": {
                    "code": "client_update_required",
                    "message": "Upgrade required",
                    "details": {"minimum_version": "2.35.0"},
                }
            },
        )
    )
    real_async_client = httpx.AsyncClient

    class _Client(real_async_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(auth_mod.httpx, "AsyncClient", _Client)

    with pytest.raises(ClientUpdateRequiredError) as exc_info:
        _run(svc._fetch_teams(retry_after_refresh=True))

    err = exc_info.value
    assert err.minimum_version == "2.35.0"
    assert "pipx upgrade servonaut" in err.message

    # TeamManagementScreen._load_teams surfaces the update-required message instead of "no teams".
    summary_updates: list[object] = []
    notifications: list[tuple[str, dict]] = []
    busy = SimpleNamespace(start=MagicMock(), stop=MagicMock())

    def _query_one(selector, _cls=None):
        if selector == "#team_list_busy":
            return busy
        return SimpleNamespace(update=summary_updates.append)

    screen = SimpleNamespace(
        app=SimpleNamespace(team_service=SimpleNamespace(list_teams=AsyncMock(side_effect=err))),
        query_one=_query_one,
        _populate_teams_table=MagicMock(),
        notify=lambda text, **kwargs: notifications.append((text, kwargs)),
    )
    _run(TeamManagementScreen._load_teams(screen))

    screen._populate_teams_table.assert_not_called()
    assert len(summary_updates) == 1
    assert isinstance(summary_updates[0], Text)
    assert "2.35.0" in summary_updates[0].plain
    assert len(notifications) == 1
    assert "pipx upgrade servonaut" in notifications[0][0]
    assert notifications[0][1].get("markup") is False
    busy.stop.assert_called_once()


def test_device_flow_headers_use_captured_version_not_live_metadata(monkeypatch) -> None:
    import servonaut
    import servonaut.services.auth_service as auth_mod

    configure_client_identity(kind="cli", version="2.31.0")
    monkeypatch.setattr(servonaut, "get_version", lambda: "9.99.0")

    headers = auth_mod._device_flow_headers("tui")
    assert headers[CLIENT_HEADER_NAME] == "2.31.0; channel=stable; kind=cli"
    assert headers["User-Agent"].startswith("servonaut-tui/2.31.0 ")
    assert "9.99.0" not in headers["User-Agent"]


def test_cli_subcommand_configures_runtime_identity_before_dispatch(monkeypatch) -> None:
    import servonaut.main as main_mod
    import servonaut.runtime as runtime_mod
    import servonaut.cli.team as team_cli

    pip_runtime = _fake_runtime(DistributionKind.PIP, version="2.31.0")
    monkeypatch.setattr(runtime_mod, "detect_runtime", lambda: pip_runtime)
    monkeypatch.setattr("sys.argv", ["servonaut", "team", "rules", "ops"])

    captured_msg: list[str] = []

    def fake_handle_team(_args) -> int:
        captured_msg.append(format_update_required_message("2.35.0"))
        return 2

    monkeypatch.setattr(team_cli, "handle_team_command", fake_handle_team)

    with pytest.raises(SystemExit) as exc_info:
        main_mod.main()

    assert exc_info.value.code == 2
    assert len(captured_msg) == 1
    assert "pip install --upgrade servonaut" in captured_msg[0]
