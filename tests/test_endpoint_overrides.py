"""Environment overrides for third-party endpoints.

``SERVONAUT_PYPI_URL``, ``SERVONAUT_HETZNER_API_URL``, ``SERVONAUT_IP_API_URL``
and ``SERVONAUT_ABUSEIPDB_URL`` redirect the update check, the Hetzner Cloud
client and the IP lookups. Unset, every call keeps its production URL. Set, an
override must be https, or http to a loopback host; anything else is refused
before a request is made.

The loopback tests serve a tiny JSON fake on 127.0.0.1, which is exactly what
the http exception exists for.
"""
from __future__ import annotations

import asyncio
import http.client
import json
import logging
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from typing import Any, Dict, Iterator, List
from unittest.mock import patch

import pytest

from servonaut.config.schema import HetznerConfig
from servonaut.services import ip_enrichment_service, update_service
from servonaut.services.hetzner_service import (
    HETZNER_API_URL_ENV,
    HetznerNotConfiguredError,
    HetznerService,
)
from servonaut.services.ip_enrichment_service import (
    ABUSEIPDB_URL_ENV,
    IP_API_URL_ENV,
    IPEnrichmentService,
)
from servonaut.services.update_service import (
    PYPI_URL,
    PYPI_URL_ENV,
    HttpsOnlyRedirectHandler,
    UpdateCheckResult,
)
from servonaut.utils.endpoints import (
    EndpointOverrideError,
    endpoint_override,
    validate_endpoint_url,
)
from tests.test_update_service import _svc

_ALL_OVERRIDES = (PYPI_URL_ENV, HETZNER_API_URL_ENV, IP_API_URL_ENV, ABUSEIPDB_URL_ENV)


@pytest.fixture(autouse=True)
def _clean_endpoint_env(monkeypatch):
    """Start every test from production defaults and without proxies."""
    for name in _ALL_OVERRIDES:
        monkeypatch.delenv(name, raising=False)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)


class _FakeService(ThreadingHTTPServer):
    """Loopback JSON server that records every request it receives."""

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _FakeHandler)
        self.routes: Dict[str, Any] = {}
        self.redirects: Dict[str, str] = {}
        self.requests: List[Dict[str, Any]] = []

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class _FakeHandler(BaseHTTPRequestHandler):
    server: _FakeService

    def _respond(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.requests.append(
            {
                "method": self.command,
                "path": self.path,
                "body": body.decode("utf-8") if body else "",
                "headers": dict(self.headers),
            }
        )
        route = self.path.split("?", 1)[0]
        if route in self.server.redirects:
            self.send_response(302)
            self.send_header("Location", self.server.redirects[route])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if route not in self.server.routes:
            self.send_error(404)
            return
        payload = json.dumps(self.server.routes[route]).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _respond
    do_POST = _respond

    def log_message(self, *_args: Any) -> None:  # keep test output quiet
        return


@pytest.fixture
def fake_service() -> Iterator[_FakeService]:
    server = _FakeService()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "normalised"),
    [
        ("https://mirror.example/pypi/servonaut/json", "https://mirror.example/pypi/servonaut/json"),
        ("HTTPS://Mirror.Example/api", "https://Mirror.Example/api"),
        ("http://127.0.0.1:8080/pypi/servonaut/json", "http://127.0.0.1:8080/pypi/servonaut/json"),
        ("http://localhost/api", "http://localhost/api"),
        ("http://[::1]:9000/api", "http://[::1]:9000/api"),
    ],
)
def test_https_and_loopback_http_are_accepted_and_normalised(url, normalised):
    assert validate_endpoint_url(url, source="TEST_URL") == normalised


@pytest.mark.parametrize(
    "url",
    [
        "http://mirror.example/api",
        "http://10.0.0.5/api",
        "ftp://mirror.example/api",
        "file:///etc/hosts",
        "mirror.example/api",
        "https://",
        "http://[::1/api",
    ],
)
def test_other_urls_are_refused(url):
    with pytest.raises(EndpointOverrideError, match="TEST_URL"):
        validate_endpoint_url(url, source="TEST_URL")


@pytest.mark.parametrize(
    "url",
    [
        # urlsplit reads the host as 127.0.0.1; HTTP clients connect to 10.8.0.3.
        "http://10.8.0.3:8080\\@127.0.0.1/v1",
        "http://10.8.0.3\\@127.0.0.1/v1",
        "https://u:p@example.com/v1",
        "http://user@127.0.0.1/v1",
        "http://@127.0.0.1/v1",
        "https://mirror.example/a b",
        "https://mirror.example/a\tb",
        "https://mirror.example/\nv1",
        "https://mirror.example/v1\x00",
        " https://mirror.example/v1",
    ],
)
def test_credentials_backslashes_whitespace_and_controls_are_refused(url):
    with pytest.raises(EndpointOverrideError, match="TEST_URL"):
        validate_endpoint_url(url, source="TEST_URL")


@pytest.mark.parametrize(
    "url",
    ["https://mirror.example:abc/x", "http://[::1]:x/", "https://mirror.example:99999/x"],
)
def test_malformed_ports_are_refused(url):
    with pytest.raises(EndpointOverrideError, match="not a valid URL"):
        validate_endpoint_url(url, source="TEST_URL")


def test_refusal_does_not_echo_the_url():
    """A URL can carry credentials; the error names the variable only."""
    with pytest.raises(EndpointOverrideError) as excinfo:
        validate_endpoint_url("https://user:hunter2@example.com/", source="TEST_URL")
    assert "hunter2" not in str(excinfo.value)


def test_unset_or_blank_means_no_override(monkeypatch):
    assert endpoint_override("SERVONAUT_TEST_ENDPOINT") is None
    monkeypatch.setenv("SERVONAUT_TEST_ENDPOINT", "   ")
    assert endpoint_override("SERVONAUT_TEST_ENDPOINT") is None


# ---------------------------------------------------------------------------
# SERVONAUT_PYPI_URL
# ---------------------------------------------------------------------------


class _PyPIResponse:
    def __init__(self, version: str) -> None:
        self._body = json.dumps({"info": {"version": version}}).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_PyPIResponse":
        return self

    def __exit__(self, *_exc: Any) -> None:
        return None


class _RecordingOpener:
    """Stands in for the service's HTTPS-only opener."""

    def __init__(self, result: Any) -> None:
        self.result = result
        self.requested: List[str] = []

    def open(self, request, timeout):
        self.requested.append(request.full_url)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def test_update_check_reads_pypi_through_the_https_only_opener():
    service = _svc(current="2.16.3")
    assert any(isinstance(h, HttpsOnlyRedirectHandler) for h in service._opener.handlers)
    service._opener = _RecordingOpener(_PyPIResponse("99.0.0"))

    assert service.check_for_update() == "99.0.0"
    assert service._opener.requested == [PYPI_URL]


def test_update_check_follows_the_override(monkeypatch, fake_service):
    fake_service.routes["/pypi/servonaut/json"] = {"info": {"version": "99.0.0"}}
    monkeypatch.setenv(PYPI_URL_ENV, f"{fake_service.base}/pypi/servonaut/json")

    service = _svc(current="2.16.3")

    assert service.check_for_update() == "99.0.0"
    assert service.last_check_result is UpdateCheckResult.UPDATE_AVAILABLE
    assert [(r["method"], r["path"]) for r in fake_service.requests] == [
        ("GET", "/pypi/servonaut/json")
    ]


def test_update_check_refuses_a_redirect_to_plain_http(monkeypatch, fake_service):
    fake_service.redirects["/pypi/servonaut/json"] = f"{fake_service.base}/elsewhere"
    fake_service.routes["/elsewhere"] = {"info": {"version": "99.0.0"}}
    monkeypatch.setenv(PYPI_URL_ENV, f"{fake_service.base}/pypi/servonaut/json")

    service = _svc(current="2.16.3")

    assert service.check_for_update() is None
    assert service.last_check_result is UpdateCheckResult.OFFLINE
    assert [r["path"] for r in fake_service.requests] == ["/pypi/servonaut/json"]


def test_update_check_refuses_a_plain_http_remote_override(monkeypatch, caplog):
    monkeypatch.setenv(PYPI_URL_ENV, "http://mirror.example/pypi/servonaut/json")
    service = _svc(current="2.16.3")
    service._opener = _RecordingOpener(AssertionError("no request may be made"))

    assert service.check_for_update() is None
    assert service.last_check_result is UpdateCheckResult.OFFLINE
    assert service._opener.requested == []
    assert PYPI_URL_ENV in caplog.text
    assert PYPI_URL_ENV in service.update_status


@pytest.mark.parametrize(
    "error",
    [
        http.client.InvalidURL("nonnumeric port: 'secret-part'"),
        ValueError("unknown url type: 'secret-part'"),
        urllib.error.URLError("no route"),
        json.JSONDecodeError("bad", "doc", 0),
    ],
)
def test_update_check_failures_are_reported_without_the_url(monkeypatch, caplog, error):
    monkeypatch.setenv(PYPI_URL_ENV, "https://mirror.example/secret-part/json")
    service = _svc(current="2.16.3")
    service._opener = _RecordingOpener(error)

    with caplog.at_level(logging.DEBUG, logger=update_service.__name__):
        assert service.check_for_update() is None

    assert service.last_check_result is UpdateCheckResult.OFFLINE
    assert PYPI_URL_ENV in caplog.text
    assert "secret-part" not in caplog.text
    assert service.update_status == "Could not check for updates (offline)."


def test_cli_update_says_the_check_failed(monkeypatch, capsys):
    """`servonaut --update` must not claim "Already up to date" after a failure."""
    from servonaut import main as main_module

    service = _svc(current="2.16.3")
    service._opener = _RecordingOpener(urllib.error.URLError("offline"))
    monkeypatch.setattr(update_service, "UpdateService", lambda _runtime: service)

    main_module._run_update()

    out = capsys.readouterr().out
    assert "Could not check for updates" in out
    assert "Already up to date" not in out


# ---------------------------------------------------------------------------
# SERVONAUT_HETZNER_API_URL
# ---------------------------------------------------------------------------


def _hetzner(tmp_path) -> HetznerService:
    return HetznerService(
        HetznerConfig(
            enabled=True,
            api_token="token-for-tests",
            cache_path=str(tmp_path / "hcache.json"),
            audit_path=str(tmp_path / "haudit.jsonl"),
        )
    )


def _capture_hcloud_client(created: List[Dict[str, Any]]):
    class _Client:
        def __init__(self, **kwargs: Any) -> None:
            created.append(kwargs)

    return patch.dict("sys.modules", {"hcloud": SimpleNamespace(Client=_Client)})


def test_hetzner_client_keeps_the_sdk_default_endpoint(tmp_path):
    created: List[Dict[str, Any]] = []
    with _capture_hcloud_client(created):
        _hetzner(tmp_path)._get_client()
    assert len(created) == 1
    assert "api_endpoint" not in created[0]


def test_hetzner_client_uses_the_override(tmp_path, monkeypatch):
    monkeypatch.setenv(HETZNER_API_URL_ENV, "https://hetzner-proxy.example/v1")
    created: List[Dict[str, Any]] = []
    with _capture_hcloud_client(created):
        _hetzner(tmp_path)._get_client()
    assert created[0]["api_endpoint"] == "https://hetzner-proxy.example/v1"


def test_hetzner_refuses_a_plain_http_remote_override(tmp_path, monkeypatch):
    monkeypatch.setenv(HETZNER_API_URL_ENV, "http://hetzner-proxy.example/v1")
    created: List[Dict[str, Any]] = []
    with _capture_hcloud_client(created):
        with pytest.raises(HetznerNotConfiguredError, match=HETZNER_API_URL_ENV):
            _hetzner(tmp_path)._get_client()
    assert created == []


def test_hetzner_refuses_an_override_that_hides_a_remote_host(tmp_path, monkeypatch):
    """The backslash form would pass a naive loopback check and send the token."""
    monkeypatch.setenv(HETZNER_API_URL_ENV, "http://10.8.0.3:8080\\@127.0.0.1/v1")
    created: List[Dict[str, Any]] = []
    with _capture_hcloud_client(created):
        with pytest.raises(HetznerNotConfiguredError, match=HETZNER_API_URL_ENV):
            _hetzner(tmp_path)._get_client()
    assert created == []


def test_real_hcloud_sdk_talks_to_the_override(tmp_path, monkeypatch, fake_service):
    pytest.importorskip("hcloud")
    fake_service.routes["/v1/servers"] = {
        "servers": [],
        "meta": {
            "pagination": {
                "page": 1,
                "per_page": 50,
                "previous_page": None,
                "next_page": None,
                "last_page": 1,
                "total_entries": 0,
            }
        },
    }
    monkeypatch.setenv(HETZNER_API_URL_ENV, f"{fake_service.base}/v1")

    result = asyncio.run(_hetzner(tmp_path).test_connection())

    assert result["success"] is True, result
    assert result["server_count"] == 0
    request = fake_service.requests[0]
    assert request["path"].startswith("/v1/servers")
    assert request["headers"]["Authorization"] == "Bearer token-for-tests"


# ---------------------------------------------------------------------------
# SERVONAUT_IP_API_URL / SERVONAUT_ABUSEIPDB_URL
# ---------------------------------------------------------------------------


def _config_with_abuse_key():
    config = SimpleNamespace(abuseipdb_api_key="abuse-key-for-tests")
    return SimpleNamespace(get=lambda: config)


def test_ip_enrichment_uses_the_public_services_by_default(monkeypatch):
    calls: List[str] = []

    async def post_json(_self, url, body):
        calls.append(url)
        return []

    async def get_json(_self, url, params, headers):
        calls.append(url)
        return {"data": {}}

    monkeypatch.setattr(IPEnrichmentService, "_post_json", post_json)
    monkeypatch.setattr(IPEnrichmentService, "_get_json", get_json)

    asyncio.run(IPEnrichmentService(_config_with_abuse_key()).enrich(["1.1.1.1"]))

    assert calls == ["http://ip-api.com/batch", "https://api.abuseipdb.com/api/v2/check"]


def test_ip_enrichment_follows_the_overrides(monkeypatch, fake_service):
    fake_service.routes["/batch"] = [
        {"query": "1.1.1.1", "status": "success", "as": "AS64500 Example", "countryCode": "AU"}
    ]
    fake_service.routes["/api/v2/check"] = {
        "data": {"abuseConfidenceScore": 7, "totalReports": 2}
    }
    monkeypatch.setenv(IP_API_URL_ENV, fake_service.base)
    # A trailing slash on the base must not produce a double slash.
    monkeypatch.setenv(ABUSEIPDB_URL_ENV, f"{fake_service.base}/api/v2/")

    rows = asyncio.run(IPEnrichmentService(_config_with_abuse_key()).enrich(["1.1.1.1"]))

    assert rows[0]["asn"] == "AS64500 Example"
    assert rows[0]["abuse_score"] == 7
    paths = sorted(r["path"].split("?", 1)[0] for r in fake_service.requests)
    assert paths == ["/api/v2/check", "/batch"]
    check = next(r for r in fake_service.requests if r["path"].startswith("/api/v2/check"))
    assert check["headers"]["Key"] == "abuse-key-for-tests"


def test_urllib_fallback_does_not_follow_a_redirect_with_the_api_key(monkeypatch, fake_service):
    """Without httpx, the stdlib path must not forward ``Key`` to another URL."""
    fake_service.routes["/batch"] = []
    fake_service.redirects["/api/v2/check"] = f"{fake_service.base}/elsewhere"
    fake_service.routes["/elsewhere"] = {"data": {"abuseConfidenceScore": 99}}
    monkeypatch.setenv(IP_API_URL_ENV, fake_service.base)
    monkeypatch.setenv(ABUSEIPDB_URL_ENV, f"{fake_service.base}/api/v2")

    with patch.dict("sys.modules", {"httpx": None}):
        rows = asyncio.run(IPEnrichmentService(_config_with_abuse_key()).enrich(["1.1.1.1"]))

    assert rows[0]["abuse_score"] is None
    paths = [r["path"].split("?", 1)[0] for r in fake_service.requests]
    assert "/elsewhere" not in paths
    check = next(r for r in fake_service.requests if r["path"].startswith("/api/v2/check"))
    assert "ipAddress=1.1.1.1" in check["path"]


def test_ip_enrichment_refuses_a_plain_http_remote_override(monkeypatch):
    monkeypatch.setenv(IP_API_URL_ENV, "http://ip-lookup.example")

    async def no_request(*_args, **_kwargs):
        raise AssertionError("no request may be made with a refused override")

    monkeypatch.setattr(IPEnrichmentService, "_post_json", no_request)

    rows = asyncio.run(IPEnrichmentService(None).enrich(["1.1.1.1"]))

    assert IP_API_URL_ENV in rows[0]["error"]


def test_cloudwatch_ip_info_follows_the_overrides(monkeypatch, fake_service):
    pytest.importorskip("httpx")
    from servonaut.screens.cloudwatch_browser import CloudWatchBrowserScreen

    fake_service.routes["/json/1.1.1.1"] = {"status": "success", "country": "Australia"}
    fake_service.routes["/check"] = {"data": {"abuseConfidenceScore": 3}}
    monkeypatch.setenv(IP_API_URL_ENV, fake_service.base)
    monkeypatch.setenv(ABUSEIPDB_URL_ENV, fake_service.base)
    screen = SimpleNamespace(app=SimpleNamespace(config_manager=_config_with_abuse_key()))

    geo = asyncio.run(CloudWatchBrowserScreen._fetch_ip_geo(screen, "1.1.1.1"))
    abuse = asyncio.run(CloudWatchBrowserScreen._fetch_abuse_info(screen, "1.1.1.1"))

    assert geo["country"] == "Australia"
    assert abuse == {"abuseConfidenceScore": 3}
    assert sorted(r["path"].split("?", 1)[0] for r in fake_service.requests) == [
        "/check",
        "/json/1.1.1.1",
    ]


def test_ip_lookup_defaults_are_unchanged():
    assert ip_enrichment_service.ip_api_base_url() == "http://ip-api.com"
    assert ip_enrichment_service.abuseipdb_base_url() == "https://api.abuseipdb.com/api/v2"
