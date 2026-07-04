"""Tests for the proactive-findings thin client.

The service is a renderer-support layer over the gated
``/api/v1/findings`` endpoints — these tests pin:

- filter params reach the wire (and invalid filters fail locally
  before any round-trip);
- scan POSTs the right body for instance vs fleet scope;
- triage actions hit their endpoints and hostile finding ids are
  rejected before path interpolation;
- the scan-progress stream opens as a GET with the instance param
  (through the extended SSE layer).

All fixtures are generic (``web-1``, RFC1918 addresses) — no real
hosts, IPs, or customer identifiers may appear here.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from servonaut.services import ai_sse
from servonaut.services.api_client import APIClient
from servonaut.services.findings_service import (
    FINDING_SEVERITIES,
    FINDING_STATUSES,
    FindingsService,
)


def run(coro):
    return asyncio.run(coro)


def _mock_api() -> MagicMock:
    # spec=APIClient catches positional-json misuse at test time.
    api = MagicMock(spec=APIClient)
    api.get = AsyncMock(return_value={"findings": [], "total": 0})
    api.post = AsyncMock(return_value={"success": True})
    return api


class TestListFindings:
    def test_default_params(self):
        api = _mock_api()
        svc = FindingsService(api)
        run(svc.list_findings())
        api.get.assert_awaited_once_with(
            "/api/v1/findings", params={"limit": 50, "offset": 0},
        )

    def test_all_filters_forwarded(self):
        api = _mock_api()
        svc = FindingsService(api)
        run(svc.list_findings(
            instance="i-0000test01", status="detected",
            severity="high", limit=10, offset=20,
        ))
        api.get.assert_awaited_once_with(
            "/api/v1/findings",
            params={
                "limit": 10, "offset": 20, "instance": "i-0000test01",
                "status": "detected", "severity": "high",
            },
        )

    def test_invalid_status_rejected_locally(self):
        api = _mock_api()
        svc = FindingsService(api)
        with pytest.raises(ValueError, match="Invalid status"):
            run(svc.list_findings(status="open"))
        api.get.assert_not_awaited()

    def test_invalid_severity_rejected_locally(self):
        api = _mock_api()
        svc = FindingsService(api)
        with pytest.raises(ValueError, match="Invalid severity"):
            run(svc.list_findings(severity="urgent"))
        api.get.assert_not_awaited()

    def test_all_contract_values_accepted(self):
        api = _mock_api()
        svc = FindingsService(api)
        for status in FINDING_STATUSES:
            run(svc.list_findings(status=status))
        for severity in FINDING_SEVERITIES:
            run(svc.list_findings(severity=severity))
        assert api.get.await_count == len(FINDING_STATUSES) + len(FINDING_SEVERITIES)


class TestScan:
    def test_instance_scan_body(self):
        api = _mock_api()
        svc = FindingsService(api)
        run(svc.scan(instance_id="i-0000test01"))
        args, kwargs = api.post.await_args
        assert args == ("/api/v1/findings/scan",)
        assert kwargs["json"] == {"instance_id": "i-0000test01"}

    def test_fleet_scan_omits_instance(self):
        api = _mock_api()
        svc = FindingsService(api)
        run(svc.scan())
        _, kwargs = api.post.await_args
        assert kwargs["json"] == {}

    def test_scan_uses_long_timeout(self):
        api = _mock_api()
        svc = FindingsService(api)
        run(svc.scan())
        _, kwargs = api.post.await_args
        assert kwargs["timeout"] > 30


class TestTriage:
    @pytest.mark.parametrize("method,endpoint", [
        ("acknowledge", "ack"),
        ("resolve", "resolve"),
        ("suppress", "suppress"),
    ])
    def test_triage_paths(self, method, endpoint):
        api = _mock_api()
        svc = FindingsService(api)
        run(getattr(svc, method)("fnd_01abc"))
        api.post.assert_awaited_once_with(
            f"/api/v1/findings/fnd_01abc/{endpoint}", json=None,
        )

    @pytest.mark.parametrize("bad_id", [
        "../other", "a/b", "", "x" * 200, "id with spaces", "-leading",
    ])
    def test_hostile_finding_id_rejected(self, bad_id):
        api = _mock_api()
        svc = FindingsService(api)
        with pytest.raises(ValueError, match="Invalid finding id"):
            run(svc.acknowledge(bad_id))
        api.post.assert_not_awaited()


class TestStreamScan:
    """The scan-progress stream is a GET with query params — exercised
    end-to-end through the SSE layer via a mock transport."""

    def _api_with_auth(self) -> APIClient:
        auth = MagicMock()
        auth.access_token = "test"
        auth.refresh_token = AsyncMock(return_value=True)
        return APIClient(auth)

    def test_stream_is_get_with_instance_param(self, monkeypatch):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["method"] = request.method
            seen["params"] = dict(request.url.params)
            seen["path"] = request.url.path
            body = (
                'event: scan.started\ndata: {"scan_id": "scn_1", "scope": "instance"}\n\n'
                'event: scan.completed\ndata: {"scan_id": "scn_1", "findings_count": 0}\n\n'
            )
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=body.encode("utf-8"),
            )

        monkeypatch.setattr(ai_sse, "_TEST_TRANSPORT", httpx.MockTransport(handler))
        api = self._api_with_auth()
        svc = FindingsService(api)

        async def _drain():
            out = []
            async for event in svc.stream_scan(instance="i-0000test01"):
                out.append(event)
            return out

        events = run(_drain())
        assert seen["method"] == "GET"
        assert seen["path"] == "/api/v1/findings/scan/stream"
        assert seen["params"] == {"instance": "i-0000test01"}
        assert [e["event"] for e in events] == ["scan.started", "scan.completed"]

    def test_error_event_raises_stream_error(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            body = (
                'event: error\n'
                'data: {"code": "cli_not_connected", "message": '
                '"Connect your CLI (servonaut connect) to enable monitoring."}\n\n'
            )
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=body.encode("utf-8"),
            )

        monkeypatch.setattr(ai_sse, "_TEST_TRANSPORT", httpx.MockTransport(handler))
        api = self._api_with_auth()
        svc = FindingsService(api)

        async def _drain():
            async for _ in svc.stream_scan():
                pass

        with pytest.raises(ai_sse.SSEStreamError) as exc_info:
            run(_drain())
        assert exc_info.value.code == "cli_not_connected"


class TestRemediation:
    """Phase 3: two-step server-signed remediation calls."""

    def test_preview_get_shape(self):
        api = _mock_api()
        svc = FindingsService(api)
        run(svc.remediate_preview("fnd_01abc", "renew_certificate"))
        api.get.assert_awaited_once_with(
            "/api/v1/findings/fnd_01abc/remediate/preview",
            params={"action": "renew_certificate"},
        )

    def test_preview_dry_run_param(self):
        api = _mock_api()
        svc = FindingsService(api)
        run(svc.remediate_preview(
            "fnd_01abc", "renew_certificate", dry_run=True,
        ))
        params = api.get.await_args.kwargs["params"]
        assert params["dry_run"] == 1

    def test_execute_post_shape(self):
        api = _mock_api()
        svc = FindingsService(api)
        run(svc.remediate("fnd_01abc", "renew_certificate", "tok-signed"))
        args, kwargs = api.post.await_args
        assert args[0] == "/api/v1/findings/fnd_01abc/remediate"
        assert kwargs["json"] == {
            "action": "renew_certificate",
            "dry_run": False,
            "confirm_token": "tok-signed",
        }
        # Blocks through relay dispatch + re-probe — long timeout required.
        assert kwargs["timeout"] >= 60

    def test_execute_dry_run_bound_in_body(self):
        # dry_run is inside the token's command hash server-side — the
        # POST body must carry the same variant that was previewed.
        api = _mock_api()
        svc = FindingsService(api)
        run(svc.remediate(
            "fnd_01abc", "renew_certificate", "tok-signed", dry_run=True,
        ))
        assert api.post.await_args.kwargs["json"]["dry_run"] is True

    @pytest.mark.parametrize("bad_action", [
        "renew; reboot", "UPPER", "", "a" * 100, "../etc",
    ])
    def test_hostile_action_rejected(self, bad_action):
        api = _mock_api()
        svc = FindingsService(api)
        with pytest.raises(ValueError, match="Invalid remediation action"):
            run(svc.remediate_preview("fnd_01abc", bad_action))
        api.get.assert_not_awaited()

    def test_missing_confirm_token_rejected(self):
        api = _mock_api()
        svc = FindingsService(api)
        with pytest.raises(ValueError, match="confirm_token"):
            run(svc.remediate("fnd_01abc", "renew_certificate", ""))
        api.post.assert_not_awaited()

    def test_hostile_finding_id_rejected(self):
        api = _mock_api()
        svc = FindingsService(api)
        with pytest.raises(ValueError, match="Invalid finding id"):
            run(svc.remediate_preview("../oops", "renew_certificate"))
        api.get.assert_not_awaited()
