"""Tests for APIClient error handling, retry logic, and get_bytes."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.services.api_client import (
    APIClient,
    APIError,
    BatchTooLargeError,
    FeatureDisabledError,
    FeatureNotAvailableError,
    ForbiddenEntitlementError,
    GrantExistsError,
    InsufficientWrapsError,
    NotFoundError,
    QuotaExceededError,
    RateLimitedError,
    ValidationFailedError,
    WeakPassphraseError,
    DEFAULT_TIMEOUT_SECONDS,
    EXPORT_TIMEOUT_SECONDS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(
    status_code: int,
    body: Any = None,
    content_type: str = "application/json",
    raw_text: str = "",
) -> MagicMock:
    """Build a minimal mock that looks like an httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"content-type": content_type}
    if body is not None:
        resp.json.return_value = body
        resp.text = json.dumps(body)
        resp.content = json.dumps(body).encode()
    else:
        resp.json.side_effect = ValueError("no body")
        resp.text = raw_text
        resp.content = raw_text.encode()
    return resp


def _make_auth(*, refresh_succeeds: bool = True) -> MagicMock:
    auth = MagicMock()
    auth.access_token = "tok"
    auth.refresh_token = AsyncMock(return_value=refresh_succeeds)
    return auth


def _make_client(auth: Optional[MagicMock] = None) -> APIClient:
    return APIClient(auth or _make_auth())


# ---------------------------------------------------------------------------
# _parse_error tests — each exercises a different envelope code / status.
# ---------------------------------------------------------------------------

class TestParseError:
    def test_rate_limited(self):
        client = _make_client()
        resp = _make_response(429, {"error": {"code": "rate_limited", "message": "Too many requests"}})
        err = client._parse_error(resp)
        assert isinstance(err, RateLimitedError)
        assert err.code == "rate_limited"
        assert err.status == 429

    def test_feature_disabled(self):
        client = _make_client()
        resp = _make_response(503, {"error": {"code": "feature_disabled", "message": "Down"}})
        err = client._parse_error(resp)
        assert isinstance(err, FeatureDisabledError)
        assert err.status == 503

    def test_forbidden_entitlement(self):
        client = _make_client()
        resp = _make_response(403, {"error": {"code": "forbidden_entitlement", "message": "Upgrade"}})
        err = client._parse_error(resp)
        assert isinstance(err, ForbiddenEntitlementError)
        assert err.status == 403

    def test_feature_not_available(self):
        client = _make_client()
        resp = _make_response(403, {"error": {"code": "feature_not_available", "message": "Beta"}})
        err = client._parse_error(resp)
        assert isinstance(err, FeatureNotAvailableError)
        assert err.status == 403

    def test_validation_failed_carries_details(self):
        details = {"errors": [{"field": "iv", "message": "must be 12 bytes"}]}
        body = {"error": {"code": "validation_failed", "message": "Invalid", "details": details}}
        client = _make_client()
        resp = _make_response(422, body)
        err = client._parse_error(resp)
        assert isinstance(err, ValidationFailedError)
        assert err.details == details

    def test_insufficient_wraps_carries_missing(self):
        missing = [{"envelope_id": "env-1", "recipient_user_id": 42}]
        body = {"error": {"code": "insufficient_wraps", "message": "Missing", "details": {"missing": missing}}}
        client = _make_client()
        resp = _make_response(422, body)
        err = client._parse_error(resp)
        assert isinstance(err, InsufficientWrapsError)
        assert err.missing == missing

    def test_413_html_body_synthesises_batch_too_large(self):
        client = _make_client()
        resp = _make_response(413, raw_text="<html>413 Request Entity Too Large</html>", content_type="text/html")
        err = client._parse_error(resp)
        assert isinstance(err, BatchTooLargeError)
        assert err.code == "batch_too_large"
        assert err.status == 413

    def test_malformed_json_returns_generic_api_error(self):
        client = _make_client()
        resp = _make_response(500, raw_text="Internal Server Error", content_type="text/plain")
        err = client._parse_error(resp)
        assert isinstance(err, APIError)
        assert err.code == "unknown"
        assert err.status == 500

    def test_response_headers_lowercased(self):
        client = _make_client()
        resp = MagicMock()
        resp.status_code = 429
        resp.headers = {"content-type": "application/json", "retry-after": "30"}
        resp.json.return_value = {"error": {"code": "rate_limited", "message": "slow down"}}
        resp.text = '{"error": {"code": "rate_limited", "message": "slow down"}}'
        err = client._parse_error(resp)
        assert "retry-after" in err.response_headers


# ---------------------------------------------------------------------------
# is_retryable property
# ---------------------------------------------------------------------------

class TestIsRetryable:
    @pytest.mark.parametrize("status", [429, 502, 503, 504])
    def test_retryable_statuses(self, status: int):
        err = APIError(code="x", message="x", status=status)
        assert err.is_retryable is True

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 413, 422])
    def test_non_retryable_statuses(self, status: int):
        err = APIError(code="x", message="x", status=status)
        assert err.is_retryable is False


# ---------------------------------------------------------------------------
# 401 retry behaviour
# ---------------------------------------------------------------------------

class TestUnauthorizedRetry:
    @pytest.mark.asyncio
    async def test_401_triggers_exactly_one_refresh_then_reraises(self):
        auth = _make_auth(refresh_succeeds=False)
        client = _make_client(auth)

        first_401 = _make_response(401, {"error": {"code": "unauthorized", "message": "Bad token"}})
        second_401 = _make_response(401, {"error": {"code": "unauthorized", "message": "Bad token"}})

        mock_http_response = AsyncMock()
        mock_http_response.__aenter__ = AsyncMock(return_value=mock_http_response)
        mock_http_response.__aexit__ = AsyncMock(return_value=False)
        mock_http_response.request = AsyncMock(side_effect=[first_401, second_401])

        with patch("httpx.AsyncClient") as mock_cls:
            instance = MagicMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            instance.request = AsyncMock(side_effect=[first_401, second_401])
            mock_cls.return_value = instance

            with pytest.raises(APIError) as exc_info:
                await client.get("/api/v1/test")

        # Refresh was attempted exactly once
        auth.refresh_token.assert_awaited_once()
        assert exc_info.value.status == 401

    @pytest.mark.asyncio
    async def test_401_with_successful_refresh_retries_request(self):
        auth = _make_auth(refresh_succeeds=True)
        client = _make_client(auth)

        first_401 = _make_response(401, {"error": {"code": "unauthorized", "message": "Expired"}})
        success_200 = _make_response(200, {"data": "ok"})

        with patch("httpx.AsyncClient") as mock_cls:
            instance = MagicMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            instance.request = AsyncMock(side_effect=[first_401, success_200])
            mock_cls.return_value = instance

            result = await client.get("/api/v1/test")

        assert result == {"data": "ok"}
        auth.refresh_token.assert_awaited_once()


# ---------------------------------------------------------------------------
# get_bytes tests
# ---------------------------------------------------------------------------

class TestGetBytes:
    @pytest.mark.asyncio
    async def test_returns_raw_bytes_and_headers_on_gzip(self):
        raw = b"\x1f\x8b\x08" + b"\x00" * 10  # gzip magic bytes stub
        auth = _make_auth()
        client = _make_client(auth)

        gzip_response = MagicMock()
        gzip_response.status_code = 200
        gzip_response.headers = {"content-type": "application/gzip", "x-request-id": "abc123"}
        gzip_response.content = raw

        with patch("httpx.AsyncClient") as mock_cls:
            instance = MagicMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            instance.get = AsyncMock(return_value=gzip_response)
            mock_cls.return_value = instance

            content, headers = await client.get_bytes("/api/v1/memory/export")

        assert content == raw
        assert headers["content-type"] == "application/gzip"
        assert headers["x-request-id"] == "abc123"

    @pytest.mark.asyncio
    async def test_raises_api_error_on_200_json_body(self):
        """A 200 with Content-Type application/json is treated as an error envelope."""
        auth = _make_auth()
        client = _make_client(auth)

        json_response = MagicMock()
        json_response.status_code = 200
        json_response.headers = {"content-type": "application/json; charset=utf-8"}
        error_body = {"error": {"code": "forbidden_entitlement", "message": "Upgrade"}}
        json_response.json.return_value = error_body
        json_response.text = json.dumps(error_body)
        json_response.content = json.dumps(error_body).encode()

        with patch("httpx.AsyncClient") as mock_cls:
            instance = MagicMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            instance.get = AsyncMock(return_value=json_response)
            mock_cls.return_value = instance

            with pytest.raises(ForbiddenEntitlementError):
                await client.get_bytes("/api/v1/memory/export")

    @pytest.mark.asyncio
    async def test_get_bytes_honours_per_call_timeout(self):
        auth = _make_auth()
        client = _make_client(auth)

        gzip_response = MagicMock()
        gzip_response.status_code = 200
        gzip_response.headers = {"content-type": "application/gzip"}
        gzip_response.content = b"data"

        with patch("httpx.AsyncClient") as mock_cls:
            instance = MagicMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            instance.get = AsyncMock(return_value=gzip_response)
            mock_cls.return_value = instance

            await client.get_bytes("/api/v1/memory/export", timeout=999)

        # The AsyncClient must have been constructed with the per-call timeout.
        mock_cls.assert_called_once_with(timeout=999)
