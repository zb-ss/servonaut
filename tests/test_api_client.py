"""Tests for APIClient."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.services.api_client import APIClient, APIError, ForbiddenEntitlementError


@pytest.fixture
def mock_auth():
    auth = MagicMock()
    auth.access_token = "test-token"
    auth.refresh_token = AsyncMock(return_value=True)
    return auth


@pytest.fixture
def api_client(mock_auth):
    return APIClient(mock_auth)


class TestAPIClient:
    def test_get_headers(self, api_client):
        headers = api_client._get_headers()
        assert headers["Authorization"] == "Bearer test-token"
        assert "User-Agent" in headers

    def test_get_headers_no_token(self, mock_auth):
        mock_auth.access_token = None
        client = APIClient(mock_auth)
        headers = client._get_headers()
        assert "Authorization" not in headers


class TestAPIClientErrors:
    def test_parse_error_forbidden(self, api_client):
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = '{"error": {"code": "forbidden_entitlement", "message": "Access denied"}}'
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {"error": {"code": "forbidden_entitlement", "message": "Access denied"}}

        err = api_client._parse_error(mock_response)
        assert isinstance(err, ForbiddenEntitlementError)
        assert err.status == 403
        assert "Access denied" in err.message


class TestGetWithHeaders:
    def test_the_body_comes_with_the_headers_in_lower_case(self, api_client):
        import asyncio

        import httpx

        def handler(request):
            assert request.url.path == "/api/v1/teams/ops-team/policy"
            assert request.headers["Authorization"] == "Bearer test-token"
            return httpx.Response(
                200, json={"data": {"allowed_tools": []}},
                headers={"Date": "Sun, 18 Oct 2026 21:00:00 GMT", "X-Extra": "1"},
            )

        api_client.transport = httpx.MockTransport(handler)
        body, headers = asyncio.run(api_client.get_with_headers("/api/v1/teams/ops-team/policy"))

        assert body == {"data": {"allowed_tools": []}}
        assert headers["date"] == "Sun, 18 Oct 2026 21:00:00 GMT"
        assert headers["x-extra"] == "1"

    def test_an_error_response_raises_like_get(self, api_client):
        import asyncio

        import httpx

        api_client.transport = httpx.MockTransport(lambda request: httpx.Response(
            403, json={"error": {"code": "forbidden", "message": "Not a member"}},
        ))
        with pytest.raises(APIError) as caught:
            asyncio.run(api_client.get_with_headers("/api/v1/teams/ops-team/policy"))
        assert caught.value.status == 403
