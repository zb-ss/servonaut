"""Tests for APIClient."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.services.api_client import APIClient


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
    def test_raise_for_status(self, api_client):
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        mock_response.json.return_value = {"message": "Access denied"}

        with pytest.raises(RuntimeError, match="API error.*403.*Access denied"):
            api_client._raise_for_status(mock_response)
