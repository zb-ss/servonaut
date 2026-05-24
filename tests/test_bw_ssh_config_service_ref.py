"""Tests for BwSshConfigService.get_personal_instance_ref (new method).

Separate file to keep the locked-contract tests in test_bw_ssh_config_service.py
untouched while adding the new-method coverage cleanly.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import APIClient, APIError
from servonaut.services.bw_ssh_config_service import BwSshConfigService


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def _api_error(status: int, code: str = "not_found") -> APIError:
    return APIError(code=code, message="boom", status=status)


@pytest.fixture
def mock_api():
    api = MagicMock(spec=APIClient)
    api.get = AsyncMock(return_value={})
    api.put = AsyncMock(return_value={})
    api.post = AsyncMock(return_value={})
    api.delete = AsyncMock(return_value={})
    return api


@pytest.fixture
def service(mock_api):
    return BwSshConfigService(mock_api)


class TestGetPersonalInstanceRef:
    def test_returns_payload_on_200(self, service, mock_api):
        """200 response is returned as-is."""
        payload = {
            "ssh_credential_provider": "bitwarden_pm",
            "ssh_credential_ref": {
                "item_id": "uuid-abc",
                "vault_url": "https://vault.bitwarden.com",
                "collection_id": "col-xyz",
            },
        }
        mock_api.get.return_value = payload
        result = _run(service.get_personal_instance_ref("aws", "i-0abc"))
        assert result is not None
        assert result["ssh_credential_ref"]["item_id"] == "uuid-abc"
        mock_api.get.assert_awaited_once_with(
            "/api/v1/me/instances/aws/i-0abc/ssh-ref"
        )

    def test_returns_none_on_404(self, service, mock_api):
        """404 → None (no ref stored, not an error)."""
        mock_api.get.side_effect = _api_error(404)
        result = _run(service.get_personal_instance_ref("aws", "i-0abc"))
        assert result is None

    def test_raises_on_non_404_errors(self, service, mock_api):
        """Non-404 API errors (e.g. 403, 500) propagate to the caller."""
        mock_api.get.side_effect = _api_error(403, "forbidden")
        with pytest.raises(APIError) as exc_info:
            _run(service.get_personal_instance_ref("aws", "i-0abc"))
        assert exc_info.value.status == 403

    def test_builds_correct_path_for_ovh(self, service, mock_api):
        mock_api.get.return_value = {
            "ssh_credential_provider": "bitwarden_pm",
            "ssh_credential_ref": {"item_id": "uuid-1"},
        }
        _run(service.get_personal_instance_ref("ovh", "server-001"))
        mock_api.get.assert_awaited_once_with(
            "/api/v1/me/instances/ovh/server-001/ssh-ref"
        )

    def test_payload_without_collection_id_is_valid(self, service, mock_api):
        """collection_id is optional — payload without it must not crash."""
        mock_api.get.return_value = {
            "ssh_credential_provider": "bitwarden_pm",
            "ssh_credential_ref": {"item_id": "uuid-only"},
        }
        result = _run(service.get_personal_instance_ref("hetzner", "htz-999"))
        assert result["ssh_credential_ref"]["item_id"] == "uuid-only"
        assert "collection_id" not in result["ssh_credential_ref"]
