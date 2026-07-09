"""Tests for BwSshConfigService — locked wire contract with servonaut.dev."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import APIClient, APIError
from servonaut.services.bw_ssh_config_service import (
    BITWARDEN_PM_PROVIDER,
    BwSshConfigService,
    STATUS_AUTH_FAILED,
    STATUS_NOT_FOUND,
    STATUS_VERIFIED,
    VALID_VERIFY_STATUSES,
)


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def _api_error(status: int, code: str = "not_found") -> APIError:
    return APIError(code=code, message="boom", status=status)


@pytest.fixture
def mock_api():
    """APIClient mock with spec so positional ``json`` payloads fail loudly."""
    api = MagicMock(spec=APIClient)
    api.get = AsyncMock(return_value={})
    api.put = AsyncMock(return_value={})
    api.post = AsyncMock(return_value={})
    api.delete = AsyncMock(return_value={})
    return api


@pytest.fixture
def service(mock_api, tmp_path):
    # tmp cache path: the ref mirror must never touch the real ~/.servonaut in tests
    return BwSshConfigService(mock_api, refs_cache_path=tmp_path / "bw_ssh_refs.json")


class TestPersonalConfig:
    def test_get_personal_config_returns_payload(self, service, mock_api):
        mock_api.get.return_value = {
            "provider": "bitwarden_pm",
            "config": {"vault_url": "https://vault.bitwarden.com"},
            "updated_at": "2026-05-24T10:00:00Z",
        }
        result = _run(service.get_personal_config())
        assert result is not None
        assert result["provider"] == "bitwarden_pm"
        mock_api.get.assert_awaited_once_with("/api/v1/me/ssh-config")

    def test_get_personal_config_returns_none_on_404(self, service, mock_api):
        mock_api.get.side_effect = _api_error(404)
        assert _run(service.get_personal_config()) is None

    def test_get_personal_config_raises_on_other_errors(self, service, mock_api):
        mock_api.get.side_effect = _api_error(500, "internal_error")
        with pytest.raises(APIError):
            _run(service.get_personal_config())

    def test_put_personal_config_minimal_body(self, service, mock_api):
        mock_api.put.return_value = {"ok": True}
        _run(service.put_personal_config(vault_url="https://vault.example.com"))
        mock_api.put.assert_awaited_once_with(
            "/api/v1/me/ssh-config",
            json={
                "provider": BITWARDEN_PM_PROVIDER,
                "config": {"vault_url": "https://vault.example.com"},
            },
        )

    def test_put_personal_config_with_collection_id(self, service, mock_api):
        _run(
            service.put_personal_config(
                vault_url="https://vault.example.com",
                default_collection_id="col-uuid",
            )
        )
        _, kwargs = mock_api.put.call_args
        assert kwargs["json"]["config"]["default_collection_id"] == "col-uuid"


class TestListPersonalInstances:
    def test_unwraps_instances_envelope(self, service, mock_api):
        mock_api.get.return_value = {
            "instances": [
                {"provider": "aws", "instance_id": "i-1"},
                {"provider": "ovh", "instance_id": "srv-2"},
            ]
        }
        result = _run(service.list_personal_instances())
        assert len(result) == 2
        assert result[0]["instance_id"] == "i-1"
        mock_api.get.assert_awaited_once_with("/api/v1/me/instances")

    def test_tolerates_bare_array(self, service, mock_api):
        mock_api.get.return_value = [{"provider": "aws", "instance_id": "i-1"}]
        result = _run(service.list_personal_instances())
        assert len(result) == 1

    def test_returns_empty_on_unknown_shape(self, service, mock_api):
        mock_api.get.return_value = "weird"  # type: ignore[arg-type]
        assert _run(service.list_personal_instances()) == []

    def test_missing_instances_key_returns_empty(self, service, mock_api):
        mock_api.get.return_value = {"foo": "bar"}
        assert _run(service.list_personal_instances()) == []


class TestPutPersonalInstanceRef:
    def test_body_uses_ssh_credential_ref_not_ref(self, service, mock_api):
        """The body field is ssh_credential_ref — NEVER ``ref``.

        PR #77 on the server side fixed a discovered mismatch where
        C-solo-2 originally accepted ``ref``. We code against the canonical
        field name from day one so we never depend on the back-compat alias.
        """
        _run(
            service.put_personal_instance_ref(
                provider="aws",
                instance_id="i-0abc",
                ssh_credential_ref={"item_id": "uuid-1"},
            )
        )
        path, kwargs = mock_api.put.call_args
        assert path[0] == "/api/v1/me/instances/aws/i-0abc/ssh-ref"
        body = kwargs["json"]
        assert "ref" not in body
        assert body["ssh_credential_ref"] == {"item_id": "uuid-1"}
        assert body["ssh_credential_provider"] == BITWARDEN_PM_PROVIDER

    def test_full_ref_shape_round_trips(self, service, mock_api):
        ref = {
            "item_id": "uuid-1",
            "collection_id": "col-1",
            "vault_url": "https://vault.example.com",
        }
        _run(
            service.put_personal_instance_ref(
                provider="hetzner",
                instance_id="hetzner-001",
                ssh_credential_ref=ref,
            )
        )
        _, kwargs = mock_api.put.call_args
        assert kwargs["json"]["ssh_credential_ref"] == ref


class TestDeletePersonalInstanceRef:
    def test_returns_true_on_success(self, service, mock_api):
        mock_api.delete.return_value = {"deleted": True}
        assert _run(service.delete_personal_instance_ref("aws", "i-1")) is True
        mock_api.delete.assert_awaited_once_with(
            "/api/v1/me/instances/aws/i-1/ssh-ref"
        )

    def test_returns_false_on_404(self, service, mock_api):
        mock_api.delete.side_effect = _api_error(404)
        assert _run(service.delete_personal_instance_ref("aws", "i-1")) is False

    def test_raises_on_other_errors(self, service, mock_api):
        mock_api.delete.side_effect = _api_error(500, "internal_error")
        with pytest.raises(APIError):
            _run(service.delete_personal_instance_ref("aws", "i-1"))


class TestVerifyStatusGet:
    def test_returns_payload(self, service, mock_api):
        payload = {
            "provider": "aws",
            "instance_id": "i-1",
            "ssh_verify_status": "verified",
            "ssh_verified_at": "2026-05-24T10:00:00Z",
            "checked_by_client": "servonaut-cli/2.12.0",
            "updated_at": "2026-05-24T10:00:00Z",
        }
        mock_api.get.return_value = payload
        result = _run(service.get_personal_instance_verify_status("aws", "i-1"))
        assert result == payload
        mock_api.get.assert_awaited_once_with(
            "/api/v1/me/instances/aws/i-1/ssh-verify-status"
        )

    def test_returns_none_on_404(self, service, mock_api):
        mock_api.get.side_effect = _api_error(404)
        assert _run(service.get_personal_instance_verify_status("aws", "i-1")) is None


class TestVerifyReport:
    @pytest.mark.parametrize(
        "status", [STATUS_VERIFIED, STATUS_NOT_FOUND, STATUS_AUTH_FAILED]
    )
    def test_accepts_all_valid_statuses(self, service, mock_api, status: str):
        _run(
            service.report_personal_instance_verify(
                provider="aws",
                instance_id="i-1",
                status=status,
                checked_by_client="servonaut-cli/2.12.0",
            )
        )
        path, kwargs = mock_api.post.call_args
        assert path[0] == "/api/v1/me/instances/aws/i-1/ssh-verify-report"
        assert kwargs["json"]["status"] == status
        assert kwargs["json"]["checked_by_client"] == "servonaut-cli/2.12.0"

    def test_omits_checked_by_client_when_none(self, service, mock_api):
        _run(
            service.report_personal_instance_verify(
                provider="aws", instance_id="i-1", status=STATUS_VERIFIED
            )
        )
        _, kwargs = mock_api.post.call_args
        assert "checked_by_client" not in kwargs["json"]

    def test_rejects_invalid_status_locally(self, service, mock_api):
        with pytest.raises(ValueError, match="status must be one of"):
            _run(
                service.report_personal_instance_verify(
                    provider="aws", instance_id="i-1", status="bogus"
                )
            )
        # Never round-tripped to the server
        mock_api.post.assert_not_called()

    def test_valid_status_set_is_locked(self):
        # Locked contract — any change requires coordination with servonaut.dev.
        assert VALID_VERIFY_STATUSES == frozenset(
            {"verified", "not_found", "auth_failed"}
        )
