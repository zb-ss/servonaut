"""Tests for OVHStorageService."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import OVHConfig
from servonaut.services.ovh_service import OVHService
from servonaut.services.ovh_storage_service import OVHStorageService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_ovh_client():
    return MagicMock()


@pytest.fixture
def ovh_service(mock_ovh_client):
    """OVHService with a pre-injected mock client."""
    cfg = OVHConfig(
        enabled=True,
        endpoint="ovh-eu",
        application_key="APP_KEY",
        application_secret="APP_SECRET",
        consumer_key="CONSUMER_KEY",
    )
    svc = OVHService(cfg)
    svc._client = mock_ovh_client
    return svc


@pytest.fixture
def storage_service(ovh_service):
    return OVHStorageService(ovh_service)


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:

    def test_stores_ovh_service_reference(self, ovh_service):
        svc = OVHStorageService(ovh_service)
        assert svc._ovh_service is ovh_service


# ---------------------------------------------------------------------------
# list_volumes
# ---------------------------------------------------------------------------

class TestListVolumes:

    def test_returns_volume_list(self, storage_service, mock_ovh_client):
        mock_ovh_client.get.return_value = [
            {"id": "vol-1", "name": "data-vol", "size": 50, "region": "GRA11", "status": "available"},
            {"id": "vol-2", "name": "backup-vol", "size": 100, "region": "BHS5", "status": "in-use"},
        ]

        result = asyncio.run(storage_service.list_volumes("abc123"))

        assert len(result) == 2
        assert result[0]["id"] == "vol-1"
        assert result[1]["name"] == "backup-vol"
        mock_ovh_client.get.assert_called_once_with("/cloud/project/abc123/volume")

    def test_returns_empty_list_on_api_error(self, storage_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("403 Forbidden")

        result = asyncio.run(storage_service.list_volumes("abc123"))

        assert result == []

    def test_returns_empty_list_when_api_returns_none(self, storage_service, mock_ovh_client):
        mock_ovh_client.get.return_value = None

        result = asyncio.run(storage_service.list_volumes("abc123"))

        assert result == []

    def test_returns_empty_list_when_api_returns_empty(self, storage_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(storage_service.list_volumes("abc123"))

        assert result == []

    def test_raises_value_error_on_invalid_project_id(self, storage_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(storage_service.list_volumes("project id with spaces"))

    def test_raises_value_error_on_empty_project_id(self, storage_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(storage_service.list_volumes(""))


# ---------------------------------------------------------------------------
# create_volume
# ---------------------------------------------------------------------------

class TestCreateVolume:

    def test_calls_post_with_correct_params(self, storage_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {
            "id": "new-vol-id",
            "name": "my-volume",
            "size": 50,
            "region": "GRA11",
            "status": "creating",
        }

        result = asyncio.run(
            storage_service.create_volume("abc123", "my-volume", 50, "GRA11", "classic")
        )

        assert result["id"] == "new-vol-id"
        mock_ovh_client.post.assert_called_once_with(
            "/cloud/project/abc123/volume",
            name="my-volume",
            size=50,
            region="GRA11",
            type="classic",
        )

    def test_uses_classic_as_default_type(self, storage_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {"id": "vol-x"}

        asyncio.run(storage_service.create_volume("abc123", "my-vol", 20, "GRA7"))

        _call_kwargs = mock_ovh_client.post.call_args[1]
        assert _call_kwargs["type"] == "classic"

    def test_raises_value_error_on_invalid_project_id(self, storage_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(storage_service.create_volume("bad id!", "vol", 10, "GRA11"))

    def test_raises_value_error_on_invalid_name(self, storage_service):
        with pytest.raises(ValueError, match="Invalid name"):
            asyncio.run(storage_service.create_volume("abc123", "", 10, "GRA11"))

    def test_raises_value_error_on_zero_size(self, storage_service):
        with pytest.raises(ValueError, match="Invalid size_gb"):
            asyncio.run(storage_service.create_volume("abc123", "vol", 0, "GRA11"))

    def test_raises_value_error_on_negative_size(self, storage_service):
        with pytest.raises(ValueError, match="Invalid size_gb"):
            asyncio.run(storage_service.create_volume("abc123", "vol", -5, "GRA11"))

    def test_raises_value_error_on_invalid_region(self, storage_service):
        with pytest.raises(ValueError, match="Invalid region"):
            asyncio.run(storage_service.create_volume("abc123", "vol", 10, ""))

    def test_propagates_api_exception(self, storage_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("500 Server Error")

        with pytest.raises(Exception, match="500 Server Error"):
            asyncio.run(storage_service.create_volume("abc123", "vol", 10, "GRA11"))


# ---------------------------------------------------------------------------
# delete_volume
# ---------------------------------------------------------------------------

class TestDeleteVolume:

    def test_returns_true_on_success(self, storage_service, mock_ovh_client):
        mock_ovh_client.delete.return_value = None

        result = asyncio.run(storage_service.delete_volume("abc123", "vol-uuid-1"))

        assert result is True

    def test_calls_correct_delete_endpoint(self, storage_service, mock_ovh_client):
        mock_ovh_client.delete.return_value = None

        asyncio.run(storage_service.delete_volume("abc123", "vol-uuid-1"))

        mock_ovh_client.delete.assert_called_once_with(
            "/cloud/project/abc123/volume/vol-uuid-1"
        )

    def test_propagates_api_exception(self, storage_service, mock_ovh_client):
        mock_ovh_client.delete.side_effect = Exception("404 Not Found")

        with pytest.raises(Exception, match="404 Not Found"):
            asyncio.run(storage_service.delete_volume("abc123", "vol-uuid-1"))

    def test_raises_value_error_on_invalid_project_id(self, storage_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(storage_service.delete_volume("bad id!", "vol-uuid-1"))

    def test_raises_value_error_on_invalid_volume_id(self, storage_service):
        with pytest.raises(ValueError, match="Invalid volume_id"):
            asyncio.run(storage_service.delete_volume("abc123", ""))

    def test_raises_value_error_on_volume_id_with_spaces(self, storage_service):
        with pytest.raises(ValueError, match="Invalid volume_id"):
            asyncio.run(storage_service.delete_volume("abc123", "vol id with spaces"))


# ---------------------------------------------------------------------------
# attach_volume
# ---------------------------------------------------------------------------

class TestAttachVolume:

    def test_returns_attachment_dict(self, storage_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {
            "id": "vol-uuid-1",
            "status": "in-use",
            "attachments": [{"serverId": "inst-uuid-1"}],
        }

        result = asyncio.run(
            storage_service.attach_volume("abc123", "vol-uuid-1", "inst-uuid-1")
        )

        assert result["status"] == "in-use"

    def test_calls_correct_attach_endpoint(self, storage_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {}

        asyncio.run(storage_service.attach_volume("abc123", "vol-uuid-1", "inst-uuid-1"))

        mock_ovh_client.post.assert_called_once_with(
            "/cloud/project/abc123/volume/vol-uuid-1/attach",
            instanceId="inst-uuid-1",
        )

    def test_propagates_api_exception(self, storage_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("409 Conflict")

        with pytest.raises(Exception, match="409 Conflict"):
            asyncio.run(storage_service.attach_volume("abc123", "vol-uuid-1", "inst-uuid-1"))

    def test_raises_value_error_on_invalid_project_id(self, storage_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(storage_service.attach_volume("bad id", "vol-1", "inst-1"))

    def test_raises_value_error_on_invalid_volume_id(self, storage_service):
        with pytest.raises(ValueError, match="Invalid volume_id"):
            asyncio.run(storage_service.attach_volume("abc123", "", "inst-1"))

    def test_raises_value_error_on_invalid_instance_id(self, storage_service):
        with pytest.raises(ValueError, match="Invalid instance_id"):
            asyncio.run(storage_service.attach_volume("abc123", "vol-1", ""))


# ---------------------------------------------------------------------------
# detach_volume
# ---------------------------------------------------------------------------

class TestDetachVolume:

    def test_returns_detachment_dict(self, storage_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {
            "id": "vol-uuid-1",
            "status": "available",
            "attachments": [],
        }

        result = asyncio.run(
            storage_service.detach_volume("abc123", "vol-uuid-1", "inst-uuid-1")
        )

        assert result["status"] == "available"

    def test_calls_correct_detach_endpoint(self, storage_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {}

        asyncio.run(storage_service.detach_volume("abc123", "vol-uuid-1", "inst-uuid-1"))

        mock_ovh_client.post.assert_called_once_with(
            "/cloud/project/abc123/volume/vol-uuid-1/detach",
            instanceId="inst-uuid-1",
        )

    def test_propagates_api_exception(self, storage_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("422 Unprocessable")

        with pytest.raises(Exception, match="422 Unprocessable"):
            asyncio.run(storage_service.detach_volume("abc123", "vol-uuid-1", "inst-uuid-1"))

    def test_raises_value_error_on_invalid_project_id(self, storage_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(storage_service.detach_volume("", "vol-1", "inst-1"))

    def test_raises_value_error_on_invalid_volume_id(self, storage_service):
        with pytest.raises(ValueError, match="Invalid volume_id"):
            asyncio.run(storage_service.detach_volume("abc123", "vol id!", "inst-1"))

    def test_raises_value_error_on_invalid_instance_id(self, storage_service):
        with pytest.raises(ValueError, match="Invalid instance_id"):
            asyncio.run(storage_service.detach_volume("abc123", "vol-1", "inst id!"))


# ---------------------------------------------------------------------------
# create_volume_snapshot
# ---------------------------------------------------------------------------

class TestCreateVolumeSnapshot:

    def test_returns_snapshot_dict(self, storage_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {
            "id": "snap-uuid-1",
            "name": "my-snapshot",
            "status": "creating",
        }

        result = asyncio.run(
            storage_service.create_volume_snapshot("abc123", "vol-uuid-1", "my-snapshot")
        )

        assert result["id"] == "snap-uuid-1"
        assert result["name"] == "my-snapshot"

    def test_calls_correct_snapshot_endpoint(self, storage_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {}

        asyncio.run(
            storage_service.create_volume_snapshot("abc123", "vol-uuid-1", "backup-snap")
        )

        mock_ovh_client.post.assert_called_once_with(
            "/cloud/project/abc123/volume/vol-uuid-1/snapshot",
            name="backup-snap",
        )

    def test_propagates_api_exception(self, storage_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("503 Service Unavailable")

        with pytest.raises(Exception, match="503 Service Unavailable"):
            asyncio.run(
                storage_service.create_volume_snapshot("abc123", "vol-uuid-1", "snap")
            )

    def test_raises_value_error_on_invalid_project_id(self, storage_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(
                storage_service.create_volume_snapshot("bad id!", "vol-1", "snap")
            )

    def test_raises_value_error_on_invalid_volume_id(self, storage_service):
        with pytest.raises(ValueError, match="Invalid volume_id"):
            asyncio.run(
                storage_service.create_volume_snapshot("abc123", "", "snap")
            )

    def test_raises_value_error_on_empty_snapshot_name(self, storage_service):
        with pytest.raises(ValueError, match="Invalid name"):
            asyncio.run(
                storage_service.create_volume_snapshot("abc123", "vol-1", "")
            )

    def test_raises_value_error_on_invalid_snapshot_name(self, storage_service):
        with pytest.raises(ValueError, match="Invalid name"):
            # Name longer than 64 chars
            asyncio.run(
                storage_service.create_volume_snapshot("abc123", "vol-1", "x" * 65)
            )
