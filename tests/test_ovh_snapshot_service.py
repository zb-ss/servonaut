"""Tests for OVHSnapshotService."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, call

import pytest

from servonaut.config.schema import OVHConfig
from servonaut.services.ovh_service import OVHService
from servonaut.services.ovh_snapshot_service import OVHSnapshotService


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
def snapshot_service(ovh_service):
    return OVHSnapshotService(ovh_service)


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:

    def test_stores_ovh_service_reference(self, ovh_service):
        svc = OVHSnapshotService(ovh_service)
        assert svc._ovh_service is ovh_service


# ---------------------------------------------------------------------------
# list_vps_snapshots
# ---------------------------------------------------------------------------

class TestListVpsSnapshots:

    def test_returns_list_of_dicts(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.return_value = [
            {"id": "snap-1", "name": "Snapshot 1", "creationDate": "2024-01-01T00:00:00Z"},
            {"id": "snap-2", "name": "Snapshot 2", "creationDate": "2024-02-01T00:00:00Z"},
        ]

        result = asyncio.run(snapshot_service.list_vps_snapshots("vps-abc123.ovh.net"))

        assert len(result) == 2
        assert result[0]["id"] == "snap-1"
        assert result[1]["name"] == "Snapshot 2"

    def test_normalises_string_ids_to_dicts(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.return_value = ["snap-id-1", "snap-id-2"]

        result = asyncio.run(snapshot_service.list_vps_snapshots("vps-abc123.ovh.net"))

        assert len(result) == 2
        assert result[0] == {"id": "snap-id-1", "name": "snap-id-1"}

    def test_returns_empty_list_on_api_error(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("404 Not Found")

        result = asyncio.run(snapshot_service.list_vps_snapshots("vps-abc123.ovh.net"))

        assert result == []

    def test_returns_empty_list_when_api_returns_none(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(snapshot_service.list_vps_snapshots("vps-abc123.ovh.net"))

        assert result == []

    def test_calls_correct_api_endpoint(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        asyncio.run(snapshot_service.list_vps_snapshots("vps-test.ovh.net"))

        mock_ovh_client.get.assert_called_once_with("/vps/vps-test.ovh.net/snapshot")

    def test_raises_value_error_on_invalid_vps_name(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(snapshot_service.list_vps_snapshots("vps name with spaces"))

    def test_raises_value_error_on_empty_vps_name(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(snapshot_service.list_vps_snapshots(""))

    def test_raises_value_error_on_injection_attempt(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(snapshot_service.list_vps_snapshots("vps; echo pwned"))


# ---------------------------------------------------------------------------
# create_vps_snapshot
# ---------------------------------------------------------------------------

class TestCreateVpsSnapshot:

    def test_calls_post_with_correct_path(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {"task": "12345"}

        result = asyncio.run(
            snapshot_service.create_vps_snapshot("vps-abc123.ovh.net", "my backup")
        )

        mock_ovh_client.post.assert_called_once_with(
            "/vps/vps-abc123.ovh.net/createSnapshot",
            description="my backup",
        )
        assert isinstance(result, dict)

    def test_uses_empty_description_by_default(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {}

        asyncio.run(snapshot_service.create_vps_snapshot("vps-abc123.ovh.net"))

        _, kwargs = mock_ovh_client.post.call_args
        assert kwargs["description"] == ""

    def test_returns_dict_from_api(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {"id": "task-99", "status": "todo"}

        result = asyncio.run(
            snapshot_service.create_vps_snapshot("vps-abc123.ovh.net")
        )

        assert result == {"id": "task-99", "status": "todo"}

    def test_returns_empty_dict_when_api_returns_none(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.return_value = None

        result = asyncio.run(
            snapshot_service.create_vps_snapshot("vps-abc123.ovh.net")
        )

        assert result == {}

    def test_propagates_api_exception(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("500 Server Error")

        with pytest.raises(Exception, match="500 Server Error"):
            asyncio.run(snapshot_service.create_vps_snapshot("vps-abc123.ovh.net"))

    def test_raises_value_error_on_invalid_vps_name(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(snapshot_service.create_vps_snapshot("bad vps!"))


# ---------------------------------------------------------------------------
# restore_vps_snapshot
# ---------------------------------------------------------------------------

class TestRestoreVpsSnapshot:

    def test_calls_post_with_correct_path(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.return_value = None

        result = asyncio.run(
            snapshot_service.restore_vps_snapshot("vps-abc123.ovh.net", "snap-42")
        )

        mock_ovh_client.post.assert_called_once_with(
            "/vps/vps-abc123.ovh.net/snapshot/snap-42/revert"
        )
        assert result is True

    def test_returns_true_on_success(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {}

        result = asyncio.run(
            snapshot_service.restore_vps_snapshot("vps-abc123.ovh.net", "snap-1")
        )

        assert result is True

    def test_propagates_api_exception(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("403 Forbidden")

        with pytest.raises(Exception, match="403 Forbidden"):
            asyncio.run(
                snapshot_service.restore_vps_snapshot("vps-abc123.ovh.net", "snap-1")
            )

    def test_raises_value_error_on_invalid_vps_name(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(snapshot_service.restore_vps_snapshot("bad vps!", "snap-1"))

    def test_raises_value_error_on_invalid_snapshot_id(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid snapshot_id"):
            asyncio.run(
                snapshot_service.restore_vps_snapshot("vps-abc123.ovh.net", "snap id with spaces")
            )


# ---------------------------------------------------------------------------
# delete_vps_snapshot
# ---------------------------------------------------------------------------

class TestDeleteVpsSnapshot:

    def test_calls_delete_with_correct_path(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.delete.return_value = None

        result = asyncio.run(snapshot_service.delete_vps_snapshot("vps-abc123.ovh.net"))

        mock_ovh_client.delete.assert_called_once_with("/vps/vps-abc123.ovh.net/snapshot")
        assert result is True

    def test_returns_true_on_success(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.delete.return_value = {}

        result = asyncio.run(snapshot_service.delete_vps_snapshot("vps-abc123.ovh.net"))

        assert result is True

    def test_propagates_api_exception(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.delete.side_effect = Exception("404 Not Found")

        with pytest.raises(Exception, match="404 Not Found"):
            asyncio.run(snapshot_service.delete_vps_snapshot("vps-abc123.ovh.net"))

    def test_raises_value_error_on_invalid_vps_name(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(snapshot_service.delete_vps_snapshot("../../etc/passwd"))


# ---------------------------------------------------------------------------
# get_vps_backup_options
# ---------------------------------------------------------------------------

class TestGetVpsBackupOptions:

    def test_returns_backup_options_dict(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {
            "state": "enabled",
            "schedule": "0 3 * * *",
            "maxSlots": 7,
        }

        result = asyncio.run(snapshot_service.get_vps_backup_options("vps-abc123.ovh.net"))

        assert result["state"] == "enabled"
        assert result["schedule"] == "0 3 * * *"

    def test_returns_empty_dict_on_api_error(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("404 Not Found")

        result = asyncio.run(snapshot_service.get_vps_backup_options("vps-abc123.ovh.net"))

        assert result == {}

    def test_returns_empty_dict_when_api_returns_non_dict(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.return_value = None

        result = asyncio.run(snapshot_service.get_vps_backup_options("vps-abc123.ovh.net"))

        assert result == {}

    def test_calls_correct_api_endpoint(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {}

        asyncio.run(snapshot_service.get_vps_backup_options("vps-test.ovh.net"))

        mock_ovh_client.get.assert_called_once_with(
            "/vps/vps-test.ovh.net/automatedBackup"
        )

    def test_raises_value_error_on_invalid_vps_name(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(snapshot_service.get_vps_backup_options("bad vps name!"))


# ---------------------------------------------------------------------------
# configure_vps_backup
# ---------------------------------------------------------------------------

class TestConfigureVpsBackup:

    def test_calls_post_with_schedule(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {}

        result = asyncio.run(
            snapshot_service.configure_vps_backup("vps-abc123.ovh.net", "0 3 * * *")
        )

        mock_ovh_client.post.assert_called_once_with(
            "/vps/vps-abc123.ovh.net/automatedBackup",
            schedule="0 3 * * *",
        )
        assert result is True

    def test_returns_true_on_success(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.return_value = None

        result = asyncio.run(
            snapshot_service.configure_vps_backup("vps-abc123.ovh.net", "0 4 * * 0")
        )

        assert result is True

    def test_propagates_api_exception(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("422 Unprocessable Entity")

        with pytest.raises(Exception, match="422 Unprocessable Entity"):
            asyncio.run(
                snapshot_service.configure_vps_backup("vps-abc123.ovh.net", "0 3 * * *")
            )

    def test_raises_value_error_on_invalid_vps_name(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(snapshot_service.configure_vps_backup("bad name!", "0 3 * * *"))

    def test_raises_value_error_on_empty_schedule(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid schedule"):
            asyncio.run(snapshot_service.configure_vps_backup("vps-abc123.ovh.net", ""))


# ---------------------------------------------------------------------------
# list_vps_backups
# ---------------------------------------------------------------------------

class TestListVpsBackups:

    def test_returns_list_of_backup_dicts(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.return_value = [
            {"restore_point": "2024-01-01T03:00:00Z", "state": "available"},
            {"restore_point": "2024-01-02T03:00:00Z", "state": "available"},
        ]

        result = asyncio.run(snapshot_service.list_vps_backups("vps-abc123.ovh.net"))

        assert len(result) == 2
        assert result[0]["state"] == "available"

    def test_normalises_string_restore_points(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.return_value = ["2024-01-01T03:00:00Z", "2024-01-02T03:00:00Z"]

        result = asyncio.run(snapshot_service.list_vps_backups("vps-abc123.ovh.net"))

        assert len(result) == 2
        assert result[0] == {"restore_point": "2024-01-01T03:00:00Z"}

    def test_returns_empty_list_on_api_error(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("403 Forbidden")

        result = asyncio.run(snapshot_service.list_vps_backups("vps-abc123.ovh.net"))

        assert result == []

    def test_returns_empty_list_when_no_backups(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(snapshot_service.list_vps_backups("vps-abc123.ovh.net"))

        assert result == []

    def test_calls_correct_api_endpoint(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        asyncio.run(snapshot_service.list_vps_backups("vps-test.ovh.net"))

        mock_ovh_client.get.assert_called_once_with(
            "/vps/vps-test.ovh.net/automatedBackup/attachedBackup"
        )

    def test_raises_value_error_on_invalid_vps_name(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(snapshot_service.list_vps_backups("../../etc/passwd"))


# ---------------------------------------------------------------------------
# restore_vps_backup
# ---------------------------------------------------------------------------

class TestRestoreVpsBackup:

    def test_calls_post_with_restore_point(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.return_value = None
        restore_point = "2024-01-01T03:00:00Z"

        result = asyncio.run(
            snapshot_service.restore_vps_backup("vps-abc123.ovh.net", restore_point)
        )

        mock_ovh_client.post.assert_called_once_with(
            "/vps/vps-abc123.ovh.net/automatedBackup/restore",
            restorePoint=restore_point,
        )
        assert result is True

    def test_returns_true_on_success(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {}

        result = asyncio.run(
            snapshot_service.restore_vps_backup("vps-abc123.ovh.net", "2024-01-01T03:00:00Z")
        )

        assert result is True

    def test_propagates_api_exception(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("500 Server Error")

        with pytest.raises(Exception, match="500 Server Error"):
            asyncio.run(
                snapshot_service.restore_vps_backup(
                    "vps-abc123.ovh.net", "2024-01-01T03:00:00Z"
                )
            )

    def test_raises_value_error_on_invalid_vps_name(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(
                snapshot_service.restore_vps_backup("bad vps!", "2024-01-01T03:00:00Z")
            )

    def test_raises_value_error_on_empty_restore_point(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid restore_point"):
            asyncio.run(snapshot_service.restore_vps_backup("vps-abc123.ovh.net", ""))

    def test_raises_value_error_on_malformed_restore_point(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid restore_point"):
            asyncio.run(
                snapshot_service.restore_vps_backup("vps-abc123.ovh.net", "not a timestamp!")
            )


# ---------------------------------------------------------------------------
# list_cloud_snapshots
# ---------------------------------------------------------------------------

class TestListCloudSnapshots:

    def test_returns_list_of_snapshot_dicts(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.return_value = [
            {"id": "snap-cloud-1", "name": "Cloud Snap 1", "status": "active"},
            {"id": "snap-cloud-2", "name": "Cloud Snap 2", "status": "active"},
        ]

        result = asyncio.run(snapshot_service.list_cloud_snapshots("proj-12345"))

        assert len(result) == 2
        assert result[0]["id"] == "snap-cloud-1"

    def test_filters_non_dict_items(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.return_value = [
            {"id": "snap-1", "name": "Snap 1"},
            "some-string-id",
        ]

        result = asyncio.run(snapshot_service.list_cloud_snapshots("proj-12345"))

        assert len(result) == 1
        assert result[0]["id"] == "snap-1"

    def test_returns_empty_list_on_api_error(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("403 Forbidden")

        result = asyncio.run(snapshot_service.list_cloud_snapshots("proj-12345"))

        assert result == []

    def test_returns_empty_list_when_no_snapshots(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(snapshot_service.list_cloud_snapshots("proj-12345"))

        assert result == []

    def test_calls_correct_api_endpoint(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        asyncio.run(snapshot_service.list_cloud_snapshots("my-project-id"))

        mock_ovh_client.get.assert_called_once_with(
            "/cloud/project/my-project-id/snapshot"
        )

    def test_raises_value_error_on_invalid_project_id(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(snapshot_service.list_cloud_snapshots("project with spaces"))

    def test_raises_value_error_on_empty_project_id(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(snapshot_service.list_cloud_snapshots(""))


# ---------------------------------------------------------------------------
# create_cloud_snapshot
# ---------------------------------------------------------------------------

class TestCreateCloudSnapshot:

    def test_calls_post_with_correct_path_and_name(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {"id": "task-111"}

        result = asyncio.run(
            snapshot_service.create_cloud_snapshot("proj-abc", "inst-xyz", "my-snapshot")
        )

        mock_ovh_client.post.assert_called_once_with(
            "/cloud/project/proj-abc/instance/inst-xyz/snapshot",
            snapshotName="my-snapshot",
        )
        assert result == {"id": "task-111"}

    def test_returns_empty_dict_when_api_returns_none(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.return_value = None

        result = asyncio.run(
            snapshot_service.create_cloud_snapshot("proj-abc", "inst-xyz", "snap-name")
        )

        assert result == {}

    def test_propagates_api_exception(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("422 Invalid payload")

        with pytest.raises(Exception, match="422 Invalid payload"):
            asyncio.run(
                snapshot_service.create_cloud_snapshot("proj-abc", "inst-xyz", "snap")
            )

    def test_raises_value_error_on_invalid_project_id(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(
                snapshot_service.create_cloud_snapshot("bad project!", "inst-xyz", "snap")
            )

    def test_raises_value_error_on_invalid_instance_id(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid instance_id"):
            asyncio.run(
                snapshot_service.create_cloud_snapshot("proj-abc", "bad instance!", "snap")
            )

    def test_raises_value_error_on_empty_snapshot_name(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid snapshot_name"):
            asyncio.run(
                snapshot_service.create_cloud_snapshot("proj-abc", "inst-xyz", "")
            )


# ---------------------------------------------------------------------------
# delete_cloud_snapshot
# ---------------------------------------------------------------------------

class TestDeleteCloudSnapshot:

    def test_calls_delete_with_correct_path(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.delete.return_value = None

        result = asyncio.run(
            snapshot_service.delete_cloud_snapshot("proj-abc", "snap-999")
        )

        mock_ovh_client.delete.assert_called_once_with(
            "/cloud/project/proj-abc/snapshot/snap-999"
        )
        assert result is True

    def test_returns_true_on_success(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.delete.return_value = {}

        result = asyncio.run(
            snapshot_service.delete_cloud_snapshot("proj-abc", "snap-999")
        )

        assert result is True

    def test_propagates_api_exception(self, snapshot_service, mock_ovh_client):
        mock_ovh_client.delete.side_effect = Exception("404 Not Found")

        with pytest.raises(Exception, match="404 Not Found"):
            asyncio.run(
                snapshot_service.delete_cloud_snapshot("proj-abc", "snap-999")
            )

    def test_raises_value_error_on_invalid_project_id(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(snapshot_service.delete_cloud_snapshot("bad project!", "snap-999"))

    def test_raises_value_error_on_invalid_snapshot_id(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid snapshot_id"):
            asyncio.run(snapshot_service.delete_cloud_snapshot("proj-abc", "snap id with spaces"))

    def test_raises_value_error_on_empty_snapshot_id(self, snapshot_service):
        with pytest.raises(ValueError, match="Invalid snapshot_id"):
            asyncio.run(snapshot_service.delete_cloud_snapshot("proj-abc", ""))
