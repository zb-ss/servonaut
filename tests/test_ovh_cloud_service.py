"""Tests for OVHCloudService."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, call

import pytest

from servonaut.config.schema import OVHConfig
from servonaut.services.ovh_service import OVHService
from servonaut.services.ovh_cloud_service import OVHCloudService


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
def cloud_service(ovh_service):
    return OVHCloudService(ovh_service)


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:

    def test_stores_ovh_service_reference(self, ovh_service):
        svc = OVHCloudService(ovh_service)
        assert svc._ovh_service is ovh_service


# ---------------------------------------------------------------------------
# list_flavors
# ---------------------------------------------------------------------------

class TestListFlavors:

    def test_returns_formatted_flavor_dicts(self, cloud_service, mock_ovh_client):
        mock_ovh_client.get.return_value = [
            {"id": "b2-7", "name": "b2-7", "vcpus": 2, "ram": 7000, "disk": 50, "region": "GRA11"},
            {"id": "b2-15", "name": "b2-15", "vcpus": 4, "ram": 15000, "disk": 100, "region": "SBG5"},
        ]

        result = asyncio.run(cloud_service.list_flavors("proj-abc123"))

        assert len(result) == 2
        assert result[0]["id"] == "b2-7"
        assert result[0]["vcpus"] == 2
        assert result[0]["ram"] == 7000
        assert result[0]["disk"] == 50
        assert result[1]["id"] == "b2-15"

    def test_filters_by_region(self, cloud_service, mock_ovh_client):
        mock_ovh_client.get.return_value = [
            {"id": "b2-7", "name": "b2-7", "vcpus": 2, "ram": 7000, "disk": 50, "region": "GRA11"},
            {"id": "b2-15", "name": "b2-15", "vcpus": 4, "ram": 15000, "disk": 100, "region": "SBG5"},
        ]

        result = asyncio.run(cloud_service.list_flavors("proj-abc123", region="GRA11"))

        assert len(result) == 1
        assert result[0]["id"] == "b2-7"
        assert result[0]["region"] == "GRA11"

    def test_returns_empty_list_when_no_region_match(self, cloud_service, mock_ovh_client):
        mock_ovh_client.get.return_value = [
            {"id": "b2-7", "name": "b2-7", "vcpus": 2, "ram": 7000, "disk": 50, "region": "GRA11"},
        ]

        result = asyncio.run(cloud_service.list_flavors("proj-abc123", region="BHS5"))

        assert result == []

    def test_returns_empty_list_on_api_error(self, cloud_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("403 Forbidden")

        result = asyncio.run(cloud_service.list_flavors("proj-abc123"))

        assert result == []

    def test_returns_empty_list_when_api_returns_empty(self, cloud_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(cloud_service.list_flavors("proj-abc123"))

        assert result == []

    def test_calls_correct_api_endpoint(self, cloud_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        asyncio.run(cloud_service.list_flavors("proj-abc123"))

        mock_ovh_client.get.assert_called_once_with(
            "/cloud/project/proj-abc123/flavor"
        )

    def test_raises_value_error_on_invalid_project_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(cloud_service.list_flavors("proj id with spaces"))

    def test_raises_value_error_on_empty_project_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(cloud_service.list_flavors(""))


# ---------------------------------------------------------------------------
# list_images
# ---------------------------------------------------------------------------

class TestListImages:

    def test_returns_formatted_image_dicts(self, cloud_service, mock_ovh_client):
        mock_ovh_client.get.return_value = [
            {"id": "img-ubuntu-22", "name": "Ubuntu 22.04", "type": "linux", "minDisk": 10, "region": "GRA11"},
            {"id": "img-debian-12", "name": "Debian 12", "type": "linux", "minDisk": 8, "region": "GRA11"},
        ]

        result = asyncio.run(cloud_service.list_images("proj-abc123"))

        assert len(result) == 2
        assert result[0]["id"] == "img-ubuntu-22"
        assert result[0]["name"] == "Ubuntu 22.04"
        assert result[0]["os_type"] == "linux"
        assert result[0]["min_disk"] == 10
        assert result[1]["id"] == "img-debian-12"

    def test_filters_by_region(self, cloud_service, mock_ovh_client):
        mock_ovh_client.get.return_value = [
            {"id": "img-ubuntu-22", "name": "Ubuntu 22.04", "type": "linux", "minDisk": 10, "region": "GRA11"},
            {"id": "img-debian-12", "name": "Debian 12", "type": "linux", "minDisk": 8, "region": "SBG5"},
        ]

        result = asyncio.run(cloud_service.list_images("proj-abc123", region="SBG5"))

        assert len(result) == 1
        assert result[0]["id"] == "img-debian-12"

    def test_returns_empty_list_on_api_error(self, cloud_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("500 Server Error")

        result = asyncio.run(cloud_service.list_images("proj-abc123"))

        assert result == []

    def test_returns_empty_list_when_api_returns_empty(self, cloud_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(cloud_service.list_images("proj-abc123"))

        assert result == []

    def test_calls_correct_api_endpoint(self, cloud_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        asyncio.run(cloud_service.list_images("proj-abc123"))

        mock_ovh_client.get.assert_called_once_with(
            "/cloud/project/proj-abc123/image"
        )

    def test_raises_value_error_on_invalid_project_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(cloud_service.list_images("proj; rm -rf"))


# ---------------------------------------------------------------------------
# list_ssh_keys
# ---------------------------------------------------------------------------

class TestListSSHKeys:

    def test_returns_formatted_key_dicts(self, cloud_service, mock_ovh_client):
        mock_ovh_client.get.return_value = [
            {"id": "key-abc", "name": "my-key", "publicKey": "ssh-rsa AAAA...", "fingerPrint": "aa:bb:cc"},
        ]

        result = asyncio.run(cloud_service.list_ssh_keys("proj-abc123"))

        assert len(result) == 1
        assert result[0]["id"] == "key-abc"
        assert result[0]["name"] == "my-key"
        assert result[0]["public_key"] == "ssh-rsa AAAA..."
        assert result[0]["fingerprint"] == "aa:bb:cc"

    def test_returns_empty_list_on_api_error(self, cloud_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("403 Forbidden")

        result = asyncio.run(cloud_service.list_ssh_keys("proj-abc123"))

        assert result == []

    def test_returns_empty_list_when_no_keys(self, cloud_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(cloud_service.list_ssh_keys("proj-abc123"))

        assert result == []

    def test_calls_correct_api_endpoint(self, cloud_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        asyncio.run(cloud_service.list_ssh_keys("proj-abc123"))

        mock_ovh_client.get.assert_called_once_with(
            "/cloud/project/proj-abc123/sshkey"
        )

    def test_raises_value_error_on_invalid_project_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(cloud_service.list_ssh_keys(""))


# ---------------------------------------------------------------------------
# add_ssh_key
# ---------------------------------------------------------------------------

class TestAddSSHKey:

    def test_calls_post_with_correct_params(self, cloud_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {
            "id": "key-new",
            "name": "deploy-key",
            "publicKey": "ssh-rsa AAAA...",
            "fingerPrint": "de:ad:be:ef",
        }

        result = asyncio.run(
            cloud_service.add_ssh_key("proj-abc123", "deploy-key", "ssh-rsa AAAA...")
        )

        mock_ovh_client.post.assert_called_once_with(
            "/cloud/project/proj-abc123/sshkey",
            name="deploy-key",
            publicKey="ssh-rsa AAAA...",
        )
        assert result["id"] == "key-new"
        assert result["name"] == "deploy-key"
        assert result["fingerprint"] == "de:ad:be:ef"

    def test_includes_region_when_provided(self, cloud_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {"id": "key-new", "name": "k", "publicKey": "", "fingerPrint": ""}

        asyncio.run(
            cloud_service.add_ssh_key("proj-abc123", "deploy-key", "ssh-rsa AAAA...", region="GRA11")
        )

        mock_ovh_client.post.assert_called_once_with(
            "/cloud/project/proj-abc123/sshkey",
            name="deploy-key",
            publicKey="ssh-rsa AAAA...",
            region="GRA11",
        )

    def test_propagates_api_exception(self, cloud_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("409 Conflict")

        with pytest.raises(Exception, match="409 Conflict"):
            asyncio.run(
                cloud_service.add_ssh_key("proj-abc123", "deploy-key", "ssh-rsa AAAA...")
            )

    def test_raises_value_error_on_invalid_project_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(cloud_service.add_ssh_key("bad proj!", "k", "ssh-rsa AAAA..."))

    def test_raises_value_error_on_invalid_name(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid name"):
            asyncio.run(cloud_service.add_ssh_key("proj-abc123", "my key!", "ssh-rsa AAAA..."))


# ---------------------------------------------------------------------------
# delete_ssh_key
# ---------------------------------------------------------------------------

class TestDeleteSSHKey:

    def test_calls_delete_with_correct_path(self, cloud_service, mock_ovh_client):
        mock_ovh_client.delete.return_value = None

        result = asyncio.run(cloud_service.delete_ssh_key("proj-abc123", "key-abc"))

        assert result is True
        mock_ovh_client.delete.assert_called_once_with(
            "/cloud/project/proj-abc123/sshkey/key-abc"
        )

    def test_propagates_api_exception(self, cloud_service, mock_ovh_client):
        mock_ovh_client.delete.side_effect = Exception("404 Not Found")

        with pytest.raises(Exception, match="404 Not Found"):
            asyncio.run(cloud_service.delete_ssh_key("proj-abc123", "key-abc"))

    def test_raises_value_error_on_invalid_project_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(cloud_service.delete_ssh_key("bad proj!", "key-abc"))

    def test_raises_value_error_on_invalid_key_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid key_id"):
            asyncio.run(cloud_service.delete_ssh_key("proj-abc123", "key with spaces"))

    def test_raises_value_error_on_empty_key_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid key_id"):
            asyncio.run(cloud_service.delete_ssh_key("proj-abc123", ""))


# ---------------------------------------------------------------------------
# create_instance
# ---------------------------------------------------------------------------

class TestCreateInstance:

    def test_calls_post_with_required_params(self, cloud_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {
            "id": "inst-xyz",
            "name": "my-server",
            "status": "BUILD",
            "region": "GRA11",
        }

        result = asyncio.run(
            cloud_service.create_instance(
                "proj-abc123", "my-server", "b2-7", "img-ubuntu-22", "GRA11"
            )
        )

        mock_ovh_client.post.assert_called_once_with(
            "/cloud/project/proj-abc123/instance",
            name="my-server",
            flavorId="b2-7",
            imageId="img-ubuntu-22",
            region="GRA11",
        )
        assert result["id"] == "inst-xyz"
        assert result["name"] == "my-server"
        assert result["status"] == "BUILD"
        assert result["flavor_id"] == "b2-7"
        assert result["image_id"] == "img-ubuntu-22"

    def test_includes_ssh_key_id_when_provided(self, cloud_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {
            "id": "inst-xyz", "name": "my-server", "status": "BUILD", "region": "GRA11"
        }

        asyncio.run(
            cloud_service.create_instance(
                "proj-abc123", "my-server", "b2-7", "img-ubuntu-22", "GRA11",
                ssh_key_id="key-abc",
            )
        )

        mock_ovh_client.post.assert_called_once_with(
            "/cloud/project/proj-abc123/instance",
            name="my-server",
            flavorId="b2-7",
            imageId="img-ubuntu-22",
            region="GRA11",
            sshKeyId="key-abc",
        )

    def test_omits_ssh_key_id_when_empty(self, cloud_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {
            "id": "inst-xyz", "name": "my-server", "status": "BUILD", "region": "GRA11"
        }

        asyncio.run(
            cloud_service.create_instance(
                "proj-abc123", "my-server", "b2-7", "img-ubuntu-22", "GRA11",
                ssh_key_id="",
            )
        )

        call_kwargs = mock_ovh_client.post.call_args.kwargs
        assert "sshKeyId" not in call_kwargs

    def test_propagates_api_exception(self, cloud_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("503 Service Unavailable")

        with pytest.raises(Exception, match="503 Service Unavailable"):
            asyncio.run(
                cloud_service.create_instance(
                    "proj-abc123", "my-server", "b2-7", "img-ubuntu-22", "GRA11"
                )
            )

    def test_raises_value_error_on_invalid_project_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(
                cloud_service.create_instance("bad proj!", "srv", "b2-7", "img", "GRA11")
            )

    def test_raises_value_error_on_invalid_name(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid name"):
            asyncio.run(
                cloud_service.create_instance(
                    "proj-abc123", "my server!", "b2-7", "img-ubuntu-22", "GRA11"
                )
            )

    def test_raises_value_error_on_invalid_flavor_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid flavor_id"):
            asyncio.run(
                cloud_service.create_instance(
                    "proj-abc123", "my-server", "flavor with spaces", "img-ubuntu-22", "GRA11"
                )
            )

    def test_raises_value_error_on_invalid_image_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid image_id"):
            asyncio.run(
                cloud_service.create_instance(
                    "proj-abc123", "my-server", "b2-7", "image with spaces", "GRA11"
                )
            )

    def test_raises_value_error_on_invalid_region(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid region"):
            asyncio.run(
                cloud_service.create_instance(
                    "proj-abc123", "my-server", "b2-7", "img-ubuntu-22", "GRA 11"
                )
            )

    def test_raises_value_error_on_invalid_ssh_key_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid ssh_key_id"):
            asyncio.run(
                cloud_service.create_instance(
                    "proj-abc123", "my-server", "b2-7", "img-ubuntu-22", "GRA11",
                    ssh_key_id="key with spaces",
                )
            )


# ---------------------------------------------------------------------------
# delete_instance
# ---------------------------------------------------------------------------

class TestDeleteInstance:

    def test_calls_delete_with_correct_path(self, cloud_service, mock_ovh_client):
        mock_ovh_client.delete.return_value = None

        result = asyncio.run(cloud_service.delete_instance("proj-abc123", "inst-xyz"))

        assert result is True
        mock_ovh_client.delete.assert_called_once_with(
            "/cloud/project/proj-abc123/instance/inst-xyz"
        )

    def test_propagates_api_exception(self, cloud_service, mock_ovh_client):
        mock_ovh_client.delete.side_effect = Exception("404 Not Found")

        with pytest.raises(Exception, match="404 Not Found"):
            asyncio.run(cloud_service.delete_instance("proj-abc123", "inst-xyz"))

    def test_raises_value_error_on_invalid_project_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(cloud_service.delete_instance("bad proj!", "inst-xyz"))

    def test_raises_value_error_on_invalid_instance_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid instance_id"):
            asyncio.run(cloud_service.delete_instance("proj-abc123", "inst with spaces"))

    def test_raises_value_error_on_empty_instance_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid instance_id"):
            asyncio.run(cloud_service.delete_instance("proj-abc123", ""))


# ---------------------------------------------------------------------------
# resize_instance
# ---------------------------------------------------------------------------

class TestResizeInstance:

    def test_calls_post_with_correct_path_and_flavor(self, cloud_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {
            "id": "inst-xyz",
            "name": "my-server",
            "status": "RESIZE",
        }

        result = asyncio.run(
            cloud_service.resize_instance("proj-abc123", "inst-xyz", "b2-15")
        )

        mock_ovh_client.post.assert_called_once_with(
            "/cloud/project/proj-abc123/instance/inst-xyz/resize",
            flavorId="b2-15",
        )
        assert result["id"] == "inst-xyz"
        assert result["flavor_id"] == "b2-15"
        assert result["status"] == "RESIZE"

    def test_uses_instance_id_as_fallback_id(self, cloud_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {"name": "my-server", "status": "RESIZE"}

        result = asyncio.run(
            cloud_service.resize_instance("proj-abc123", "inst-xyz", "b2-15")
        )

        assert result["id"] == "inst-xyz"

    def test_propagates_api_exception(self, cloud_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("409 Conflict")

        with pytest.raises(Exception, match="409 Conflict"):
            asyncio.run(
                cloud_service.resize_instance("proj-abc123", "inst-xyz", "b2-15")
            )

    def test_raises_value_error_on_invalid_project_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid project_id"):
            asyncio.run(cloud_service.resize_instance("", "inst-xyz", "b2-15"))

    def test_raises_value_error_on_invalid_instance_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid instance_id"):
            asyncio.run(cloud_service.resize_instance("proj-abc123", "inst xyz!", "b2-15"))

    def test_raises_value_error_on_invalid_flavor_id(self, cloud_service):
        with pytest.raises(ValueError, match="Invalid flavor_id"):
            asyncio.run(cloud_service.resize_instance("proj-abc123", "inst-xyz", "flavor id!"))
