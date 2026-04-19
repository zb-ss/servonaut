"""Tests for OVHVPSService."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import OVHConfig
from servonaut.services.ovh_service import OVHService
from servonaut.services.ovh_vps_service import OVHVPSService


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
def vps_service(ovh_service):
    return OVHVPSService(ovh_service)


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:

    def test_stores_ovh_service_reference(self, ovh_service):
        svc = OVHVPSService(ovh_service)
        assert svc._ovh_service is ovh_service


# ---------------------------------------------------------------------------
# list_images
# ---------------------------------------------------------------------------

class TestListImages:

    def test_returns_formatted_image_dicts(self, vps_service, mock_ovh_client):
        mock_ovh_client.get.return_value = [
            {'id': 'ubuntu-22.04', 'name': 'Ubuntu 22.04', 'os': 'linux'},
            {'id': 'debian-12', 'name': 'Debian 12', 'os': 'linux'},
        ]

        result = asyncio.run(vps_service.list_images("vps-abc123.ovh.net"))

        assert len(result) == 2
        assert result[0]['id'] == 'ubuntu-22.04'
        assert result[0]['name'] == 'Ubuntu 22.04'
        assert result[0]['os_type'] == 'linux'
        assert result[1]['id'] == 'debian-12'

    def test_returns_empty_list_on_api_error(self, vps_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("403 Forbidden")

        result = asyncio.run(vps_service.list_images("vps-abc123.ovh.net"))

        assert result == []

    def test_returns_empty_list_when_api_returns_empty(self, vps_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(vps_service.list_images("vps-abc123.ovh.net"))

        assert result == []

    def test_handles_string_id_list_response(self, vps_service, mock_ovh_client):
        """Some OVH endpoints return a list of string IDs rather than dicts."""
        def side_effect(path):
            if path == "/vps/vps-abc.ovh.net/availableImages":
                return ["ubuntu-22.04", "debian-12"]
            if "ubuntu-22.04" in path:
                return {'id': 'ubuntu-22.04', 'name': 'Ubuntu 22.04', 'os': 'linux'}
            if "debian-12" in path:
                return {'id': 'debian-12', 'name': 'Debian 12', 'os': 'linux'}
            return {}

        mock_ovh_client.get.side_effect = side_effect

        result = asyncio.run(vps_service.list_images("vps-abc.ovh.net"))

        assert len(result) == 2
        names = [r['name'] for r in result]
        assert 'Ubuntu 22.04' in names
        assert 'Debian 12' in names

    def test_raises_value_error_on_invalid_vps_name(self, vps_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(vps_service.list_images("vps name with spaces"))

    def test_raises_value_error_on_empty_vps_name(self, vps_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(vps_service.list_images(""))

    def test_raises_value_error_on_injection_attempt(self, vps_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(vps_service.list_images("vps; echo pwned"))


# ---------------------------------------------------------------------------
# reinstall
# ---------------------------------------------------------------------------

class TestReinstall:

    def test_calls_post_with_correct_path_and_image_id(self, vps_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {"task": "12345"}

        result = asyncio.run(vps_service.reinstall("vps-abc123.ovh.net", "ubuntu-22.04"))

        assert result is True
        mock_ovh_client.post.assert_called_once_with(
            "/vps/vps-abc123.ovh.net/reinstall",
            imageId="ubuntu-22.04",
        )

    def test_returns_true_on_success(self, vps_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {}

        result = asyncio.run(vps_service.reinstall("vps-abc123.ovh.net", "debian-12"))

        assert result is True

    def test_propagates_api_exception(self, vps_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("500 Server Error")

        with pytest.raises(Exception, match="500 Server Error"):
            asyncio.run(vps_service.reinstall("vps-abc123.ovh.net", "ubuntu-22.04"))

    def test_raises_value_error_on_invalid_vps_name(self, vps_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(vps_service.reinstall("bad name!", "ubuntu-22.04"))

    def test_raises_value_error_on_invalid_image_id(self, vps_service):
        with pytest.raises(ValueError, match="Invalid image_id"):
            asyncio.run(vps_service.reinstall("vps-abc123.ovh.net", "image with spaces"))


# ---------------------------------------------------------------------------
# list_upgrade_models
# ---------------------------------------------------------------------------

class TestListUpgradeModels:

    def test_returns_formatted_model_dicts(self, vps_service, mock_ovh_client):
        mock_ovh_client.get.return_value = [
            {'name': 'vps-le-2-2-40', 'vcores': 2, 'memory': 2048, 'disk': 40, 'price': 5.99},
            {'name': 'vps-le-4-8-160', 'vcores': 4, 'memory': 8192, 'disk': 160, 'price': 19.99},
        ]

        result = asyncio.run(vps_service.list_upgrade_models("vps-abc123.ovh.net"))

        assert len(result) == 2
        assert result[0]['name'] == 'vps-le-2-2-40'
        assert result[0]['vcpus'] == 2
        assert result[0]['ram'] == 2048
        assert result[0]['disk'] == 40
        assert result[0]['price'] == 5.99
        assert result[1]['name'] == 'vps-le-4-8-160'

    def test_returns_empty_list_on_api_error(self, vps_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("403 Forbidden")

        result = asyncio.run(vps_service.list_upgrade_models("vps-abc123.ovh.net"))

        assert result == []

    def test_returns_empty_list_when_no_upgrades_available(self, vps_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(vps_service.list_upgrade_models("vps-abc123.ovh.net"))

        assert result == []

    def test_handles_string_model_list_response(self, vps_service, mock_ovh_client):
        """Some OVH endpoints return plain model name strings."""
        mock_ovh_client.get.return_value = ["vps-le-2-2-40", "vps-le-4-8-160"]

        result = asyncio.run(vps_service.list_upgrade_models("vps-abc123.ovh.net"))

        assert len(result) == 2
        assert result[0]['name'] == 'vps-le-2-2-40'
        assert result[1]['name'] == 'vps-le-4-8-160'

    def test_raises_value_error_on_invalid_vps_name(self, vps_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(vps_service.list_upgrade_models("vps name with spaces!"))

    def test_calls_correct_api_endpoint(self, vps_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        asyncio.run(vps_service.list_upgrade_models("vps-abc123.ovh.net"))

        mock_ovh_client.get.assert_called_once_with(
            "/vps/vps-abc123.ovh.net/availableUpgrade"
        )


# ---------------------------------------------------------------------------
# upgrade
# ---------------------------------------------------------------------------

class TestUpgrade:

    def test_calls_post_with_correct_path_and_model(self, vps_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {"task": "67890"}

        result = asyncio.run(vps_service.upgrade("vps-abc123.ovh.net", "vps-le-4-8-160"))

        assert result is True
        mock_ovh_client.post.assert_called_once_with(
            "/vps/vps-abc123.ovh.net/change",
            model="vps-le-4-8-160",
        )

    def test_returns_true_on_success(self, vps_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {}

        result = asyncio.run(vps_service.upgrade("vps-abc123.ovh.net", "vps-le-2-2-40"))

        assert result is True

    def test_propagates_api_exception(self, vps_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("409 Conflict")

        with pytest.raises(Exception, match="409 Conflict"):
            asyncio.run(vps_service.upgrade("vps-abc123.ovh.net", "vps-le-4-8-160"))

    def test_raises_value_error_on_invalid_vps_name(self, vps_service):
        with pytest.raises(ValueError, match="Invalid vps_name"):
            asyncio.run(vps_service.upgrade("vps name!", "vps-le-4-8-160"))

    def test_raises_value_error_on_invalid_model(self, vps_service):
        with pytest.raises(ValueError, match="Invalid model"):
            asyncio.run(vps_service.upgrade("vps-abc123.ovh.net", "model with spaces"))

    def test_raises_value_error_on_empty_model(self, vps_service):
        with pytest.raises(ValueError, match="Invalid model"):
            asyncio.run(vps_service.upgrade("vps-abc123.ovh.net", ""))
