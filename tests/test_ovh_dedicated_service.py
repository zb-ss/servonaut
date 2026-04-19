"""Tests for OVHDedicatedService."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, call

import pytest

from servonaut.config.schema import OVHConfig
from servonaut.services.ovh_dedicated_service import OVHDedicatedService
from servonaut.services.ovh_service import OVHService


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
def dedicated_service(ovh_service):
    return OVHDedicatedService(ovh_service)


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:

    def test_stores_ovh_service_reference(self, ovh_service):
        svc = OVHDedicatedService(ovh_service)
        assert svc._ovh_service is ovh_service


# ---------------------------------------------------------------------------
# list_templates
# ---------------------------------------------------------------------------

class TestListTemplates:

    def test_returns_flat_list_from_family_grouped_response(
        self, dedicated_service, mock_ovh_client
    ):
        mock_ovh_client.get.return_value = {
            "linux": ["debian12_64", "ubuntu2404-server_64"],
            "windows": ["win2022-core_64"],
        }

        result = asyncio.run(
            dedicated_service.list_templates("ns123456.ip-1-2-3.eu")
        )

        assert len(result) == 3
        names = {t["name"] for t in result}
        assert "debian12_64" in names
        assert "ubuntu2404-server_64" in names
        assert "win2022-core_64" in names

    def test_family_field_preserved(self, dedicated_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {
            "linux": ["debian12_64"],
            "windows": ["win2022-core_64"],
        }

        result = asyncio.run(
            dedicated_service.list_templates("ns123456.ip-1-2-3.eu")
        )

        by_name = {t["name"]: t["family"] for t in result}
        assert by_name["debian12_64"] == "linux"
        assert by_name["win2022-core_64"] == "windows"

    def test_empty_response_returns_empty_list(self, dedicated_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {}

        result = asyncio.run(
            dedicated_service.list_templates("ns123456.ip-1-2-3.eu")
        )

        assert result == []

    def test_calls_correct_endpoint(self, dedicated_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {}

        asyncio.run(dedicated_service.list_templates("ns123456.ip-1-2-3.eu"))

        mock_ovh_client.get.assert_called_once_with(
            "/dedicated/server/ns123456.ip-1-2-3.eu/install/compatibleTemplates"
        )

    def test_invalid_server_name_raises_value_error(self, dedicated_service):
        with pytest.raises(ValueError, match="Invalid server_name"):
            asyncio.run(dedicated_service.list_templates("server; DROP TABLE"))

    def test_server_name_with_special_chars_rejected(self, dedicated_service):
        for bad in ["server name", "server@host", "server$"]:
            with pytest.raises(ValueError):
                asyncio.run(dedicated_service.list_templates(bad))


# ---------------------------------------------------------------------------
# get_template_details
# ---------------------------------------------------------------------------

class TestGetTemplateDetails:

    def test_returns_template_dict(self, dedicated_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {
            "templateName": "debian12_64",
            "description": "Debian 12 (Bookworm) (64bits)",
            "category": "server",
            "distribution": "debian",
            "endOfInstall": None,
        }

        result = asyncio.run(
            dedicated_service.get_template_details("debian12_64")
        )

        assert result["templateName"] == "debian12_64"
        assert result["distribution"] == "debian"

    def test_calls_correct_endpoint(self, dedicated_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {}

        asyncio.run(dedicated_service.get_template_details("debian12_64"))

        mock_ovh_client.get.assert_called_once_with(
            "/dedicated/installationTemplate/debian12_64"
        )

    def test_invalid_template_name_raises_value_error(self, dedicated_service):
        with pytest.raises(ValueError, match="Invalid template_name"):
            asyncio.run(dedicated_service.get_template_details("bad template!"))

    def test_api_error_propagates(self, dedicated_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("404 Not Found")

        with pytest.raises(Exception, match="404 Not Found"):
            asyncio.run(dedicated_service.get_template_details("debian12_64"))


# ---------------------------------------------------------------------------
# reinstall
# ---------------------------------------------------------------------------

class TestReinstall:

    def test_posts_with_template_name_only(self, dedicated_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {"id": 12345, "status": "todo"}

        result = asyncio.run(
            dedicated_service.reinstall("ns123456.ip-1-2-3.eu", "debian12_64")
        )

        assert result["id"] == 12345
        mock_ovh_client.post.assert_called_once_with(
            "/dedicated/server/ns123456.ip-1-2-3.eu/install/start",
            templateName="debian12_64",
        )

    def test_posts_with_customization_merged(self, dedicated_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {"id": 99, "status": "todo"}

        asyncio.run(
            dedicated_service.reinstall(
                "ns123456.ip-1-2-3.eu",
                "debian12_64",
                customization={
                    "sshKeyName": "my-key",
                    "hostname": "web01.example.com",
                    "partitionSchemeName": "default",
                },
            )
        )

        mock_ovh_client.post.assert_called_once_with(
            "/dedicated/server/ns123456.ip-1-2-3.eu/install/start",
            templateName="debian12_64",
            sshKeyName="my-key",
            hostname="web01.example.com",
            partitionSchemeName="default",
        )

    def test_none_customization_omits_extra_fields(self, dedicated_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {"id": 1}

        asyncio.run(
            dedicated_service.reinstall("ns123456.ip-1-2-3.eu", "debian12_64", None)
        )

        _, kwargs = mock_ovh_client.post.call_args
        assert set(kwargs.keys()) == {"templateName"}

    def test_returns_task_dict(self, dedicated_service, mock_ovh_client):
        task = {"id": 777, "function": "reinstallServer", "status": "todo"}
        mock_ovh_client.post.return_value = task

        result = asyncio.run(
            dedicated_service.reinstall("ns123456.ip-1-2-3.eu", "debian12_64")
        )

        assert result is task

    def test_invalid_server_name_raises_value_error(self, dedicated_service):
        with pytest.raises(ValueError, match="Invalid server_name"):
            asyncio.run(
                dedicated_service.reinstall("bad server!", "debian12_64")
            )

    def test_invalid_template_name_raises_value_error(self, dedicated_service):
        with pytest.raises(ValueError, match="Invalid template_name"):
            asyncio.run(
                dedicated_service.reinstall(
                    "ns123456.ip-1-2-3.eu", "bad template name!"
                )
            )

    def test_api_error_propagates(self, dedicated_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("500 Server Error")

        with pytest.raises(Exception, match="500 Server Error"):
            asyncio.run(
                dedicated_service.reinstall("ns123456.ip-1-2-3.eu", "debian12_64")
            )


# ---------------------------------------------------------------------------
# get_install_status
# ---------------------------------------------------------------------------

class TestGetInstallStatus:

    def test_returns_status_dict(self, dedicated_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {
            "progressStatus": 45,
            "comment": "Installing base system",
        }

        result = asyncio.run(
            dedicated_service.get_install_status("ns123456.ip-1-2-3.eu")
        )

        assert result["progressStatus"] == 45
        assert result["comment"] == "Installing base system"

    def test_calls_correct_endpoint(self, dedicated_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {}

        asyncio.run(dedicated_service.get_install_status("ns123456.ip-1-2-3.eu"))

        mock_ovh_client.get.assert_called_once_with(
            "/dedicated/server/ns123456.ip-1-2-3.eu/install/status"
        )

    def test_invalid_server_name_raises_value_error(self, dedicated_service):
        with pytest.raises(ValueError, match="Invalid server_name"):
            asyncio.run(dedicated_service.get_install_status("bad server!"))

    def test_api_error_propagates(self, dedicated_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("503 Unavailable")

        with pytest.raises(Exception, match="503 Unavailable"):
            asyncio.run(dedicated_service.get_install_status("ns123456.ip-1-2-3.eu"))

    def test_completed_status(self, dedicated_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {
            "progressStatus": 100,
            "comment": "Installation complete",
        }

        result = asyncio.run(
            dedicated_service.get_install_status("ns123456.ip-1-2-3.eu")
        )

        assert result["progressStatus"] == 100


# ---------------------------------------------------------------------------
# Input validation (_validate_name)
# ---------------------------------------------------------------------------

class TestValidateName:

    @pytest.mark.parametrize("valid_name", [
        "ns123456.ip-1-2-3.eu",
        "dedicated.server-01",
        "server:8080",
        "host/path",
        "simple",
        "ABC123",
        "a.b-c_d:e/f",
    ])
    def test_valid_names_pass(self, dedicated_service, mock_ovh_client, valid_name):
        mock_ovh_client.get.return_value = {}
        # Should not raise
        asyncio.run(dedicated_service.get_install_status(valid_name))

    @pytest.mark.parametrize("bad_name", [
        "",
        "server name",
        "server@host",
        "server$123",
        "server!",
        "server\x00name",
    ])
    def test_invalid_names_raise(self, dedicated_service, bad_name):
        with pytest.raises(ValueError):
            asyncio.run(dedicated_service.get_install_status(bad_name))
