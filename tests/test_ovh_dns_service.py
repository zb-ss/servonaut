"""Tests for OVHDNSService."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, call

import pytest

from servonaut.config.schema import OVHConfig
from servonaut.services.ovh_service import OVHService
from servonaut.services.ovh_dns_service import OVHDNSService


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
def dns_service(ovh_service):
    return OVHDNSService(ovh_service)


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:

    def test_stores_ovh_service_reference(self, ovh_service):
        svc = OVHDNSService(ovh_service)
        assert svc._ovh_service is ovh_service


# ---------------------------------------------------------------------------
# list_domains
# ---------------------------------------------------------------------------

class TestListDomains:

    def test_returns_domain_list(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.return_value = ["example.com", "test.org"]

        result = asyncio.run(dns_service.list_domains())

        assert result == ["example.com", "test.org"]
        mock_ovh_client.get.assert_called_once_with("/domain/zone")

    def test_returns_empty_list_on_api_error(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("403 Forbidden")

        result = asyncio.run(dns_service.list_domains())

        assert result == []

    def test_returns_empty_list_when_api_returns_none(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.return_value = None

        result = asyncio.run(dns_service.list_domains())

        assert result == []

    def test_returns_empty_list_when_api_returns_empty(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(dns_service.list_domains())

        assert result == []


# ---------------------------------------------------------------------------
# get_zone_info
# ---------------------------------------------------------------------------

class TestGetZoneInfo:

    def test_returns_zone_info_dict(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {
            "name": "example.com",
            "dnssecSupported": True,
            "hasDnsAnycast": False,
        }

        result = asyncio.run(dns_service.get_zone_info("example.com"))

        assert result["name"] == "example.com"
        mock_ovh_client.get.assert_called_once_with("/domain/zone/example.com")

    def test_returns_empty_dict_on_api_error(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("404 Not Found")

        result = asyncio.run(dns_service.get_zone_info("example.com"))

        assert result == {}

    def test_raises_value_error_on_empty_zone_name(self, dns_service):
        with pytest.raises(ValueError, match="Invalid zone_name"):
            asyncio.run(dns_service.get_zone_info(""))

    def test_raises_value_error_on_invalid_zone_name(self, dns_service):
        with pytest.raises(ValueError, match="Invalid zone_name"):
            asyncio.run(dns_service.get_zone_info("bad zone name!"))


# ---------------------------------------------------------------------------
# list_records
# ---------------------------------------------------------------------------

class TestListRecords:

    def test_returns_records_with_detail(self, dns_service, mock_ovh_client):
        """list_records fetches IDs then fetches each record detail."""
        def _get_side_effect(path, **kwargs):
            if path == "/domain/zone/example.com/record":
                return [101, 102]
            if path == "/domain/zone/example.com/record/101":
                return {"id": 101, "fieldType": "A", "subDomain": "www", "target": "1.2.3.4", "ttl": 3600}
            if path == "/domain/zone/example.com/record/102":
                return {"id": 102, "fieldType": "MX", "subDomain": "", "target": "mail.example.com", "ttl": 600}
            return {}

        mock_ovh_client.get.side_effect = _get_side_effect

        result = asyncio.run(dns_service.list_records("example.com"))

        assert len(result) == 2
        assert result[0] == {"id": 101, "fieldType": "A", "subDomain": "www", "target": "1.2.3.4", "ttl": 3600}
        assert result[1] == {"id": 102, "fieldType": "MX", "subDomain": "", "target": "mail.example.com", "ttl": 600}

    def test_passes_field_type_filter(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        asyncio.run(dns_service.list_records("example.com", field_type="A"))

        mock_ovh_client.get.assert_called_once_with(
            "/domain/zone/example.com/record", fieldType="A"
        )

    def test_passes_sub_domain_filter(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        asyncio.run(dns_service.list_records("example.com", sub_domain="www"))

        mock_ovh_client.get.assert_called_once_with(
            "/domain/zone/example.com/record", subDomain="www"
        )

    def test_passes_both_filters(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        asyncio.run(dns_service.list_records("example.com", field_type="CNAME", sub_domain="mail"))

        mock_ovh_client.get.assert_called_once_with(
            "/domain/zone/example.com/record", fieldType="CNAME", subDomain="mail"
        )

    def test_returns_empty_list_when_no_records(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(dns_service.list_records("example.com"))

        assert result == []

    def test_returns_empty_list_on_api_error(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("500 Server Error")

        result = asyncio.run(dns_service.list_records("example.com"))

        assert result == []

    def test_skips_failed_record_detail_fetch(self, dns_service, mock_ovh_client):
        """A failed detail fetch for one record ID is skipped; others still returned."""
        def _get_side_effect(path, **kwargs):
            if path == "/domain/zone/example.com/record":
                return [101, 102]
            if path == "/domain/zone/example.com/record/101":
                raise Exception("Network error")
            if path == "/domain/zone/example.com/record/102":
                return {"id": 102, "fieldType": "TXT", "subDomain": "", "target": "v=spf1", "ttl": 3600}
            return {}

        mock_ovh_client.get.side_effect = _get_side_effect

        result = asyncio.run(dns_service.list_records("example.com"))

        assert len(result) == 1
        assert result[0]["id"] == 102

    def test_raises_value_error_on_invalid_zone_name(self, dns_service):
        with pytest.raises(ValueError, match="Invalid zone_name"):
            asyncio.run(dns_service.list_records("invalid zone!"))


# ---------------------------------------------------------------------------
# create_record
# ---------------------------------------------------------------------------

class TestCreateRecord:

    def test_calls_post_with_correct_params(self, dns_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {
            "id": 201, "fieldType": "A", "subDomain": "www", "target": "1.2.3.4", "ttl": 3600
        }

        result = asyncio.run(
            dns_service.create_record("example.com", "A", "www", "1.2.3.4", 3600)
        )

        assert result["id"] == 201
        mock_ovh_client.post.assert_called_once_with(
            "/domain/zone/example.com/record",
            fieldType="A",
            subDomain="www",
            target="1.2.3.4",
            ttl=3600,
        )

    def test_uses_default_ttl_3600(self, dns_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {"id": 202}

        asyncio.run(dns_service.create_record("example.com", "A", "", "1.2.3.4"))

        call_kwargs = mock_ovh_client.post.call_args[1]
        assert call_kwargs["ttl"] == 3600

    def test_allows_empty_subdomain(self, dns_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {"id": 203}

        asyncio.run(dns_service.create_record("example.com", "MX", "", "mail.example.com"))

        call_kwargs = mock_ovh_client.post.call_args[1]
        assert call_kwargs["subDomain"] == ""

    def test_raises_value_error_on_invalid_zone_name(self, dns_service):
        with pytest.raises(ValueError, match="Invalid zone_name"):
            asyncio.run(dns_service.create_record("bad zone!", "A", "", "1.2.3.4"))

    def test_raises_value_error_on_empty_field_type(self, dns_service):
        with pytest.raises(ValueError, match="field_type must not be empty"):
            asyncio.run(dns_service.create_record("example.com", "", "", "1.2.3.4"))

    def test_raises_value_error_on_empty_target(self, dns_service):
        with pytest.raises(ValueError, match="target must not be empty"):
            asyncio.run(dns_service.create_record("example.com", "A", "www", ""))

    def test_propagates_api_exception(self, dns_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("422 Unprocessable")

        with pytest.raises(Exception, match="422 Unprocessable"):
            asyncio.run(dns_service.create_record("example.com", "A", "www", "1.2.3.4"))


# ---------------------------------------------------------------------------
# update_record
# ---------------------------------------------------------------------------

class TestUpdateRecord:

    def test_returns_true_on_success(self, dns_service, mock_ovh_client):
        mock_ovh_client.put.return_value = None

        result = asyncio.run(
            dns_service.update_record("example.com", 101, target="5.6.7.8")
        )

        assert result is True

    def test_sends_only_provided_fields(self, dns_service, mock_ovh_client):
        mock_ovh_client.put.return_value = None

        asyncio.run(dns_service.update_record("example.com", 101, target="5.6.7.8"))

        call_kwargs = mock_ovh_client.put.call_args[1]
        assert "target" in call_kwargs
        assert "subDomain" not in call_kwargs
        assert "ttl" not in call_kwargs

    def test_sends_sub_domain_when_provided(self, dns_service, mock_ovh_client):
        mock_ovh_client.put.return_value = None

        asyncio.run(dns_service.update_record("example.com", 101, sub_domain="api"))

        call_kwargs = mock_ovh_client.put.call_args[1]
        assert call_kwargs["subDomain"] == "api"

    def test_sends_ttl_when_provided(self, dns_service, mock_ovh_client):
        mock_ovh_client.put.return_value = None

        asyncio.run(dns_service.update_record("example.com", 101, ttl=7200))

        call_kwargs = mock_ovh_client.put.call_args[1]
        assert call_kwargs["ttl"] == 7200

    def test_sends_all_fields_when_all_provided(self, dns_service, mock_ovh_client):
        mock_ovh_client.put.return_value = None

        asyncio.run(
            dns_service.update_record("example.com", 101, sub_domain="v2", target="9.9.9.9", ttl=300)
        )

        call_kwargs = mock_ovh_client.put.call_args[1]
        assert call_kwargs["subDomain"] == "v2"
        assert call_kwargs["target"] == "9.9.9.9"
        assert call_kwargs["ttl"] == 300

    def test_calls_correct_endpoint(self, dns_service, mock_ovh_client):
        mock_ovh_client.put.return_value = None

        asyncio.run(dns_service.update_record("example.com", 101, target="1.1.1.1"))

        call_args = mock_ovh_client.put.call_args[0]
        assert call_args[0] == "/domain/zone/example.com/record/101"

    def test_raises_value_error_on_invalid_zone_name(self, dns_service):
        with pytest.raises(ValueError, match="Invalid zone_name"):
            asyncio.run(dns_service.update_record("bad zone!", 101, target="1.1.1.1"))

    def test_propagates_api_exception(self, dns_service, mock_ovh_client):
        mock_ovh_client.put.side_effect = Exception("404 Not Found")

        with pytest.raises(Exception, match="404 Not Found"):
            asyncio.run(dns_service.update_record("example.com", 101, target="1.1.1.1"))


# ---------------------------------------------------------------------------
# delete_record
# ---------------------------------------------------------------------------

class TestDeleteRecord:

    def test_returns_true_on_success(self, dns_service, mock_ovh_client):
        mock_ovh_client.delete.return_value = None

        result = asyncio.run(dns_service.delete_record("example.com", 101))

        assert result is True

    def test_calls_correct_endpoint(self, dns_service, mock_ovh_client):
        mock_ovh_client.delete.return_value = None

        asyncio.run(dns_service.delete_record("example.com", 101))

        mock_ovh_client.delete.assert_called_once_with(
            "/domain/zone/example.com/record/101"
        )

    def test_raises_value_error_on_invalid_zone_name(self, dns_service):
        with pytest.raises(ValueError, match="Invalid zone_name"):
            asyncio.run(dns_service.delete_record("", 101))

    def test_propagates_api_exception(self, dns_service, mock_ovh_client):
        mock_ovh_client.delete.side_effect = Exception("403 Forbidden")

        with pytest.raises(Exception, match="403 Forbidden"):
            asyncio.run(dns_service.delete_record("example.com", 101))


# ---------------------------------------------------------------------------
# refresh_zone
# ---------------------------------------------------------------------------

class TestRefreshZone:

    def test_returns_true_on_success(self, dns_service, mock_ovh_client):
        mock_ovh_client.post.return_value = None

        result = asyncio.run(dns_service.refresh_zone("example.com"))

        assert result is True

    def test_calls_correct_endpoint(self, dns_service, mock_ovh_client):
        mock_ovh_client.post.return_value = None

        asyncio.run(dns_service.refresh_zone("example.com"))

        mock_ovh_client.post.assert_called_once_with(
            "/domain/zone/example.com/refresh"
        )

    def test_raises_value_error_on_invalid_zone_name(self, dns_service):
        with pytest.raises(ValueError, match="Invalid zone_name"):
            asyncio.run(dns_service.refresh_zone("bad zone!"))

    def test_propagates_api_exception(self, dns_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("500 Server Error")

        with pytest.raises(Exception, match="500 Server Error"):
            asyncio.run(dns_service.refresh_zone("example.com"))


# ---------------------------------------------------------------------------
# get_domain_info
# ---------------------------------------------------------------------------

class TestGetDomainInfo:

    def test_returns_domain_info_dict(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {
            "domain": "example.com",
            "transferLockStatus": "locked",
        }

        result = asyncio.run(dns_service.get_domain_info("example.com"))

        assert result["domain"] == "example.com"
        mock_ovh_client.get.assert_called_once_with("/domain/example.com")

    def test_returns_empty_dict_on_api_error(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("404 Not Found")

        result = asyncio.run(dns_service.get_domain_info("example.com"))

        assert result == {}

    def test_raises_value_error_on_empty_domain(self, dns_service):
        with pytest.raises(ValueError, match="Invalid domain"):
            asyncio.run(dns_service.get_domain_info(""))

    def test_raises_value_error_on_invalid_domain(self, dns_service):
        with pytest.raises(ValueError, match="Invalid domain"):
            asyncio.run(dns_service.get_domain_info("not a valid domain!"))


# ---------------------------------------------------------------------------
# list_domain_tasks
# ---------------------------------------------------------------------------

class TestListDomainTasks:

    def test_returns_task_list(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.return_value = [
            {"id": 1, "type": "DnsAnycast", "status": "todo"},
            {"id": 2, "type": "DnsZoneCreate", "status": "done"},
        ]

        result = asyncio.run(dns_service.list_domain_tasks("example.com"))

        assert len(result) == 2
        assert result[0]["type"] == "DnsAnycast"
        mock_ovh_client.get.assert_called_once_with("/domain/example.com/task")

    def test_returns_empty_list_on_api_error(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("403 Forbidden")

        result = asyncio.run(dns_service.list_domain_tasks("example.com"))

        assert result == []

    def test_returns_empty_list_when_no_tasks(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(dns_service.list_domain_tasks("example.com"))

        assert result == []

    def test_returns_empty_list_when_api_returns_none(self, dns_service, mock_ovh_client):
        mock_ovh_client.get.return_value = None

        result = asyncio.run(dns_service.list_domain_tasks("example.com"))

        assert result == []

    def test_raises_value_error_on_empty_domain(self, dns_service):
        with pytest.raises(ValueError, match="Invalid domain"):
            asyncio.run(dns_service.list_domain_tasks(""))

    def test_raises_value_error_on_invalid_domain(self, dns_service):
        with pytest.raises(ValueError, match="Invalid domain"):
            asyncio.run(dns_service.list_domain_tasks("bad domain!"))


# ---------------------------------------------------------------------------
# Input validation edge cases
# ---------------------------------------------------------------------------

class TestInputValidation:

    def test_zone_name_with_subdomain_levels(self, dns_service, mock_ovh_client):
        """Multi-level zone names like sub.example.co.uk are valid."""
        mock_ovh_client.get.return_value = {}
        result = asyncio.run(dns_service.get_zone_info("sub.example.co.uk"))
        mock_ovh_client.get.assert_called_once_with("/domain/zone/sub.example.co.uk")

    def test_zone_name_with_hyphens_in_label(self, dns_service, mock_ovh_client):
        """Labels with hyphens like my-domain.com are valid."""
        mock_ovh_client.get.return_value = {}
        asyncio.run(dns_service.get_zone_info("my-domain.com"))
        mock_ovh_client.get.assert_called_once_with("/domain/zone/my-domain.com")

    def test_zone_name_with_leading_dot_is_invalid(self, dns_service):
        with pytest.raises(ValueError, match="Invalid zone_name"):
            asyncio.run(dns_service.get_zone_info(".example.com"))

    def test_zone_name_with_trailing_dot_is_invalid(self, dns_service):
        with pytest.raises(ValueError, match="Invalid zone_name"):
            asyncio.run(dns_service.get_zone_info("example.com."))

    def test_create_record_sends_empty_subdomain_to_represent_apex(self, dns_service, mock_ovh_client):
        """An empty string subdomain represents the zone apex (@) and is valid."""
        mock_ovh_client.post.return_value = {"id": 300}
        asyncio.run(dns_service.create_record("example.com", "A", "", "1.1.1.1"))
        call_kwargs = mock_ovh_client.post.call_args[1]
        assert call_kwargs["subDomain"] == ""
