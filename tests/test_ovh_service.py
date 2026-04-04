"""Tests for OVHService."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from servonaut.config.schema import OVHConfig
from servonaut.services.ovh_service import OVHService, _OVH_CACHE_TTL_SECONDS


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_config(**kwargs) -> OVHConfig:
    """Return an OVHConfig pre-populated with 3-key credentials."""
    defaults = dict(
        enabled=True,
        endpoint="ovh-eu",
        application_key="APP_KEY",
        application_secret="APP_SECRET",
        consumer_key="CONSUMER_KEY",
        include_dedicated=True,
        include_vps=True,
        include_cloud=True,
        cloud_project_ids=["proj-123"],
    )
    defaults.update(kwargs)
    return OVHConfig(**defaults)


@pytest.fixture
def config():
    return _make_config()


@pytest.fixture
def service(config):
    return OVHService(config)


@pytest.fixture
def mock_client():
    return MagicMock()


@pytest.fixture
def service_with_client(service, mock_client):
    """OVHService with a pre-injected mock client (bypasses _get_client)."""
    service._client = mock_client
    return service


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:

    def test_client_is_none_at_init(self, config):
        svc = OVHService(config)
        assert svc._client is None

    def test_config_is_stored(self, config):
        svc = OVHService(config)
        assert svc._config is config


# ---------------------------------------------------------------------------
# _get_client
# ---------------------------------------------------------------------------

class TestGetClient:

    def test_returns_cached_client_on_second_call(self, service):
        fake_client = MagicMock()
        service._client = fake_client
        assert service._get_client() is fake_client

    def test_raises_import_error_when_ovh_missing(self, config):
        svc = OVHService(config)
        with patch.dict("sys.modules", {"ovh": None}):
            with pytest.raises(ImportError, match="python-ovh is not installed"):
                svc._get_client()

    def test_3key_auth_uses_correct_kwargs(self, config):
        mock_ovh_module = MagicMock()
        mock_ovh_module.Client.return_value = MagicMock()
        with patch.dict("sys.modules", {"ovh": mock_ovh_module}):
            svc = OVHService(config)
            svc._get_client()

        mock_ovh_module.Client.assert_called_once_with(
            endpoint="ovh-eu",
            application_key="APP_KEY",
            application_secret="APP_SECRET",
            consumer_key="CONSUMER_KEY",
        )

    def test_oauth2_auth_used_when_client_id_set(self):
        cfg = _make_config(client_id="my-client-id", client_secret="my-secret")
        mock_ovh_module = MagicMock()
        mock_ovh_module.Client.return_value = MagicMock()
        with patch.dict("sys.modules", {"ovh": mock_ovh_module}):
            svc = OVHService(cfg)
            svc._get_client()

        mock_ovh_module.Client.assert_called_once_with(
            endpoint="ovh-eu",
            client_id="my-client-id",
            client_secret="my-secret",
        )

    def test_resolve_secret_called_for_credentials(self, config):
        mock_ovh_module = MagicMock()
        mock_ovh_module.Client.return_value = MagicMock()
        with patch("servonaut.services.ovh_service.resolve_secret", side_effect=lambda v: v) as mock_resolve, \
             patch.dict("sys.modules", {"ovh": mock_ovh_module}):
            svc = OVHService(config)
            svc._get_client()

        # resolve_secret called for all 5 credential fields
        resolved_values = [c.args[0] for c in mock_resolve.call_args_list]
        assert "APP_KEY" in resolved_values
        assert "APP_SECRET" in resolved_values
        assert "CONSUMER_KEY" in resolved_values

    def test_env_var_secret_resolved(self):
        cfg = _make_config(application_secret="$MY_OVH_SECRET")
        mock_ovh_module = MagicMock()
        mock_ovh_module.Client.return_value = MagicMock()
        with patch.dict(os.environ, {"MY_OVH_SECRET": "resolved-secret"}), \
             patch.dict("sys.modules", {"ovh": mock_ovh_module}):
            svc = OVHService(cfg)
            svc._get_client()

        _, kwargs = mock_ovh_module.Client.call_args
        assert kwargs["application_secret"] == "resolved-secret"

    def test_client_property_calls_get_client(self, service, mock_client):
        service._client = mock_client
        assert service.client is mock_client


# ---------------------------------------------------------------------------
# default_username
# ---------------------------------------------------------------------------

class TestDefaultUsername:

    def test_cloud_returns_ubuntu(self):
        assert OVHService.default_username("cloud") == "ubuntu"

    def test_dedicated_returns_debian(self):
        assert OVHService.default_username("dedicated") == "debian"

    def test_vps_returns_ubuntu(self):
        assert OVHService.default_username("vps") == "ubuntu"

    def test_unknown_returns_ubuntu(self):
        assert OVHService.default_username("unknown-type") == "ubuntu"

    def test_empty_string_returns_ubuntu(self):
        assert OVHService.default_username("") == "ubuntu"


# ---------------------------------------------------------------------------
# State mapping helpers
# ---------------------------------------------------------------------------

class TestMapDedicatedState:

    def test_ok_maps_to_running(self):
        assert OVHService._map_dedicated_state("ok") == "running"

    def test_hacked_maps_to_error(self):
        assert OVHService._map_dedicated_state("hacked") == "error"

    def test_hacked_blocked_maps_to_error(self):
        assert OVHService._map_dedicated_state("hackedBlocked") == "error"

    def test_unknown_state_returned_as_is(self):
        assert OVHService._map_dedicated_state("maintenance") == "maintenance"

    def test_empty_string_returned_as_is(self):
        assert OVHService._map_dedicated_state("") == ""


class TestMapVpsState:

    def test_running_maps_to_running(self):
        assert OVHService._map_vps_state("running") == "running"

    def test_stopped_maps_to_stopped(self):
        assert OVHService._map_vps_state("stopped") == "stopped"

    def test_installing_maps_to_pending(self):
        assert OVHService._map_vps_state("installing") == "pending"

    def test_rescue_mode_maps_to_running(self):
        assert OVHService._map_vps_state("rescueMode") == "running"

    def test_unknown_returned_as_is(self):
        assert OVHService._map_vps_state("rebooting") == "rebooting"

    def test_empty_string_returned_as_is(self):
        assert OVHService._map_vps_state("") == ""


class TestMapCloudState:

    def test_active_maps_to_running(self):
        assert OVHService._map_cloud_state("ACTIVE") == "running"

    def test_shutoff_maps_to_stopped(self):
        assert OVHService._map_cloud_state("SHUTOFF") == "stopped"

    def test_build_maps_to_pending(self):
        assert OVHService._map_cloud_state("BUILD") == "pending"

    def test_error_maps_to_error(self):
        assert OVHService._map_cloud_state("ERROR") == "error"

    def test_shelved_maps_to_stopped(self):
        assert OVHService._map_cloud_state("SHELVED") == "stopped"

    def test_rescued_maps_to_running(self):
        assert OVHService._map_cloud_state("RESCUED") == "running"

    def test_suspended_maps_to_stopped(self):
        assert OVHService._map_cloud_state("SUSPENDED") == "stopped"

    def test_unknown_status_lowercased(self):
        assert OVHService._map_cloud_state("VERIFY_RESIZE") == "verify_resize"

    def test_empty_string_returns_empty(self):
        assert OVHService._map_cloud_state("") == ""


# ---------------------------------------------------------------------------
# IP extraction helpers
# ---------------------------------------------------------------------------

class TestFindPublicIp:

    def test_returns_public_ip(self):
        # 5.39.45.10 is a real OVH public IP
        ips = ["10.0.0.1", "5.39.45.10"]
        assert OVHService._find_public_ip(ips) == "5.39.45.10"

    def test_strips_cidr_notation(self):
        ips = ["5.39.45.10/32"]
        assert OVHService._find_public_ip(ips) == "5.39.45.10"

    def test_empty_list_returns_empty(self):
        assert OVHService._find_public_ip([]) == ""

    def test_fallback_to_first_entry_when_no_public_ip(self):
        # All private — fallback returns the first entry unchanged
        ips = ["192.168.1.1", "10.0.0.2"]
        result = OVHService._find_public_ip(ips)
        assert result == "192.168.1.1"

    def test_skips_private_10_range_in_favour_of_global(self):
        # 5.39.0.1 is routable/global (not private, not loopback)
        ips = ["10.0.0.1", "5.39.0.1"]
        assert OVHService._find_public_ip(ips) == "5.39.0.1"

    def test_skips_loopback_in_favour_of_global(self):
        ips = ["127.0.0.1", "5.39.0.1"]
        assert OVHService._find_public_ip(ips) == "5.39.0.1"

    def test_skips_172_16_private_in_favour_of_global(self):
        ips = ["172.16.0.1", "5.39.0.1"]
        assert OVHService._find_public_ip(ips) == "5.39.0.1"

    def test_invalid_ip_entries_are_skipped_and_fallback_applied(self):
        # "not-an-ip" is invalid (ValueError), no valid public IP found,
        # so fallback returns the first entry as-is.
        ips = ["not-an-ip", "5.39.0.1"]
        # 5.39.0.1 is a valid public IP — it should be returned
        assert OVHService._find_public_ip(ips) == "5.39.0.1"

    def test_fallback_returns_first_entry_when_all_invalid(self):
        # All entries are unparseable — fallback returns the first entry
        ips = ["not-an-ip", "also-invalid"]
        assert OVHService._find_public_ip(ips) == "not-an-ip"


class TestFindPrivateIp:

    def test_returns_private_ip(self):
        ips = ["5.39.45.10", "10.0.0.1"]
        assert OVHService._find_private_ip(ips) == "10.0.0.1"

    def test_strips_cidr_notation(self):
        ips = ["192.168.1.5/24"]
        assert OVHService._find_private_ip(ips) == "192.168.1.5"

    def test_empty_list_returns_empty(self):
        assert OVHService._find_private_ip([]) == ""

    def test_no_private_ip_returns_empty(self):
        # Use IPs that are genuinely global/public in Python 3.11+ is_private logic
        ips = ["5.39.0.1", "51.195.10.20"]
        assert OVHService._find_private_ip(ips) == ""

    def test_172_16_recognized_as_private(self):
        ips = ["172.16.5.1"]
        assert OVHService._find_private_ip(ips) == "172.16.5.1"

    def test_invalid_entries_skipped(self):
        ips = ["not-valid", "10.1.2.3"]
        assert OVHService._find_private_ip(ips) == "10.1.2.3"


class TestExtractPublicIp:

    def test_returns_public_ipv4(self):
        ip_addresses = [
            {"type": "public", "version": 4, "ip": "5.39.45.10"},
            {"type": "private", "version": 4, "ip": "10.0.0.1"},
        ]
        assert OVHService._extract_public_ip(ip_addresses) == "5.39.45.10"

    def test_prefers_ipv4_over_ipv6(self):
        ip_addresses = [
            {"type": "public", "version": 6, "ip": "2001:db8::1"},
            {"type": "public", "version": 4, "ip": "5.39.45.10"},
        ]
        assert OVHService._extract_public_ip(ip_addresses) == "5.39.45.10"

    def test_falls_back_to_any_public(self):
        ip_addresses = [
            {"type": "public", "version": 6, "ip": "2001:db8::1"},
        ]
        assert OVHService._extract_public_ip(ip_addresses) == "2001:db8::1"

    def test_empty_list_returns_empty(self):
        assert OVHService._extract_public_ip([]) == ""

    def test_no_public_returns_empty(self):
        ip_addresses = [{"type": "private", "version": 4, "ip": "10.0.0.1"}]
        assert OVHService._extract_public_ip(ip_addresses) == ""


class TestExtractPrivateIp:

    def test_returns_private_ipv4(self):
        ip_addresses = [
            {"type": "public", "version": 4, "ip": "5.39.45.10"},
            {"type": "private", "version": 4, "ip": "10.0.0.1"},
        ]
        assert OVHService._extract_private_ip(ip_addresses) == "10.0.0.1"

    def test_falls_back_to_any_private(self):
        ip_addresses = [
            {"type": "private", "version": 6, "ip": "fd00::1"},
        ]
        assert OVHService._extract_private_ip(ip_addresses) == "fd00::1"

    def test_empty_list_returns_empty(self):
        assert OVHService._extract_private_ip([]) == ""

    def test_no_private_returns_empty(self):
        ip_addresses = [{"type": "public", "version": 4, "ip": "5.39.45.10"}]
        assert OVHService._extract_private_ip(ip_addresses) == ""


# ---------------------------------------------------------------------------
# Unit conversion helpers
# ---------------------------------------------------------------------------

class TestBytesToGb:

    def test_zero_returns_zero(self):
        assert OVHService._bytes_to_gb(0) == 0.0

    def test_none_returns_zero(self):
        assert OVHService._bytes_to_gb(None) == 0.0

    def test_16gb_in_bytes(self):
        assert OVHService._bytes_to_gb(16 * 1024 ** 3) == 16.0

    def test_rounding(self):
        # 1.5 GB in bytes = 1.5 GB
        assert OVHService._bytes_to_gb(int(1.5 * 1024 ** 3)) == 1.5

    def test_invalid_string_returns_zero(self):
        assert OVHService._bytes_to_gb("invalid") == 0.0

    def test_string_integer_accepted(self):
        assert OVHService._bytes_to_gb(str(8 * 1024 ** 3)) == 8.0


class TestMbToGb:

    def test_zero_returns_zero(self):
        assert OVHService._mb_to_gb(0) == 0.0

    def test_none_returns_zero(self):
        assert OVHService._mb_to_gb(None) == 0.0

    def test_2048mb_is_2gb(self):
        assert OVHService._mb_to_gb(2048) == 2.0

    def test_1024mb_is_1gb(self):
        assert OVHService._mb_to_gb(1024) == 1.0

    def test_invalid_string_returns_zero(self):
        assert OVHService._mb_to_gb("not-a-number") == 0.0

    def test_string_integer_accepted(self):
        assert OVHService._mb_to_gb("4096") == 4.0


# ---------------------------------------------------------------------------
# _fetch_dedicated
# ---------------------------------------------------------------------------

class TestFetchDedicated:

    def test_returns_instance_list(self, service_with_client, mock_client):
        mock_client.get.side_effect = lambda path, **kw: {
            "/dedicated/server": ["ns1234.example.com"],
            "/dedicated/server/ns1234.example.com": {
                "reverse": "my-server.example.com",
                "state": "ok",
                "datacenter": "sbg5",
                "os": "debian10_64",
            },
            "/dedicated/server/ns1234.example.com/specifications/hardware": {
                "description": "HOST-32M-NVME",
                "numberOfCores": 8,
                "memorySize": 34359738368,  # 32 GB
            },
            "/dedicated/server/ns1234.example.com/ips": ["51.195.10.20"],
        }.get(path, {})

        result = service_with_client._fetch_dedicated()

        assert len(result) == 1
        inst = result[0]
        assert inst["id"] == "ns1234.example.com"
        assert inst["name"] == "my-server.example.com"
        assert inst["state"] == "running"
        assert inst["region"] == "sbg5"
        assert inst["provider"] == "OVH"
        assert inst["provider_type"] == "dedicated"
        assert inst["is_ovh"] is True
        assert inst["public_ip"] == "51.195.10.20"
        assert inst["cpu"] == 8
        assert inst["ram_gb"] == 32.0

    def test_empty_server_list_returns_empty(self, service_with_client, mock_client):
        mock_client.get.return_value = []
        result = service_with_client._fetch_dedicated()
        assert result == []

    def test_error_listing_returns_empty(self, service_with_client, mock_client):
        mock_client.get.side_effect = Exception("API error")
        result = service_with_client._fetch_dedicated()
        assert result == []

    def test_individual_server_error_skipped(self, service_with_client, mock_client):
        def side_effect(path, **kw):
            if path == "/dedicated/server":
                return ["server1", "server2"]
            if "server1" in path:
                raise Exception("server1 unavailable")
            # server2 minimal details
            if path == "/dedicated/server/server2":
                return {"state": "ok", "datacenter": "sbg5"}
            return {}

        mock_client.get.side_effect = side_effect
        result = service_with_client._fetch_dedicated()
        # server1 failed, server2 should still succeed
        assert len(result) == 1
        assert result[0]["id"] == "server2"

    def test_hardware_specs_failure_non_fatal(self, service_with_client, mock_client):
        def side_effect(path, **kw):
            if path == "/dedicated/server":
                return ["server1"]
            if path == "/dedicated/server/server1":
                return {"state": "ok", "datacenter": "rbx1"}
            if "specifications" in path:
                raise Exception("no specs")
            if path == "/dedicated/server/server1/ips":
                return []
            return {}

        mock_client.get.side_effect = side_effect
        result = service_with_client._fetch_dedicated()
        assert len(result) == 1
        assert result[0]["type"] == "Dedicated"

    def test_uses_name_as_fallback_when_no_reverse(self, service_with_client, mock_client):
        def side_effect(path, **kw):
            if path == "/dedicated/server":
                return ["ns5678"]
            if path == "/dedicated/server/ns5678":
                return {"state": "ok", "datacenter": "gra"}  # no 'reverse'
            return {}

        mock_client.get.side_effect = side_effect
        result = service_with_client._fetch_dedicated()
        assert result[0]["name"] == "ns5678"

    def test_dedicated_server_unexpected_exception_skipped(self, service_with_client, mock_client):
        """Unexpected exceptions from _fetch_dedicated_server are caught in the loop."""
        mock_client.get.return_value = ["ns-unexpected"]
        with patch.object(
            service_with_client, "_fetch_dedicated_server",
            side_effect=RuntimeError("unexpected crash")
        ):
            result = service_with_client._fetch_dedicated()
        assert result == []

    def test_ips_fetch_failure_non_fatal(self, service_with_client, mock_client):
        def side_effect(path, **kw):
            if path == "/dedicated/server":
                return ["ns9999"]
            if path == "/dedicated/server/ns9999":
                return {"state": "ok", "datacenter": "rbx"}
            if path == "/dedicated/server/ns9999/specifications/hardware":
                return {}
            if path == "/dedicated/server/ns9999/ips":
                raise Exception("IPs not available")
            return {}

        mock_client.get.side_effect = side_effect
        result = service_with_client._fetch_dedicated()
        assert len(result) == 1
        assert result[0]["public_ip"] == ""


# ---------------------------------------------------------------------------
# _fetch_vps
# ---------------------------------------------------------------------------

class TestFetchVps:

    def test_returns_vps_instances(self, service_with_client, mock_client):
        mock_client.get.side_effect = lambda path, **kw: {
            "/vps": ["vps-aaa.ovh.net"],
            "/vps/vps-aaa.ovh.net": {
                "displayName": "My VPS",
                "state": "running",
                "zone": "GRA1",
                "model": {"name": "VPS-SSD-2", "memory": 4096},
            },
            "/vps/vps-aaa.ovh.net/ips": ["51.195.10.21", "2001:db8::1"],
        }.get(path, {})

        result = service_with_client._fetch_vps()

        assert len(result) == 1
        inst = result[0]
        assert inst["id"] == "vps-aaa.ovh.net"
        assert inst["name"] == "My VPS"
        assert inst["state"] == "running"
        assert inst["type"] == "VPS-SSD-2"
        assert inst["region"] == "GRA1"
        assert inst["public_ip"] == "51.195.10.21"
        assert inst["ram_gb"] == 4.0
        assert inst["provider_type"] == "vps"
        assert inst["is_ovh"] is True

    def test_empty_vps_list_returns_empty(self, service_with_client, mock_client):
        mock_client.get.return_value = []
        result = service_with_client._fetch_vps()
        assert result == []

    def test_error_listing_returns_empty(self, service_with_client, mock_client):
        mock_client.get.side_effect = Exception("API unavailable")
        result = service_with_client._fetch_vps()
        assert result == []

    def test_individual_vps_error_skipped(self, service_with_client, mock_client):
        def side_effect(path, **kw):
            if path == "/vps":
                return ["vps-a", "vps-b"]
            if path == "/vps/vps-a":
                raise Exception("vps-a error")
            if path == "/vps/vps-b":
                return {"state": "stopped", "zone": "SBG1", "model": {}}
            return {}

        mock_client.get.side_effect = side_effect
        result = service_with_client._fetch_vps()
        assert len(result) == 1
        assert result[0]["id"] == "vps-b"

    def test_state_mapping_applied(self, service_with_client, mock_client):
        mock_client.get.side_effect = lambda path, **kw: {
            "/vps": ["vps-x"],
            "/vps/vps-x": {"state": "installing", "zone": "", "model": {}},
        }.get(path, {})

        result = service_with_client._fetch_vps()
        assert result[0]["state"] == "pending"

    def test_display_name_fallback_to_id(self, service_with_client, mock_client):
        mock_client.get.side_effect = lambda path, **kw: {
            "/vps": ["vps-noname"],
            "/vps/vps-noname": {"state": "running", "zone": "", "model": {}},
        }.get(path, {})

        result = service_with_client._fetch_vps()
        assert result[0]["name"] == "vps-noname"

    def test_no_ips_field_leaves_public_ip_empty(self, service_with_client, mock_client):
        mock_client.get.side_effect = lambda path, **kw: {
            "/vps": ["vps-noip"],
            "/vps/vps-noip": {"state": "running", "zone": "", "model": {}},
        }.get(path, {})

        result = service_with_client._fetch_vps()
        assert result[0]["public_ip"] == ""


# ---------------------------------------------------------------------------
# _fetch_cloud
# ---------------------------------------------------------------------------

class TestFetchCloud:

    def test_returns_cloud_instances(self, service_with_client, mock_client):
        mock_client.get.return_value = [
            {
                "id": "inst-abc",
                "name": "my-cloud-vm",
                "flavor": {"name": "b2-7"},
                "flavorId": "b2-7-flavor",
                "status": "ACTIVE",
                "region": "GRA11",
                "ipAddresses": [
                    {"type": "public", "version": 4, "ip": "54.36.10.1"},
                    {"type": "private", "version": 4, "ip": "192.168.0.5"},
                ],
            }
        ]

        result = service_with_client._fetch_cloud("proj-123")

        assert len(result) == 1
        inst = result[0]
        # composite ID
        assert inst["id"] == "proj-123/inst-abc"
        assert inst["name"] == "my-cloud-vm"
        assert inst["type"] == "b2-7"
        assert inst["state"] == "running"
        assert inst["region"] == "GRA11"
        assert inst["public_ip"] == "54.36.10.1"
        assert inst["private_ip"] == "192.168.0.5"
        assert inst["provider_type"] == "cloud"
        assert inst["is_ovh"] is True

    def test_error_returns_empty(self, service_with_client, mock_client):
        mock_client.get.side_effect = Exception("Cloud project inaccessible")
        result = service_with_client._fetch_cloud("proj-123")
        assert result == []

    def test_empty_instance_list_returns_empty(self, service_with_client, mock_client):
        mock_client.get.return_value = []
        result = service_with_client._fetch_cloud("proj-123")
        assert result == []

    def test_flavor_name_fallback_to_flavor_id(self, service_with_client, mock_client):
        mock_client.get.return_value = [
            {
                "id": "inst-xyz",
                "name": "vm",
                "flavor": {},  # no 'name'
                "flavorId": "s1-2",
                "status": "ACTIVE",
                "region": "SBG5",
                "ipAddresses": [],
            }
        ]
        result = service_with_client._fetch_cloud("proj-999")
        assert result[0]["type"] == "s1-2"

    def test_composite_id_encodes_project(self, service_with_client, mock_client):
        mock_client.get.return_value = [
            {"id": "inst-001", "name": "vm", "status": "ACTIVE", "region": "", "ipAddresses": []}
        ]
        result = service_with_client._fetch_cloud("my-project")
        assert result[0]["id"] == "my-project/inst-001"

    def test_state_mapping_applied(self, service_with_client, mock_client):
        mock_client.get.return_value = [
            {"id": "inst-002", "name": "vm", "status": "SHUTOFF", "region": "", "ipAddresses": []}
        ]
        result = service_with_client._fetch_cloud("proj-x")
        assert result[0]["state"] == "stopped"


# ---------------------------------------------------------------------------
# fetch_instances (async, integration of all types)
# ---------------------------------------------------------------------------

class TestFetchInstances:

    def _make_service(self, include_dedicated=True, include_vps=True, include_cloud=True,
                      cloud_project_ids=None):
        cfg = _make_config(
            include_dedicated=include_dedicated,
            include_vps=include_vps,
            include_cloud=include_cloud,
            cloud_project_ids=cloud_project_ids or [],
        )
        return OVHService(cfg)

    def test_all_types_enabled(self):
        svc = self._make_service(cloud_project_ids=["proj-1"])
        fake_dedicated = [{"id": "d1", "provider_type": "dedicated"}]
        fake_vps = [{"id": "v1", "provider_type": "vps"}]
        fake_cloud = [{"id": "proj-1/c1", "provider_type": "cloud"}]

        with patch.object(svc, "_fetch_dedicated", return_value=fake_dedicated), \
             patch.object(svc, "_fetch_vps", return_value=fake_vps), \
             patch.object(svc, "_fetch_cloud", return_value=fake_cloud):
            result = asyncio.run(svc.fetch_instances())

        ids = [inst["id"] for inst in result]
        assert "d1" in ids
        assert "v1" in ids
        assert "proj-1/c1" in ids

    def test_dedicated_disabled(self):
        svc = self._make_service(include_dedicated=False)
        with patch.object(svc, "_fetch_dedicated") as mock_ded, \
             patch.object(svc, "_fetch_vps", return_value=[]), \
             patch.object(svc, "_fetch_cloud", return_value=[]):
            asyncio.run(svc.fetch_instances())

        mock_ded.assert_not_called()

    def test_vps_disabled(self):
        svc = self._make_service(include_vps=False)
        with patch.object(svc, "_fetch_dedicated", return_value=[]), \
             patch.object(svc, "_fetch_vps") as mock_vps, \
             patch.object(svc, "_fetch_cloud", return_value=[]):
            asyncio.run(svc.fetch_instances())

        mock_vps.assert_not_called()

    def test_cloud_disabled(self):
        svc = self._make_service(include_cloud=False)
        with patch.object(svc, "_fetch_dedicated", return_value=[]), \
             patch.object(svc, "_fetch_vps", return_value=[]), \
             patch.object(svc, "_fetch_cloud") as mock_cloud:
            asyncio.run(svc.fetch_instances())

        mock_cloud.assert_not_called()

    def test_error_in_dedicated_does_not_block_vps(self):
        svc = self._make_service(include_cloud=False)

        def raise_error():
            raise Exception("dedicated API down")

        with patch.object(svc, "_fetch_dedicated", side_effect=raise_error), \
             patch.object(svc, "_fetch_vps", return_value=[{"id": "v1"}]):
            result = asyncio.run(svc.fetch_instances())

        assert len(result) == 1
        assert result[0]["id"] == "v1"

    def test_error_in_vps_does_not_block_dedicated(self):
        svc = self._make_service(include_cloud=False)

        def raise_error():
            raise Exception("VPS API down")

        with patch.object(svc, "_fetch_dedicated", return_value=[{"id": "d1"}]), \
             patch.object(svc, "_fetch_vps", side_effect=raise_error):
            result = asyncio.run(svc.fetch_instances())

        assert len(result) == 1
        assert result[0]["id"] == "d1"

    def test_error_in_one_cloud_project_does_not_block_other(self):
        cfg = _make_config(
            include_dedicated=False,
            include_vps=False,
            include_cloud=True,
            cloud_project_ids=["proj-a", "proj-b"],
        )
        svc = OVHService(cfg)

        def fetch_cloud_side_effect(project_id):
            if project_id == "proj-a":
                raise Exception("proj-a error")
            return [{"id": f"{project_id}/inst-1"}]

        with patch.object(svc, "_fetch_cloud", side_effect=fetch_cloud_side_effect):
            result = asyncio.run(svc.fetch_instances())

        assert len(result) == 1
        assert result[0]["id"] == "proj-b/inst-1"

    def test_multiple_cloud_projects_fetched(self):
        cfg = _make_config(
            include_dedicated=False,
            include_vps=False,
            include_cloud=True,
            cloud_project_ids=["proj-a", "proj-b", "proj-c"],
        )
        svc = OVHService(cfg)

        def fetch_cloud_side_effect(project_id):
            return [{"id": f"{project_id}/inst-1"}]

        with patch.object(svc, "_fetch_cloud", side_effect=fetch_cloud_side_effect):
            result = asyncio.run(svc.fetch_instances())

        assert len(result) == 3


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

class TestSaveCache:

    def test_saves_json_file(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        instances = [{"id": "ns1", "name": "server1"}]

        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            service._save_cache(instances)

        assert cache_path.exists()
        data = json.loads(cache_path.read_text())
        assert data["instances"] == instances
        assert "timestamp" in data

    def test_file_has_restricted_permissions(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"

        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            service._save_cache([])

        file_mode = stat.S_IMODE(os.stat(str(cache_path)).st_mode)
        assert file_mode == 0o600

    def test_creates_parent_directory(self, service, tmp_path):
        cache_path = tmp_path / "subdir" / "ovh_cache.json"

        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            service._save_cache([])

        assert cache_path.exists()

    def test_save_error_is_caught_silently(self, service, tmp_path):
        # Point at a path whose parent cannot be created (non-writable root)
        # Simulate the write failing by patching os.open
        cache_path = tmp_path / "cache.json"
        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path), \
             patch("os.open", side_effect=OSError("permission denied")):
            # Must not raise
            service._save_cache([{"id": "ns1"}])


class TestLoadCache:

    def test_returns_none_when_file_missing(self, service, tmp_path):
        cache_path = tmp_path / "nonexistent.json"
        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            result = service._load_cache()
        assert result is None

    def test_returns_instances_when_fresh(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        instances = [{"id": "ns1", "name": "server1"}]
        data = {
            "timestamp": datetime.now().isoformat(),
            "instances": instances,
        }
        cache_path.write_text(json.dumps(data))

        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            result = service._load_cache()

        assert result == instances

    def test_returns_none_when_expired(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        expired_ts = datetime.now() - timedelta(seconds=_OVH_CACHE_TTL_SECONDS + 60)
        data = {
            "timestamp": expired_ts.isoformat(),
            "instances": [{"id": "ns1"}],
        }
        cache_path.write_text(json.dumps(data))

        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            result = service._load_cache()

        assert result is None

    def test_ignore_ttl_returns_expired_data(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        expired_ts = datetime.now() - timedelta(seconds=_OVH_CACHE_TTL_SECONDS + 3600)
        data = {
            "timestamp": expired_ts.isoformat(),
            "instances": [{"id": "stale"}],
        }
        cache_path.write_text(json.dumps(data))

        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            result = service._load_cache(ignore_ttl=True)

        assert result == [{"id": "stale"}]

    def test_corrupt_json_returns_none(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        cache_path.write_text("not-valid-json{{{{")

        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            result = service._load_cache()

        assert result is None

    def test_missing_timestamp_returns_none(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        cache_path.write_text(json.dumps({"instances": []}))

        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            result = service._load_cache()

        assert result is None

    def test_missing_instances_key_returns_none(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        cache_path.write_text(json.dumps({"timestamp": datetime.now().isoformat()}))

        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            result = service._load_cache()

        assert result is None


class TestFetchInstancesCached:

    def test_returns_cached_data_when_fresh(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        cached_instances = [{"id": "ns1"}]
        data = {
            "timestamp": datetime.now().isoformat(),
            "instances": cached_instances,
        }
        cache_path.write_text(json.dumps(data))

        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path), \
             patch.object(service, "fetch_instances") as mock_fetch:
            result = asyncio.run(service.fetch_instances_cached())

        mock_fetch.assert_not_called()
        assert result == cached_instances

    def test_fetches_from_api_when_cache_expired(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        expired_ts = datetime.now() - timedelta(seconds=_OVH_CACHE_TTL_SECONDS + 60)
        cache_path.write_text(json.dumps({
            "timestamp": expired_ts.isoformat(),
            "instances": [{"id": "old"}],
        }))
        fresh_instances = [{"id": "new"}]

        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path), \
             patch.object(service, "fetch_instances", return_value=fresh_instances) as mock_fetch, \
             patch.object(service, "_save_cache"):
            result = asyncio.run(service.fetch_instances_cached())

        mock_fetch.assert_called_once()
        assert result == fresh_instances

    def test_force_refresh_bypasses_cache(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        # Fresh cache
        cache_path.write_text(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "instances": [{"id": "cached"}],
        }))
        api_instances = [{"id": "api-fresh"}]

        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path), \
             patch.object(service, "fetch_instances", return_value=api_instances) as mock_fetch, \
             patch.object(service, "_save_cache"):
            result = asyncio.run(service.fetch_instances_cached(force_refresh=True))

        mock_fetch.assert_called_once()
        assert result == api_instances

    def test_saves_cache_after_api_fetch(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        instances = [{"id": "ns1"}]

        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path), \
             patch.object(service, "fetch_instances", return_value=instances), \
             patch.object(service, "_save_cache") as mock_save:
            asyncio.run(service.fetch_instances_cached(force_refresh=True))

        mock_save.assert_called_once_with(instances)


class TestGetCachedInstances:

    def test_returns_cached_instances_regardless_of_age(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        expired_ts = datetime.now() - timedelta(days=7)
        instances = [{"id": "old-server"}]
        cache_path.write_text(json.dumps({
            "timestamp": expired_ts.isoformat(),
            "instances": instances,
        }))

        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            result = service.get_cached_instances()

        assert result == instances

    def test_returns_empty_list_when_no_cache(self, service, tmp_path):
        cache_path = tmp_path / "no_such_file.json"

        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            result = service.get_cached_instances()

        assert result == []


class TestIsCacheFresh:

    def test_returns_false_when_no_cache(self, service, tmp_path):
        cache_path = tmp_path / "no_such_file.json"
        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            assert service.is_cache_fresh() is False

    def test_returns_true_when_fresh(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        cache_path.write_text(json.dumps({
            "timestamp": datetime.now().isoformat(),
            "instances": [],
        }))
        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            assert service.is_cache_fresh() is True

    def test_returns_false_when_expired(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        expired_ts = datetime.now() - timedelta(seconds=_OVH_CACHE_TTL_SECONDS + 1)
        cache_path.write_text(json.dumps({
            "timestamp": expired_ts.isoformat(),
            "instances": [],
        }))
        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            assert service.is_cache_fresh() is False

    def test_returns_false_on_corrupt_cache(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        cache_path.write_text("{{broken json")
        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            assert service.is_cache_fresh() is False

    def test_returns_false_when_timestamp_missing(self, service, tmp_path):
        cache_path = tmp_path / "ovh_cache.json"
        # Valid JSON but no 'timestamp' key
        cache_path.write_text(json.dumps({"instances": []}))
        with patch("servonaut.services.ovh_service._OVH_CACHE_PATH", cache_path):
            assert service.is_cache_fresh() is False


# ---------------------------------------------------------------------------
# Power management
# ---------------------------------------------------------------------------

class TestRebootInstance:

    def test_dedicated_sends_correct_endpoint(self, service_with_client, mock_client):
        asyncio.run(service_with_client.reboot_instance("ns1234", "dedicated"))
        mock_client.post.assert_called_once_with("/dedicated/server/ns1234/reboot")

    def test_vps_sends_correct_endpoint(self, service_with_client, mock_client):
        asyncio.run(service_with_client.reboot_instance("vps-aaa.ovh.net", "vps"))
        mock_client.post.assert_called_once_with("/vps/vps-aaa.ovh.net/reboot")

    def test_cloud_sends_correct_endpoint_with_soft_type(self, service_with_client, mock_client):
        asyncio.run(service_with_client.reboot_instance("proj-123/inst-abc", "cloud"))
        mock_client.post.assert_called_once_with(
            "/cloud/project/proj-123/instance/inst-abc/reboot",
            type="soft",
        )

    def test_unknown_provider_type_raises(self, service_with_client):
        with pytest.raises(ValueError, match="Unknown OVH provider_type"):
            asyncio.run(service_with_client.reboot_instance("ns1234", "baremetal"))

    def test_invalid_instance_id_raises(self, service_with_client):
        with pytest.raises(ValueError, match="Invalid instance_id format"):
            asyncio.run(service_with_client.reboot_instance("id with spaces!", "vps"))

    def test_returns_true_on_success(self, service_with_client, mock_client):
        result = asyncio.run(service_with_client.reboot_instance("ns1", "dedicated"))
        assert result is True


class TestStartInstance:

    def test_vps_sends_correct_endpoint(self, service_with_client, mock_client):
        asyncio.run(service_with_client.start_instance("vps-aaa.ovh.net", "vps"))
        mock_client.post.assert_called_once_with("/vps/vps-aaa.ovh.net/start")

    def test_cloud_sends_correct_endpoint(self, service_with_client, mock_client):
        asyncio.run(service_with_client.start_instance("proj-123/inst-abc", "cloud"))
        mock_client.post.assert_called_once_with(
            "/cloud/project/proj-123/instance/inst-abc/start"
        )

    def test_dedicated_raises(self, service_with_client):
        with pytest.raises(ValueError, match="Start is not supported"):
            asyncio.run(service_with_client.start_instance("ns1234", "dedicated"))

    def test_invalid_instance_id_raises(self, service_with_client):
        with pytest.raises(ValueError, match="Invalid instance_id format"):
            asyncio.run(service_with_client.start_instance("id;rm -rf /", "vps"))

    def test_returns_true_on_success(self, service_with_client, mock_client):
        result = asyncio.run(service_with_client.start_instance("vps-a", "vps"))
        assert result is True


class TestStopInstance:

    def test_vps_sends_correct_endpoint(self, service_with_client, mock_client):
        asyncio.run(service_with_client.stop_instance("vps-aaa.ovh.net", "vps"))
        mock_client.post.assert_called_once_with("/vps/vps-aaa.ovh.net/stop")

    def test_cloud_sends_correct_endpoint(self, service_with_client, mock_client):
        asyncio.run(service_with_client.stop_instance("proj-123/inst-abc", "cloud"))
        mock_client.post.assert_called_once_with(
            "/cloud/project/proj-123/instance/inst-abc/stop"
        )

    def test_dedicated_raises(self, service_with_client):
        with pytest.raises(ValueError, match="Stop is not supported"):
            asyncio.run(service_with_client.stop_instance("ns1234", "dedicated"))

    def test_invalid_instance_id_raises(self, service_with_client):
        with pytest.raises(ValueError, match="Invalid instance_id format"):
            asyncio.run(service_with_client.stop_instance("id\ninjected", "vps"))

    def test_returns_true_on_success(self, service_with_client, mock_client):
        result = asyncio.run(service_with_client.stop_instance("vps-a", "vps"))
        assert result is True


class TestInstanceIdValidation:
    """Instance ID character validation is shared across reboot/start/stop."""

    @pytest.mark.parametrize("valid_id", [
        "ns1234.example.com",
        "vps-aaa.ovh.net",
        "proj-123/inst-abc",
        "simple",
        "with_underscore",
        "with:colon",
    ])
    def test_valid_ids_accepted(self, service_with_client, mock_client, valid_id):
        # Should not raise
        asyncio.run(service_with_client.reboot_instance(valid_id, "dedicated"))

    @pytest.mark.parametrize("invalid_id", [
        "id with space",
        "id;rm",
        "id$(echo)",
        "id\nnewline",
        "id&background",
        "id|pipe",
    ])
    def test_invalid_ids_rejected(self, service_with_client, invalid_id):
        with pytest.raises(ValueError, match="Invalid instance_id format"):
            asyncio.run(service_with_client.reboot_instance(invalid_id, "dedicated"))


# ---------------------------------------------------------------------------
# test_connection
# ---------------------------------------------------------------------------

class TestTestConnection:

    def test_success_with_nichandle(self, service_with_client, mock_client):
        mock_client.get.return_value = {"nichandle": "ab12345-ovh", "email": "me@example.com"}
        result = asyncio.run(service_with_client.test_connection())
        assert result["success"] is True
        assert result["account"] == "ab12345-ovh"
        assert "ab12345-ovh" in result["message"]

    def test_success_falls_back_to_email(self, service_with_client, mock_client):
        mock_client.get.return_value = {"nichandle": "", "email": "fallback@example.com"}
        result = asyncio.run(service_with_client.test_connection())
        assert result["success"] is True
        assert result["account"] == "fallback@example.com"

    def test_success_falls_back_to_unknown(self, service_with_client, mock_client):
        mock_client.get.return_value = {}
        result = asyncio.run(service_with_client.test_connection())
        assert result["success"] is True
        assert result["account"] == "unknown"

    def test_failure_returns_generic_message(self, service_with_client, mock_client):
        mock_client.get.side_effect = Exception("401 Unauthorized")
        result = asyncio.run(service_with_client.test_connection())
        assert result["success"] is False
        assert result["account"] == ""
        # Generic message — must NOT expose raw exception text
        assert "401" not in result["message"]
        assert "Authentication failed" in result["message"]


# ---------------------------------------------------------------------------
# request_consumer_key
# ---------------------------------------------------------------------------

class TestRequestConsumerKey:

    def test_calls_request_consumerkey_with_correct_access_rules(self, config):
        svc = OVHService(config)
        expected_result = {
            "consumerKey": "new-key",
            "validationUrl": "https://eu.api.ovh.com/auth/",
            "state": "pendingValidation",
        }

        mock_ovh_module = MagicMock()
        mock_client_instance = MagicMock()
        mock_client_instance.request_consumerkey.return_value = expected_result
        mock_ovh_module.Client.return_value = mock_client_instance

        with patch.dict("sys.modules", {"ovh": mock_ovh_module}):
            result = asyncio.run(svc.request_consumer_key())

        assert result == expected_result
        call_args = mock_client_instance.request_consumerkey.call_args
        access_rules = call_args.args[0]
        paths = [r["path"] for r in access_rules]
        assert "/me" in paths
        assert "/vps/*" in paths
        assert "/dedicated/server/*" in paths
        assert "/cloud/project/*" in paths

    def test_raises_import_error_when_ovh_missing(self, config):
        svc = OVHService(config)
        with patch.dict("sys.modules", {"ovh": None}):
            with pytest.raises(ImportError, match="python-ovh is not installed"):
                asyncio.run(svc.request_consumer_key())
