"""Tests for OVHIPService."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, call

import pytest

from servonaut.config.schema import OVHConfig
from servonaut.services.ovh_service import OVHService
from servonaut.services.ovh_ip_service import OVHIPService


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
def ip_service(ovh_service):
    return OVHIPService(ovh_service)


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:

    def test_stores_ovh_service_reference(self, ovh_service):
        svc = OVHIPService(ovh_service)
        assert svc._ovh_service is ovh_service


# ---------------------------------------------------------------------------
# list_ips
# ---------------------------------------------------------------------------

class TestListIps:

    def test_returns_list_of_dicts(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = [
            ["1.2.3.4/32", "5.6.7.8/32"],
            {"ip": "1.2.3.4/32", "type": "dedicated"},
            {"ip": "5.6.7.8/32", "type": "failover"},
        ]

        result = asyncio.run(ip_service.list_ips())

        assert len(result) == 2
        assert result[0]["type"] == "dedicated"
        assert result[1]["type"] == "failover"

    def test_returns_empty_list_when_no_ips(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(ip_service.list_ips())

        assert result == []

    def test_returns_empty_list_on_api_error(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("403 Forbidden")

        result = asyncio.run(ip_service.list_ips())

        assert result == []

    def test_first_call_gets_ip_list(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        asyncio.run(ip_service.list_ips())

        mock_ovh_client.get.assert_any_call("/ip")

    def test_detail_call_for_each_block(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = [
            ["1.2.3.4/32"],
            {"ip": "1.2.3.4/32", "type": "dedicated"},
        ]

        asyncio.run(ip_service.list_ips())

        mock_ovh_client.get.assert_any_call("/ip/1.2.3.4%2F32")

    def test_wraps_non_dict_detail_in_dict(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = [
            ["1.2.3.4/32"],
            "some-raw-value",
        ]

        result = asyncio.run(ip_service.list_ips())

        assert len(result) == 1
        assert result[0]["ip"] == "1.2.3.4/32"
        assert result[0]["raw"] == "some-raw-value"

    def test_skips_blocks_with_detail_error(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = [
            ["1.2.3.4/32", "5.6.7.8/32"],
            Exception("404"),
            {"ip": "5.6.7.8/32", "type": "failover"},
        ]

        result = asyncio.run(ip_service.list_ips())

        # First block errored, second succeeded
        assert len(result) == 1
        assert result[0]["ip"] == "5.6.7.8/32"


# ---------------------------------------------------------------------------
# list_failover_ips
# ---------------------------------------------------------------------------

class TestListFailoverIps:

    def test_returns_only_failover_ips(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = [
            ["1.2.3.4/32", "5.6.7.8/32"],
            {"ip": "1.2.3.4/32", "type": "dedicated"},
            {"ip": "5.6.7.8/32", "type": "failover"},
        ]

        result = asyncio.run(ip_service.list_failover_ips())

        assert len(result) == 1
        assert result[0]["type"] == "failover"
        assert result[0]["ip"] == "5.6.7.8/32"

    def test_returns_empty_list_when_no_failover(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = [
            ["1.2.3.4/32"],
            {"ip": "1.2.3.4/32", "type": "dedicated"},
        ]

        result = asyncio.run(ip_service.list_failover_ips())

        assert result == []

    def test_returns_empty_list_on_api_error(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("500 Server Error")

        result = asyncio.run(ip_service.list_failover_ips())

        assert result == []


# ---------------------------------------------------------------------------
# move_failover_ip
# ---------------------------------------------------------------------------

class TestMoveFailoverIp:

    def test_calls_post_with_correct_path_and_target(self, ip_service, mock_ovh_client):
        mock_ovh_client.post.return_value = None

        result = asyncio.run(
            ip_service.move_failover_ip("1.2.3.4/32", "vps-abc123.ovh.net")
        )

        mock_ovh_client.post.assert_called_once_with(
            "/ip/1.2.3.4/32/move", to="vps-abc123.ovh.net"
        )
        assert result is True

    def test_returns_true_on_success(self, ip_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {}

        result = asyncio.run(
            ip_service.move_failover_ip("1.2.3.4/32", "vps-abc123.ovh.net")
        )

        assert result is True

    def test_propagates_api_exception(self, ip_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("409 Conflict")

        with pytest.raises(Exception, match="409 Conflict"):
            asyncio.run(ip_service.move_failover_ip("1.2.3.4/32", "vps-abc.ovh.net"))

    def test_raises_value_error_on_invalid_ip(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip"):
            asyncio.run(ip_service.move_failover_ip("bad ip!", "vps-abc.ovh.net"))

    def test_raises_value_error_on_empty_ip(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip"):
            asyncio.run(ip_service.move_failover_ip("", "vps-abc.ovh.net"))

    def test_raises_value_error_on_invalid_target(self, ip_service):
        with pytest.raises(ValueError, match="Invalid target_service"):
            asyncio.run(ip_service.move_failover_ip("1.2.3.4/32", "bad service!"))

    def test_raises_value_error_on_empty_target(self, ip_service):
        with pytest.raises(ValueError, match="Invalid target_service"):
            asyncio.run(ip_service.move_failover_ip("1.2.3.4/32", ""))


# ---------------------------------------------------------------------------
# get_ip_details
# ---------------------------------------------------------------------------

class TestGetIpDetails:

    def test_returns_dict(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {
            "ip": "1.2.3.4/32",
            "type": "dedicated",
            "routedTo": {"serviceName": "ns123456.ovh.net"},
        }

        result = asyncio.run(ip_service.get_ip_details("1.2.3.4/32"))

        assert result["ip"] == "1.2.3.4/32"
        assert result["type"] == "dedicated"

    def test_calls_correct_api_endpoint(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {}

        asyncio.run(ip_service.get_ip_details("5.6.7.8/32"))

        mock_ovh_client.get.assert_called_once_with("/ip/5.6.7.8%2F32")

    def test_returns_empty_dict_on_api_error(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("404 Not Found")

        result = asyncio.run(ip_service.get_ip_details("1.2.3.4/32"))

        assert result == {}

    def test_returns_empty_dict_when_api_returns_non_dict(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.return_value = None

        result = asyncio.run(ip_service.get_ip_details("1.2.3.4/32"))

        assert result == {}

    def test_raises_value_error_on_invalid_ip(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip"):
            asyncio.run(ip_service.get_ip_details("not an ip!"))

    def test_raises_value_error_on_empty_ip(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip"):
            asyncio.run(ip_service.get_ip_details(""))


# ---------------------------------------------------------------------------
# get_reverse_dns
# ---------------------------------------------------------------------------

class TestGetReverseDns:

    def test_returns_rdns_dict(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {
            "ipReverse": "1.2.3.4",
            "reverse": "server.example.com",
        }

        result = asyncio.run(ip_service.get_reverse_dns("1.2.3.0/24", "1.2.3.4"))

        assert result["reverse"] == "server.example.com"

    def test_calls_correct_api_endpoint(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {}

        asyncio.run(ip_service.get_reverse_dns("1.2.3.0/24", "1.2.3.4"))

        mock_ovh_client.get.assert_called_once_with("/ip/1.2.3.0%2F24/reverse/1.2.3.4")

    def test_returns_empty_dict_on_api_error(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("404 Not Found")

        result = asyncio.run(ip_service.get_reverse_dns("1.2.3.0/24", "1.2.3.4"))

        assert result == {}

    def test_returns_empty_dict_when_api_returns_non_dict(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.return_value = None

        result = asyncio.run(ip_service.get_reverse_dns("1.2.3.0/24", "1.2.3.4"))

        assert result == {}

    def test_raises_value_error_on_invalid_ip_block(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip_block"):
            asyncio.run(ip_service.get_reverse_dns("bad block!", "1.2.3.4"))

    def test_raises_value_error_on_invalid_ip(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip"):
            asyncio.run(ip_service.get_reverse_dns("1.2.3.0/24", "bad ip!"))


# ---------------------------------------------------------------------------
# set_reverse_dns
# ---------------------------------------------------------------------------

class TestSetReverseDns:

    def test_calls_post_with_correct_path_and_body(self, ip_service, mock_ovh_client):
        mock_ovh_client.post.return_value = None

        result = asyncio.run(
            ip_service.set_reverse_dns("1.2.3.0/24", "1.2.3.4", "server.example.com")
        )

        mock_ovh_client.post.assert_called_once_with(
            "/ip/1.2.3.0%2F24/reverse",
            ipReverse="1.2.3.4",
            reverse="server.example.com",
        )
        assert result is True

    def test_returns_true_on_success(self, ip_service, mock_ovh_client):
        mock_ovh_client.post.return_value = {}

        result = asyncio.run(
            ip_service.set_reverse_dns("1.2.3.0/24", "1.2.3.4", "server.example.com")
        )

        assert result is True

    def test_propagates_api_exception(self, ip_service, mock_ovh_client):
        mock_ovh_client.post.side_effect = Exception("400 Bad Request")

        with pytest.raises(Exception, match="400 Bad Request"):
            asyncio.run(
                ip_service.set_reverse_dns("1.2.3.0/24", "1.2.3.4", "server.example.com")
            )

    def test_raises_value_error_on_invalid_ip_block(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip_block"):
            asyncio.run(ip_service.set_reverse_dns("bad!", "1.2.3.4", "server.example.com"))

    def test_raises_value_error_on_invalid_ip(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip"):
            asyncio.run(ip_service.set_reverse_dns("1.2.3.0/24", "bad ip!", "server.example.com"))

    def test_raises_value_error_on_invalid_reverse(self, ip_service):
        with pytest.raises(ValueError, match="Invalid reverse DNS hostname"):
            asyncio.run(
                ip_service.set_reverse_dns("1.2.3.0/24", "1.2.3.4", "not a valid hostname!")
            )

    def test_raises_value_error_on_empty_reverse(self, ip_service):
        with pytest.raises(ValueError, match="Invalid reverse DNS hostname"):
            asyncio.run(ip_service.set_reverse_dns("1.2.3.0/24", "1.2.3.4", ""))


# ---------------------------------------------------------------------------
# delete_reverse_dns
# ---------------------------------------------------------------------------

class TestDeleteReverseDns:

    def test_calls_delete_with_correct_path(self, ip_service, mock_ovh_client):
        mock_ovh_client.delete.return_value = None

        result = asyncio.run(ip_service.delete_reverse_dns("1.2.3.0/24", "1.2.3.4"))

        mock_ovh_client.delete.assert_called_once_with(
            "/ip/1.2.3.0%2F24/reverse/1.2.3.4"
        )
        assert result is True

    def test_returns_true_on_success(self, ip_service, mock_ovh_client):
        mock_ovh_client.delete.return_value = {}

        result = asyncio.run(ip_service.delete_reverse_dns("1.2.3.0/24", "1.2.3.4"))

        assert result is True

    def test_propagates_api_exception(self, ip_service, mock_ovh_client):
        mock_ovh_client.delete.side_effect = Exception("404 Not Found")

        with pytest.raises(Exception, match="404 Not Found"):
            asyncio.run(ip_service.delete_reverse_dns("1.2.3.0/24", "1.2.3.4"))

    def test_raises_value_error_on_invalid_ip_block(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip_block"):
            asyncio.run(ip_service.delete_reverse_dns("bad block!", "1.2.3.4"))

    def test_raises_value_error_on_invalid_ip(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip"):
            asyncio.run(ip_service.delete_reverse_dns("1.2.3.0/24", "not an ip!"))


# ---------------------------------------------------------------------------
# get_firewall
# ---------------------------------------------------------------------------

class TestGetFirewall:

    def test_returns_firewall_state_dict(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {
            "enabled": True,
            "ipOnFirewall": "1.2.3.4",
            "state": "ok",
        }

        result = asyncio.run(ip_service.get_firewall("1.2.3.4"))

        assert result["enabled"] is True
        assert result["state"] == "ok"

    def test_calls_correct_api_endpoint(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.return_value = {}

        asyncio.run(ip_service.get_firewall("1.2.3.4"))

        mock_ovh_client.get.assert_called_once_with("/ip/1.2.3.4/firewall/1.2.3.4")

    def test_returns_empty_dict_on_api_error(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("404 Not Found")

        result = asyncio.run(ip_service.get_firewall("1.2.3.4"))

        assert result == {}

    def test_returns_empty_dict_when_api_returns_non_dict(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.return_value = None

        result = asyncio.run(ip_service.get_firewall("1.2.3.4"))

        assert result == {}

    def test_raises_value_error_on_invalid_ip(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip"):
            asyncio.run(ip_service.get_firewall("not valid!"))

    def test_raises_value_error_on_empty_ip(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip"):
            asyncio.run(ip_service.get_firewall(""))


# ---------------------------------------------------------------------------
# toggle_firewall
# ---------------------------------------------------------------------------

class TestToggleFirewall:

    def test_calls_put_with_enabled_true(self, ip_service, mock_ovh_client):
        mock_ovh_client.put.return_value = None

        result = asyncio.run(ip_service.toggle_firewall("1.2.3.4", True))

        mock_ovh_client.put.assert_called_once_with(
            "/ip/1.2.3.4/firewall/1.2.3.4", enabled=True
        )
        assert result is True

    def test_calls_put_with_enabled_false(self, ip_service, mock_ovh_client):
        mock_ovh_client.put.return_value = None

        result = asyncio.run(ip_service.toggle_firewall("1.2.3.4", False))

        mock_ovh_client.put.assert_called_once_with(
            "/ip/1.2.3.4/firewall/1.2.3.4", enabled=False
        )
        assert result is True

    def test_propagates_api_exception(self, ip_service, mock_ovh_client):
        mock_ovh_client.put.side_effect = Exception("403 Forbidden")

        with pytest.raises(Exception, match="403 Forbidden"):
            asyncio.run(ip_service.toggle_firewall("1.2.3.4", True))

    def test_raises_value_error_on_invalid_ip(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip"):
            asyncio.run(ip_service.toggle_firewall("not an ip!", True))


# ---------------------------------------------------------------------------
# list_firewall_rules
# ---------------------------------------------------------------------------

class TestListFirewallRules:

    def test_returns_list_of_rule_dicts(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = [
            [0, 1],
            {"sequence": 0, "action": "permit", "protocol": "tcp"},
            {"sequence": 1, "action": "deny", "protocol": "udp"},
        ]

        result = asyncio.run(ip_service.list_firewall_rules("1.2.3.4"))

        assert len(result) == 2
        assert result[0]["action"] == "permit"
        assert result[1]["action"] == "deny"

    def test_calls_correct_sequence_list_endpoint(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        asyncio.run(ip_service.list_firewall_rules("1.2.3.4"))

        mock_ovh_client.get.assert_any_call("/ip/1.2.3.4/firewall/1.2.3.4/rule")

    def test_calls_individual_rule_endpoints(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = [
            [5],
            {"sequence": 5, "action": "permit", "protocol": "tcp"},
        ]

        asyncio.run(ip_service.list_firewall_rules("1.2.3.4"))

        mock_ovh_client.get.assert_any_call("/ip/1.2.3.4/firewall/1.2.3.4/rule/5")

    def test_returns_empty_list_when_no_rules(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.return_value = []

        result = asyncio.run(ip_service.list_firewall_rules("1.2.3.4"))

        assert result == []

    def test_returns_empty_list_on_api_error(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = Exception("500 Server Error")

        result = asyncio.run(ip_service.list_firewall_rules("1.2.3.4"))

        assert result == []

    def test_skips_rules_that_return_non_dict(self, ip_service, mock_ovh_client):
        mock_ovh_client.get.side_effect = [
            [0, 1],
            "not-a-dict",
            {"sequence": 1, "action": "deny", "protocol": "tcp"},
        ]

        result = asyncio.run(ip_service.list_firewall_rules("1.2.3.4"))

        assert len(result) == 1
        assert result[0]["sequence"] == 1

    def test_raises_value_error_on_invalid_ip(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip"):
            asyncio.run(ip_service.list_firewall_rules("not valid!"))


# ---------------------------------------------------------------------------
# add_firewall_rule
# ---------------------------------------------------------------------------

class TestAddFirewallRule:

    def test_calls_post_with_rule_kwargs(self, ip_service, mock_ovh_client):
        rule = {"action": "permit", "protocol": "tcp", "sequence": 0, "destinationPort": "80"}
        mock_ovh_client.post.return_value = {"sequence": 0, "action": "permit"}

        result = asyncio.run(ip_service.add_firewall_rule("1.2.3.4", rule))

        mock_ovh_client.post.assert_called_once_with(
            "/ip/1.2.3.4/firewall/1.2.3.4/rule",
            **rule,
        )
        assert result["action"] == "permit"

    def test_returns_empty_dict_when_api_returns_none(self, ip_service, mock_ovh_client):
        rule = {"action": "deny", "protocol": "udp", "sequence": 1}
        mock_ovh_client.post.return_value = None

        result = asyncio.run(ip_service.add_firewall_rule("1.2.3.4", rule))

        assert result == {}

    def test_propagates_api_exception(self, ip_service, mock_ovh_client):
        rule = {"action": "permit", "protocol": "tcp", "sequence": 0}
        mock_ovh_client.post.side_effect = Exception("422 Unprocessable Entity")

        with pytest.raises(Exception, match="422 Unprocessable Entity"):
            asyncio.run(ip_service.add_firewall_rule("1.2.3.4", rule))

    def test_raises_value_error_on_invalid_ip(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip"):
            asyncio.run(
                ip_service.add_firewall_rule("bad ip!", {"action": "permit", "protocol": "tcp", "sequence": 0})
            )

    def test_raises_value_error_when_rule_not_dict(self, ip_service):
        with pytest.raises(ValueError, match="rule must be a dict"):
            asyncio.run(ip_service.add_firewall_rule("1.2.3.4", "not-a-dict"))

    def test_raises_value_error_on_missing_required_keys(self, ip_service):
        with pytest.raises(ValueError, match="missing required keys"):
            asyncio.run(ip_service.add_firewall_rule("1.2.3.4", {"action": "permit"}))

    def test_raises_value_error_when_protocol_missing(self, ip_service):
        with pytest.raises(ValueError, match="missing required keys"):
            asyncio.run(
                ip_service.add_firewall_rule("1.2.3.4", {"action": "permit", "sequence": 0})
            )


# ---------------------------------------------------------------------------
# delete_firewall_rule
# ---------------------------------------------------------------------------

class TestDeleteFirewallRule:

    def test_calls_delete_with_correct_path(self, ip_service, mock_ovh_client):
        mock_ovh_client.delete.return_value = None

        result = asyncio.run(ip_service.delete_firewall_rule("1.2.3.4", 5))

        mock_ovh_client.delete.assert_called_once_with(
            "/ip/1.2.3.4/firewall/1.2.3.4/rule/5"
        )
        assert result is True

    def test_returns_true_on_success(self, ip_service, mock_ovh_client):
        mock_ovh_client.delete.return_value = {}

        result = asyncio.run(ip_service.delete_firewall_rule("1.2.3.4", 0))

        assert result is True

    def test_propagates_api_exception(self, ip_service, mock_ovh_client):
        mock_ovh_client.delete.side_effect = Exception("404 Not Found")

        with pytest.raises(Exception, match="404 Not Found"):
            asyncio.run(ip_service.delete_firewall_rule("1.2.3.4", 3))

    def test_raises_value_error_on_invalid_ip(self, ip_service):
        with pytest.raises(ValueError, match="Invalid ip"):
            asyncio.run(ip_service.delete_firewall_rule("not valid!", 0))

    def test_raises_value_error_on_negative_sequence(self, ip_service):
        with pytest.raises(ValueError, match="Invalid sequence number"):
            asyncio.run(ip_service.delete_firewall_rule("1.2.3.4", -1))

    def test_raises_value_error_on_non_int_sequence(self, ip_service):
        with pytest.raises(ValueError, match="Invalid sequence number"):
            asyncio.run(ip_service.delete_firewall_rule("1.2.3.4", "five"))
