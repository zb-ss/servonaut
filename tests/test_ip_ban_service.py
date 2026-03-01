"""Tests for IP ban service and strategies."""

from __future__ import annotations

import json
import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock
from typing import List

import pytest

from servonaut.config.schema import AppConfig, IPBanConfig
from servonaut.services.ip_ban_service import (
    IPBanService,
    WAFStrategy,
    SecurityGroupStrategy,
    NACLStrategy,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_config_manager(ip_ban_configs: List[IPBanConfig], audit_path: str = "/tmp/test_audit.json") -> MagicMock:
    cm = MagicMock()
    cfg = AppConfig(ip_ban_configs=ip_ban_configs, ip_ban_audit_path=audit_path)
    cm.get.return_value = cfg
    return cm


def waf_config() -> IPBanConfig:
    return IPBanConfig(
        name="test-waf",
        method="waf",
        region="us-east-1",
        ip_set_id="abc-123",
        ip_set_name="my-ip-set",
        waf_scope="REGIONAL",
    )


def sg_config() -> IPBanConfig:
    return IPBanConfig(
        name="test-sg",
        method="security_group",
        region="us-east-1",
        security_group_id="sg-12345",
    )


def nacl_config() -> IPBanConfig:
    return IPBanConfig(
        name="test-nacl",
        method="nacl",
        region="us-east-1",
        nacl_id="acl-67890",
        rule_number_start=100,
    )


# ---------------------------------------------------------------------------
# WAFStrategy tests
# ---------------------------------------------------------------------------

class TestWAFStrategy:
    def test_ban_ip_adds_to_address_list(self):
        strategy = WAFStrategy()
        config = waf_config()

        fake_client = MagicMock()
        fake_client.get_ip_set.return_value = {
            'IPSet': {'Addresses': []},
            'LockToken': 'token-abc',
        }

        with patch('boto3.client', return_value=fake_client):
            result = asyncio.get_event_loop().run_until_complete(
                strategy.ban_ip('1.2.3.4', config)
            )

        assert result['success'] is True
        assert '1.2.3.4' in result['message']
        fake_client.update_ip_set.assert_called_once()
        call_kwargs = fake_client.update_ip_set.call_args[1]
        assert '1.2.3.4/32' in call_kwargs['Addresses']

    def test_ban_ip_duplicate_returns_failure(self):
        strategy = WAFStrategy()
        config = waf_config()

        fake_client = MagicMock()
        fake_client.get_ip_set.return_value = {
            'IPSet': {'Addresses': ['1.2.3.4/32']},
            'LockToken': 'token-abc',
        }

        with patch('boto3.client', return_value=fake_client):
            result = asyncio.get_event_loop().run_until_complete(
                strategy.ban_ip('1.2.3.4', config)
            )

        assert result['success'] is False
        assert 'already banned' in result['message']
        fake_client.update_ip_set.assert_not_called()

    def test_unban_ip_removes_from_list(self):
        strategy = WAFStrategy()
        config = waf_config()

        fake_client = MagicMock()
        fake_client.get_ip_set.return_value = {
            'IPSet': {'Addresses': ['1.2.3.4/32', '5.6.7.8/32']},
            'LockToken': 'token-abc',
        }

        with patch('boto3.client', return_value=fake_client):
            result = asyncio.get_event_loop().run_until_complete(
                strategy.unban_ip('1.2.3.4', config)
            )

        assert result['success'] is True
        call_kwargs = fake_client.update_ip_set.call_args[1]
        assert '1.2.3.4/32' not in call_kwargs['Addresses']
        assert '5.6.7.8/32' in call_kwargs['Addresses']

    def test_unban_ip_not_found_returns_failure(self):
        strategy = WAFStrategy()
        config = waf_config()

        fake_client = MagicMock()
        fake_client.get_ip_set.return_value = {
            'IPSet': {'Addresses': []},
            'LockToken': 'token-abc',
        }

        with patch('boto3.client', return_value=fake_client):
            result = asyncio.get_event_loop().run_until_complete(
                strategy.unban_ip('1.2.3.4', config)
            )

        assert result['success'] is False
        assert 'not found' in result['message']

    def test_list_banned_returns_addresses(self):
        strategy = WAFStrategy()
        config = waf_config()

        fake_client = MagicMock()
        fake_client.get_ip_set.return_value = {
            'IPSet': {'Addresses': ['1.2.3.4/32', '5.6.7.8/32']},
            'LockToken': 'token-abc',
        }

        with patch('boto3.client', return_value=fake_client):
            result = asyncio.get_event_loop().run_until_complete(
                strategy.list_banned(config)
            )

        assert '1.2.3.4/32' in result
        assert '5.6.7.8/32' in result


# ---------------------------------------------------------------------------
# SecurityGroupStrategy tests
# ---------------------------------------------------------------------------

class TestSecurityGroupStrategy:
    def _make_sg_response(self, ips=None):
        ip_ranges = []
        for ip in (ips or []):
            ip_ranges.append({'CidrIp': ip, 'Description': 'servonaut-ban'})
        return {
            'SecurityGroups': [{
                'IpPermissions': [
                    {'IpProtocol': '-1', 'IpRanges': ip_ranges}
                ] if ip_ranges else []
            }]
        }

    def test_ban_ip_creates_ingress_rule(self):
        strategy = SecurityGroupStrategy()
        config = sg_config()

        fake_client = MagicMock()
        fake_client.describe_security_groups.return_value = self._make_sg_response()

        with patch('boto3.client', return_value=fake_client):
            result = asyncio.get_event_loop().run_until_complete(
                strategy.ban_ip('1.2.3.4', config)
            )

        assert result['success'] is True
        fake_client.authorize_security_group_ingress.assert_called_once()
        call_kwargs = fake_client.authorize_security_group_ingress.call_args[1]
        ip_perms = call_kwargs['IpPermissions']
        assert ip_perms[0]['IpRanges'][0]['CidrIp'] == '1.2.3.4/32'
        assert ip_perms[0]['IpRanges'][0]['Description'] == 'servonaut-ban'

    def test_ban_ip_duplicate_returns_failure(self):
        strategy = SecurityGroupStrategy()
        config = sg_config()

        fake_client = MagicMock()
        fake_client.describe_security_groups.return_value = self._make_sg_response(
            ips=['1.2.3.4/32']
        )

        with patch('boto3.client', return_value=fake_client):
            result = asyncio.get_event_loop().run_until_complete(
                strategy.ban_ip('1.2.3.4', config)
            )

        assert result['success'] is False
        fake_client.authorize_security_group_ingress.assert_not_called()

    def test_unban_ip_revokes_rule(self):
        strategy = SecurityGroupStrategy()
        config = sg_config()

        fake_client = MagicMock()

        with patch('boto3.client', return_value=fake_client):
            result = asyncio.get_event_loop().run_until_complete(
                strategy.unban_ip('1.2.3.4', config)
            )

        assert result['success'] is True
        fake_client.revoke_security_group_ingress.assert_called_once()

    def test_list_banned_filters_by_description(self):
        strategy = SecurityGroupStrategy()
        config = sg_config()

        fake_client = MagicMock()
        fake_client.describe_security_groups.return_value = {
            'SecurityGroups': [{
                'IpPermissions': [
                    {
                        'IpProtocol': '-1',
                        'IpRanges': [
                            {'CidrIp': '1.2.3.4/32', 'Description': 'servonaut-ban'},
                            {'CidrIp': '9.9.9.9/32', 'Description': 'other-rule'},
                        ]
                    }
                ]
            }]
        }

        with patch('boto3.client', return_value=fake_client):
            result = asyncio.get_event_loop().run_until_complete(
                strategy.list_banned(config)
            )

        assert '1.2.3.4/32' in result
        assert '9.9.9.9/32' not in result


# ---------------------------------------------------------------------------
# NACLStrategy tests
# ---------------------------------------------------------------------------

class TestNACLStrategy:
    def _make_nacl_response(self, entries=None):
        return {
            'NetworkAcls': [{
                'Entries': entries or []
            }]
        }

    def test_ban_ip_creates_deny_entry(self):
        strategy = NACLStrategy()
        config = nacl_config()

        fake_client = MagicMock()
        fake_client.describe_network_acls.return_value = self._make_nacl_response()

        with patch('boto3.client', return_value=fake_client):
            result = asyncio.get_event_loop().run_until_complete(
                strategy.ban_ip('1.2.3.4', config)
            )

        assert result['success'] is True
        fake_client.create_network_acl_entry.assert_called_once()
        call_kwargs = fake_client.create_network_acl_entry.call_args[1]
        assert call_kwargs['CidrBlock'] == '1.2.3.4/32'
        assert call_kwargs['RuleAction'] == 'deny'
        assert call_kwargs['Egress'] is False

    def test_ban_ip_duplicate_returns_failure(self):
        strategy = NACLStrategy()
        config = nacl_config()

        fake_client = MagicMock()
        fake_client.describe_network_acls.return_value = self._make_nacl_response(entries=[
            {'RuleNumber': 100, 'CidrBlock': '1.2.3.4/32', 'RuleAction': 'deny', 'Egress': False}
        ])

        with patch('boto3.client', return_value=fake_client):
            result = asyncio.get_event_loop().run_until_complete(
                strategy.ban_ip('1.2.3.4', config)
            )

        assert result['success'] is False
        fake_client.create_network_acl_entry.assert_not_called()

    def test_unban_ip_deletes_entry(self):
        strategy = NACLStrategy()
        config = nacl_config()

        fake_client = MagicMock()
        fake_client.describe_network_acls.return_value = self._make_nacl_response(entries=[
            {'RuleNumber': 100, 'CidrBlock': '1.2.3.4/32', 'RuleAction': 'deny', 'Egress': False}
        ])

        with patch('boto3.client', return_value=fake_client):
            result = asyncio.get_event_loop().run_until_complete(
                strategy.unban_ip('1.2.3.4', config)
            )

        assert result['success'] is True
        fake_client.delete_network_acl_entry.assert_called_once_with(
            NetworkAclId='acl-67890',
            RuleNumber=100,
            Egress=False,
        )

    def test_unban_ip_not_found_returns_failure(self):
        strategy = NACLStrategy()
        config = nacl_config()

        fake_client = MagicMock()
        fake_client.describe_network_acls.return_value = self._make_nacl_response()

        with patch('boto3.client', return_value=fake_client):
            result = asyncio.get_event_loop().run_until_complete(
                strategy.unban_ip('1.2.3.4', config)
            )

        assert result['success'] is False

    def test_list_banned_filters_deny_rules(self):
        strategy = NACLStrategy()
        config = nacl_config()

        fake_client = MagicMock()
        fake_client.describe_network_acls.return_value = self._make_nacl_response(entries=[
            {'RuleNumber': 100, 'CidrBlock': '1.2.3.4/32', 'RuleAction': 'deny', 'Egress': False},
            {'RuleNumber': 200, 'CidrBlock': '5.6.7.8/32', 'RuleAction': 'allow', 'Egress': False},
            {'RuleNumber': 101, 'CidrBlock': '9.9.9.9/32', 'RuleAction': 'deny', 'Egress': True},
        ])

        with patch('boto3.client', return_value=fake_client):
            result = asyncio.get_event_loop().run_until_complete(
                strategy.list_banned(config)
            )

        assert '1.2.3.4/32' in result
        assert '5.6.7.8/32' not in result  # allow rule
        assert '9.9.9.9/32' not in result  # egress rule


# ---------------------------------------------------------------------------
# IPBanService tests
# ---------------------------------------------------------------------------

class TestIPBanService:
    def test_validate_ip_valid_ipv4(self):
        cm = make_config_manager([])
        service = IPBanService(cm)
        assert service.validate_ip('1.2.3.4') is True

    def test_validate_ip_valid_ipv6(self):
        cm = make_config_manager([])
        service = IPBanService(cm)
        assert service.validate_ip('2001:db8::1') is True

    def test_validate_ip_invalid(self):
        cm = make_config_manager([])
        service = IPBanService(cm)
        assert service.validate_ip('not-an-ip') is False
        assert service.validate_ip('999.999.999.999') is False
        assert service.validate_ip('') is False

    def test_get_configs_returns_from_config(self):
        configs = [waf_config(), sg_config()]
        cm = make_config_manager(configs)
        service = IPBanService(cm)
        result = service.get_configs()
        assert len(result) == 2
        assert result[0].name == 'test-waf'
        assert result[1].name == 'test-sg'

    def test_unknown_config_raises_value_error(self):
        cm = make_config_manager([])
        service = IPBanService(cm)
        result = asyncio.get_event_loop().run_until_complete(
            service.ban_ip('1.2.3.4', 'nonexistent')
        )
        # ValueError from _get_config is caught and returned as failure
        assert result['success'] is False

    def test_invalid_ip_returns_failure(self):
        cm = make_config_manager([waf_config()])
        service = IPBanService(cm)
        result = asyncio.get_event_loop().run_until_complete(
            service.ban_ip('bad-ip', 'test-waf')
        )
        assert result['success'] is False
        assert 'Invalid IP' in result['message']

    def test_audit_log_writes_entry(self, tmp_path):
        audit_file = str(tmp_path / "audit.json")
        cm = make_config_manager([waf_config()], audit_path=audit_file)
        service = IPBanService(cm)

        fake_client = MagicMock()
        fake_client.get_ip_set.return_value = {
            'IPSet': {'Addresses': []},
            'LockToken': 'tok',
        }

        with patch('boto3.client', return_value=fake_client):
            asyncio.get_event_loop().run_until_complete(
                service.ban_ip('1.2.3.4', 'test-waf')
            )

        entries = json.loads(Path(audit_file).read_text())
        assert len(entries) == 1
        assert entries[0]['action'] == 'ban'
        assert entries[0]['ip_address'] == '1.2.3.4'
        assert entries[0]['config'] == 'test-waf'
        assert entries[0]['success'] is True
        assert 'timestamp' in entries[0]

    def test_audit_log_appends_multiple_entries(self, tmp_path):
        audit_file = str(tmp_path / "audit.json")
        cm = make_config_manager([waf_config()], audit_path=audit_file)
        service = IPBanService(cm)

        fake_client = MagicMock()
        fake_client.get_ip_set.side_effect = [
            {'IPSet': {'Addresses': []}, 'LockToken': 'tok1'},
            {'IPSet': {'Addresses': ['1.2.3.4/32']}, 'LockToken': 'tok2'},
        ]

        with patch('boto3.client', return_value=fake_client):
            asyncio.get_event_loop().run_until_complete(service.ban_ip('1.2.3.4', 'test-waf'))
            asyncio.get_event_loop().run_until_complete(service.unban_ip('1.2.3.4', 'test-waf'))

        entries = json.loads(Path(audit_file).read_text())
        assert len(entries) == 2
        assert entries[0]['action'] == 'ban'
        assert entries[1]['action'] == 'unban'
