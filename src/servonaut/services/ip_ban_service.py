"""IP Ban service with WAF, Security Group, and NACL strategies."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, TYPE_CHECKING

from servonaut.services.interfaces import IPBanStrategyInterface, IPBanServiceInterface

if TYPE_CHECKING:
    from servonaut.config.schema import IPBanConfig
    from servonaut.config.manager import ConfigManager

logger = logging.getLogger(__name__)


class WAFStrategy(IPBanStrategyInterface):
    """Ban IPs via AWS WAFv2 IP sets."""

    async def ban_ip(self, ip_address: str, config: 'IPBanConfig') -> dict:
        loop = asyncio.get_event_loop()

        def _ban() -> dict:
            import boto3
            client = boto3.client('wafv2', region_name=config.region or 'us-east-1')
            response = client.get_ip_set(
                Name=config.ip_set_name,
                Scope=config.waf_scope,
                Id=config.ip_set_id,
            )
            addresses = list(response['IPSet']['Addresses'])
            cidr = f"{ip_address}/32"
            if cidr in addresses:
                return {'success': False, 'message': f'{ip_address} already banned in WAF'}
            addresses.append(cidr)
            client.update_ip_set(
                Name=config.ip_set_name,
                Scope=config.waf_scope,
                Id=config.ip_set_id,
                Addresses=addresses,
                LockToken=response['LockToken'],
            )
            return {'success': True, 'message': f'Banned {ip_address} via WAF IP set'}

        return await loop.run_in_executor(None, _ban)

    async def unban_ip(self, ip_address: str, config: 'IPBanConfig') -> dict:
        loop = asyncio.get_event_loop()

        def _unban() -> dict:
            import boto3
            client = boto3.client('wafv2', region_name=config.region or 'us-east-1')
            response = client.get_ip_set(
                Name=config.ip_set_name,
                Scope=config.waf_scope,
                Id=config.ip_set_id,
            )
            addresses = list(response['IPSet']['Addresses'])
            cidr = f"{ip_address}/32"
            if cidr not in addresses:
                return {'success': False, 'message': f'{ip_address} not found in WAF ban list'}
            addresses.remove(cidr)
            client.update_ip_set(
                Name=config.ip_set_name,
                Scope=config.waf_scope,
                Id=config.ip_set_id,
                Addresses=addresses,
                LockToken=response['LockToken'],
            )
            return {'success': True, 'message': f'Unbanned {ip_address} from WAF IP set'}

        return await loop.run_in_executor(None, _unban)

    async def list_banned(self, config: 'IPBanConfig') -> List[str]:
        loop = asyncio.get_event_loop()

        def _list() -> List[str]:
            import boto3
            client = boto3.client('wafv2', region_name=config.region or 'us-east-1')
            response = client.get_ip_set(
                Name=config.ip_set_name,
                Scope=config.waf_scope,
                Id=config.ip_set_id,
            )
            return list(response['IPSet']['Addresses'])

        return await loop.run_in_executor(None, _list)


class SecurityGroupStrategy(IPBanStrategyInterface):
    """Ban IPs via Security Group ingress deny rules."""

    _BAN_DESCRIPTION = "servonaut-ban"

    async def ban_ip(self, ip_address: str, config: 'IPBanConfig') -> dict:
        loop = asyncio.get_event_loop()

        def _ban() -> dict:
            import boto3
            ec2 = boto3.client('ec2', region_name=config.region or 'us-east-1')
            # Check if already banned
            sg_response = ec2.describe_security_groups(
                GroupIds=[config.security_group_id]
            )
            existing = sg_response['SecurityGroups'][0].get('IpPermissions', [])
            for perm in existing:
                for ip_range in perm.get('IpRanges', []):
                    if (ip_range.get('CidrIp') == f"{ip_address}/32"
                            and ip_range.get('Description') == SecurityGroupStrategy._BAN_DESCRIPTION):
                        return {'success': False, 'message': f'{ip_address} already banned in security group'}
            ec2.authorize_security_group_ingress(
                GroupId=config.security_group_id,
                IpPermissions=[{
                    'IpProtocol': '-1',
                    'IpRanges': [{
                        'CidrIp': f"{ip_address}/32",
                        'Description': SecurityGroupStrategy._BAN_DESCRIPTION,
                    }],
                }],
            )
            return {'success': True, 'message': f'Banned {ip_address} via security group'}

        return await loop.run_in_executor(None, _ban)

    async def unban_ip(self, ip_address: str, config: 'IPBanConfig') -> dict:
        loop = asyncio.get_event_loop()

        def _unban() -> dict:
            import boto3
            ec2 = boto3.client('ec2', region_name=config.region or 'us-east-1')
            try:
                ec2.revoke_security_group_ingress(
                    GroupId=config.security_group_id,
                    IpPermissions=[{
                        'IpProtocol': '-1',
                        'IpRanges': [{
                            'CidrIp': f"{ip_address}/32",
                            'Description': SecurityGroupStrategy._BAN_DESCRIPTION,
                        }],
                    }],
                )
                return {'success': True, 'message': f'Unbanned {ip_address} from security group'}
            except Exception as e:
                return {'success': False, 'message': f'Failed to unban {ip_address}: {e}'}

        return await loop.run_in_executor(None, _unban)

    async def list_banned(self, config: 'IPBanConfig') -> List[str]:
        loop = asyncio.get_event_loop()

        def _list() -> List[str]:
            import boto3
            ec2 = boto3.client('ec2', region_name=config.region or 'us-east-1')
            response = ec2.describe_security_groups(GroupIds=[config.security_group_id])
            banned = []
            for perm in response['SecurityGroups'][0].get('IpPermissions', []):
                for ip_range in perm.get('IpRanges', []):
                    if ip_range.get('Description') == SecurityGroupStrategy._BAN_DESCRIPTION:
                        cidr = ip_range.get('CidrIp', '')
                        if cidr:
                            banned.append(cidr)
            return banned

        return await loop.run_in_executor(None, _list)


class NACLStrategy(IPBanStrategyInterface):
    """Ban IPs via Network ACL DENY rules."""

    async def ban_ip(self, ip_address: str, config: 'IPBanConfig') -> dict:
        loop = asyncio.get_event_loop()

        def _ban() -> dict:
            import boto3
            ec2 = boto3.client('ec2', region_name=config.region or 'us-east-1')
            # Find next available rule number
            response = ec2.describe_network_acls(NetworkAclIds=[config.nacl_id])
            entries = response['NetworkAcls'][0].get('Entries', [])
            used_numbers = {
                e['RuleNumber'] for e in entries
                if e.get('RuleAction') == 'deny' and not e.get('Egress', False)
            }
            rule_number = config.rule_number_start
            while rule_number in used_numbers:
                rule_number += 1
            # Check if IP already banned
            cidr = f"{ip_address}/32"
            for entry in entries:
                if (entry.get('CidrBlock') == cidr
                        and entry.get('RuleAction') == 'deny'
                        and not entry.get('Egress', False)):
                    return {'success': False, 'message': f'{ip_address} already banned in NACL'}
            ec2.create_network_acl_entry(
                NetworkAclId=config.nacl_id,
                RuleNumber=rule_number,
                Protocol='-1',
                RuleAction='deny',
                Egress=False,
                CidrBlock=cidr,
            )
            return {'success': True, 'message': f'Banned {ip_address} via NACL rule {rule_number}'}

        return await loop.run_in_executor(None, _ban)

    async def unban_ip(self, ip_address: str, config: 'IPBanConfig') -> dict:
        loop = asyncio.get_event_loop()

        def _unban() -> dict:
            import boto3
            ec2 = boto3.client('ec2', region_name=config.region or 'us-east-1')
            response = ec2.describe_network_acls(NetworkAclIds=[config.nacl_id])
            entries = response['NetworkAcls'][0].get('Entries', [])
            cidr = f"{ip_address}/32"
            rule_number = None
            for entry in entries:
                if (entry.get('CidrBlock') == cidr
                        and entry.get('RuleAction') == 'deny'
                        and not entry.get('Egress', False)):
                    rule_number = entry['RuleNumber']
                    break
            if rule_number is None:
                return {'success': False, 'message': f'{ip_address} not found in NACL ban list'}
            ec2.delete_network_acl_entry(
                NetworkAclId=config.nacl_id,
                RuleNumber=rule_number,
                Egress=False,
            )
            return {'success': True, 'message': f'Unbanned {ip_address} from NACL'}

        return await loop.run_in_executor(None, _unban)

    async def list_banned(self, config: 'IPBanConfig') -> List[str]:
        loop = asyncio.get_event_loop()

        def _list() -> List[str]:
            import boto3
            ec2 = boto3.client('ec2', region_name=config.region or 'us-east-1')
            response = ec2.describe_network_acls(NetworkAclIds=[config.nacl_id])
            banned = []
            for entry in response['NetworkAcls'][0].get('Entries', []):
                if entry.get('RuleAction') == 'deny' and not entry.get('Egress', False):
                    cidr = entry.get('CidrBlock', '')
                    if cidr:
                        banned.append(cidr)
            return banned

        return await loop.run_in_executor(None, _list)


class IPBanService(IPBanServiceInterface):
    """Orchestrates IP banning across WAF, Security Groups, and NACLs."""

    STRATEGIES = {
        'waf': WAFStrategy,
        'security_group': SecurityGroupStrategy,
        'nacl': NACLStrategy,
    }

    def __init__(self, config_manager: 'ConfigManager') -> None:
        self._config_manager = config_manager
        self._strategies = {k: v() for k, v in self.STRATEGIES.items()}

    def _get_config(self, config_name: str) -> 'IPBanConfig':
        configs = self._config_manager.get().ip_ban_configs
        for c in configs:
            if c.name == config_name:
                return c
        raise ValueError(f"Unknown IP ban config: {config_name}")

    async def ban_ip(self, ip_address: str, config_name: str) -> dict:
        if not self.validate_ip(ip_address):
            return {'success': False, 'message': f'Invalid IP address: {ip_address}'}
        try:
            config = self._get_config(config_name)
            strategy = self._strategies[config.method]
            result = await strategy.ban_ip(ip_address, config)
        except Exception as e:
            logger.error("ban_ip failed for %s via %s: %s", ip_address, config_name, e)
            result = {'success': False, 'message': str(e)}
        self._audit_log('ban', ip_address, config_name, result)
        return result

    async def unban_ip(self, ip_address: str, config_name: str) -> dict:
        if not self.validate_ip(ip_address):
            return {'success': False, 'message': f'Invalid IP address: {ip_address}'}
        try:
            config = self._get_config(config_name)
            strategy = self._strategies[config.method]
            result = await strategy.unban_ip(ip_address, config)
        except Exception as e:
            logger.error("unban_ip failed for %s via %s: %s", ip_address, config_name, e)
            result = {'success': False, 'message': str(e)}
        self._audit_log('unban', ip_address, config_name, result)
        return result

    async def list_banned(self, config_name: str) -> List[str]:
        config = self._get_config(config_name)
        strategy = self._strategies[config.method]
        return await strategy.list_banned(config)

    def get_configs(self) -> List['IPBanConfig']:
        return self._config_manager.get().ip_ban_configs

    def validate_ip(self, ip_address: str) -> bool:
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    def _audit_log(self, action: str, ip_address: str, config_name: str, result: dict) -> None:
        """Append action to the audit trail JSON file."""
        audit_path = Path(self._config_manager.get().ip_ban_audit_path).expanduser()
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'ip_address': ip_address,
            'config': config_name,
            'success': result.get('success', False),
            'message': result.get('message', ''),
        }
        entries: List[dict] = []
        if audit_path.exists():
            try:
                entries = json.loads(audit_path.read_text())
            except Exception:
                entries = []
        entries.append(entry)
        audit_path.write_text(json.dumps(entries, indent=2))
