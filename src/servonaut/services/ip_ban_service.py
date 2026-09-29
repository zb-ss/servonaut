"""IP Ban service with WAF, Security Group, and NACL strategies."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, TYPE_CHECKING

import boto3

from servonaut.services.accounts.aws_account import aws_client
from servonaut.services.accounts.registry import UnknownAccountError, row_provider
from servonaut.services.interfaces import IPBanStrategyInterface, IPBanServiceInterface

if TYPE_CHECKING:
    from servonaut.config.schema import IPBanConfig
    from servonaut.config.manager import ConfigManager

logger = logging.getLogger(__name__)


def _to_cidr(ip_address: str) -> str:
    """Normalize an IP or CIDR to CIDR form (a bare IP becomes /32)."""
    return ip_address if "/" in ip_address else f"{ip_address}/32"


def _aws_account_key(accounts: Any, label: str) -> Optional[str]:
    """Key of the AWS account *label* names ("" = default); None if none."""
    try:
        return accounts.account("aws", label or None).key
    except UnknownAccountError:
        return None


def configs_in_account(
    configs: Iterable['IPBanConfig'], accounts: Optional[Any], account: str = "",
) -> List['IPBanConfig']:
    """The ban configs that act in AWS account *account* ("" = the default).

    Each config acts in the account it names (empty = the default account),
    so only these change that account's WAF IP sets, security groups and
    network ACLs. A config naming an account that no longer exists acts in
    none. Without an account registry (*accounts* None) there is one
    account and every config acts in it.
    """
    configs = list(configs)
    if accounts is None:
        return configs
    wanted = _aws_account_key(accounts, account)
    if wanted is None:
        return []
    return [config for config in configs if _aws_account_key(accounts, _label(config)) == wanted]


def _label(config: Any) -> str:
    """The account label a config names ("" = default)."""
    label = getattr(config, "account", "")
    return label if isinstance(label, str) else ""


def configs_for_server(
    configs: Iterable['IPBanConfig'], accounts: Optional[Any],
    server: Optional[Dict[str, Any]],
) -> Tuple[List['IPBanConfig'], str]:
    """The ban configs that can shield *server*, and the account they act in.

    With one AWS account (or no registry) every config qualifies and the
    account label is "". With several, only the configs of the server's own
    AWS account do: a ban in another account's IP set would be reported as
    applied while the server stays exposed.

    Raises:
        UnknownAccountError: There are several AWS accounts and the server's
            cannot be told (not a listed AWS server, or its account was
            removed from the settings).
    """
    if accounts is None or not accounts.is_multi("aws"):
        return list(configs), ""
    if not server or row_provider(server) != "aws":
        name = (server or {}).get("name") or (server or {}).get("id") or "the target"
        raise UnknownAccountError(
            f"the AWS account of {name} is unknown: it is not a listed AWS server"
        )
    owner = accounts.account_for(server)
    return configs_in_account(configs, accounts, owner.label), owner.label


class _AccountClients:
    """Builds AWS clients in the account a ban config names.

    ``IPBanConfig.account`` is an account label; empty means the default
    AWS account. Without a registry (older callers) every config uses the
    default credential chain, as before.
    """

    def __init__(self, accounts: Optional[Any] = None) -> None:
        self._accounts = accounts

    def _client(self, service: str, config: 'IPBanConfig') -> Any:
        account = None
        if self._accounts is not None:
            account = self._accounts.aws_context(getattr(config, "account", "") or None)
        return aws_client(account, boto3, service, region_name=config.region or 'us-east-1')


class WAFStrategy(_AccountClients, IPBanStrategyInterface):
    """Ban IPs via AWS WAFv2 IP sets."""

    async def ban_ip(self, ip_address: str, config: 'IPBanConfig') -> dict:
        loop = asyncio.get_event_loop()

        def _ban() -> dict:
            client = self._client('wafv2', config)
            response = client.get_ip_set(
                Name=config.ip_set_name,
                Scope=config.waf_scope,
                Id=config.ip_set_id,
            )
            addresses = list(response['IPSet']['Addresses'])
            cidr = _to_cidr(ip_address)
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
            # The unban handle for a WAF ban is the CIDR entry within
            # this ip_set — persisted as rule_id in remediation evidence.
            return {
                'success': True,
                'message': f'Banned {ip_address} via WAF IP set',
                'rule_id': cidr,
            }

        return await loop.run_in_executor(None, _ban)

    async def unban_ip(self, ip_address: str, config: 'IPBanConfig') -> dict:
        loop = asyncio.get_event_loop()

        def _unban() -> dict:
            client = self._client('wafv2', config)
            response = client.get_ip_set(
                Name=config.ip_set_name,
                Scope=config.waf_scope,
                Id=config.ip_set_id,
            )
            addresses = list(response['IPSet']['Addresses'])
            cidr = _to_cidr(ip_address)
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
            client = self._client('wafv2', config)
            response = client.get_ip_set(
                Name=config.ip_set_name,
                Scope=config.waf_scope,
                Id=config.ip_set_id,
            )
            return list(response['IPSet']['Addresses'])

        return await loop.run_in_executor(None, _list)


class SecurityGroupStrategy(_AccountClients, IPBanStrategyInterface):
    """Ban IPs via Security Group ingress deny rules."""

    _BAN_DESCRIPTION = "servonaut-ban"

    async def ban_ip(self, ip_address: str, config: 'IPBanConfig') -> dict:
        loop = asyncio.get_event_loop()

        def _ban() -> dict:
            ec2 = self._client('ec2', config)
            # Check if already banned
            sg_response = ec2.describe_security_groups(
                GroupIds=[config.security_group_id]
            )
            existing = sg_response['SecurityGroups'][0].get('IpPermissions', [])
            for perm in existing:
                for ip_range in perm.get('IpRanges', []):
                    if (ip_range.get('CidrIp') == _to_cidr(ip_address)
                            and ip_range.get('Description') == SecurityGroupStrategy._BAN_DESCRIPTION):
                        return {'success': False, 'message': f'{ip_address} already banned in security group'}
            auth_response = ec2.authorize_security_group_ingress(
                GroupId=config.security_group_id,
                IpPermissions=[{
                    'IpProtocol': '-1',
                    'IpRanges': [{
                        'CidrIp': _to_cidr(ip_address),
                        'Description': SecurityGroupStrategy._BAN_DESCRIPTION,
                    }],
                }],
            )
            rules = auth_response.get('SecurityGroupRules') if isinstance(auth_response, dict) else None
            rule = rules[0] if isinstance(rules, list) and rules and isinstance(rules[0], dict) else {}
            rule_id = rule.get('SecurityGroupRuleId') or _to_cidr(ip_address)
            return {
                'success': True,
                'message': f'Banned {ip_address} via security group',
                'rule_id': rule_id,
            }

        return await loop.run_in_executor(None, _ban)

    async def unban_ip(self, ip_address: str, config: 'IPBanConfig') -> dict:
        loop = asyncio.get_event_loop()

        def _unban() -> dict:
            ec2 = self._client('ec2', config)
            try:
                ec2.revoke_security_group_ingress(
                    GroupId=config.security_group_id,
                    IpPermissions=[{
                        'IpProtocol': '-1',
                        'IpRanges': [{
                            'CidrIp': _to_cidr(ip_address),
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
            ec2 = self._client('ec2', config)
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


class NACLStrategy(_AccountClients, IPBanStrategyInterface):
    """Ban IPs via Network ACL DENY rules."""

    async def ban_ip(self, ip_address: str, config: 'IPBanConfig') -> dict:
        loop = asyncio.get_event_loop()

        def _ban() -> dict:
            ec2 = self._client('ec2', config)
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
            cidr = _to_cidr(ip_address)
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
            return {
                'success': True,
                'message': f'Banned {ip_address} via NACL rule {rule_number}',
                'rule_id': str(rule_number),
            }

        return await loop.run_in_executor(None, _ban)

    async def unban_ip(self, ip_address: str, config: 'IPBanConfig') -> dict:
        loop = asyncio.get_event_loop()

        def _unban() -> dict:
            ec2 = self._client('ec2', config)
            response = ec2.describe_network_acls(NetworkAclIds=[config.nacl_id])
            entries = response['NetworkAcls'][0].get('Entries', [])
            cidr = _to_cidr(ip_address)
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
            ec2 = self._client('ec2', config)
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

    def __init__(self, config_manager: 'ConfigManager', accounts: Optional[Any] = None) -> None:
        """Build the service.

        Args:
            config_manager: Source of the ban configurations.
            accounts: The account registry, so each ban config acts in the
                AWS account it names. None uses the default credential chain.
        """
        self._config_manager = config_manager
        self._strategies = {k: v(accounts) for k, v in self.STRATEGIES.items()}

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
        """Accept a bare IP or a CIDR block (additive — old callers unaffected)."""
        try:
            if "/" in ip_address:
                ipaddress.ip_network(ip_address, strict=False)
            else:
                ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    def _config_account(self, config_name: str) -> str:
        """The account label a ban config names ("" = default account)."""
        try:
            return self._get_config(config_name).account or ""
        except (ValueError, AttributeError):
            return ""

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
        account = self._config_account(config_name)
        if account:
            entry['account'] = account
        entries: List[dict] = []
        if audit_path.exists():
            try:
                entries = json.loads(audit_path.read_text())
            except Exception:
                entries = []
        entries.append(entry)
        audit_path.write_text(json.dumps(entries, indent=2))
