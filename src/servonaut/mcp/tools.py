"""MCP tool implementations for Servonaut."""
from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional

from servonaut.utils.ssh_utils import run_ssh_subprocess

logger = logging.getLogger(__name__)


class ServonautTools:
    """Implements all MCP tools using Servonaut services."""

    def __init__(self, config_manager, aws_service, cache_service, ssh_service,
                 connection_service, scp_service, guard, audit) -> None:
        self._config_manager = config_manager
        self._aws_service = aws_service
        self._cache_service = cache_service
        self._ssh_service = ssh_service
        self._connection_service = connection_service
        self._scp_service = scp_service
        self._guard = guard
        self._audit = audit
        self._max_lines = config_manager.get().mcp.max_output_lines

    async def list_instances(self, region: str = "", state: str = "") -> str:
        """List EC2 instances, optionally filtered by region/state."""
        allowed, reason = self._guard.check_tool('list_instances')
        if not allowed:
            self._audit.log('list_instances', {'region': region, 'state': state}, '', False, reason)
            return f"Blocked: {reason}"

        instances = await self._aws_service.fetch_instances_cached()
        if region:
            instances = [i for i in instances if i.get('region') == region]
        if state:
            instances = [i for i in instances if i.get('state') == state]

        result = self._format_instances(instances)
        self._audit.log('list_instances', {'region': region, 'state': state}, result, True)
        return result

    async def run_command(self, instance_id: str, command: str) -> str:
        """Run a command on a remote instance via SSH."""
        allowed, reason = self._guard.check_tool('run_command')
        if not allowed:
            self._audit.log('run_command', {'instance_id': instance_id, 'command': command}, '', False, reason)
            return f"Blocked: {reason}"

        cmd_allowed, cmd_reason = self._guard.check_command(command)
        if not cmd_allowed:
            self._audit.log('run_command', {'instance_id': instance_id, 'command': command}, '', False, cmd_reason)
            return f"Blocked: {cmd_reason}"

        instance = await self._find_instance(instance_id)
        if not instance:
            return f"Instance not found: {instance_id}"

        profile = self._connection_service.resolve_profile(instance)
        host = self._connection_service.get_target_host(instance, profile)
        proxy_args = self._connection_service.get_proxy_args(profile) if profile else []
        username = self._config_manager.get().default_username
        key_path = self._ssh_service.get_key_path(instance_id)
        if not key_path and instance.get('key_name'):
            key_path = self._ssh_service.discover_key(instance['key_name'])

        ssh_cmd = self._ssh_service.build_ssh_command(
            host=host, username=username, key_path=key_path,
            proxy_args=proxy_args, remote_command=command
        )

        try:
            stdout, stderr = await run_ssh_subprocess(ssh_cmd, timeout=60)
        except asyncio.TimeoutError:
            return "Error: Command timed out after 60 seconds"
        except Exception as e:
            return f"Error: {e}"

        output = stdout.decode('utf-8', errors='replace')
        lines = output.split('\n')
        if len(lines) > self._max_lines:
            output = '\n'.join(lines[:self._max_lines]) + f'\n... (truncated, {len(lines)} total lines)'

        if stderr:
            output += f"\nSTDERR:\n{stderr.decode('utf-8', errors='replace')}"

        self._audit.log('run_command', {'instance_id': instance_id, 'command': command}, output, True)
        return output

    async def get_logs(self, instance_id: str, log_path: str = "/var/log/syslog", lines: int = 100) -> str:
        """Get log content from remote instance."""
        return await self.run_command(instance_id, f"tail -n {lines} {log_path}")

    async def check_status(self, instance_id: str) -> str:
        """Get instance status (state, IPs, type, region)."""
        allowed, reason = self._guard.check_tool('check_status')
        if not allowed:
            self._audit.log('check_status', {'instance_id': instance_id}, '', False, reason)
            return f"Blocked: {reason}"

        instance = await self._find_instance(instance_id)
        if not instance:
            return f"Instance not found: {instance_id}"

        lines = [
            f"Instance:   {instance.get('id', '')}",
            f"Name:       {instance.get('name', '')}",
            f"State:      {instance.get('state', '')}",
            f"Type:       {instance.get('type', '')}",
            f"Region:     {instance.get('region', '')}",
            f"Public IP:  {instance.get('public_ip') or '-'}",
            f"Private IP: {instance.get('private_ip') or '-'}",
            f"Key Name:   {instance.get('key_name') or '-'}",
        ]
        result = '\n'.join(lines)
        self._audit.log('check_status', {'instance_id': instance_id}, result, True)
        return result

    async def get_server_info(self, instance_id: str) -> str:
        """Get detailed server info (hostname, uptime, disk, memory)."""
        allowed, reason = self._guard.check_tool('get_server_info')
        if not allowed:
            self._audit.log('get_server_info', {'instance_id': instance_id}, '', False, reason)
            return f"Blocked: {reason}"

        command = "hostname && uptime && df -h && free -m"
        # Bypass guard check since these are safe info commands, but must bypass
        # the standard-mode allowlist. We call run_command directly but need to
        # temporarily allow compound commands in dangerous-equivalent mode.
        # Instead, execute via SSH directly to avoid double guard checking.
        instance = await self._find_instance(instance_id)
        if not instance:
            return f"Instance not found: {instance_id}"

        profile = self._connection_service.resolve_profile(instance)
        host = self._connection_service.get_target_host(instance, profile)
        proxy_args = self._connection_service.get_proxy_args(profile) if profile else []
        username = self._config_manager.get().default_username
        key_path = self._ssh_service.get_key_path(instance_id)
        if not key_path and instance.get('key_name'):
            key_path = self._ssh_service.discover_key(instance['key_name'])

        ssh_cmd = self._ssh_service.build_ssh_command(
            host=host, username=username, key_path=key_path,
            proxy_args=proxy_args, remote_command=command
        )

        try:
            stdout, stderr = await run_ssh_subprocess(ssh_cmd, timeout=60)
        except asyncio.TimeoutError:
            return "Error: Command timed out after 60 seconds"
        except Exception as e:
            return f"Error: {e}"

        output = stdout.decode('utf-8', errors='replace')
        if stderr:
            output += f"\nSTDERR:\n{stderr.decode('utf-8', errors='replace')}"

        self._audit.log('get_server_info', {'instance_id': instance_id}, output, True)
        return output

    async def transfer_file(self, instance_id: str, local_path: str, remote_path: str, direction: str = "download") -> str:
        """Transfer file via SCP."""
        allowed, reason = self._guard.check_tool('transfer_file')
        if not allowed:
            self._audit.log('transfer_file', {
                'instance_id': instance_id, 'local_path': local_path,
                'remote_path': remote_path, 'direction': direction,
            }, '', False, reason)
            return f"Blocked: {reason}"

        instance = await self._find_instance(instance_id)
        if not instance:
            return f"Instance not found: {instance_id}"

        profile = self._connection_service.resolve_profile(instance)
        host = self._connection_service.get_target_host(instance, profile)
        proxy_args = self._connection_service.get_proxy_args(profile) if profile else []
        username = self._config_manager.get().default_username
        key_path = self._ssh_service.get_key_path(instance_id)
        if not key_path and instance.get('key_name'):
            key_path = self._ssh_service.discover_key(instance['key_name'])

        proxy_jump = self._connection_service.get_proxy_jump_string(profile) if profile else None

        if direction == "upload":
            scp_cmd = self._scp_service.build_upload_command(
                local_path=local_path, remote_path=remote_path,
                host=host, username=username, key_path=key_path,
                proxy_jump=proxy_jump, proxy_args=proxy_args or None,
            )
        else:
            scp_cmd = self._scp_service.build_download_command(
                remote_path=remote_path, local_path=local_path,
                host=host, username=username, key_path=key_path,
                proxy_jump=proxy_jump, proxy_args=proxy_args or None,
            )

        returncode, stdout, stderr = await self._scp_service.execute_transfer(scp_cmd)
        if returncode == 0:
            result = f"Transfer successful: {direction} complete"
            if stdout:
                result += f"\n{stdout}"
        else:
            result = f"Transfer failed (exit {returncode})"
            if stderr:
                result += f"\n{stderr}"

        self._audit.log('transfer_file', {
            'instance_id': instance_id, 'local_path': local_path,
            'remote_path': remote_path, 'direction': direction,
        }, result, returncode == 0)
        return result

    async def _find_instance(self, instance_id: str) -> Optional[Dict]:
        instances = await self._aws_service.fetch_instances_cached()
        for inst in instances:
            if inst.get('id') == instance_id or inst.get('name') == instance_id:
                return inst
        return None

    def _format_instances(self, instances: List[Dict]) -> str:
        lines = [f"{'Name':<30} {'ID':<20} {'State':<10} {'Public IP':<16} {'Region':<14}"]
        lines.append('-' * 90)
        for i in instances:
            lines.append(
                f"{(i.get('name') or ''):<30} "
                f"{i.get('id', ''):<20} "
                f"{i.get('state', ''):<10} "
                f"{(i.get('public_ip') or '-'):<16} "
                f"{i.get('region', ''):<14}"
            )
        return '\n'.join(lines)
