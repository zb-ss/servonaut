"""Relay executor: routes inbound CommandRequests to local SSH/SCP execution."""
from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

from servonaut.models.relay_messages import CommandRequest, CommandResponse, CommandType
from servonaut.utils.ssh_utils import run_ssh_subprocess

logger = logging.getLogger(__name__)

_MAX_OUTPUT_LINES = 500
_MAX_TTL_SECONDS = 300  # Cap command timeout at 5 minutes
_TRANSFERS_DIR = Path.home() / '.servonaut' / 'transfers'

# Always-blocked patterns (same as MCP guard — never allow, even from backend)
_COMMAND_BLOCKLIST = [
    re.compile(r'\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive)\b'),
    re.compile(r'\brm\s+-rf\b'),
    re.compile(r'\bmkfs\b'),
    re.compile(r'\bdd\s+.*of=/dev/'),
    re.compile(r'\b(shutdown|reboot|halt|poweroff)\b'),
    re.compile(r'>\s*/dev/sd[a-z]'),
    re.compile(r'\bchmod\s+-R\s+777\b'),
    re.compile(r':\(\)\{'),  # Fork bomb
]

# Safe path pattern for log file paths
_SAFE_PATH_RE = re.compile(r'^[a-zA-Z0-9_./\-]+$')


class RelayExecutors:
    """Routes relay CommandRequests to local service execution."""

    def __init__(self, config_manager, aws_service, custom_server_service,
                 ssh_service, connection_service, scp_service) -> None:
        self._config_manager = config_manager
        self._aws_service = aws_service
        self._custom_server_service = custom_server_service
        self._ssh_service = ssh_service
        self._connection_service = connection_service
        self._scp_service = scp_service
        # Load additional blocklist patterns from config
        mcp_config = config_manager.get().mcp
        self._extra_blocklist: List[re.Pattern] = [
            re.compile(p) for p in mcp_config.command_blocklist
        ] if hasattr(mcp_config, 'command_blocklist') else []

    async def execute(self, request: CommandRequest) -> CommandResponse:
        """Dispatch a CommandRequest to the appropriate executor."""
        # Clamp TTL to prevent unbounded command execution
        request.ttl_seconds = max(1, min(request.ttl_seconds, _MAX_TTL_SECONDS))
        try:
            match request.type:
                case CommandType.GET_LOGS:
                    return await self._get_logs(request)
                case CommandType.TRANSFER_FILE:
                    return await self._transfer_file(request)
                case _:
                    # RUN_COMMAND, DEPLOY, PROVISION_*, COST_REPORT, SECURITY_SCAN
                    return await self._run_command(request)
        except Exception as e:
            logger.error("Executor error for request %s: %s", request.id, e)
            return CommandResponse(
                request_id=request.id,
                status="error",
                error_message=str(e),
            )

    async def _find_instance(self, identifier: str) -> Optional[Dict]:
        """Find instance by ID or name across all providers (AWS + custom)."""
        aws_instances = await self._aws_service.fetch_instances_cached()
        custom_instances = self._custom_server_service.list_as_instances()
        all_instances = aws_instances + custom_instances
        identifier_lower = identifier.lower()
        for inst in all_instances:
            if (inst.get('id') == identifier
                    or inst.get('id', '').lower() == identifier_lower
                    or inst.get('name') == identifier
                    or inst.get('name', '').lower() == identifier_lower):
                return inst
        return None

    def _resolve_connection(self, instance: Dict) -> Dict:
        """Resolve SSH connection parameters for an instance."""
        profile = self._connection_service.resolve_profile(instance)
        host = self._connection_service.get_target_host(instance, profile)
        proxy_args = self._connection_service.get_proxy_args(profile) if profile else []

        if instance.get('is_custom'):
            username = (
                instance.get('username')
                or self._config_manager.get().default_username
                or 'root'
            )
            key_path = instance.get('ssh_key') or instance.get('key_name') or None
            port = instance.get('port') or None
        else:
            username = (
                (profile.username if profile else None)
                or self._config_manager.get().default_username
            )
            instance_id = instance.get('id', '')
            key_path = self._ssh_service.get_key_path(instance_id)
            if not key_path and instance.get('key_name'):
                key_path = self._ssh_service.discover_key(instance['key_name'])
            port = None

        return {
            'host': host,
            'username': username,
            'key_path': key_path,
            'proxy_args': proxy_args,
            'profile': profile,
            'port': port,
        }

    def _check_blocklist(self, command: str) -> Optional[str]:
        """Check command against blocklist. Returns rejection reason or None."""
        for pattern in _COMMAND_BLOCKLIST:
            if pattern.search(command):
                return f"Command matches blocklist pattern: {pattern.pattern}"
        for pattern in self._extra_blocklist:
            if pattern.search(command):
                return f"Command matches blocklist pattern: {pattern.pattern}"
        return None

    async def _run_command(self, request: CommandRequest) -> CommandResponse:
        """Execute an arbitrary SSH command on the target server."""
        command = request.payload.get('command', '')
        if not command:
            return CommandResponse(
                request_id=request.id,
                status="rejected",
                error_message="No 'command' key in payload.",
            )

        # Enforce command blocklist
        rejection = self._check_blocklist(command)
        if rejection:
            logger.warning("Blocked command from relay: %s — %s", command, rejection)
            return CommandResponse(
                request_id=request.id,
                status="rejected",
                error_message=rejection,
            )

        instance = await self._find_instance(request.target_server_id)
        if not instance:
            return CommandResponse(
                request_id=request.id,
                status="error",
                error_message=f"Instance not found: {request.target_server_id}",
            )

        conn = self._resolve_connection(instance)
        ssh_cmd = self._ssh_service.build_ssh_command(
            host=conn['host'],
            username=conn['username'],
            key_path=conn['key_path'],
            proxy_args=conn['proxy_args'],
            remote_command=command,
            port=conn.get('port'),
        )

        try:
            stdout, stderr = await run_ssh_subprocess(ssh_cmd, timeout=request.ttl_seconds)
        except asyncio.TimeoutError:
            return CommandResponse(
                request_id=request.id,
                status="timeout",
                error_message=f"Command timed out after {request.ttl_seconds}s",
            )
        except Exception as e:
            return CommandResponse(
                request_id=request.id,
                status="error",
                error_message=str(e),
            )

        output = stdout.decode('utf-8', errors='replace')
        lines = output.split('\n')
        if len(lines) > _MAX_OUTPUT_LINES:
            output = '\n'.join(lines[:_MAX_OUTPUT_LINES]) + (
                f'\n... (truncated, {len(lines)} total lines)'
            )

        if stderr:
            output += f"\nSTDERR:\n{stderr.decode('utf-8', errors='replace')}"

        return CommandResponse(
            request_id=request.id,
            status="success",
            output=output,
        )

    async def _get_logs(self, request: CommandRequest) -> CommandResponse:
        """Fetch remote log content via tail/journalctl."""
        log_path = request.payload.get('log_path', '/var/log/syslog')
        lines = request.payload.get('lines', 100)

        # Validate lines is a positive integer
        try:
            lines = int(lines)
            if lines < 1 or lines > 10000:
                raise ValueError
        except (TypeError, ValueError):
            return CommandResponse(
                request_id=request.id,
                status="rejected",
                error_message=f"Invalid 'lines' value: {request.payload.get('lines')}",
            )

        # Validate log_path against safe pattern (no shell metacharacters)
        if not _SAFE_PATH_RE.fullmatch(log_path):
            return CommandResponse(
                request_id=request.id,
                status="rejected",
                error_message=f"Invalid log path: contains unsafe characters",
            )

        # Build a synthetic run_command request using the validated logs payload
        run_request = CommandRequest(
            id=request.id,
            user_id=request.user_id,
            type=CommandType.RUN_COMMAND,
            target_server_id=request.target_server_id,
            payload={'command': f'tail -n {lines} {log_path}'},
            ttl_seconds=request.ttl_seconds,
        )
        return await self._run_command(run_request)

    async def _transfer_file(self, request: CommandRequest) -> CommandResponse:
        """Transfer a file via SCP using parameters from the payload."""
        local_path = request.payload.get('local_path', '')
        remote_path = request.payload.get('remote_path', '')
        direction = request.payload.get('direction', 'download')

        if not local_path or not remote_path:
            return CommandResponse(
                request_id=request.id,
                status="rejected",
                error_message="Payload must contain 'local_path' and 'remote_path'.",
            )

        # Restrict local_path to transfers directory to prevent exfiltration
        _TRANSFERS_DIR.mkdir(parents=True, exist_ok=True)
        resolved_local = Path(local_path).resolve()
        if not resolved_local.is_relative_to(_TRANSFERS_DIR.resolve()):
            return CommandResponse(
                request_id=request.id,
                status="rejected",
                error_message=f"local_path must be under {_TRANSFERS_DIR}",
            )
        local_path = str(resolved_local)

        # Reject path traversal in remote_path
        if '..' in remote_path:
            return CommandResponse(
                request_id=request.id,
                status="rejected",
                error_message="remote_path must not contain '..'",
            )

        instance = await self._find_instance(request.target_server_id)
        if not instance:
            return CommandResponse(
                request_id=request.id,
                status="error",
                error_message=f"Instance not found: {request.target_server_id}",
            )

        conn = self._resolve_connection(instance)
        host = conn['host']
        username = conn['username']
        key_path = conn['key_path']
        proxy_args = conn['proxy_args']
        profile = conn['profile']
        port = conn.get('port')

        proxy_jump = (
            self._connection_service.get_proxy_jump_string(profile) if profile else None
        )

        if direction == "upload":
            scp_cmd = self._scp_service.build_upload_command(
                local_path=local_path,
                remote_path=remote_path,
                host=host,
                username=username,
                key_path=key_path,
                proxy_jump=proxy_jump,
                proxy_args=proxy_args or None,
                port=port,
            )
        else:
            scp_cmd = self._scp_service.build_download_command(
                remote_path=remote_path,
                local_path=local_path,
                host=host,
                username=username,
                key_path=key_path,
                proxy_jump=proxy_jump,
                proxy_args=proxy_args or None,
                port=port,
            )

        returncode, stdout, stderr = await self._scp_service.execute_transfer(scp_cmd)

        if returncode == 0:
            output = f"Transfer successful: {direction} complete"
            if stdout:
                output += f"\n{stdout}"
            return CommandResponse(
                request_id=request.id,
                status="success",
                output=output,
            )
        else:
            error_msg = f"Transfer failed (exit {returncode})"
            if stderr:
                error_msg += f"\n{stderr}"
            return CommandResponse(
                request_id=request.id,
                status="error",
                error_message=error_msg,
            )
