"""Server scanning service for Servonaut v2.0."""

from __future__ import annotations

import asyncio
import logging
import subprocess
import shlex
from typing import List, Dict, Tuple, Optional
from datetime import datetime

from servonaut.services.interfaces import (
    ScanServiceInterface,
    SSHServiceInterface,
    ConnectionServiceInterface,
)
from servonaut.config.manager import ConfigManager
from servonaut.utils.match_utils import matches_conditions

logger = logging.getLogger(__name__)

# ssh exits 255 when it cannot connect or authenticate; a remote command's
# own failure exits with that command's status instead.
_SSH_CONNECTION_FAILED = 255

# Provider-reported power states in which an instance cannot answer SSH.
# Custom servers report ``unknown`` because there is no power API to ask.
_KNOWN_DOWN_STATES = frozenset({'stopped', 'stopping', 'terminated', 'shutting-down'})


class ScanConnectionError(Exception):
    """SSH could not reach or log in to the instance, so nothing was scanned."""


def is_scannable(instance: dict) -> bool:
    """Return False only for an instance known to be powered off.

    Custom servers are always attempted: their state is ``unknown``, and an
    unreachable one surfaces as :class:`ScanConnectionError` rather than
    being skipped without a word.
    """
    if instance.get('is_custom'):
        return True
    return (instance.get('state') or '').lower() not in _KNOWN_DOWN_STATES


class ScanService(ScanServiceInterface):
    """Scans remote servers by running SSH commands and collecting output.

    This service connects to managed instances via SSH and runs configured commands
    or scans specified paths to collect keyword data for later searching.
    """

    def __init__(self, config_manager: ConfigManager) -> None:
        """Initialize the scan service.

        Args:
            config_manager: Configuration manager instance
        """
        self._config_manager = config_manager

    async def scan_server(
        self,
        instance: dict,
        ssh_service: SSHServiceInterface,
        connection_service: ConnectionServiceInterface
    ) -> List[dict]:
        """Scan a single server based on its matching config rules.

        Args:
            instance: Instance dictionary with keys: id, name, state, etc.
            ssh_service: SSH service for building commands
            connection_service: Connection service for profile resolution

        Returns:
            List of scan results:
            [{"source": "path:/home/user/shared/" or "command:pm2 list",
              "content": "output text...",
              "timestamp": "2026-02-08T12:00:00"}]

        Raises:
            ScanConnectionError: SSH could not connect or authenticate. The
                scan stops at the first such failure instead of paying the
                connect timeout once per path and command.
        """
        if not is_scannable(instance):
            logger.info(
                "Skipping scan for %s - instance is %s",
                instance.get('id'), instance.get('state'),
            )
            return []

        scan_paths, scan_commands = self.get_scan_config_for_instance(instance)

        if not scan_paths and not scan_commands:
            logger.info("No scan config for instance %s", instance.get('id'))
            return []

        # Resolve connection details
        profile = connection_service.resolve_profile(instance)
        host = connection_service.get_target_host(instance, profile)
        proxy_args = []
        if profile:
            proxy_args = connection_service.get_proxy_args(profile)
        # BatchMode: a scan runs with its output captured, so a password or
        # passphrase prompt could never be answered and would only stall.
        extra_options = [
            'BatchMode=yes',
            *connection_service.get_extra_options(instance, profile),
        ]
        port = connection_service.get_target_port(instance)

        if instance.get('is_custom'):
            username = instance.get('username') or 'root'
            key_path = instance.get('ssh_key') or instance.get('key_name') or None
        else:
            username = (
                (profile.username if profile else None)
                or self._config_manager.get().default_username
            )
            key_path = ssh_service.get_key_path(instance.get('id', ''))
            if not key_path and instance.get('key_name'):
                key_path = ssh_service.discover_key(instance['key_name'])

        if not host:
            logger.warning("No reachable host for instance %s", instance.get('id'))
            raise ScanConnectionError("No IP address or hostname to connect to")

        results = []

        # Scan paths (run ls -la on each path)
        for path in scan_paths:
            result = await self._run_path_scan(
                path, host, username, key_path, proxy_args, ssh_service, extra_options,
                port=port,
            )
            if result:
                results.append(result)

        # Run scan commands
        for command in scan_commands:
            result = await self._run_command_scan(
                command, host, username, key_path, proxy_args, ssh_service, extra_options,
                port=port,
            )
            if result:
                results.append(result)

        return results

    def get_scan_config_for_instance(self, instance: dict) -> Tuple[List[str], List[str]]:
        """Get combined scan paths and commands for an instance.

        Merges default_scan_paths with any matching scan_rules.

        Args:
            instance: Instance dictionary

        Returns:
            Tuple of (paths, commands)
        """
        config = self._config_manager.get()
        paths = list(config.default_scan_paths)  # copy defaults
        commands = []  # no default commands

        for rule in config.scan_rules:
            if matches_conditions(instance, rule.match_conditions):
                paths.extend(rule.scan_paths)
                commands.extend(rule.scan_commands)

        # Deduplicate while preserving order
        paths = list(dict.fromkeys(paths))
        commands = list(dict.fromkeys(commands))

        return paths, commands

    async def _run_path_scan(
        self,
        path: str,
        host: str,
        username: str,
        key_path: Optional[str],
        proxy_args: List[str],
        ssh_service: SSHServiceInterface,
        extra_options: Optional[List[str]] = None,
        port: Optional[int] = None,
    ) -> Optional[dict]:
        """Scan a remote path by running ls -la via SSH.

        Args:
            path: Remote path to scan
            host: Target host
            username: SSH username
            key_path: SSH key path (optional)
            proxy_args: SSH proxy arguments from ConnectionService.get_proxy_args()
            ssh_service: SSH service for building commands
            extra_options: Extra ``-o KEY=VALUE`` entries for the target
            port: Target SSH port (None for the default)

        Returns:
            Scan result dictionary or None on failure
        """
        # Expand ~ to $HOME for remote shell (shlex.quote prevents tilde expansion)
        if path.startswith('~/'):
            safe_path = '$HOME/' + path[2:]
        elif path == '~':
            safe_path = '$HOME'
        else:
            safe_path = path
        remote_command = f'ls -la "{safe_path}" 2>/dev/null'
        ssh_cmd = ssh_service.build_ssh_command(
            host, username, key_path,
            remote_command=remote_command,
            proxy_args=proxy_args,
            port=port,
            extra_options=extra_options,
        )

        try:
            result = await self._run_ssh(ssh_cmd, host, timeout=30)
        except ScanConnectionError:
            raise
        except Exception as e:
            logger.error("Path scan failed for %s on %s: %s", path, host, e)
            return None

        if result.returncode == 0 and result.stdout.strip():
            return {
                'source': f'path:{path}',
                'content': result.stdout.strip(),
                'timestamp': datetime.now().isoformat()
            }
        return None

    async def _run_command_scan(
        self,
        command: str,
        host: str,
        username: str,
        key_path: Optional[str],
        proxy_args: List[str],
        ssh_service: SSHServiceInterface,
        extra_options: Optional[List[str]] = None,
        port: Optional[int] = None,
    ) -> Optional[dict]:
        """Run a scan command via SSH and capture output.

        Args:
            command: Command to run remotely
            host: Target host
            username: SSH username
            key_path: SSH key path (optional)
            proxy_args: SSH proxy arguments from ConnectionService.get_proxy_args()
            ssh_service: SSH service for building commands
            extra_options: Extra ``-o KEY=VALUE`` entries for the target
            port: Target SSH port (None for the default)

        Returns:
            Scan result dictionary or None on failure
        """
        ssh_cmd = ssh_service.build_ssh_command(
            host, username, key_path,
            remote_command=command,
            proxy_args=proxy_args,
            port=port,
            extra_options=extra_options,
        )

        try:
            result = await self._run_ssh(ssh_cmd, host, timeout=60)
        except ScanConnectionError:
            raise
        except Exception as e:
            logger.error("Command scan failed for '%s' on %s: %s", command, host, e)
            return None

        if result.returncode == 0 and result.stdout.strip():
            return {
                'source': f'command:{command}',
                'content': result.stdout.strip(),
                'timestamp': datetime.now().isoformat()
            }
        if result.stderr.strip():
            logger.warning(
                "Command '%s' on %s stderr: %s",
                command, host, result.stderr.strip()
            )
        return None

    @staticmethod
    async def _run_ssh(
        ssh_cmd: List[str], host: str, timeout: int
    ) -> subprocess.CompletedProcess:
        """Run one non-interactive ssh call off the event loop.

        stdin is /dev/null so the child never inherits (and competes for)
        the TUI's terminal input.

        Raises:
            ScanConnectionError: ssh itself failed (exit 255).
            subprocess.TimeoutExpired: the call outlived *timeout* seconds.
        """
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
            ),
        )
        if result.returncode == _SSH_CONNECTION_FAILED:
            lines = (result.stderr or '').strip().splitlines()
            reason = lines[-1] if lines else 'ssh exited with status 255'
            logger.warning("Scan could not connect to %s: %s", host, reason)
            raise ScanConnectionError(reason)
        return result
