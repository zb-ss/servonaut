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


class ScanService(ScanServiceInterface):
    """Scans remote servers by running SSH commands and collecting output.

    This service connects to EC2 instances via SSH and runs configured commands
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
        """
        if instance.get('state') != 'running':
            logger.info("Skipping scan for %s - instance not running", instance.get('id'))
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
            return []

        results = []

        # Scan paths (run ls -la on each path)
        for path in scan_paths:
            result = await self._run_path_scan(
                path, host, username, key_path, proxy_args, ssh_service
            )
            if result:
                results.append(result)

        # Run scan commands
        for command in scan_commands:
            result = await self._run_command_scan(
                command, host, username, key_path, proxy_args, ssh_service
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
        ssh_service: SSHServiceInterface
    ) -> Optional[dict]:
        """Scan a remote path by running ls -la via SSH.

        Args:
            path: Remote path to scan
            host: Target host
            username: SSH username
            key_path: SSH key path (optional)
            proxy_args: SSH proxy arguments from ConnectionService.get_proxy_args()
            ssh_service: SSH service for building commands

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
            host, username, key_path, remote_command=remote_command, proxy_args=proxy_args
        )

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ssh_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    stdin=subprocess.DEVNULL
                )
            )

            if result.returncode == 0 and result.stdout.strip():
                return {
                    'source': f'path:{path}',
                    'content': result.stdout.strip(),
                    'timestamp': datetime.now().isoformat()
                }
        except Exception as e:
            logger.error("Path scan failed for %s on %s: %s", path, host, e)

        return None

    async def _run_command_scan(
        self,
        command: str,
        host: str,
        username: str,
        key_path: Optional[str],
        proxy_args: List[str],
        ssh_service: SSHServiceInterface
    ) -> Optional[dict]:
        """Run a scan command via SSH and capture output.

        Args:
            command: Command to run remotely
            host: Target host
            username: SSH username
            key_path: SSH key path (optional)
            proxy_args: SSH proxy arguments from ConnectionService.get_proxy_args()
            ssh_service: SSH service for building commands

        Returns:
            Scan result dictionary or None on failure
        """
        ssh_cmd = ssh_service.build_ssh_command(
            host, username, key_path, remote_command=command, proxy_args=proxy_args
        )

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ssh_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
            )

            if result.returncode == 0 and result.stdout.strip():
                return {
                    'source': f'command:{command}',
                    'content': result.stdout.strip(),
                    'timestamp': datetime.now().isoformat()
                }
            elif result.stderr.strip():
                logger.warning(
                    "Command '%s' on %s stderr: %s",
                    command, host, result.stderr.strip()
                )
        except Exception as e:
            logger.error("Command scan failed for '%s' on %s: %s", command, host, e)

        return None
