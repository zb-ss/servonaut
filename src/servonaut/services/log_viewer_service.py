"""Log viewer service for Servonaut v2.0."""

from __future__ import annotations

import asyncio
import logging
from typing import List, Optional, TYPE_CHECKING

from servonaut.services.interfaces import LogViewerServiceInterface

if TYPE_CHECKING:
    from servonaut.config.manager import ConfigManager
    from servonaut.services.interfaces import SSHServiceInterface, ConnectionServiceInterface

logger = logging.getLogger(__name__)


class LogViewerService(LogViewerServiceInterface):
    """Service for probing and streaming remote log files via SSH tail -f."""

    def __init__(self, config_manager: "ConfigManager") -> None:
        self._config_manager = config_manager

    async def probe_log_paths(
        self,
        instance: dict,
        ssh_service: "SSHServiceInterface",
        connection_service: "ConnectionServiceInterface"
    ) -> List[str]:
        """SSH into server, test readability of each configured path, return readable ones.

        Builds a single SSH command that checks all paths at once using test -r.
        """
        config = self._config_manager.get()
        instance_id = instance.get("id", "")

        all_paths = list(config.log_viewer_default_paths)
        custom = config.log_viewer_custom_paths.get(instance_id, [])
        all_paths.extend(custom)

        if not all_paths:
            return []

        # Build a compound shell command: test -r /path && echo /path; ...
        checks = "; ".join(
            f"test -r {path} && echo {path}" for path in all_paths
        )

        if instance.get('is_custom'):
            host = instance.get('public_ip') or instance.get('private_ip')
            username = instance.get('username') or 'root'
            key_path = instance.get('key_name') or None  # type: Optional[str]
            proxy_args = []  # type: List[str]
            port = instance.get('port', 22)
        else:
            profile = connection_service.resolve_profile(instance)
            host = connection_service.get_target_host(instance, profile)
            proxy_args = []
            if profile:
                proxy_args = connection_service.get_proxy_args(profile)
            username = config.default_username
            key_path = ssh_service.get_key_path(instance_id)
            if not key_path and instance.get("key_name"):
                key_path = ssh_service.discover_key(instance["key_name"])
            port = None

        ssh_cmd = ssh_service.build_ssh_command(
            host=host,
            username=username,
            key_path=key_path,
            proxy_args=proxy_args,
            remote_command=checks,
            port=port,
        )

        try:
            process = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=15)
            readable = [
                line.strip()
                for line in stdout.decode("utf-8", errors="replace").splitlines()
                if line.strip()
            ]
            logger.debug("Probed log paths for %s: %s", instance_id, readable)
            return readable
        except asyncio.TimeoutError:
            logger.warning("Timeout probing log paths for %s", instance_id)
            return []
        except Exception as e:
            logger.error("Error probing log paths for %s: %s", instance_id, e)
            return []

    def get_tail_command(self, log_path: str, num_lines: int = 100, follow: bool = True) -> str:
        """Build tail command string for remote execution."""
        if follow:
            return f"tail -n {num_lines} -f {log_path}"
        return f"tail -n {num_lines} {log_path}"

    def get_custom_paths(self, instance_id: str) -> List[str]:
        """Get user-configured custom log paths for an instance."""
        config = self._config_manager.get()
        return list(config.log_viewer_custom_paths.get(instance_id, []))

    def set_custom_paths(self, instance_id: str, paths: List[str]) -> None:
        """Set custom log paths for an instance and persist config."""
        config = self._config_manager.get()
        config.log_viewer_custom_paths[instance_id] = paths
        self._config_manager.save(config)
