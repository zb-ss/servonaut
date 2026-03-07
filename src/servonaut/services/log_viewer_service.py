"""Log viewer service for Servonaut v2.0."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

from servonaut.services.interfaces import LogViewerServiceInterface
from servonaut.utils.ssh_utils import run_ssh_subprocess

if TYPE_CHECKING:
    from servonaut.config.manager import ConfigManager
    from servonaut.services.interfaces import SSHServiceInterface, ConnectionServiceInterface

logger = logging.getLogger(__name__)

# Patterns for file classification
_COMPRESSED_RE = re.compile(r"\.(gz|bz2|xz|zst)$")
_ROTATED_RE = re.compile(r"\.\d+$")

# Map of compressed extensions to decompression commands
_DECOMPRESS_COMMANDS = {
    ".gz": "zcat",
    ".bz2": "bzcat",
    ".xz": "xzcat",
    ".zst": "zstdcat",
}


class LogViewerService(LogViewerServiceInterface):
    """Service for probing and streaming remote log files via SSH tail -f."""

    def __init__(self, config_manager: "ConfigManager") -> None:
        self._config_manager = config_manager

    def _resolve_connection(
        self,
        instance: dict,
        ssh_service: "SSHServiceInterface",
        connection_service: "ConnectionServiceInterface",
    ) -> Dict[str, object]:
        """Resolve SSH connection parameters for an instance.

        Returns:
            Dict with keys: host, username, key_path, proxy_args, port.
        """
        config = self._config_manager.get()

        if instance.get("is_custom"):
            return {
                "host": instance.get("public_ip") or instance.get("private_ip"),
                "username": instance.get("username") or "root",
                "key_path": instance.get("key_name") or None,
                "proxy_args": [],
                "port": instance.get("port", 22),
            }

        profile = connection_service.resolve_profile(instance)
        host = connection_service.get_target_host(instance, profile)
        proxy_args: List[str] = []
        if profile:
            proxy_args = connection_service.get_proxy_args(profile)

        instance_id = instance.get("id", "")
        key_path = ssh_service.get_key_path(instance_id)
        if not key_path and instance.get("key_name"):
            key_path = ssh_service.discover_key(instance["key_name"])

        return {
            "host": host,
            "username": config.default_username,
            "key_path": key_path,
            "proxy_args": proxy_args,
            "port": None,
        }

    async def probe_log_paths(
        self,
        instance: dict,
        ssh_service: "SSHServiceInterface",
        connection_service: "ConnectionServiceInterface",
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

        conn = self._resolve_connection(instance, ssh_service, connection_service)
        ssh_cmd = ssh_service.build_ssh_command(
            host=conn["host"],
            username=conn["username"],
            key_path=conn["key_path"],
            proxy_args=conn["proxy_args"],
            remote_command=checks,
            port=conn["port"],
        )

        try:
            stdout, _ = await run_ssh_subprocess(ssh_cmd, timeout=15)
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

    def classify_log_file(self, path: str) -> str:
        """Classify a log file as active, rotated, or compressed."""
        if _COMPRESSED_RE.search(path):
            return "compressed"
        if _ROTATED_RE.search(path):
            return "rotated"
        return "active"

    def get_read_command(self, log_path: str, num_lines: int = 100) -> str:
        """Build read command appropriate for the file type.

        - compressed (.gz, .bz2, .xz, .zst): uses decompression tool
        - rotated (.1, .2, ...): tail without -f
        - active: tail -f
        """
        classification = self.classify_log_file(log_path)

        if classification == "compressed":
            for ext, cmd in _DECOMPRESS_COMMANDS.items():
                if log_path.endswith(ext):
                    return f"{cmd} {log_path}"
            # Fallback for unknown compressed extension
            return f"zcat {log_path}"

        if classification == "rotated":
            return f"tail -n {num_lines} {log_path}"

        # Active file — follow
        return f"tail -n {num_lines} -f {log_path}"

    async def scan_log_directories(
        self,
        instance: dict,
        ssh_service: "SSHServiceInterface",
        connection_service: "ConnectionServiceInterface",
        directories: Optional[List[str]] = None,
        max_depth: int = 2,
    ) -> List[str]:
        """Scan remote directories for log files via SSH find command."""
        config = self._config_manager.get()
        if directories is None:
            directories = config.log_viewer_scan_directories
        if max_depth == 2:
            max_depth = config.log_viewer_scan_max_depth

        if not directories:
            return []

        # Build find command for all directories
        dir_args = " ".join(directories)
        find_cmd = (
            f"find {dir_args} -maxdepth {max_depth} -type f -readable "
            f"2>/dev/null | sort -u"
        )

        conn = self._resolve_connection(instance, ssh_service, connection_service)
        ssh_cmd = ssh_service.build_ssh_command(
            host=conn["host"],
            username=conn["username"],
            key_path=conn["key_path"],
            proxy_args=conn["proxy_args"],
            remote_command=find_cmd,
            port=conn["port"],
        )

        try:
            stdout, _ = await run_ssh_subprocess(ssh_cmd, timeout=20)
            paths = sorted(set(
                line.strip()
                for line in stdout.decode("utf-8", errors="replace").splitlines()
                if line.strip()
            ))
            logger.debug(
                "Scanned directories for %s: found %d files",
                instance.get("id", ""),
                len(paths),
            )
            return paths
        except asyncio.TimeoutError:
            logger.warning(
                "Timeout scanning log directories for %s",
                instance.get("id", ""),
            )
            return []
        except Exception as e:
            logger.error(
                "Error scanning log directories for %s: %s",
                instance.get("id", ""),
                e,
            )
            return []

    def get_custom_paths(self, instance_id: str) -> List[str]:
        """Get user-configured custom log paths for an instance."""
        config = self._config_manager.get()
        return list(config.log_viewer_custom_paths.get(instance_id, []))

    def set_custom_paths(self, instance_id: str, paths: List[str]) -> None:
        """Set custom log paths for an instance and persist config."""
        config = self._config_manager.get()
        config.log_viewer_custom_paths[instance_id] = paths
        self._config_manager.save(config)
