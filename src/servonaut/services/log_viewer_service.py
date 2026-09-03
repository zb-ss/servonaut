"""Log viewer service for Servonaut v2.0."""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

from servonaut.services.interfaces import LogViewerServiceInterface
from servonaut.utils.ssh_utils import run_ssh_subprocess

if TYPE_CHECKING:
    from servonaut.config.manager import ConfigManager
    from servonaut.services.interfaces import SSHServiceInterface, ConnectionServiceInterface
    from servonaut.services.memory.interfaces import MemoryServiceInterface

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
    """Service for probing and streaming remote log files via SSH tail -f.

    Args:
        config_manager: App config manager.
        memory_service: Optional :class:`MemoryServiceInterface` — when wired
            the service consults ``memory/<provider>/<id>/logs.json`` before
            spawning an SSH probe. Cache hits return the stored ``probed_paths``
            instantly; cache misses fall through to the live SSH probe.
    """

    # Last probe source, populated by ``probe_log_paths``.  ``"cache"`` when
    # ``memory.logs.probed_paths`` supplied the result, ``"live"`` when an
    # SSH probe actually ran, ``"empty"`` when the config has no paths, and
    # ``None`` before the first call.  The UI reads this to render the
    # subtle "cached/live" indicator in the header.
    last_probe_source: Optional[str] = None

    # When ``last_probe_source == "cache"`` this holds the cached
    # ``probed_at`` ISO timestamp from the memory store, else ``None``.
    last_probe_probed_at: Optional[str] = None

    def __init__(
        self,
        config_manager: "ConfigManager",
        memory_service: Optional["MemoryServiceInterface"] = None,
    ) -> None:
        self._config_manager = config_manager
        self._memory_service = memory_service

    def set_memory_service(
        self, memory_service: Optional["MemoryServiceInterface"]
    ) -> None:
        """Wire a ``MemoryService`` after construction.

        Memory and log-viewer services have a circular dependency (the memory
        subsystem's ``LogsProber`` uses ``LogViewerService.probe_log_paths``;
        the log viewer wants to consult memory for cached paths).  Callers
        create ``LogViewerService`` first, then ``MemoryService`` with the
        log viewer injected, and finally wire the memory service back here.
        """
        self._memory_service = memory_service

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
                "key_path": instance.get("ssh_key") or instance.get("key_name") or None,
                "proxy_args": [],
                "port": instance.get("port", 22),
                "extra_options": connection_service.get_extra_options(instance, None),
            }

        profile = connection_service.resolve_profile(instance)
        host = connection_service.get_target_host(instance, profile)
        proxy_args: List[str] = []
        if profile:
            proxy_args = connection_service.get_proxy_args(profile)
        extra_options = connection_service.get_extra_options(instance, profile)

        instance_id = instance.get("id", "")
        key_path = ssh_service.get_key_path(instance_id)
        if not key_path and instance.get("key_name"):
            key_path = ssh_service.discover_key(instance["key_name"])

        username = (
            (profile.username if profile else None)
            or config.default_username
        )

        return {
            "host": host,
            "username": username,
            "key_path": key_path,
            "proxy_args": proxy_args,
            "port": None,
            "extra_options": extra_options,
        }

    async def probe_log_paths(
        self,
        instance: dict,
        ssh_service: "SSHServiceInterface",
        connection_service: "ConnectionServiceInterface",
    ) -> List[str]:
        """Return readable log paths, preferring cached memory when available.

        Strategy:
            1. If a memory service is wired AND the ``logs`` module has
               cached ``probed_paths``, return the cached list immediately.
               Stale data (past TTL) is still served but a warning is logged.
            2. Otherwise build a single SSH ``test -r`` compound command
               against every configured path and return the readable ones.

        The last-call source is recorded in :attr:`last_probe_source` so UI
        layers can show a "cached/live" indicator without re-running the probe.
        """
        config = self._config_manager.get()
        instance_id = instance.get("id") or instance.get("name", "")

        # ------------------------------------------------------------------
        # Memory cache short-circuit
        # ------------------------------------------------------------------
        cached_paths = self._lookup_cached_log_paths(instance)
        if cached_paths is not None:
            return cached_paths

        all_paths = list(config.log_viewer_default_paths)
        custom = config.log_viewer_custom_paths.get(instance_id, [])
        # Expand dir: entries — include only the plain file paths for readability probing;
        # directories themselves are expanded by scan_log_directories at call time.
        for entry in custom:
            if not entry.startswith("dir:"):
                all_paths.append(entry)

        if not all_paths:
            self.last_probe_source = "empty"
            self.last_probe_probed_at = None
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
            extra_options=conn.get("extra_options") or [],
        )

        try:
            stdout, _ = await run_ssh_subprocess(ssh_cmd, timeout=15)
            readable = [
                line.strip()
                for line in stdout.decode("utf-8", errors="replace").splitlines()
                if line.strip()
            ]
            logger.debug("Probed log paths for %s: %s", instance_id, readable)
            self.last_probe_source = "live"
            self.last_probe_probed_at = None
            return readable
        except asyncio.TimeoutError:
            logger.warning("Timeout probing log paths for %s", instance_id)
            self.last_probe_source = "live"
            self.last_probe_probed_at = None
            return []
        except Exception as e:
            logger.error("Error probing log paths for %s: %s", instance_id, e)
            self.last_probe_source = "live"
            self.last_probe_probed_at = None
            return []

    def _memory_cache_opted_out(self, instance_id: str, instance_name: str) -> bool:
        """True when memory must not be consulted for this instance.

        The memory read API has no opt-out check of its own, so the viewer
        used to serve cached probed paths even for servers the operator had
        opted out (``memory.per_server_overrides``), a disabled ``logs``
        module, or memory switched off entirely. Those operators expect the
        configured path list to win, which only happens on a live probe.
        """
        try:
            config = self._config_manager.get()
            disabled_modules = list(getattr(config.memory, "disabled_modules", []) or [])
        except Exception:  # config shape is not this method's concern
            disabled_modules = []
        if "logs" in disabled_modules:
            return True
        checker = getattr(self._memory_service, "is_memory_disabled", None)
        if not callable(checker):
            return False
        try:
            return checker(instance_id, instance_name) is True
        except Exception:
            return False

    def _lookup_cached_log_paths(self, instance: dict) -> Optional[List[str]]:
        """Return cached probed_paths for *instance* or ``None`` on cache miss.

        The lookup is best-effort — any exception inside the memory service
        is treated as a miss so log-viewer operations never break because of
        a memory-subsystem regression.  Stale data (past TTL) is still served
        but a warning is logged so operators know to refresh memory.
        """
        if self._memory_service is None:
            return None

        instance_id = instance.get("id") or instance.get("name", "")
        if not instance_id:
            return None
        if self._memory_cache_opted_out(instance_id, str(instance.get("name") or "")):
            return None
        provider = instance.get("provider", "custom")

        try:
            logs_mod = self._memory_service.get(instance_id, "logs", provider)
        except (ValueError, OSError) as exc:
            logger.debug("memory.get failed for %s logs: %s", instance_id, exc)
            return None
        if not logs_mod:
            return None

        observed = logs_mod.get("observed") if isinstance(logs_mod, dict) else None
        if not isinstance(observed, dict):
            return None
        probed_paths = observed.get("probed_paths")
        if not isinstance(probed_paths, list) or not probed_paths:
            return None

        probed_at = str(logs_mod.get("probed_at") or "")
        ttl_seconds = int(logs_mod.get("ttl_seconds") or 0)
        if probed_at and ttl_seconds and _is_past_ttl(probed_at, ttl_seconds):
            logger.warning(
                "Serving stale memory.logs cache for %s (probed_at=%s, ttl=%ss)",
                instance_id, probed_at, ttl_seconds,
            )

        self.last_probe_source = "cache"
        self.last_probe_probed_at = probed_at or None
        logger.debug(
            "Log viewer cache hit for %s: %d path(s)", instance_id, len(probed_paths),
        )
        return [p for p in probed_paths if isinstance(p, str) and p]

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
            extra_options=conn.get("extra_options") or [],
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

    async def add_custom_directory(
        self,
        instance: dict,
        directory: str,
        ssh_service: "SSHServiceInterface",
        connection_service: "ConnectionServiceInterface",
    ) -> List[str]:
        """Scan a remote directory for log files and save it to custom paths.

        The directory is stored with a ``dir:`` prefix in custom_paths so that
        ``probe_log_paths`` can expand it on future calls.

        Args:
            instance: Instance dictionary with connection details.
            directory: Absolute path to the directory on the remote server.
            ssh_service: SSH service for building commands.
            connection_service: Connection service for profile resolution.

        Returns:
            List of discovered file paths found in the directory.
        """
        instance_id = instance.get("id", "")

        # Persist the directory entry (prefix distinguishes it from file paths)
        existing = self.get_custom_paths(instance_id)
        dir_entry = f"dir:{directory}"
        if dir_entry not in existing:
            existing.append(dir_entry)
            self.set_custom_paths(instance_id, existing)

        find_cmd = (
            f"find {directory} -maxdepth 2 -type f -readable "
            r"\( -name '*.log' -o -name '*.log.*' -o -name 'syslog*' -o -name 'messages*' \) "
            "2>/dev/null | sort -u"
        )

        conn = self._resolve_connection(instance, ssh_service, connection_service)
        ssh_cmd = ssh_service.build_ssh_command(
            host=conn["host"],
            username=conn["username"],
            key_path=conn["key_path"],
            proxy_args=conn["proxy_args"],
            remote_command=find_cmd,
            port=conn["port"],
            extra_options=conn.get("extra_options") or [],
        )

        try:
            stdout, _ = await run_ssh_subprocess(ssh_cmd, timeout=20)
            paths = sorted(set(
                line.strip()
                for line in stdout.decode("utf-8", errors="replace").splitlines()
                if line.strip()
            ))
            logger.debug(
                "add_custom_directory for %s found %d files in %s",
                instance_id,
                len(paths),
                directory,
            )
            return paths
        except asyncio.TimeoutError:
            logger.warning("Timeout scanning directory %s for %s", directory, instance_id)
            return []
        except Exception as e:
            logger.error("Error scanning directory %s for %s: %s", directory, instance_id, e)
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_past_ttl(probed_at_iso: str, ttl_seconds: int) -> bool:
    """Return True when *probed_at_iso* is older than *ttl_seconds*."""
    if not probed_at_iso or ttl_seconds <= 0:
        return False
    try:
        probed_at = datetime.fromisoformat(probed_at_iso.rstrip("Z"))
        if not probed_at.tzinfo:
            probed_at = probed_at.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return False
    age = (datetime.now(tz=timezone.utc) - probed_at).total_seconds()
    return age > ttl_seconds
