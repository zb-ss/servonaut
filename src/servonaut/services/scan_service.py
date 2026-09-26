"""Server scanning service for Servonaut v2.0."""

from __future__ import annotations

import asyncio
import logging
import subprocess
from dataclasses import dataclass
from typing import List, Tuple, Optional
from datetime import datetime

from servonaut.services.interfaces import (
    ScanServiceInterface,
    SSHServiceInterface,
    ConnectionServiceInterface,
)
from servonaut.config.manager import ConfigManager
from servonaut.services.ssh_host_keys import (
    HostKeyPolicy,
    HostKeyTarget,
    HostKeyVerificationError,
    detect_host_key_problem,
)
from servonaut.utils.match_utils import matches_conditions
from servonaut.utils.ssh_utils import run_ssh

logger = logging.getLogger(__name__)

# ssh exits 255 when it cannot connect or authenticate.
_SSH_CONNECTION_FAILED = 255

# Seconds before one scan call is abandoned. The connection check shares the
# path-scan limit; ssh's own ConnectTimeout (config ``ssh.connect_timeout``)
# normally fires first.
_PATH_SCAN_TIMEOUT = 30
_COMMAND_SCAN_TIMEOUT = 60

# A provider instance is scanned only while it reports ``running``: pending,
# stopped, error, maintenance and any unmapped state cannot be relied on to
# answer SSH. Custom servers have no power API (state ``unknown``) and are
# always attempted.
_SCANNABLE_STATES = frozenset({'running'})

# Short, host-free labels for why ssh could not connect, matched against its
# stderr (first match wins). They are what demo mode shows, because ssh's own
# message names the host and often the user.
_FAILURE_REASONS: Tuple[Tuple[Tuple[str, ...], str], ...] = (
    (
        ("could not resolve hostname", "name or service not known",
         "nodename nor servname", "name resolution"),
        "host name could not be resolved",
    ),
    (("timed out",), "connection timed out"),
    (("connection refused",), "connection refused"),
    (("no route to host", "network is unreachable", "host is down"), "host unreachable"),
    (
        ("host key verification failed", "host identification has changed"),
        "host key verification failed",
    ),
    (
        ("permission denied", "too many authentication failures",
         "no supported authentication methods", "authentication failed"),
        "authentication failed",
    ),
    (
        ("connection closed", "connection reset", "kex_exchange_identification"),
        "connection closed by the server",
    ),
)

_PASSPHRASE_HINT = (
    "if the key has a passphrase, load it into ssh-agent with ssh-add: "
    "a scan cannot prompt for it"
)


class ScanConnectionError(Exception):
    """SSH could not reach or log in to the instance, so nothing was scanned.

    Attributes:
        reason: Short category such as ``connection refused``. Never names
            the host or the user.
        detail: ssh's own last error line; may name the host and the user.
        hint: Optional advice on how to fix the problem.
    """

    def __init__(self, reason: str, detail: str = "", hint: str = "") -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail
        self.hint = hint

    @classmethod
    def from_ssh_stderr(cls, stderr: str) -> "ScanConnectionError":
        """Classify a failed ssh call from its stderr."""
        lines = [
            line.strip() for line in (stderr or '').splitlines()
            if line.strip() and not line.startswith('Warning:')
        ]
        text = ' '.join(lines).lower()
        reason = next(
            (label for needles, label in _FAILURE_REASONS if any(n in text for n in needles)),
            'connection failed',
        )
        hint = _PASSPHRASE_HINT if reason == 'authentication failed' and 'publickey' in text else ''
        return cls(reason, lines[-1] if lines else '', hint)

    def describe(self, *, redact: bool) -> str:
        """User-facing text. *redact* (demo mode) keeps only the category."""
        text = self.reason if redact or not self.detail else self.detail
        return f"{text} ({self.hint})" if self.hint else text


def is_scannable(instance: dict) -> bool:
    """True for a custom server, or a provider instance reported as running.

    Custom servers report ``unknown`` because there is no power API to ask;
    an unreachable one surfaces as :class:`ScanConnectionError` rather than
    being skipped without a word.
    """
    if instance.get('is_custom'):
        return True
    return (instance.get('state') or '').lower() in _SCANNABLE_STATES


@dataclass(frozen=True)
class _ScanTarget:
    """Everything needed to build an ssh argv for one server."""

    ssh_service: SSHServiceInterface
    host: str
    username: str
    key_path: Optional[str]
    proxy_args: List[str]
    extra_options: List[str]
    port: Optional[int]
    # Names a genuine host-key refusal can report.
    host_key_target: HostKeyTarget

    def argv(self, remote_command: str) -> List[str]:
        return self.ssh_service.build_ssh_command(
            self.host, self.username, self.key_path,
            remote_command=remote_command,
            proxy_args=self.proxy_args,
            port=self.port,
            extra_options=self.extra_options,
        )


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
            ScanConnectionError: SSH could not connect or authenticate. One
                connection check runs before the scan, so an unreachable
                server costs one connect timeout, not one per path and command.
            HostKeyVerificationError: ssh refused the host key; the message
                names the host and the recovery command.
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

        target = self._resolve_target(instance, ssh_service, connection_service)
        await self._check_connection(target)

        results = []

        # Scan paths (run ls -la on each path)
        for path in scan_paths:
            result = await self._run_path_scan(path, target)
            if result:
                results.append(result)

        # Run scan commands
        for command in scan_commands:
            result = await self._run_command_scan(command, target)
            if result:
                results.append(result)

        return results

    def _resolve_target(
        self,
        instance: dict,
        ssh_service: SSHServiceInterface,
        connection_service: ConnectionServiceInterface,
    ) -> _ScanTarget:
        """Resolve host, user, key, proxy and options for *instance*.

        Raises:
            ScanConnectionError: The instance has no address to connect to.
        """
        profile = connection_service.resolve_profile(instance)
        host = connection_service.get_target_host(instance, profile)
        if not host:
            logger.warning("No reachable host for instance %s", instance.get('id'))
            raise ScanConnectionError("no IP address or hostname to connect to")

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

        port = connection_service.get_target_port(instance)
        return _ScanTarget(
            ssh_service=ssh_service,
            host=host,
            username=username,
            key_path=key_path,
            proxy_args=connection_service.get_proxy_args(profile) if profile else [],
            # BatchMode: a scan runs with its output captured, so a password or
            # passphrase prompt could never be answered and would only stall.
            extra_options=[
                'BatchMode=yes',
                *connection_service.get_extra_options(instance, profile),
            ],
            port=port,
            host_key_target=HostKeyTarget.for_connection(
                host, port, instance=instance, profile=profile,
            ),
        )

    async def _check_connection(self, target: _ScanTarget) -> None:
        """Open one connection before scanning.

        Only this check reads exit status 255 as "could not connect". The
        paths and commands that follow are read literally, because a scan
        command can exit 255 itself (a PHP CLI fatal error does).

        Raises:
            HostKeyVerificationError: ssh refused the host key.
            ScanConnectionError: ssh could not connect, log in, or answer in time.
        """
        try:
            result = await self._run_ssh(target.argv('true'), timeout=_PATH_SCAN_TIMEOUT)
        except subprocess.TimeoutExpired:
            logger.warning("Scan connection check to %s timed out", target.host)
            raise ScanConnectionError("connection timed out") from None
        # A refused host key also exits 255; report it with its recovery
        # command rather than as a generic connection failure.
        self._raise_for_host_key_problem(result, target.host_key_target)
        if result.returncode == _SSH_CONNECTION_FAILED:
            error = ScanConnectionError.from_ssh_stderr(result.stderr)
            logger.warning(
                "Scan could not connect to %s: %s", target.host, error.detail or error.reason
            )
            raise error

    def _raise_for_host_key_problem(
        self, result: subprocess.CompletedProcess, target: HostKeyTarget,
    ) -> None:
        """Stop the scan when ssh refused the host key.

        Every further scan of the host would be refused the same way, and
        the caller must be able to tell a changed key from "no matches".
        """
        problem = detect_host_key_problem(
            getattr(result, "diagnostics", "") or "", result.returncode, target,
            HostKeyPolicy.from_ssh_config(self._config_manager.get().ssh),
            stdout=result.stdout,
        )
        if problem is not None:
            raise HostKeyVerificationError(problem)

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

    async def _run_path_scan(self, path: str, target: _ScanTarget) -> Optional[dict]:
        """Scan a remote path by running ls -la via SSH.

        Args:
            path: Remote path to scan
            target: Connection details for the server

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
        ssh_cmd = target.argv(f'ls -la "{safe_path}" 2>/dev/null')

        try:
            result = await self._run_ssh(ssh_cmd, timeout=_PATH_SCAN_TIMEOUT)
        except Exception as e:
            logger.error("Path scan failed for %s on %s: %s", path, target.host, e)
            return None
        self._raise_for_host_key_problem(result, target.host_key_target)

        if result.returncode == 0 and result.stdout.strip():
            return {
                'source': f'path:{path}',
                'content': result.stdout.strip(),
                'timestamp': datetime.now().isoformat()
            }
        return None

    async def _run_command_scan(self, command: str, target: _ScanTarget) -> Optional[dict]:
        """Run a scan command via SSH and capture output.

        Args:
            command: Command to run remotely
            target: Connection details for the server

        Returns:
            Scan result dictionary or None on failure
        """
        try:
            result = await self._run_ssh(target.argv(command), timeout=_COMMAND_SCAN_TIMEOUT)
        except Exception as e:
            logger.error("Command scan failed for '%s' on %s: %s", command, target.host, e)
            return None
        self._raise_for_host_key_problem(result, target.host_key_target)

        if result.returncode == 0 and result.stdout.strip():
            return {
                'source': f'command:{command}',
                'content': result.stdout.strip(),
                'timestamp': datetime.now().isoformat()
            }
        if result.returncode != 0:
            logger.warning(
                "Command '%s' on %s exited %d: %s",
                command, target.host, result.returncode, (result.stderr or '').strip(),
            )
        return None

    @staticmethod
    async def _run_ssh(ssh_cmd: List[str], timeout: int) -> subprocess.CompletedProcess:
        """Run one non-interactive ssh call off the event loop.

        stdin is /dev/null so the child never inherits (and competes for)
        the TUI's terminal input, and ssh's own messages go to a private log
        (``run_ssh``) so a host-key refusal can be told apart from command
        output.

        Raises:
            subprocess.TimeoutExpired: the call outlived *timeout* seconds.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: run_ssh(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
            ),
        )
