"""SSH service for key management and SSH command building."""

from __future__ import annotations
import os
import subprocess
import logging
from pathlib import Path
from typing import List, Optional

from servonaut.services.interfaces import SSHServiceInterface
from servonaut.config.manager import ConfigManager

logger = logging.getLogger(__name__)


class SSHService(SSHServiceInterface):
    """SSH service implementing key management and command building.

    Migrated from legacy KeyManager class with enhanced functionality.
    Always uses IdentitiesOnly=yes with -i flag to prevent
    'Too many authentication failures' errors.
    """

    def __init__(self, config_manager: ConfigManager) -> None:
        """Initialize SSH service.

        Args:
            config_manager: Configuration manager instance.
        """
        self._config_manager = config_manager
        self._ssh_dir = Path.home() / '.ssh'

    def get_key_path(self, instance_id: str) -> Optional[str]:
        """Get SSH key path for an instance. Falls back to default key.

        Args:
            instance_id: EC2 instance ID.

        Returns:
            Path to SSH key file, or None if not configured.
        """
        config = self._config_manager.get()
        return config.instance_keys.get(instance_id, config.default_key or None)

    def set_key_path(self, instance_id: str, key_path: str) -> None:
        """Set SSH key path for a specific instance and save.

        Args:
            instance_id: EC2 instance ID.
            key_path: Path to SSH key file.
        """
        config = self._config_manager.get()
        config.instance_keys[instance_id] = key_path
        self._config_manager.save(config)

    def set_default_key(self, key_path: str) -> None:
        """Set default SSH key and save.

        Args:
            key_path: Path to SSH key file.
        """
        self._config_manager.update(default_key=key_path)

    def discover_key(self, key_name: str) -> Optional[str]:
        """Auto-discover SSH key in ~/.ssh/ based on AWS key name.

        Searches in order:
        1. Exact match patterns (key_name, key_name.pem, id_rsa_*, etc.)
        2. Fuzzy match (case-insensitive substring in filename)

        Args:
            key_name: AWS key pair name.

        Returns:
            Path to discovered key, or None if not found.
        """
        if not key_name:
            return None

        # Ensure .ssh directory exists
        if not self._ssh_dir.exists():
            logger.debug("SSH directory does not exist: %s", self._ssh_dir)
            return None

        # Common key file patterns to search for
        patterns = [
            f"{key_name}",
            f"{key_name}.pem",
            f"id_rsa_{key_name}",
            f"{key_name}_id_rsa",
            f"aws_{key_name}",
            f"{key_name}_aws",
        ]

        # Search for matching keys
        for pattern in patterns:
            # Check for exact match
            key_path = self._ssh_dir / pattern
            if key_path.exists():
                logger.info("Discovered SSH key: %s", key_path)
                return str(key_path)

            # Check for .pem extension
            key_path_pem = self._ssh_dir / f"{pattern}.pem"
            if key_path_pem.exists():
                logger.info("Discovered SSH key: %s", key_path_pem)
                return str(key_path_pem)

        # If no exact match, try fuzzy search
        all_keys = self.list_available_keys()
        for key_path in all_keys:
            key_filename = Path(key_path).stem.lower()
            if key_name.lower() in key_filename:
                logger.info("Fuzzy match discovered SSH key: %s", key_path)
                return key_path

        logger.debug("No matching SSH key found for: %s", key_name)
        return None

    def list_available_keys(self) -> List[str]:
        """List SSH keys in ~/.ssh/ directory.

        Returns:
            List of absolute paths to SSH key files.
        """
        if not self._ssh_dir.exists():
            logger.debug("SSH directory does not exist: %s", self._ssh_dir)
            return []

        key_files = []
        # Look for common SSH key files
        patterns = ['*.pem', 'id_*', '*_id_rsa', '*_rsa', 'aws_*']

        for pattern in patterns:
            for key_file in self._ssh_dir.glob(pattern):
                if key_file.is_file():
                    key_files.append(str(key_file))

        return sorted(list(set(key_files)))  # Remove duplicates and sort

    def check_ssh_agent(self) -> bool:
        """Check if SSH agent is running and accessible.

        Uses ssh-add -l as the authoritative check, since many systems
        run the agent via socket activation (systemd, GNOME Keyring,
        macOS Keychain) without setting SSH_AGENT_PID.

        Returns:
            True if SSH agent is running and reachable.
        """
        # Quick check: if SSH_AUTH_SOCK is set and socket exists, try it
        auth_sock = os.environ.get('SSH_AUTH_SOCK')
        if auth_sock and os.path.exists(auth_sock):
            try:
                result = subprocess.run(
                    ['ssh-add', '-l'],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                # 0 = keys listed, 1 = agent running but no keys
                return result.returncode in (0, 1)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return False

        # Fallback: check env var
        return os.environ.get('SSH_AGENT_PID') is not None

    def start_ssh_agent(self) -> bool:
        """Start SSH agent and set environment variables.

        Returns:
            True if agent was started successfully.
        """
        try:
            result = subprocess.run(
                ['ssh-agent', '-s'],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.error("Failed to start ssh-agent: %s", result.stderr)
                return False

            # Parse the output to set environment variables
            # ssh-agent -s outputs: SSH_AUTH_SOCK=/tmp/...; export SSH_AUTH_SOCK;
            #                       SSH_AGENT_PID=12345; export SSH_AGENT_PID;
            for line in result.stdout.splitlines():
                if line.startswith('SSH_AUTH_SOCK='):
                    sock = line.split(';')[0].split('=', 1)[1]
                    os.environ['SSH_AUTH_SOCK'] = sock
                elif line.startswith('SSH_AGENT_PID='):
                    pid = line.split(';')[0].split('=', 1)[1]
                    os.environ['SSH_AGENT_PID'] = pid

            logger.info("Started SSH agent (PID: %s)", os.environ.get('SSH_AGENT_PID'))
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error("Failed to start ssh-agent: %s", e)
            return False

    def add_key_to_agent(self, key_path: str) -> bool:
        """Add key to SSH agent. Check permissions first.

        Args:
            key_path: Path to SSH key file.

        Returns:
            True if key was successfully added.
        """
        try:
            # Expand ~ in paths
            key_path = os.path.expanduser(key_path)

            # Check if key file exists
            if not os.path.exists(key_path):
                logger.error("Key file does not exist: %s", key_path)
                return False

            # Check key file permissions
            if not self.check_key_permissions(key_path):
                logger.warning(
                    "Key file %s has incorrect permissions. Should be 600 or 400.",
                    key_path
                )
                return False

            # Try to add the key
            result = subprocess.run(
                ['ssh-add', key_path],
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )

            # Verify the key was added
            verify = subprocess.run(
                ['ssh-add', '-l'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if verify.returncode == 0:
                logger.info("Successfully added key %s to SSH agent", key_path)
                return True
            else:
                logger.error("Failed to verify key addition: %s", verify.stderr)
                return False

        except subprocess.CalledProcessError as e:
            if "Could not open a connection to your authentication agent" in str(e.stderr):
                logger.error("SSH agent is not running")
            else:
                logger.error("Error adding key to SSH agent: %s", e.stderr)
            return False
        except Exception as e:
            logger.error("Unexpected error adding key to agent: %s", e)
            return False

    def check_key_permissions(self, key_path: str) -> bool:
        """Check if key file has correct permissions (600 or 400).

        Args:
            key_path: Path to SSH key file.

        Returns:
            True if permissions are correct.
        """
        key_path = os.path.expanduser(key_path)
        if not os.path.exists(key_path):
            return False
        perms = oct(os.stat(key_path).st_mode)[-3:]
        return perms in ('600', '400')

    def fix_key_permissions(self, key_path: str) -> None:
        """Fix key file permissions to 600.

        Args:
            key_path: Path to SSH key file.
        """
        key_path = os.path.expanduser(key_path)
        os.chmod(key_path, 0o600)
        logger.info("Fixed permissions for key: %s", key_path)

    def build_ssh_command(
        self,
        host: str,
        username: str,
        key_path: Optional[str] = None,
        proxy_jump: Optional[str] = None,
        remote_command: Optional[str] = None,
        proxy_args: Optional[List[str]] = None,
        port: Optional[int] = None,
    ) -> List[str]:
        """Build SSH command as List[str]. NEVER use shell=True.

        Always uses -o IdentitiesOnly=yes with -i to prevent
        'Too many authentication failures' errors.

        Args:
            host: Target hostname or IP.
            username: SSH username.
            key_path: Path to SSH key (optional if using agent).
            proxy_jump: ProxyJump string (user@host or user@host:port).
            remote_command: Command to execute remotely.
            proxy_args: List of SSH proxy arguments (takes precedence over proxy_jump).
            port: SSH port to connect on (omitted if None or 22).

        Returns:
            List of command arguments for subprocess.
        """
        cmd = [
            'ssh',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
        ]

        # Add non-default port
        if port is not None and port != 22:
            cmd.extend(['-p', str(port)])

        # Add proxy arguments (proxy_args takes precedence over proxy_jump)
        if proxy_args:
            cmd.extend(proxy_args)
        elif proxy_jump:
            cmd.extend(['-J', proxy_jump])

        # Add identity file with IdentitiesOnly to prevent "Too many auth failures"
        if key_path:
            expanded = os.path.expanduser(key_path)
            cmd.extend(['-o', 'IdentitiesOnly=yes', '-i', expanded])

        # Add target host
        cmd.append(f'{username}@{host}')

        # Add remote command if specified
        if remote_command:
            cmd.append(remote_command)

        logger.debug("Built SSH command: %s", ' '.join(cmd))
        return cmd
