"""Abstract base classes for all services in Servonaut v2.0."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.config.schema import ConnectionProfile


class InstanceServiceInterface(ABC):
    """Interface for fetching and caching EC2 instance data."""

    @abstractmethod
    async def fetch_instances(self) -> List[dict]:
        """Fetch instances from AWS across all regions.

        Returns:
            List of instance dictionaries with keys: id, name, type, state,
            public_ip, private_ip, region, key_name.
        """
        pass

    @abstractmethod
    async def fetch_instances_cached(self, force_refresh: bool = False) -> List[dict]:
        """Fetch instances with caching support.

        Args:
            force_refresh: If True, bypass cache and fetch from AWS.

        Returns:
            List of instance dictionaries.
        """
        pass


class SSHServiceInterface(ABC):
    """Interface for SSH key management and connection building."""

    @abstractmethod
    def get_key_path(self, instance_id: str) -> Optional[str]:
        """Get SSH key path for an instance.

        Args:
            instance_id: EC2 instance ID.

        Returns:
            Path to SSH key file, or None if not configured.
        """
        pass

    @abstractmethod
    def set_key_path(self, instance_id: str, key_path: str) -> None:
        """Set SSH key path for an instance.

        Args:
            instance_id: EC2 instance ID.
            key_path: Path to SSH key file.
        """
        pass

    @abstractmethod
    def discover_key(self, key_name: str) -> Optional[str]:
        """Auto-discover SSH key in ~/.ssh/ based on AWS key name.

        Args:
            key_name: AWS key pair name.

        Returns:
            Path to discovered key, or None if not found.
        """
        pass

    @abstractmethod
    def list_available_keys(self) -> List[str]:
        """List all SSH keys in ~/.ssh/ directory.

        Returns:
            List of absolute paths to SSH key files.
        """
        pass

    @abstractmethod
    def check_ssh_agent(self) -> bool:
        """Check if SSH agent is running.

        Returns:
            True if SSH agent is running.
        """
        pass

    @abstractmethod
    def add_key_to_agent(self, key_path: str) -> bool:
        """Add SSH key to SSH agent.

        Args:
            key_path: Path to SSH key file.

        Returns:
            True if key was successfully added.
        """
        pass

    @abstractmethod
    def check_key_permissions(self, key_path: str) -> bool:
        """Check if SSH key has correct permissions (600 or 400).

        Args:
            key_path: Path to SSH key file.

        Returns:
            True if permissions are correct.
        """
        pass

    @abstractmethod
    def fix_key_permissions(self, key_path: str) -> None:
        """Fix SSH key permissions to 600.

        Args:
            key_path: Path to SSH key file.
        """
        pass

    @abstractmethod
    def build_ssh_command(
        self,
        host: str,
        username: str,
        key_path: Optional[str] = None,
        proxy_jump: Optional[str] = None,
        remote_command: Optional[str] = None,
        proxy_args: Optional[List[str]] = None
    ) -> List[str]:
        """Build SSH command with appropriate options.

        Args:
            host: Target hostname or IP.
            username: SSH username.
            key_path: Path to SSH key (optional if using agent).
            proxy_jump: ProxyJump string (user@host). Deprecated, use proxy_args.
            remote_command: Command to execute remotely.
            proxy_args: List of SSH proxy arguments from ConnectionService.get_proxy_args().

        Returns:
            List of command arguments for subprocess.
        """
        pass


class SCPServiceInterface(ABC):
    """Interface for SCP file transfer operations."""

    @abstractmethod
    def build_upload_command(
        self,
        local_path: str,
        remote_path: str,
        host: str,
        username: str,
        key_path: Optional[str] = None,
        proxy_jump: Optional[str] = None
    ) -> List[str]:
        """Build SCP upload command.

        Args:
            local_path: Local file/directory path.
            remote_path: Remote destination path.
            host: Target hostname or IP.
            username: SSH username.
            key_path: Path to SSH key (optional if using agent).
            proxy_jump: ProxyJump string (user@host).

        Returns:
            List of command arguments for subprocess.
        """
        pass

    @abstractmethod
    def build_download_command(
        self,
        remote_path: str,
        local_path: str,
        host: str,
        username: str,
        key_path: Optional[str] = None,
        proxy_jump: Optional[str] = None
    ) -> List[str]:
        """Build SCP download command.

        Args:
            remote_path: Remote file/directory path.
            local_path: Local destination path.
            host: Target hostname or IP.
            username: SSH username.
            key_path: Path to SSH key (optional if using agent).
            proxy_jump: ProxyJump string (user@host).

        Returns:
            List of command arguments for subprocess.
        """
        pass

    @abstractmethod
    async def execute_transfer(self, command: List[str]) -> tuple:
        """Execute SCP transfer command.

        Args:
            command: Command list from build_upload_command or build_download_command.

        Returns:
            Tuple of (returncode, stdout, stderr).
        """
        pass


class ConnectionServiceInterface(ABC):
    """Interface for connection profile resolution and proxy handling."""

    @abstractmethod
    def resolve_profile(self, instance: dict) -> Optional[ConnectionProfile]:
        """Resolve connection profile for an instance.

        Args:
            instance: Instance dictionary.

        Returns:
            Matching ConnectionProfile, or None if using defaults.
        """
        pass

    @abstractmethod
    def get_proxy_jump_string(
        self,
        profile: ConnectionProfile,
        key_path: Optional[str] = None
    ) -> Optional[str]:
        """Build ProxyJump string from profile.

        Args:
            profile: Connection profile with bastion config.
            key_path: SSH key path for bastion (optional).

        Returns:
            ProxyJump string (user@host), or None if no bastion.
        """
        pass

    @abstractmethod
    def get_proxy_args(self, profile: ConnectionProfile) -> List[str]:
        """Build SSH proxy arguments for bastion connection.

        Uses ProxyCommand when bastion_key is specified, ProxyJump otherwise.

        Args:
            profile: Connection profile with bastion config.

        Returns:
            List of SSH arguments for proxy, or empty list if no bastion.
        """
        pass

    @abstractmethod
    def get_target_host(
        self,
        instance: dict,
        profile: Optional[ConnectionProfile] = None
    ) -> str:
        """Get target hostname/IP for connection.

        Args:
            instance: Instance dictionary.
            profile: Connection profile (uses prefer_private_ip setting).

        Returns:
            IP address or hostname to connect to.
        """
        pass


class ScanServiceInterface(ABC):
    """Interface for server scanning (keyword search in files)."""

    @abstractmethod
    async def scan_server(
        self,
        instance: dict,
        ssh_service: SSHServiceInterface,
        connection_service: ConnectionServiceInterface
    ) -> List[dict]:
        """Scan server for keywords in specified paths.

        Args:
            instance: Instance dictionary.
            ssh_service: SSH service for building commands.
            connection_service: Connection service for profile resolution.

        Returns:
            List of match dictionaries with keys: file, line_number, line_text, keyword.
        """
        pass

    @abstractmethod
    def get_scan_config_for_instance(self, instance: dict) -> tuple:
        """Get scan configuration (keywords, paths) for instance.

        Args:
            instance: Instance dictionary.

        Returns:
            Tuple of (keywords: List[str], paths: List[str]).
        """
        pass


class KeywordStoreInterface(ABC):
    """Interface for storing and searching keyword scan results."""

    @abstractmethod
    def save_results(self, server_id: str, results: List[dict]) -> None:
        """Save scan results for a server.

        Args:
            server_id: Instance ID or unique identifier.
            results: List of match dictionaries.
        """
        pass

    @abstractmethod
    def get_results(self, server_id: str) -> List[dict]:
        """Get cached scan results for a server.

        Args:
            server_id: Instance ID or unique identifier.

        Returns:
            List of match dictionaries, or empty list if not cached.
        """
        pass

    @abstractmethod
    def search(self, query: str) -> List[dict]:
        """Search across all cached scan results.

        Args:
            query: Search query string.

        Returns:
            List of matching results with server_id added to each dict.
        """
        pass

    @abstractmethod
    def prune_stale(self, active_instance_ids: List[str]) -> int:
        """Remove cached results for instances that no longer exist.

        Args:
            active_instance_ids: List of currently active instance IDs.

        Returns:
            Number of entries pruned.
        """
        pass


class TerminalServiceInterface(ABC):
    """Interface for terminal detection and SSH session launching."""

    @abstractmethod
    def detect_terminal(self) -> str:
        """Detect available terminal emulator.

        Returns:
            Terminal command name (e.g., 'gnome-terminal', 'iterm', 'wt').
        """
        pass

    @abstractmethod
    def launch_ssh_in_terminal(self, ssh_command: List[str]) -> bool:
        """Launch SSH session in a new terminal window.

        Args:
            ssh_command: SSH command list from SSHServiceInterface.

        Returns:
            True if terminal launched successfully.
        """
        pass
