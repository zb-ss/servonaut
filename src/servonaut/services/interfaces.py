"""Abstract base classes for all services in Servonaut v2.0."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.config.schema import AIProviderConfig, ConnectionProfile, CustomServer, IPBanConfig


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
        proxy_args: Optional[List[str]] = None,
        port: Optional[int] = None,
    ) -> List[str]:
        """Build SSH command with appropriate options.

        Args:
            host: Target hostname or IP.
            username: SSH username.
            key_path: Path to SSH key (optional if using agent).
            proxy_jump: ProxyJump string (user@host). Deprecated, use proxy_args.
            remote_command: Command to execute remotely.
            proxy_args: List of SSH proxy arguments from ConnectionService.get_proxy_args().
            port: SSH port (omitted if None or 22).

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


class CustomServerServiceInterface(ABC):
    """Interface for managing non-AWS custom servers."""

    @abstractmethod
    def add_server(self, server: 'CustomServer') -> None:
        """Add a custom server to config.

        Args:
            server: CustomServer instance to add.
        """
        pass

    @abstractmethod
    def remove_server(self, name: str) -> bool:
        """Remove a custom server by name.

        Args:
            name: Server name to remove.

        Returns:
            True if found and removed, False otherwise.
        """
        pass

    @abstractmethod
    def update_server(self, name: str, server: 'CustomServer') -> bool:
        """Replace a custom server entry by name.

        Args:
            name: Existing server name to replace.
            server: New CustomServer data.

        Returns:
            True if found and updated, False otherwise.
        """
        pass

    @abstractmethod
    def list_servers(self) -> List['CustomServer']:
        """Return all custom servers.

        Returns:
            List of CustomServer instances.
        """
        pass

    @abstractmethod
    def get_server(self, name: str) -> Optional['CustomServer']:
        """Get a custom server by name.

        Args:
            name: Server name to look up.

        Returns:
            CustomServer if found, None otherwise.
        """
        pass

    @abstractmethod
    def to_instance_dict(self, server: 'CustomServer') -> dict:
        """Convert a CustomServer to instance dict format.

        Args:
            server: CustomServer to convert.

        Returns:
            Instance dictionary compatible with app.instances format.
        """
        pass

    @abstractmethod
    def list_as_instances(self) -> List[dict]:
        """Return all custom servers as instance dicts.

        Returns:
            List of instance dictionaries.
        """
        pass


class LogViewerServiceInterface(ABC):
    """Interface for remote log file viewing and management."""

    @abstractmethod
    async def probe_log_paths(
        self,
        instance: dict,
        ssh_service: "SSHServiceInterface",
        connection_service: "ConnectionServiceInterface"
    ) -> List[str]:
        """Probe remote server for readable log files.

        Args:
            instance: Instance dictionary with connection details.
            ssh_service: SSH service for building commands.
            connection_service: Connection service for profile resolution.

        Returns:
            List of readable log file paths.
        """
        pass

    @abstractmethod
    def get_tail_command(self, log_path: str, num_lines: int = 100, follow: bool = True) -> str:
        """Build tail command string for remote execution.

        Args:
            log_path: Remote path to the log file.
            num_lines: Number of initial lines to tail.
            follow: If True, use tail -f to follow the file.

        Returns:
            Shell command string.
        """
        pass

    @abstractmethod
    def get_custom_paths(self, instance_id: str) -> List[str]:
        """Get user-configured custom log paths for an instance.

        Args:
            instance_id: EC2 instance ID.

        Returns:
            List of custom log paths configured for this instance.
        """
        pass

    @abstractmethod
    def set_custom_paths(self, instance_id: str, paths: List[str]) -> None:
        """Set custom log paths for an instance.

        Args:
            instance_id: EC2 instance ID.
            paths: List of log paths to configure.
        """
        pass

    @abstractmethod
    async def scan_log_directories(
        self,
        instance: dict,
        ssh_service: "SSHServiceInterface",
        connection_service: "ConnectionServiceInterface",
        directories: Optional[List[str]] = None,
        max_depth: int = 2,
    ) -> List[str]:
        """Scan remote directories for log files via SSH find.

        Args:
            instance: Instance dictionary with connection details.
            ssh_service: SSH service for building commands.
            connection_service: Connection service for profile resolution.
            directories: Directories to scan (defaults to config setting).
            max_depth: Maximum directory depth for find command.

        Returns:
            Sorted, deduplicated list of discovered log file paths.
        """
        pass

    @abstractmethod
    def get_read_command(self, log_path: str, num_lines: int = 100) -> str:
        """Build read command appropriate for the file type.

        Returns zcat for .gz, bzcat for .bz2, xzcat for .xz,
        tail (no -f) for rotated files, tail -f for active files.

        Args:
            log_path: Remote path to the log file.
            num_lines: Number of lines for tail commands.

        Returns:
            Shell command string.
        """
        pass

    @abstractmethod
    def classify_log_file(self, path: str) -> str:
        """Classify a log file as active, rotated, or compressed.

        Args:
            path: Log file path.

        Returns:
            One of "active", "rotated", or "compressed".
        """
        pass


class CloudTrailServiceInterface(ABC):
    """Interface for browsing AWS CloudTrail events."""

    @abstractmethod
    async def lookup_events(
        self,
        region: str = "",
        start_time: Optional[object] = None,
        end_time: Optional[object] = None,
        event_name: str = "",
        username: str = "",
        resource_type: str = "",
        max_results: int = 100,
    ) -> List[dict]:
        """Look up CloudTrail events with filters.

        Returns list of event dicts with keys: event_time, event_name, username,
        source_ip, resource_type, resource_name, region, error_code, raw_event.
        """
        pass

    @abstractmethod
    async def get_available_regions(self) -> List[str]:
        """Get list of AWS regions where CloudTrail is available."""
        pass


class IPBanStrategyInterface(ABC):
    """Interface for a single IP ban strategy (WAF, Security Group, NACL)."""

    @abstractmethod
    async def ban_ip(self, ip_address: str, config: 'IPBanConfig') -> dict:
        """Ban an IP address.

        Args:
            ip_address: IPv4 or IPv6 address to ban.
            config: IPBanConfig with method-specific parameters.

        Returns:
            Dict with keys 'success' (bool) and 'message' (str).
        """
        pass

    @abstractmethod
    async def unban_ip(self, ip_address: str, config: 'IPBanConfig') -> dict:
        """Unban an IP address.

        Args:
            ip_address: IPv4 or IPv6 address to unban.
            config: IPBanConfig with method-specific parameters.

        Returns:
            Dict with keys 'success' (bool) and 'message' (str).
        """
        pass

    @abstractmethod
    async def list_banned(self, config: 'IPBanConfig') -> List[str]:
        """List currently banned IP addresses.

        Args:
            config: IPBanConfig with method-specific parameters.

        Returns:
            List of banned IP address strings (CIDR notation for WAF).
        """
        pass


class IPBanServiceInterface(ABC):
    """Interface for IP ban orchestration across multiple configs."""

    @abstractmethod
    async def ban_ip(self, ip_address: str, config_name: str) -> dict:
        """Ban IP using a named configuration.

        Args:
            ip_address: IPv4 or IPv6 address to ban.
            config_name: Name of the IPBanConfig to use.

        Returns:
            Dict with keys 'success' (bool) and 'message' (str).
        """
        pass

    @abstractmethod
    async def unban_ip(self, ip_address: str, config_name: str) -> dict:
        """Unban IP using a named configuration.

        Args:
            ip_address: IPv4 or IPv6 address to unban.
            config_name: Name of the IPBanConfig to use.

        Returns:
            Dict with keys 'success' (bool) and 'message' (str).
        """
        pass

    @abstractmethod
    async def list_banned(self, config_name: str) -> List[str]:
        """List banned IPs for a named configuration.

        Args:
            config_name: Name of the IPBanConfig to query.

        Returns:
            List of banned IP address strings.
        """
        pass

    @abstractmethod
    def get_configs(self) -> List['IPBanConfig']:
        """Get all IP ban configurations.

        Returns:
            List of IPBanConfig instances from app config.
        """
        pass

    @abstractmethod
    def validate_ip(self, ip_address: str) -> bool:
        """Validate IP address format.

        Args:
            ip_address: String to validate.

        Returns:
            True if valid IPv4 or IPv6 address.
        """
        pass


class AIProviderInterface(ABC):
    """Interface for a single AI provider (OpenAI, Anthropic, Ollama)."""

    @abstractmethod
    async def analyze(self, text: str, system_prompt: str, config: 'AIProviderConfig') -> dict:
        """Send text for AI analysis.

        Returns:
            Dict with keys 'content', 'tokens_used', 'model'.
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if required library (httpx) is installed."""
        pass


class AIAnalysisServiceInterface(ABC):
    """Interface for AI-powered log/text analysis."""

    @abstractmethod
    async def analyze_text(self, text: str, system_prompt: str = "") -> dict:
        """Analyze text using configured AI provider.

        Returns:
            Dict with keys 'content', 'tokens_used', 'model', 'estimated_cost'.
        """
        pass

    @abstractmethod
    def estimate_tokens(self, text: str) -> int:
        """Estimate token count (~4 chars per token)."""
        pass

    @abstractmethod
    def chunk_text(self, text: str, chunk_size: int = 0) -> List[str]:
        """Split text into chunks with overlap."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if AI analysis is available (httpx installed, provider configured)."""
        pass


class CloudWatchServiceInterface(ABC):
    """Interface for browsing AWS CloudWatch Logs."""

    @abstractmethod
    async def list_log_groups(
        self, prefix: str = "", region: str = ""
    ) -> List[Dict]:
        """List CloudWatch log groups with optional prefix filter.

        Returns list of dicts with keys: name, stored_bytes, retention_days.
        """
        pass

    @abstractmethod
    async def get_log_events(
        self,
        log_group: str,
        start_time: object,
        end_time: object,
        filter_pattern: str = "",
        region: str = "",
        max_events: int = 500,
    ) -> List[Dict]:
        """Get filtered log events from a log group.

        Returns list of dicts with keys: timestamp, message, log_stream.
        """
        pass

    @staticmethod
    @abstractmethod
    def extract_top_ips(events: List[Dict], limit: int = 20) -> List[Dict]:
        """Extract and rank top public IPs from log event messages.

        Returns list of dicts with keys: ip, count, sorted by count descending.
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
