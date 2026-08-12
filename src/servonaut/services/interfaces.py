"""Abstract base classes for all services in Servonaut v2.0."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Callable, List, Dict, Optional, TYPE_CHECKING

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
        extra_options: Optional[List[str]] = None,
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
            extra_options: Extra ``-o KEY=VALUE`` entries for the target
                connection. From ConnectionService.get_extra_options().

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
        proxy_jump: Optional[str] = None,
        proxy_args: Optional[List[str]] = None,
        port: Optional[int] = None,
        extra_options: Optional[List[str]] = None,
    ) -> List[str]:
        """Build SCP upload command.

        Args:
            local_path: Local file/directory path.
            remote_path: Remote destination path.
            host: Target hostname or IP.
            username: SSH username.
            key_path: Path to SSH key (optional if using agent).
            proxy_jump: ProxyJump string (user@host).
            proxy_args: List of SSH proxy arguments.
            port: SSH port (omitted if None or 22).
            extra_options: Extra ``-o KEY=VALUE`` entries for the target connection.

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
        proxy_jump: Optional[str] = None,
        proxy_args: Optional[List[str]] = None,
        port: Optional[int] = None,
        extra_options: Optional[List[str]] = None,
    ) -> List[str]:
        """Build SCP download command.

        Args:
            remote_path: Remote file/directory path.
            local_path: Local destination path.
            host: Target hostname or IP.
            username: SSH username.
            key_path: Path to SSH key (optional if using agent).
            proxy_jump: ProxyJump string (user@host).
            proxy_args: List of SSH proxy arguments.
            port: SSH port (omitted if None or 22).
            extra_options: Extra ``-o KEY=VALUE`` entries for the target connection.

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
    def get_extra_options(
        self,
        instance: dict,
        profile: Optional[ConnectionProfile] = None,
    ) -> List[str]:
        """Merge extra ``-o KEY=VALUE`` entries from profile and custom server.

        Args:
            instance: Instance dictionary (may include extra_ssh_options).
            profile: Resolved connection profile, or None.

        Returns:
            Flat list of ``KEY=VALUE`` strings (no ``-o`` prefix).
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

    async def chat(
        self,
        messages: List[Dict],
        system_prompt: str,
        config: 'AIProviderConfig',
        tools: Optional[List[Dict]] = None,
    ) -> dict:
        """Multi-turn chat with optional tool calling.

        Default implementation falls back to analyze() with the last user
        message.  Providers override this to support native tool calling.

        Returns:
            Dict with keys: content, tool_calls, tokens_used, input_tokens,
            output_tokens, model, raw_message, stop_reason.
        """
        last_text = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    last_text = content
                break
        result = await self.analyze(last_text or "", system_prompt, config)
        return {
            "content": result.get("content", ""),
            "tool_calls": [],
            "tokens_used": result.get("tokens_used", 0),
            "input_tokens": result.get("input_tokens", 0),
            "output_tokens": result.get("output_tokens", 0),
            "model": result.get("model", ""),
            "raw_message": None,
            "stop_reason": "end_turn",
        }

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


class AuthServiceInterface(ABC):
    """Interface for OAuth2 device flow authentication."""

    @abstractmethod
    async def start_device_flow(self) -> dict:
        pass

    @abstractmethod
    async def poll_for_token(
        self,
        device_code: str,
        interval: int = 5,
        max_wait_seconds: int = 120,
    ) -> bool:
        pass

    @abstractmethod
    async def refresh_token(self) -> bool:
        pass

    @abstractmethod
    async def logout(self) -> None:
        pass

    @property
    @abstractmethod
    def is_authenticated(self) -> bool:
        pass

    @property
    @abstractmethod
    def plan(self) -> str:
        pass

    @abstractmethod
    def has_feature(self, feature: str) -> bool:
        pass

    @abstractmethod
    async def fetch_entitlements(self) -> Optional[dict]:
        pass


class APIClientInterface(ABC):
    """Interface for authenticated HTTP client."""

    @abstractmethod
    async def get(self, path: str, **kwargs) -> dict:
        pass

    @abstractmethod
    async def post(self, path: str, *, json=None, **kwargs) -> dict:
        pass

    @abstractmethod
    async def patch(self, path: str, *, json=None, **kwargs) -> dict:
        pass

    @abstractmethod
    async def delete(self, path: str, **kwargs) -> dict:
        pass

    @abstractmethod
    async def get_bytes(self, path: str, **kwargs) -> tuple:
        pass


class ConfigSyncServiceInterface(ABC):
    """Interface for cloud config sync."""

    @abstractmethod
    async def push(
        self,
        passphrase: Optional[str] = None,
        label: Optional[str] = None,
    ) -> dict:
        pass

    @abstractmethod
    async def pull(self, passphrase: Optional[str] = None) -> dict:
        pass

    @abstractmethod
    async def list_snapshots(self, limit: int = 30) -> List[dict]:
        pass

    @abstractmethod
    async def restore(self, version: int, passphrase: Optional[str] = None) -> dict:
        pass

    @abstractmethod
    async def rename_snapshot(self, snapshot_id: str, label: str) -> dict:
        pass

    @abstractmethod
    async def delete_snapshot(self, snapshot_id: str) -> dict:
        pass


class CloudServiceInterface(ABC):
    """Interface for cloud provider instance services (GCP, Azure)."""

    @abstractmethod
    async def fetch_instances(self) -> List[dict]:
        pass


class TeamServiceInterface(ABC):
    """Interface for team management."""

    @abstractmethod
    async def list_teams(self) -> List[dict]:
        pass

    @abstractmethod
    async def get_team(self, slug: str) -> dict:
        pass

    @abstractmethod
    async def create_team(self, name: str) -> dict:
        pass

    @abstractmethod
    async def invite_member(self, slug: str, email: str, role: str = "member") -> dict:
        pass

    @abstractmethod
    async def remove_member(self, slug: str, member_id: str) -> dict:
        pass

    @abstractmethod
    async def update_role(self, slug: str, member_id: str, role: str) -> dict:
        pass

    @abstractmethod
    async def resend_invite(self, slug: str, member_id: str) -> dict:
        pass

    @abstractmethod
    async def list_shared_servers(self, slug: str) -> List[dict]:
        pass

    @abstractmethod
    async def push_server(self, slug: str, server_data: dict) -> dict:
        pass

    @abstractmethod
    async def list_team_configs(self, slug: str) -> List[dict]:
        pass

    @abstractmethod
    async def get_latest_team_config(self, slug: str) -> Optional[dict]:
        pass

    @abstractmethod
    async def push_team_config(
        self, slug: str, config_data: dict, description: Optional[str] = None
    ) -> dict:
        pass

    @abstractmethod
    async def get_team_ssh_config(self, slug: str) -> Optional[dict]:
        pass

    @abstractmethod
    async def put_team_ssh_config(
        self,
        slug: str,
        vault_url: str,
        default_collection_id: Optional[str] = None,
        provider: str = "bitwarden_pm",
    ) -> dict:
        pass

    @abstractmethod
    async def get_team_server_ssh_ref(self, slug: str, server_id: str) -> Optional[dict]:
        pass

    @abstractmethod
    async def put_team_server_ssh_ref(
        self,
        slug: str,
        server_id: str,
        ssh_credential_ref: dict,
        ssh_credential_provider: str = "bitwarden_pm",
    ) -> dict:
        pass

    @abstractmethod
    async def delete_team_server_ssh_ref(self, slug: str, server_id: str) -> bool:
        pass

    @abstractmethod
    async def get_team_server_ssh_verify_status(
        self, slug: str, server_id: str
    ) -> Optional[dict]:
        pass

    @abstractmethod
    async def report_team_server_ssh_verify(
        self,
        slug: str,
        server_id: str,
        status: str,
        checked_by_client: Optional[str] = None,
    ) -> dict:
        pass


class RemoteAuditServiceInterface(ABC):
    """Interface for remote audit trail."""

    @abstractmethod
    async def log_event(self, event_type: str, details: dict) -> None:
        pass

    @abstractmethod
    async def flush_queue(self) -> int:
        pass


# Defence-in-depth caps applied by every :class:`SecretProviderInterface`
# implementation BEFORE the backend is touched. The values are bounded
# above by Bitwarden's documented per-secret limits — staying under
# them at the CLI layer means our error messages can be specific
# instead of relaying a bws "bad request" with a coarse message.
#
# A future provider that needs different limits (Vault, 1Password) can
# override them per-instance, but the defaults reflect the smallest
# backend's ceiling so cross-provider portability is automatic.
SECRET_NAME_MAX_LENGTH = 256
SECRET_VALUE_MAX_LENGTH = 65_536  # 64 KiB


def _validate_secret_name(name: str) -> str:
    """Reject empty / oversize / non-string names with a clear error.

    Centralised here so every provider gets identical input validation
    — important for portability (set in LocalProvider, get from
    BitwardenProvider after a migration should observe the same
    rejection rules).
    """
    if not isinstance(name, str):
        raise TypeError(
            f"secret name must be a string; got {type(name).__name__}"
        )
    if not name:
        raise ValueError("secret name must be non-empty")
    if len(name) > SECRET_NAME_MAX_LENGTH:
        raise ValueError(
            f"secret name must be ≤ {SECRET_NAME_MAX_LENGTH} chars; "
            f"got {len(name)}"
        )
    return name


def _validate_secret_value(value: str) -> str:
    """Reject oversize / non-string values.

    Empty string IS allowed — some users genuinely want to set a
    secret to the empty string to represent "explicitly cleared".
    """
    if not isinstance(value, str):
        raise TypeError(
            f"secret value must be a string; got {type(value).__name__}"
        )
    if len(value) > SECRET_VALUE_MAX_LENGTH:
        raise ValueError(
            f"secret value must be ≤ {SECRET_VALUE_MAX_LENGTH} bytes; "
            f"got {len(value)}"
        )
    return value


class BwSshConfigServiceInterface(ABC):
    """Interface for personal SSH config + per-instance ref endpoints.

    See :mod:`servonaut.services.bw_ssh_config_service` for the locked wire
    contract (2026-05-24 with servonaut.dev).
    """

    @abstractmethod
    async def get_personal_config(self) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def put_personal_config(
        self,
        vault_url: str,
        default_collection_id: Optional[str] = None,
        provider: str = "bitwarden_pm",
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def list_personal_instances(self) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    async def put_personal_instance_ref(
        self,
        provider: str,
        instance_id: str,
        ssh_credential_ref: Dict[str, Any],
        ssh_credential_provider: str = "bitwarden_pm",
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def delete_personal_instance_ref(
        self, provider: str, instance_id: str
    ) -> bool:
        pass

    @abstractmethod
    async def get_personal_instance_ref(
        self, provider: str, instance_id: str
    ) -> Optional[Dict[str, Any]]:
        """GET /api/v1/me/instances/{provider}/{instance_id}/ssh-ref.

        Returns ``{"ssh_credential_provider": ..., "ssh_credential_ref": {...}}``
        on 200, or ``None`` on 404 (no ref stored).
        """
        pass

    @abstractmethod
    async def get_personal_instance_verify_status(
        self, provider: str, instance_id: str
    ) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def report_personal_instance_verify(
        self,
        provider: str,
        instance_id: str,
        status: str,
        checked_by_client: Optional[str] = None,
    ) -> Dict[str, Any]:
        pass


class SecretProviderInterface(ABC):
    """Abstract surface for the secrets-management feature.

    Concrete providers (``LocalProvider``, ``BitwardenProvider``, …) wrap a
    backend (local filesystem, Bitwarden Secrets Manager, etc.) behind a
    single CRUD-shaped contract. ``ssh_service`` and any other consumer that
    needs to resolve a named secret reaches through this interface, never
    the underlying backend, so the active provider can be swapped per team
    via the server-side :class:`TeamSecretsConfig` without touching the
    call sites.

    MCP boundary sentinel:
        ``_servonaut_secret_boundary = True`` is a class-level marker
        the future MCP tool registry will inspect. Any MCP tool whose
        argument or return type ultimately resolves to a
        :class:`SecretProviderInterface` (or its outputs) must be
        rejected at registration time — secret VALUES cannot cross
        the MCP boundary, only NAMES. This sentinel is the
        machine-readable hook so the check survives every refactor
        without relying on developers remembering a docstring rule.

    The server-side contract is:

    - **Async by default** so providers that talk to a remote backend
      (Bitwarden, future Vault) don't block the TUI event loop. The
      ``LocalProvider`` is async-shaped even though its IO is purely
      local — calling-site uniformity matters more than the trivial
      ``await`` overhead.
    - **Secret names are stable, opaque, case-sensitive identifiers**.
      Providers must NOT silently canonicalise (lowercase, strip,
      collapse separators); two callers with different spellings see
      two different secrets.
    - **The value returned by :meth:`get_secret` is the raw secret string**.
      Callers are responsible for whatever wrapping is appropriate
      (file write with 0600 perms, in-memory only, etc.).
    - **MCP boundary**: this interface and its consumers MUST NEVER let
      a secret value cross the MCP tool boundary. Tools may reference
      secret NAMES only; the executor on the receiving end resolves
      via the provider itself. The MCP audit log records the name, not
      the value.
    """

    #: Machine-readable marker the future MCP tool registry inspects
    #: to refuse any tool wiring that would let a secret value cross
    #: the MCP boundary. See class docstring.
    _servonaut_secret_boundary: bool = True

    @abstractmethod
    async def get_secret(self, name: str) -> Optional[str]:
        """Resolve ``name`` to its plaintext value.

        Returns ``None`` when the secret is not present in this backend.
        Raises only on transport / authentication failures the caller
        should surface (network down, BWS token rejected, etc.) — a
        missing secret is NOT an exceptional condition.
        """
        pass

    @abstractmethod
    async def set_secret(self, name: str, value: str) -> None:
        """Persist ``name`` → ``value`` in the backend.

        Idempotent: setting a name that already exists overwrites its
        value. Concurrent writes are last-write-wins at this layer;
        backends with stronger guarantees may layer them on top.
        """
        pass

    @abstractmethod
    async def delete_secret(self, name: str) -> bool:
        """Remove ``name`` from the backend.

        Returns ``True`` if a secret was removed, ``False`` if it
        wasn't there to begin with. Idempotent: callers MUST NOT
        treat ``False`` as an error.
        """
        pass

    @abstractmethod
    async def list_secrets(self) -> List[str]:
        """Enumerate the names of every secret in this backend.

        Returns a sorted list (deterministic so callers can diff
        snapshots). Empty backend returns ``[]``, never ``None``.

        SECURITY: this method MUST NOT return any values, ever — even
        if the underlying backend would happily ship them inline.
        Listing names is a routine introspection action that runs at
        lower privilege than ``get_secret``; do not amplify the blast
        radius by piggybacking values onto the listing.
        """
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Short stable identifier — ``"local"``, ``"bitwarden"``, …

        Matches the ``provider`` field in the server-side
        :class:`TeamSecretsConfig` and the CLI's :class:`SecretsConfig`
        dataclass. Used for audit logs, status display, and dispatch.
        """
        pass


class ObjectStorageServiceInterface(ABC):
    """Interface for S3-compatible object storage operations.

    Implemented by :class:`servonaut.services.object_storage_service.ObjectStorageService`.
    All methods are async and delegate blocking boto3 calls via
    ``asyncio.to_thread``.  Credentials are ALREADY resolved by the caller
    (``$ENV_VAR`` expanded) before the service is constructed.
    """

    @abstractmethod
    async def list_buckets(self) -> List[Dict[str, Any]]:
        """List all buckets accessible with the configured credentials.

        Returns:
            List of dicts with keys: ``name`` (str), ``creation_date`` (str).
        """
        pass

    @abstractmethod
    async def create_bucket(self, bucket: str, region: str = "") -> None:
        """Create a new bucket.

        Args:
            bucket: Bucket name to create.
            region: Region to create the bucket in.  Empty → the region the
                service was configured with.  Providers whose region is pinned
                by a configured endpoint URL reject a differing override.

        Raises:
            ValueError: If *bucket* or *region* fails validation.
        """
        pass

    @abstractmethod
    async def delete_bucket(self, bucket: str, region: str = "") -> None:
        """Delete a bucket.  The bucket must be empty.

        Args:
            bucket: Name of the bucket to delete.
            region: Region the bucket lives in.  Empty → the configured
                region, with a redirect when it is wrong.

        Raises:
            ValueError: If *bucket* fails validation.
        """
        pass

    @abstractmethod
    async def list_objects(
        self,
        bucket: str,
        prefix: str = "",
        delimiter: str = "/",
        region: str = "",
    ) -> Dict[str, Any]:
        """List objects and common-prefix "folders" inside *bucket*.

        Args:
            bucket: Target bucket name.
            prefix: Key prefix to filter results (e.g. ``"images/"``).
            delimiter: Hierarchy delimiter (default ``"/"``).
            region: Region the bucket lives in.  Empty → the configured
                region, with a redirect when it is wrong.

        Returns:
            Dict with keys:

            - ``"folders"`` — ``List[str]``: common-prefix strings
              (virtual folder names).
            - ``"objects"`` — ``List[Dict]``: each entry has keys
              ``"key"`` (str), ``"size"`` (int, bytes),
              ``"last_modified"`` (str ISO-8601).
            - ``"is_truncated"`` — ``bool``: True when more than 1000
              keys match (single S3 page; pagination is a future task).
        """
        pass

    @abstractmethod
    async def upload_object(
        self,
        bucket: str,
        key: str,
        local_path: str,
        region: str = "",
    ) -> None:
        """Upload a local file to *bucket* at *key*.

        Args:
            bucket: Target bucket name.
            key: Destination object key.
            local_path: Absolute path to the local file.
            region: Region the bucket lives in.  Empty → the configured
                region, with a redirect when it is wrong.

        Raises:
            ValueError: If any argument fails validation.
        """
        pass

    @abstractmethod
    async def download_object(
        self,
        bucket: str,
        key: str,
        local_path: str,
        region: str = "",
    ) -> None:
        """Download an object from *bucket*/*key* to *local_path*.

        Args:
            bucket: Source bucket name.
            key: Object key to download.
            local_path: Absolute path where the file will be written.
            region: Region the bucket lives in.  Empty → the configured
                region, with a redirect when it is wrong.

        Raises:
            ValueError: If any argument fails validation.
        """
        pass

    @abstractmethod
    async def delete_object(self, bucket: str, key: str, region: str = "") -> None:
        """Delete a single object.

        Args:
            bucket: Bucket containing the object.
            key: Object key to delete.
            region: Region the bucket lives in.  Empty → the configured
                region, with a redirect when it is wrong.

        Raises:
            ValueError: If *bucket* or *key* fails validation.
        """
        pass

    @abstractmethod
    async def copy_object(
        self,
        src_bucket: str,
        src_key: str,
        dst_bucket: str,
        dst_key: str,
        region: str = "",
    ) -> None:
        """Server-side copy of an object.

        Args:
            src_bucket: Source bucket name.
            src_key: Source object key.
            dst_bucket: Destination bucket name.
            dst_key: Destination object key.
            region: Region *dst_bucket* lives in — a cross-region copy is
                driven from the destination side.

        Raises:
            ValueError: If any argument fails validation.
        """
        pass

    @abstractmethod
    async def move_object(
        self,
        src_bucket: str,
        src_key: str,
        dst_bucket: str,
        dst_key: str,
        region: str = "",
        src_region: str = "",
    ) -> None:
        """Move an object (server-side copy then delete source).

        Args:
            src_bucket: Source bucket name.
            src_key: Source object key.
            dst_bucket: Destination bucket name.
            dst_key: Destination object key.
            region: Region *dst_bucket* lives in (drives the copy leg).
            src_region: Region *src_bucket* lives in (drives the delete leg).

        Raises:
            ValueError: If any argument fails validation.
        """
        pass

    @abstractmethod
    async def generate_presigned_url(
        self,
        bucket: str,
        key: str,
        expires_in: int = 3600,
        region: str = "",
    ) -> str:
        """Generate a pre-signed URL for temporary public access to an object.

        Args:
            bucket: Bucket containing the object.
            key: Object key.
            expires_in: Expiry in seconds (1–604800, default 3600).
            region: Region the bucket lives in.  Empty → resolved for the
                caller, since SigV4 binds the region into the signature and a
                mismatch produces a URL that fails when opened.

        Returns:
            Pre-signed URL string.

        Raises:
            ValueError: If any argument fails validation.
        """
        pass


class VoiceInputServiceInterface(ABC):
    """Interface for microphone capture and local speech-to-text.

    Optional frame-tap protocol (duck-typed, not abstract): an engine
    that wants to power hands-free conversation mode additionally
    provides ``set_frame_callback(callback | None)`` — a tap that hands
    every captured mono float32 audio block to the callback for
    voice-activity detection, surviving past the recording cap so
    detection keeps running during long turns — and
    ``reset_recording_budget()``, which re-arms ``max_recording_seconds``
    when a listening session rolls into a new turn. The conversation
    loop probes for these with ``hasattr`` and degrades with a
    user-facing hint when they are missing, so an implementation without
    them still satisfies this interface for push-to-talk dictation; it
    just cannot host the hands-free loop. They are deliberately not
    ``@abstractmethod``s: making them abstract would break third-party
    engines, and providing concrete defaults would defeat the
    ``hasattr`` capability probe.
    """

    @abstractmethod
    def is_available(self) -> bool:
        """Check if voice input can be used right now.

        Returns:
            True only when the optional audio/transcription libraries are
            importable AND at least one input device is present.
        """
        pass

    @abstractmethod
    def unavailable_reason(self) -> str:
        """Explain why voice input cannot be used.

        Returns:
            Short, actionable message for the UI, or an empty string when
            voice input is available.
        """
        pass

    @abstractmethod
    def start_recording(self) -> None:
        """Begin capturing microphone audio into an in-memory buffer.

        Raises:
            VoiceInputError: If a recording is already in progress, voice
                input is unavailable, or the audio device cannot be opened.
        """
        pass

    @abstractmethod
    def stop_and_transcribe(self, initial_prompt: str = "") -> str:
        """Stop capturing and transcribe the buffered audio.

        Args:
            initial_prompt: Optional vocabulary hint (e.g. server names)
                used to bias recognition of proper nouns.

        Returns:
            Transcribed text, or an empty string when the recording was
            too short to transcribe.

        Raises:
            VoiceInputError: If transcription fails.
        """
        pass

    @abstractmethod
    def cancel_recording(self) -> None:
        """Stop capturing and discard the buffer without transcribing."""
        pass

    @property
    @abstractmethod
    def is_recording(self) -> bool:
        """Whether a recording is currently in progress."""
        pass

    @property
    @abstractmethod
    def hit_recording_cap(self) -> bool:
        """Whether the last transcription's audio was cut off by the cap."""
        pass


class VoiceOutputServiceInterface(ABC):
    """Interface for local speech synthesis and playback of reply text."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if spoken replies can be produced right now.

        Returns:
            True only when the optional synthesis libraries are importable,
            the speech model is on disk, AND at least one output device is
            present.
        """
        pass

    @abstractmethod
    def unavailable_reason(self) -> str:
        """Explain why spoken replies cannot be produced.

        Returns:
            Short, actionable message for the UI, or an empty string when
            voice output is available.
        """
        pass

    @abstractmethod
    def speak(self, text: str, *, epoch: Optional[int] = None) -> None:
        """Synthesise *text* and play it, blocking until playback finishes.

        Blocks for the whole synthesis and playback (and, on the first
        call, the model load), so callers must run it in a worker thread —
        never on the UI event loop.

        Args:
            text: Text to read aloud. Cleaned for speech before synthesis;
                text with nothing speakable left is a silent no-op.
            epoch: Cancellation token from :meth:`current_epoch`, captured
                before this call was scheduled on another thread. When a
                :meth:`stop` has landed since, the utterance is silently
                dropped. ``None`` pins the epoch when the call arrives.

        Raises:
            VoiceOutputError: If synthesis or playback fails.
        """
        pass

    @abstractmethod
    def enqueue(self, sentence: str, *, epoch: Optional[int] = None) -> None:
        """Queue *sentence* for playback without waiting for it.

        Sentences play in the order they were queued. Failures are logged
        rather than raised — a fire-and-forget path has no caller left to
        catch them.

        Args:
            sentence: Text to read aloud after everything already queued.
            epoch: Cancellation token from :meth:`current_epoch`; see
                :meth:`speak`.
        """
        pass

    @abstractmethod
    def begin_utterance(
        self,
        *,
        on_complete: Optional[Callable[[bool], None]] = None,
        epoch: Optional[int] = None,
    ) -> Any:
        """Open a streamed-utterance session for one reply's sentences.

        The streaming counterpart of one :meth:`speak` call. The
        returned session exposes ``enqueue(sentence)`` (fire-and-forget,
        ordered behind the session's earlier sentences) and ``end()``
        (the stream is over). ``on_complete`` fires EXACTLY once per
        session: with ``played_to_end=True`` when every enqueued
        sentence finished playing after ``end()``, or with ``False`` the
        moment a :meth:`stop` supersedes the session — whether or not
        ``end()`` was called — so an interrupted stream can never strand
        its consumer. Invoked from an internal thread; UI consumers must
        marshal.

        Args:
            on_complete: The exactly-once completion callback.
            epoch: Cancellation token from :meth:`current_epoch`; a
                stale token yields a session that is born superseded
                (completion fires ``False`` immediately). ``None`` pins
                the epoch at entry.

        Returns:
            The session object. Never raises.
        """
        pass

    @abstractmethod
    def current_epoch(self) -> int:
        """Cancellation token for a speak/enqueue scheduled on another thread.

        Snapshot before handing a :meth:`speak` off to a thread pool and
        pass it as ``epoch``: a :meth:`stop` landing while the hand-off is
        in flight then retires the utterance instead of racing it.

        Returns:
            The current cancellation epoch.
        """
        pass

    @abstractmethod
    def stop(self) -> None:
        """Discard everything queued and stop playback promptly.

        Safe to call from any thread and never raises — it is the cancel
        path for every failure route.
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """Shut the service down for good when it is being replaced.

        Stops playback and releases the background worker and any loaded
        synthesis engine. Idempotent, safe from any thread, never raises.
        A closed service silently drops further speak/enqueue calls.
        """
        pass

    @abstractmethod
    def is_speaking(self) -> bool:
        """Whether anything is currently being synthesised, played, or queued.

        Returns:
            True while audible output is in progress or pending.
        """
        pass


class VoiceConversationServiceInterface(ABC):
    """Interface for the hands-free conversation loop controller.

    A state machine over IDLE / LISTENING / THINKING / SPEAKING that
    composes the capture, voice-activity, and speech-output services; it
    owns no audio code itself. Half-duplex by contract: the microphone is
    fully closed while a reply is being produced or spoken. The one
    opt-in exception is barge-in (``voice.barge_in``, headphones mode):
    during SPEAKING a detection-only capture feeds the voice-activity
    monitor — never transcription — and sustained speech drives
    :meth:`interrupt`. With the flag off (the default) the strict
    contract holds unchanged.

    Threading contract: every method is thread-safe and may be called
    from any thread. Every registered callback is invoked from an
    internal worker thread or from whichever thread drove the transition
    — never guaranteed to be the UI thread — so UI layers must marshal
    onto their own event loop (``App.call_from_thread``). Methods that
    close a running capture (``stop``, ``reply_started``, ``interrupt``)
    can block briefly while the stream tears down; prefer calling them
    from a worker.
    """

    @property
    @abstractmethod
    def state(self):
        """The loop's current state (a ``ConversationState`` member)."""
        pass

    @abstractmethod
    def start(self) -> None:
        """Begin the loop: IDLE -> LISTENING.

        Validates prerequisites synchronously; the microphone opens on an
        internal thread so a first-use model load never blocks the
        caller. Failures after this returns arrive via the error
        callback.

        Raises:
            VoiceConversationError: If the loop is already active, no
                capture service is available, the engine lacks a frame
                tap, or the voice-activity model is missing.
        """
        pass

    @abstractmethod
    def stop(self, *, join: bool = True) -> None:
        """End the loop from any state: -> IDLE. Never raises.

        Reports IDLE with the "user" stop reason; a no-op when already
        idle. ``join=False`` skips the bounded wait for the listening
        thread — for callers on a UI thread that must never block on a
        transcription in flight.
        """
        pass

    @abstractmethod
    def interrupt(self) -> None:
        """Cut the assistant short and listen again. Never raises.

        SPEAKING: stops playback and reopens the mic. THINKING: abandons
        the pending reply state-side (the UI owns cancelling its own
        request) and reopens the mic. No-op in IDLE and LISTENING.
        """
        pass

    @abstractmethod
    def reply_started(self) -> None:
        """UI signal that a chat turn is in flight: LISTENING/SPEAKING -> THINKING.

        Closes the mic for sends the loop did not initiate; from SPEAKING
        it also cuts the superseded reply's playback short. A no-op in
        every other state.
        """
        pass

    @abstractmethod
    def reply_finished(self) -> None:
        """UI signal that the reply completed with nothing to speak.

        THINKING -> LISTENING; a no-op in every other state.
        """
        pass

    @abstractmethod
    def speaking_started(self) -> None:
        """UI signal that reply playback began: THINKING -> SPEAKING.

        A no-op in every other state.
        """
        pass

    @abstractmethod
    def speaking_finished(self) -> None:
        """UI signal that playback fully drained: SPEAKING -> LISTENING.

        A no-op in every other state.
        """
        pass

    @abstractmethod
    def set_state_callback(self, callback: Optional[Callable[[Any], None]]) -> None:
        """Register a callback fired on every state transition."""
        pass

    @abstractmethod
    def set_transcript_callback(
        self, callback: Optional[Callable[[str], None]]
    ) -> None:
        """Register a callback fired with each non-empty utterance transcript."""
        pass

    @abstractmethod
    def set_error_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        """Register a callback fired when a running loop fails."""
        pass

    @abstractmethod
    def set_stopped_callback(self, callback: Optional[Callable[[str], None]]) -> None:
        """Register a callback fired with a reason whenever the loop lands in IDLE."""
        pass
