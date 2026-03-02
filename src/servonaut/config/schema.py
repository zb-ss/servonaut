"""Configuration schema definitions for Servonaut v2.0."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Optional

CONFIG_VERSION = 2


@dataclass
class ScanRule:
    """Rule for scanning instance filesystems based on instance attributes.

    Attributes:
        name: Descriptive name for the rule
        match_conditions: Dictionary of conditions to match instances
            Example: {"name_contains": "web", "region": "us-east-1"}
        scan_paths: List of paths to scan on matching instances
        scan_commands: List of commands to run on matching instances
    """
    name: str
    match_conditions: Dict[str, str]
    scan_paths: List[str] = field(default_factory=list)
    scan_commands: List[str] = field(default_factory=list)


@dataclass
class ConnectionProfile:
    """SSH connection profile defining bastion/proxy configuration.

    Attributes:
        name: Profile identifier
        bastion_host: Bastion host address (optional)
        bastion_user: Username for bastion connection (optional)
        bastion_key: SSH key for bastion (optional)
        proxy_command: Custom ProxyCommand for SSH (optional)
        ssh_port: SSH port to use (default: 22)
    """
    name: str
    bastion_host: Optional[str] = None
    bastion_user: Optional[str] = None
    bastion_key: Optional[str] = None
    proxy_command: Optional[str] = None
    ssh_port: int = 22


@dataclass
class ConnectionRule:
    """Rule for applying connection profiles to instances.

    Attributes:
        name: Descriptive name for the rule
        match_conditions: Dictionary of conditions to match instances
            Example: {"region": "us-west-2", "name_contains": "private"}
        profile_name: Name of ConnectionProfile to apply
    """
    name: str
    match_conditions: Dict[str, str]
    profile_name: str


@dataclass
class CustomServer:
    """Non-AWS custom server definition.

    Attributes:
        name: Unique server name/identifier
        host: Hostname or IP address
        username: SSH username (default: root)
        ssh_key: Path to SSH key file
        port: SSH port (default: 22)
        provider: Provider label (e.g., 'DigitalOcean', 'Hetzner')
        group: Optional grouping label
        tags: Arbitrary key-value metadata
    """
    name: str
    host: str
    username: str = "root"
    ssh_key: str = ""
    port: int = 22
    provider: str = ""
    group: str = ""
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class IPBanConfig:
    """Configuration for an IP ban method.

    Attributes:
        name: Unique identifier for this ban configuration
        method: Ban method - 'waf', 'security_group', or 'nacl'
        region: AWS region (defaults to us-east-1 if empty)
        ip_set_id: WAF IP set ID (WAF only)
        ip_set_name: WAF IP set name (WAF only)
        waf_scope: WAF scope - 'REGIONAL' or 'CLOUDFRONT' (WAF only)
        security_group_id: Security group ID (security_group only)
        nacl_id: Network ACL ID (nacl only)
        rule_number_start: Starting rule number for NACL entries (nacl only)
    """
    name: str
    method: str  # 'waf', 'security_group', 'nacl'
    region: str = ""
    # WAF-specific
    ip_set_id: str = ""
    ip_set_name: str = ""
    waf_scope: str = "REGIONAL"  # REGIONAL or CLOUDFRONT
    # Security Group-specific
    security_group_id: str = ""
    # NACL-specific
    nacl_id: str = ""
    rule_number_start: int = 100


@dataclass
class AIProviderConfig:
    """AI provider configuration."""
    provider: str = "openai"  # openai, anthropic, ollama
    api_key: str = ""  # supports $ENV_VAR syntax
    model: str = ""  # empty = use provider default
    base_url: str = ""  # for Ollama: http://localhost:11434
    max_tokens: int = 2048
    temperature: float = 0.3


@dataclass
class MCPConfig:
    """MCP server configuration."""
    guard_level: str = "standard"  # readonly, standard, dangerous
    command_blocklist: List[str] = field(default_factory=lambda: [
        r"rm\s+-rf", r"\bdd\b", r"\bmkfs\b", r"\bshutdown\b",
        r"\breboot\b", r"\bfdisk\b", r"\bparted\b", r"\bhalt\b",
        r":\(\)\{", r"\bsudo\s+rm\b",
    ])
    command_allowlist: List[str] = field(default_factory=lambda: [
        "ls", "cat", "grep", "ps", "df", "du", "top", "free",
        "uptime", "whoami", "hostname", "uname", "date", "w",
        "netstat", "ss", "ip", "ifconfig", "ping", "dig", "nslookup",
        "head", "tail", "wc", "sort", "find", "file", "stat",
    ])
    audit_path: str = "~/.servonaut/mcp_audit.jsonl"
    max_output_lines: int = 500


@dataclass
class AppConfig:
    """Main application configuration.

    Attributes:
        version: Config schema version (current: 2)
        default_key: Default SSH key path for all instances
        instance_keys: Instance-specific SSH key mappings {instance_id: key_path}
        default_username: Default SSH username (default: ec2-user)
        cache_ttl_seconds: Instance cache TTL in seconds (default: 300)
        default_scan_paths: Default paths to scan on all instances
        scan_rules: List of conditional scan rules
        connection_profiles: List of SSH connection profiles
        connection_rules: List of rules for applying profiles
        custom_servers: List of non-AWS custom servers
        terminal_emulator: Terminal emulator preference (default: auto)
        keyword_store_path: Path to keyword store file
        theme: UI theme preference (default: dark)
    """
    version: int = CONFIG_VERSION
    default_key: str = ""
    instance_keys: Dict[str, str] = field(default_factory=dict)
    default_username: str = "ec2-user"
    cache_ttl_seconds: int = 3600
    default_scan_paths: List[str] = field(default_factory=lambda: ["~/"])
    scan_rules: List[ScanRule] = field(default_factory=list)
    connection_profiles: List[ConnectionProfile] = field(default_factory=list)
    connection_rules: List[ConnectionRule] = field(default_factory=list)
    custom_servers: List[CustomServer] = field(default_factory=list)
    terminal_emulator: str = "auto"
    keyword_store_path: str = "~/.servonaut/keywords.json"
    command_history_path: str = "~/.servonaut/command_history.json"
    max_command_history: int = 50
    theme: str = "dark"
    log_viewer_default_paths: List[str] = field(default_factory=lambda: [
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/messages",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/mysql/error.log",
        "/var/log/postgresql/postgresql-main.log",
    ])
    log_viewer_custom_paths: Dict[str, List[str]] = field(default_factory=dict)
    log_viewer_scan_directories: List[str] = field(default_factory=lambda: ["/var/log"])
    log_viewer_scan_max_depth: int = 2
    log_viewer_max_lines: int = 10000
    log_viewer_tail_lines: int = 100
    cloudtrail_default_region: str = ""
    cloudtrail_max_events: int = 100
    cloudtrail_default_lookback_hours: int = 24
    cloudwatch_default_region: str = ""
    cloudwatch_max_events: int = 500
    cloudwatch_log_group_prefix: str = ""
    ip_ban_configs: List[IPBanConfig] = field(default_factory=list)
    ip_ban_audit_path: str = "~/.servonaut/ip_ban_audit.json"
    ai_provider: AIProviderConfig = field(default_factory=AIProviderConfig)
    ai_chunk_size: int = 4000
    ai_system_prompt: str = (
        "You are a server log analyst. Analyze the following log output and provide: "
        "1) A summary of what's happening, 2) Any errors or warnings found, "
        "3) Potential issues or security concerns, 4) Recommended actions."
    )
    mcp: MCPConfig = field(default_factory=MCPConfig)
