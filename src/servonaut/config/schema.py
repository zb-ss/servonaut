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
    terminal_emulator: str = "auto"
    keyword_store_path: str = "~/.servonaut/keywords.json"
    command_history_path: str = "~/.servonaut/command_history.json"
    max_command_history: int = 50
    theme: str = "dark"
