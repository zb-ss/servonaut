"""Ordered catalog of settings panels (groups + search keywords + factory).

Each :class:`PanelSpec` factory LAZILY imports its panel class so importing
this module does not import every panel eagerly — a broken or not-yet-built
panel only fails when the shell actually instantiates it, and the shell wraps
that in a per-panel try/except.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List

from servonaut.screens.settings.base import SettingsPanel


@dataclass(frozen=True)
class PanelSpec:
    """Static metadata for one settings panel.

    Attributes:
        id: Stable panel id (matches ``SettingsPanel.PANEL_ID`` and nav button
            id suffix ``navbtn_{id}``).
        title: Human-readable nav label / panel header.
        group: Section heading the nav button lives under.
        keywords: Extra search terms (besides the title) the search box matches.
        factory: Zero-arg callable returning the panel class. Imports lazily.
        preview: When True, the nav button gets a "· preview" tag — the feature
            is scaffolded but not yet live (its panel shows a preview banner).
    """

    id: str
    title: str
    group: str
    keywords: List[str] = field(default_factory=list)
    factory: Callable[[], type[SettingsPanel]] = None  # type: ignore[assignment]
    preview: bool = False


def _panel(module: str, cls: str) -> Callable[[], type[SettingsPanel]]:
    """Build a lazy factory importing *cls* from ``settings.panels.{module}``."""
    return lambda: getattr(
        __import__(
            f"servonaut.screens.settings.panels.{module}",
            fromlist=[cls],
        ),
        cls,
    )


# Ordered panel catalog. Groups mirror the build spec's Panel Catalog exactly.
PANELS: List[PanelSpec] = [
    # ---------------------------------------------------------------- General
    PanelSpec(
        id="general",
        title="General",
        group="General",
        keywords=["username", "key", "cache", "ttl", "terminal", "theme"],
        factory=_panel("general", "GeneralPanel"),
    ),
    PanelSpec(
        id="history_paths",
        title="History & Paths",
        group="General",
        keywords=["keywords", "command", "history", "chat", "paths", "store"],
        factory=_panel("history_paths", "HistoryPathsPanel"),
    ),
    # ------------------------------------------------------------ Connections
    PanelSpec(
        id="scan",
        title="Scan",
        group="Connections",
        keywords=["scan", "paths", "rules", "keyword", "commands"],
        factory=_panel("scan", "ScanPanel"),
    ),
    PanelSpec(
        id="connections",
        title="Connections",
        group="Connections",
        keywords=["profiles", "rules", "bastion", "proxy", "ssh", "port"],
        factory=_panel("connections", "ConnectionsPanel"),
    ),
    PanelSpec(
        id="custom_servers",
        title="Custom Servers",
        group="Connections",
        keywords=["custom", "servers", "non-aws", "hosts", "provider"],
        factory=_panel("custom_servers", "CustomServersPanel"),
    ),
    PanelSpec(
        id="ssh_keys",
        title="SSH Keys",
        group="Connections",
        keywords=["ssh", "keys", "instance", "default", "key", "pem"],
        factory=_panel("ssh_keys", "SshKeysPanel"),
    ),
    # ------------------------------------------------------- Cloud Providers
    PanelSpec(
        id="aws",
        title="AWS",
        group="Cloud Providers",
        keywords=["aws", "ec2", "region", "s3", "object", "storage",
                  "control-plane", "role", "arn"],
        factory=_panel("aws", "AwsPanel"),
    ),
    PanelSpec(
        id="ovh",
        title="OVHcloud",
        group="Cloud Providers",
        keywords=["ovh", "ovhcloud", "cloud", "vps", "dedicated", "s3", "cost"],
        factory=_panel("ovh", "OvhPanel"),
    ),
    PanelSpec(
        id="hetzner",
        title="Hetzner",
        group="Cloud Providers",
        keywords=["hetzner", "cloud", "server", "image", "location", "s3", "cost"],
        factory=_panel("hetzner", "HetznerPanel"),
    ),
    PanelSpec(
        id="gcp",
        title="Google Cloud",
        group="Cloud Providers",
        keywords=["gcp", "google", "compute", "project", "zone", "credentials",
                  "preview"],
        factory=_panel("gcp", "GcpPanel"),
        preview=True,
    ),
    PanelSpec(
        id="azure",
        title="Azure",
        group="Cloud Providers",
        keywords=["azure", "vm", "subscription", "resource", "group", "preview"],
        factory=_panel("azure", "AzurePanel"),
        preview=True,
    ),
    # --------------------------------------------------- Security & Network
    PanelSpec(
        id="ip_ban",
        title="IP Ban",
        group="Security & Network",
        keywords=["ip", "ban", "waf", "security", "group", "nacl", "block"],
        factory=_panel("ip_ban", "IpBanPanel"),
    ),
    PanelSpec(
        id="ip_lookup",
        title="IP Lookup",
        group="Security & Network",
        keywords=["abuseipdb", "ip", "lookup", "reputation", "geolocation", "abuse"],
        factory=_panel("ip_lookup", "IpLookupPanel"),
    ),
    PanelSpec(
        id="cloudtrail",
        title="CloudTrail",
        group="Security & Network",
        keywords=["cloudtrail", "region", "events", "lookback", "audit"],
        factory=_panel("cloudtrail", "CloudtrailPanel"),
    ),
    PanelSpec(
        id="cloudwatch",
        title="CloudWatch",
        group="Security & Network",
        keywords=["cloudwatch", "logs", "region", "events", "log group", "prefix"],
        factory=_panel("cloudwatch", "CloudwatchPanel"),
    ),
    PanelSpec(
        id="log_viewer",
        title="Log Viewer",
        group="Security & Network",
        keywords=["log", "viewer", "paths", "tail", "lines", "scan", "depth"],
        factory=_panel("log_viewer", "LogViewerPanel"),
    ),
    PanelSpec(
        id="mcp",
        title="MCP Server",
        group="Security & Network",
        keywords=["mcp", "guard", "allowlist", "blocklist", "audit", "agents"],
        factory=_panel("mcp", "McpPanel"),
    ),
    PanelSpec(
        id="relay",
        title="Relay",
        group="Security & Network",
        keywords=["relay", "mercure", "heartbeat", "listener", "auto-approve"],
        factory=_panel("relay", "RelayPanel"),
    ),
    # ------------------------------------------------------------------- AI
    PanelSpec(
        id="ai_provider",
        title="AI Provider",
        group="AI",
        keywords=["ai", "provider", "openai", "anthropic", "gemini", "ollama",
                  "model", "api key", "temperature"],
        factory=_panel("ai_provider", "AiProviderPanel"),
    ),
    PanelSpec(
        id="ai_chat",
        title="AI Chat",
        group="AI",
        keywords=["ai", "chat", "prompt", "tool", "iterations", "guard", "memory"],
        factory=_panel("ai_chat", "AiChatPanel"),
    ),
    # ------------------------------------------------------- Memory & Sync
    PanelSpec(
        id="memory",
        title="Memory",
        group="Memory & Sync",
        keywords=["memory", "redaction", "modules", "ttl", "findings", "snapshot"],
        factory=_panel("memory", "MemoryPanel"),
    ),
    PanelSpec(
        id="memory_sync",
        title="Memory Sync",
        group="Memory & Sync",
        keywords=["memory", "sync", "digest", "mercure", "consent", "cloud"],
        factory=_panel("memory_sync", "MemorySyncPanel"),
    ),
    PanelSpec(
        id="bw_ssh",
        title="Bitwarden SSH",
        group="Memory & Sync",
        keywords=["bitwarden", "ssh", "vault", "collection", "secrets"],
        factory=_panel("bw_ssh", "BwSshPanel"),
    ),
    PanelSpec(
        id="backups",
        title="Backups",
        group="Memory & Sync",
        keywords=["backups", "snapshots", "restore", "config", "sync"],
        factory=_panel("backups", "BackupsPanel"),
    ),
]
