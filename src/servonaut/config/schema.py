"""Configuration schema definitions for Servonaut v2.0."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, List, Dict, Optional

logger = logging.getLogger(__name__)

CONFIG_VERSION = 5

# Known :class:`SecretProviderInterface` implementations the CLI
# recognises. Any value outside this set, however received (server
# bug, malicious downgrade attack, future provider added on the
# server before the CLI ships a matching release), gets coerced
# down to the always-safe ``"local"`` fallback with a WARNING log.
# Defence-in-depth: even if the server is compromised it cannot
# trick the CLI into instantiating an arbitrary provider name
# downstream.
_KNOWN_SECRET_PROVIDERS: frozenset = frozenset({"local", "bitwarden"})


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
        username: SSH username for the target host (optional, overrides default_username)
        proxy_command: Custom ProxyCommand for SSH (optional)
        ssh_port: SSH port to use (default: 22)
        extra_ssh_options: Extra ``-o KEY=VALUE`` pairs applied to the target
            SSH connection. Each entry is the ``KEY=VALUE`` string without the
            leading ``-o``. Useful for legacy hosts that need, e.g.,
            ``HostKeyAlgorithms=+ssh-rsa`` or custom ``ServerAliveInterval``.
    """
    name: str
    bastion_host: Optional[str] = None
    bastion_user: Optional[str] = None
    bastion_key: Optional[str] = None
    username: Optional[str] = None
    proxy_command: Optional[str] = None
    ssh_port: int = 22
    extra_ssh_options: List[str] = field(default_factory=list)


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
        extra_ssh_options: Extra ``-o KEY=VALUE`` pairs applied to the target
            SSH/SCP connection. Useful for legacy hosts requiring
            ``HostKeyAlgorithms=+ssh-rsa`` or similar overrides.
    """
    name: str
    host: str
    username: str = "root"
    ssh_key: str = ""
    port: int = 22
    provider: str = ""
    group: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    extra_ssh_options: List[str] = field(default_factory=list)


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
class DBProfile:
    """Database connection profile for the ``db_processlist`` / ``db_top_queries`` tools.

    The credential never lives in this dataclass. ``password_secret`` is the
    *name* of a secret in the user's active secret store (LocalProvider or
    Bitwarden — whichever ``resolve_secret_provider`` returns); the tool
    resolves it at call time and passes it to the on-box DB client via an
    environment variable (``MYSQL_PWD`` / ``PGPASSWORD``), never on argv.

    Attributes:
        instance: Instance id or name this profile applies to (matched
            case-insensitively against both, like ``_find_instance``).
        engine: ``"mysql"`` (covers MariaDB) or ``"postgres"``.
        host: DB host as seen *from the box* (usually ``127.0.0.1`` or an
            RDS endpoint reachable from the instance).
        port: DB port (3306 mysql / 5432 postgres).
        user: DB username.
        password_secret: Name of the password secret in the active secret
            store. Empty means "no password" (socket / trust / IAM auth).
        database: Optional default database to connect to.
    """
    instance: str
    engine: str = "mysql"  # mysql | postgres
    host: str = "127.0.0.1"
    port: int = 3306
    user: str = "root"
    password_secret: str = ""
    database: str = ""


@dataclass
class AIProviderConfig:
    """AI provider configuration.

    Attributes:
        provider: Default provider when no explicit preference applies. One of
            ``"openai"``, ``"anthropic"``, ``"ollama"``, ``"gemini"``,
            ``"servonaut"``.
        api_key: Per-provider API key (supports ``$ENV_VAR`` syntax). Not used
            by the ``servonaut`` provider — that one auths via OAuth bearer.
        model: Override of the per-provider default model. Empty string means
            "use provider default".
        base_url: Override of the per-provider base URL (e.g. Ollama's
            ``http://localhost:11434``). Empty string means "use provider
            default".
        max_tokens: Maximum tokens to request per response.
        temperature: Sampling temperature.
        provider_preference: Explicit preference set by the user (e.g. via the
            T4.5 first-run modal). One of the same string values as ``provider``
            or ``None`` to fall back to the auto-resolution decision tree.
        local_fallback_provider: Provider name to fall back to when Servonaut
            AI is unavailable (T10). Default ``None`` disables automatic
            fallback — privacy-preserving default. Set to ``"ollama"`` for
            on-device prompts or any of the other provider names.
        dismissed_banners: Banner IDs the user has dismissed forever. Examples:
            ``"ai.banner.paying_twice"``, ``"ai.banner.capability"``. The list
            is consulted by the T4.5 banner gating in
            ``ProviderPreferenceResolver``.
    """
    provider: str = "openai"  # openai, anthropic, ollama, gemini, servonaut
    api_key: str = ""  # legacy single-key field; kept for backward compat
    model: str = ""  # empty = use provider default
    base_url: str = ""  # for Ollama: http://localhost:11434
    max_tokens: int = 4096
    temperature: float = 0.3
    # T4.5 — provider preference / coexistence with existing local providers.
    provider_preference: Optional[str] = None
    # T10 — opt-in client-side fallback. Default None = no automatic fallback.
    local_fallback_provider: Optional[str] = None
    # T4.5 — banner IDs the user has dismissed forever (e.g. paying-twice,
    # capability). Persisted across CLI restarts.
    dismissed_banners: List[str] = field(default_factory=list)
    # v4 — per-provider API keys. Replaces the shared `api_key` field for
    # cloud providers so detection can correctly distinguish "OpenAI is
    # configured" from "Anthropic is configured". The legacy `api_key`
    # remains as a fallback for the currently selected provider only.
    # ``ollama_api_key`` is for Ollama Cloud (https://ollama.com) — local
    # Ollama installs leave it empty and the provider sends no auth header.
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    gemini_api_key: str = ""
    ollama_api_key: str = ""

    def key_for(self, provider_name: str) -> str:
        """Return the configured API key for *provider_name*.

        Per-provider fields take precedence; the legacy ``api_key`` is
        consulted only when the per-provider field is empty AND the legacy
        field was last saved for that exact provider (``self.provider ==
        provider_name``). This avoids leaking a stale OpenAI key into an
        Anthropic detection check, which is exactly the bug this field
        split was added to fix.

        Ollama is a special case: the legacy ``api_key`` field was never
        populated for Ollama (local installs need no auth), so we skip the
        legacy fallback for it entirely.
        """
        name = (provider_name or "").strip().lower()
        per_provider = {
            "openai": self.openai_api_key,
            "anthropic": self.anthropic_api_key,
            "gemini": self.gemini_api_key,
            "ollama": self.ollama_api_key,
        }.get(name, "")
        if per_provider:
            return per_provider
        if name == "ollama":
            return ""
        if self.api_key and (self.provider or "").strip().lower() == name:
            return self.api_key
        return ""


@dataclass(repr=False)
class ObjectStorageConfig:
    """S3-compatible object storage credentials and endpoint configuration.

    Shared by :class:`AWSConfig`, :class:`HetznerConfig`, and
    :class:`OVHConfig`.  Both ``access_key`` and ``secret_key`` support
    ``$ENV_VAR`` and ``file:`` prefix syntax via
    :func:`servonaut.config.secrets.resolve_secret`.  The RAW (possibly
    ``$ENV_VAR``) value is stored in this dataclass; callers must resolve
    at construction time before passing to the service layer.

    Attributes:
        access_key: S3 access key ID. Supports ``$ENV_VAR``/``file:`` prefix.
        secret_key: S3 secret access key. Supports ``$ENV_VAR``/``file:`` prefix.
        region: AWS region or provider-specific region (e.g. ``"us-east-1"``).
            Empty string defers to the provider's SDK default.
        endpoint_url: Custom S3-compatible endpoint (e.g. Hetzner Object Storage,
            OVH Object Storage).  Empty string → use boto3 default (AWS S3).
    """

    access_key: str = ""  # supports $ENV_VAR and file: prefix
    secret_key: str = ""  # supports $ENV_VAR and file: prefix
    region: str = ""
    endpoint_url: str = ""

    def __repr__(self) -> str:
        """Custom repr that redacts secrets to prevent log leaks."""
        ak_repr = "'<set>'" if self.access_key else "''"
        sk_repr = "'<set>'" if self.secret_key else "''"
        return (
            f"ObjectStorageConfig(access_key={ak_repr}, secret_key={sk_repr}, "
            f"region={self.region!r}, endpoint_url={self.endpoint_url!r})"
        )


@dataclass(repr=False)
class AWSConfig:
    """AWS provider configuration for EC2 management and S3 object storage.

    Attributes:
        enabled: Whether the AWS provider is active.
        default_region: Default AWS region used when no region is specified.
        cache_ttl_seconds: TTL for the on-disk EC2 instance cache.
        cache_path: On-disk cache file path.
        audit_path: JSONL audit trail path for mutating EC2 operations.
        object_storage: S3 object storage credentials and endpoint override.
        control_plane_role_arn: Default IAM role ARN that Servonaut assumes (via
            STS) for control-plane reads (SGs, WAF, ELB, logs, metrics). Empty
            ("") means use the ambient credential chain (env / shared config /
            host instance profile) exactly as before — no behaviour change.
        control_plane_role_arns: Per-account override mapping ``account_id ->
            role_arn``. Looked up first by the ``account`` argument; falls back
            to ``control_plane_role_arn`` when the account is absent or unset.
        control_plane_external_id: Optional STS ``ExternalId`` passed on
            AssumeRole (confused-deputy hardening). Supports ``$ENV_VAR`` /
            ``file:`` prefixes resolved at use time.
        assume_role_session_name: ``RoleSessionName`` used on AssumeRole; shows
            up in CloudTrail so control-plane reads are attributable.
    """

    enabled: bool = True
    default_region: str = "us-east-1"
    cache_ttl_seconds: int = 300
    cache_path: str = "~/.servonaut/aws_cache.json"
    audit_path: str = "~/.servonaut/aws_audit.jsonl"
    object_storage: ObjectStorageConfig = field(default_factory=ObjectStorageConfig)
    control_plane_role_arn: str = ""
    control_plane_role_arns: Dict[str, str] = field(default_factory=dict)
    control_plane_external_id: str = ""  # supports $ENV_VAR / file: prefix
    assume_role_session_name: str = "servonaut-control-plane"
    # Separate write-capable role for the aws_call mutate path. The control-
    # plane read role is intentionally read-only (the backstop), so mutations
    # must NOT assume it — when no mutate role is set, the aws_call write path
    # falls back to the ambient credential chain instead of the read role.
    control_plane_mutate_role_arn: str = ""
    control_plane_mutate_role_arns: Dict[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        """Custom repr that redacts any nested secrets."""
        ext_repr = "'<set>'" if self.control_plane_external_id else "''"
        return (
            f"AWSConfig(enabled={self.enabled!r}, "
            f"default_region={self.default_region!r}, "
            f"cache_ttl_seconds={self.cache_ttl_seconds!r}, "
            f"cache_path={self.cache_path!r}, "
            f"audit_path={self.audit_path!r}, "
            f"control_plane_role_arn={self.control_plane_role_arn!r}, "
            f"control_plane_role_arns={self.control_plane_role_arns!r}, "
            f"control_plane_external_id={ext_repr}, "
            f"assume_role_session_name={self.assume_role_session_name!r}, "
            f"object_storage={self.object_storage!r})"
        )


@dataclass
class GCPConfig:
    """GCP Compute Engine configuration."""
    enabled: bool = False
    project_ids: List[str] = field(default_factory=list)
    credentials_path: str = ""  # path to service account JSON
    zones: List[str] = field(default_factory=list)  # empty = all zones


@dataclass
class AzureConfig:
    """Azure VM configuration."""
    enabled: bool = False
    subscription_ids: List[str] = field(default_factory=list)
    resource_groups: List[str] = field(default_factory=list)


@dataclass
class RelayConfig:
    """Mercure relay listener configuration.

    ``base_url`` is the servonaut.dev REST API where the listener posts
    heartbeats and fetches the short-lived Mercure subscriber JWT.
    ``mercure_url`` is the Mercure hub itself — on production, the hub
    is mounted at the apex domain's ``/.well-known/mercure`` path (no
    dedicated subdomain). A typical production ``relay`` block in
    ``~/.servonaut/config.json``:

    * base_url    = ``https://api.servonaut.dev``
    * mercure_url = ``https://servonaut.dev/.well-known/mercure``
    """
    base_url: str = ""            # e.g. https://api.servonaut.dev
    mercure_url: str = ""         # e.g. https://servonaut.dev/.well-known/mercure
    heartbeat_interval: int = 30


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
    # Opt-in: allow destructive verbs (delete/terminate/destroy/purge) through
    # the generic aws_call passthrough. Default OFF — destructive ops are
    # refused entirely. When ON they still require the dangerous guard tier,
    # mutate=true, AND a mandatory two-phase confirmation token, and the most
    # unrecoverable ops stay refused regardless (see _AWS_NEVER_DESTRUCTIVE).
    allow_destructive_aws_call: bool = False


@dataclass
class OVHConfig:
    """OVHcloud API configuration.

    Attributes:
        enabled: Whether OVH provider is active
        endpoint: OVH API endpoint (ovh-eu, ovh-us, ovh-ca, etc.)
        application_key: OVH application key (classic 3-key auth)
        application_secret: OVH application secret (supports $ENV_VAR)
        consumer_key: OVH consumer key (supports $ENV_VAR)
        client_id: OAuth2 service account client ID
        client_secret: OAuth2 service account client secret (supports $ENV_VAR)
        cloud_project_ids: List of Public Cloud project IDs to include
        include_dedicated: Whether to fetch dedicated servers
        include_vps: Whether to fetch VPS instances
        include_cloud: Whether to fetch Public Cloud instances
    """
    enabled: bool = False
    endpoint: str = "ovh-eu"
    # Classic 3-key auth
    application_key: str = ""
    application_secret: str = ""  # supports $ENV_VAR
    consumer_key: str = ""  # supports $ENV_VAR
    # OAuth2 service account (alternative auth)
    client_id: str = ""
    client_secret: str = ""  # supports $ENV_VAR
    # SSH defaults
    default_ssh_key: str = ""  # default SSH key for all OVH instances
    default_username: str = ""  # override default username (empty = auto by provider type)
    # Filters
    cloud_project_ids: List[str] = field(default_factory=list)
    include_dedicated: bool = True
    include_vps: bool = True
    include_cloud: bool = True
    # Audit
    ovh_audit_path: str = "~/.servonaut/ovh_audit.json"
    # Cost alerts
    cost_alert_threshold: float = 0.0   # monthly alert threshold in currency, 0 = disabled
    cost_alert_currency: str = "EUR"
    # Object storage credentials (OVH Object Storage, S3-compatible).
    # Independent of cloud product — a user can have OVH Object Storage
    # without any OVH Public Cloud instances.
    object_storage: ObjectStorageConfig = field(default_factory=ObjectStorageConfig)


@dataclass(repr=False)
class HetznerConfig:
    """Hetzner Cloud API configuration.

    Token resolution chain (highest priority first), evaluated in
    :class:`servonaut.services.hetzner_service.HetznerService`:

    1. ``api_token`` field below — supports ``$ENV_VAR`` and
       ``file:/path/to/token`` syntax via
       :func:`servonaut.config.secrets.resolve_secret`.
    2. ``$HCLOUD_TOKEN`` environment variable (the canonical envvar the
       Hetzner SDK / Terraform / hcloud CLI all use).
    3. ``~/.config/hcloud/token`` file fallback (the canonical path
       ``hcloud`` CLI writes its bearer token to).
    4. Service refuses to initialise (raises ``HetznerNotConfiguredError``).

    Attributes:
        enabled: Whether the Hetzner provider is active. Defaults to
            ``False`` so a fresh CLI install never tries to talk to
            Hetzner unless the user opts in.
        api_token: Hetzner Cloud API token (Read+Write scope). Supports
            ``$ENV_VAR`` and ``file:`` prefixes. Stripped before any
            config-sync upload (see SENSITIVE_FIELDS in
            :mod:`servonaut.services.config_sync_service`).
        default_hetzner_ssh_key: Name (or numeric ID as a string) of an
            SSH key registered ON Hetzner Cloud. Used as the
            ``ssh_keys`` argument when creating a server so the CLI
            doesn't need a per-call ``--ssh-key`` flag. NOT a local
            file path — it is a Hetzner-side identifier.
        default_local_ssh_key: Local on-disk private-key path used by
            the CLI / TUI when SSH-ing INTO a Hetzner-created server.
            Falls back to ``AppConfig.default_key`` when empty.
            Supports ``$ENV_VAR`` and ``file:`` prefixes for the path
            string, but is NEVER dereferenced — the literal string is
            what gets passed to ``ssh -i``.
        default_username: SSH username for instances created via this
            provider. Defaults to ``"root"`` because Hetzner Cloud
            images (Ubuntu, Debian, Fedora, Rocky, etc.) all ship with
            root as the only pre-provisioned account; cloud-init
            doesn't seed a dedicated low-priv user.
        default_image: Image name for ``hetzner create`` when the user
            doesn't pass ``--image``. Empty disables the default and
            forces the user to choose.
        default_server_type: Server type for ``hetzner create`` when
            the user doesn't pass ``--type``. Empty disables.
        default_location: Datacentre location (``fsn1`` / ``nbg1`` /
            ``hel1`` / ``ash`` / ``hil``).
        cache_ttl_seconds: TTL for the on-disk Hetzner instance cache.
            300s mirrors the OVH provider.
        cache_path: On-disk cache file (instances). Defaults to
            ``~/.servonaut/hetzner_cache.json``.
        audit_path: JSONL audit trail of mutating operations
            (create/delete server, create SSH key). Distinct from the
            generic MCP audit log so operators can rotate it
            independently.
        cost_alert_threshold: Optional monthly EUR ceiling. ``0.0``
            disables the alert; the field exists so the CLI can warn
            before a stray demo fleet eats the budget.
        require_ssh_keys_on_create: When ``True`` (default), a
            ``hetzner create`` call without any SSH keys configured —
            neither ``--ssh-key`` flag nor ``default_hetzner_ssh_key``
            — is rejected. This avoids the footgun where Hetzner
            spawns a server with a random root password the user
            never sees, leaving a billed unreachable box.
    """
    enabled: bool = False
    api_token: str = ""  # supports $ENV_VAR and file:/path/to/token
    # Hetzner-side identifier. NOT dereferenced through resolve_secret.
    default_hetzner_ssh_key: str = ""
    # Local on-disk path used by ssh -i when connecting to created servers.
    default_local_ssh_key: str = ""
    default_username: str = "root"
    default_image: str = "ubuntu-22.04"
    # Hetzner deprecates server types per-location every ~18 months
    # (https://docs.hetzner.cloud/changelog#2025-09-24-per-location-server-types).
    # ``cx23`` is the current cheapest non-deprecated x86 type in fsn1
    # at the time of writing (~€0.0077/hr). When this default rots,
    # users can either:
    #
    #   1. Override per-call: ``servonaut hetzner create demo --type=cx33``
    #   2. Update ``hetzner.default_server_type`` in
    #      ``~/.servonaut/config.json`` to the current cheapest type
    #      shown by ``servonaut hetzner server-types``.
    #
    # We deliberately do not auto-discover the cheapest type at runtime
    # because the choice has cost/privacy implications the user should
    # see explicitly.
    default_server_type: str = "cx23"
    default_location: str = "fsn1"
    cache_ttl_seconds: int = 300
    cache_path: str = "~/.servonaut/hetzner_cache.json"
    audit_path: str = "~/.servonaut/hetzner_audit.jsonl"
    cost_alert_threshold: float = 0.0
    require_ssh_keys_on_create: bool = True
    object_storage: ObjectStorageConfig = field(default_factory=ObjectStorageConfig)

    def __repr__(self) -> str:
        """Custom repr that redacts the API token to prevent log leaks.

        Auto-generated dataclass ``__repr__`` would otherwise emit the
        live ``api_token`` value into any caller that interpolates the
        config into a log line / exception message. Returning a fixed
        ``'***'`` placeholder when the token is non-empty preserves
        debuggability ("is the token set?") without leaking material.
        """
        token_repr = "'<set>'" if self.api_token else "''"
        return (
            f"HetznerConfig(enabled={self.enabled!r}, api_token={token_repr}, "
            f"default_hetzner_ssh_key={self.default_hetzner_ssh_key!r}, "
            f"default_local_ssh_key={self.default_local_ssh_key!r}, "
            f"default_username={self.default_username!r}, "
            f"default_image={self.default_image!r}, "
            f"default_server_type={self.default_server_type!r}, "
            f"default_location={self.default_location!r}, "
            f"cache_ttl_seconds={self.cache_ttl_seconds!r}, "
            f"cache_path={self.cache_path!r}, "
            f"audit_path={self.audit_path!r}, "
            f"cost_alert_threshold={self.cost_alert_threshold!r}, "
            f"require_ssh_keys_on_create={self.require_ssh_keys_on_create!r}, "
            f"object_storage={self.object_storage!r})"
        )


# Server-level staleness threshold: the fleet/instances "Stale" badge flips
# once the *whole snapshot* (newest probe) is older than this.  Deliberately
# decoupled from per-module TTLs — volatile modules (containers 30 min, disk
# 1 h) intentionally re-probe fast and must not drag the whole-server badge.
DEFAULT_SNAPSHOT_STALE_SECONDS = 7 * 86400  # 7 days

# Re-prompt threshold for the first-connect "Build memory" banner: a server
# that already has memory is only re-prompted once its snapshot is older than
# this (servers with no memory at all are always prompted).
DEFAULT_FIRST_CONNECT_REPROMPT_SECONDS = 14 * 86400  # 14 days


@dataclass
class MemoryConfig:
    """Configuration for the server memory subsystem.

    Controls which modules are active, TTL overrides, redaction, and
    per-server opt-outs.

    JSON shape example (inside ``~/.servonaut/config.json``)::

        {
          "memory": {
            "enabled": true,
            "default_ttl_overrides": {
              "services": 1800
            },
            "snapshot_stale_seconds": 604800,
            "first_connect_reprompt_seconds": 1209600,
            "disabled_modules": ["containers"],
            "redaction_enabled": true,
            "per_server_overrides": {
              "i-critical-prod": { "memory_disabled": true }
            }
          }
        }

    Attributes:
        enabled: Master switch — when ``False`` no probes run and no
            memory is read or written.
        default_ttl_overrides: Per-module TTL overrides in seconds.
            Keys are module names (e.g. ``"services"``); values are seconds.
            Overrides the module's built-in default TTL.
        disabled_modules: Module names that are globally disabled.
            Probers for these modules are skipped entirely.
        redaction_enabled: When ``True`` raw probe output is passed through
            the redaction layer before being written to disk.
        per_server_overrides: Per-instance override dict.
            Each key is an instance ID; the value is a dict that may include:
            ``memory_disabled`` (bool) to opt a single server out of probing.
        snapshot_stale_seconds: Server-level staleness threshold in seconds.
            The fleet/instances "Stale" badge flips once the whole snapshot
            (newest probe) is older than this. Independent of per-module TTLs.
        first_connect_reprompt_seconds: Age in seconds beyond which a server
            that already has memory is re-prompted by the first-connect
            "Build memory" banner. Servers with no memory are always prompted.
    """

    enabled: bool = True
    default_ttl_overrides: Dict[str, int] = field(default_factory=dict)
    disabled_modules: List[str] = field(default_factory=list)
    redaction_enabled: bool = True
    per_server_overrides: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    snapshot_stale_seconds: int = DEFAULT_SNAPSHOT_STALE_SECONDS
    first_connect_reprompt_seconds: int = DEFAULT_FIRST_CONNECT_REPROMPT_SECONDS

    # ------------------------------------------------------------------
    # Helpers used by MemoryService / MemoryStore
    # ------------------------------------------------------------------

    def is_module_enabled(self, instance_id: str, module: str) -> bool:
        """Return ``True`` if *module* should be probed for *instance_id*.

        A module is disabled if either:
        - it appears in ``disabled_modules``, or
        - the instance has ``"memory_disabled": true`` in
          ``per_server_overrides``.

        Args:
            instance_id: Instance identifier.
            module: Module name (e.g. ``"runtimes"``).
        """
        if module in self.disabled_modules:
            return False
        server_override = self.per_server_overrides.get(instance_id, {})
        if server_override.get("memory_disabled", False):
            return False
        return True

    def is_module_disabled_for(self, instance_id: str) -> bool:
        """Return ``True`` if the entire server is opted out of memory.

        Args:
            instance_id: Instance identifier.
        """
        server_override = self.per_server_overrides.get(instance_id, {})
        return bool(server_override.get("memory_disabled", False))

    def is_instance_disabled(self, instance_id: str, instance_name: str = "") -> bool:
        """Return ``True`` if *instance_id* or *instance_name* is opted out.

        This avoids ambiguity when an instance is registered by name in
        ``per_server_overrides`` but the caller only has the cloud ID, or
        vice-versa.  Both keys are checked; either match disables the instance.

        Args:
            instance_id: Unique cloud identifier (e.g. ``"i-abc123"``).
            instance_name: Human-readable name (e.g. ``"prod-web"``).  When
                empty the name check is skipped.
        """
        if self.is_module_disabled_for(instance_id):
            return True
        if instance_name and self.is_module_disabled_for(instance_name):
            return True
        return False


@dataclass
class SecretsConfig:
    """Effective secrets-management configuration for one team scope.

    This is the dataclass shape the CLI uses everywhere — both for the
    server-supplied team config (cached under
    :pyattr:`AuthToken.secrets_config`) and for the always-available
    LocalProvider fallback when no team config is in play.

    The server-side contract is:

    Wire format from ``GET /api/v1/teams/{id}/secrets-config``::

        {
          "provider": "bitwarden",
          "config":   { "project_id": "...", "token_env_var": "BWS_ACCESS_TOKEN" },
          "updated_at": "2026-05-16T16:00:00Z"
        }

    Notes on each field:

    - ``provider`` — short identifier matching the value
      :pyattr:`SecretProviderInterface.provider_name` returns. Today:
      ``"local"`` (always available) or ``"bitwarden"`` (Teams-only).
    - ``config`` — provider-specific blob. Schema varies per provider.
      Kept as ``Dict[str, Any]`` so we don't have to ship a CLI release
      every time we add a new key on the server side.
    - ``updated_at`` — server-side wall-clock of the last admin change,
      ISO-8601 string. Compared against the CLI's cache timestamp so
      we can surface "team config changed since last fetch" without
      polling the audit log.
    """

    provider: str = "local"
    config: Dict[str, Any] = field(default_factory=dict)
    updated_at: str = ""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @classmethod
    def local_default(cls) -> "SecretsConfig":
        """Construct the always-available LocalProvider config.

        Used as the fallback when no team config is present (the
        endpoint returned 404) and at first-run before the entitlement
        cache has been hydrated. Equivalent to the on-disk shape an
        endpoint COULD return for a local-only team, but we don't
        round-trip through the network for it.
        """
        return cls(provider="local", config={}, updated_at="")

    @classmethod
    def from_wire(cls, payload: Dict[str, Any]) -> "SecretsConfig":
        """Parse the JSON response from ``/api/v1/teams/{slug}/secrets-config``.

        Defensive against unknown keys and shape drift — the contract
        is locked but the backend may grow new optional keys before
        the CLI ships a matching release. Unknown keys are ignored;
        missing keys fall back to the LocalProvider defaults.

        Provider allowlist: only ``"local"`` and ``"bitwarden"`` are
        accepted (the MVP-locked set in
        :data:`_KNOWN_SECRET_PROVIDERS`). Anything else coerces down
        to ``"local"`` with a WARNING — protects against a server
        sending a provider name the CLI doesn't know how to instantiate
        safely (or, in the worst case, a malicious string that downstream
        code would try to dispatch on).
        """
        raw_provider = str(payload.get("provider", "local")) or "local"
        if raw_provider in _KNOWN_SECRET_PROVIDERS:
            provider = raw_provider
        else:
            logger.warning(
                "SecretsConfig.from_wire: provider %r not in known set %s; "
                "coercing to 'local' for safety. Server may have rolled out "
                "a new provider before this CLI release supports it; check "
                "for a CLI update.",
                raw_provider, sorted(_KNOWN_SECRET_PROVIDERS),
            )
            provider = "local"
        raw_config = payload.get("config")
        config: Dict[str, Any] = (
            dict(raw_config) if isinstance(raw_config, dict) else {}
        )
        updated_at = str(payload.get("updated_at", "") or "")
        return cls(provider=provider, config=config, updated_at=updated_at)

    def to_wire(self) -> Dict[str, Any]:
        """Inverse of :meth:`from_wire` for tests / debug dumps.

        Production code rarely needs this — the CLI is a consumer, not
        an emitter, of the wire format — but the symmetry is useful
        for round-trip tests pinning the parse path.
        """
        return {
            "provider": self.provider,
            "config": dict(self.config),
            "updated_at": self.updated_at,
        }


@dataclass
class AppConfig:
    """Main application configuration.

    Attributes:
        version: Config schema version (current: 3)
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
    cloudtrail_default_lookback_minutes: int = 0
    cloudwatch_default_region: str = ""
    cloudwatch_max_events: int = 500
    cloudwatch_log_group_prefix: str = ""
    abuseipdb_api_key: str = ""
    ip_ban_configs: List[IPBanConfig] = field(default_factory=list)
    ip_ban_audit_path: str = "~/.servonaut/ip_ban_audit.json"
    db_profiles: List[DBProfile] = field(default_factory=list)
    ai_provider: AIProviderConfig = field(default_factory=AIProviderConfig)
    ai_chunk_size: int = 100000
    ai_system_prompt: str = (
        "You are a server log analyst. Analyze the following log output and provide: "
        "1) A summary of what's happening, 2) Any errors or warnings found, "
        "3) Potential issues or security concerns, 4) Recommended actions."
    )
    mcp: MCPConfig = field(default_factory=MCPConfig)
    relay: RelayConfig = field(default_factory=RelayConfig)
    ovh: OVHConfig = field(default_factory=OVHConfig)
    hetzner: HetznerConfig = field(default_factory=HetznerConfig)
    aws: AWSConfig = field(default_factory=AWSConfig)
    gcp: GCPConfig = field(default_factory=GCPConfig)
    azure: AzureConfig = field(default_factory=AzureConfig)
    chat_history_path: str = "~/.servonaut/chats"
    chat_max_history_messages: int = 20
    chat_system_prompt: str = ""
    chat_max_tool_iterations: int = 10
    chat_tool_guard_level: str = "standard"  # readonly, standard, dangerous
    # When True (default), tool-result rows are persisted in the local
    # chat session so they re-appear when the session is reloaded — useful
    # for debugging "what did the model see?". Toggle off if the noise
    # outweighs the value; transient render still happens during the
    # current turn either way.
    chat_keep_tool_results: bool = True
    # Controls whether every chat turn pre-flights a curated <CONTEXT>
    # block of local server memory and sends it to the AI provider so
    # the model can answer "what's running on srv-X?" from cache
    # instead of rediscovering via tool calls.  Two related fields:
    #
    #   chat_inject_server_memory_decision — tri-state.
    #     "unset"   : user hasn't been asked yet → first chat with an
    #                 in-scope instance pushes the consent modal and
    #                 NO memory is injected on that turn.
    #     "allowed" : explicit user opt-in (modal accepted OR Settings
    #                 toggle flipped on).
    #     "denied"  : explicit user opt-out (modal declined OR Settings
    #                 toggle flipped off).
    #
    #   chat_inject_server_memory — legacy bool kept for back-compat
    #     with already-saved configs and the existing Settings switch.
    #     Source of truth is `_decision`; the bool mirrors it
    #     ("allowed" => True, anything else => False) when saving.
    #
    # Defaults are both safe: a fresh install or upgrade lands at
    # decision="unset" + bool=False, so memory never leaves the box
    # until the user actually says yes.
    chat_inject_server_memory: bool = False
    chat_inject_server_memory_decision: str = "unset"
    sync_encryption_enabled: bool = True
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    # T11: first-connect memory-build prompt gating.
    # Counts how many times the user has dismissed the post-connect banner
    # asking "Build memory for <server>? [y]".  After three dismissals the
    # banner is suppressed globally; the ``servonaut memory reset-prompts``
    # command resets it back to 0 so users can re-enable the nudge later.
    memory_first_connect_dismissed_count: int = 0

    def db_profile_for(
        self, instance_id: str, instance_name: str = "",
    ) -> Optional["DBProfile"]:
        """Return the :class:`DBProfile` matching an instance, or ``None``.

        Matches ``profile.instance`` case-insensitively against either the
        instance id or its name — same dual-key matching the rest of the
        tool surface uses so a profile keyed by name still resolves when the
        caller passes an id (and vice versa).
        """
        targets = {
            (instance_id or "").strip().lower(),
            (instance_name or "").strip().lower(),
        }
        targets.discard("")
        for profile in self.db_profiles:
            if (profile.instance or "").strip().lower() in targets:
                return profile
        return None
