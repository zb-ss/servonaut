"""Keeps the user's server inventory out of bug reports.

A bug report can become a public GitHub issue, and its config snapshot and
log excerpt name the user's servers: hosts, addresses, logins, instance and
project ids. :class:`InventoryScrubber` replaces every such value it knows
(taken from the fleet, the config and the DNS zones seen this session) with
the stand-in demo mode would show, then applies shape rules to what it does
not know: the ``RedactionService.scrub_stream`` rules (IPs, URLs, e-mail
addresses, home paths, account ids), ARN resource names, and any token that
looks like a host name. Inventory sections of the config are left out
altogether, keeping only how many entries each had.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, Iterable, List, Optional

from servonaut.services.redaction_service import RedactionService

# Config sections that list the user's servers, logins or accounts. The
# snapshot keeps only their size: their structure is not worth the risk of a
# field that no rule below recognises.
INVENTORY_SECTIONS: tuple = (
    "instance_keys",
    "custom_servers",
    "connection_profiles",
    "connection_rules",
    "scan_rules",
    "ip_ban_configs",
    "db_profiles",
    "log_viewer_custom_paths",
    "db_scan_roots",
    "memory.per_server_overrides",
    "ovh.cloud_project_ids",
    "gcp.project_ids",
    "azure.subscription_ids",
    "azure.resource_groups",
)
# Account wiring whose value is never useful in a report: the OAuth client,
# the STS role ARNs and ExternalId, the service-account key file.
OMITTED_FIELDS: tuple = ("ovh.client_id", "gcp.credentials_path")
OMITTED_PREFIXES: tuple = ("aws.control_plane_",)

# Scalar fields named after what they hold, wherever they appear.
_USERNAME_FIELDS = frozenset({"username", "default_username", "user", "bastion_user"})
_HOST_FIELDS = frozenset({"host", "hostname", "bastion_host"})

# Shorter values (a port, "db") would turn ordinary words into stand-ins.
_MIN_IDENTIFIER_LENGTH = 3
# Values that identify nobody: replacing them only makes a report misleading.
_GENERIC_VALUES = frozenset({
    "root", "admin", "administrator", "ubuntu", "debian", "centos", "fedora",
    "rocky", "almalinux", "ec2-user", "opc", "bitnami", "core", "deploy", "user",
    "default", "production", "prod", "staging", "stage", "development", "dev",
    "test", "testing", "demo", "local", "localhost", "main", "master", "backup",
    "primary", "secondary", "public", "private", "web", "api", "app", "db",
    "mail", "www", "none", "null", "true", "false",
})
# Not part of a longer name, host or path segment on either side.
_BOUNDARY_BEFORE = r"(?<![A-Za-z0-9_.\-])"
_BOUNDARY_AFTER = r"(?![A-Za-z0-9_\-])"

# ARN with an optional account; the resource after it names the user's things.
_ARN_RE = re.compile(
    r"arn:(?P<partition>aws[\w-]*):(?P<service>[\w-]*):(?P<region>[\w-]*):"
    r"(?P<account>\d{12})?:(?P<resource>[\w+=,.@/:*-]+)"
)
# A dotted run that ends in a TLD-shaped label, taken whole: a run that goes
# on into more dotted or word characters (``self.app.push_screen``) is code.
_HOSTNAME_RE = re.compile(
    r"(?<![\w.@/-])(?P<host>(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?P<tld>[A-Za-z]{2,24}))(?![\w-]|\.[\w-])"
)
# Last labels taken for a TLD: every two-letter label (country codes) except
# file extensions, plus common generic and private-network names.
_LONG_TLDS = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io", "dev",
    "app", "cloud", "online", "site", "tech", "xyz", "host", "hosting", "server",
    "services", "network", "systems", "digital", "email", "shop", "store", "web",
    "website", "space", "agency", "company", "solutions", "ovh", "aws",
    "local", "lan", "internal", "intranet", "corp", "home", "localdomain",
    "example", "test", "invalid", "arpa",
})
_FILE_EXTENSIONS = frozenset({
    "py", "sh", "md", "js", "ts", "rs", "go", "rb", "pl", "cs", "cc", "hh", "so",
    "gz", "xz", "bz", "db", "pm", "mo", "po", "el", "ml", "rc", "ui",
})
# Dotted names that are Python modules or attribute chains, not hosts.
_MODULE_PREFIXES = (
    "servonaut.", "textual.", "asyncio.", "botocore.", "boto3.", "urllib3.",
    "httpx.", "httpcore.", "mcp.", "rich.", "concurrent.", "json.", "logging.",
    "keyring.", "sherpa_onnx.", "self.", "cls.", "os.", "sys.",
)
# Documentation domains (RFC 2606), which is where the stand-ins live too.
_DOC_DOMAIN_RE = re.compile(r"(?:^|\.)example\.(?:com|net|org)$", re.IGNORECASE)


class InventoryScrubber:
    """Replaces known and recognisable server identifiers in report text."""

    def __init__(
        self,
        redaction: RedactionService,
        identifiers: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Args:
            redaction: Source of the stand-ins and of the shape rules.
            identifiers: Real value -> stand-in, for values no shape rule
                recognises (server names, bare host names, logins, ids).
        """
        self._redaction = redaction
        self._identifiers = {
            real.lower(): fake for real, fake in (identifiers or {}).items()
            if len(real) >= _MIN_IDENTIFIER_LENGTH
            and real.lower() not in _GENERIC_VALUES
            and real != fake
        }
        self._pattern = self._build_pattern(self._identifiers)

    @classmethod
    def from_inventory(
        cls,
        instances: Iterable[Dict[str, Any]],
        config: Optional[Dict[str, Any]],
        known_hosts: Iterable[str] = (),
    ) -> "InventoryScrubber":
        """Build a scrubber from the real fleet, the config (as a dict) and
        other host names seen this session (DNS zones)."""
        redaction = RedactionService()
        collector = _IdentifierCollector(redaction)
        for instance in instances or []:
            if isinstance(instance, dict):
                collector.add_instance(instance)
        if isinstance(config, dict):
            collector.add_config(config)
        for host in known_hosts or ():
            collector.add_host(host)
        return cls(redaction, collector.found)

    # ------------------------------------------------------------------
    # Text
    # ------------------------------------------------------------------

    def scrub_text(self, text: Optional[str]) -> Optional[str]:
        """Log lines, tracebacks, config values: every rule.

        A dotted word taken for a host name is an acceptable loss here: the
        text is diagnostics, and a leak cannot be taken back.
        """
        if not text:
            return text
        text = self._replace_known(text)
        text = _ARN_RE.sub(_redact_arn, text)
        text = self._redaction.scrub_stream(text, honour_kill_switch=False)
        return _HOSTNAME_RE.sub(self._redact_hostname, text)

    def scrub_prose(self, text: Optional[str]) -> Optional[str]:
        """What the user typed: known identifiers and IP addresses only.

        URLs and e-mail addresses in a description are usually there on
        purpose (a docs link, a contact), so they are left as typed.
        """
        if not text:
            return text
        text = self._replace_known(text)
        text = self._redaction.redact_text(text)
        return self._redaction.redact_ipv6(text)

    def _replace_known(self, text: str) -> str:
        if self._pattern is None:
            return text
        return self._pattern.sub(lambda m: self._identifiers[m.group(0).lower()], text)

    @staticmethod
    def _build_pattern(identifiers: Dict[str, str]) -> Optional["re.Pattern[str]"]:
        if not identifiers:
            return None
        # Longest first, so a host name wins over the server name inside it.
        alternatives = "|".join(
            re.escape(value) for value in sorted(identifiers, key=len, reverse=True)
        )
        return re.compile(
            f"{_BOUNDARY_BEFORE}(?:{alternatives}){_BOUNDARY_AFTER}", re.IGNORECASE
        )

    def _redact_hostname(self, match: "re.Match[str]") -> str:
        host = match.group("host")
        tld = match.group("tld").lower()
        lowered = host.lower()
        if (
            _DOC_DOMAIN_RE.search(lowered)
            or lowered.startswith(_MODULE_PREFIXES)
            or (len(tld) == 2 and tld in _FILE_EXTENSIONS)
            or (len(tld) > 2 and tld not in _LONG_TLDS)
        ):
            return host
        return self._redaction.redact_hostname(host)

    # ------------------------------------------------------------------
    # Config snapshot
    # ------------------------------------------------------------------

    def scrub_config(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Return a copy with inventory sections summarised and values scrubbed."""
        return self._scrub_node(snapshot, ())

    def _scrub_node(self, node: Any, path: tuple) -> Any:
        if isinstance(node, dict):
            out: Dict[str, Any] = {}
            for key, value in node.items():
                child = path + (str(key),)
                dotted = ".".join(child)
                if dotted in INVENTORY_SECTIONS and value:
                    out[key] = _omitted_label(value)
                elif _is_omitted(dotted) and value:
                    out[key] = "<omitted>"
                elif isinstance(value, str) and value:
                    out[key] = self._scrub_field(str(key), value)
                else:
                    out[key] = self._scrub_node(value, child)
            return out
        if isinstance(node, list):
            return [self._scrub_node(item, path) for item in node]
        if isinstance(node, str):
            return self.scrub_text(node)
        return node

    def _scrub_field(self, key: str, value: str) -> str:
        if key in _USERNAME_FIELDS:
            return self._redaction.redact_username(value)
        if key in _HOST_FIELDS:
            return self._redaction.redact_host(value)
        return self.scrub_text(value)


def _redact_arn(match: "re.Match[str]") -> str:
    """Keep an ARN's service, region and resource type; drop the rest."""
    account = "000000000000" if match.group("account") else ""
    resource = match.group("resource")
    split = re.search(r"[/:]", resource)
    tail = f"{resource[:split.end()]}redacted" if split else "redacted"
    return (
        f"arn:{match.group('partition')}:{match.group('service')}:"
        f"{match.group('region')}:{account}:{tail}"
    )


def _is_omitted(dotted: str) -> bool:
    return dotted in OMITTED_FIELDS or dotted.startswith(OMITTED_PREFIXES)


def _omitted_label(value: Any) -> str:
    count = len(value) if hasattr(value, "__len__") else 1
    noun = "entry" if count == 1 else "entries"
    return f"<omitted: {count} {noun}>"


class _IdentifierCollector:
    """Gathers real identifier -> stand-in pairs from the fleet and config."""

    def __init__(self, redaction: RedactionService) -> None:
        self._redaction = redaction
        self.found: Dict[str, str] = {}

    def add(self, value: Any, redact: Callable[[str], str]) -> None:
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return
        value = str(value).strip()
        if len(value) < _MIN_IDENTIFIER_LENGTH or value in self.found:
            return
        if value.lower() in _GENERIC_VALUES:
            return
        fake = redact(value)
        if fake and fake != value:
            self.found[value] = fake

    def add_id(self, value: Any) -> None:
        self.add(value, self._redaction.redact_identifier)
        # OVH Public Cloud ids are "<project>/<instance>": each half too.
        if isinstance(value, str) and "/" in value:
            for part in value.split("/"):
                self.add(part, self._redaction.redact_identifier)

    def add_key(self, value: Any) -> None:
        if not isinstance(value, str) or not value.strip():
            return
        self.add(value, self._redaction.redact_key_name)
        self.add(value.rstrip("/").rsplit("/", 1)[-1], self._redaction.redact_key_name)

    def add_host(self, value: Any) -> None:
        if isinstance(value, str):
            value = value.rstrip(".")
        self.add(value, self._redaction.redact_host)

    def add_name(self, value: Any) -> None:
        self.add(value, self._redaction.redact_name)

    def add_username(self, value: Any) -> None:
        self.add(value, self._redaction.redact_username)

    def add_instance(self, instance: Dict[str, Any]) -> None:
        self.add_id(instance.get("id"))
        self.add_name(instance.get("name"))
        for field in ("public_ip", "private_ip", "host"):
            self.add_host(instance.get(field))
        self.add_username(instance.get("username"))
        self.add_key(instance.get("key_name"))
        self.add_key(instance.get("ssh_key"))
        self.add(instance.get("group"), self._redaction.redact_group)
        tags = instance.get("tags")
        if isinstance(tags, dict):
            for tag_value in tags.values():
                self.add_name(tag_value)

    def add_config(self, config: Dict[str, Any]) -> None:
        for server in _items(config, "custom_servers"):
            self.add_instance(server)
        for instance_id, key_path in _mapping(config, "instance_keys").items():
            self.add_id(instance_id)
            self.add_key(key_path)
        for profile in _items(config, "connection_profiles"):
            self.add_name(profile.get("name"))
            self.add_host(profile.get("bastion_host"))
            self.add_username(profile.get("bastion_user"))
            self.add_username(profile.get("username"))
            self.add_key(profile.get("bastion_key"))
        for rule in _items(config, "connection_rules") + _items(config, "scan_rules"):
            self.add_name(rule.get("name"))
            for condition in (rule.get("match_conditions") or {}).values():
                self.add_name(condition)
        for db in _items(config, "db_profiles"):
            self.add_id(db.get("instance"))
            self.add_host(db.get("host"))
            self.add_username(db.get("user"))
            self.add_name(db.get("database"))
        for ban in _items(config, "ip_ban_configs"):
            self.add_name(ban.get("name"))
            self.add_name(ban.get("ip_set_name"))
            for field in ("ip_set_id", "security_group_id", "nacl_id"):
                self.add_id(ban.get(field))
        for section in ("log_viewer_custom_paths", "db_scan_roots"):
            for instance_id in _mapping(config, section):
                self.add_id(instance_id)
        for instance_id in _mapping(_mapping(config, "memory"), "per_server_overrides"):
            self.add_id(instance_id)
        for path in ("ovh.cloud_project_ids", "gcp.project_ids", "azure.subscription_ids"):
            for value in _values(config, path):
                self.add_id(value)
        for value in _values(config, "azure.resource_groups"):
            self.add_name(value)
        for path in ("ovh.client_id", "aws.control_plane_external_id"):
            self.add_id(_value(config, path))
        for key_path in (
            _value(config, "default_key"),
            _value(config, "ovh.default_ssh_key"),
            _value(config, "hetzner.default_local_ssh_key"),
            _value(config, "hetzner.default_hetzner_ssh_key"),
            _value(config, "gcp.credentials_path"),
        ):
            self.add_key(key_path)
        for username in (
            _value(config, "default_username"),
            _value(config, "ovh.default_username"),
            _value(config, "hetzner.default_username"),
        ):
            self.add_username(username)


def _value(config: Dict[str, Any], path: str) -> Any:
    node: Any = config
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _values(config: Dict[str, Any], path: str) -> List[Any]:
    value = _value(config, path)
    return list(value) if isinstance(value, (list, tuple)) else []


def _items(config: Dict[str, Any], path: str) -> List[Dict[str, Any]]:
    return [item for item in _values(config, path) if isinstance(item, dict)]


def _mapping(config: Any, path: str) -> Dict[str, Any]:
    value = _value(config, path) if isinstance(config, dict) else None
    return value if isinstance(value, dict) else {}
