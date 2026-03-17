"""Redaction service for demo/screenshot mode.

Consistently maps real identifiable data to fake but realistic-looking
data using deterministic hashing so the same input always produces the
same output across the entire session.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# RFC 5737 documentation IP ranges (safe for public use)
_DOC_NETS = ["192.0.2", "198.51.100", "203.0.113"]

# Realistic fake server name components
_NAME_PREFIXES = [
    "web", "api", "app", "db", "cache", "worker", "proxy",
    "gateway", "auth", "queue", "monitor", "scheduler",
    "search", "mail", "cdn", "storage", "backup", "deploy",
]
_NAME_SUFFIXES = [
    "prod", "staging", "dev", "test", "eu", "us", "ap",
    "primary", "replica", "blue", "green", "canary",
]

# Fake provider/group names
_PROVIDERS = ["AWS", "GCP", "Azure", "Hetzner", "OVH", "DigitalOcean"]
_GROUPS = [
    "production", "staging", "development", "monitoring",
    "web-servers", "api-servers", "databases", "workers",
]

# Fake key names
_KEY_NAMES = [
    "deploy-key", "prod-key", "staging-key", "dev-key",
    "bastion-key", "service-key", "admin-key", "ci-key",
]

# Fake usernames
_USERNAMES = ["ubuntu", "ec2-user", "admin", "deploy", "root", "centos"]


def _hash_int(value: str, modulo: int) -> int:
    """Deterministic hash of a string to an int in [0, modulo)."""
    digest = hashlib.sha256(value.encode()).hexdigest()
    return int(digest[:8], 16) % modulo


def _hash_pick(value: str, choices: list) -> str:
    """Pick a consistent item from a list based on the input string."""
    return choices[_hash_int(value, len(choices))]


class RedactionService:
    """Replaces identifiable data with fake but realistic equivalents.

    All mappings are deterministic — the same input always produces the
    same output, so the UI looks consistent across screens.
    """

    def __init__(self) -> None:
        self._ip_cache: dict[str, str] = {}
        self._name_cache: dict[str, str] = {}
        self._counter: int = 0

    def redact_ip(self, ip: str) -> str:
        """Map a real IP to a documentation-range IP."""
        if not ip or ip == "-" or ip == "N/A":
            return ip
        if ip in self._ip_cache:
            return self._ip_cache[ip]

        net = _DOC_NETS[_hash_int(ip, len(_DOC_NETS))]
        host = _hash_int(ip + "host", 254) + 1
        fake = f"{net}.{host}"
        self._ip_cache[ip] = fake
        return fake

    def redact_name(self, name: str) -> str:
        """Map a real server name to a fake but realistic one."""
        if not name or name == "-":
            return name
        if name in self._name_cache:
            return self._name_cache[name]

        prefix = _hash_pick(name, _NAME_PREFIXES)
        suffix = _hash_pick(name + "sfx", _NAME_SUFFIXES)
        num = _hash_int(name + "num", 20) + 1
        fake = f"{prefix}-{suffix}-{num}"
        self._name_cache[name] = fake
        return fake

    def redact_instance_id(self, instance_id: str) -> str:
        """Map a real instance ID to a fake one preserving format."""
        if not instance_id:
            return instance_id
        fake_hex = hashlib.sha256(instance_id.encode()).hexdigest()[:17]
        if instance_id.startswith("custom-"):
            return f"custom-{fake_hex[:12]}"
        if instance_id.startswith("i-"):
            return f"i-{fake_hex}"
        return instance_id

    def redact_hostname(self, hostname: str) -> str:
        """Map a real hostname/FQDN to a fake one."""
        if not hostname or hostname == "-":
            return hostname
        prefix = _hash_pick(hostname, _NAME_PREFIXES)
        num = _hash_int(hostname, 100) + 1
        return f"{prefix}-{num}.example.com"

    def redact_key_name(self, key: str) -> str:
        """Map a real SSH key name/path to a fake one."""
        if not key or key == "-":
            return key
        fake = _hash_pick(key, _KEY_NAMES)
        if "/" in key:
            return f"~/.ssh/{fake}"
        return fake

    def redact_provider(self, provider: str) -> str:
        """Map a real provider name to a fake one."""
        if not provider or provider == "-":
            return provider
        return _hash_pick(provider, _PROVIDERS)

    def redact_group(self, group: str) -> str:
        """Map a real group name to a fake one."""
        if not group or group == "-":
            return group
        return _hash_pick(group, _GROUPS)

    def redact_username(self, username: str) -> str:
        """Map a real username to a fake one."""
        if not username or username == "-":
            return username
        return _hash_pick(username, _USERNAMES)

    def redact_instance(self, instance: dict[str, Any]) -> dict[str, Any]:
        """Redact all identifiable fields in an instance dict (in-place)."""
        if instance.get("name"):
            instance["name"] = self.redact_name(instance["name"])
        if instance.get("id"):
            instance["id"] = self.redact_instance_id(instance["id"])
        if instance.get("public_ip"):
            instance["public_ip"] = self.redact_ip(instance["public_ip"])
        if instance.get("private_ip"):
            instance["private_ip"] = self.redact_ip(instance["private_ip"])
        if instance.get("key_name"):
            instance["key_name"] = self.redact_key_name(instance["key_name"])
        if instance.get("ssh_key"):
            instance["ssh_key"] = self.redact_key_name(instance["ssh_key"])
        if instance.get("provider"):
            instance["provider"] = self.redact_provider(instance["provider"])
        if instance.get("group"):
            instance["group"] = self.redact_group(instance["group"])
        if instance.get("username"):
            instance["username"] = self.redact_username(instance["username"])
        # Hostnames in custom servers
        if instance.get("host"):
            instance["host"] = self.redact_hostname(instance["host"])
        # Tags may contain client names
        if instance.get("tags") and isinstance(instance["tags"], dict):
            instance["tags"] = {
                k: self.redact_name(v) for k, v in instance["tags"].items()
            }
        # Custom servers use provider as region — redact if not a standard AWS region
        if instance.get("is_custom") and instance.get("region"):
            region = instance["region"]
            if not region.startswith(("us-", "eu-", "ap-", "sa-", "ca-", "me-", "af-")):
                instance["region"] = self.redact_provider(region)
        return instance

    def redact_instances(self, instances: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Redact all instances in a list."""
        for inst in instances:
            self.redact_instance(inst)
        return instances

    def redact_text(self, text: str) -> str:
        """Redact IPs found in arbitrary text (e.g., log output)."""
        ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        def _replace(match: re.Match) -> str:
            return self.redact_ip(match.group(1))
        return ip_pattern.sub(_replace, text)
