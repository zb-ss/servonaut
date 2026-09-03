"""Redaction service for demo/screenshot mode.

Consistently maps real identifiable data to fake but realistic-looking
data using deterministic hashing so the same input always produces the
same output across the entire session.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from typing import Any

from servonaut.services.memory.redaction import default_redactor

logger = logging.getLogger(__name__)

# RFC 5737 documentation IP ranges (safe for public use)
_DOC_NETS = ["192.0.2", "198.51.100", "203.0.113"]

# Realistic fake server name components
_NAME_PREFIXES = [
    # Original 18
    "web", "api", "app", "db", "cache", "worker", "proxy",
    "gateway", "auth", "queue", "monitor", "scheduler",
    "search", "mail", "cdn", "storage", "backup", "deploy",
    # Expanded to 50 — generic, common, non-loaded English tech words
    "build", "run", "task", "job", "pipe", "stream", "relay",
    "node", "edge", "core", "hub", "mesh", "bridge", "link",
    "log", "trace", "metric", "alert", "event", "audit",
    "image", "media", "asset", "graph", "data", "sync",
    "push", "pull", "fetch", "serve",
]
_NAME_SUFFIXES = [
    # Original 12
    "prod", "staging", "dev", "test", "eu", "us", "ap",
    "primary", "replica", "blue", "green", "canary",
    # Expanded to 50 — geographic/tier/role suffixes common in infra naming
    "west", "east", "north", "south", "central",
    "alpha", "beta", "gamma", "delta",
    "main", "backup", "secondary", "tertiary",
    "fast", "slow", "heavy", "light",
    "a", "b", "c", "d",
    "v1", "v2", "v3",
    "internal", "external", "public", "private",
    "shared", "dedicated", "cluster",
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

# ---------------------------------------------------------------------------
# Regex patterns for scrub_stream primitives (compiled once at import time)
# ---------------------------------------------------------------------------

# ARN — replaces account-id component with 000000000000; preserves service/region/rest
_ARN_RE = re.compile(
    r"arn:aws:(?P<service>[a-z0-9\-]+):"
    r"(?P<region>[a-z0-9\-]*):"
    r"(?P<account>\d{12}):"
    r"(?P<rest>[\w\-/:.*?]+)"
)

# Bare 12-digit AWS account ID — negative lookaround prevents 15-digit shredding
# and excludes numbers adjacent to dots (timestamps, request IDs with dots).
_AWS_ACCOUNT_ID_RE = re.compile(r"(?<![\d.])(\d{12})(?![\d.])")

# IPv4 addresses in free-form text (e.g. log output)
_IPV4_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

# Unix home paths — /home/<user>/ and /Users/<user>/
_HOME_PATH_RE = re.compile(r"(/home/)([^/\s:'\"]+)")
_USERS_PATH_RE = re.compile(r"(/Users/)([^/\s:'\"]+)")

# URLs — host → example.com; query params (often signed tokens) stripped
_URL_RE = re.compile(
    r"(?P<scheme>https?)://(?P<host>[^\s/?#'\"<>]+)(?P<rest>[^\s'\"<>]*)"
)

# CloudWatch log group names — /aws/<svc>/<name>
_LOG_GROUP_RE = re.compile(r"(/aws/[a-z0-9\-]+/)([A-Za-z0-9\-_./]+)")

# ECR hostname — <12-digit-account>.dkr.ecr.<region>.amazonaws.com
# Must be handled BEFORE the bare account_id regex to avoid the dot-boundary
# lookaround accidentally excluding accounts adjacent to dots in this pattern.
_ECR_HOST_RE = re.compile(
    r"\b(\d{12})\.dkr\.ecr\.([a-z0-9\-]+)\.amazonaws\.com\b"
)

# IPv6 addresses — require at least 3 colons ({2,7} groups) to avoid matching
# MAC addresses (aa:bb:cc:dd:ee:ff has only 5 colons with no leading digits of
# this form). Replace with 2001:db8::1 (RFC 3849 documentation prefix).
# Known limitation: very short IPv6 forms like "::1" (loopback) are not matched
# because they contain only 1 colon — see docs/demo-mode.md.
_IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
)

# S3 bucket names — only explicit s3:// URIs (unambiguous).
# Quoted DNS-shaped names are NOT matched: pattern is too broad and matches
# free-form prose such as "hello-world" (Known limitation — see docs/demo-mode.md).
_S3_URI_RE = re.compile(r"s3://([a-z0-9][a-z0-9\-\.]{2,62}[a-z0-9])")

# Email addresses — matches RFC 5321 local-part @ domain.tld forms.
# Applied AFTER redact_url so URL-embedded "user:pass@host" forms are consumed
# first by the URL regex (order matters in scrub_stream pipeline).
# Idempotent: local parts already in _fake_names pass through unchanged.
_EMAIL_RE = re.compile(
    r"\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b"
)


# Dashed-IP host fragments: OVH dedicated / VPS service names look like
# ``ns3141592.ip-51-195-150-236.eu``.  The IPv4 rule cannot see the dashed
# form, so it gets its own rule that reuses the ``redact_ip`` mapping.
_EC2_ID_RE = re.compile(r"\bi-[0-9a-f]{8,17}\b")
_DASHED_IP_RE = re.compile(r"\bip-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})\b")

# A bare hostname / FQDN on its own: dotted labels and nothing else.  Callers
# also require at least one letter so a pure IPv4 literal never matches.
_BARE_HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?"
    r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+\.?$"
)
_IPV4_WITH_PREFIX_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?$")
_FAKE_HOST_SUFFIX = ".example.com"
# One whole IPv6 address (2-7 colons), optionally with a /prefix.
_IPV6_HOST_RE = re.compile(
    r"^([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(/\d{1,3})?$"
)
_FAKE_IPV6_PREFIX = "2001:db8:"
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


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
        self._ipv6_cache: dict[str, str] = {}
        self._name_cache: dict[str, str] = {}
        # Instance ids: real -> fake, plus the set of fakes emitted so a fake
        # fed back in on a re-render is returned unchanged (idempotence).
        self._id_cache: dict[str, str] = {}
        self._fake_ids: set[str] = set()
        self._real_id_by_fake: dict[str, str] = {}
        # Values the operator typed while demo mode was on (a server added
        # on camera): shown as typed, never hashed. Nothing real is in here
        # unless the operator chose to type it in front of the recorder.
        self._authored: set[str] = set()
        self._counter: int = 0
        # Tracks every fake name ever emitted by redact_name so that
        # a second scrub_stream pass does not re-replace already-fake names
        # (idempotence guarantee for log group and resource name redaction).
        self._fake_names: set[str] = set()

    def redact_ip(self, ip: str) -> str:
        """Map a real IP to a documentation-range IP."""
        if not ip or ip == "-" or ip == "N/A":
            return ip
        # Idempotence guard: doc-range IP fed back into redact_ip would re-hash
        # to a DIFFERENT doc-range IP (cache is keyed on original input).
        # Short-circuit so scrub_stream composes safely across re-renders.
        for net in _DOC_NETS:
            if ip.startswith(net + "."):
                return ip
        if ip in self._ip_cache:
            return self._ip_cache[ip]

        net = _DOC_NETS[_hash_int(ip, len(_DOC_NETS))]
        host = _hash_int(ip + "host", 254) + 1
        fake = f"{net}.{host}"
        self._ip_cache[ip] = fake
        return fake

    def keep_as_authored(self, *values: str) -> None:
        """Remember values typed during this demo session so they render as typed."""
        self._authored.update(v for v in values if isinstance(v, str) and v)

    def redact_name(self, name: str) -> str:
        """Map a real server name to a fake but realistic one."""
        if not name or name == "-" or name in self._authored:
            return name
        if name in self._name_cache:
            return self._name_cache[name]

        prefix = _hash_pick(name, _NAME_PREFIXES)
        suffix = _hash_pick(name + "sfx", _NAME_SUFFIXES)
        num = _hash_int(name + "num", 30) + 1
        fake = f"{prefix}-{suffix}-{num}"
        self._name_cache[name] = fake
        self._fake_names.add(fake)
        return fake

    def redact_instance_id(self, instance_id: str) -> str:
        """Map a real instance ID to a fake one preserving its format.

        Covers AWS ``i-…`` and ``custom-…`` ids, hostname-shaped provider
        service names, OVH Public Cloud composites ``<project>/<instance>``,
        UUIDs and purely numeric ids.  Unknown shapes pass through unchanged.
        Idempotent within a session: a fake fed back in is returned as-is.
        """
        if not instance_id:
            return instance_id
        if instance_id in self._fake_ids:
            return instance_id
        cached = self._id_cache.get(instance_id)
        if cached is not None:
            return cached
        fake = self._fake_instance_id(instance_id)
        if fake != instance_id:
            self._id_cache[instance_id] = fake
            self._fake_ids.add(fake)
            self._real_id_by_fake[fake] = instance_id
        return fake

    def real_instance_id(self, instance_id: str) -> str:
        """Inverse of ``redact_instance_id`` for fakes emitted this session.

        Anything else (a real id, an empty string) comes back unchanged, so
        callers can apply it unconditionally.
        """
        if not instance_id:
            return instance_id
        return self._real_id_by_fake.get(instance_id, instance_id)

    def _fake_instance_id(self, instance_id: str) -> str:
        digest = hashlib.sha256(instance_id.encode()).hexdigest()
        if instance_id.startswith("custom-"):
            return f"custom-{digest[:12]}"
        if instance_id.startswith("i-"):
            return f"i-{digest[:17]}"
        if "/" in instance_id:
            # OVH Public Cloud composite "<project_id>/<instance_id>".
            return "/".join(
                self._fake_instance_id(part) if part else part
                for part in instance_id.split("/")
            )
        if _UUID_RE.match(instance_id):
            return (
                f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-"
                f"{digest[16:20]}-{digest[20:32]}"
            )
        if instance_id.isdigit():
            digits = str(int(digest[:24], 16))
            return digits[:len(instance_id)].rjust(len(instance_id), "7")
        if (
            "." in instance_id
            and any(c.isalpha() for c in instance_id)
            and _BARE_HOSTNAME_RE.match(instance_id)
        ):
            return self.redact_hostname(instance_id)
        return instance_id

    def redact_hostname(self, hostname: str) -> str:
        """Map a real hostname/FQDN to a fake one."""
        if not hostname or hostname == "-" or hostname in self._authored:
            return hostname
        # Idempotence guard (mirrors redact_ip): a fake host fed back in on a
        # re-render must not re-hash to a different fake.
        if hostname.endswith(_FAKE_HOST_SUFFIX):
            return hostname
        prefix = _hash_pick(hostname, _NAME_PREFIXES)
        num = _hash_int(hostname, 100) + 1
        return f"{prefix}-{num}{_FAKE_HOST_SUFFIX}"

    def redact_host(self, value: str) -> str:
        """Redact a display value that is a host *by definition*.

        Accepts an IPv4 literal (optionally with a ``/prefix``), a bare
        hostname / FQDN, or free text, and dispatches to ``redact_ip``,
        ``redact_hostname`` or ``scrub_stream`` respectively.

        ``scrub_stream`` deliberately has no bare-hostname rule (it would
        false-positive on ordinary prose), so columns that always hold a
        host -- DNS zones, reverse-DNS targets, provider service names,
        custom-server hosts, instance IP fields -- route through this.
        """
        if not value or value in ("-", "—", "N/A"):
            return value
        stripped = value.strip()
        ip_match = _IPV4_WITH_PREFIX_RE.match(stripped)
        if ip_match:
            return self.redact_ip(ip_match.group(1)) + (ip_match.group(2) or "")
        v6_match = _IPV6_HOST_RE.match(stripped)
        if v6_match:
            return self.redact_ipv6_address(v6_match.group(1)) + (v6_match.group(2) or "")
        if _BARE_HOSTNAME_RE.match(stripped) and any(c.isalpha() for c in stripped):
            return self.redact_hostname(stripped)
        return self.scrub_stream(value)

    def redact_key_name(self, key: str) -> str:
        """Map a real SSH key name/path to a fake one."""
        if not key or key == "-" or key in self._authored:
            return key
        fake = _hash_pick(key, _KEY_NAMES)
        if "/" in key:
            return f"~/.ssh/{fake}"
        return fake

    def redact_provider(self, provider: str) -> str:
        """Map a provider label to a pool one; pool labels pass through.

        The pool is public taxonomy (AWS, OVH, Hetzner …), so a real label
        that is already in it stays put and the provider column stays true.
        """
        if not provider or provider == "-":
            return provider
        if provider in _PROVIDERS:
            return provider
        return _hash_pick(provider, _PROVIDERS)

    def redact_group(self, group: str) -> str:
        """Map a real group name to a fake one."""
        if not group or group == "-" or group in self._authored:
            return group
        return _hash_pick(group, _GROUPS)

    def redact_username(self, username: str) -> str:
        """Map a real username to a fake one."""
        if not username or username == "-" or username in self._authored:
            return username
        return _hash_pick(username, _USERNAMES)

    def redact_instance(self, instance: dict[str, Any]) -> dict[str, Any]:
        """Redact all identifiable fields in an instance dict (in-place)."""
        if instance.get("name"):
            instance["name"] = self.redact_name(instance["name"])
        if instance.get("id"):
            instance["id"] = self.redact_instance_id(instance["id"])
        # Custom servers copy their host into the IP fields, so these may be
        # FQDNs -- redact_host keeps the IP mapping for real IPs and gives a
        # hostname a hostname-shaped fake instead of hashing it into an IP.
        if instance.get("public_ip"):
            instance["public_ip"] = self.redact_host(instance["public_ip"])
        if instance.get("private_ip"):
            instance["private_ip"] = self.redact_host(instance["private_ip"])
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
        # Hostnames in custom servers (may also be a plain IP)
        if instance.get("host"):
            instance["host"] = self.redact_host(instance["host"])
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
        def _replace(match: re.Match) -> str:
            return self.redact_ip(match.group(1))
        return _IPV4_RE.sub(_replace, text)

    def redact_arn(self, text: str) -> str:
        """Replace the account-id component inside ARNs with 000000000000.

        Preserves service, region, and resource segments so the ARN remains
        structurally valid. Only 12-digit accounts are matched to avoid
        false positives.
        """
        def _replace(m: re.Match) -> str:
            return (
                f"arn:aws:{m.group('service')}:{m.group('region')}:"
                f"000000000000:{m.group('rest')}"
            )
        return _ARN_RE.sub(_replace, text)

    def redact_account_id(self, text: str) -> str:
        """Replace bare 12-digit AWS account IDs with 000000000000.

        Negative lookbehind/lookahead prevents replacing longer digit runs
        such as phone numbers or 15-digit GCP project numbers.
        """
        return _AWS_ACCOUNT_ID_RE.sub("000000000000", text)

    def redact_path(self, text: str) -> str:
        """Replace username component in /home/<user>/ and /Users/<user>/ paths."""
        text = _HOME_PATH_RE.sub(r"\1user", text)
        text = _USERS_PATH_RE.sub(r"\1user", text)
        return text

    def redact_url(self, text: str) -> str:
        """Replace hostname in URLs with example.com and strip query strings.

        Path segments are preserved so structure is still visible. Query
        parameters (which often contain signed tokens) are dropped entirely.
        """
        def _replace(m: re.Match) -> str:
            rest = m.group("rest")
            # Strip query and fragment; keep only path
            path = rest.split("?")[0].split("#")[0]
            return f"{m.group('scheme')}://example.com{path}"
        return _URL_RE.sub(_replace, text)

    def redact_log_group(self, text: str) -> str:
        """Replace the log-group name component in /aws/<svc>/<name> patterns.

        The service prefix (lambda, ecs, apigateway …) is preserved so the
        log origin is still identifiable; only the first name component that
        could reveal a project or function name is scrubbed.

        Idempotent: if the name component is already a fake name produced by
        a prior scrub_stream pass, it is returned unchanged.
        """
        def _replace(m: re.Match) -> str:
            name = m.group(2)
            # Idempotence guard: already a fake name → leave it alone
            if name in self._fake_names:
                return m.group(0)
            fake_name = self.redact_name(name)
            return f"{m.group(1)}{fake_name}"
        return _LOG_GROUP_RE.sub(_replace, text)

    def redact_ipv6_address(self, address: str) -> str:
        """Map one whole IPv6 address to a clean RFC 3849 doc-range address.

        The stream rule (``redact_ipv6``) substitutes a constant and leaves
        compressed forms looking malformed; a host column holds exactly one
        address, so it gets a deterministic ``2001:db8:xxxx::yyyy`` instead.
        """
        if not address or address.lower().startswith(_FAKE_IPV6_PREFIX):
            return address
        cached = self._ipv6_cache.get(address)
        if cached is not None:
            return cached
        head = _hash_int(address, 0xFFFF)
        tail = _hash_int(address + "tail", 0xFFFF) + 1
        fake = f"{_FAKE_IPV6_PREFIX}{head:x}::{tail:x}"
        self._ipv6_cache[address] = fake
        return fake

    def redact_ec2_ids(self, text: str) -> str:
        """Replace EC2 instance ids embedded in free text.

        CloudTrail usernames for instance-role sessions, log lines and tool
        output all carry ``i-…`` ids; the fake keeps the id shape and is the
        same one the fleet table shows for that instance.
        """
        if not text:
            return text
        return _EC2_ID_RE.sub(lambda m: self.redact_instance_id(m.group(0)), text)

    def redact_dashed_ip(self, text: str) -> str:
        """Replace ``ip-A-B-C-D`` host fragments with the dashed form of the
        doc-range IP ``redact_ip`` maps ``A.B.C.D`` to (same session mapping,
        so a dashed and a dotted spelling of one host agree on screen)."""
        def _replace(m: re.Match) -> str:
            dotted = ".".join(m.groups())
            return "ip-" + self.redact_ip(dotted).replace(".", "-")
        return _DASHED_IP_RE.sub(_replace, text)

    def redact_ipv6(self, text: str) -> str:
        """Replace IPv6 addresses with the RFC 3849 documentation address.

        Matches groups of 2-7 hex-colon segments (requiring ≥3 colons total)
        to avoid false-positives on MAC addresses (aa:bb:cc:dd:ee:ff) which
        have 5 colons but no leading word boundary matching the ``\b`` anchor
        combined with the {2,7} repetition in the regex.

        Known limitation: loopback ``::1`` and compressed forms with only one
        colon group are not matched — see docs/demo-mode.md.

        Clock times and durations (``19:15:03``, ``1:23:45``) share the
        two-colon digit shape and are left alone: an address is only assumed
        when the match has hex letters or at least three colons.
        """
        def _replace(m: re.Match) -> str:
            value = m.group(0)
            if value.count(":") <= 2 and not re.search(r"[a-fA-F]", value):
                return value
            return "2001:db8::1"

        return _IPV6_RE.sub(_replace, text)

    def redact_ecr_host(self, text: str) -> str:
        """Replace the AWS account-ID component in ECR hostnames.

        ``123456789012.dkr.ecr.us-east-1.amazonaws.com`` becomes
        ``000000000000.dkr.ecr.us-east-1.amazonaws.com``.

        Must run BEFORE redact_account_id so the dot-bounded account stays
        in its ECR-specific syntactic context (the bare-account regex has a
        negative dot-lookaround that would otherwise exclude the match).
        """
        return _ECR_HOST_RE.sub(r"000000000000.dkr.ecr.\2.amazonaws.com", text)

    def redact_email(self, text: str) -> str:
        """Replace email addresses with a fake local-part @ example.com.

        The local part (before @) is replaced with a deterministic fake name
        drawn from the same name pool as ``redact_name`` so that the same
        email address always maps to the same fake name within a session.

        The domain is unconditionally replaced with ``example.com``.

        Idempotent: if the local part is already a member of ``_fake_names``
        (i.e. already replaced in a prior scrub pass) the address is left
        unchanged — this prevents double-substitution in re-render scenarios.

        Applied AFTER ``redact_url`` in the ``scrub_stream`` pipeline so that
        URL-embedded credentials (``user:pass@host``) are consumed first.
        """
        def _replace(m: re.Match) -> str:
            local = m.group(1)
            # Idempotence guard: local part already fake → leave it alone.
            if local in self._fake_names:
                return m.group(0)
            fake_local = self.redact_name(local)
            return f"{fake_local}@example.com"
        return _EMAIL_RE.sub(_replace, text)

    def redact_resource_name(self, text: str) -> str:
        """Redact S3 bucket names via explicit s3:// URIs only.

        Quoted DNS-shaped bucket names are intentionally excluded: the pattern
        is too broad and matches free-form prose such as "hello-world". Use
        the s3:// URI form in chat / logs to guarantee redaction.
        See docs/demo-mode.md Known Limitations for details.

        Idempotent: if the bucket name is already a fake name produced by a
        prior scrub_stream pass, it is returned unchanged.
        """
        def _replace_uri(m: re.Match) -> str:
            name = m.group(1)
            # Idempotence guard: already a fake name → leave it alone
            if name in self._fake_names:
                return m.group(0)
            fake = self.redact_name(name)
            return f"s3://{fake}"

        text = _S3_URI_RE.sub(_replace_uri, text)
        return text

    def scrub_stream(self, text: str | None) -> str:
        """Full-pipeline scrubber for any user-visible streamed string.

        Composition order (tested, order matters — see below):
          1. memory.redaction.default_redactor — secrets first (API keys, JWTs …)
          2. self.redact_text             — IPv4 → RFC 5737 doc-range
          2b. self.redact_dashed_ip       — ip-A-B-C-D fragments, same mapping
          3. self.redact_arn              — ARN account-id → 000000000000
          4. self.redact_account_id       — bare 12-digit AWS account
          5. self.redact_log_group        — /aws/<svc>/<name>
          6. self.redact_url              — host → example.com, query stripped
          7. self.redact_email            — user@domain → fake@example.com
          8. self.redact_path             — /home/<user>/, /Users/<user>/
          9. self.redact_resource_name    — S3 buckets (quoted) + s3:// URI

        Order rationale: secrets before name/IP substitution so embedded keys
        inside URLs are masked first; IPs before hostnames because doc-range
        IPs are explicitly guarded; ARN before account_id so ARN-embedded
        accounts get their in-place replacement, not the bare-account regex.
        URL before email so URL-embedded credentials (user:pass@host) are
        consumed by the URL regex first.

        Args:
            text: Any string. None returns ""; non-str is coerced with str().

        Returns:
            Idempotent string — scrub_stream(scrub_stream(s)) == scrub_stream(s).

        Performance:
            ~25–40 µs per 200-char log line; ~5–8 ms per MiB. Safe for
            tail -f streams ≤200 lines/sec inside the 100 ms flush tick.

        Demo-mode guard: CALLER-SIDE. RedactionService has no app reference.
        Each call site uses:
            if self.app.demo_mode and self.app.redaction_service:
                line = self.app.redaction_service.scrub_stream(line)

        Kill switch: SERVONAUT_DEMO_DISABLE_STREAM=1 returns input unchanged.
        """
        if text is None:
            return ""
        if not isinstance(text, str):
            text = str(text)
        if not text:
            return text

        if os.environ.get("SERVONAUT_DEMO_DISABLE_STREAM") == "1":
            return text

        orig = text
        try:
            text = default_redactor(text)
            text = self.redact_text(text)
            text = self.redact_dashed_ip(text)
            text = self.redact_ec2_ids(text)
            text = self.redact_ipv6(text)
            text = self.redact_arn(text)
            text = self.redact_ecr_host(text)
            text = self.redact_account_id(text)
            text = self.redact_log_group(text)
            text = self.redact_url(text)
            text = self.redact_email(text)
            text = self.redact_path(text)
            text = self.redact_resource_name(text)
            return text
        except Exception:
            logger.exception("scrub_stream failed; falling back to redact_text only")
            try:
                return self.redact_text(orig)
            except Exception:
                return "<redaction-error>"
