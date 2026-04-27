"""Secret-redaction library for server memory raw output.

Two redactor callables live here:

``noop_redactor(text) -> text``
    Returns its input unchanged.  Used as the ``redaction_enabled=False``
    code path and by tests that need a deterministic pass-through.

``default_redactor(text) -> text``
    The production regex-based scrubber.  It detects eleven secret
    categories and replaces each match with ``<redacted:{category}>`` so
    operators can see *what* was scrubbed without seeing the value itself.

Design rules
------------
1. Regexes compile **once at import time** — hot path is match-only.
2. Substitution always retains structural scaffolding (``=``, ``:``,
   ``Bearer ``) so downstream parsers don't break.
3. ``default_redactor`` never raises: any unexpected input type is
   coerced to ``str`` before processing.
4. Annotation warnings are produced by :func:`scan_for_secrets` — a
   separate entry point for the UI layer that wants to flag a user-authored
   annotation before saving it.

Tested extensively under ``tests/test_memory_redaction.py`` and
``tests/test_redaction_known_secrets.py`` (20+ positive + 20+ negative cases
plus a performance benchmark).
"""

from __future__ import annotations

import re
from typing import Callable, List, Tuple

# ---------------------------------------------------------------------------
# noop passthrough — unchanged signature so existing wiring keeps working.
# ---------------------------------------------------------------------------


def noop_redactor(text: str) -> str:
    """No-op redactor: returns *text* unchanged.

    Args:
        text: Raw output string.

    Returns:
        The same string, byte-identical.
    """
    return text


# ---------------------------------------------------------------------------
# Compiled patterns — each entry is (category, compiled_regex, replacement_builder).
# ---------------------------------------------------------------------------

# AWS access keys: AKIA / ASIA / AGPA / AROA / AIPA / ANPA / ANVA / ASCA prefixes.
_AWS_ACCESS_KEY_RE = re.compile(
    r"\b(?:AKIA|ASIA|AGPA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b"
)

# AWS secret access key — only match when we have a contextual prefix so we
# don't accidentally redact long base64 blobs elsewhere.
_AWS_SECRET_CONTEXT_RE = re.compile(
    r"(?P<prefix>aws_secret_access_key\s*[=:]\s*['\"]?)"
    r"(?P<secret>[A-Za-z0-9/+=]{40})",
    re.IGNORECASE,
)

# GitHub classic personal access tokens (ghp_) and fine-grained (github_pat_).
# Fine-grained tokens are a pat prefix followed by 22 chars, underscore, 59 chars.
_GITHUB_CLASSIC_PAT_RE = re.compile(r"\bghp_[A-Za-z0-9]{36}\b")
_GITHUB_FINE_GRAINED_PAT_RE = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{80,}\b")
# GitHub OAuth/server-to-server/refresh tokens share the same shape.
_GITHUB_OAUTH_RE = re.compile(r"\b(?:gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36}\b")

# JWT: three base64url segments separated by dots, starting with the canonical
# ``eyJ`` JSON header prefix so we don't mis-match arbitrary three-dot tokens.
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+\b"
)

# SSH/RSA/EC/DSA/ED25519 private-key blocks — DOTALL because the key body is
# multi-line.  Match the *entire* BEGIN…END armor so downstream tooling sees
# the placeholder instead of partial key material.
_SSH_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|ED25519) PRIVATE KEY-----"
    r".*?-----END (?:OPENSSH|RSA|EC|DSA|ED25519) PRIVATE KEY-----",
    re.DOTALL,
)

# Generic PEM blocks (certificates, private keys, encrypted keys).  Matched
# AFTER the SSH-specific pattern so those catch first and get the
# ``ssh-private-key`` tag.
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN (?:CERTIFICATE|PRIVATE KEY|ENCRYPTED PRIVATE KEY|"
    r"RSA PUBLIC KEY|PUBLIC KEY)-----"
    r".*?-----END (?:CERTIFICATE|PRIVATE KEY|ENCRYPTED PRIVATE KEY|"
    r"RSA PUBLIC KEY|PUBLIC KEY)-----",
    re.DOTALL,
)

# Generic bearer token — at least 20 chars after ``Bearer ``.
_BEARER_TOKEN_RE = re.compile(
    r"(?P<prefix>\bBearer\s+)(?P<token>[A-Za-z0-9\-_\.~+/=]{20,})"
)

# Password literal in ``password=...`` / ``password:...`` form.  Stops at
# whitespace or a closing quote, requires ≥4 chars after the operator.
_PASSWORD_LITERAL_RE = re.compile(
    r"(?P<prefix>\bpassword\s*[=:]\s*['\"]?)"
    r"(?P<pwd>[^\s'\"]{4,})(?P<suffix>['\"]?)",
    re.IGNORECASE,
)

# Slack tokens: xoxb-, xoxp-, xoxa-, xoxr-, xoxs- + numeric + more base62.
_SLACK_TOKEN_RE = re.compile(
    r"\bxox[baprs]-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-z0-9]{24,}\b"
)

# Stripe secret keys: ``sk_test_...`` / ``sk_live_...`` — at least 24 chars.
_STRIPE_KEY_RE = re.compile(r"\bsk_(?:test|live)_[A-Za-z0-9]{24,}\b")

# Connection strings with embedded credentials: mysql / postgres / mongodb.
_DB_CONN_STRING_RE = re.compile(
    r"(?P<scheme>(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?)://)"
    r"(?P<user>[^:/\s@]+):(?P<pwd>[^@\s]+)@"
)

# Ordering is critical: SSH-specific keys MUST run before the generic PEM
# rule so they're tagged ``ssh-private-key`` rather than ``pem-block``.
_REDACTORS: List[Tuple[str, re.Pattern, Callable[[re.Match], str]]] = [
    (
        "aws-access-key",
        _AWS_ACCESS_KEY_RE,
        lambda m: "<redacted:aws-access-key>",
    ),
    (
        "aws-secret-key",
        _AWS_SECRET_CONTEXT_RE,
        lambda m: f"{m.group('prefix')}<redacted:aws-secret-key>",
    ),
    (
        "github-token",
        _GITHUB_CLASSIC_PAT_RE,
        lambda m: "<redacted:github-token>",
    ),
    (
        "github-token",
        _GITHUB_FINE_GRAINED_PAT_RE,
        lambda m: "<redacted:github-token>",
    ),
    (
        "github-token",
        _GITHUB_OAUTH_RE,
        lambda m: "<redacted:github-token>",
    ),
    (
        "ssh-private-key",
        _SSH_PRIVATE_KEY_RE,
        lambda m: "<redacted:ssh-private-key>",
    ),
    (
        "pem-block",
        _PEM_BLOCK_RE,
        lambda m: "<redacted:pem-block>",
    ),
    (
        "bearer-token",
        _BEARER_TOKEN_RE,
        lambda m: f"{m.group('prefix')}<redacted:bearer-token>",
    ),
    (
        "password",
        _PASSWORD_LITERAL_RE,
        lambda m: f"{m.group('prefix')}<redacted:password>{m.group('suffix')}",
    ),
    (
        "slack-token",
        _SLACK_TOKEN_RE,
        lambda m: "<redacted:slack-token>",
    ),
    (
        "stripe-key",
        _STRIPE_KEY_RE,
        lambda m: "<redacted:stripe-key>",
    ),
    (
        "conn-string",
        _DB_CONN_STRING_RE,
        lambda m: (
            f"{m.group('scheme')}<redacted:conn-user>:<redacted:conn-pass>@"
        ),
    ),
]

# JWT is applied at the very end — eyJ headers appear inside many tokens and
# would otherwise shadow more-specific patterns.
_JWT_REDACTOR: Tuple[str, re.Pattern, Callable[[re.Match], str]] = (
    "jwt",
    _JWT_RE,
    lambda m: "<redacted:jwt>",
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def default_redactor(text: str) -> str:
    """Apply every compiled secret pattern and return the scrubbed string.

    Args:
        text: Raw output (probe stdout, annotation body, or similar).

    Returns:
        The string with every matching secret replaced by
        ``<redacted:{category}>`` (or a structure-preserving variant).

    Notes:
        Ordering matters — SSH-specific blocks run before the generic PEM
        block, and JWT runs last so eyJ tokens don't get eaten by earlier
        narrower rules.  This keeps the category labels precise.
    """
    if not isinstance(text, str):
        text = str(text)

    for _, pattern, builder in _REDACTORS:
        text = pattern.sub(builder, text)

    # JWT last — so eyJ tokens inside OAuth or bearer contexts don't get
    # relabelled ``jwt`` when a more-specific category would have fired.
    text = _JWT_RE.sub(_JWT_REDACTOR[2], text)

    return text


def scan_for_secrets(text: str) -> List[str]:
    """Return the ordered list of secret categories found in *text*.

    Used by the UI layer before saving user-authored annotations: if the
    list is non-empty the UI must show a warning ("Possible secret detected
    — please review") but still allow the save, because the user may have
    intentionally pasted a placeholder.

    Args:
        text: String to scan (typically a short annotation body).

    Returns:
        Ordered list of category labels for every pattern that matched.
        Empty when no secrets are detected.
    """
    if not isinstance(text, str) or not text:
        return []

    found: List[str] = []
    for category, pattern, _ in _REDACTORS:
        if pattern.search(text):
            found.append(category)
    if _JWT_RE.search(text):
        found.append("jwt")
    return found
