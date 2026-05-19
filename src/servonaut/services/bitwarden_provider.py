"""Bitwarden Secrets Manager :class:`SecretProvider` implementation.

Wraps the upstream ``bws`` CLI (https://bitwarden.com/help/secrets-manager-cli/)
behind the same :class:`SecretProviderInterface` :class:`LocalProvider`
implements, so consumers (``ssh_service``, the future named-secret
resolver, the chat-panel "what credentials do I have?" hooks) can swap
backends transparently per the active :class:`SecretsConfig`.

Why subprocess instead of a Python SDK?
    Bitwarden ships ``bws`` (Rust) but does NOT publish a stable
    Python SDK at the time of writing (kickoff doc §Provider config
    schemas confirms this). Shelling out keeps us on the supported
    surface and means a future ``bws`` upgrade lands without a CLI
    release on our side. The performance hit (one fork+exec per
    operation, ~30-80ms) is negligible against the network round-trip
    to the Bitwarden API that ``bws`` itself makes.

Why the value never crosses MCP:
    The :class:`SecretProviderInterface` docstring spells this out —
    secrets values are exempt from the MCP audit / cross-boundary
    surface; tools may pass NAMES only. This file is a CLI-internal
    consumer of those values; if a future MCP tool wants to surface
    Bitwarden secrets it MUST resolve them inside the executor and
    let only the resulting effect (e.g. an SSH session) cross.

Authentication model:
    ``bws`` reads an access token from one of:
      1. ``BWS_ACCESS_TOKEN`` (or whatever env var the team's
         :class:`SecretsConfig` points at via ``token_env_var``).
      2. The interactive ``bws config server`` flow (not used here).

    The CLI is responsible for setting the env var BEFORE invoking
    ``bws``. We resolve the value at *call time*, not construction
    time, so a user who sets the var via ``servonaut secrets refresh``
    mid-session has it picked up without restarting.

Naming model:
    Bitwarden addresses secrets by UUID, not by name. We translate
    name → secret-id via ``bws secret list --output json`` and
    pattern-match on the ``key`` field. That's O(n) per operation;
    fine for the modest secret counts (<200 per project) Teams
    customers will realistically hit.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
from typing import Any, Dict, List, Optional

from .interfaces import (
    SecretProviderInterface,
    _validate_secret_name,
    _validate_secret_value,
)

logger = logging.getLogger(__name__)


# Token-shaped substrings the redaction layer scrubs from any error
# context that may surface to logs, UI, or test snapshots. Bitwarden
# occasionally echoes the presented access token in error responses
# (well-formed but expired, malformed-prefix, etc.) — leaking that
# downstream would defeat the "token never on argv" guarantee.
# Patterns are coarse on purpose: we'd rather over-redact a benign
# id field than under-redact a real token. Replacement preserves
# enough shape that an operator can recognise "yes, there was a
# token here" without seeing the secret material.
_TOKEN_REDACTION_PATTERNS = [
    # Generic bearer / access-token-style key=value fragments.
    re.compile(
        r"(?i)((?:access[_-]?token|bearer|token|api[_-]?key|secret)\s*[=:]\s*)"
        r"['\"]?([^\s'\"&]{8,})['\"]?"
    ),
    # Bitwarden Secrets Manager access tokens — long opaque strings
    # often introduced with a "0." prefix and dot-separated segments.
    re.compile(r"\b(0\.[A-Za-z0-9_\-]{20,}(?:\.[A-Za-z0-9_\-]{8,})*)\b"),
]


def _redact_token_material(text: str, *, extra_literals: Optional[List[str]] = None) -> str:
    """Replace token-shaped substrings in ``text`` with ``<redacted>``.

    Two passes:
    1. Generic patterns from :data:`_TOKEN_REDACTION_PATTERNS` — match
       key/value fragments and BWS-shaped opaque blobs.
    2. The caller's own ``extra_literals`` — anything they're confident
       is sensitive (typically the current value of the configured
       token env var, captured at error-construction time).

    Returns the redacted string. Never raises; on a regex / type error
    we fall back to the original value rather than swallow context.
    """
    if not text:
        return text
    redacted = text
    try:
        for pat in _TOKEN_REDACTION_PATTERNS:
            # Group-aware substitution: keep the "access_token=" prefix
            # visible so operators can see WHAT was redacted, just not
            # the value.
            if pat.groups >= 2:
                redacted = pat.sub(r"\1<redacted>", redacted)
            else:
                redacted = pat.sub("<redacted>", redacted)
        if extra_literals:
            for literal in extra_literals:
                if literal and len(literal) >= 4:
                    redacted = redacted.replace(literal, "<redacted>")
    except (re.error, TypeError):
        return text
    return redacted


# Default ``bws`` invocation timeout. Most operations land in <2s
# against bitwarden.com; 15s gives plenty of slack for a slow network
# without making the TUI hang on a hard-broken backend.
DEFAULT_BWS_TIMEOUT_SECONDS = 15

# Sentinel for the default env var that holds the BWS access token.
# The team's :class:`SecretsConfig` can override this per project so
# customers running multiple Bitwarden orgs side by side don't have
# their tokens collide.
DEFAULT_TOKEN_ENV_VAR = "BWS_ACCESS_TOKEN"


class BitwardenProviderError(RuntimeError):
    """Base class for all :class:`BitwardenProvider` failures.

    Distinguished into specific subclasses so callers (chat panel,
    SSH key resolver, settings screen) can format the right
    remediation message without parsing strings.
    """


class BitwardenCLIMissingError(BitwardenProviderError):
    """``bws`` is not on ``PATH``.

    Surface this to the user with a pointer to
    ``servonaut secrets install bws`` (planned Step 8) — the executor
    will run the upstream installer for the user's platform.
    """


class BitwardenTokenMissingError(BitwardenProviderError):
    """The env var named by the team config is unset or empty.

    Pointing the team config at a missing env var is a configuration
    bug rather than a transient failure; we raise instead of
    returning ``None`` so the user gets a clear "your machine isn't
    set up" message instead of a silent empty result.
    """


class BitwardenAPIError(BitwardenProviderError):
    """The ``bws`` subprocess exited non-zero or produced bad output.

    The ``.stderr`` and ``.exit_code`` attributes carry the failure
    details so callers can log them at WARNING. Both ``message`` and
    ``stderr`` go through :func:`_redact_token_material` on
    construction so a caller that blindly logs ``str(exc)`` or
    ``exc.stderr`` cannot accidentally leak token fragments —
    Bitwarden's error messages occasionally echo a (well-formed but
    expired, or malformed-prefix) presented token, and the CLI
    can't undo a log line after the fact.

    Pass ``token_literal=`` at construction time to redact that
    specific token value too (typically the current value of the
    configured token env var) — covers tokens shaped like Bitwarden's
    BWS access tokens that the generic patterns might miss.
    """

    def __init__(
        self,
        message: str,
        *,
        exit_code: Optional[int] = None,
        stderr: str = "",
        token_literal: Optional[str] = None,
    ) -> None:
        extras = [token_literal] if token_literal else None
        redacted_message = _redact_token_material(message, extra_literals=extras)
        redacted_stderr = _redact_token_material(stderr, extra_literals=extras)
        super().__init__(redacted_message)
        self.exit_code = exit_code
        self.stderr = redacted_stderr


class BitwardenProvider(SecretProviderInterface):
    """``bws``-CLI-backed implementation of :class:`SecretProviderInterface`.

    Args:
        project_id: Bitwarden project UUID the team config points at.
            All operations are scoped to this project — listing in
            particular MUST NOT enumerate secrets from a sibling
            project the access token happens to grant.
        token_env_var: Name of the OS env var that holds the BWS
            access token. Defaults to ``BWS_ACCESS_TOKEN``; team
            config can override per project.
        bws_path: Override the resolved ``bws`` binary path.
            Production code leaves this ``None`` (resolved via
            :func:`shutil.which` at first use); tests pin a fake
            script.
        timeout: Per-invocation subprocess timeout in seconds. Same
            value applies to every ``bws`` call this provider makes.

    The provider is constructed eagerly even on machines without
    ``bws`` installed — we don't want a fresh CLI to crash on import
    just because the optional dependency is missing. The friendly
    error fires on the first network-touching method call instead.
    """

    def __init__(
        self,
        project_id: str,
        token_env_var: str = DEFAULT_TOKEN_ENV_VAR,
        *,
        bws_path: Optional[str] = None,
        timeout: float = DEFAULT_BWS_TIMEOUT_SECONDS,
    ) -> None:
        if not project_id:
            raise ValueError(
                "BitwardenProvider requires a project_id from the team's "
                "SecretsConfig — empty value is a configuration bug."
            )
        self._project_id = project_id
        self._token_env_var = token_env_var or DEFAULT_TOKEN_ENV_VAR
        self._bws_path_override = bws_path
        self._timeout = timeout

    # ------------------------------------------------------------------
    # SecretProviderInterface
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "bitwarden"

    @property
    def project_id(self) -> str:
        """The Bitwarden project the provider is scoped to.

        Exposed so the status panel can render which project's
        secrets are visible without reaching for a private attribute.
        """
        return self._project_id

    async def get_secret(self, name: str) -> Optional[str]:
        name = _validate_secret_name(name)
        match = await self._find_by_key(name)
        if match is None:
            return None
        value = match.get("value")
        return value if isinstance(value, str) else None

    async def set_secret(self, name: str, value: str) -> None:
        name = _validate_secret_name(name)
        value = _validate_secret_value(value)
        existing = await self._find_by_key(name)
        if existing is None:
            # ``bws secret create <key> <value> <project_id>``.
            await self._run_bws_json(
                "secret", "create", name, value, self._project_id,
            )
            return
        # Update in place by ID. Bitwarden allows changing both key
        # and value via ``edit``; we only need to bump the value.
        secret_id = existing.get("id")
        if not isinstance(secret_id, str) or not secret_id:
            raise BitwardenAPIError(
                f"bws returned a secret with no id for key {name!r}; "
                "cannot perform update safely",
            )
        await self._run_bws_json(
            "secret", "edit", secret_id, "--value", value,
        )

    async def delete_secret(self, name: str) -> bool:
        name = _validate_secret_name(name)
        existing = await self._find_by_key(name)
        if existing is None:
            return False  # Idempotent per interface contract.
        secret_id = existing.get("id")
        if not isinstance(secret_id, str) or not secret_id:
            # Shouldn't happen — bws guarantees IDs — but failing
            # gracefully beats crashing the caller.
            logger.warning(
                "delete_secret(%r): bws returned a secret with no id; "
                "treating as not present",
                name,
            )
            return False
        await self._run_bws("secret", "delete", secret_id)
        return True

    async def list_secrets(self) -> List[str]:
        raw = await self._list_raw()
        names = [
            item["key"] for item in raw
            if isinstance(item, dict) and isinstance(item.get("key"), str)
        ]
        return sorted(names)

    # ------------------------------------------------------------------
    # bws subprocess plumbing
    # ------------------------------------------------------------------

    def _resolve_bws_path(self) -> str:
        """Locate the ``bws`` binary, raising :class:`BitwardenCLIMissingError`
        with a remediation hint if it's not installed.

        Resolved at call time, not in ``__init__``: a user who
        ``pipx install bws`` mid-session shouldn't have to restart
        the TUI.
        """
        if self._bws_path_override:
            return self._bws_path_override
        path = shutil.which("bws")
        if not path:
            raise BitwardenCLIMissingError(
                "The Bitwarden Secrets Manager CLI (`bws`) is not installed. "
                "Run `servonaut secrets install bws` for a one-click install, "
                "or follow the manual instructions in the README."
            )
        return path

    def _resolve_token(self) -> str:
        """Read the access token from the configured env var.

        Stripped of surrounding whitespace because shells occasionally
        carry trailing newlines from `cat secret.txt | xargs -I {} export...`
        style flows.
        """
        raw = os.environ.get(self._token_env_var, "")
        token = raw.strip()
        if not token:
            raise BitwardenTokenMissingError(
                f"Bitwarden access token env var {self._token_env_var!r} "
                "is not set. Set it in your shell rc file or via "
                "`export "
                f"{self._token_env_var}=...` before running secrets-management "
                "commands. See "
                "https://bitwarden.com/help/personal-access-tokens/ for how "
                "to mint one."
            )
        return token

    async def _run_bws(
        self, *args: str, parse_json: bool = False,
    ) -> Any:
        """Invoke ``bws`` with the resolved path, token, and a JSON output flag.

        Returns:
            ``str`` if ``parse_json`` is False (raw stdout), or the
            parsed JSON object if True.

        Raises:
            :class:`BitwardenCLIMissingError`: ``bws`` not on PATH.
            :class:`BitwardenTokenMissingError`: env var unset.
            :class:`BitwardenAPIError`: non-zero exit, timeout, or
            malformed JSON output.
        """
        bws = self._resolve_bws_path()
        token = self._resolve_token()

        # Inject the access token via env, not argv — argv is visible
        # in /proc/<pid>/cmdline on Linux, leaking the token to any
        # local process that can read /proc.
        env = os.environ.copy()
        env[self._token_env_var] = token
        # Force JSON output where supported. ``bws`` accepts
        # ``--output json`` as a global flag in recent versions; for
        # subcommands that don't honour it (rare) we fall back to
        # parsing the human-readable output. The output flag goes
        # FIRST so it precedes the subcommand.
        full_args = ["--output", "json", *args] if parse_json else list(args)

        try:
            proc = await asyncio.create_subprocess_exec(
                bws, *full_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError as exc:
            # Race between :func:`shutil.which` and ``execve`` — the
            # binary was on PATH at the resolve step but is gone now.
            # Surface as the same error class the resolve step would
            # have raised.
            raise BitwardenCLIMissingError(
                "The Bitwarden Secrets Manager CLI (`bws`) is not installed."
            ) from exc

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=self._timeout,
            )
        except asyncio.TimeoutError as exc:
            # Kill the subprocess so we don't leak it.
            proc.kill()
            try:
                await proc.communicate()
            except Exception:  # noqa: BLE001
                pass
            raise BitwardenAPIError(
                f"`bws {' '.join(args)}` timed out after "
                f"{self._timeout}s. Bitwarden API may be slow or "
                "unreachable.",
                token_literal=token,
            ) from exc

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        if proc.returncode != 0:
            # Pass the token literal so the redaction layer scrubs
            # any echo of it back from bws-side error messages.
            raise BitwardenAPIError(
                f"`bws {' '.join(args)}` exited with code {proc.returncode}.",
                exit_code=proc.returncode,
                stderr=stderr,
                token_literal=token,
            )

        if not parse_json:
            return stdout

        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise BitwardenAPIError(
                f"`bws {' '.join(args)}` returned non-JSON output: {stdout[:200]!r}",
                stderr=stderr,
                token_literal=token,
            ) from exc

    async def _run_bws_json(self, *args: str) -> Any:
        """Convenience: :meth:`_run_bws` with ``parse_json=True``."""
        return await self._run_bws(*args, parse_json=True)

    async def _list_raw(self) -> List[Dict[str, Any]]:
        """Return the raw ``bws secret list`` output for this project.

        Scoped strictly to ``self._project_id`` even though the
        access token may grant the holder access to sibling projects
        in the same Bitwarden org. Cross-project listing would be a
        privacy bug — a Teams "view your secrets" UI showing items
        the user never wrote is a worse failure than a missing one.
        """
        result = await self._run_bws_json("secret", "list", self._project_id)
        if not isinstance(result, list):
            raise BitwardenAPIError(
                f"`bws secret list` returned non-list output: "
                f"{type(result).__name__}",
            )
        return result

    async def _find_by_key(self, name: str) -> Optional[Dict[str, Any]]:
        """Find a secret in this project by its ``key`` field.

        Returns the first match (Bitwarden allows duplicate keys
        within a project but the team-secrets-management UX in the
        kickoff doc treats names as unique; if you have duplicates,
        the first wins deterministically since :meth:`_list_raw`
        preserves bws' response ordering).
        """
        for item in await self._list_raw():
            if isinstance(item, dict) and item.get("key") == name:
                return item
        return None
