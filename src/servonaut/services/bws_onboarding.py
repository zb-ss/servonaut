"""Guided ``bws`` onboarding helpers — Layer B1 of the DB-credential vault.

Stateless helpers shared by the ``servonaut secrets setup`` CLI wizard and
the TUI :class:`SecretsSetupScreen`. They cover the two steps the raw
:class:`BitwardenProvider` can't (it requires a ``project_id`` at
construction, which is the very thing the operator is trying to choose):

- :func:`list_bws_projects` — ``bws project list`` so the operator can PICK
  a project by NAME instead of pasting a UUID (kills the project_id
  friction; parallels the SSH-key picker).
- :func:`bws_test_connection` — ``bws secret list <project_id>`` to confirm
  the token + project resolve BEFORE we persist config. Critical at scale:
  don't let the operator invest in imports against a misconfigured project.

Security contract (carried over from :class:`BitwardenProvider`):
- The bws access token is read from an ENV VAR and injected into the
  subprocess environment — NEVER passed on argv (argv leaks via
  ``/proc/<pid>/cmdline``) and NEVER persisted anywhere.
- Any bws-side error text is scrubbed of the token literal before it
  surfaces to a UI string / log.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from dataclasses import dataclass
from typing import List

logger = logging.getLogger(__name__)

DEFAULT_TOKEN_ENV_VAR = "BWS_ACCESS_TOKEN"
_BWS_TIMEOUT_SECONDS = 30.0


class BwsOnboardingError(Exception):
    """A step of the guided bws setup could not complete.

    Carries a user-facing message with any token literal already
    scrubbed. The wizard renders ``str(exc)`` directly.
    """


@dataclass(frozen=True)
class BwsProject:
    """One Bitwarden Secrets Manager project the access token can see."""

    id: str
    name: str


def bws_installed() -> bool:
    """``True`` iff the ``bws`` CLI is resolvable on PATH."""
    return shutil.which("bws") is not None


def token_is_set(token_env_var: str = DEFAULT_TOKEN_ENV_VAR) -> bool:
    """``True`` iff the configured token env var holds a non-empty value."""
    return bool(os.environ.get(token_env_var, "").strip())


def _redact(text: str, token: str) -> str:
    """Scrub the token literal from bws-side error text before surfacing."""
    if token and token in text:
        text = text.replace(token, "<redacted-token>")
    return text.strip()


async def _run_bws_json(
    *args: str,
    token_env_var: str = DEFAULT_TOKEN_ENV_VAR,
    timeout: float = _BWS_TIMEOUT_SECONDS,
) -> object:
    """Run ``bws --output json <args>`` with the token injected via env.

    Mirrors :meth:`BitwardenProvider._run_bws` (token via env not argv,
    JSON output, timeout, token-scrubbed errors) but is token-only — it
    needs no ``project_id``, so it can run BEFORE one is chosen.
    """
    bws = shutil.which("bws")
    if not bws:
        raise BwsOnboardingError(
            "The Bitwarden Secrets Manager CLI (`bws`) is not installed. "
            "Run `servonaut secrets install bws` first."
        )
    token = os.environ.get(token_env_var, "").strip()
    if not token:
        raise BwsOnboardingError(
            f"Access token env var {token_env_var!r} is not set. "
            f"Set it with `export {token_env_var}=<token>` and retry."
        )
    env = os.environ.copy()
    env[token_env_var] = token
    try:
        proc = await asyncio.create_subprocess_exec(
            bws, "--output", "json", *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except FileNotFoundError as exc:  # race between which() and execve
        raise BwsOnboardingError(
            "`bws` disappeared from PATH before it could run."
        ) from exc

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout,
        )
    except asyncio.TimeoutError as exc:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:  # noqa: BLE001
            pass
        raise BwsOnboardingError(
            f"`bws {' '.join(args)}` timed out after {timeout:.0f}s. "
            "The Bitwarden API may be slow or unreachable."
        ) from exc

    stdout = stdout_b.decode("utf-8", errors="replace")
    stderr = stderr_b.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        raise BwsOnboardingError(
            f"`bws {' '.join(args)}` failed (exit {proc.returncode}): "
            f"{_redact(stderr, token) or '(no error output)'}"
        )
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise BwsOnboardingError(
            f"`bws {' '.join(args)}` returned non-JSON output."
        ) from exc


async def list_bws_projects(
    token_env_var: str = DEFAULT_TOKEN_ENV_VAR,
    *,
    timeout: float = _BWS_TIMEOUT_SECONDS,
) -> List[BwsProject]:
    """Return the projects the current access token can see (by name).

    Lets the wizard offer a pick-by-name list instead of a UUID paste.
    Raises :class:`BwsOnboardingError` on any failure (bws missing, token
    unset, API error) with a token-scrubbed message.
    """
    data = await _run_bws_json(
        "project", "list", token_env_var=token_env_var, timeout=timeout,
    )
    if not isinstance(data, list):
        raise BwsOnboardingError(
            "`bws project list` returned an unexpected shape "
            f"({type(data).__name__}); expected a list."
        )
    projects: List[BwsProject] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        pid = item.get("id")
        if not isinstance(pid, str) or not pid:
            continue
        name = item.get("name")
        projects.append(BwsProject(id=pid, name=str(name) if name else ""))
    return projects


async def bws_test_connection(
    project_id: str,
    token_env_var: str = DEFAULT_TOKEN_ENV_VAR,
) -> int:
    """Validate the token + project by listing the project's secrets.

    Returns the secret count on success (0 is a valid, healthy result —
    a brand-new project). Reuses :class:`BitwardenProvider` so the
    subprocess + token + scoping contract is byte-for-byte identical to
    the production read path. Raises :class:`BwsOnboardingError` on
    failure, with the token literal scrubbed.
    """
    pid = (project_id or "").strip()
    if not pid:
        raise BwsOnboardingError("A project_id is required to test the connection.")
    from servonaut.services.bitwarden_provider import (
        BitwardenProvider,
        BitwardenProviderError,
    )

    provider = BitwardenProvider(project_id=pid, token_env_var=token_env_var)
    try:
        names = await provider.list_secrets()
    except BitwardenProviderError as exc:
        # BitwardenProviderError subclasses already scrub the token literal.
        raise BwsOnboardingError(str(exc)) from exc
    return len(names)
