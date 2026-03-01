"""Centralized secret resolution for Servonaut configuration values."""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_SECRETS_PATH = Path.home() / '.secrets' / 'servonaut.env'


def resolve_secret(value: str) -> str:
    """Resolve a secret value from env var, file, or plain text.

    Supported syntaxes:
        - ``$ENV_VAR`` — reads from ``os.environ``
        - ``file:/path/to/secret`` — reads file contents (whitespace-stripped)
        - plain text — returned as-is

    Returns:
        The resolved secret string, or empty string if the reference
        cannot be resolved (env var unset, file missing).
    """
    if not value:
        return value

    # $ENV_VAR syntax
    if value.startswith('$'):
        return os.environ.get(value[1:], '')

    # file:/path syntax
    if value.startswith('file:'):
        file_path = Path(value[5:]).expanduser()
        try:
            return file_path.read_text().strip()
        except (OSError, IOError):
            logger.warning("Secret file not found or unreadable: %s", file_path)
            return ''

    # Plain text
    return value


def is_secret_ref(value: str) -> bool:
    """Check whether a value is a secret reference ($VAR or file:path)."""
    if not value:
        return False
    return value.startswith('$') or value.startswith('file:')


def load_secrets_env(path: str | Path = DEFAULT_SECRETS_PATH) -> None:
    """Load KEY=value pairs from a file into ``os.environ``.

    Existing environment variables take precedence (are not overwritten).
    Supports ``#`` comments, blank lines, and optional single/double quoting
    around values.  No external dependencies required.

    Args:
        path: Path to the env file.  Silently skipped if missing.
    """
    secrets_path = Path(path).expanduser()
    if not secrets_path.is_file():
        return

    logger.debug("Loading secrets from %s", secrets_path)

    for lineno, raw_line in enumerate(secrets_path.read_text().splitlines(), 1):
        line = raw_line.strip()

        # Skip blanks and comments
        if not line or line.startswith('#'):
            continue

        # Expect KEY=value
        if '=' not in line:
            logger.warning("%s:%d: skipping malformed line (no '=')", secrets_path, lineno)
            continue

        key, _, val = line.partition('=')
        key = key.strip()
        val = val.strip()

        if not key:
            continue

        # Strip optional quoting
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            val = val[1:-1]

        # Env takes precedence — don't overwrite existing vars
        if key not in os.environ:
            os.environ[key] = val
