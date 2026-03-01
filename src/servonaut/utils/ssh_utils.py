"""SSH utility functions for path handling and validation."""

from __future__ import annotations
import os
from pathlib import Path
from typing import List


def expand_key_path(key_path: str) -> str:
    """Expand ~ and environment variables in key path.

    Args:
        key_path: Path to SSH key file (may contain ~ or env vars).

    Returns:
        Fully expanded absolute path.

    Examples:
        >>> expand_key_path('~/my-key.pem')
        '/home/user/my-key.pem'
    """
    return os.path.expanduser(os.path.expandvars(key_path))


def validate_key_path(key_path: str) -> bool:
    """Check if key file exists and is a regular file.

    Args:
        key_path: Path to SSH key file.

    Returns:
        True if key file exists and is a regular file.

    Examples:
        >>> validate_key_path('/path/to/nonexistent.pem')
        False
    """
    expanded = expand_key_path(key_path)
    return os.path.isfile(expanded)


def get_key_permissions(key_path: str) -> str:
    """Get key file permissions as octal string (e.g., '600').

    Args:
        key_path: Path to SSH key file.

    Returns:
        Three-digit octal permission string.

    Examples:
        >>> get_key_permissions('/path/to/key.pem')  # doctest: +SKIP
        '600'
    """
    expanded = expand_key_path(key_path)
    return oct(os.stat(expanded).st_mode)[-3:]


def parse_ssh_output(output: str) -> List[str]:
    """Split SSH command output into lines, stripping whitespace.

    Args:
        output: Raw output from SSH command.

    Returns:
        List of non-empty trimmed lines.

    Examples:
        >>> parse_ssh_output('line1\\n  line2  \\n\\nline3\\n')
        ['line1', 'line2', 'line3']
    """
    return [line.strip() for line in output.splitlines() if line.strip()]
