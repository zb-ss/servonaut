"""SSH utility functions for path handling and validation."""

from __future__ import annotations
import asyncio
import logging
import os
from pathlib import Path
from typing import List, Sequence, Tuple, Union

logger = logging.getLogger(__name__)


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


async def run_ssh_subprocess(
    ssh_cmd: Sequence[Union[str, os.PathLike]],
    timeout: float = 30,
) -> Tuple[bytes, bytes]:
    """Run an SSH command as a subprocess, returning (stdout, stderr).

    Properly closes the asyncio transport after completion to prevent
    'Event loop is closed' errors on application shutdown.
    """
    proc = await asyncio.create_subprocess_exec(
        *[str(a) for a in ssh_cmd],
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return stdout, stderr
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    finally:
        # Explicitly close transport to avoid __del__ errors after event loop closes
        transport = getattr(proc, '_transport', None)
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
