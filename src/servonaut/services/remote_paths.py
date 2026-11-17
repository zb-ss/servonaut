"""Read-only path checks using an already resolved SSH connection."""

from __future__ import annotations

import asyncio
import subprocess
import posixpath

from servonaut.utils.remote_shell import shell_path, posix_command
from servonaut.utils.ssh_utils import run_ssh
from servonaut.utils.scp_client import remote_path_value


async def remote_path_kind(app, options: dict, path: str) -> str:
    """Return directory/file/other/missing, preserving the connection identity."""
    quoted = shell_path(remote_path_value(path))
    command = (
        f"if [ -d {quoted} ]; then printf directory; "
        f"elif [ -f {quoted} ]; then printf file; "
        f"elif [ -e {quoted} ] || [ -L {quoted} ]; then printf other; "
        "else printf missing; fi"
    )
    output = await _read_remote(app, options, posix_command(command))
    kind = output.strip()
    if kind not in {'directory', 'file', 'other', 'missing'}:
        raise RuntimeError('The server returned an invalid path response')
    return kind


async def remote_home_basename(app, options: dict) -> str:
    """A '~' folder source lands under the login home's actual basename."""
    output = await _read_remote(app, options, posix_command('printf "%s\\0" "$HOME"'))
    if not output.endswith('\0') or '\0' in output[:-1] or not output.startswith('/'):
        raise RuntimeError('Could not resolve the remote home folder')
    return posixpath.basename(output[:-1].rstrip('/')) or '.'


async def remote_parent_directory(app, options: dict, path: str) -> str:
    """Resolve Up for home and dot paths without assuming the server's home."""
    script = f'cd {shell_path(remote_path_value(path))} && cd .. && printf "%s\\0" "$PWD"'
    output = await _read_remote(app, options, posix_command(script))
    if not output.endswith('\0') or '\0' in output[:-1] or not output.startswith('/'):
        raise RuntimeError('Could not resolve the parent folder')
    return output[:-1]


def path_error_message(error: str) -> str:
    """Explain a failed folder load without displaying remote command output."""
    lowered = error.lower()
    if 'permission denied' in lowered:
        return "You don't have permission to open this folder."
    if any(part in lowered for part in ('no such file', 'cannot access', 'not found', 'not a directory', 'existing folder')):
        return 'This folder was not found. Enter an existing folder.'
    if 'timed out' in lowered or 'timeout' in lowered:
        return 'The server took too long to respond. Try again.'
    if 'authentication' in lowered or 'sign in' in lowered:
        return 'Could not sign in to the server. Check the connection settings.'
    if 'host key' in lowered or 'host-key' in lowered:
        return "Could not verify the server's identity. Check the connection settings."
    if any(part in lowered for part in ('connection refused', 'unreachable', 'no route')):
        return 'Could not connect to the server. Try again.'
    if 'named-user home' in lowered or 'nul character' in lowered:
        return error
    return 'Could not open this folder. Try again or enter another location.'


async def _read_remote(app, options: dict, command: str) -> str:
    argv = app.ssh_service.build_ssh_command(remote_command=command, **options)
    try:
        result = await asyncio.to_thread(
            run_ssh, argv, capture_output=True, text=False,
            timeout=app.config_manager.get().ssh.connect_timeout,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError('Connection timed out') from error
    stdout = result.stdout.decode('utf-8', errors='surrogateescape') if isinstance(result.stdout, bytes) else result.stdout
    stderr = result.stderr.decode('utf-8', errors='replace') if isinstance(result.stderr, bytes) else result.stderr
    if result.returncode:
        raise RuntimeError(stderr.strip() or 'Could not inspect the remote path')
    return stdout
