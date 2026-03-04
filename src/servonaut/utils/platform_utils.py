"""Platform detection and OS-specific utilities."""

from __future__ import annotations
import platform
import shutil
import subprocess
from pathlib import Path


def get_os() -> str:
    """Get operating system type.

    Returns:
        One of: 'linux', 'darwin' (macOS), or 'windows'.

    Examples:
        >>> get_os() in ['linux', 'darwin', 'windows']
        True
    """
    system = platform.system().lower()
    if system == 'darwin':
        return 'darwin'
    elif system == 'linux':
        return 'linux'
    elif system == 'windows':
        return 'windows'
    else:
        # Fallback for unknown systems
        return system


def command_exists(cmd: str) -> bool:
    """Check if a command exists in PATH.

    Args:
        cmd: Command name to check (e.g., 'ssh', 'git').

    Returns:
        True if command is available in PATH.

    Examples:
        >>> command_exists('python')
        True
        >>> command_exists('nonexistent_command_xyz')
        False
    """
    return shutil.which(cmd) is not None


def get_home_dir() -> Path:
    """Get user's home directory.

    Returns:
        Path to home directory.

    Examples:
        >>> get_home_dir().exists()
        True
    """
    return Path.home()


def get_ssh_dir() -> Path:
    """Get user's SSH directory (~/.ssh).

    Returns:
        Path to .ssh directory (may not exist).

    Examples:
        >>> get_ssh_dir().name
        '.ssh'
    """
    return Path.home() / '.ssh'


def copy_to_clipboard(text: str) -> bool:
    """Copy text to system clipboard.

    Uses platform-appropriate clipboard command:
    - macOS: pbcopy
    - Linux: wl-copy (Wayland), xclip, or xsel (X11)
    - Windows: clip

    Args:
        text: Text to copy to clipboard.

    Returns:
        True if copy succeeded, False otherwise.
    """
    os_type = get_os()

    try:
        if os_type == 'darwin':
            subprocess.run(['pbcopy'], input=text.encode(), check=True)
            return True
        elif os_type == 'linux':
            clipboard_cmds = [
                ['wl-copy'],
                ['xclip', '-selection', 'clipboard'],
                ['xsel', '--clipboard', '--input'],
            ]
            for cmd in clipboard_cmds:
                if shutil.which(cmd[0]):
                    subprocess.run(cmd, input=text.encode(), check=True)
                    return True
            return False
        elif os_type == 'windows':
            subprocess.run(['clip'], input=text.encode(), check=True)
            return True
        return False
    except (subprocess.SubprocessError, FileNotFoundError):
        return False
