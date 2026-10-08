"""Platform detection and OS-specific utilities."""

from __future__ import annotations
import platform
import re
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


# The longest platform name describe_platform() returns.
_PLATFORM_NAME_MAX = 40
_PLATFORM_NAME_UNSAFE = re.compile(r"[^A-Za-z0-9 ._()/+-]")
# The first Windows 11 build; Python before 3.12 reports Windows 11 as release "10".
_WINDOWS_11_BUILD = 22000


def describe_platform() -> str:
    """A coarse name for this operating system, such as 'macOS 15' or 'Ubuntu 24.04'.

    Major versions only, and never the host name, user name or kernel build:
    the sign-in review page shows it so a person can tell which of their
    machines is asking to sign in.
    """
    os_name = get_os()
    if os_name == 'darwin':
        major = platform.mac_ver()[0].split('.')[0]
        name = f"macOS {major}" if major else "macOS"
    elif os_name == 'windows':
        name = _windows_name()
    elif os_name == 'linux':
        name = _linux_name()
    else:
        name = platform.system()
    name = _PLATFORM_NAME_UNSAFE.sub('', name).strip()[:_PLATFORM_NAME_MAX].strip()
    return name or "unknown"


def _windows_name() -> str:
    release = platform.release()
    try:
        build = int(platform.version().split('.')[2])
    except (IndexError, ValueError):
        build = 0
    if release == '10' and build >= _WINDOWS_11_BUILD:
        release = '11'
    return f"Windows {release}" if release else "Windows"


def _linux_name() -> str:
    try:
        release = platform.freedesktop_os_release()
    except OSError:
        return "Linux"
    name = release.get('NAME') or "Linux"
    return f"{name} {release.get('VERSION_ID', '')}".strip()


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
