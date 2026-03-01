"""Terminal service for detecting and launching terminal emulators."""

from __future__ import annotations
import logging
import os
import subprocess
import shutil
import shlex
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from servonaut.services.interfaces import TerminalServiceInterface
from servonaut.utils.platform_utils import get_os

logger = logging.getLogger(__name__)

# Directory for wrapper scripts that keep the terminal open on failure
_WRAPPER_DIR = Path.home() / '.servonaut' / 'logs'


class TerminalService(TerminalServiceInterface):
    """Terminal service for cross-platform terminal detection and SSH launching.

    Supports Linux, macOS, and Windows terminal emulators.
    """

    # Linux terminals: (executable_name, launch_style)
    # "list" style: terminal passes remaining args as command argv
    # "string" style: terminal expects a single string argument for -e
    LINUX_TERMINALS: List[Tuple[str, str]] = [
        ("gnome-terminal", "list"),
        ("konsole", "list"),
        ("alacritty", "list"),
        ("kitty", "list"),
        ("xterm", "list"),
        ("xfce4-terminal", "string"),
        ("mate-terminal", "string"),
        ("tilix", "list"),
    ]

    MACOS_TERMINALS: List[str] = [
        "Terminal.app",
        "iTerm.app",
    ]

    WINDOWS_TERMINALS: List[str] = [
        "wt.exe",
        "cmd.exe",
    ]

    def __init__(self, preferred: str = "auto") -> None:
        """Initialize terminal service.

        Args:
            preferred: Preferred terminal name, or "auto" for auto-detection.
        """
        self._preferred = preferred
        self._detected: Optional[str] = None

    def detect_terminal(self) -> str:
        """Detect available terminal emulator.

        Checks for preferred terminal first, then searches by platform.

        Returns:
            Terminal command name (e.g., 'gnome-terminal', 'Terminal.app', 'wt.exe'),
            or 'none' if no terminal found.
        """
        if self._preferred and self._preferred != "auto":
            if shutil.which(self._preferred):
                self._detected = self._preferred
                logger.info("Using preferred terminal: %s", self._preferred)
                return self._preferred
            else:
                logger.warning("Preferred terminal '%s' not found, auto-detecting", self._preferred)

        os_name = get_os()

        if os_name == 'linux':
            return self._detect_linux_terminal()
        elif os_name == 'darwin':
            return self._detect_macos_terminal()
        elif os_name == 'windows':
            return self._detect_windows_terminal()

        logger.warning("Unknown OS: %s, trying Linux terminals", os_name)
        return self._detect_linux_terminal()

    def _detect_linux_terminal(self) -> str:
        """Detect available Linux terminal."""
        for name, _ in self.LINUX_TERMINALS:
            if shutil.which(name):
                self._detected = name
                logger.info("Detected Linux terminal: %s", name)
                return name
        logger.error("No terminal emulator detected on Linux")
        return 'none'

    def _detect_macos_terminal(self) -> str:
        """Detect available macOS terminal."""
        for name in self.MACOS_TERMINALS:
            app_path = f"/Applications/{name}"
            if os.path.exists(app_path):
                self._detected = name
                logger.info("Detected macOS terminal: %s", name)
                return name
        # Terminal.app should always exist on macOS
        self._detected = "Terminal.app"
        logger.info("Falling back to Terminal.app")
        return "Terminal.app"

    def _detect_windows_terminal(self) -> str:
        """Detect available Windows terminal."""
        for name in self.WINDOWS_TERMINALS:
            if shutil.which(name):
                self._detected = name
                logger.info("Detected Windows terminal: %s", name)
                return name
        logger.error("No terminal emulator detected on Windows")
        return 'none'

    def _create_wrapper_script(self, ssh_command: List[str]) -> str:
        """Create a bash wrapper script that runs SSH and keeps terminal open on failure.

        The wrapper:
        - Prints the SSH command being run
        - Executes the SSH command
        - On non-zero exit, shows the error and waits for Enter before closing
        - On normal exit (user typed 'exit'), closes cleanly

        Args:
            ssh_command: SSH command as list of arguments.

        Returns:
            Path to the wrapper script.
        """
        _WRAPPER_DIR.mkdir(exist_ok=True)

        ssh_cmd_str = shlex.join(ssh_command)
        script_content = f"""#!/bin/bash
echo "Connecting: {ssh_cmd_str}"
echo "---"
{ssh_cmd_str}
exit_code=$?
if [ $exit_code -ne 0 ]; then
    echo ""
    echo "--- SSH exited with code $exit_code ---"
    echo "Press Enter to close this window..."
    read -r
fi
"""
        # Use a fixed name per host to avoid accumulating temp files
        fd, script_path = tempfile.mkstemp(
            prefix='servonaut_', suffix='.sh', dir=str(_WRAPPER_DIR)
        )
        with os.fdopen(fd, 'w') as f:
            f.write(script_content)
        os.chmod(script_path, 0o700)
        logger.debug("Created wrapper script: %s", script_path)
        return script_path

    def launch_ssh_in_terminal(self, ssh_command: List[str]) -> bool:
        """Launch SSH session in a new terminal window.

        Wraps the SSH command in a script that keeps the terminal open
        on failure so the user can see error messages.

        Args:
            ssh_command: SSH command list from SSHServiceInterface.

        Returns:
            True if terminal launched successfully.
        """
        terminal = self._detected or self.detect_terminal()

        if terminal == 'none':
            logger.error("No terminal emulator available for launching SSH")
            return False

        os_name = get_os()
        logger.info("Launching SSH in %s (OS: %s)", terminal, os_name)
        logger.info("SSH command: %s", shlex.join(ssh_command))

        try:
            if os_name == 'darwin':
                return self._launch_macos_terminal(terminal, ssh_command)
            elif os_name == 'linux':
                return self._launch_linux_terminal(terminal, ssh_command)
            elif os_name == 'windows':
                return self._launch_windows_terminal(terminal, ssh_command)
            else:
                logger.error("Unsupported OS: %s", os_name)
                return False

        except FileNotFoundError as e:
            logger.error("Terminal executable not found: %s — %s", terminal, e)
            self._detected = None
            return False
        except PermissionError as e:
            logger.error("Permission denied launching terminal: %s — %s", terminal, e)
            return False
        except Exception as e:
            logger.error("Failed to launch terminal %s: %s", terminal, e)
            return False

    def _launch_macos_terminal(self, terminal: str, ssh_command: List[str]) -> bool:
        """Launch SSH in macOS terminal using osascript.

        Uses a wrapper script so the terminal stays open on SSH failure.

        Args:
            terminal: Terminal app name.
            ssh_command: SSH command as list.

        Returns:
            True if launched successfully.
        """
        wrapper = self._create_wrapper_script(ssh_command)
        escaped_wrapper = wrapper.replace('\\', '\\\\').replace('"', '\\"')

        if 'iTerm' in terminal:
            script = (
                f'tell application "iTerm"\n'
                f'  create window with default profile command "bash {escaped_wrapper}"\n'
                f'end tell'
            )
        else:
            script = (
                f'tell application "Terminal"\n'
                f'  do script "bash {escaped_wrapper}"\n'
                f'  activate\n'
                f'end tell'
            )

        subprocess.Popen(
            ['osascript', '-e', script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.info("Launched SSH in macOS %s", terminal)
        return True

    def _launch_linux_terminal(self, terminal: str, ssh_command: List[str]) -> bool:
        """Launch SSH in Linux terminal.

        Uses a wrapper script that keeps the terminal open on SSH failure
        so the user can see error messages.

        Args:
            terminal: Terminal command name.
            ssh_command: SSH command as list.

        Returns:
            True if launched successfully.
        """
        wrapper = self._create_wrapper_script(ssh_command)
        cmd = self._build_linux_command(terminal, wrapper)
        if not cmd:
            return False

        logger.debug("Terminal launch command: %s", cmd)
        subprocess.Popen(
            cmd,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.info("Launched SSH in Linux %s", terminal)
        return True

    def _build_linux_command(self, terminal: str, wrapper_script: str) -> Optional[List[str]]:
        """Build command to launch a terminal running a wrapper script.

        Args:
            terminal: Terminal executable name.
            wrapper_script: Path to the bash wrapper script.

        Returns:
            Command list for subprocess, or None if terminal is unknown.
        """
        for name, _ in self.LINUX_TERMINALS:
            if name == terminal:
                if name == 'gnome-terminal':
                    return ['gnome-terminal', '--', 'bash', wrapper_script]
                else:
                    # -e flag: all terminals accept a single command string
                    return [name, '-e', f'bash {shlex.quote(wrapper_script)}']

        # User-configured terminal — try -e with wrapper
        logger.warning("Terminal '%s' not in known list, trying -e flag", terminal)
        return [terminal, '-e', f'bash {shlex.quote(wrapper_script)}']

    def _launch_windows_terminal(self, terminal: str, ssh_command: List[str]) -> bool:
        """Launch SSH in Windows terminal.

        Args:
            terminal: Terminal executable name.
            ssh_command: SSH command as list.

        Returns:
            True if launched successfully.
        """
        wrapper = self._create_wrapper_script(ssh_command)

        if terminal == 'wt.exe':
            cmd = ['wt.exe', 'bash', wrapper]
        elif terminal == 'cmd.exe':
            cmd = ['cmd.exe', '/c', 'start', 'cmd.exe', '/k', f'bash {wrapper}']
        else:
            cmd = [terminal, 'bash', wrapper]

        logger.debug("Windows terminal launch command: %s", cmd)
        subprocess.Popen(
            cmd,
            creationflags=getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.info("Launched SSH in Windows %s", terminal)
        return True
