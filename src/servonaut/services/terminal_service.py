"""Terminal detection and safe external SSH-session launching."""

from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path, PureWindowsPath
from typing import Final, Optional

from servonaut.services.interfaces import TerminalServiceInterface
from servonaut.utils.platform_utils import get_os

logger = logging.getLogger(__name__)

# Kept as a module constant for backwards-compatible callers and tests. New
# runtime-aware callers inject ``data_root`` instead of changing this value.
_WRAPPER_DIR: Final[Path] = Path.home() / ".servonaut" / "logs"
_WRAPPER_TTL_SECONDS: Final[int] = 24 * 60 * 60


def _windows_system_directory() -> Path:
    """Load the shared, fail-closed native Windows system-directory helper."""
    from servonaut.services.process_control import windows_system_directory

    return windows_system_directory()


def quote_powershell_argument(argument: str) -> str:
    """Return one PowerShell single-quoted literal argument."""
    _validate_wrapper_argument(argument)
    return "'" + argument.replace("'", "''") + "'"


def quote_cmd_argument(argument: str) -> str:
    """Return one literal argument for a ``.cmd`` wrapper.

    The wrapper disables delayed expansion, doubles percent for batch-file
    expansion, and applies the Windows CRT backslash/quote algorithm. The
    unconditional double quotes keep cmd metacharacters (including ``^``,
    ``&``, ``|``, redirections, and parentheses) as data. Embedded quotes
    receive a caret so cmd passes them to the target executable as data.
    """
    _validate_wrapper_argument(argument)
    parts: list[str] = ['"']
    backslashes = 0
    for character in argument:
        if character == "\\":
            backslashes += 1
            continue
        if character == '"':
            parts.append("\\" * (backslashes * 2 + 1))
            parts.append('^"')
        else:
            parts.append("\\" * backslashes)
            parts.append("%%" if character == "%" else character)
        backslashes = 0
    # A trailing slash must not escape the closing quote.
    parts.append("\\" * (backslashes * 2))
    parts.append('"')
    return "".join(parts)


def _quote_windows_argv_argument(argument: str) -> str:
    """Quote an argument for the Windows CRT command-line parser only."""
    _validate_wrapper_argument(argument)
    parts: list[str] = ['"']
    backslashes = 0
    for character in argument:
        if character == "\\":
            backslashes += 1
            continue
        if character == '"':
            parts.append("\\" * (backslashes * 2 + 1))
            parts.append('"')
        else:
            parts.append("\\" * backslashes)
            parts.append(character)
        backslashes = 0
    parts.append("\\" * (backslashes * 2))
    parts.append('"')
    return "".join(parts)


def _validate_wrapper_argument(argument: str) -> None:
    """Reject values that no line-oriented shell wrapper can represent."""
    if not isinstance(argument, str):
        raise ValueError("SSH command arguments must be strings.")
    if "\x00" in argument or "\r" in argument or "\n" in argument:
        raise ValueError("SSH command contains an unsupported control character.")


class TerminalService(TerminalServiceInterface):
    """Detect a terminal and launch SSH through a platform-native wrapper."""

    LINUX_TERMINALS: Final[tuple[tuple[str, str], ...]] = (
        ("gnome-terminal", "list"),
        ("konsole", "list"),
        ("alacritty", "list"),
        ("kitty", "list"),
        ("xterm", "list"),
        ("xfce4-terminal", "string"),
        ("mate-terminal", "string"),
        ("tilix", "list"),
    )
    MACOS_TERMINALS: Final[tuple[str, ...]] = ("Terminal.app", "iTerm.app")
    WINDOWS_TERMINALS: Final[tuple[str, ...]] = ("wt.exe", "cmd.exe")

    def __init__(
        self,
        preferred: str = "auto",
        *,
        data_root: Path | None = None,
        command_resolver: Callable[[str], str | None] | None = None,
    ) -> None:
        """Create a launcher with injectable runtime storage and PATH lookup."""
        self._preferred = preferred
        self._detected: Optional[str] = None
        self._detected_path: str | None = None
        self._last_error: str | None = None
        self._command_resolver = command_resolver or shutil.which
        self._wrapper_dir = (data_root / "logs") if data_root is not None else _WRAPPER_DIR

    @property
    def last_error(self) -> str | None:
        """Most recent actionable launch failure, if any."""
        return self._last_error

    def detect_terminal(self) -> str:
        """Detect an available terminal emulator, or return ``"none"``."""
        if self._preferred and self._preferred != "auto":
            resolved = self._resolve_terminal_executable(self._preferred)
            if resolved is not None:
                self._remember_detected_terminal(self._preferred, resolved)
                return self._preferred
            logger.warning("Preferred terminal %r was not found", self._preferred)

        os_name = get_os()
        if os_name == "linux":
            return self._detect_linux_terminal()
        if os_name == "darwin":
            return self._detect_macos_terminal()
        if os_name == "windows":
            return self._detect_windows_terminal()
        logger.warning("Unknown OS %s; trying Linux terminal detection", os_name)
        return self._detect_linux_terminal()

    def _detect_linux_terminal(self) -> str:
        for name, _style in self.LINUX_TERMINALS:
            resolved = self._resolve_terminal_executable(name)
            if resolved is not None:
                self._remember_detected_terminal(name, resolved)
                return name
        return "none"

    def _detect_macos_terminal(self) -> str:
        for name in self.MACOS_TERMINALS:
            if (Path("/Applications") / name).exists():
                self._remember_detected_terminal(name, None)
                return name
        self._remember_detected_terminal("Terminal.app", None)
        return self._detected

    def _detect_windows_terminal(self) -> str:
        for name in self.WINDOWS_TERMINALS:
            resolved = self._resolve_terminal_executable(name)
            if resolved is not None:
                self._remember_detected_terminal(name, resolved)
                return name
        return "none"

    def _remember_detected_terminal(self, name: str, executable: str | None) -> None:
        """Keep the public display name and the verified launch path separately."""
        self._detected = name
        self._detected_path = executable

    def _resolve_terminal_executable(self, name: str) -> str | None:
        """Resolve a terminal once and retain its absolute executable path."""
        resolved = self._command_resolver(name)
        if not resolved:
            return None
        value = str(resolved)
        if get_os() == "windows":
            return value if PureWindowsPath(value).is_absolute() else None
        return value if Path(value).is_absolute() else None

    def _resolve_ssh_command(self, ssh_command: Sequence[str]) -> list[str] | None:
        """Resolve OpenSSH before writing a wrapper, with distinct guidance."""
        if not ssh_command:
            self._last_error = "SSH command is empty."
            return None
        try:
            command = list(ssh_command)
            for argument in command:
                _validate_wrapper_argument(argument)
        except ValueError as exc:
            self._last_error = str(exc)
            return None

        executable = command[0]
        if Path(executable).is_absolute() or "/" in executable or "\\" in executable:
            return command
        resolved = self._command_resolver(executable)
        if resolved:
            command[0] = resolved
            return command

        if get_os() == "windows":
            self._last_error = (
                "OpenSSH Client (ssh.exe) is not installed. Install the Windows "
                "Optional Feature 'OpenSSH Client' and try again."
            )
        else:
            self._last_error = (
                "OpenSSH client (ssh) was not found. Install OpenSSH and ensure it is on PATH."
            )
        return None

    def _create_wrapper_script(self, ssh_command: Sequence[str]) -> str:
        """Create the platform wrapper selected by the current operating system."""
        if get_os() == "windows":
            if (self._detected or self.detect_terminal()) == "wt.exe":
                return self._create_powershell_wrapper(ssh_command)
            return self._create_cmd_wrapper(ssh_command)
        return self._create_posix_wrapper(ssh_command)

    def _create_posix_wrapper(self, ssh_command: Sequence[str]) -> str:
        """Create the existing executable bash wrapper for POSIX terminals."""
        self._prepare_wrapper_directory()
        command_line = shlex.join(ssh_command)
        display_line = shlex.quote(command_line)
        content = f"""#!/bin/bash
printf '%s\\n' 'Connecting:'
printf '%s\\n' {display_line}
printf '%s\\n' '---'
{command_line}
exit_code=$?
if [ $exit_code -ne 0 ]; then
    printf '\\n--- SSH exited with code %s ---\\n' "$exit_code"
    printf '%s\\n' 'Press Enter to close this window...'
    read -r
fi
"""
        return self._write_wrapper(content, ".sh", encoding="utf-8", mode=0o700)

    def _create_powershell_wrapper(self, ssh_command: Sequence[str]) -> str:
        """Create a Windows Terminal PowerShell wrapper without invoking Bash."""
        self._prepare_wrapper_directory()
        executable = quote_powershell_argument(ssh_command[0])
        native_arguments = " ".join(
            _quote_windows_argv_argument(arg) for arg in ssh_command[1:]
        )
        content = "\n".join(
            (
                "$ErrorActionPreference = 'Continue'",
                "Write-Host 'Connecting with OpenSSH...'",
                "$startInfo = New-Object System.Diagnostics.ProcessStartInfo",
                f"$startInfo.FileName = {executable}",
                "$startInfo.UseShellExecute = $false",
                f"$startInfo.Arguments = {quote_powershell_argument(native_arguments)}",
                "$process = [System.Diagnostics.Process]::Start($startInfo)",
                "$process.WaitForExit()",
                "$exitCode = $process.ExitCode",
                "if ($exitCode -ne 0) {",
                "    Write-Host \"`n--- SSH exited with code $exitCode ---\"",
                "    Read-Host 'Press Enter to close this window'",
                "}",
                "exit $exitCode",
                "",
            )
        )
        return self._write_wrapper(content, ".ps1", encoding="utf-8-sig", mode=None)

    def _create_cmd_wrapper(self, ssh_command: Sequence[str]) -> str:
        """Create a cmd fallback wrapper using cmd-specific literal quoting."""
        self._prepare_wrapper_directory()
        invocation = " ".join(quote_cmd_argument(arg) for arg in ssh_command)
        content = "\r\n".join(
            (
                "@echo off",
                "chcp 65001 >nul",
                "setlocal DisableDelayedExpansion",
                "echo Connecting with OpenSSH...",
                invocation,
                "set \"servonaut_exit_code=%ERRORLEVEL%\"",
                "if not \"%servonaut_exit_code%\"==\"0\" (",
                "  echo.",
                "  echo --- SSH exited with code %servonaut_exit_code% ---",
                "  pause >nul",
                ")",
                "exit /b %servonaut_exit_code%",
                "",
            )
        )
        # cmd parses batch source using its active OEM code page. Start with
        # ASCII-only directives, switch that code page to UTF-8, then place
        # the Unicode command line on a later line. A UTF-16 batch file is not
        # a supported cmd input format, and a UTF-8 BOM would become input.
        return self._write_wrapper(content, ".cmd", encoding="utf-8", mode=None)

    def _prepare_wrapper_directory(self) -> None:
        self._wrapper_dir.mkdir(parents=True, exist_ok=True)
        self._sweep_stale_wrappers(self._wrapper_dir)

    def _write_wrapper(
        self, content: str, suffix: str, *, encoding: str, mode: int | None
    ) -> str:
        descriptor, wrapper_path = tempfile.mkstemp(
            prefix="servonaut_", suffix=suffix, dir=str(self._wrapper_dir)
        )
        with os.fdopen(descriptor, "w", encoding=encoding, newline="") as wrapper_file:
            wrapper_file.write(content)
        if mode is not None:
            os.chmod(wrapper_path, mode)
        return wrapper_path

    @staticmethod
    def _sweep_stale_wrappers(wrapper_dir: Path | None = None) -> None:
        """Best-effort deletion of stale, owned POSIX and Windows wrappers."""
        directory = wrapper_dir if wrapper_dir is not None else _WRAPPER_DIR
        if not directory.exists():
            return
        cutoff = time.time() - _WRAPPER_TTL_SECONDS
        for suffix in (".sh", ".ps1", ".cmd"):
            for candidate in directory.glob(f"servonaut_*{suffix}"):
                try:
                    if candidate.stat().st_mtime < cutoff:
                        candidate.unlink()
                except OSError as exc:
                    logger.debug("Could not sweep terminal wrapper %s: %s", candidate, exc)

    def launch_ssh_in_terminal(self, ssh_command: list[str]) -> bool:
        """Open a native external terminal for the supplied SSH argv."""
        self._last_error = None
        resolved_ssh = self._resolve_ssh_command(ssh_command)
        if resolved_ssh is None:
            return False

        terminal = self._detected or self.detect_terminal()
        if terminal == "none":
            self._last_error = (
                "No terminal emulator is available. Install Windows Terminal or a supported "
                "terminal emulator, then try again."
            )
            return False

        try:
            os_name = get_os()
            if os_name == "darwin":
                return self._launch_macos_terminal(terminal, resolved_ssh)
            if os_name == "linux":
                executable = self._detected_path or self._resolve_terminal_executable(terminal)
                if executable is None:
                    self._last_error = f"Could not resolve terminal executable: {terminal}."
                    return False
                return self._launch_linux_terminal(terminal, executable, resolved_ssh)
            if os_name == "windows":
                executable = self._detected_path or self._resolve_terminal_executable(terminal)
                if executable is None:
                    self._last_error = f"Could not resolve terminal executable: {terminal}."
                    return False
                return self._launch_windows_terminal(terminal, executable, resolved_ssh)
            self._last_error = f"Unsupported operating system: {os_name}."
            return False
        except (OSError, ValueError) as exc:
            logger.error("Could not launch SSH terminal %s: %s", terminal, exc)
            self._detected = None
            self._detected_path = None
            self._last_error = f"Could not start terminal {terminal}: {exc}"
            return False

    def _launch_macos_terminal(self, terminal: str, ssh_command: Sequence[str]) -> bool:
        wrapper = self._create_posix_wrapper(ssh_command)
        shell_command = f"bash {shlex.quote(wrapper)}"
        escaped_shell_command = shell_command.replace("\\", "\\\\").replace('"', '\\"')
        if "iTerm" in terminal:
            script = (
                'tell application "iTerm"\n'
                f'  create window with default profile command "{escaped_shell_command}"\n'
                "end tell"
            )
        else:
            script = (
                'tell application "Terminal"\n'
                f'  do script "{escaped_shell_command}"\n'
                "  activate\n"
                "end tell"
            )
        subprocess.Popen(
            ["osascript", "-e", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return True

    def _launch_linux_terminal(
        self, terminal: str, executable: str, ssh_command: Sequence[str]
    ) -> bool:
        wrapper = self._create_posix_wrapper(ssh_command)
        command = self._build_linux_command(terminal, executable, wrapper)
        if command is None:
            self._last_error = f"Terminal {terminal} has no supported launch command."
            return False
        subprocess.Popen(
            command,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True

    def _build_linux_command(
        self, terminal: str, executable: str, wrapper_script: str
    ) -> list[str] | None:
        for name, _style in self.LINUX_TERMINALS:
            if name != terminal:
                continue
            if name == "gnome-terminal":
                return [executable, "--", "bash", wrapper_script]
            return [executable, "-e", f"bash {shlex.quote(wrapper_script)}"]
        return [executable, "-e", f"bash {shlex.quote(wrapper_script)}"]

    def _launch_windows_terminal(
        self, terminal: str, executable: str, ssh_command: Sequence[str]
    ) -> bool:
        system_directory = _windows_system_directory()
        if terminal == "wt.exe":
            wrapper = self._create_powershell_wrapper(ssh_command)
            powershell = system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            command = [
                executable,
                "new-window",
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                wrapper,
            ]
            flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            subprocess.Popen(
                command,
                shell=False,
                creationflags=flags,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            wrapper = self._create_cmd_wrapper(ssh_command)
            command_interpreter = system_directory / "cmd.exe"
            flags = (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
            )
            # ``/c`` asks cmd to parse its final argument as command text, then
            # exits when the wrapper succeeds. The wrapper itself pauses only
            # after a failed SSH command. Passing the wrapper's absolute path
            # would reintroduce cmd injection through a valid but hostile
            # data-root directory name, even with Python ``shell=False``.
            # mkstemp gives us an ASCII basename; start cmd in the wrapper
            # directory and pass only that basename through the cmd parser.
            wrapper_path = Path(wrapper)
            command = [str(command_interpreter), "/d", "/v:off", "/c", wrapper_path.name]
            # A direct cmd fallback owns a newly created console. Let its
            # standard handles inherit that console rather than redirecting
            # wrapper output and input to NUL.
            subprocess.Popen(
                command,
                shell=False,
                creationflags=flags,
                cwd=str(wrapper_path.parent),
            )
        return True
