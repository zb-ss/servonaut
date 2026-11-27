"""Terminal detection and safe external SSH-session launching."""

from __future__ import annotations

import logging
import os
import plistlib
import shlex
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path, PureWindowsPath
from typing import Final, NamedTuple, Optional
from xml.parsers.expat import ExpatError

from servonaut.services.interfaces import TerminalServiceInterface
from servonaut.utils.markup import inert_text
from servonaut.utils.platform_utils import get_os
from servonaut.utils.terminal_output import first_control_index, has_controls

logger = logging.getLogger(__name__)

# Kept as a module constant for backwards-compatible callers and tests. New
# runtime-aware callers inject ``data_root`` instead of changing this value.
_WRAPPER_DIR: Final[Path] = Path.home() / ".servonaut" / "logs"
_WRAPPER_TTL_SECONDS: Final[int] = 24 * 60 * 60
_ITERM_BUNDLE_ID: Final[str] = "com.googlecode.iterm2"
_TERMINAL_BUNDLE_ID: Final[str] = "com.apple.Terminal"
_GHOSTTY_BUNDLE_ID: Final[str] = "com.mitchellh.ghostty"
_WEZTERM_BUNDLE_ID: Final[str] = "com.github.wez.wezterm"
_ALACRITTY_BUNDLE_ID: Final[str] = "org.alacritty"
_KITTY_BUNDLE_ID: Final[str] = "net.kovidgoyal.kitty"
_RIO_BUNDLE_ID: Final[str] = "com.raphaelamorim.rio"
_MACOS_CLI_TERMINAL_STYLES: Final[dict[str, str]] = {
    "alacritty": "list",
    "kitty": "list",
    "xterm": "list",
    "rio": "list",
    "wezterm": "start_separator",
    "wezterm-gui": "start_separator",
}
_MACOS_CLI_BUNDLE_STYLES: Final[dict[str, str]] = {
    _ALACRITTY_BUNDLE_ID: "list",
    _KITTY_BUNDLE_ID: "list",
    _RIO_BUNDLE_ID: "list",
    _WEZTERM_BUNDLE_ID: "start_separator",
}
# PowerShell's tokenizer ends a single-quoted string at the ASCII apostrophe
# and at the typographic single quotes U+2018..U+201B alike.
_POWERSHELL_SINGLE_QUOTES: Final[frozenset[str]] = frozenset("'\u2018\u2019\u201a\u201b")


class _MacOSBundleInfo(NamedTuple):
    bundle: Path
    bundle_id: str | None
    executable_name: str | None
    plist_readable: bool


def _macos_app_search_dirs() -> tuple[Path, ...]:
    """Return standard macOS directories searched for ``.app`` bundles."""
    return (
        Path("/Applications"),
        Path("/System/Applications/Utilities"),
        Path("/System/Applications"),
        Path.home() / "Applications",
    )


def _is_macos_bundle_dir(path: Path) -> bool:
    """Return whether *path* is an existing macOS ``.app`` bundle directory."""
    # os.path probes return False on OSError; Path.is_dir()/is_file() raise
    # PermissionError on Python < 3.14 for an untraversable parent directory.
    if path.suffix.lower() != ".app" or not os.path.isdir(path):
        return False
    contents = path / "Contents"
    return os.path.isfile(contents / "Info.plist") or os.path.isdir(contents / "MacOS")


def _is_plain_file_name(value: object) -> bool:
    """Return whether *value* is a bare file name that cannot leave its directory."""
    return isinstance(value, str) and os.path.basename(value) == value and value not in ("", ".", "..")


def _windows_system_directory() -> Path:
    """Load the shared, fail-closed native Windows system-directory helper."""
    from servonaut.services.process_control import windows_system_directory

    return windows_system_directory()


def _terminal_identity(name: str) -> str:
    """Normalise a terminal name or path for case-insensitive comparison."""
    return PureWindowsPath(name).name.casefold().removesuffix(".exe")


def _escape_applescript_text(value: str) -> str:
    """Escape a value for a double-quoted AppleScript literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")


def quote_powershell_argument(argument: str) -> str:
    """Return one PowerShell single-quoted literal argument."""
    _validate_wrapper_argument(argument)
    # Doubling any single-quote character makes PowerShell read it literally.
    escaped = "".join(
        character * 2 if character in _POWERSHELL_SINGLE_QUOTES else character
        for character in argument
    )
    return f"'{escaped}'"


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
    if has_controls(argument):
        raise ValueError("SSH command contains an unsupported control character.")


_EXCERPT_RADIUS = 30


def _refused_field(command: Sequence[str], index: int) -> str:
    argument = command[index]
    previous = command[index - 1] if index > 0 else ""
    if argument.lower().startswith(("proxycommand=", "-oproxycommand=")) or (
        previous == "-o" and argument.lower().startswith("proxycommand")
    ):
        return "proxy command"
    if previous == "-J" or argument.startswith("-J"):
        return "jump host"
    if "@" in argument:
        return "user or host name"
    if previous == "-i":
        return "key file path"
    return f"argument {index}"


def _excerpt_around_control(argument: str) -> str:
    """The part of *argument* around its first control character, written out.

    Tabs and newlines are written out too, so the culprit can be seen.
    """
    at = max(first_control_index(argument), 0)
    start = max(0, at - _EXCERPT_RADIUS)
    end = at + _EXCERPT_RADIUS
    shown = inert_text(argument[start:end]).replace("\t", "\\t").replace("\n", "\\n")
    return ("..." if start else "") + shown + ("..." if end < len(argument) else "")


def _describe_refused_argument(command: Sequence[str], index: int) -> str:
    """Say which part of the SSH command holds a control character.

    The value is shown with the characters written out, never as is: it may
    come from a server list that someone else controls.
    """
    return (
        f"Not connecting: the {_refused_field(command, index)} contains a control "
        f"character ({_excerpt_around_control(command[index])}). "
        "Check the server's details."
    )


class TerminalService(TerminalServiceInterface):
    """Detect a terminal and launch SSH through a platform-native wrapper."""

    # How each terminal receives the wrapper command: "separator" takes the
    # argv after ``--``, "list" takes it after ``-e`` as separate arguments,
    # and "string" takes one shell-quoted command string after ``-e``.
    LINUX_TERMINALS: Final[tuple[tuple[str, str], ...]] = (
        ("gnome-terminal", "separator"),
        ("konsole", "list"),
        ("alacritty", "list"),
        ("kitty", "list"),
        ("xterm", "list"),
        ("xfce4-terminal", "string"),
        ("mate-terminal", "string"),
        ("tilix", "string"),
    )
    DEFAULT_LINUX_TERMINAL_STYLE: Final[str] = "string"
    MACOS_TERMINALS: Final[tuple[str, ...]] = ("iTerm.app", "Terminal.app")
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
        os_name = get_os()
        if self._preferred and self._preferred != "auto":
            resolved = (
                self._resolve_macos_terminal(self._preferred)
                if os_name == "darwin"
                else self._resolve_terminal_executable(self._preferred)
            )
            if resolved is not None:
                self._remember_detected_terminal(self._preferred, resolved)
                return self._preferred
            logger.warning("Preferred terminal %r was not found", self._preferred)

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
            bundle = self._find_macos_app_bundle(name)
            if bundle is not None:
                self._remember_detected_terminal(name, str(bundle))
                return name
        self._remember_detected_terminal("Terminal.app", None)
        return self._detected

    @staticmethod
    def _find_macos_app_bundle(bundle_name: str) -> Path | None:
        for directory in _macos_app_search_dirs():
            candidate = directory / bundle_name
            if _is_macos_bundle_dir(candidate):
                return candidate
        return None

    def _resolve_macos_terminal(self, preferred: str) -> str | None:
        expanded = os.path.expanduser(preferred)
        candidate = Path(expanded)
        if candidate.is_absolute() and _is_macos_bundle_dir(candidate):
            return str(candidate)
        if "/" not in expanded and "\\" not in expanded and expanded.lower().endswith(".app"):
            bundle = self._find_macos_app_bundle(expanded)
            return str(bundle) if bundle is not None else None
        return self._resolve_terminal_executable(expanded)

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
        expanded = os.path.expanduser(name)
        resolved = self._command_resolver(expanded)
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
            for index, argument in enumerate(command):
                try:
                    _validate_wrapper_argument(argument)
                except ValueError:
                    if isinstance(argument, str):
                        self._last_error = _describe_refused_argument(command, index)
                        return None
                    raise
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

    def _create_posix_wrapper(self, ssh_command: Sequence[str]) -> str:
        """Create the existing executable bash wrapper for POSIX terminals."""
        self._prepare_wrapper_directory()
        command_line = shlex.join(ssh_command)
        display_line = shlex.quote(inert_text(command_line))
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

    def _create_powershell_wrapper(
        self, ssh_command: Sequence[str], *, pause_on_failure: bool = True
    ) -> str:
        """Create a Windows Terminal PowerShell wrapper without invoking Bash."""
        self._prepare_wrapper_directory()
        executable = quote_powershell_argument(ssh_command[0])
        native_arguments = " ".join(
            _quote_windows_argv_argument(arg) for arg in ssh_command[1:]
        )
        lines = [
            "$ErrorActionPreference = 'Stop'",
            "$exitCode = 1",
            "try {",
            "    Write-Host 'Connecting with OpenSSH...'",
            "    $startInfo = New-Object System.Diagnostics.ProcessStartInfo",
            f"    $startInfo.FileName = {executable}",
            "    $startInfo.UseShellExecute = $false",
            f"    $startInfo.Arguments = {quote_powershell_argument(native_arguments)}",
            "    $process = [System.Diagnostics.Process]::Start($startInfo)",
            "    if ($null -eq $process) { throw 'OpenSSH process could not be started.' }",
            "    $process.WaitForExit()",
            "    $exitCode = $process.ExitCode",
            "} catch {",
            "    Write-Host \"`n--- Could not start OpenSSH: $($_.Exception.Message) ---\"",
            "}",
        ]
        if pause_on_failure:
            lines.extend(
                (
                    "if ($exitCode -ne 0) {",
                    "    Write-Host \"`n--- SSH exited with code $exitCode ---\"",
                    "    Read-Host 'Press Enter to close this window'",
                    "}",
                )
            )
        lines.extend(("exit $exitCode", ""))
        content = "\n".join(lines)
        return self._write_wrapper(content, ".ps1", encoding="utf-8-sig", mode=None)

    def _create_cmd_wrapper(
        self, ssh_command: Sequence[str], *, powershell_executable: Path
    ) -> str:
        """Create a cmd trampoline with no dynamic arguments in batch source."""
        powershell_wrapper = Path(
            self._create_powershell_wrapper(ssh_command, pause_on_failure=False)
        )
        content = "\r\n".join(
            (
                "@echo off",
                "chcp 65001 >nul",
                "setlocal DisableDelayedExpansion",
                "echo Connecting with OpenSSH...",
                f'"{powershell_executable}" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "{powershell_wrapper.name}"',
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
        # The batch source holds only trusted paths and an ASCII mkstemp
        # basename. Dynamic SSH arguments live exclusively in the adjacent
        # ProcessStartInfo wrapper, avoiding cmd's incompatible quote parser.
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

    @staticmethod
    def _bundle_paths_from_candidate(candidate: Path) -> tuple[Path, Path] | None:
        if candidate.suffix.lower() == ".app" and os.path.isdir(candidate):
            return candidate, candidate / "Contents"
        macos = candidate.parent
        contents = macos.parent
        bundle = contents.parent
        if macos.name == "MacOS" and contents.name == "Contents" and bundle.suffix.lower() == ".app":
            return bundle, contents
        return None

    def _configured_macos_bundle(self) -> _MacOSBundleInfo | None:
        """Read the identity of the bundle for the configured macOS terminal."""
        if self._detected_path is None:
            return None
        candidate = Path(self._detected_path)
        located = self._bundle_paths_from_candidate(candidate)
        if located is None:
            try:
                resolved = candidate.resolve()
            except (OSError, RuntimeError):
                # RuntimeError: symlink loop on Python < 3.13.
                return None
            if resolved != candidate:
                located = self._bundle_paths_from_candidate(resolved)
        if located is None:
            return None
        bundle, contents = located
        try:
            with (contents / "Info.plist").open("rb") as file:
                info = plistlib.load(file)
        except (OSError, ValueError, ExpatError, AttributeError, IndexError, RecursionError):
            # plistlib can raise AttributeError for an invalid XML date,
            # IndexError for a <key> without a value and RecursionError for
            # deeply nested input.
            return _MacOSBundleInfo(
                bundle=bundle,
                bundle_id=None,
                executable_name=None,
                plist_readable=False,
            )
        if not isinstance(info, dict):
            return _MacOSBundleInfo(
                bundle=bundle,
                bundle_id=None,
                executable_name=None,
                plist_readable=False,
            )
        raw_bundle_id = info.get("CFBundleIdentifier")
        raw_executable = info.get("CFBundleExecutable")
        return _MacOSBundleInfo(
            bundle=bundle,
            bundle_id=raw_bundle_id if isinstance(raw_bundle_id, str) else None,
            executable_name=raw_executable if _is_plain_file_name(raw_executable) else None,
            plist_readable=True,
        )

    def _resolve_macos_bundle_cli(self, bundle_info: _MacOSBundleInfo) -> tuple[str, str] | None:
        """Resolve a CLI-capable executable and launch style for a third-party ``.app`` bundle."""
        detected_path = Path(self._detected_path) if self._detected_path is not None else None
        detected_is_file = detected_path is not None and os.path.isfile(detected_path)

        if bundle_info.bundle_id == _WEZTERM_BUNDLE_ID:
            if detected_is_file and self._detected_path is not None:
                return self._detected_path, "start_separator"
            macos_dir = bundle_info.bundle / "Contents" / "MacOS"
            for candidate_name in ("wezterm", bundle_info.executable_name or "wezterm-gui"):
                candidate = macos_dir / candidate_name
                if os.path.isfile(candidate):
                    return str(candidate), "start_separator"
            return None

        if detected_is_file and self._detected_path is not None:
            identity = _terminal_identity(self._detected_path)
            if identity in _MACOS_CLI_TERMINAL_STYLES:
                return self._detected_path, _MACOS_CLI_TERMINAL_STYLES[identity]

        if bundle_info.executable_name:
            exe_identity = _terminal_identity(bundle_info.executable_name)
            style = _MACOS_CLI_TERMINAL_STYLES.get(exe_identity) or _MACOS_CLI_BUNDLE_STYLES.get(
                bundle_info.bundle_id or ""
            )
            if style is not None:
                exe_path = bundle_info.bundle / "Contents" / "MacOS" / bundle_info.executable_name
                if os.path.isfile(exe_path):
                    return str(exe_path), style

        return None

    def _launch_macos_applescript(
        self, app: str, *, use_iterm: bool, ssh_command: Sequence[str]
    ) -> bool:
        wrapper = self._create_posix_wrapper(ssh_command)
        shell_command = f"bash {shlex.quote(wrapper)}"
        escaped_shell_command = _escape_applescript_text(shell_command)
        if use_iterm:
            script = (
                f'tell application "{app}"\n'
                f'  create window with default profile command "{escaped_shell_command}"\n'
                "end tell"
            )
        else:
            script = (
                f'tell application "{app}"\n'
                f'  do script "{escaped_shell_command}"\n'
                "  activate\n"
                "end tell"
            )
        subprocess.Popen(
            ["osascript", "-e", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return True

    def _launch_macos_ghostty(self, target: str, ssh_command: Sequence[str]) -> bool:
        wrapper = self._create_posix_wrapper(ssh_command)
        subprocess.Popen(
            ["open", "-na", target, "--args", "-e", "bash", wrapper],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True

    def _launch_macos_terminal(self, terminal: str, ssh_command: Sequence[str]) -> bool:
        configured_bundle = self._configured_macos_bundle()
        if configured_bundle is not None:
            bundle_id = configured_bundle.bundle_id
            if bundle_id in (_ITERM_BUNDLE_ID, _TERMINAL_BUNDLE_ID):
                app = _escape_applescript_text(configured_bundle.bundle.as_posix())
                return self._launch_macos_applescript(
                    app, use_iterm=bundle_id == _ITERM_BUNDLE_ID, ssh_command=ssh_command
                )

            is_ghostty = (
                bundle_id == _GHOSTTY_BUNDLE_ID
                or (
                    configured_bundle.executable_name is not None
                    and _terminal_identity(configured_bundle.executable_name) == "ghostty"
                )
                or (
                    self._detected_path is not None
                    and _terminal_identity(self._detected_path) == "ghostty"
                )
            )
            if is_ghostty:
                return self._launch_macos_ghostty(
                    configured_bundle.bundle.as_posix(), ssh_command
                )

            cli_launch = self._resolve_macos_bundle_cli(configured_bundle)
            if cli_launch is not None:
                executable, style = cli_launch
                wrapper = self._create_posix_wrapper(ssh_command)
                command = self._build_command_for_style(style, executable, wrapper)
                subprocess.Popen(
                    command,
                    start_new_session=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return True

            bundle_name_lower = configured_bundle.bundle.name.casefold()
            if (not configured_bundle.plist_readable or bundle_id is None) and (
                "iterm" in bundle_name_lower or "terminal" in bundle_name_lower
            ):
                use_iterm = "iterm" in bundle_name_lower
                return self._launch_macos_applescript(
                    "iTerm" if use_iterm else "Terminal",
                    use_iterm=use_iterm,
                    ssh_command=ssh_command,
                )

            self._last_error = (
                f"Unsupported macOS terminal bundle {configured_bundle.bundle.name}. "
                "Use Terminal.app, iTerm.app, Ghostty.app, WezTerm.app, Alacritty.app, "
                "kitty.app, Rio.app, or a CLI terminal executable."
            )
            return False

        if self._detected_path is not None:
            identity = _terminal_identity(self._detected_path)
            if identity == "ghostty":
                ghostty_bundle = self._find_macos_app_bundle("Ghostty.app")
                target = ghostty_bundle.as_posix() if ghostty_bundle is not None else "Ghostty"
                return self._launch_macos_ghostty(target, ssh_command)
            wrapper = self._create_posix_wrapper(ssh_command)
            style = _MACOS_CLI_TERMINAL_STYLES.get(identity) or self._linux_terminal_style(
                terminal
            )
            command = self._build_command_for_style(style, self._detected_path, wrapper)
            subprocess.Popen(
                command,
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True

        use_iterm = "iTerm" in terminal
        return self._launch_macos_applescript(
            "iTerm" if use_iterm else "Terminal",
            use_iterm=use_iterm,
            ssh_command=ssh_command,
        )

    def _launch_linux_terminal(
        self, terminal: str, executable: str, ssh_command: Sequence[str]
    ) -> bool:
        wrapper = self._create_posix_wrapper(ssh_command)
        command = self._build_linux_command(terminal, executable, wrapper)
        subprocess.Popen(
            command,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True

    @staticmethod
    def _build_command_for_style(
        style: str, executable: str, wrapper_script: str
    ) -> list[str]:
        if style == "separator":
            return [executable, "--", "bash", wrapper_script]
        if style == "start_separator":
            return [executable, "start", "--", "bash", wrapper_script]
        if style == "list":
            return [executable, "-e", "bash", wrapper_script]
        return [executable, "-e", f"bash {shlex.quote(wrapper_script)}"]

    def _build_linux_command(
        self, terminal: str, executable: str, wrapper_script: str
    ) -> list[str]:
        return self._build_command_for_style(
            self._linux_terminal_style(terminal), executable, wrapper_script
        )

    def _linux_terminal_style(self, terminal: str) -> str:
        """Return the declared argv style for a terminal name or path."""
        identity = _terminal_identity(terminal)
        for name, style in self.LINUX_TERMINALS:
            if name == identity:
                return style
        return self.DEFAULT_LINUX_TERMINAL_STYLE

    def _launch_windows_terminal(
        self, terminal: str, executable: str, ssh_command: Sequence[str]
    ) -> bool:
        system_directory = _windows_system_directory()
        powershell = system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if not powershell.is_file():
            self._last_error = (
                "Windows PowerShell was not found in the Windows system directory. "
                "Repair or install Windows PowerShell, then try again."
            )
            return False
        if _terminal_identity(terminal) == "wt":
            wrapper = self._create_powershell_wrapper(ssh_command)
            # ``wt`` has no window subcommand: ``-w new`` selects a new window
            # and ``new-tab`` runs the remaining argv as that tab's command.
            command = [
                executable,
                "-w",
                "new",
                "new-tab",
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                wrapper,
            ]
            flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            breakaway = getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0x01000000)
            flags_with_breakaway = flags | breakaway
            try:
                subprocess.Popen(
                    command,
                    shell=False,
                    creationflags=flags_with_breakaway,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError:
                subprocess.Popen(
                    command,
                    shell=False,
                    creationflags=flags,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        else:
            command_interpreter = system_directory / "cmd.exe"
            wrapper = self._create_cmd_wrapper(
                ssh_command, powershell_executable=powershell
            )
            flags = (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
            )
            breakaway = getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0x01000000)
            flags_with_breakaway = flags | breakaway
            # ``/c`` asks cmd to parse its final argument as command text, then
            # exits when the wrapper succeeds. The wrapper itself pauses only
            # after a failed SSH command. Passing the wrapper's absolute path
            # would reintroduce cmd injection through a valid but hostile
            # data-root directory name, even with Python ``shell=False``.
            # mkstemp gives us an ASCII basename; start cmd in the wrapper
            # directory and pass only that basename through the cmd parser.
            # The explicit ``.\`` keeps the lookup working when
            # NoDefaultCurrentDirectoryInExePath removes the current directory
            # from cmd's command search.
            wrapper_path = Path(wrapper)
            command = [
                str(command_interpreter),
                "/d",
                "/v:off",
                "/c",
                f".\\{wrapper_path.name}",
            ]
            # A direct cmd fallback owns a newly created console. Let its
            # standard handles inherit that console rather than redirecting
            # wrapper output and input to NUL.
            try:
                subprocess.Popen(
                    command,
                    shell=False,
                    creationflags=flags_with_breakaway,
                    cwd=str(wrapper_path.parent),
                )
            except OSError:
                subprocess.Popen(
                    command,
                    shell=False,
                    creationflags=flags,
                    cwd=str(wrapper_path.parent),
                )
        return True
