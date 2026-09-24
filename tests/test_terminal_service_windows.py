"""Windows-specific terminal wrapper construction and execution coverage."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path, PureWindowsPath
from unittest.mock import MagicMock, patch

import pytest

from servonaut.services.terminal_service import (
    TerminalService,
    quote_powershell_argument,
)


def _resolver(*available: str):
    paths = {name: rf"C:\\Tools\\{name}" for name in available}
    return lambda command: paths.get(command)


def _system_directory(tmp_path: Path) -> Path:
    directory = tmp_path / "Windows" / "System32"
    directory.mkdir(parents=True)
    powershell = directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    powershell.parent.mkdir(parents=True)
    powershell.touch()
    return directory


def _native_wrapper_timeout_diagnostic(
    *,
    wrapper_kind: str,
    stdout: object | None,
    capture_path: Path,
    expected_payload: list[str],
) -> str:
    """Classify bounded, non-sensitive wrapper observations after a timeout."""
    captured_stdout = stdout if isinstance(stdout, bytes) else b""
    captured_stdout = captured_stdout[:4096]
    failure_banner = b"--- SSH exited with code " in captured_stdout

    if wrapper_kind == "cmd":
        connecting_count = captured_stdout.count(b"Connecting with OpenSSH...")
        connecting = "2+" if connecting_count >= 2 else str(connecting_count)
    else:
        connecting = "not-applicable"

    capture_exists = False
    capture_valid = False
    capture_matches_expected = False
    try:
        capture_exists = capture_path.is_file()
        if capture_exists:
            with capture_path.open("rb") as capture_file:
                content = capture_file.read(4097)
            if len(content) <= 4096:
                decoded = json.loads(content)
                capture_valid = isinstance(decoded, list) and all(
                    isinstance(item, str) for item in decoded
                )
                capture_matches_expected = capture_valid and decoded == expected_payload
    except (OSError, UnicodeError, ValueError, RecursionError):
        pass

    return (
        "native-wrapper-timeout observed-after-timeout "
        f"wrapper={wrapper_kind} connecting_messages={connecting} "
        f"failure_banner={int(failure_banner)} capture_exists={int(capture_exists)} "
        f"capture_valid={int(capture_valid)} "
        f"capture_matches_expected={int(capture_matches_expected)}"
    )


def test_native_wrapper_timeout_diagnostic_classifies_bounded_observations(
    tmp_path: Path,
) -> None:
    """Timeout diagnostics retain only fixed markers and boolean file facts."""
    capture_path = tmp_path / "capture.json"
    expected_payload = ["expected"]

    assert _native_wrapper_timeout_diagnostic(
        wrapper_kind="cmd",
        stdout=b"Connecting with OpenSSH...\n--- SSH exited with code 1 ---\n",
        capture_path=capture_path,
        expected_payload=expected_payload,
    ) == (
        "native-wrapper-timeout observed-after-timeout wrapper=cmd "
        "connecting_messages=1 failure_banner=1 capture_exists=0 "
        "capture_valid=0 capture_matches_expected=0"
    )

    capture_path.write_text(json.dumps(expected_payload), encoding="utf-8")
    assert _native_wrapper_timeout_diagnostic(
        wrapper_kind="cmd",
        stdout=b"Connecting with OpenSSH...Connecting with OpenSSH...",
        capture_path=capture_path,
        expected_payload=expected_payload,
    ) == (
        "native-wrapper-timeout observed-after-timeout wrapper=cmd "
        "connecting_messages=2+ failure_banner=0 capture_exists=1 "
        "capture_valid=1 capture_matches_expected=1"
    )

    capture_path.write_bytes(b"{invalid")
    assert _native_wrapper_timeout_diagnostic(
        wrapper_kind="powershell",
        stdout=object(),
        capture_path=capture_path,
        expected_payload=expected_payload,
    ) == (
        "native-wrapper-timeout observed-after-timeout wrapper=powershell "
        "connecting_messages=not-applicable failure_banner=0 capture_exists=1 "
        "capture_valid=0 capture_matches_expected=0"
    )

    capture_path.write_text(json.dumps(["different"]), encoding="utf-8")
    assert _native_wrapper_timeout_diagnostic(
        wrapper_kind="cmd",
        stdout=None,
        capture_path=capture_path,
        expected_payload=expected_payload,
    ) == (
        "native-wrapper-timeout observed-after-timeout wrapper=cmd "
        "connecting_messages=0 failure_banner=0 capture_exists=1 "
        "capture_valid=1 capture_matches_expected=0"
    )

    stdout_canary = b"stdout-canary"
    message = _native_wrapper_timeout_diagnostic(
        wrapper_kind="cmd",
        stdout=stdout_canary + b"Connecting with OpenSSH...",
        capture_path=tmp_path / "missing.json",
        expected_payload=expected_payload,
    )
    assert message == (
        "native-wrapper-timeout observed-after-timeout wrapper=cmd "
        "connecting_messages=1 failure_banner=0 capture_exists=0 "
        "capture_valid=0 capture_matches_expected=0"
    )
    assert stdout_canary.decode() not in message

    message = _native_wrapper_timeout_diagnostic(
        wrapper_kind="cmd",
        stdout=(b"x" * 4096) + b"Connecting with OpenSSH...",
        capture_path=tmp_path / "missing.json",
        expected_payload=expected_payload,
    )
    assert "connecting_messages=0" in message

    capture_canary = b"capture-canary"
    capture_path.write_bytes(capture_canary + (b"x" * 4083))
    message = _native_wrapper_timeout_diagnostic(
        wrapper_kind="cmd",
        stdout=None,
        capture_path=capture_path,
        expected_payload=expected_payload,
    )
    assert "capture_exists=1 capture_valid=0 capture_matches_expected=0" in message
    assert capture_canary.decode() not in message


def test_powershell_quote_doubles_embedded_single_quote() -> None:
    assert quote_powershell_argument("it's safe") == "'it''s safe'"


# PowerShell closes a single-quoted string at any of these characters; a
# doubled one (of any of the five) is read as the second character.
_POWERSHELL_QUOTES = "'\u2018\u2019\u201a\u201b"


def _parse_powershell_single_quoted(source: str) -> tuple[str, str]:
    """Tokenize one leading single-quoted literal; return (value, remainder)."""
    assert source[0] in _POWERSHELL_QUOTES
    value: list[str] = []
    index = 1
    while index < len(source):
        character = source[index]
        if character in _POWERSHELL_QUOTES:
            if index + 1 < len(source) and source[index + 1] in _POWERSHELL_QUOTES:
                value.append(source[index + 1])
                index += 2
                continue
            return "".join(value), source[index + 1:]
        value.append(character)
        index += 1
    raise AssertionError("unterminated PowerShell literal")


@pytest.mark.parametrize("quote", list(_POWERSHELL_QUOTES))
def test_powershell_quote_keeps_every_single_quote_character_literal(quote: str) -> None:
    argument = f"x{quote}; Start-Process calc; {quote}{quote}end"

    value, remainder = _parse_powershell_single_quoted(quote_powershell_argument(argument))

    assert value == argument
    assert remainder == ""


def test_powershell_wrapper_keeps_typographic_quotes_inside_the_arguments_literal(
    tmp_path: Path,
) -> None:
    host_argument = "user\u2019; Start-Process calc; \u2018@web-1"
    service = TerminalService(data_root=tmp_path, command_resolver=_resolver())
    wrapper = Path(
        service._create_powershell_wrapper([r"C:\\Tools\\ssh.exe", host_argument])
    )
    prefix = "    $startInfo.Arguments = "
    line = next(
        line
        for line in wrapper.read_text(encoding="utf-8-sig").splitlines()
        if line.startswith(prefix)
    )

    value, remainder = _parse_powershell_single_quoted(line[len(prefix):])

    assert value == subprocess.list2cmdline([host_argument])
    assert remainder == ""


@pytest.mark.parametrize(
    "preferred", ["wt", "WT.EXE", r"C:\\Users\\me\\AppData\\Local\\Microsoft\\WindowsApps\\Wt.exe"]
)
def test_preferred_windows_terminal_is_matched_without_case_or_extension(
    tmp_path: Path, preferred: str
) -> None:
    paths = {"ssh": r"C:\\Tools\\ssh.exe", preferred: r"C:\\Tools\\wt.exe"}
    service = TerminalService(
        preferred,
        data_root=tmp_path,
        command_resolver=paths.get,
    )
    popen = MagicMock()
    system_directory = _system_directory(tmp_path)
    with (
        patch("servonaut.services.terminal_service.get_os", return_value="windows"),
        patch(
            "servonaut.services.terminal_service._windows_system_directory",
            return_value=system_directory,
        ),
        patch("servonaut.services.terminal_service.subprocess.Popen", popen),
    ):
        assert service.launch_ssh_in_terminal(["ssh", "web-1"])

    argv = popen.call_args.args[0]
    assert argv[:4] == [r"C:\\Tools\\wt.exe", "-w", "new", "new-tab"]
    assert Path(argv[-1]).suffix == ".ps1"


@pytest.mark.parametrize("argument", ["bad\nvalue", "bad\x00value"])
def test_shell_wrappers_refuse_unrepresentable_arguments(argument: str) -> None:
    with pytest.raises(ValueError):
        quote_powershell_argument(argument)


def test_windows_missing_openssh_is_not_reported_as_missing_terminal(
    tmp_path: Path,
) -> None:
    service = TerminalService(
        data_root=tmp_path,
        command_resolver=_resolver("wt.exe"),
    )
    with patch("servonaut.services.terminal_service.get_os", return_value="windows"):
        assert not service.launch_ssh_in_terminal(["ssh", "host"])

    assert service.last_error is not None
    assert "OpenSSH Client" in service.last_error
    assert "terminal emulator" not in service.last_error.lower()
    assert not (tmp_path / "logs").exists()


def test_windows_missing_terminal_is_distinct_from_openssh(tmp_path: Path) -> None:
    service = TerminalService(
        data_root=tmp_path,
        command_resolver=_resolver("ssh"),
    )
    with patch("servonaut.services.terminal_service.get_os", return_value="windows"):
        assert not service.launch_ssh_in_terminal(["ssh", "host"])

    assert service.last_error is not None
    assert "terminal emulator" in service.last_error.lower()
    assert "OpenSSH Client" not in service.last_error


def test_windows_missing_system_powershell_is_actionable(tmp_path: Path) -> None:
    service = TerminalService(
        data_root=tmp_path,
        command_resolver=_resolver("ssh", "cmd.exe"),
    )
    popen = MagicMock()
    missing_system_directory = tmp_path / "Windows" / "System32"
    missing_system_directory.mkdir(parents=True)
    with (
        patch("servonaut.services.terminal_service.get_os", return_value="windows"),
        patch(
            "servonaut.services.terminal_service._windows_system_directory",
            return_value=missing_system_directory,
        ),
        patch("servonaut.services.terminal_service.subprocess.Popen", popen),
    ):
        assert not service.launch_ssh_in_terminal(["ssh", "host"])

    assert service.last_error is not None
    assert "Windows PowerShell" in service.last_error
    assert "Repair or install" in service.last_error
    popen.assert_not_called()


def test_windows_terminal_uses_a_powershell_wrapper_and_native_argv(tmp_path: Path) -> None:
    service = TerminalService(
        data_root=tmp_path,
        command_resolver=_resolver("ssh", "wt.exe"),
    )
    popen = MagicMock()
    system_directory = _system_directory(tmp_path)
    with (
        patch("servonaut.services.terminal_service.get_os", return_value="windows"),
        patch(
            "servonaut.services.terminal_service._windows_system_directory",
            return_value=system_directory,
        ),
        patch("servonaut.services.terminal_service.subprocess.Popen", popen),
    ):
        assert service.launch_ssh_in_terminal(["ssh", "name with spaces"])

    argv = popen.call_args.args[0]
    assert argv[:5] == [r"C:\\Tools\\wt.exe", "-w", "new", "new-tab", str(
        system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )]
    assert "-ExecutionPolicy" in argv
    assert argv[-2] == "-File"
    wrapper = Path(argv[-1])
    assert wrapper.suffix == ".ps1"
    assert "bash" not in wrapper.read_text(encoding="utf-8-sig").lower()
    content = wrapper.read_text(encoding="utf-8-sig")
    assert "ProcessStartInfo" in content
    assert "$startInfo.Arguments" in content
    assert '"name with spaces"' in content
    launch_kwargs = popen.call_args.kwargs
    assert launch_kwargs["shell"] is False
    assert launch_kwargs["stdout"] is subprocess.DEVNULL
    assert launch_kwargs["stderr"] is subprocess.DEVNULL


def test_powershell_wrapper_uses_process_start_info_for_embedded_quotes(
    tmp_path: Path,
) -> None:
    """PowerShell 5.1 does not directly parse native SSH arguments."""
    service = TerminalService(data_root=tmp_path, command_resolver=_resolver())
    wrapper = Path(
        service._create_powershell_wrapper(
            [r"C:\\Tools\\ssh.exe", 'a "quote" and trailing\\']
        )
    )
    content = wrapper.read_text(encoding="utf-8-sig")

    assert "$startInfo.FileName" in content
    assert "$startInfo.Arguments" in content
    assert "[System.Diagnostics.Process]::Start($startInfo)" in content
    assert "& '" not in content


def test_macos_terminal_quotes_a_wrapper_path_with_spaces(tmp_path: Path) -> None:
    service = TerminalService(data_root=tmp_path, command_resolver=_resolver())
    popen = MagicMock()
    with (
        patch.object(service, "_create_posix_wrapper", return_value="/tmp/a b/session.sh"),
        patch("servonaut.services.terminal_service.subprocess.Popen", popen),
    ):
        assert service._launch_macos_terminal("Terminal.app", ["ssh", "host"])

    applescript = popen.call_args.args[0][2]
    assert 'do script "bash \'/tmp/a b/session.sh\'"' in applescript


def test_cmd_fallback_uses_cmd_wrapper_and_new_console(tmp_path: Path) -> None:
    service = TerminalService(
        data_root=tmp_path,
        command_resolver=_resolver("ssh", "cmd.exe"),
    )
    popen = MagicMock()
    system_directory = _system_directory(tmp_path)
    with (
        patch("servonaut.services.terminal_service.get_os", return_value="windows"),
        patch(
            "servonaut.services.terminal_service._windows_system_directory",
            return_value=system_directory,
        ),
        patch("servonaut.services.terminal_service.subprocess.Popen", popen),
    ):
        assert service.launch_ssh_in_terminal(["ssh", "safe & literal"])

    argv = popen.call_args.args[0]
    assert argv[:4] == [str(system_directory / "cmd.exe"), "/d", "/v:off", "/c"]
    assert argv[-1].startswith(".\\")
    wrapper = Path(popen.call_args.kwargs["cwd"]) / PureWindowsPath(argv[-1]).name
    assert wrapper.suffix == ".cmd"
    content = wrapper.read_text(encoding="utf-8")
    assert content.splitlines()[1] == "chcp 65001 >nul"
    assert "DisableDelayedExpansion" in content
    assert "safe & literal" not in content
    assert (
        f'"{system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"}"'
        in content
    )
    powershell_wrapper = next((tmp_path / "logs").glob("servonaut_*.ps1"))
    assert powershell_wrapper.name in content
    powershell_content = powershell_wrapper.read_text(encoding="utf-8-sig")
    assert "ProcessStartInfo" in powershell_content
    assert "$ErrorActionPreference = 'Stop'" in powershell_content
    assert "$exitCode = 1" in powershell_content
    assert "Read-Host" not in powershell_content
    assert "pause >nul" in content
    launch_kwargs = popen.call_args.kwargs
    assert launch_kwargs["shell"] is False
    assert launch_kwargs["cwd"] == str(tmp_path / "logs")
    assert "stdin" not in launch_kwargs
    assert "stdout" not in launch_kwargs
    assert "stderr" not in launch_kwargs


def test_cmd_fallback_passes_only_wrapper_basename_to_cmd(tmp_path: Path) -> None:
    """A hostile wrapper parent never reaches cmd's command-text argument."""
    data_root = tmp_path / "wrapper & copy NUL cmd-injection-marker & rem"
    service = TerminalService(
        data_root=data_root,
        command_resolver=_resolver("ssh", "cmd.exe"),
    )
    popen = MagicMock()
    system_directory = _system_directory(tmp_path)
    with (
        patch("servonaut.services.terminal_service.get_os", return_value="windows"),
        patch(
            "servonaut.services.terminal_service._windows_system_directory",
            return_value=system_directory,
        ),
        patch("servonaut.services.terminal_service.subprocess.Popen", popen),
    ):
        assert service.launch_ssh_in_terminal(["ssh", "host"])

    argv = popen.call_args.args[0]
    wrapper_argument = PureWindowsPath(argv[-1])
    wrapper_name = wrapper_argument.name
    wrapper_dir = data_root / "logs"
    assert argv[-1] == f".\\{wrapper_name}"
    assert wrapper_argument.parent == PureWindowsPath(".")
    assert wrapper_name.startswith("servonaut_")
    assert wrapper_name.endswith(".cmd")
    assert popen.call_args.kwargs["cwd"] == str(wrapper_dir)
    assert str(wrapper_dir) not in subprocess.list2cmdline(argv)
    assert "&" not in subprocess.list2cmdline(argv)


def test_windows_cmd_uses_system_directory_instead_of_resolver_decoy(
    tmp_path: Path,
) -> None:
    """A PATH/cwd cmd.exe decoy cannot replace the native command interpreter."""
    system_directory = _system_directory(tmp_path)
    resolver = lambda name: {
        "ssh": r"C:\\checked\\ssh.exe",
        "cmd.exe": r"C:\\decoy\\cmd.exe",
    }.get(name)
    service = TerminalService(data_root=tmp_path, command_resolver=resolver)
    popen = MagicMock()
    with (
        patch("servonaut.services.terminal_service.get_os", return_value="windows"),
        patch(
            "servonaut.services.terminal_service._windows_system_directory",
            return_value=system_directory,
        ),
        patch("servonaut.services.terminal_service.subprocess.Popen", popen),
    ):
        assert service.launch_ssh_in_terminal(["ssh", "host"])

    assert popen.call_args.args[0][0] == str(system_directory / "cmd.exe")
    assert r"C:\\decoy\\cmd.exe" not in popen.call_args.args[0]


def test_linux_launch_reuses_resolved_terminal_path(tmp_path: Path) -> None:
    """A selected user terminal is not looked up again at launch time."""
    executable_suffix = ".exe" if os.name == "nt" else ""
    ssh = tmp_path / "checked" / f"ssh{executable_suffix}"
    terminal = tmp_path / "checked" / f"gnome-terminal{executable_suffix}"
    ssh.parent.mkdir()
    ssh.write_text("fixture", encoding="utf-8")
    terminal.write_text("fixture", encoding="utf-8")
    resolver = lambda name: {
        "ssh": str(ssh),
        "gnome-terminal": str(terminal),
    }.get(name)
    service = TerminalService(data_root=tmp_path, command_resolver=resolver)
    popen = MagicMock()
    with (
        patch("servonaut.services.terminal_service.get_os", return_value="linux"),
        patch("servonaut.services.terminal_service.subprocess.Popen", popen),
    ):
        assert service.launch_ssh_in_terminal(["ssh", "host"])

    assert popen.call_args.args[0][0] == str(terminal)


_WRAPPER = "/home/user/.servonaut/logs/servonaut_ab c.sh"
_LINUX_LAUNCH_ARGV = {
    "gnome-terminal": ["--", "bash", _WRAPPER],
    "konsole": ["-e", "bash", _WRAPPER],
    "alacritty": ["-e", "bash", _WRAPPER],
    "kitty": ["-e", "bash", _WRAPPER],
    "xterm": ["-e", "bash", _WRAPPER],
    "xfce4-terminal": ["-e", f"bash {shlex.quote(_WRAPPER)}"],
    "mate-terminal": ["-e", f"bash {shlex.quote(_WRAPPER)}"],
    "tilix": ["-e", f"bash {shlex.quote(_WRAPPER)}"],
}


def test_every_linux_terminal_has_a_pinned_launch_argv() -> None:
    assert {name for name, _style in TerminalService.LINUX_TERMINALS} == set(
        _LINUX_LAUNCH_ARGV
    )


@pytest.mark.parametrize(("terminal", "arguments"), sorted(_LINUX_LAUNCH_ARGV.items()))
def test_linux_terminal_receives_the_wrapper_in_its_declared_style(
    terminal: str, arguments: list[str]
) -> None:
    service = TerminalService(command_resolver=_resolver())

    command = service._build_linux_command(terminal, "/usr/bin/term", _WRAPPER)

    assert command == ["/usr/bin/term", *arguments]


def test_preferred_linux_terminal_path_is_matched_without_case() -> None:
    preferred = "/opt/tools/Alacritty"
    service = TerminalService(preferred, command_resolver=_resolver())

    command = service._build_linux_command(preferred, preferred, _WRAPPER)

    assert command == [preferred, "-e", "bash", _WRAPPER]


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows cmd and PowerShell")
@pytest.mark.parametrize("wrapper_kind", ["cmd", "powershell"])
def test_native_windows_wrapper_preserves_hostile_argv(
    tmp_path: Path, wrapper_kind: str
) -> None:
    """Execute each wrapper with a benign argv-capture program on Windows."""
    capture_script = tmp_path / "capture argv.py"
    output = tmp_path / "captured argv.json"
    capture_script.write_text(
        "import json, pathlib, sys\n"
        "pathlib.Path(sys.argv[1]).write_text(\n"
        "    json.dumps(sys.argv[2:], ensure_ascii=False), encoding='utf-8'\n"
        ")\n",
        encoding="utf-8",
    )
    payload = [
        "path with spaces",
        "& whoami | findstr anything < input > output",
        "%PATH%!delayed!^caret^(group)",
        "naïve-東京",
        'a "quote" and trailing\\',
        "typographic \u2019; Write-Output injected; \u2018 quotes",
    ]
    service = TerminalService(data_root=tmp_path, command_resolver=_resolver())
    command = [sys.executable, str(capture_script), str(output), *payload]

    if wrapper_kind == "cmd":
        from servonaut.services.process_control import windows_system_directory

        system_directory = windows_system_directory()
        wrapper_path = Path(
            service._create_cmd_wrapper(
                command,
                powershell_executable=(
                    system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
                ),
            )
        )
        runner = [str(system_directory / "cmd.exe"), "/d", "/v:off", "/c", wrapper_path.name]
        runner_cwd = wrapper_path.parent
    else:
        wrapper = service._create_powershell_wrapper(command)
        runner = [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            wrapper,
        ]
        runner_cwd = None

    try:
        completed = subprocess.run(
            runner,
            cwd=runner_cwd,
            check=False,
            capture_output=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(
            _native_wrapper_timeout_diagnostic(
                wrapper_kind=wrapper_kind,
                stdout=exc.stdout,
                capture_path=output,
                expected_payload=payload,
            ),
            pytrace=False,
        )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    assert json.loads(output.read_text(encoding="utf-8")) == payload


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows cmd")
@pytest.mark.parametrize(
    "argument_template",
    [
        "",
        '"',
        '""',
        'embedded "quote" without a trailing slash',
        "path with spaces and a trailing slash\\",
        'one backslash before a quote\\"',
        'two backslashes before a quote\\\\"',
        (
            'combined "quote" & copy NUL "{marker}" & rem '
            "%PATH%!bang!^caret^(group)\\"
        ),
    ],
)
def test_native_cmd_trampoline_preserves_quote_boundaries(
    tmp_path: Path, argument_template: str
) -> None:
    """Embedded quotes never expose a cmd metacharacter as a second command."""
    from servonaut.services.process_control import windows_system_directory

    marker = tmp_path / "cmd-quote-injection-marker"
    argument = argument_template.format(marker=marker)
    capture_script = tmp_path / "capture argv.py"
    output = tmp_path / "captured argv.json"
    capture_script.write_text(
        "import json, pathlib, sys\n"
        "pathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]))\n",
        encoding="utf-8",
    )
    system_directory = windows_system_directory()
    service = TerminalService(data_root=tmp_path, command_resolver=_resolver())
    wrapper_path = Path(
        service._create_cmd_wrapper(
            [sys.executable, str(capture_script), str(output), argument],
            powershell_executable=(
                system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            ),
        )
    )

    completed = subprocess.run(
        [str(system_directory / "cmd.exe"), "/d", "/v:off", "/c", wrapper_path.name],
        cwd=wrapper_path.parent,
        check=False,
        capture_output=True,
        timeout=20,
    )

    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    assert json.loads(output.read_text(encoding="utf-8")) == [argument]
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows cmd")
def test_native_cmd_trampoline_reports_a_missing_executable(tmp_path: Path) -> None:
    """A ProcessStartInfo failure returns nonzero through the cmd wrapper."""
    from servonaut.services.process_control import windows_system_directory

    system_directory = windows_system_directory()
    service = TerminalService(data_root=tmp_path, command_resolver=_resolver())
    wrapper_path = Path(
        service._create_cmd_wrapper(
            [str(tmp_path / "missing-ssh.exe")],
            powershell_executable=(
                system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            ),
        )
    )

    completed = subprocess.run(
        [str(system_directory / "cmd.exe"), "/d", "/v:off", "/c", wrapper_path.name],
        cwd=wrapper_path.parent,
        input=b"\r\n",
        check=False,
        capture_output=True,
        timeout=20,
    )

    assert completed.returncode == 1, completed.stderr.decode(errors="replace")
    assert b"Could not start OpenSSH" in completed.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows cmd")
def test_native_cmd_wrapper_parent_path_cannot_inject_a_command(tmp_path: Path) -> None:
    """Run the cmd wrapper from a metacharacter parent without marker execution."""
    from servonaut.services.process_control import windows_system_directory

    marker = tmp_path / "cmd-injection-marker"
    data_root = tmp_path / "wrapper & copy NUL cmd-injection-marker & rem"
    decoy_directory = tmp_path / "path-decoy"
    decoy_directory.mkdir()
    decoy_marker = decoy_directory / "cmd-decoy-used"
    (decoy_directory / "cmd.exe").write_text(
        f'@echo decoy > "{decoy_marker}"\r\n', encoding="utf-8"
    )
    capture_script = tmp_path / "capture argv.py"
    output = tmp_path / "captured argv.json"
    capture_script.write_text(
        "import json, pathlib, sys\n"
        "pathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]))\n",
        encoding="utf-8",
    )
    service = TerminalService(data_root=data_root, command_resolver=_resolver())
    wrapper = Path(
        service._create_cmd_wrapper(
            [sys.executable, str(capture_script), str(output), "safe payload"],
            powershell_executable=(
                windows_system_directory()
                / "WindowsPowerShell"
                / "v1.0"
                / "powershell.exe"
            ),
        )
    )

    environment = os.environ.copy()
    environment["PATH"] = str(decoy_directory)
    completed = subprocess.run(
        [str(windows_system_directory() / "cmd.exe"), "/d", "/v:off", "/c", wrapper.name],
        cwd=wrapper.parent,
        env=environment,
        check=False,
        capture_output=True,
        timeout=20,
    )

    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    assert json.loads(output.read_text(encoding="utf-8")) == ["safe payload"]
    assert not marker.exists()
    assert not decoy_marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows cmd")
def test_native_production_cmd_argv_exits_after_success_and_pauses_on_failure(
    tmp_path: Path,
) -> None:
    """Execute the exact cmd argv produced by the production launch path."""
    from servonaut.services.process_control import windows_system_directory

    system_cmd = windows_system_directory() / "cmd.exe"

    def resolver(name: str) -> str | None:
        if name == "ssh":
            return sys.executable
        if name == "cmd.exe":
            return str(system_cmd)
        return None

    def production_argv(ssh_command: list[str]) -> tuple[list[str], str]:
        service = TerminalService(data_root=tmp_path, command_resolver=resolver)
        launched: list[tuple[list[str], dict]] = []

        def record_launch(command: list[str], **kwargs):
            launched.append((list(command), kwargs))
            return MagicMock()

        with patch("servonaut.services.terminal_service.subprocess.Popen", record_launch):
            assert service.launch_ssh_in_terminal(ssh_command)

        command, kwargs = launched.pop()
        assert command[:4] == [str(system_cmd), "/d", "/v:off", "/c"]
        return command, kwargs["cwd"]

    success_output = tmp_path / "success.txt"
    success_script = tmp_path / "success.py"
    success_script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "Path(sys.argv[1]).write_text('ok')\n",
        encoding="utf-8",
    )
    success_argv, success_cwd = production_argv(
        [sys.executable, str(success_script), str(success_output)]
    )
    success = subprocess.run(
        success_argv,
        cwd=success_cwd,
        input=b"\r\n",
        capture_output=True,
        check=False,
        timeout=20,
    )
    assert success.returncode == 0, success.stderr.decode(errors="replace")
    assert success_output.read_text(encoding="utf-8") == "ok"

    failure_argv, failure_cwd = production_argv(
        [sys.executable, "-c", "import sys; raise SystemExit(7)"]
    )
    failure = subprocess.Popen(
        failure_argv,
        cwd=failure_cwd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.25)
    assert failure.poll() is None, "failed SSH wrapper must wait for acknowledgement"
    stdout, stderr = failure.communicate(input=b"\r\n", timeout=20)
    assert failure.returncode == 7, stderr.decode(errors="replace")
    assert b"SSH exited with code 7" in stdout


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows cmd")
def test_native_production_cmd_launch_inherits_new_console_handles(tmp_path: Path) -> None:
    """The direct cmd path retains its new console's standard handles."""
    from servonaut.services.process_control import windows_system_directory

    system_cmd = windows_system_directory() / "cmd.exe"
    evidence_path = tmp_path / "console-handles.json"
    helper_path = tmp_path / "inspect_console_handles.py"
    helper_path.write_text(
        "import ctypes\n"
        "import json\n"
        "from pathlib import Path\n"
        "import sys\n"
        "kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)\n"
        "kernel32.GetStdHandle.restype = ctypes.c_void_p\n"
        "kernel32.GetFileType.argtypes = [ctypes.c_void_p]\n"
        "kernel32.GetFileType.restype = ctypes.c_uint\n"
        "kernel32.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]\n"
        "kernel32.GetConsoleMode.restype = ctypes.c_int\n"
        "results = {}\n"
        "for name, selector in {'stdin': -10, 'stdout': -11, 'stderr': -12}.items():\n"
        "    handle = kernel32.GetStdHandle(selector)\n"
        "    mode = ctypes.c_ulong()\n"
        "    results[name] = {\n"
        "        'file_type': kernel32.GetFileType(handle),\n"
        "        'is_console': bool(kernel32.GetConsoleMode(handle, ctypes.byref(mode))),\n"
        "    }\n"
        "Path(sys.argv[1]).write_text(json.dumps(results), encoding='utf-8')\n",
        encoding="utf-8",
    )

    def resolver(name: str) -> str | None:
        if name == "ssh":
            return sys.executable
        if name == "cmd.exe":
            return str(system_cmd)
        return None

    service = TerminalService(data_root=tmp_path, command_resolver=resolver)
    production_popen = subprocess.Popen
    launched: list[tuple[list[str], dict, subprocess.Popen]] = []

    def record_and_launch(command: list[str], **kwargs):
        process = production_popen(command, **kwargs)
        launched.append((list(command), kwargs, process))
        return process

    with patch("servonaut.services.terminal_service.subprocess.Popen", record_and_launch):
        assert service.launch_ssh_in_terminal(
            [sys.executable, str(helper_path), str(evidence_path)]
        )

    command, launch_kwargs, process = launched.pop()
    assert command[:4] == [str(system_cmd), "/d", "/v:off", "/c"]
    assert "stdin" not in launch_kwargs
    assert "stdout" not in launch_kwargs
    assert "stderr" not in launch_kwargs
    assert process.wait(timeout=20) == 0
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert all(handle["file_type"] == 2 for handle in evidence.values())
    assert all(handle["is_console"] for handle in evidence.values())
