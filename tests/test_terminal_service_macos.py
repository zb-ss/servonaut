"""macOS terminal detection and launch coverage."""

from __future__ import annotations

import json
import os
import plistlib
import shlex
from pathlib import Path
from unittest.mock import patch

import pytest

from servonaut.services.terminal_service import TerminalService, _escape_applescript_text


def _make_bundle(
    parent: Path,
    bundle_name: str,
    *,
    bundle_id: str | None = None,
    executable_name: str | None = None,
    extra_executables: tuple[str, ...] = (),
    plist_bytes: bytes | None = None,
) -> tuple[Path, Path | None]:
    bundle = parent / bundle_name
    contents = bundle / "Contents"
    macos = contents / "MacOS"
    macos.mkdir(parents=True)

    main_executable: Path | None = None
    if executable_name is not None:
        main_executable = macos / executable_name
        main_executable.touch()
    for extra in extra_executables:
        (macos / extra).touch()

    if plist_bytes is not None:
        (contents / "Info.plist").write_bytes(plist_bytes)
    else:
        payload: dict[str, str] = {}
        if bundle_id is not None:
            payload["CFBundleIdentifier"] = bundle_id
        if executable_name is not None:
            payload["CFBundleExecutable"] = executable_name
        (contents / "Info.plist").write_bytes(plistlib.dumps(payload))

    return bundle, main_executable


@pytest.mark.parametrize(
    ("bundle_name", "bundle_id", "executable_name", "window_command"),
    [
        (
            "iTerm 2.app",
            "com.googlecode.iterm2",
            "iTerm2",
            "create window with default profile command",
        ),
        (
            "Work Terminal.app",
            "com.googlecode.iterm2",
            "iTerm2",
            "create window with default profile command",
        ),
        pytest.param(
            r'Work "Terminal" \ QA.app',
            "com.googlecode.iterm2",
            "iTerm2",
            "create window with default profile command",
            marks=pytest.mark.skipif(
                os.name == "nt", reason="The path uses POSIX filename characters"
            ),
        ),
        ("iTerm QA.app", "com.apple.Terminal", "Terminal", "do script"),
    ],
)
def test_macos_ssh_targets_configured_bundle_executable(
    tmp_path: Path,
    bundle_name: str,
    bundle_id: str,
    executable_name: str,
    window_command: str,
) -> None:
    bundle, executable = _make_bundle(
        tmp_path / "Local Apps",
        bundle_name,
        bundle_id=bundle_id,
        executable_name=executable_name,
    )
    assert executable is not None
    service = TerminalService(
        preferred=str(executable),
        data_root=tmp_path,
        command_resolver={str(executable): str(executable)}.get,
    )

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="darwin"),
        patch("servonaut.services.terminal_service.subprocess.Popen") as popen,
    ):
        assert service.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])

    apple_script = popen.call_args.args[0][2]
    expected_target = json.dumps(bundle.as_posix(), ensure_ascii=False)
    assert apple_script.splitlines()[0] == f"tell application {expected_target}"
    assert f'  {window_command} "bash ' in apple_script


@pytest.mark.parametrize(
    ("bundle_name", "bundle_id", "executable_name", "window_command", "trailing_slash"),
    [
        (
            "Work Terminal.app",
            "com.apple.Terminal",
            "Terminal",
            "do script",
            False,
        ),
        (
            "iTerm 2.APP",
            "com.googlecode.iterm2",
            "iTerm2",
            "create window with default profile command",
            True,
        ),
        pytest.param(
            r'Custom "iTerm" \ Path.app',
            "com.googlecode.iterm2",
            "iTerm2",
            "create window with default profile command",
            False,
            marks=pytest.mark.skipif(
                os.name == "nt", reason="The path uses POSIX filename characters"
            ),
        ),
    ],
)
def test_macos_ssh_targets_configured_app_bundle_directory(
    tmp_path: Path,
    bundle_name: str,
    bundle_id: str,
    executable_name: str,
    window_command: str,
    trailing_slash: bool,
) -> None:
    bundle, _executable = _make_bundle(
        tmp_path / "Local Apps",
        bundle_name,
        bundle_id=bundle_id,
        executable_name=executable_name,
    )
    preferred = f"{bundle}/" if trailing_slash else str(bundle)
    service = TerminalService(
        preferred=preferred,
        data_root=tmp_path,
        command_resolver=lambda _name: None,
    )

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="darwin"),
        patch("servonaut.services.terminal_service.subprocess.Popen") as popen,
    ):
        assert service.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])

    apple_script = popen.call_args.args[0][2]
    expected_target = json.dumps(bundle.as_posix(), ensure_ascii=False)
    assert apple_script.splitlines()[0] == f"tell application {expected_target}"
    assert f'  {window_command} "bash ' in apple_script


def test_macos_bare_terminal_app_name_respects_terminal_when_iterm_also_installed(
    tmp_path: Path,
) -> None:
    apps_dir = tmp_path / "Applications"
    utilities_dir = tmp_path / "SystemUtilities"
    iterm_bundle, _ = _make_bundle(
        apps_dir,
        "iTerm.app",
        bundle_id="com.googlecode.iterm2",
        executable_name="iTerm2",
    )
    terminal_bundle, _ = _make_bundle(
        utilities_dir,
        "Terminal.app",
        bundle_id="com.apple.Terminal",
        executable_name="Terminal",
    )

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="darwin"),
        patch(
            "servonaut.services.terminal_service._macos_app_search_dirs",
            return_value=(apps_dir, utilities_dir),
        ),
        patch("servonaut.services.terminal_service.subprocess.Popen") as popen,
    ):
        terminal_service = TerminalService(
            preferred="Terminal.app",
            data_root=tmp_path,
            command_resolver=lambda _name: None,
        )
        assert terminal_service.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])
        terminal_script = popen.call_args.args[0][2]
        assert terminal_script.splitlines()[0] == (
            f"tell application {json.dumps(terminal_bundle.as_posix(), ensure_ascii=False)}"
        )
        assert '  do script "bash ' in terminal_script

        iterm_service = TerminalService(
            preferred="iTerm.app",
            data_root=tmp_path,
            command_resolver=lambda _name: None,
        )
        assert iterm_service.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])
        iterm_script = popen.call_args.args[0][2]
        assert iterm_script.splitlines()[0] == (
            f"tell application {json.dumps(iterm_bundle.as_posix(), ensure_ascii=False)}"
        )
        assert '  create window with default profile command "bash ' in iterm_script


def test_macos_tilde_paths_resolve_bundle_and_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    bundle, executable = _make_bundle(
        tmp_path / "Applications",
        "Work iTerm.app",
        bundle_id="com.googlecode.iterm2",
        executable_name="iTerm2",
    )
    assert executable is not None

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="darwin"),
        patch("servonaut.services.terminal_service.subprocess.Popen") as popen,
    ):
        dir_service = TerminalService(
            preferred="~/Applications/Work iTerm.app",
            data_root=tmp_path,
            command_resolver=lambda _name: None,
        )
        assert dir_service.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])
        assert popen.call_args.args[0][2].splitlines()[0] == (
            f"tell application {json.dumps(bundle.as_posix(), ensure_ascii=False)}"
        )

        exe_service = TerminalService(
            preferred="~/Applications/Work iTerm.app/Contents/MacOS/iTerm2",
            data_root=tmp_path,
            command_resolver={str(executable): str(executable)}.get,
        )
        assert exe_service.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])
        assert popen.call_args.args[0][2].splitlines()[0] == (
            f"tell application {json.dumps(bundle.as_posix(), ensure_ascii=False)}"
        )


@pytest.mark.skipif(os.name == "nt", reason="symlinks require POSIX permissions")
def test_macos_symlink_to_bundle_executable_targets_bundle(tmp_path: Path) -> None:
    bundle, executable = _make_bundle(
        tmp_path / "Applications",
        "Work iTerm.app",
        bundle_id="com.googlecode.iterm2",
        executable_name="iTerm2",
    )
    assert executable is not None
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    symlink = bin_dir / "iterm2"
    symlink.symlink_to(executable)

    service = TerminalService(
        preferred="iterm2",
        data_root=tmp_path,
        command_resolver={"iterm2": str(symlink)}.get,
    )

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="darwin"),
        patch("servonaut.services.terminal_service.subprocess.Popen") as popen,
    ):
        assert service.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])

    expected_target = json.dumps(bundle.as_posix(), ensure_ascii=False)
    assert popen.call_args.args[0][2].splitlines()[0] == f"tell application {expected_target}"


def test_macos_ghostty_bundle_and_binary_launch_via_open(tmp_path: Path) -> None:
    apps_dir = tmp_path / "Applications"
    bundle, executable = _make_bundle(
        apps_dir,
        "Ghostty.app",
        bundle_id="com.mitchellh.ghostty",
        executable_name="ghostty",
    )
    assert executable is not None
    standalone_ghostty = tmp_path / "bin" / "ghostty"
    standalone_ghostty.parent.mkdir()
    standalone_ghostty.touch()

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="darwin"),
        patch(
            "servonaut.services.terminal_service._macos_app_search_dirs",
            return_value=(apps_dir,),
        ),
        patch("servonaut.services.terminal_service.subprocess.Popen") as popen,
    ):
        for preferred, resolver in (
            (str(bundle), lambda _name: None),
            ("Ghostty.app", lambda _name: None),
            (str(executable), {str(executable): str(executable)}.get),
            ("ghostty", {"ghostty": str(standalone_ghostty)}.get),
        ):
            service = TerminalService(
                preferred=preferred,
                data_root=tmp_path,
                command_resolver=resolver,
            )
            assert service.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])
            argv = popen.call_args.args[0]
            assert argv[:6] == ["open", "-na", bundle.as_posix(), "--args", "-e", "bash"]
            assert Path(argv[6]).is_file()


def test_macos_ghostty_cli_without_bundle_falls_back_to_app_name(tmp_path: Path) -> None:
    standalone_ghostty = tmp_path / "bin" / "ghostty"
    standalone_ghostty.parent.mkdir()
    standalone_ghostty.touch()
    service = TerminalService(
        preferred="ghostty",
        data_root=tmp_path,
        command_resolver={"ghostty": str(standalone_ghostty)}.get,
    )

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="darwin"),
        patch("servonaut.services.terminal_service._macos_app_search_dirs", return_value=()),
        patch("servonaut.services.terminal_service.subprocess.Popen") as popen,
    ):
        assert service.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])

    argv = popen.call_args.args[0]
    assert argv[:6] == ["open", "-na", "Ghostty", "--args", "-e", "bash"]
    assert Path(argv[6]).is_file()


@pytest.mark.parametrize(
    ("bundle_name", "bundle_id", "executable_name", "extra_executables", "expected_exe", "prefix"),
    [
        (
            "WezTerm.app",
            "com.github.wez.wezterm",
            "wezterm-gui",
            ("wezterm",),
            "wezterm",
            ["start", "--", "bash"],
        ),
        (
            "WezTerm.app",
            "com.github.wez.wezterm",
            "wezterm-gui",
            (),
            "wezterm-gui",
            ["start", "--", "bash"],
        ),
        (
            "Alacritty.app",
            "org.alacritty",
            "alacritty",
            (),
            "alacritty",
            ["-e", "bash"],
        ),
        (
            "kitty.app",
            "net.kovidgoyal.kitty",
            "kitty",
            (),
            "kitty",
            ["-e", "bash"],
        ),
        (
            "Rio.app",
            "com.raphaelamorim.rio",
            "rio",
            (),
            "rio",
            ["-e", "bash"],
        ),
    ],
)
def test_macos_cli_capable_app_bundles_launch_directly(
    tmp_path: Path,
    bundle_name: str,
    bundle_id: str,
    executable_name: str,
    extra_executables: tuple[str, ...],
    expected_exe: str,
    prefix: list[str],
) -> None:
    bundle, _ = _make_bundle(
        tmp_path / "Applications",
        bundle_name,
        bundle_id=bundle_id,
        executable_name=executable_name,
        extra_executables=extra_executables,
    )
    service = TerminalService(
        preferred=str(bundle),
        data_root=tmp_path,
        command_resolver=lambda _name: None,
    )

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="darwin"),
        patch("servonaut.services.terminal_service.subprocess.Popen") as popen,
    ):
        assert service.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])

    argv = popen.call_args.args[0]
    assert argv[0] == str(bundle / "Contents" / "MacOS" / expected_exe)
    assert argv[1:-1] == prefix
    assert Path(argv[-1]).is_file()
    assert popen.call_args.kwargs["start_new_session"] is True


@pytest.mark.parametrize(
    ("binary_name", "expected_mode"),
    [
        ("alacritty", "list"),
        ("kitty", "list"),
        ("rio", "list"),
        ("xterm", "list"),
        ("wezterm", "start_separator"),
        ("my-custom-term", "string"),
    ],
)
def test_macos_direct_cli_binaries_launch_directly(
    tmp_path: Path, binary_name: str, expected_mode: str
) -> None:
    binary = tmp_path / "bin" / binary_name
    binary.parent.mkdir()
    binary.touch()
    service = TerminalService(
        preferred=binary_name,
        data_root=tmp_path,
        command_resolver={binary_name: str(binary)}.get,
    )

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="darwin"),
        patch("servonaut.services.terminal_service.subprocess.Popen") as popen,
    ):
        assert service.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])

    argv = popen.call_args.args[0]
    assert argv[0] == str(binary)
    if expected_mode == "list":
        assert argv[1:3] == ["-e", "bash"]
        assert Path(argv[3]).is_file()
    elif expected_mode == "start_separator":
        assert argv[1:4] == ["start", "--", "bash"]
        assert Path(argv[4]).is_file()
    else:
        assert argv[1] == "-e"
        assert argv[2].startswith("bash ")
        parsed = shlex.split(argv[2])
        assert parsed[0] == "bash"
        assert Path(parsed[1]).is_file()


@pytest.mark.parametrize(
    ("bundle_name", "bundle_id", "executable_name", "plist_bytes"),
    [
        ("Warp.app", "dev.warp.Warp-Stable", "stable", None),
        ("CustomGUI.app", "com.example.customgui", "CustomGUI", None),
        ("BrokenCustom.app", None, "BrokenCustom", b"not a valid plist"),
    ],
)
def test_macos_unsupported_app_bundle_fails_without_opening_terminal(
    tmp_path: Path,
    bundle_name: str,
    bundle_id: str | None,
    executable_name: str,
    plist_bytes: bytes | None,
) -> None:
    bundle, _ = _make_bundle(
        tmp_path / "Applications",
        bundle_name,
        bundle_id=bundle_id,
        executable_name=executable_name,
        plist_bytes=plist_bytes,
    )
    service = TerminalService(
        preferred=str(bundle),
        data_root=tmp_path,
        command_resolver=lambda _name: None,
    )

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="darwin"),
        patch("servonaut.services.terminal_service.subprocess.Popen") as popen,
    ):
        assert not service.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])

    popen.assert_not_called()
    assert service.last_error is not None
    assert bundle_name in service.last_error


@pytest.mark.parametrize(
    ("bundle_name", "plist_bytes", "expected_app"),
    [
        (
            "iTerm Preview.app",
            (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<plist version="1.0"><dict>'
                "<key>CFBundleIdentifier</key><string>com.googlecode.iterm2</string>"
                "<key>BuildDate</key><date>invalid-date</date>"
                "</dict></plist>"
            ).encode("utf-8"),
            "iTerm",
        ),
        (
            "Broken Terminal.app",
            plistlib.dumps(["not", "a", "dict"]),
            "Terminal",
        ),
    ],
)
def test_macos_ssh_keeps_name_fallback_for_unreadable_bundle_id(
    tmp_path: Path, bundle_name: str, plist_bytes: bytes, expected_app: str
) -> None:
    _bundle, executable = _make_bundle(
        tmp_path,
        bundle_name,
        executable_name="Bin",
        plist_bytes=plist_bytes,
    )
    assert executable is not None
    service = TerminalService(
        preferred=str(executable),
        data_root=tmp_path,
        command_resolver={str(executable): str(executable)}.get,
    )

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="darwin"),
        patch("servonaut.services.terminal_service.subprocess.Popen") as popen,
    ):
        assert service.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])

    assert popen.call_args.args[0][2].splitlines()[0] == f'tell application "{expected_app}"'


def test_macos_auto_detection_prefers_iterm_then_terminal_then_fallback(
    tmp_path: Path,
) -> None:
    apps_dir = tmp_path / "Applications"
    utilities_dir = tmp_path / "SystemUtilities"
    terminal_bundle, _ = _make_bundle(
        utilities_dir,
        "Terminal.app",
        bundle_id="com.apple.Terminal",
        executable_name="Terminal",
    )

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="darwin"),
        patch(
            "servonaut.services.terminal_service._macos_app_search_dirs",
            return_value=(apps_dir, utilities_dir),
        ),
        patch("servonaut.services.terminal_service.subprocess.Popen") as popen,
    ):
        terminal_only = TerminalService(preferred="auto", data_root=tmp_path)
        assert terminal_only.detect_terminal() == "Terminal.app"
        assert terminal_only.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])
        assert popen.call_args.args[0][2].splitlines()[0] == (
            f"tell application {json.dumps(terminal_bundle.as_posix(), ensure_ascii=False)}"
        )

        iterm_bundle, _ = _make_bundle(
            apps_dir,
            "iTerm.app",
            bundle_id="com.googlecode.iterm2",
            executable_name="iTerm2",
        )
        with_iterm = TerminalService(preferred="auto", data_root=tmp_path)
        assert with_iterm.detect_terminal() == "iTerm.app"
        assert with_iterm.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])
        assert popen.call_args.args[0][2].splitlines()[0] == (
            f"tell application {json.dumps(iterm_bundle.as_posix(), ensure_ascii=False)}"
        )

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="darwin"),
        patch("servonaut.services.terminal_service._macos_app_search_dirs", return_value=()),
        patch("servonaut.services.terminal_service.subprocess.Popen") as popen,
    ):
        fallback = TerminalService(preferred="auto", data_root=tmp_path)
        assert fallback.detect_terminal() == "Terminal.app"
        assert fallback.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])
        assert popen.call_args.args[0][2].splitlines()[0] == 'tell application "Terminal"'


def test_escape_applescript_text_escapes_special_characters() -> None:
    assert _escape_applescript_text('a\\b"c\rd\ne') == r'a\\b\"c\rd\ne'


def test_macos_unreadable_configured_path_does_not_crash_launch(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    configured = locked / "Private Terminal.app"
    real_stat = os.stat

    def deny_locked(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if str(path).startswith(str(locked)):
            raise PermissionError(13, "Permission denied", str(path))
        return real_stat(path, *args, **kwargs)

    service = TerminalService(
        preferred=str(configured),
        data_root=tmp_path,
        command_resolver=lambda _name: None,
    )

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="darwin"),
        patch("servonaut.services.terminal_service.os.stat", side_effect=deny_locked),
        patch("servonaut.services.terminal_service._macos_app_search_dirs", return_value=()),
        patch("servonaut.services.terminal_service.subprocess.Popen") as popen,
    ):
        service.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])

    assert popen.call_args.args[0][2].splitlines()[0] == 'tell application "Terminal"'


@pytest.mark.parametrize(
    "plist_bytes",
    [b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><key>a</key></plist>'],
    ids=["key-without-value"],
)
def test_macos_malformed_info_plist_keeps_name_fallback(
    tmp_path: Path, plist_bytes: bytes
) -> None:
    _bundle, executable = _make_bundle(
        tmp_path,
        "Malformed Terminal.app",
        executable_name="Bin",
        plist_bytes=plist_bytes,
    )
    assert executable is not None
    service = TerminalService(
        preferred=str(executable),
        data_root=tmp_path,
        command_resolver={str(executable): str(executable)}.get,
    )

    with (
        patch("servonaut.services.terminal_service.get_os", return_value="darwin"),
        patch("servonaut.services.terminal_service.subprocess.Popen") as popen,
    ):
        assert service.launch_ssh_in_terminal(["/usr/bin/ssh", "example.invalid"])

    assert popen.call_args.args[0][2].splitlines()[0] == 'tell application "Terminal"'
