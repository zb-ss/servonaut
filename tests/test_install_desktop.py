"""The terminal shortcuts ``servonaut --install-desktop`` writes, and the older ones it replaces.

The packaged desktop app brings its own launcher: dev.servonaut.Servonaut.desktop
on Linux, Servonaut.app (dev.servonaut.desktop) on macOS. The terminal shortcuts
are named apart from it. A shortcut an earlier version wrote under the desktop
app's name is removed only when it is recognisably one that version wrote.
"""
from __future__ import annotations

import ast
import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from servonaut import main
from servonaut.runtime import DistributionKind

_REPO_ROOT = Path(__file__).resolve().parents[1]
_APP_ARGV = [str(Path(sys.executable).resolve()), "-m", "servonaut"]
_TERMINAL_LAUNCHER = "dev.servonaut.Servonaut.Terminal.desktop"
_TERMINAL_BUNDLE = "Servonaut Terminal.app"
_LEGACY_COMMENT = "Comment=Server Manager — SSH, SCP, AI Analysis, and more"
# The Info.plist earlier versions wrote into ~/Applications/Servonaut.app.
_LEGACY_INFO_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Servonaut</string>
    <key>CFBundleName</key>
    <string>Servonaut</string>
    <key>CFBundleIdentifier</key>
    <string>{identifier}</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
</dict>
</plist>
"""


def _runtime(kind: DistributionKind = DistributionKind.SOURCE) -> SimpleNamespace:
    executable = Path(sys.executable).resolve()
    return SimpleNamespace(
        kind=kind,
        executable=executable,
        executable_root=executable.parent,
        is_frozen=False,
        desktop_child=None,
        current_app_argv=lambda: list(_APP_ARGV),
    )


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: _runtime())
    return home


@pytest.fixture
def applications(home: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A Linux session with gnome-terminal; its user applications directory."""
    monkeypatch.setattr("servonaut.utils.platform_utils.get_os", lambda: "linux")
    monkeypatch.setattr(
        shutil, "which", lambda name: f"/usr/bin/{name}" if name == "gnome-terminal" else None
    )
    directory = home / ".local" / "share" / "applications"
    directory.mkdir(parents=True)
    return directory


@pytest.fixture
def mac_applications(home: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A macOS session; its ~/Applications directory."""
    monkeypatch.setattr("servonaut.utils.platform_utils.get_os", lambda: "darwin")
    directory = home / "Applications"
    directory.mkdir()
    return directory


def _legacy_launcher(command: str, *, comment: str = _LEGACY_COMMENT) -> str:
    """The Linux launcher earlier versions wrote, running *command*."""
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Servonaut\n"
        f"{comment}\n"
        f"Exec={command}\n"
        "Icon=utilities-terminal\n"
        "Terminal=false\n"
        "Categories=System;TerminalEmulator;\n"
        "Keywords=ssh;server;aws;ec2;\n"
    )


def _legacy_bundle(
    directory: Path, *, with_helper: bool = True, identifier: str = "com.servonaut.app"
) -> Path:
    """The macOS shortcut earlier versions wrote, first without a command helper."""
    bundle = directory / "Servonaut.app"
    executables = bundle / "Contents" / "MacOS"
    executables.mkdir(parents=True)
    if with_helper:
        (executables / "Servonaut.command").write_text(
            "#!/bin/sh\nexec /usr/local/bin/servonaut\n", encoding="utf-8"
        )
        (executables / "Servonaut").write_text(
            "#!/bin/sh\n"
            'script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)\n'
            'exec open -a Terminal "$script_dir/Servonaut.command"\n',
            encoding="utf-8",
        )
    else:
        (executables / "Servonaut").write_text(
            '#!/bin/bash\nopen -a Terminal "/usr/local/bin/servonaut"\n', encoding="utf-8"
        )
    (bundle / "Contents" / "Info.plist").write_text(
        _LEGACY_INFO_PLIST.format(identifier=identifier), encoding="utf-8"
    )
    return bundle


def _tree(root: Path) -> dict[str, bytes | str]:
    """Every entry under *root*: file contents, or where a link points."""
    entries: dict[str, bytes | str] = {}
    for directory, subdirectories, files in os.walk(root):
        for name in (*subdirectories, *files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                entries[relative] = f"-> {os.readlink(path)}"
            elif path.is_file():
                entries[relative] = path.read_bytes()
            else:
                entries[relative] = "<dir>"
    return entries


def _macos_app_defaults() -> dict[str, str]:
    """The desktop app bundle's name and identifier, as the macOS packager defaults them."""
    packager = _REPO_ROOT / "scripts" / "distribution" / "package_macos.py"
    for node in ast.walk(ast.parse(packager.read_text(encoding="utf-8"))):
        if isinstance(node, ast.FunctionDef) and node.name == "assemble_app_bundle":
            keywords = node.args.kwonlyargs
            defaults = node.args.kw_defaults
            return {
                argument.arg: ast.literal_eval(default)
                for argument, default in zip(keywords, defaults)
                if default is not None and argument.arg in {"bundle_name", "bundle_id"}
            }
    raise AssertionError("package_macos.py defines no assemble_app_bundle")


# Linux


def test_the_linux_launcher_is_named_apart_from_the_desktop_app(
    applications: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main._install_desktop()

    launcher = applications / _TERMINAL_LAUNCHER
    lines = launcher.read_text(encoding="utf-8").splitlines()
    assert "Name=Servonaut (terminal)" in lines
    assert "X-Servonaut-Launcher=terminal" in lines
    assert f"Exec={main._desktop_exec(['gnome-terminal', '--', *_APP_ARGV])}" in lines
    assert "Icon=utilities-terminal" in lines
    # A TerminalEmulator entry is offered as the default terminal.
    assert "Categories=System;" in lines
    packaged = {entry.name for entry in (_REPO_ROOT / "packaging" / "deb").glob("*.desktop")}
    assert packaged == {"dev.servonaut.Servonaut.desktop"}
    assert [entry.name for entry in applications.iterdir()] == [_TERMINAL_LAUNCHER]
    assert "Servonaut (terminal)" in capsys.readouterr().out


@pytest.mark.skipif(
    shutil.which("desktop-file-validate") is None, reason="needs desktop-file-validate"
)
def test_the_linux_launcher_is_a_valid_desktop_entry(applications: Path) -> None:
    main._install_desktop()

    validation = subprocess.run(
        ["desktop-file-validate", str(applications / _TERMINAL_LAUNCHER)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert validation.returncode == 0, validation.stdout + validation.stderr
    assert validation.stdout == ""


@pytest.mark.parametrize(
    "content",
    [
        # The first version: an unquoted command, "gnome-terminal -- " and the path.
        _legacy_launcher("gnome-terminal --  /usr/local/bin/servonaut"),
        # Quoted arguments, while xfce4-terminal still took -e.
        _legacy_launcher('"xfce4-terminal" "-e" "/usr/local/bin/servonaut"'),
        _legacy_launcher('"kitty" "-e" "/opt/venv/bin/python" "-m" "servonaut.main"'),
        # Whatever else it says, the marker key is ours.
        "[Desktop Entry]\nType=Application\nName=Anything\nExec=true\n"
        "X-Servonaut-Launcher=terminal\n",
    ],
    ids=["first-version", "xfce4-terminal-e", "module-command", "marker"],
)
def test_a_launcher_an_earlier_version_wrote_is_replaced(
    applications: Path, capsys: pytest.CaptureFixture[str], content: str
) -> None:
    legacy = applications / "servonaut.desktop"
    legacy.write_text(content, encoding="utf-8")

    main._install_desktop()

    assert not legacy.exists()
    assert (applications / _TERMINAL_LAUNCHER).is_file()
    assert f"Removed the previous terminal launcher {legacy}" in capsys.readouterr().out


@pytest.mark.parametrize(
    "content",
    [
        "[Desktop Entry]\nType=Application\nName=Servonaut\nExec=servonaut\n",
        _legacy_launcher('"kitty" "-e" "htop"'),
        _legacy_launcher('"tilix" "-e" "/usr/local/bin/servonaut"'),
        _legacy_launcher('"kitty" "-e" "/usr/local/bin/servonaut"', comment="Comment=Mine"),
        _legacy_launcher('"kitty" "-e" "/usr/local/bin/servonaut'),
        _legacy_launcher('"kitty" "-e" "/usr/local/bin/servonaut"') + "Exec=servonaut\n",
    ],
    ids=[
        "hand-made",
        "other-command",
        "other-terminal",
        "other-comment",
        "unparsable",
        "two-commands",
    ],
)
def test_a_launcher_it_did_not_write_is_kept(
    applications: Path, capsys: pytest.CaptureFixture[str], content: str
) -> None:
    legacy = applications / "servonaut.desktop"
    legacy.write_text(content, encoding="utf-8")

    main._install_desktop()

    assert legacy.read_text(encoding="utf-8") == content
    assert (applications / _TERMINAL_LAUNCHER).is_file()
    assert f"Left {legacy} unchanged" in capsys.readouterr().out


def test_a_linked_launcher_is_kept(applications: Path, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.desktop"
    target.write_text(
        _legacy_launcher("gnome-terminal --  /usr/local/bin/servonaut"), encoding="utf-8"
    )
    legacy = applications / "servonaut.desktop"
    legacy.symlink_to(target)

    main._install_desktop()

    assert legacy.is_symlink()
    assert target.is_file()


def test_without_a_terminal_the_earlier_launcher_stays(
    applications: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    legacy = applications / "servonaut.desktop"
    legacy.write_text(
        _legacy_launcher("gnome-terminal --  /usr/local/bin/servonaut"), encoding="utf-8"
    )

    main._install_desktop()

    assert legacy.is_file()
    assert not (applications / _TERMINAL_LAUNCHER).exists()
    assert "No supported terminal emulator found" in capsys.readouterr().out


def test_a_packaged_build_writes_nothing_and_points_at_the_earlier_launcher(
    applications: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "servonaut.runtime.detect_runtime",
        lambda: _runtime(DistributionKind.PACKAGED_DESKTOP),
    )
    legacy = applications / "servonaut.desktop"
    legacy.write_text(
        _legacy_launcher("gnome-terminal --  /usr/local/bin/servonaut"), encoding="utf-8"
    )

    main._install_desktop()

    output = capsys.readouterr().out
    assert "already provides its GUI launcher" in output
    assert f"An older Servonaut terminal shortcut is at {legacy}" in output
    assert [entry.name for entry in applications.iterdir()] == ["servonaut.desktop"]


# macOS


def test_the_macos_shortcut_is_named_apart_from_the_desktop_app(
    mac_applications: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main._install_desktop()

    bundle = mac_applications / _TERMINAL_BUNDLE
    info = plistlib.loads((bundle / "Contents" / "Info.plist").read_bytes())
    desktop_app = _macos_app_defaults()
    assert desktop_app == {"bundle_name": "Servonaut.app", "bundle_id": "dev.servonaut.desktop"}
    assert bundle.name != desktop_app["bundle_name"]
    assert info["CFBundleIdentifier"] == "dev.servonaut.terminal"
    assert info["CFBundleIdentifier"] != desktop_app["bundle_id"]
    assert info["CFBundleName"] == info["CFBundleDisplayName"] == "Servonaut Terminal"
    assert info["CFBundlePackageType"] == "APPL"
    executable = bundle / "Contents" / "MacOS" / info["CFBundleExecutable"]
    assert os.access(executable, os.X_OK)
    assert [entry.name for entry in mac_applications.iterdir()] == [_TERMINAL_BUNDLE]
    assert "Servonaut Terminal should now appear" in capsys.readouterr().out


@pytest.mark.parametrize("with_helper", [False, True], ids=["first-version", "command-helper"])
def test_a_shortcut_an_earlier_version_wrote_is_replaced(
    mac_applications: Path, capsys: pytest.CaptureFixture[str], with_helper: bool
) -> None:
    legacy = _legacy_bundle(mac_applications, with_helper=with_helper)

    main._install_desktop()

    assert not legacy.exists()
    assert (mac_applications / _TERMINAL_BUNDLE).is_dir()
    assert f"Removed the previous terminal shortcut {legacy}" in capsys.readouterr().out


def _desktop_app_bundle(directory: Path) -> Path:
    bundle = directory / "Servonaut.app"
    (bundle / "Contents" / "MacOS").mkdir(parents=True)
    (bundle / "Contents" / "Resources").mkdir()
    (bundle / "Contents" / "MacOS" / "servonaut-desktop").write_bytes(b"\x7fELF")
    (bundle / "Contents" / "Resources" / "AppIcon.icns").write_bytes(b"icns")
    info = {
        "CFBundleIdentifier": "dev.servonaut.desktop",
        "CFBundleExecutable": "servonaut-desktop",
    }
    (bundle / "Contents" / "Info.plist").write_bytes(plistlib.dumps(info))
    return bundle


def _with_an_icon(directory: Path) -> Path:
    bundle = _legacy_bundle(directory)
    (bundle / "Contents" / "Resources").mkdir()
    (bundle / "Contents" / "Resources" / "AppIcon.icns").write_bytes(b"icns")
    return bundle


def _with_a_linked_helper(directory: Path) -> Path:
    bundle = _legacy_bundle(directory)
    helper = bundle / "Contents" / "MacOS" / "Servonaut.command"
    helper.unlink()
    helper.symlink_to("/bin/sh")
    return bundle


@pytest.mark.parametrize(
    "make_bundle",
    [
        _desktop_app_bundle,
        _with_an_icon,
        _with_a_linked_helper,
        lambda directory: _legacy_bundle(directory, identifier="com.example.servonaut"),
    ],
    ids=["desktop-app", "extra-file", "linked-file", "other-identifier"],
)
def test_a_bundle_it_did_not_write_is_kept(
    mac_applications: Path, capsys: pytest.CaptureFixture[str], make_bundle
) -> None:
    bundle = make_bundle(mac_applications)
    before = _tree(bundle)

    main._install_desktop()

    assert _tree(bundle) == before
    assert f"Left {bundle} unchanged" in capsys.readouterr().out


def test_a_linked_bundle_is_kept(mac_applications: Path, tmp_path: Path) -> None:
    target = _legacy_bundle(tmp_path)
    before = _tree(target)
    legacy = mac_applications / "Servonaut.app"
    legacy.symlink_to(target, target_is_directory=True)

    main._install_desktop()

    assert legacy.is_symlink()
    assert _tree(target) == before
