"""Tests for the macOS desktop app's ``~/.local/bin/servonaut`` link."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from servonaut import cli_link
from servonaut.cli_link import CliLinkState, ensure_cli_link, is_app_bundle_command
from servonaut.runtime import DistributionKind


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return home


@pytest.fixture
def on_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("servonaut.utils.platform_utils.get_os", lambda: "darwin")
    monkeypatch.setattr(cli_link, "validate_launch_argv", lambda argv, runtime: list(argv))


def _app(root: Path) -> Path:
    """The command line inside an installed app bundle."""
    command = root / "Servonaut.app" / "Contents" / "MacOS" / "servonaut"
    command.parent.mkdir(parents=True)
    command.write_text("#!/bin/sh\n", encoding="utf-8")
    command.chmod(0o755)
    return command


def _desktop(command: Path | str) -> SimpleNamespace:
    return SimpleNamespace(
        kind=DistributionKind.PACKAGED_DESKTOP, current_app_argv=lambda: [str(command)]
    )


def _link(home: Path) -> Path:
    return home / ".local" / "bin" / "servonaut"


def test_the_command_is_linked_when_nothing_is_there(
    home: Path, tmp_path: Path, on_macos: None
) -> None:
    app = _app(tmp_path / "Applications")

    result = ensure_cli_link(_desktop(app))

    assert result is not None
    assert result.state is CliLinkState.CREATED
    assert os.readlink(_link(home)) == str(app)


def test_a_link_to_this_app_is_left_unchanged(
    home: Path, tmp_path: Path, on_macos: None
) -> None:
    app = _app(tmp_path / "Applications")
    ensure_cli_link(_desktop(app))

    result = ensure_cli_link(_desktop(app))

    assert result is not None
    assert result.state is CliLinkState.UNCHANGED


def test_its_own_link_follows_the_app_when_it_moves(
    home: Path, tmp_path: Path, on_macos: None
) -> None:
    old = _app(tmp_path / "old")
    ensure_cli_link(_desktop(old))
    new = _app(tmp_path / "Applications")

    result = ensure_cli_link(_desktop(new))

    assert result is not None
    assert result.state is CliLinkState.UPDATED
    assert os.readlink(_link(home)) == str(new)


def test_a_dangling_link_is_replaced(home: Path, tmp_path: Path, on_macos: None) -> None:
    link = _link(home)
    link.parent.mkdir(parents=True)
    link.symlink_to(tmp_path / "pipx" / "venvs" / "servonaut" / "bin" / "servonaut")
    app = _app(tmp_path / "Applications")

    result = ensure_cli_link(_desktop(app))

    assert result is not None
    assert result.state is CliLinkState.UPDATED
    assert os.readlink(link) == str(app)


def test_a_working_link_of_another_install_is_left_alone(
    home: Path, tmp_path: Path, on_macos: None
) -> None:
    pipx_console = tmp_path / "pipx" / "venvs" / "servonaut" / "bin" / "servonaut"
    pipx_console.parent.mkdir(parents=True)
    pipx_console.write_text("#!/bin/sh\n", encoding="utf-8")
    link = _link(home)
    link.parent.mkdir(parents=True)
    link.symlink_to(pipx_console)

    result = ensure_cli_link(_desktop(_app(tmp_path / "Applications")))

    assert result is not None
    assert result.state is CliLinkState.OCCUPIED
    assert result.holder == str(pipx_console)
    assert os.readlink(link) == str(pipx_console)


def test_a_file_in_the_way_is_left_alone(home: Path, tmp_path: Path, on_macos: None) -> None:
    script = _link(home)
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\nexec somewhere-else \"$@\"\n", encoding="utf-8")

    result = ensure_cli_link(_desktop(_app(tmp_path / "Applications")))

    assert result is not None
    assert result.state is CliLinkState.OCCUPIED
    assert not script.is_symlink()
    assert "somewhere-else" in script.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "location",
    [
        "/private/var/folders/x/T/AppTranslocation/ABC/d/Servonaut.app/Contents/MacOS/servonaut",
        "/Volumes/Servonaut/Servonaut.app/Contents/MacOS/servonaut",
    ],
    ids=["translocated", "disk-image"],
)
def test_an_app_that_will_not_stay_there_is_not_linked(
    home: Path, on_macos: None, location: str
) -> None:
    result = ensure_cli_link(_desktop(location))

    assert result is not None
    assert result.state is CliLinkState.SKIPPED
    assert "Applications folder" in result.detail
    assert not _link(home).is_symlink()


def test_a_link_that_cannot_be_made_is_reported(
    home: Path, tmp_path: Path, on_macos: None
) -> None:
    # ~/.local is a file, so ~/.local/bin cannot be created.
    (home / ".local").write_text("", encoding="utf-8")

    result = ensure_cli_link(_desktop(_app(tmp_path / "Applications")))

    assert result is not None
    assert result.state is CliLinkState.FAILED
    assert result.detail


def test_only_the_macos_app_is_linked(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, on_macos: None
) -> None:
    app = _app(tmp_path / "Applications")
    pipx = SimpleNamespace(kind=DistributionKind.PIPX, current_app_argv=lambda: [str(app)])
    assert ensure_cli_link(pipx) is None

    monkeypatch.setattr("servonaut.utils.platform_utils.get_os", lambda: "linux")
    assert ensure_cli_link(_desktop(app)) is None
    assert not _link(home).is_symlink()


def test_app_bundle_commands_are_recognised() -> None:
    assert is_app_bundle_command("/Applications/Servonaut.app/Contents/MacOS/servonaut")
    assert is_app_bundle_command("../../Apps/Servonaut Preview.app/Contents/MacOS/servonaut")
    assert not is_app_bundle_command("/opt/pipx/venvs/servonaut/bin/servonaut")
    assert not is_app_bundle_command("/Applications/Other.app/Contents/MacOS/other")
