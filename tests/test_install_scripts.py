"""Contract tests for the install scripts, install.sh and install.ps1.

The scripts run for real against stand-ins for pipx, Python and git: they
install Servonaut from PyPI only, show pipx's error when that fails, and
never fetch the repository's unreleased source instead.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "install.sh"
INSTALL_PS1 = ROOT / "install.ps1"
TROUBLESHOOTING = ROOT / "docs" / "troubleshooting.md"
TROUBLESHOOTING_HEADING = "## The Install Script Stops\n"
TROUBLESHOOTING_URL = (
    "https://github.com/zb-ss/servonaut/blob/master/docs/troubleshooting.md"
    "#the-install-script-stops"
)
PIPX_ERROR = "stand-in pipx: could not reach the package index"

needs_posix_shell = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None,
    reason="Runs the POSIX installer with shell stand-ins",
)
needs_pwsh = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("pwsh") is None,
    reason="Runs the PowerShell installer with shell stand-ins (needs PowerShell 7)",
)


def _stand_ins(tmp_path: Path, pipx_exit: int) -> Path:
    """pipx, python3 and git stand-ins that record how they were called."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    scripts = {
        "pipx": f"""#!/bin/sh
echo "pipx $*" >> "{log}"
case "$1" in
  --version) echo "1.8.0"; exit 0 ;;
  list) echo "servonaut 1.0.0"; exit 0 ;;
  ensurepath) exit 0 ;;
esac
if [ {pipx_exit} -ne 0 ]; then
  echo "{PIPX_ERROR}" >&2
fi
exit {pipx_exit}
""",
        "python3": """#!/bin/sh
echo "3.12"
""",
        "git": f"""#!/bin/sh
echo "git $*" >> "{log}"
exit 97
""",
    }
    for name, body in scripts.items():
        path = bin_dir / name
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)
    return bin_dir


def _calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "calls.log"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def _environment(tmp_path: Path, bin_dir: Path, **extra: str) -> dict[str, str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return {
        "HOME": str(home),
        "PATH": f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin",
        "TERM": "dumb",
        **extra,
    }


def _run_install_sh(
    tmp_path: Path, *args: str, pipx_exit: int = 0, **env: str
) -> subprocess.CompletedProcess[str]:
    """Run install.sh as `curl ... | bash -s -- ARGS` does, outside a checkout."""
    bin_dir = _stand_ins(tmp_path, pipx_exit)
    work = tmp_path / "work"
    work.mkdir()
    return subprocess.run(
        ["bash", "-s", "--", *args],
        input=INSTALL_SH.read_text(encoding="utf-8"),
        cwd=work,
        text=True,
        capture_output=True,
        check=False,
        env=_environment(tmp_path, bin_dir, **env),
        # No controlling terminal, so the setup wizard's questions answer no.
        start_new_session=True,
        timeout=30,
    )


def _run_install_ps1(
    tmp_path: Path, *args: str, pipx_exit: int = 0
) -> subprocess.CompletedProcess[str]:
    bin_dir = _stand_ins(tmp_path, pipx_exit)
    work = tmp_path / "work"
    work.mkdir()
    return subprocess.run(
        [shutil.which("pwsh"), "-NoProfile", "-File", str(INSTALL_PS1), *args],
        input="n\n",
        cwd=work,
        text=True,
        capture_output=True,
        check=False,
        env=_environment(tmp_path, bin_dir),
        timeout=60,
    )


# ---------------------------------------------------------------------------
# What the scripts contain
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("script", [INSTALL_SH, INSTALL_PS1], ids=lambda path: path.name)
def test_the_scripts_never_fetch_the_repository(script: Path) -> None:
    source = script.read_text(encoding="utf-8")

    assert not re.search(r"\bgit\b", source)
    assert "raw.githubusercontent.com" not in source


def test_the_pypi_install_output_is_not_hidden() -> None:
    sh = INSTALL_SH.read_text(encoding="utf-8")
    ps1 = INSTALL_PS1.read_text(encoding="utf-8")

    assert "    if pipx install servonaut; then\n" in sh
    assert "    & pipx install servonaut\n" in ps1


@pytest.mark.parametrize("script", [INSTALL_SH, INSTALL_PS1], ids=lambda path: path.name)
def test_the_failure_message_points_at_troubleshooting(script: Path) -> None:
    # The scripts build the link from the repository URL; the runs below
    # check the whole link as printed.
    anchor = TROUBLESHOOTING_URL.removeprefix("https://github.com/zb-ss/servonaut")
    assert f'{anchor}"\n' in script.read_text(encoding="utf-8")
    assert TROUBLESHOOTING_HEADING in TROUBLESHOOTING.read_text(encoding="utf-8")


def test_install_ps1_is_ascii() -> None:
    """Release assets are served without a charset, and Windows PowerShell
    then decodes them as ISO-8859-1, so anything but ASCII would be garbled."""
    INSTALL_PS1.read_bytes().decode("ascii")


# ---------------------------------------------------------------------------
# install.sh, executed
# ---------------------------------------------------------------------------


@needs_posix_shell
def test_install_sh_installs_the_stable_release_from_pypi(tmp_path: Path) -> None:
    result = _run_install_sh(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "pipx install servonaut" in _calls(tmp_path)
    assert not [call for call in _calls(tmp_path) if call.startswith("git")]
    assert "Servonaut installed successfully from PyPI" in result.stdout


@needs_posix_shell
def test_install_sh_stops_with_pipx_error_when_pypi_fails(tmp_path: Path) -> None:
    result = _run_install_sh(tmp_path, pipx_exit=1)

    assert result.returncode == 1
    # pipx's own error reaches the user, and nothing else is tried.
    assert PIPX_ERROR in result.stderr
    assert "Could not install Servonaut from PyPI" in result.stderr
    assert "  pipx install servonaut\n" in result.stdout
    assert f"Troubleshooting: {TROUBLESHOOTING_URL}\n" in result.stdout
    assert "Installation Complete" not in result.stdout
    calls = _calls(tmp_path)
    assert [call for call in calls if call.startswith("pipx install")] == [
        "pipx install servonaut"
    ]
    assert not [call for call in calls if call.startswith("git")]


@needs_posix_shell
@pytest.mark.parametrize(
    "args,env",
    [(("--pre",), {}), ((), {"SERVONAUT_PRE": "1"})],
    ids=["option", "environment"],
)
def test_install_sh_installs_a_release_candidate_on_request(
    tmp_path: Path, args: tuple[str, ...], env: dict[str, str]
) -> None:
    result = _run_install_sh(tmp_path, *args, **env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "pipx install --force servonaut>=0rc0" in _calls(tmp_path)
    assert "pipx install servonaut" not in _calls(tmp_path)


# ---------------------------------------------------------------------------
# install.ps1, executed
# ---------------------------------------------------------------------------


@needs_pwsh
def test_install_ps1_installs_the_stable_release_from_pypi(tmp_path: Path) -> None:
    result = _run_install_ps1(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "pipx install servonaut" in _calls(tmp_path)
    assert not [call for call in _calls(tmp_path) if call.startswith("git")]


@needs_pwsh
def test_install_ps1_stops_with_pipx_error_when_pypi_fails(tmp_path: Path) -> None:
    result = _run_install_ps1(tmp_path, pipx_exit=1)
    output = result.stdout + result.stderr

    assert result.returncode == 1
    assert PIPX_ERROR in output
    assert "Could not install Servonaut from PyPI" in output
    assert f"Troubleshooting: {TROUBLESHOOTING_URL}" in output
    assert "Installation Complete" not in output
    calls = _calls(tmp_path)
    assert [call for call in calls if call.startswith("pipx install")] == [
        "pipx install servonaut"
    ]
    assert not [call for call in calls if call.startswith("git")]


@needs_pwsh
def test_install_ps1_installs_a_release_candidate_on_request(tmp_path: Path) -> None:
    result = _run_install_ps1(tmp_path, "-Pre")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "pipx install --force servonaut>=0rc0" in _calls(tmp_path)
