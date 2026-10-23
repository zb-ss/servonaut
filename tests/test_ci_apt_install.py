"""Behaviour of the CI helper that installs Ubuntu packages behind a mirror fallback.

The helper runs here against stub ``sudo``, ``timeout`` and ``apt-get``
commands that log their calls, and a stub ``timeout`` that can play a slow
mirror for a number of download attempts.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "apt-install.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "desktop-probe.yml"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required")

_STUBS = {
    "sudo": 'exec "$@"\n',
    "apt-get": 'echo "apt-get $*" >> "$STUB_LOG"\n',
    # timeout --kill-after=10 LIMIT COMMAND...
    "timeout": (
        "shift\n"
        'limit="$1"\n'
        "shift\n"
        'echo "timeout $limit $*" >> "$STUB_LOG"\n'
        'case "$*" in\n'
        "  *--download-only*)\n"
        '    slow=$(cat "$STUB_SLOW")\n'
        '    if [ "$slow" -gt 0 ]; then echo $((slow - 1)) > "$STUB_SLOW"; exit 124; fi\n'
        "    ;;\n"
        "esac\n"
        'exec "$@"\n'
    ),
}

_AZURE_LIST = "deb http://azure.archive.ubuntu.com/ubuntu jammy main universe\n"
_AZURE_SOURCES = "Types: deb\nURIs: http://azure.archive.ubuntu.com/ubuntu/\nSuites: noble\n"
_OTHER_LIST = "deb https://packages.microsoft.com/ubuntu/22.04/prod jammy main\n"


def _run(tmp_path: Path, *packages: str, slow_attempts: int = 0):
    stubs = tmp_path / "bin"
    stubs.mkdir()
    for name, body in _STUBS.items():
        stub = stubs / name
        stub.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        stub.chmod(0o755)
    apt_dir = tmp_path / "apt"
    (apt_dir / "sources.list.d").mkdir(parents=True)
    (apt_dir / "sources.list").write_text(_AZURE_LIST, encoding="utf-8")
    (apt_dir / "sources.list.d" / "ubuntu.sources").write_text(_AZURE_SOURCES, encoding="utf-8")
    (apt_dir / "sources.list.d" / "microsoft-prod.list").write_text(_OTHER_LIST, encoding="utf-8")
    log = tmp_path / "calls.log"
    log.touch()
    slow = tmp_path / "slow"
    slow.write_text(str(slow_attempts), encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}",
        "APT_DIR": str(apt_dir),
        "STUB_LOG": str(log),
        "STUB_SLOW": str(slow),
    }
    env.pop("APT_ATTEMPT_SECONDS", None)
    result = subprocess.run(
        ["bash", str(SCRIPT), *packages], env=env, capture_output=True, text=True
    )
    return result, log.read_text(encoding="utf-8").splitlines(), apt_dir


def _sources(apt_dir: Path) -> tuple[str, str, str]:
    return (
        (apt_dir / "sources.list").read_text(encoding="utf-8"),
        (apt_dir / "sources.list.d" / "ubuntu.sources").read_text(encoding="utf-8"),
        (apt_dir / "sources.list.d" / "microsoft-prod.list").read_text(encoding="utf-8"),
    )


def test_a_healthy_mirror_downloads_once_then_installs(tmp_path: Path) -> None:
    result, calls, apt_dir = _run(tmp_path, "xvfb", "xauth")

    assert result.returncode == 0, result.stderr
    assert [call for call in calls if call.startswith("timeout")] == [
        "timeout 120 apt-get update -q",
        "timeout 120 apt-get install -y -q --download-only xvfb xauth",
    ]
    # The install itself, where dpkg runs, is never under a time limit.
    assert calls[-1] == "apt-get install -y -q xvfb xauth"
    assert calls.count("apt-get install -y -q xvfb xauth") == 1
    assert _sources(apt_dir) == (_AZURE_LIST, _AZURE_SOURCES, _OTHER_LIST)
    assert "::warning::" not in result.stdout


def test_a_slow_mirror_is_replaced_by_the_main_archive(tmp_path: Path) -> None:
    result, calls, apt_dir = _run(tmp_path, "xvfb", slow_attempts=1)

    assert result.returncode == 0, result.stderr
    assert [call for call in calls if call.startswith("timeout")] == [
        "timeout 120 apt-get update -q",
        "timeout 120 apt-get install -y -q --download-only xvfb",
        "timeout 120 apt-get update -q",
        "timeout 120 apt-get install -y -q --download-only xvfb",
    ]
    assert calls[-1] == "apt-get install -y -q xvfb"
    sources_list, ubuntu_sources, other_list = _sources(apt_dir)
    assert sources_list == "deb http://archive.ubuntu.com/ubuntu/ jammy main universe\n"
    assert "URIs: http://archive.ubuntu.com/ubuntu/\n" in ubuntu_sources
    assert other_list == _OTHER_LIST
    assert "::warning::The Ubuntu mirror did not deliver within 120s" in result.stdout


def test_a_last_attempt_has_no_time_limit(tmp_path: Path) -> None:
    result, calls, _ = _run(
        tmp_path, "--no-install-recommends", "libwoff1", slow_attempts=2
    )

    assert result.returncode == 0, result.stderr
    downloads = [call for call in calls if call.startswith("timeout") and "--download-only" in call]
    assert downloads == [
        "timeout 120 apt-get install -y -q --download-only --no-install-recommends libwoff1",
        "timeout 120 apt-get install -y -q --download-only --no-install-recommends libwoff1",
        "timeout 0 apt-get install -y -q --download-only --no-install-recommends libwoff1",
    ]
    assert calls[-1] == "apt-get install -y -q --no-install-recommends libwoff1"
    assert "retrying without a time limit" in result.stdout


def test_nothing_is_installed_when_every_download_fails(tmp_path: Path) -> None:
    result, calls, _ = _run(tmp_path, "xvfb", slow_attempts=3)

    assert result.returncode != 0
    assert "apt-get install -y -q xvfb" not in calls


def test_the_desktop_probe_installs_linux_packages_through_the_helper() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    assert "sudo apt-get" not in source
    assert source.count(".github/scripts/apt-install.sh python3-venv") == 1
    assert source.count(".github/scripts/apt-install.sh --no-install-recommends $missing") == 1
    # A change to the helper runs the workflow on pushes and pull requests.
    assert source.count("      - '.github/scripts/apt-install.sh'\n") == 2
