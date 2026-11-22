"""Tests for the ``servonaut --update`` command across distributions."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from servonaut import main
from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)
from servonaut.services.update_service import UpdateService


def _frozen_runtime(tmp_path: Path) -> RuntimeLayout:
    return RuntimeLayout(
        kind=DistributionKind.FROZEN_CLI,
        product_version="2.26.3",
        build_revision=None,
        resource_root=tmp_path,
        executable_root=tmp_path,
        data_root=tmp_path / "data",
        executable=tmp_path / "servonaut",
        python_executable=None,
        path_console=None,
        console_helper=tmp_path / "servonaut",
        desktop_child=None,
        package_management=PackageManagementCapability(PackageManagementKind.UNSUPPORTED, (), False),
        is_frozen=True,
    )


@pytest.fixture
def frozen_update(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: _frozen_runtime(tmp_path))
    monkeypatch.setattr(UpdateService, "check_for_update", lambda _self: "2.27.0")

    def install(result: tuple[bool, str]) -> AsyncMock:
        run_upgrade = AsyncMock(return_value=result)
        monkeypatch.setattr(UpdateService, "run_upgrade", run_upgrade)
        return run_upgrade

    return install


def test_frozen_update_runs_the_verified_download(frozen_update, capsys) -> None:
    run_upgrade = frozen_update((True, "Downloaded verified update to /downloads/servonaut.tar.gz."))

    main._run_update()

    run_upgrade.assert_awaited_once()
    output = capsys.readouterr().out
    assert "New version available: 2.27.0" in output
    assert "Downloaded verified update" in output
    assert "not configured" not in output


def test_frozen_update_exits_nonzero_when_the_download_fails(frozen_update, capsys) -> None:
    frozen_update((False, "The update could not be downloaded."))

    with pytest.raises(SystemExit) as exit_info:
        main._run_update()

    assert exit_info.value.code == 1
    assert "could not be downloaded" in capsys.readouterr().out


def test_update_logs_a_failed_check_to_the_file_not_stderr(tmp_path: Path) -> None:
    # Scripts and the packaged smoke test read --update's stdout and require an
    # empty stderr; the cause of the failure is still in the log file.
    import os
    import subprocess
    import sys

    home = tmp_path / "home"
    home.mkdir()
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("SERVONAUT_", "PIPX_", "VIRTUAL_ENV"))
    }
    env.update({
        "HOME": str(home),
        "USERPROFILE": str(home),
        "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src"),
        # Nothing listens on port 9, so the request really fails.
        "SERVONAUT_PYPI_URL": "https://127.0.0.1:9/pypi/servonaut/json",
    })
    result = subprocess.run(
        [sys.executable, "-m", "servonaut.main", "--update"],
        env=env, cwd=tmp_path, capture_output=True, text=True, timeout=120,
    )
    assert result.stderr == ""
    assert "Could not" in result.stdout
    log = (home / ".servonaut" / "logs" / "servonaut.log").read_text(encoding="utf-8")
    assert "Version check via SERVONAUT_PYPI_URL failed" in log
