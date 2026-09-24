"""Tests for UpdateService's post-upgrade installed-version probe."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)
from servonaut.services.update_service import UpdateService

_PIPX = Path("/usr/bin/pipx")


def _pipx_runtime(tmp_path: Path, version: str = "2.26.3") -> RuntimeLayout:
    return RuntimeLayout(
        kind=DistributionKind.PIPX,
        product_version=version,
        build_revision=None,
        resource_root=tmp_path / "resources",
        executable_root=tmp_path / "bin",
        data_root=tmp_path / "data",
        executable=tmp_path / "bin" / "python",
        python_executable=tmp_path / "bin" / "python",
        path_console=None,
        console_helper=None,
        desktop_child=None,
        package_management=PackageManagementCapability(
            kind=PackageManagementKind.PIPX,
            argv_prefix=(str(_PIPX),),
            allows_automatic_mutation=True,
        ),
        is_frozen=False,
    )


def _pipx_list(*rows: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        [str(_PIPX), "list", "--short"], 0, stdout="".join(f"{row}\n" for row in rows), stderr=""
    )


def _finished_process(returncode: int = 0) -> MagicMock:
    process = MagicMock()
    process.returncode = returncode
    process.communicate = AsyncMock(return_value=(b"upgraded package servonaut", b""))
    return process


def test_pipx_version_is_found_after_packages_that_sort_first(tmp_path: Path) -> None:
    service = UpdateService(_pipx_runtime(tmp_path))
    listing = _pipx_list("black 24.1.0", "httpie 3.2.2", "servonaut 2.27.0", "tox 4.0.0")

    with patch("subprocess.run", return_value=listing) as run:
        assert service.installed_version_external() == "2.27.0"

    run.assert_called_once()
    assert run.call_args.args[0] == [str(_PIPX), "list", "--short"]


def test_pipx_listing_without_servonaut_reports_unknown(tmp_path: Path) -> None:
    service = UpdateService(_pipx_runtime(tmp_path))

    with patch("subprocess.run", return_value=_pipx_list("black 24.1.0", "httpie 3.2.2")) as run:
        assert service.installed_version_external() is None

    run.assert_called_once()


def test_pipx_upgrade_verifies_the_new_version_end_to_end(tmp_path: Path) -> None:
    service = UpdateService(_pipx_runtime(tmp_path))
    service._latest = "2.27.0"
    listings = [
        _pipx_list("black 24.1.0", "servonaut 2.26.3"),
        _pipx_list("black 24.1.0", "servonaut 2.27.0"),
    ]

    with patch("subprocess.run", side_effect=listings), patch(
        "asyncio.create_subprocess_exec",
        new_callable=AsyncMock,
        return_value=_finished_process(),
    ) as spawn:
        ok, message = asyncio.run(service.run_upgrade())

    assert ok is True
    assert "v2.26.3" in message and "v2.27.0" in message
    assert spawn.call_args.args == (str(_PIPX), "upgrade", "servonaut")
