"""Native Windows filesystem contracts for standalone payload snapshots."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest
from test_standalone_artifact_filesystem import _LIMITS, _NOTICE_POLICIES, _artifact

from scripts.standalone_cli import artifact_filesystem
from scripts.standalone_cli.artifact_filesystem import snapshot_payload
from scripts.standalone_cli.artifact_types import ArtifactEvidenceError

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="native Windows filesystem contract"
)


@pytest.fixture(autouse=True)
def _trusted_notice_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        artifact_filesystem,
        "load_embedded_notice_policy",
        lambda _path, _limit: _NOTICE_POLICIES,
    )


def test_native_windows_path_stat_supplies_link_count_for_complete_snapshot(
    tmp_path: Path,
) -> None:
    artifact = _artifact(tmp_path, target_name="windows-x64")
    with os.scandir(artifact.payload_root) as children:
        executable = next(child for child in children if child.name == "servonaut.exe")
        scan_status = executable.stat(follow_symlinks=False)
    path_status = os.stat(artifact.executable, follow_symlinks=False)

    snapshot = snapshot_payload(artifact, _LIMITS)

    assert scan_status.st_nlink == 0
    assert path_status.st_nlink == 1
    assert snapshot.executable_relative_path == PurePosixPath("servonaut.exe")


def test_native_windows_path_stat_still_rejects_a_real_hard_link(
    tmp_path: Path,
) -> None:
    artifact = _artifact(tmp_path, target_name="windows-x64")
    source = artifact.payload_root / "_internal" / "base.bin"
    os.link(source, artifact.payload_root / "_internal" / "duplicate.bin")

    with pytest.raises(ArtifactEvidenceError, match="hard-linked"):
        snapshot_payload(artifact, _LIMITS)


def test_native_windows_rejects_an_owned_junction_before_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = _artifact(tmp_path, target_name="windows-x64")
    outside = tmp_path / "owned-foreign-directory"
    outside.mkdir()
    outside_file = outside / "outside.bin"
    outside_file.write_bytes(b"outside")
    junction = artifact.payload_root / "junction"
    command = os.environ.get("COMSPEC")
    if not command or not Path(command).is_absolute() or not Path(command).is_file():
        pytest.skip("the native command interpreter is unavailable")
    try:
        completed = subprocess.run(
            [command, "/d", "/c", "mklink", "/J", str(junction), str(outside)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        if completed.returncode != 0:
            pytest.fail("owned junction creation failed")
        if not os.path.isjunction(junction):
            pytest.fail("owned junction was not created")
        real_scandir = os.scandir
        scanned: list[Path] = []

        def tracking_scandir(path: Path) -> os.ScandirIterator[str]:
            scanned.append(Path(path))
            return real_scandir(path)

        monkeypatch.setattr(artifact_filesystem.os, "scandir", tracking_scandir)
        with pytest.raises(ArtifactEvidenceError, match="reparse"):
            snapshot_payload(artifact, _LIMITS)
        assert junction not in scanned
        assert outside_file.read_bytes() == b"outside"
    finally:
        if os.path.isjunction(junction):
            junction.rmdir()
