"""Boundary coverage for lstat-only standalone artifact snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import zipfile
from pathlib import Path

import pytest

from scripts.standalone_cli.artifact_filesystem import snapshot_payload
from scripts.standalone_cli.artifact_types import (
    ArtifactDescriptor,
    ArtifactEvidenceError,
)
from scripts.standalone_cli.evidence_policy_types import EvidenceLimits
from scripts.standalone_cli.model import load_target_spec

_POLICY = (
    Path(__file__).parents[2] / "packaging" / "standalone_cli" / "target-policy.json"
)
_LIMITS = EvidenceLimits(
    1024 * 1024,
    1000,
    1024 * 1024,
    8 * 1024 * 1024,
    30,
    1024 * 1024,
)


def test_snapshot_records_sorted_entries_and_preserves_relative_link_target(
    tmp_path: Path,
) -> None:
    artifact = _artifact(tmp_path)
    os.symlink("base.bin", artifact.payload_root / "_internal" / "runtime.bin")

    snapshot = snapshot_payload(artifact, _LIMITS)

    paths = [entry.relative_path.as_posix() for entry in snapshot.entries]
    assert paths == sorted(paths)
    link = next(entry for entry in snapshot.entries if entry.kind == "symlink")
    assert link.relative_path.as_posix() == "_internal/runtime.bin"
    assert link.link_target == "base.bin"
    assert snapshot.executable_relative_path.as_posix() == "servonaut"


@pytest.mark.parametrize("target", ("../outside", "/outside", "missing", "runtime.bin"))
def test_snapshot_rejects_unsafe_or_dangling_symbolic_links(
    tmp_path: Path, target: str
) -> None:
    artifact = _artifact(tmp_path)
    link = artifact.payload_root / "_internal" / "runtime.bin"
    if target == "runtime.bin":
        os.symlink("loop-b", link)
        os.symlink("runtime.bin", artifact.payload_root / "_internal" / "loop-b")
    else:
        os.symlink(target, link)

    with pytest.raises(ArtifactEvidenceError):
        snapshot_payload(artifact, _LIMITS)


def test_snapshot_rejects_hard_linked_regular_files(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    source = artifact.payload_root / "_internal" / "base.bin"
    os.link(source, artifact.payload_root / "_internal" / "duplicate.bin")

    with pytest.raises(ArtifactEvidenceError, match="hard-linked"):
        snapshot_payload(artifact, _LIMITS)


def test_snapshot_rejects_marker_and_provenance_mismatches(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    provenance = artifact.build_metadata_dir / "resolved" / "build-provenance.json"
    payload = json.loads(provenance.read_text(encoding="utf-8"))
    payload["target"] = "windows-x64"
    provenance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ArtifactEvidenceError, match="target"):
        snapshot_payload(artifact, _LIMITS)


def test_snapshot_rejects_invalid_build_toolchain(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    toolchain = artifact.build_metadata_dir / "resolved" / "build-toolchain.json"
    payload = json.loads(toolchain.read_text(encoding="utf-8"))
    payload["python_version"] = "3.11.0"
    toolchain.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ArtifactEvidenceError, match="Python version"):
        snapshot_payload(artifact, _LIMITS)


def test_snapshot_normalizes_deep_json_recursion_error(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    marker = artifact.payload_root / "servonaut-runtime.json"
    marker.write_text(
        ("{\"n\":" * 100_000) + "0" + ("}" * 100_000),
        encoding="utf-8",
    )

    assert marker.stat().st_size < _LIMITS.max_metadata_file_bytes
    with pytest.raises(ArtifactEvidenceError, match="runtime marker is not valid JSON"):
        snapshot_payload(artifact, _LIMITS)


def test_snapshot_rejects_windows_links(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path, target_name="windows-x64")
    os.symlink("base.bin", artifact.payload_root / "_internal" / "runtime.bin")

    with pytest.raises(ArtifactEvidenceError, match="Windows"):
        snapshot_payload(artifact, _LIMITS)


def _artifact(
    tmp_path: Path, target_name: str = "linux-x64-ubuntu-22.04"
) -> ArtifactDescriptor:
    target = load_target_spec(_POLICY, target_name)
    payload = tmp_path / "payload"
    internal = payload / "_internal"
    internal.mkdir(parents=True)
    executable = payload / (
        "servonaut.exe" if target.platform == "win32" else "servonaut"
    )
    executable.write_bytes(b"executable")
    executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    (internal / "base.bin").write_bytes(b"runtime")
    wheel = tmp_path / "servonaut-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "servonaut-1.2.3.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: servonaut\nVersion: 1.2.3\n",
        )
    marker = {
        "schema_version": 1,
        "distribution": "frozen-cli",
        "product_version": "1.2.3",
        "build_revision": "build-1",
        "console_helper": executable.name,
        "desktop_child": None,
    }
    (payload / "servonaut-runtime.json").write_text(
        json.dumps(marker), encoding="utf-8"
    )
    metadata = tmp_path / "build-metadata"
    pyinstaller = metadata / "pyinstaller"
    resolved = metadata / "resolved"
    pyinstaller.mkdir(parents=True)
    resolved.mkdir()
    warning = pyinstaller / "warn-servonaut.txt"
    warning.write_text("", encoding="utf-8")
    (pyinstaller / "Analysis-00.toc").write_text("[]", encoding="utf-8")
    (pyinstaller / "PYZ-00.toc").write_text("[]", encoding="utf-8")
    (resolved / "environment.json").write_text("{}", encoding="utf-8")
    (resolved / "licenses.json").write_text("{}", encoding="utf-8")
    (resolved / "sbom-python.cdx.json").write_text("{}", encoding="utf-8")
    (resolved / "build-provenance.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_commit": "abc1234",
                "target": target.name,
                "product_version": "1.2.3",
                "build_revision": "build-1",
                "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    (resolved / "build-toolchain.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "python_implementation": "CPython",
                "python_version": "3.12.0",
                "spec_sha256": "a" * 64,
                "hooks_sha256": "b" * 64,
            }
        ),
        encoding="utf-8",
    )
    return ArtifactDescriptor(
        payload, executable, None, target, wheel, warning, metadata
    )
