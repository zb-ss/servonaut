"""Boundary coverage for lstat-only standalone artifact snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import zipfile
from pathlib import Path, PurePosixPath

import pytest

from scripts.standalone_cli import artifact_filesystem
from scripts.standalone_cli.artifact_filesystem import (
    SnapshotPathResolver,
    snapshot_payload,
)
from scripts.standalone_cli.artifact_types import (
    ArtifactDescriptor,
    ArtifactEvidenceError,
    PayloadEntry,
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
        ('{"n":' * 100_000) + "0" + ("}" * 100_000),
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


def test_snapshot_rejects_declared_executable_alias(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    artifact.executable.unlink()
    os.symlink("_internal/base.bin", artifact.executable)

    with pytest.raises(ArtifactEvidenceError, match="executable.*regular"):
        snapshot_payload(artifact, _LIMITS)


def test_manifest_resolver_follows_macos_framework_alias_chain() -> None:
    entries = _resolver_entries(
        ("Python.framework", "directory", None),
        ("Python.framework/Versions", "directory", None),
        ("Python.framework/Versions/3.12", "directory", None),
        ("Python.framework/Versions/3.12/Python", "file", None),
        ("Python.framework/Versions/3.12/Resources", "directory", None),
        ("Python.framework/Versions/Current", "symlink", "3.12"),
        (
            "Python.framework/Python",
            "symlink",
            "Versions/Current/Python",
        ),
        (
            "Python.framework/Resources",
            "symlink",
            "Versions/Current/Resources",
        ),
    )
    resolver = SnapshotPathResolver(entries, 100)

    resolver.validate_links("darwin")
    resolved = resolver.resolve_entry(PurePosixPath("Python.framework/Python"))

    assert resolved.relative_path == PurePosixPath(
        "Python.framework/Versions/3.12/Python"
    )
    assert resolved.entry.kind == "file"


def test_manifest_resolver_preserves_posix_dotdot_after_alias_expansion() -> None:
    entries = _resolver_entries(
        ("nested", "directory", None),
        ("nested/dir", "directory", None),
        ("nested/file", "file", None),
        ("alias", "symlink", "nested/dir"),
        ("via-alias", "symlink", "alias/../file"),
        ("repeated", "symlink", "alias/../../alias"),
    )
    resolver = SnapshotPathResolver(entries, 100)

    resolver.validate_links("darwin")

    assert resolver.resolve_entry(PurePosixPath("via-alias")).relative_path == (
        PurePosixPath("nested/file")
    )
    assert resolver.resolve_entry(PurePosixPath("repeated")).relative_path == (
        PurePosixPath("nested/dir")
    )


@pytest.mark.parametrize("target", ("file/", "file/.", "file//", "file/../directory"))
def test_manifest_resolver_rejects_file_with_following_path_syntax(target: str) -> None:
    entries = _resolver_entries(
        ("file", "file", None),
        ("directory", "directory", None),
        ("link", "symlink", target),
    )

    with pytest.raises(ArtifactEvidenceError, match="requires a directory"):
        SnapshotPathResolver(entries, 100).validate_links("darwin")


def test_manifest_resolver_rejects_alias_to_file_with_caller_suffix() -> None:
    entries = _resolver_entries(
        ("file", "file", None),
        ("alias", "symlink", "file"),
    )
    resolver = SnapshotPathResolver(entries, 100)

    resolver.validate_links("darwin")

    with pytest.raises(ArtifactEvidenceError, match="requires a directory"):
        resolver.resolve_entry(PurePosixPath("alias/child"))


@pytest.mark.parametrize(
    "target",
    ("../file", "/file", "C:file", "file\\name", "file\x00name"),
)
def test_manifest_resolver_rejects_unsafe_raw_targets(target: str) -> None:
    entries = _resolver_entries(
        ("file", "file", None),
        ("link", "symlink", target),
    )

    with pytest.raises(ArtifactEvidenceError):
        SnapshotPathResolver(entries, 100).validate_links("darwin")


def test_manifest_resolver_rejects_shared_budget_exhaustion() -> None:
    entries = _resolver_entries(
        ("file", "file", None),
        ("link", "symlink", "file/."),
    )

    with pytest.raises(ArtifactEvidenceError, match="resolution limit"):
        SnapshotPathResolver(entries, 2).validate_links("darwin")


def test_manifest_resolver_rejects_unrecorded_link_parent() -> None:
    entries = _resolver_entries(
        ("file", "file", None),
        ("missing/link", "symlink", "../file"),
    )

    with pytest.raises(ArtifactEvidenceError, match="parent is invalid"):
        SnapshotPathResolver(entries, 100).validate_links("darwin")


def test_manifest_resolver_rejects_active_link_cycles() -> None:
    for entries in (
        _resolver_entries(("self", "symlink", "self")),
        _resolver_entries(
            ("first", "symlink", "second"),
            ("second", "symlink", "first"),
        ),
    ):
        with pytest.raises(ArtifactEvidenceError, match="cycle"):
            SnapshotPathResolver(entries, 100).validate_links("darwin")


@pytest.mark.parametrize("depth", (750, 1_500, 3_000))
def test_manifest_resolver_charges_deep_multicomponent_append_before_copy(
    depth: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    entries = _deep_multicomponent_entries(depth)
    append_calls = 0
    original_append = artifact_filesystem._append_path

    def count_append(parent: PurePosixPath | None, component: str) -> PurePosixPath:
        nonlocal append_calls
        append_calls += 1
        return original_append(parent, component)

    monkeypatch.setattr(artifact_filesystem, "_append_path", count_append)

    with pytest.raises(ArtifactEvidenceError, match="resolution limit"):
        SnapshotPathResolver(entries, len(entries)).validate_links("darwin")

    # Each successful append retains an ever-longer prefix. The next one is
    # rejected before allocation once those retained components exhaust budget.
    assert append_calls * append_calls <= 2 * depth


@pytest.mark.parametrize("depth", (750, 1_500, 3_000))
def test_manifest_resolver_charges_deep_nested_alias_before_copy(
    depth: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    entries = _deep_nested_alias_entries(depth)
    append_calls = 0
    original_append = artifact_filesystem._append_path

    def count_append(parent: PurePosixPath | None, component: str) -> PurePosixPath:
        nonlocal append_calls
        append_calls += 1
        return original_append(parent, component)

    monkeypatch.setattr(artifact_filesystem, "_append_path", count_append)

    with pytest.raises(ArtifactEvidenceError, match="resolution limit"):
        SnapshotPathResolver(entries, len(entries)).validate_links("darwin")

    assert append_calls == 0


def test_manifest_resolver_reuses_recorded_paths_for_nested_aliases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = _deep_nested_alias_entries(20)
    target = entries[-3]
    inner = entries[-2]
    outer = entries[-1]
    resolver = SnapshotPathResolver(entries, 10_000)
    parent_calls = 0
    original_parent = resolver._parent_entry_path

    def count_parent(path: PurePosixPath | None) -> PurePosixPath | None:
        nonlocal parent_calls
        parent_calls += 1
        return original_parent(path)

    monkeypatch.setattr(resolver, "_parent_entry_path", count_parent)

    resolver.validate_links("darwin")
    outer_resolved = resolver.resolve_entry(outer.relative_path)
    inner_resolved = resolver.resolve_entry(inner.relative_path)

    assert parent_calls == 1
    assert outer_resolved.relative_path is target.relative_path
    assert inner_resolved.relative_path is target.relative_path


def _deep_multicomponent_entries(depth: int) -> tuple[PayloadEntry, ...]:
    parent: PurePosixPath | None = None
    entries: list[PayloadEntry] = []
    for index in range(depth):
        parent = _append_component(parent, f"segment-{index:04d}")
        entries.append(PayloadEntry(parent, "directory", 0o755, 0, None, None))
    file_path = _append_component(parent, "payload.bin")
    entries.append(PayloadEntry(file_path, "file", 0o644, 0, None, None))
    entries.append(
        PayloadEntry(
            PurePosixPath("link"),
            "symlink",
            0o777,
            0,
            None,
            file_path.as_posix(),
        )
    )
    return tuple(entries)


def _deep_nested_alias_entries(depth: int) -> tuple[PayloadEntry, ...]:
    parent: PurePosixPath | None = None
    entries: list[PayloadEntry] = []
    for index in range(depth):
        parent = _append_component(parent, f"segment-{index:04d}")
        entries.append(PayloadEntry(parent, "directory", 0o755, 0, None, None))
    target = _append_component(parent, "payload.bin")
    outer = _append_component(parent, "outer")
    inner = _append_component(parent, "inner")
    entries.extend(
        (
            PayloadEntry(target, "file", 0o644, 0, None, None),
            PayloadEntry(outer, "symlink", 0o777, 0, None, "inner"),
            PayloadEntry(inner, "symlink", 0o777, 0, None, "payload.bin"),
        )
    )
    return tuple(entries)


def _append_component(parent: PurePosixPath | None, component: str) -> PurePosixPath:
    return PurePosixPath(component) if parent is None else parent / component


def _resolver_entries(
    *rows: tuple[str, str, str | None],
) -> tuple[PayloadEntry, ...]:
    return tuple(
        PayloadEntry(PurePosixPath(path), kind, 0o755, 0, None, target)
        for path, kind, target in rows
    )


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
