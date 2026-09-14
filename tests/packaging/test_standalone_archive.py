"""Deterministic archive and hostile extraction coverage."""

from __future__ import annotations

import base64
import io
import os
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest
from test_standalone_artifact_filesystem import _artifact

from scripts.standalone_cli import artifact_archive
from scripts.standalone_cli.artifact_archive import (
    create_archive_from_snapshot,
    delete_owned_archive,
    extract_archive_safely,
)
from scripts.standalone_cli.artifact_filesystem import snapshot_payload
from scripts.standalone_cli.artifact_types import ArtifactEvidenceError
from scripts.standalone_cli.evidence_policy_types import (
    EvidenceLimits,
    EvidencePolicy,
    NativeConstraints,
)

_LIMITS = EvidenceLimits(
    1024 * 1024,
    1000,
    1024 * 1024,
    8 * 1024 * 1024,
    30,
    1024 * 1024,
)
_POLICY = EvidencePolicy(
    _LIMITS,
    NativeConstraints("x64", "x86-64", "2.35", "ubuntu", "22.04"),
    frozenset(),
    9,
)
_ENCRYPTED_ZIP_FIXTURE = (
    "UEsDBAoACQAAAAAAIQAVaixCEwAAAAcAAAAKAAAAbWVtYmVyLnR4dIxTkaZq9X/C8BDu"
    "P4HtuWQ3sYFQSwcIFWosQhMAAAAHAAAAUEsBAh4DCgAJAAAAAAAhABVqLEITAAAABwAA"
    "AAoAAAAAAAAAAQAAALSBAAAAAG1lbWJlci50eHRQSwUGAAAAAAEAAQA4AAAASwAAAAAA"
)


def test_tar_archive_is_deterministic_and_extracts_posix_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path)
    os.symlink("base.bin", artifact.payload_root / "_internal" / "runtime.bin")
    snapshot = snapshot_payload(artifact, _LIMITS)
    first_output, second_output = tmp_path / "archive-one", tmp_path / "archive-two"

    first = create_archive_from_snapshot(
        snapshot, artifact.target, _POLICY, first_output
    )
    second = create_archive_from_snapshot(
        snapshot, artifact.target, _POLICY, second_output
    )
    extracted = extract_archive_safely(
        first.path, tmp_path / "extracted payload", _LIMITS
    )

    assert first.path.read_bytes() == second.path.read_bytes()
    assert os.readlink(extracted / "_internal" / "runtime.bin") == "base.bin"
    assert (extracted / "_internal" / "base.bin").read_bytes() == b"runtime"
    assert dict(first.archive_profile) == {
        "format": "tar.gz",
        "compression": "gzip",
        "compression_level": 9,
        "container_format": "pax",
        "timestamp_policy": "source-date-epoch",
        "ownership_policy": "uid-gid-zero-empty-names",
    }
    assert first.source_date_epoch == 1_700_000_000


def test_long_posix_link_chain_is_iterative_and_extracts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path)
    for index in range(1_200):
        target = f"link-{index + 1:04d}" if index < 1_199 else "_internal/base.bin"
        os.symlink(target, artifact.payload_root / f"link-{index:04d}")
    limits = EvidenceLimits(
        1024 * 1024, 250_000, 1024 * 1024, 8 * 1024 * 1024, 30, 1024 * 1024
    )
    snapshot = snapshot_payload(artifact, limits)

    owner = create_archive_from_snapshot(
        snapshot,
        artifact.target,
        EvidencePolicy(limits, _POLICY.native, frozenset(), 9),
        tmp_path / "archive",
    )
    extracted = extract_archive_safely(owner.path, tmp_path / "extracted", limits)

    assert os.readlink(extracted / "link-0000") == "link-0001"


def test_framework_alias_archive_is_deterministic_and_round_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path)
    framework = artifact.payload_root / "Python.framework"
    version = framework / "Versions" / "3.12"
    version.mkdir(parents=True)
    (version / "Python").write_bytes(b"framework-python")
    (version / "Resources").mkdir()
    (version / "Resources" / "marker.txt").write_text("resources", encoding="utf-8")
    os.symlink("3.12", framework / "Versions" / "Current")
    os.symlink("Versions/Current/Python", framework / "Python")
    os.symlink("Versions/Current/Resources", framework / "Resources")
    first_output, second_output = tmp_path / "archive-one", tmp_path / "archive-two"

    snapshot = snapshot_payload(artifact, _LIMITS)
    first = create_archive_from_snapshot(
        snapshot, artifact.target, _POLICY, first_output
    )
    second = create_archive_from_snapshot(
        snapshot, artifact.target, _POLICY, second_output
    )
    extracted = extract_archive_safely(first.path, tmp_path / "extracted", _LIMITS)

    assert first.path.read_bytes() == second.path.read_bytes()
    assert PurePosixPath("Python.framework/Versions/Current/Python") not in {
        entry.relative_path for entry in snapshot.entries
    }
    assert (
        os.readlink(extracted / "Python.framework" / "Versions" / "Current") == "3.12"
    )
    assert (
        extracted / "Python.framework" / "Python"
    ).read_bytes() == b"framework-python"
    assert (extracted / "Python.framework" / "Resources" / "marker.txt").read_text(
        encoding="utf-8"
    ) == "resources"


@pytest.mark.parametrize(
    "target",
    (
        "payload.bin/",
        "payload.bin/.",
        "payload.bin//",
        "payload.bin/../directory",
        "alias/child",
    ),
)
def test_extraction_rejects_link_through_file_before_creating_destination(
    tmp_path: Path, target: str
) -> None:
    archive = tmp_path / "file-link.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        payload = tarfile.TarInfo("payload.bin")
        payload.size = 1
        output.addfile(payload, io.BytesIO(b"x"))
        alias = tarfile.TarInfo("alias")
        alias.type = tarfile.SYMTYPE
        alias.linkname = "payload.bin"
        output.addfile(alias)
        link = tarfile.TarInfo("runtime")
        link.type = tarfile.SYMTYPE
        link.linkname = target
        output.addfile(link)

    destination = tmp_path / "destination"
    with pytest.raises(ArtifactEvidenceError, match="requires a directory"):
        extract_archive_safely(archive, destination, _LIMITS)

    assert not destination.exists()


def test_extraction_rejects_resolution_budget_exhaustion_before_destination(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "budget.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        payload = tarfile.TarInfo("payload.bin")
        payload.size = 1
        output.addfile(payload, io.BytesIO(b"x"))
        link = tarfile.TarInfo("runtime")
        link.type = tarfile.SYMTYPE
        link.linkname = "payload.bin/."
        output.addfile(link)
    limits = EvidenceLimits(1024, 2, 1024, 1024, 30, 1024)
    destination = tmp_path / "destination"

    with pytest.raises(ArtifactEvidenceError, match="resolution limit"):
        extract_archive_safely(archive, destination, limits)

    assert not destination.exists()


def test_zip_archive_extracts_regular_windows_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path, target_name="windows-x64")
    snapshot = snapshot_payload(artifact, _LIMITS)
    output = tmp_path / "archive"

    archive = create_archive_from_snapshot(snapshot, artifact.target, _POLICY, output)
    extracted = extract_archive_safely(archive.path, tmp_path / "extracted", _LIMITS)

    assert archive.path.suffix == ".zip"
    assert (extracted / "servonaut.exe").read_bytes() == b"executable"
    assert dict(archive.archive_profile) == {
        "format": "zip",
        "compression": "deflate",
        "compression_level": 9,
        "container_format": "zip",
        "timestamp_policy": "zip-clamped-source-date-epoch",
        "ownership_policy": "zip-unix-modes",
    }


def test_extraction_restores_explicit_directory_modes_across_umasks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path)
    (artifact.payload_root / "_internal").chmod(0o755)
    snapshot = snapshot_payload(artifact, _LIMITS)
    owner = create_archive_from_snapshot(
        snapshot, artifact.target, _POLICY, tmp_path / "archive"
    )

    previous_umask = os.umask(0o077)
    try:
        first = extract_archive_safely(owner.path, tmp_path / "first", _LIMITS)
    finally:
        os.umask(previous_umask)
    previous_umask = os.umask(0o022)
    try:
        second = extract_archive_safely(owner.path, tmp_path / "second", _LIMITS)
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE((first / "_internal").stat().st_mode) == 0o755
    assert stat.S_IMODE((second / "_internal").stat().st_mode) == 0o755
    assert stat.S_IMODE(first.stat().st_mode) == 0o700


def test_extraction_rejects_traversal_before_creating_destination(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "hostile.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        member = tarfile.TarInfo("../escape")
        member.size = 1
        output.addfile(member, io.BytesIO(b"x"))

    destination = tmp_path / "destination"
    with pytest.raises(ArtifactEvidenceError):
        extract_archive_safely(archive, destination, _LIMITS)

    assert not destination.exists()


@pytest.mark.parametrize("suffix", [".tar.gz", ".zip"])
def test_extraction_normalizes_malformed_archive_errors(
    tmp_path: Path, suffix: str
) -> None:
    archive = tmp_path / f"malformed{suffix}"
    archive.write_bytes(b"not an archive")
    destination = tmp_path / "destination"

    with pytest.raises(ArtifactEvidenceError, match="archive could not be read"):
        extract_archive_safely(archive, destination, _LIMITS)

    assert not destination.exists()


def test_extraction_rejects_oversized_members_before_creating_destination(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "oversized.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        member = tarfile.TarInfo("payload.bin")
        member.size = 5
        output.addfile(member, io.BytesIO(b"12345"))
    limits = EvidenceLimits(1024, 10, 4, 4, 30, 1024)
    destination = tmp_path / "destination"

    with pytest.raises(ArtifactEvidenceError, match="regular-file"):
        extract_archive_safely(archive, destination, limits)

    assert not destination.exists()


@pytest.mark.parametrize(
    "kind", ["duplicate", "absolute", "device", "dangling", "cycle", "link-parent"]
)
def test_extraction_rejects_unsafe_member_layout_before_creating_destination(
    tmp_path: Path, kind: str
) -> None:
    archive = tmp_path / f"{kind}.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        if kind == "duplicate":
            for _ in range(2):
                member = tarfile.TarInfo("duplicate")
                member.size = 1
                output.addfile(member, io.BytesIO(b"x"))
        elif kind == "absolute":
            member = tarfile.TarInfo("/escape")
            member.size = 1
            output.addfile(member, io.BytesIO(b"x"))
        elif kind == "device":
            member = tarfile.TarInfo("device")
            member.type = tarfile.CHRTYPE
            member.devmajor = member.devminor = 0
            output.addfile(member)
        elif kind == "dangling":
            member = tarfile.TarInfo("runtime")
            member.type = tarfile.SYMTYPE
            member.linkname = "missing"
            output.addfile(member)
        elif kind == "cycle":
            for name, target in (("one", "two"), ("two", "one")):
                member = tarfile.TarInfo(name)
                member.type = tarfile.SYMTYPE
                member.linkname = target
                output.addfile(member)
        else:
            link = tarfile.TarInfo("directory")
            link.type = tarfile.SYMTYPE
            link.linkname = ".."
            output.addfile(link)
            member = tarfile.TarInfo("directory/file")
            member.size = 1
            output.addfile(member, io.BytesIO(b"x"))

    destination = tmp_path / "destination"
    with pytest.raises(ArtifactEvidenceError):
        extract_archive_safely(archive, destination, _LIMITS)

    assert not destination.exists()


def test_extraction_preserves_existing_destination(tmp_path: Path) -> None:
    archive = tmp_path / "empty.tar.gz"
    with tarfile.open(archive, "w:gz"):
        pass
    destination = tmp_path / "destination"
    destination.mkdir()
    marker = destination / "foreign.txt"
    marker.write_text("foreign", encoding="utf-8")

    with pytest.raises(ArtifactEvidenceError, match="already exists"):
        extract_archive_safely(archive, destination, _LIMITS)

    assert marker.read_text(encoding="utf-8") == "foreign"


@pytest.mark.parametrize("name", ["C:/escape", "C:relative", "safe:stream"])
def test_extraction_rejects_windows_drive_and_stream_member_names(
    tmp_path: Path, name: str
) -> None:
    archive = tmp_path / "hostile.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(name, b"x")

    destination = tmp_path / "destination"
    with pytest.raises(ArtifactEvidenceError, match="path is unsafe"):
        extract_archive_safely(archive, destination, _LIMITS)

    assert not destination.exists()


def test_extraction_rejects_actual_encrypted_zip_member(tmp_path: Path) -> None:
    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(base64.b64decode(_ENCRYPTED_ZIP_FIXTURE, validate=True))
    with zipfile.ZipFile(archive) as reader:
        members = reader.infolist()
        assert len(members) == 1
        assert members[0].filename == "member.txt"
        assert members[0].flag_bits & 0x1
        assert members[0].date_time == (1980, 1, 1, 0, 0, 0)
        assert members[0].extra == members[0].comment == b""
        assert reader.read(members[0], pwd=b"test-password") == b"payload"

    destination = tmp_path / "destination"
    with pytest.raises(ArtifactEvidenceError, match="encrypted"):
        extract_archive_safely(archive, destination, _LIMITS)

    assert not destination.exists()


@pytest.mark.parametrize(
    ("epoch", "message"),
    ((None, "required"), ("not-an-epoch", "invalid")),
)
def test_invalid_epoch_does_not_create_archive_output_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, epoch: str | None, message: str
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path)
    snapshot = snapshot_payload(artifact, _LIMITS)
    if epoch is None:
        monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    else:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", epoch)
    output = tmp_path / "archive"

    with pytest.raises(ArtifactEvidenceError, match=message):
        create_archive_from_snapshot(snapshot, artifact.target, _POLICY, output)

    assert not output.exists()


def test_archive_requires_a_fresh_output_root_and_preserves_late_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path)
    snapshot = snapshot_payload(artifact, _LIMITS)
    output = tmp_path / "archive"
    output.mkdir()

    with pytest.raises(ArtifactEvidenceError, match="already exists"):
        create_archive_from_snapshot(snapshot, artifact.target, _POLICY, output)

    output.rmdir()
    real_writer = artifact_archive._write_tar_gz

    def create_foreign_destination(*args: object) -> None:
        real_writer(*args)
        output.mkdir(exist_ok=True)
        archive_name = artifact.target.artifact_name_template.format(
            product_version="1.2.3",
            target=artifact.target.name,
            extension=artifact.target.archive_extension,
        )
        (output / archive_name).write_text("foreign", encoding="utf-8")

    monkeypatch.setattr(artifact_archive, "_write_tar_gz", create_foreign_destination)

    with pytest.raises(ArtifactEvidenceError, match="already exists"):
        create_archive_from_snapshot(snapshot, artifact.target, _POLICY, output)

    foreign = next(output.iterdir())
    assert foreign.read_text(encoding="utf-8") == "foreign"
    assert stat.S_ISREG(foreign.stat().st_mode)


def test_delete_owned_archive_removes_only_its_empty_output_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path)
    snapshot = snapshot_payload(artifact, _LIMITS)
    output = tmp_path / "archive"

    owner = create_archive_from_snapshot(snapshot, artifact.target, _POLICY, output)
    delete_owned_archive(owner)

    assert not output.exists()


def test_inspection_enforces_before_retaining_its_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.standalone_cli import inspect as artifact_inspect

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path)
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    reports = SimpleNamespace(
        manifest=evidence_dir / "manifest.json",
        sizes=evidence_dir / "sizes.json",
        warnings=evidence_dir / "warnings.json",
        architecture=evidence_dir / "architecture.json",
    )
    calls: list[str] = []

    monkeypatch.setattr(artifact_inspect, "_load_policy", lambda: _POLICY)
    monkeypatch.setattr(
        artifact_inspect,
        "_generate_supply",
        lambda *args: SimpleNamespace(
            payload_sbom=Path("payload"), python_closure_sbom=Path("closure")
        ),
    )
    monkeypatch.setattr(artifact_inspect, "_analyse_raw", lambda *args: object())
    monkeypatch.setattr(artifact_inspect, "_report_archive", lambda *args: reports)

    def reject(*args: object) -> None:
        calls.append("enforced")
        raise ArtifactEvidenceError("qualification failed")

    monkeypatch.setattr(artifact_inspect, "_enforce", reject)

    with pytest.raises(ArtifactEvidenceError, match="qualification failed"):
        artifact_inspect.inspect_artifact(artifact, evidence_dir)

    assert calls == ["enforced"]
    assert not list(tmp_path.glob(".artifact-evidence-*"))
