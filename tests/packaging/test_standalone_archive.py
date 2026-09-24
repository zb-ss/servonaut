"""Deterministic archive and hostile extraction coverage."""

from __future__ import annotations

import base64
import gzip
import io
import os
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest
from test_standalone_artifact_filesystem import _NOTICE_POLICIES, _artifact

from scripts.standalone_cli import artifact_archive, artifact_filesystem
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


@pytest.fixture(autouse=True)
def _trusted_notice_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        artifact_filesystem,
        "load_embedded_notice_policy",
        lambda _path, _limit: _NOTICE_POLICIES,
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


def _tar_gz(path: Path, tar_bytes: bytes) -> Path:
    path.write_bytes(gzip.compress(tar_bytes, mtime=0))
    return path


def _regular_tar_member(name: str, data: bytes) -> bytes:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    padding = b"\0" * (-len(data) % tarfile.BLOCKSIZE)
    return info.tobuf(format=tarfile.USTAR_FORMAT) + data + padding


def _tar_end() -> bytes:
    return b"\0" * tarfile.RECORDSIZE


@pytest.mark.parametrize(
    "header_type", (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME), ids=("pax", "gnu")
)
def test_extraction_bounds_extended_headers_before_reading_them(
    tmp_path: Path, header_type: bytes
) -> None:
    oversized = 2048
    header = tarfile.TarInfo("././@LongHeader")
    header.type = header_type
    header.size = oversized
    body = b"\0" * oversized
    archive = _tar_gz(
        tmp_path / "extended.tar.gz",
        header.tobuf(format=tarfile.USTAR_FORMAT)
        + body
        + _regular_tar_member("payload.bin", b"x")
        + _tar_end(),
    )
    limits = EvidenceLimits(1024, 1000, 1024, 4096, 30, 1024)
    destination = tmp_path / "destination"

    with pytest.raises(ArtifactEvidenceError, match="extended header exceeds"):
        extract_archive_safely(archive, destination, limits)

    assert not destination.exists()


def test_extraction_rejects_an_unsupported_member_before_skipping_its_body(
    tmp_path: Path,
) -> None:
    unsupported = tarfile.TarInfo("unsupported")
    unsupported.type = b"Z"
    unsupported.size = 64 * 1024 * 1024
    archive = _tar_gz(
        tmp_path / "unsupported.tar.gz",
        unsupported.tobuf(format=tarfile.GNU_FORMAT) + b"\0" * tarfile.BLOCKSIZE,
    )
    destination = tmp_path / "destination"

    with pytest.raises(ArtifactEvidenceError, match="unsupported member"):
        extract_archive_safely(archive, destination, _LIMITS)

    assert not destination.exists()


def test_extraction_verifies_the_gzip_checksum_before_writing(tmp_path: Path) -> None:
    archive = _tar_gz(
        tmp_path / "checksum.tar.gz",
        _regular_tar_member("payload.bin", b"payload") + _tar_end(),
    )
    data = bytearray(archive.read_bytes())
    data[-8] ^= 0xFF
    archive.write_bytes(bytes(data))
    destination = tmp_path / "destination"

    with pytest.raises(ArtifactEvidenceError, match="could not be read"):
        extract_archive_safely(archive, destination, _LIMITS)

    assert not destination.exists()


def test_extraction_rejects_data_after_the_end_marker(tmp_path: Path) -> None:
    archive = _tar_gz(
        tmp_path / "trailing.tar.gz",
        _regular_tar_member("payload.bin", b"payload")
        + b"\0" * tarfile.BLOCKSIZE
        + _regular_tar_member("hidden.bin", b"hidden")
        + _tar_end(),
    )
    destination = tmp_path / "destination"

    with pytest.raises(ArtifactEvidenceError, match="after its end marker"):
        extract_archive_safely(archive, destination, _LIMITS)

    assert not destination.exists()


def test_extraction_accepts_the_padding_written_by_tarfile(tmp_path: Path) -> None:
    archive = tmp_path / "padded.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        member = tarfile.TarInfo("payload.bin")
        member.size = 7
        output.addfile(member, io.BytesIO(b"payload"))
    destination = tmp_path / "destination"

    extract_archive_safely(archive, destination, _LIMITS)

    assert (destination / "payload.bin").read_bytes() == b"payload"


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


@pytest.mark.parametrize("target_name", ("linux-x64-ubuntu-22.04", "windows-x64"))
def test_repeated_archive_proof_keeps_only_the_primary_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_name: str
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path, target_name=target_name)
    snapshot = snapshot_payload(artifact, _LIMITS)
    primary = create_archive_from_snapshot(
        snapshot, artifact.target, _POLICY, tmp_path / "archive"
    )

    artifact_archive._verify_repeated_archive(
        snapshot, artifact.target, _POLICY, primary
    )

    assert primary.path.is_file()
    assert not (tmp_path / "archive-repeat").exists()
    assert not (tmp_path / "archive-repeat").is_symlink()


def test_repeated_archive_comparison_rejects_same_length_byte_difference(
    tmp_path: Path,
) -> None:
    primary = tmp_path / "primary"
    repeated = tmp_path / "repeated"
    primary.write_bytes(b"one")
    repeated.write_bytes(b"two")

    with pytest.raises(ArtifactEvidenceError, match="repeated archive differs"):
        artifact_archive._compare_archive_bytes(primary, repeated, 3)


def test_repeated_archive_comparison_rejects_growth_after_recorded_size(
    tmp_path: Path,
) -> None:
    primary = tmp_path / "primary"
    repeated = tmp_path / "repeated"
    primary.write_bytes(b"a")
    repeated.write_bytes(b"ab")

    with pytest.raises(ArtifactEvidenceError, match="repeated archive differs"):
        artifact_archive._compare_archive_bytes(primary, repeated, 1)


@pytest.mark.parametrize("content", (b"x", b""))
def test_repeated_archive_comparison_rejects_paired_premature_eof(
    tmp_path: Path, content: bytes
) -> None:
    primary = tmp_path / "primary"
    repeated = tmp_path / "repeated"
    primary.write_bytes(content)
    repeated.write_bytes(content)

    with pytest.raises(ArtifactEvidenceError, match="repeated archive differs"):
        artifact_archive._compare_archive_bytes(primary, repeated, 2)


def test_repeated_archive_mismatch_removes_duplicate_and_keeps_primary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path)
    snapshot = snapshot_payload(artifact, _LIMITS)
    primary = create_archive_from_snapshot(
        snapshot, artifact.target, _POLICY, tmp_path / "archive"
    )

    def reject_comparison(*_args: object) -> None:
        raise ArtifactEvidenceError("repeated archive differs")

    monkeypatch.setattr(artifact_archive, "_compare_archive_bytes", reject_comparison)
    with pytest.raises(ArtifactEvidenceError, match="repeated archive differs"):
        artifact_archive._verify_repeated_archive(
            snapshot, artifact.target, _POLICY, primary
        )

    assert primary.path.is_file()
    assert not (tmp_path / "archive-repeat").exists()


@pytest.mark.parametrize("kind", ("file", "directory"))
def test_repeated_archive_refuses_existing_derived_output_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path)
    snapshot = snapshot_payload(artifact, _LIMITS)
    primary = create_archive_from_snapshot(
        snapshot, artifact.target, _POLICY, tmp_path / "archive"
    )
    repeat_root = tmp_path / "archive-repeat"
    if kind == "file":
        repeat_root.write_text("foreign", encoding="utf-8")
    else:
        repeat_root.mkdir()

    with pytest.raises(
        ArtifactEvidenceError, match="repeated archive output is invalid"
    ):
        artifact_archive._verify_repeated_archive(
            snapshot, artifact.target, _POLICY, primary
        )

    assert repeat_root.exists()
    assert primary.path.is_file()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink output-root boundary")
def test_repeated_archive_refuses_existing_derived_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path)
    snapshot = snapshot_payload(artifact, _LIMITS)
    primary = create_archive_from_snapshot(
        snapshot, artifact.target, _POLICY, tmp_path / "archive"
    )
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    repeat_root = tmp_path / "archive-repeat"
    repeat_root.symlink_to(foreign, target_is_directory=True)

    with pytest.raises(
        ArtifactEvidenceError, match="repeated archive output is invalid"
    ):
        artifact_archive._verify_repeated_archive(
            snapshot, artifact.target, _POLICY, primary
        )

    assert repeat_root.is_symlink()
    assert primary.path.is_file()


def test_repeated_archive_cleanup_refusal_preserves_duplicate_and_primary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path)
    snapshot = snapshot_payload(artifact, _LIMITS)
    primary = create_archive_from_snapshot(
        snapshot, artifact.target, _POLICY, tmp_path / "archive"
    )
    monkeypatch.setattr(artifact_archive, "delete_owned_archive", lambda _owner: None)

    with pytest.raises(ArtifactEvidenceError, match="repeated archive cleanup failed"):
        artifact_archive._verify_repeated_archive(
            snapshot, artifact.target, _POLICY, primary
        )

    assert primary.path.is_file()
    assert any((tmp_path / "archive-repeat").iterdir())


def test_repeated_archive_rejects_replaced_primary_before_creating_duplicate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path)
    snapshot = snapshot_payload(artifact, _LIMITS)
    primary = create_archive_from_snapshot(
        snapshot, artifact.target, _POLICY, tmp_path / "archive"
    )
    original_identity = (primary.path.stat().st_dev, primary.path.stat().st_ino)
    retained = primary.path.with_name("retained-primary")
    primary.path.rename(retained)
    primary.path.write_bytes(b"foreign")
    replacement_identity = (primary.path.stat().st_dev, primary.path.stat().st_ino)
    assert replacement_identity != original_identity

    with pytest.raises(
        ArtifactEvidenceError, match="repeated archive primary is invalid"
    ):
        artifact_archive._verify_repeated_archive(
            snapshot, artifact.target, _POLICY, primary
        )

    assert primary.path.read_bytes() == b"foreign"
    assert retained.is_file()
    assert not (tmp_path / "archive-repeat").exists()


def test_repeated_archive_duplicate_constructor_failure_keeps_primary_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    artifact = _artifact(tmp_path)
    snapshot = snapshot_payload(artifact, _LIMITS)
    primary = create_archive_from_snapshot(
        snapshot, artifact.target, _POLICY, tmp_path / "archive"
    )

    def reject_writer(*_args: object) -> None:
        raise ArtifactEvidenceError("repeated archive differs")

    monkeypatch.setattr(artifact_archive, "_write_tar_gz", reject_writer)
    with pytest.raises(ArtifactEvidenceError, match="repeated archive differs"):
        artifact_archive._verify_repeated_archive(
            snapshot, artifact.target, _POLICY, primary
        )

    assert primary.path.is_file()
    assert not (tmp_path / "archive-repeat").exists()


def test_repeated_archive_uses_one_captured_source_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = _artifact(tmp_path)
    snapshot = snapshot_payload(artifact, _LIMITS)
    epoch_reads: list[int] = []

    def epoch_once() -> int:
        epoch_reads.append(1)
        if len(epoch_reads) > 1:
            raise AssertionError("source epoch read more than once")
        return 1_700_000_000

    monkeypatch.setattr(artifact_archive, "_source_date_epoch", epoch_once)
    primary = create_archive_from_snapshot(
        snapshot, artifact.target, _POLICY, tmp_path / "archive"
    )
    artifact_archive._verify_repeated_archive(
        snapshot, artifact.target, _POLICY, primary
    )

    assert epoch_reads == [1]
    assert primary.source_date_epoch == 1_700_000_000


def test_inspection_enforces_before_retaining_its_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.standalone_cli import artifact_inspect

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


def test_private_collection_enforces_once_after_normal_body_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.standalone_cli import artifact_inspect

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
    original_create = artifact_inspect.create_archive_from_snapshot
    original_verify = artifact_archive._verify_repeated_archive
    result_holder: dict[str, Path] = {}

    def record_create(*args: object) -> object:
        calls.append("primary")
        owner = original_create(*args)
        result_holder["primary"] = owner.path
        return owner

    def record_repeat(*args: object) -> None:
        calls.append("repeat")
        original_verify(*args)

    def report(*args: object) -> object:
        calls.append("report")
        assert args[2].path == result_holder["primary"]
        return reports

    monkeypatch.setattr(artifact_inspect, "create_archive_from_snapshot", record_create)
    monkeypatch.setattr(artifact_archive, "_verify_repeated_archive", record_repeat)
    monkeypatch.setattr(artifact_inspect, "_report_archive", report)
    monkeypatch.setattr(
        artifact_inspect, "_enforce", lambda *args: calls.append("enforced")
    )

    with artifact_inspect._collected_artifact_for_smoke(
        artifact, evidence_dir
    ) as result:
        calls.append("body")
        assert result.archive == result._archive_owner.path
        assert result.archive.is_file()

    assert calls == ["primary", "repeat", "report", "body", "enforced"]
    assert result.archive.is_file()
    assert not (result._archive_owner.output_root.parent / "archive-repeat").exists()


def test_private_collection_body_failure_skips_enforcement_and_removes_owned_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.standalone_cli import artifact_inspect

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
    monkeypatch.setattr(
        artifact_inspect, "_enforce", lambda *args: calls.append("enforced")
    )

    with (
        pytest.raises(RuntimeError, match="smoke failed"),
        artifact_inspect._collected_artifact_for_smoke(artifact, evidence_dir),
    ):
        raise RuntimeError("smoke failed")

    assert calls == []
    assert not list(tmp_path.glob(".artifact-evidence-*"))
