"""Candidate-first release policy: deterministic identity and fail-closed gating."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from scripts.distribution.release_candidate import (
    CandidatePolicyError,
    ReleaseCandidate,
    candidate_digest,
    candidate_from_evidence,
    ensure_publishable,
    evidence_matches_tag,
    load_evidence,
    main,
    plan_candidate,
    verify_candidate,
)
from servonaut.distribution.builder import ManifestBuilder
from servonaut.distribution.manifest import (
    ArtifactKind,
    ReleaseChannel,
    ReleaseManifest,
    canonicalize_json,
)
from servonaut.runtime import DistributionKind


def _package_tree(root: Path, version: str = "2.27.0") -> Path:
    (root / "src" / "servonaut").mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text(
        f'[project]\nversion = "{version}"\n', encoding="utf-8"
    )
    (root / "src" / "servonaut" / "__init__.py").write_text(
        f"__version__ = '{version}'\n", encoding="utf-8"
    )
    return root


def _manifest(
    tmp_path: Path,
    *,
    version: str = "2.27.0",
    signed: bool = True,
    artifacts: int = 1,
) -> tuple[ReleaseManifest, dict[str, Path]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    files: dict[str, Path] = {}
    builder = ManifestBuilder(product_version=version, channel=ReleaseChannel.STABLE)
    key = Ed25519PrivateKey.generate()
    for index in range(artifacts):
        artifact = tmp_path / f"servonaut-{index}.tar.gz"
        artifact.write_bytes(b"PAYLOAD" + bytes([index]))
        record = builder.add_artifact_file(
            artifact,
            kind=ArtifactKind.STANDALONE_CLI,
            distribution=DistributionKind.FROZEN_CLI,
            platform="linux",
            arch="x86_64",
            download_url=f"https://example.com/servonaut-{index}.tar.gz",
        )
        if signed:
            builder.sign_artifact(record.artifact_id, key)
        files[record.artifact_id] = artifact
    return builder.build(), files


def _candidate(tmp_path: Path, **kwargs: object) -> tuple[ReleaseCandidate, dict[str, Path]]:
    manifest, files = _manifest(tmp_path, **kwargs)
    candidate = plan_candidate(
        manifest,
        tag="v2.27.0",
        source_commit="a" * 40,
        requires_signing=bool(kwargs.get("signed", True)),
    )
    return candidate, files


def test_digest_is_order_independent_and_content_bound(tmp_path: Path) -> None:
    first = _candidate(tmp_path / "one")[0]
    assert candidate_digest(first.artifacts) == first.digest

    reordered = type(first)(
        tag=first.tag,
        product_version=first.product_version,
        source_commit=first.source_commit,
        digest=first.digest,
        artifacts=tuple(reversed(first.artifacts)),
        requires_signing=first.requires_signing,
    )
    assert candidate_digest(reordered.artifacts) == first.digest


def test_digest_changes_when_an_artifact_changes(tmp_path: Path) -> None:
    base, _ = _candidate(tmp_path / "base")
    changed_dir = tmp_path / "changed"
    changed_dir.mkdir()
    manifest = ManifestBuilder(
        product_version="2.27.0", channel=ReleaseChannel.STABLE
    )
    artifact = changed_dir / "servonaut-0.tar.gz"
    artifact.write_bytes(b"DIFFERENT-PAYLOAD")
    manifest.add_artifact_file(
        artifact,
        kind=ArtifactKind.STANDALONE_CLI,
        distribution=DistributionKind.FROZEN_CLI,
        platform="linux",
        arch="x86_64",
        download_url="https://example.com/servonaut-0.tar.gz",
    )
    changed = plan_candidate(
        manifest.build(),
        tag="v2.27.0",
        source_commit="a" * 40,
        requires_signing=False,
    )
    assert changed.digest != base.digest


@pytest.mark.parametrize(
    "tag,commit",
    [
        ("2.27.0", "a" * 40),
        ("v2.27", "a" * 40),
        ("v2.27.0-rc.1", "a" * 40),
        ("v2.28.0", "a" * 40),
        ("v2.27.0", ""),
    ],
)
def test_plan_rejects_invalid_tag_or_version(
    tmp_path: Path, tag: str, commit: str
) -> None:
    manifest, _ = _manifest(tmp_path)
    with pytest.raises(CandidatePolicyError):
        plan_candidate(
            manifest,
            tag=tag,
            source_commit=commit,
            requires_signing=True,
        )


def test_plan_rejects_duplicate_artifact_filenames(tmp_path: Path) -> None:
    manifest, _ = _manifest(tmp_path, artifacts=1)
    duplicate = replace(manifest.artifacts[0], artifact_id="second-id")
    tampered = replace(
        manifest,
        artifacts=manifest.artifacts + (duplicate,),
        signatures=(),
    )
    with pytest.raises(CandidatePolicyError) as raised:
        plan_candidate(
            tampered,
            tag="v2.27.0",
            source_commit="a" * 40,
            requires_signing=True,
        )
    assert raised.value.code == "duplicate-artifacts"


def test_verify_accepts_a_matching_candidate(tmp_path: Path) -> None:
    root = _package_tree(tmp_path / "repo")
    candidate, files = _candidate(tmp_path)
    verify_candidate(
        candidate, expected_digest=candidate.digest, root=root, artifact_files=files
    )


@pytest.mark.parametrize(
    "mutate,expected",
    [
        ({"expected_digest": "0" * 64}, "digest-changed"),
        ({"expected_digest": "not-a-digest"}, "invalid-digest"),
    ],
)
def test_verify_rejects_digest_drift(
    tmp_path: Path, mutate: dict[str, str], expected: str
) -> None:
    root = _package_tree(tmp_path / "repo")
    candidate, files = _candidate(tmp_path)
    argument = mutate.get("expected_digest", candidate.digest)
    with pytest.raises(CandidatePolicyError) as raised:
        verify_candidate(
            candidate, expected_digest=argument, root=root, artifact_files=files
        )
    assert raised.value.code == expected


def test_verify_rejects_package_version_drift(tmp_path: Path) -> None:
    root = _package_tree(tmp_path / "repo", version="2.28.0")
    candidate, files = _candidate(tmp_path)
    with pytest.raises(CandidatePolicyError) as raised:
        verify_candidate(
            candidate, expected_digest=candidate.digest, root=root, artifact_files=files
        )
    assert raised.value.code == "version-mismatch"


def test_verify_rejects_unsigned_when_signing_required(tmp_path: Path) -> None:
    root = _package_tree(tmp_path / "repo")
    manifest, files = _manifest(tmp_path, signed=False)
    candidate = plan_candidate(
        manifest,
        tag="v2.27.0",
        source_commit="a" * 40,
        requires_signing=True,
    )
    with pytest.raises(CandidatePolicyError) as raised:
        verify_candidate(
            candidate, expected_digest=candidate.digest, root=root, artifact_files=files
        )
    assert raised.value.code == "unsigned-artifact"


def test_verify_rejects_changed_artifact_file(tmp_path: Path) -> None:
    root = _package_tree(tmp_path / "repo")
    candidate, files = _candidate(tmp_path)
    changed = dict(files)
    first_id = candidate.artifacts[0].artifact_id
    changed[first_id].write_bytes(b"TAMPERED-CONTENT")
    with pytest.raises(CandidatePolicyError) as raised:
        verify_candidate(
            candidate, expected_digest=candidate.digest, root=root, artifact_files=changed
        )
    assert raised.value.code == "size-mismatch"


def test_verify_rejects_same_size_content_change(tmp_path: Path) -> None:
    root = _package_tree(tmp_path / "repo")
    candidate, files = _candidate(tmp_path)
    changed = dict(files)
    first_id = candidate.artifacts[0].artifact_id
    original = changed[first_id].read_bytes()
    changed[first_id].write_bytes(b"X" * len(original))
    with pytest.raises(CandidatePolicyError) as raised:
        verify_candidate(
            candidate, expected_digest=candidate.digest, root=root, artifact_files=changed
        )
    assert raised.value.code == "hash-mismatch"


def test_verify_rejects_missing_artifact_file(tmp_path: Path) -> None:
    root = _package_tree(tmp_path / "repo")
    candidate, _ = _candidate(tmp_path)
    with pytest.raises(CandidatePolicyError) as raised:
        verify_candidate(
            candidate, expected_digest=candidate.digest, root=root, artifact_files={}
        )
    assert raised.value.code == "missing-artifact"


def test_evidence_round_trips_and_gates_publishing(tmp_path: Path) -> None:
    candidate, _ = _candidate(tmp_path)
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(canonicalize_json(candidate.to_evidence()) + b"\n")

    document = load_evidence(evidence)
    assert evidence_matches_tag(document, "v2.27.0")
    assert not evidence_matches_tag(document, "v2.27.1")
    ensure_publishable(document, "v2.27.0")
    assert candidate_from_evidence(document).digest == candidate.digest


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not json",
        b"[]",
        b"{}",
        b'{"schema_version": 2}',
        b'{"schema_version": 1, "artifacts": []}',
    ],
)
def test_load_evidence_fails_closed(tmp_path: Path, payload: bytes) -> None:
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(payload)
    with pytest.raises(CandidatePolicyError) as raised:
        load_evidence(evidence)
    assert raised.value.code in {"evidence-invalid", "evidence-unreadable"}


def test_ensure_publishable_rejects_unsigned_evidence(tmp_path: Path) -> None:
    candidate, _ = _candidate(tmp_path)
    document = candidate.to_evidence()
    document["signing"] = {"required": True, "satisfied": False}
    with pytest.raises(CandidatePolicyError) as raised:
        ensure_publishable(document, "v2.27.0")
    assert raised.value.code == "candidate-unsigned"


def test_ensure_publishable_rejects_missing_tag(tmp_path: Path) -> None:
    candidate, _ = _candidate(tmp_path)
    with pytest.raises(CandidatePolicyError) as raised:
        ensure_publishable(candidate.to_evidence(), "v9.9.9")
    assert raised.value.code == "candidate-missing"


def test_cli_plan_verify_and_check_publish(tmp_path: Path) -> None:
    root = _package_tree(tmp_path / "repo")
    manifest, files = _manifest(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(canonicalize_json(manifest.to_dict()) + b"\n")
    evidence = tmp_path / "evidence.json"

    assert (
        main(
            [
                "plan",
                "--manifest",
                str(manifest_path),
                "--tag",
                "v2.27.0",
                "--commit",
                "a" * 40,
                "--repo",
                str(root),
                "--evidence-out",
                str(evidence),
            ]
        )
        == 0
    )
    digest = json.loads(evidence.read_text(encoding="utf-8"))["digest"]
    assert (
        main(
            [
                "verify",
                "--evidence",
                str(evidence),
                "--expected-digest",
                digest,
                "--repo",
                str(root),
            ]
        )
        == 0
    )
    assert (
        main(["check-publish", "--evidence", str(evidence), "--tag", "v2.27.0"]) == 0
    )
    assert (
        main(["check-publish", "--evidence", str(evidence), "--tag", "v2.27.1"]) == 1
    )
    assert files  # artifact fixtures were used by the manifest build


def test_cli_plan_rejects_version_drift(tmp_path: Path, capsys) -> None:
    root = _package_tree(tmp_path / "repo", version="2.28.0")
    manifest, _ = _manifest(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(canonicalize_json(manifest.to_dict()) + b"\n")
    assert (
        main(
            [
                "plan",
                "--manifest",
                str(manifest_path),
                "--tag",
                "v2.27.0",
                "--commit",
                "a" * 40,
                "--repo",
                str(root),
            ]
        )
        == 1
    )
    assert "::error::" in capsys.readouterr().err
