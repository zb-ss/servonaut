"""Candidate-first release policy: deterministic identity and fail-closed gating."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from scripts.distribution.release_candidate import (
    CandidateArtifact,
    CandidatePolicyError,
    ReleaseCandidate,
    candidate_digest,
    candidate_from_evidence,
    channel_for_tag,
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


def _publish(
    document: dict,
    artifacts_dir: Path,
    *,
    tag: str = "v2.27.0",
    channel: ReleaseChannel = ReleaseChannel.STABLE,
    commit: str = "a" * 40,
) -> None:
    ensure_publishable(
        document,
        tag,
        channel=channel,
        source_commit=commit,
        artifacts_dir=artifacts_dir,
    )


def _manifest_file(artifacts: Path) -> tuple[Path, dict[str, Path]]:
    manifest, files = _manifest(artifacts)
    manifest_path = artifacts / "manifest.json"
    manifest_path.write_bytes(canonicalize_json(manifest.to_dict()) + b"\n")
    return manifest_path, files


def _cli_plan(
    manifest: Path, artifacts: Path, root: Path, evidence: Optional[Path]
) -> int:
    argv = [
        "plan",
        "--manifest",
        str(manifest),
        "--artifacts-dir",
        str(artifacts),
        "--tag",
        "v2.27.0",
        "--commit",
        "a" * 40,
        "--repo",
        str(root),
    ]
    if evidence is not None:
        argv += ["--evidence-out", str(evidence)]
    return main(argv)


def _cli_verify(evidence: Path, artifacts: Path, root: Path, digest: str) -> int:
    return main(
        [
            "verify",
            "--evidence",
            str(evidence),
            "--artifacts-dir",
            str(artifacts),
            "--expected-digest",
            digest,
            "--repo",
            str(root),
        ]
    )


def test_digest_is_order_independent_and_content_bound(tmp_path: Path) -> None:
    first = _candidate(tmp_path / "one")[0]
    assert candidate_digest(first.artifacts) == first.digest

    reordered = type(first)(
        tag=first.tag,
        channel=first.channel,
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
    _publish(document, tmp_path)
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
    candidate, _ = _candidate(tmp_path, signed=False)
    document = candidate.to_evidence()
    document["signing"] = {"required": True, "satisfied": False}
    with pytest.raises(CandidatePolicyError) as raised:
        _publish(document, tmp_path)
    assert raised.value.code == "candidate-unsigned"


def test_ensure_publishable_rejects_missing_tag(tmp_path: Path) -> None:
    candidate, _ = _candidate(tmp_path)
    with pytest.raises(CandidatePolicyError) as raised:
        _publish(candidate.to_evidence(), tmp_path, tag="v9.9.9")
    assert raised.value.code == "candidate-missing"


def test_stable_publish_ignores_a_declared_satisfied_flag(tmp_path: Path) -> None:
    """Signing is derived from the artifacts, never from the evidence's own flag."""
    candidate, _ = _candidate(tmp_path, signed=False)
    document = candidate.to_evidence()
    document["signing"] = {"required": True, "satisfied": True}
    with pytest.raises(CandidatePolicyError) as raised:
        _publish(document, tmp_path)
    assert raised.value.code == "candidate-unsigned"


def test_stable_publish_requires_signing_to_be_required(tmp_path: Path) -> None:
    candidate, _ = _candidate(tmp_path, signed=False)
    document = candidate.to_evidence()
    assert document["signing"] == {"required": False, "satisfied": False}
    with pytest.raises(CandidatePolicyError) as raised:
        _publish(document, tmp_path)
    assert raised.value.code == "candidate-signing-not-required"


def test_publish_rejects_a_satisfied_flag_that_contradicts_the_artifacts(
    tmp_path: Path,
) -> None:
    candidate, _ = _candidate(tmp_path)
    document = candidate.to_evidence()
    document["signing"] = {"required": True, "satisfied": False}
    with pytest.raises(CandidatePolicyError) as raised:
        _publish(document, tmp_path)
    assert raised.value.code == "candidate-signing-inconsistent"


def test_publish_rejects_evidence_from_another_commit(tmp_path: Path) -> None:
    candidate, _ = _candidate(tmp_path)
    with pytest.raises(CandidatePolicyError) as raised:
        _publish(candidate.to_evidence(), tmp_path, commit="b" * 40)
    assert raised.value.code == "candidate-commit-mismatch"


@pytest.mark.parametrize(
    "tamper,expected",
    [
        (lambda path: path.write_bytes(b"TAMPERED-CONTENT"), "size-mismatch"),
        (lambda path: path.write_bytes(b"X" * path.stat().st_size), "hash-mismatch"),
        (lambda path: path.unlink(), "missing-artifact"),
    ],
)
def test_publish_hashes_the_release_files(
    tmp_path: Path, tamper, expected: str
) -> None:
    candidate, files = _candidate(tmp_path)
    tamper(files[candidate.artifacts[0].artifact_id])
    with pytest.raises(CandidatePolicyError) as raised:
        _publish(candidate.to_evidence(), tmp_path)
    assert raised.value.code == expected


def test_publish_rejects_evidence_without_artifacts(tmp_path: Path) -> None:
    candidate, _ = _candidate(tmp_path)
    document = candidate.to_evidence()
    document["artifacts"] = []
    document["digest"] = candidate_digest(())
    with pytest.raises(CandidatePolicyError) as raised:
        _publish(document, tmp_path)
    assert raised.value.code == "evidence-invalid"


def test_publish_rejects_duplicate_evidence_filenames(tmp_path: Path) -> None:
    candidate, _ = _candidate(tmp_path)
    document = candidate.to_evidence()
    duplicate = dict(document["artifacts"][0], artifact_id="second-id")
    document["artifacts"].append(duplicate)
    with pytest.raises(CandidatePolicyError) as raised:
        _publish(document, tmp_path)
    assert raised.value.code == "duplicate-artifacts"


@pytest.mark.parametrize(
    "filename", ["../servonaut-0.tar.gz", "nested/servonaut-0.tar.gz", "..", "a\\b"]
)
def test_release_files_are_looked_up_by_plain_name_only(
    tmp_path: Path, filename: str
) -> None:
    candidate, _ = _candidate(tmp_path / "files")
    document = candidate.to_evidence()
    document["artifacts"][0]["filename"] = filename
    document["digest"] = candidate_digest(
        candidate_from_evidence(document).artifacts
    )
    with pytest.raises(CandidatePolicyError) as raised:
        _publish(document, tmp_path / "files")
    assert raised.value.code == "invalid-artifact-name"


def _cli_check_publish(
    evidence: Path, artifacts: Path, *, tag: str = "v2.27.0", commit: str = "a" * 40
) -> int:
    return main(
        [
            "check-publish",
            "--evidence",
            str(evidence),
            "--artifacts-dir",
            str(artifacts),
            "--tag",
            tag,
            "--commit",
            commit,
        ]
    )


def test_cli_plan_verify_and_check_publish(tmp_path: Path) -> None:
    root = _package_tree(tmp_path / "repo")
    artifacts = tmp_path / "artifacts"
    manifest_path, _ = _manifest_file(artifacts)
    evidence = tmp_path / "evidence.json"

    assert _cli_plan(manifest_path, artifacts, root, evidence) == 0
    digest = json.loads(evidence.read_text(encoding="utf-8"))["digest"]
    assert _cli_verify(evidence, artifacts, root, digest) == 0
    assert _cli_check_publish(evidence, artifacts) == 0
    assert _cli_check_publish(evidence, artifacts, tag="v2.27.1") == 1
    assert _cli_check_publish(evidence, artifacts, commit="b" * 40) == 1


def test_cli_stages_hash_the_real_artifact_files(tmp_path: Path) -> None:
    root = _package_tree(tmp_path / "repo")
    artifacts = tmp_path / "artifacts"
    manifest_path, files = _manifest_file(artifacts)
    evidence = tmp_path / "evidence.json"
    assert _cli_plan(manifest_path, artifacts, root, evidence) == 0
    digest = json.loads(evidence.read_text(encoding="utf-8"))["digest"]

    for path in files.values():
        path.write_bytes(b"X" * path.stat().st_size)

    assert _cli_plan(manifest_path, artifacts, root, tmp_path / "other.json") == 1
    assert _cli_verify(evidence, artifacts, root, digest) == 1
    assert _cli_check_publish(evidence, artifacts) == 1


@pytest.mark.parametrize(
    "argv",
    [
        ["plan", "--manifest", "m.json", "--tag", "v2.27.0", "--commit", "a" * 40],
        ["verify", "--evidence", "e.json", "--expected-digest", "0" * 64],
        ["check-publish", "--evidence", "e.json", "--tag", "v2.27.0", "--commit", "a" * 40],
    ],
)
def test_cli_stages_require_the_artifact_files(argv: list[str], capsys) -> None:
    with pytest.raises(SystemExit) as raised:
        main(argv)
    assert raised.value.code == 2
    assert "--artifacts-dir" in capsys.readouterr().err


def test_cli_check_publish_requires_the_released_commit(capsys) -> None:
    with pytest.raises(SystemExit) as raised:
        main(
            [
                "check-publish",
                "--evidence",
                "e.json",
                "--artifacts-dir",
                "artifacts",
                "--tag",
                "v2.27.0",
            ]
        )
    assert raised.value.code == 2
    assert "--commit" in capsys.readouterr().err


def test_cli_check_publish_rejects_hand_written_evidence(
    tmp_path: Path, capsys
) -> None:
    """Evidence that no candidate run produced must not authorize a publish."""
    release_file = tmp_path / "servonaut.tar.gz"
    release_file.write_bytes(b"PAYLOAD")
    artifact = {
        "artifact_id": "x",
        "filename": release_file.name,
        "byte_size": 1,
        "sha256": "0" * 64,
        "signature": "x",
    }
    document = {
        "schema_version": 2,
        "channel": "stable",
        "tag": "v2.27.0",
        "product_version": "2.27.0",
        "source_commit": "not-a-commit",
        "artifacts": [artifact],
        "signing": {"required": True, "satisfied": True},
    }
    document["digest"] = candidate_digest([CandidateArtifact(**artifact)])
    evidence = tmp_path / "candidate-evidence.json"
    evidence.write_bytes(canonicalize_json(document) + b"\n")

    assert _cli_check_publish(evidence, tmp_path) == 1
    document["source_commit"] = "a" * 40
    evidence.write_bytes(canonicalize_json(document) + b"\n")
    assert _cli_check_publish(evidence, tmp_path) == 1
    assert "::error::" in capsys.readouterr().err


def test_cli_plan_rejects_version_drift(tmp_path: Path, capsys) -> None:
    root = _package_tree(tmp_path / "repo", version="2.28.0")
    artifacts = tmp_path / "artifacts"
    manifest_path, _ = _manifest_file(artifacts)
    assert _cli_plan(manifest_path, artifacts, root, None) == 1
    assert "::error::" in capsys.readouterr().err


@pytest.mark.parametrize(
    "tag,channel",
    [
        ("v2.27.0", ReleaseChannel.STABLE),
        ("v2.27.0-preview.1", ReleaseChannel.PREVIEW),
    ],
)
def test_channel_for_tag_maps_only_valid_tags(
    tag: str, channel: ReleaseChannel
) -> None:
    assert channel_for_tag(tag) is channel


@pytest.mark.parametrize(
    "tag",
    ["2.27.0", "v2.27", "v2.27.0-rc.1", "v2.27.0-preview.0", "v2.27.0-preview.x", ""],
)
def test_channel_for_tag_rejects_non_channel_tags(tag: str) -> None:
    with pytest.raises(CandidatePolicyError) as raised:
        channel_for_tag(tag)
    assert raised.value.code == "invalid-tag"


def _preview_candidate(tmp_path: Path, *, signed: bool = True) -> ReleaseCandidate:
    tmp_path.mkdir(parents=True, exist_ok=True)
    artifact = tmp_path / "servonaut-preview.tar.gz"
    artifact.write_bytes(b"PREVIEW-PAYLOAD")
    builder = ManifestBuilder(
        product_version="2.27.0", channel=ReleaseChannel.PREVIEW
    )
    record = builder.add_artifact_file(
        artifact,
        kind=ArtifactKind.STANDALONE_CLI,
        distribution=DistributionKind.FROZEN_CLI,
        platform="linux",
        arch="x86_64",
        download_url="https://example.com/servonaut-preview.tar.gz",
    )
    if signed:
        builder.sign_artifact(record.artifact_id, Ed25519PrivateKey.generate())
    return plan_candidate(
        builder.build(),
        tag="v2.27.0-preview.3",
        source_commit="b" * 40,
        requires_signing=signed,
    )


def test_preview_candidate_keeps_target_product_version(tmp_path: Path) -> None:
    candidate = _preview_candidate(tmp_path)
    assert candidate.channel is ReleaseChannel.PREVIEW
    assert candidate.product_version == "2.27.0"
    document = candidate.to_evidence()
    assert document["channel"] == "preview"
    assert document["tag"] == "v2.27.0-preview.3"


def test_preview_candidate_can_authorize_preview_publishing(tmp_path: Path) -> None:
    candidate = _preview_candidate(tmp_path)
    _publish(
        candidate.to_evidence(),
        tmp_path,
        tag="v2.27.0-preview.3",
        channel=ReleaseChannel.PREVIEW,
        commit="b" * 40,
    )


def test_unsigned_preview_candidate_can_authorize_preview_publishing(
    tmp_path: Path,
) -> None:
    candidate = _preview_candidate(tmp_path, signed=False)
    assert candidate.to_evidence()["signing"] == {"required": False, "satisfied": False}
    _publish(
        candidate.to_evidence(),
        tmp_path,
        tag="v2.27.0-preview.3",
        channel=ReleaseChannel.PREVIEW,
        commit="b" * 40,
    )


def test_preview_candidate_never_authorizes_stable_publishing(tmp_path: Path) -> None:
    candidate = _preview_candidate(tmp_path)
    with pytest.raises(CandidatePolicyError) as raised:
        _publish(
            candidate.to_evidence(), tmp_path, tag="v2.27.0-preview.3", commit="b" * 40
        )
    assert raised.value.code == "candidate-channel-mismatch"


def test_stable_candidate_never_authorizes_preview_publishing(tmp_path: Path) -> None:
    candidate, _ = _candidate(tmp_path)
    with pytest.raises(CandidatePolicyError) as raised:
        _publish(candidate.to_evidence(), tmp_path, channel=ReleaseChannel.PREVIEW)
    assert raised.value.code == "candidate-channel-mismatch"


def test_plan_rejects_tag_and_manifest_channel_mismatch(tmp_path: Path) -> None:
    manifest, _ = _manifest(tmp_path)  # stable manifest
    with pytest.raises(CandidatePolicyError) as raised:
        plan_candidate(
            manifest, tag="v2.27.0-preview.1", source_commit="a" * 40
        )
    assert raised.value.code == "channel-manifest-mismatch"


def test_plan_rejects_explicit_channel_override_mismatch(tmp_path: Path) -> None:
    manifest, _ = _manifest(tmp_path)
    with pytest.raises(CandidatePolicyError) as raised:
        plan_candidate(
            manifest,
            tag="v2.27.0",
            source_commit="a" * 40,
            channel=ReleaseChannel.PREVIEW,
        )
    assert raised.value.code == "channel-tag-mismatch"


def test_preview_evidence_cannot_be_relabelled_stable(tmp_path: Path) -> None:
    candidate = _preview_candidate(tmp_path)
    document = candidate.to_evidence()
    document["channel"] = ReleaseChannel.STABLE.value
    with pytest.raises(CandidatePolicyError) as raised:
        _publish(document, tmp_path, tag="v2.27.0-preview.3", commit="b" * 40)
    assert raised.value.code == "candidate-missing"


def test_evidence_with_unknown_channel_is_malformed(tmp_path: Path) -> None:
    candidate, _ = _candidate(tmp_path)
    document = candidate.to_evidence()
    document["channel"] = "beta"
    path = tmp_path / "evidence.json"
    path.write_bytes(canonicalize_json(document) + b"\n")
    with pytest.raises(CandidatePolicyError) as raised:
        load_evidence(path)
    assert raised.value.code == "evidence-invalid"


def test_old_schema_version_evidence_is_rejected(tmp_path: Path) -> None:
    candidate, _ = _candidate(tmp_path)
    document = candidate.to_evidence()
    document["schema_version"] = 1
    path = tmp_path / "evidence.json"
    path.write_bytes(canonicalize_json(document) + b"\n")
    with pytest.raises(CandidatePolicyError) as raised:
        load_evidence(path)
    assert raised.value.code == "evidence-invalid"
