"""Candidate-first release policy: deterministic identity and fail-closed verification.

Phase 6 replaces publish-first release automation with a candidate-first state
machine. This module is the read-only policy core: it turns a validated release
manifest into a *candidate* with a deterministic digest, and verifies that a
candidate being published is exactly the one that was built, smoke-tested,
signed and reviewed. It performs no network access and mutates nothing.

The plan, verify and check-publish commands all hash the real artifact files:
their sizes and SHA-256 digests must match the candidate. Artifact signatures
are checked for presence only.
The detached-signature format is not defined yet, so a non-empty signature
field counts as signed and no signature is verified cryptographically here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from servonaut.distribution.artifact_marker import (
    ArtifactMarkerError,
    identity_mismatches,
    read_artifact_marker,
)
from servonaut.distribution.manifest import (
    ManifestError,
    ReleaseChannel,
    ReleaseManifest,
    canonicalize_json,
)

STABLE_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
PREVIEW_TAG = re.compile(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-preview\.[1-9][0-9]*"
)

_PYPROJECT_VERSION = re.compile(r'^version = "([0-9]+\.[0-9]+\.[0-9]+)"$', re.MULTILINE)
_INIT_VERSION = re.compile(
    r"^__version__ = ['\"]([0-9]+\.[0-9]+\.[0-9]+)['\"]$", re.MULTILINE
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_MAX_BYTES = 1_000_000
_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "channel",
        "tag",
        "product_version",
        "source_commit",
        "digest",
        "artifacts",
        "signing",
    }
)
_ARTIFACT_FIELDS = frozenset(
    {"artifact_id", "filename", "byte_size", "sha256", "signature"}
)
_SIGNING_FIELDS = frozenset({"required", "satisfied"})
_EVIDENCE_SCHEMA_VERSION = 2


class CandidatePolicyError(ManifestError):
    """A candidate-policy failure with a stable, public-logs-safe reason code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def channel_for_tag(tag: str) -> ReleaseChannel:
    """Map a candidate tag to its release channel, rejecting anything else."""
    if not isinstance(tag, str):
        raise CandidatePolicyError(
            "invalid-tag", "The candidate tag must be a string."
        )
    if STABLE_TAG.fullmatch(tag) is not None:
        return ReleaseChannel.STABLE
    if PREVIEW_TAG.fullmatch(tag) is not None:
        return ReleaseChannel.PREVIEW
    raise CandidatePolicyError(
        "invalid-tag",
        "The candidate tag must be a stable vX.Y.Z or preview vX.Y.Z-preview.N tag.",
    )


def tag_product_version(tag: str) -> str:
    """The product version a candidate tag targets (minus any preview suffix)."""
    channel_for_tag(tag)
    return tag[1:].split("-", 1)[0]


@dataclass(frozen=True, slots=True)
class CandidateArtifact:
    """A single artifact's immutable identity within a candidate."""

    artifact_id: str
    filename: str
    byte_size: int
    sha256: str
    signature: Optional[str]

    @property
    def is_signed(self) -> bool:
        """Whether the artifact carries a signature (presence only, not verified)."""
        return bool(self.signature)


@dataclass(frozen=True, slots=True)
class ReleaseCandidate:
    """A release candidate identified by tag, channel, commit and artifact digest."""

    tag: str
    channel: ReleaseChannel
    product_version: str
    source_commit: str
    digest: str
    artifacts: tuple[CandidateArtifact, ...]
    requires_signing: bool

    @property
    def signing_satisfied(self) -> bool:
        """Whether every artifact carries a signature; derived, never declared."""
        return bool(self.artifacts) and all(
            artifact.is_signed for artifact in self.artifacts
        )

    def to_evidence(self) -> dict[str, Any]:
        """Render the public candidate-evidence document."""
        return {
            "schema_version": _EVIDENCE_SCHEMA_VERSION,
            "channel": self.channel.value,
            "tag": self.tag,
            "product_version": self.product_version,
            "source_commit": self.source_commit,
            "digest": self.digest,
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "filename": artifact.filename,
                    "byte_size": artifact.byte_size,
                    "sha256": artifact.sha256,
                    "signature": artifact.signature,
                }
                for artifact in self.artifacts
            ],
            "signing": {
                "required": self.requires_signing,
                "satisfied": self.signing_satisfied,
            },
        }


def _candidate_artifacts(manifest: ReleaseManifest) -> tuple[CandidateArtifact, ...]:
    artifacts = tuple(
        CandidateArtifact(
            artifact_id=artifact.artifact_id,
            filename=artifact.filename,
            byte_size=artifact.byte_size,
            sha256=artifact.sha256.lower(),
            signature=artifact.signature,
        )
        for artifact in manifest.artifacts
    )
    _reject_duplicate_filenames(artifacts)
    return tuple(sorted(artifacts, key=lambda artifact: artifact.artifact_id))


def _reject_duplicate_filenames(artifacts: Sequence[CandidateArtifact]) -> None:
    filenames = [artifact.filename for artifact in artifacts]
    if len(set(filenames)) != len(filenames):
        raise CandidatePolicyError(
            "duplicate-artifacts", "Candidate declares duplicate artifact filenames."
        )


def candidate_digest(artifacts: Sequence[CandidateArtifact]) -> str:
    """Hash the artifact identities in a deterministic, build-order-independent way."""
    payload = [
        {
            "artifact_id": artifact.artifact_id,
            "filename": artifact.filename,
            "byte_size": artifact.byte_size,
            "sha256": artifact.sha256,
        }
        for artifact in sorted(artifacts, key=lambda item: item.artifact_id)
    ]
    return hashlib.sha256(canonicalize_json(payload)).hexdigest()


def _read_package_version(root: Path) -> str:
    pyproject = root / "pyproject.toml"
    init = root / "src" / "servonaut" / "__init__.py"
    try:
        pyproject_matches = _PYPROJECT_VERSION.findall(
            pyproject.read_text(encoding="utf-8")
        )
        init_matches = _INIT_VERSION.findall(init.read_text(encoding="utf-8"))
    except OSError as error:
        raise CandidatePolicyError(
            "version-unreadable", "Could not read the package version files."
        ) from error
    if len(pyproject_matches) != 1 or len(init_matches) != 1:
        raise CandidatePolicyError(
            "version-ambiguous", "Expected exactly one version in each package file."
        )
    if pyproject_matches[0] != init_matches[0]:
        raise CandidatePolicyError(
            "version-mismatch", "pyproject.toml and __init__.py versions disagree."
        )
    return pyproject_matches[0]


def plan_candidate(
    manifest: ReleaseManifest,
    *,
    tag: str,
    source_commit: str,
    artifact_files: Mapping[str, Path],
    requires_signing: bool = True,
    channel: Optional[ReleaseChannel] = None,
) -> ReleaseCandidate:
    """Create a candidate from a validated manifest, failing closed on mismatches.

    Every artifact file must match the manifest, and the runtime marker inside
    it must name the tag's release channel and the manifest's packaging
    revision, so an update check orders the released build correctly.
    """
    tag_channel = channel_for_tag(tag)
    if channel is not None and channel is not tag_channel:
        raise CandidatePolicyError(
            "channel-tag-mismatch",
            "The requested channel does not match the candidate tag.",
        )
    if manifest.channel is not tag_channel:
        raise CandidatePolicyError(
            "channel-manifest-mismatch",
            "The candidate tag and manifest release channel disagree.",
        )
    if not source_commit or not isinstance(source_commit, str):
        raise CandidatePolicyError(
            "invalid-commit", "The candidate source commit must be a non-empty string."
        )
    if tag_product_version(tag) != manifest.product_version:
        raise CandidatePolicyError(
            "version-tag-mismatch",
            "The candidate tag and manifest product version disagree.",
        )
    artifacts = _candidate_artifacts(manifest)
    if not artifacts:
        raise CandidatePolicyError(
            "no-artifacts", "A candidate must declare at least one artifact."
        )
    verify_artifact_files(artifacts, artifact_files)
    _require_marker_identity(manifest, tag_channel, artifact_files)
    return ReleaseCandidate(
        tag=tag,
        channel=tag_channel,
        product_version=manifest.product_version,
        source_commit=source_commit,
        digest=candidate_digest(artifacts),
        artifacts=artifacts,
        requires_signing=bool(requires_signing),
    )


def _require_marker_identity(
    manifest: ReleaseManifest,
    channel: ReleaseChannel,
    artifact_files: Mapping[str, Path],
) -> None:
    """Require each artifact's runtime marker to match the tag and the manifest."""
    revision = manifest.packaging_revision
    if revision is None:
        raise CandidatePolicyError(
            "revision-missing",
            "The manifest must state the packaging revision its artifacts carry.",
        )
    for artifact in manifest.artifacts:
        try:
            marker = read_artifact_marker(
                artifact, Path(artifact_files[artifact.artifact_id])
            )
        except ArtifactMarkerError as error:
            raise CandidatePolicyError(
                "marker-unreadable",
                "A candidate artifact's runtime marker could not be verified.",
            ) from error
        mismatches = identity_mismatches(
            marker,
            artifact=artifact,
            product_version=manifest.product_version,
            channel=channel.value,
            packaging_revision=revision,
        )
        if "channel" in mismatches:
            raise CandidatePolicyError(
                "marker-channel-mismatch",
                "A candidate artifact was built for a different release channel.",
            )
        if "packaging_revision" in mismatches:
            raise CandidatePolicyError(
                "marker-revision-mismatch",
                "A candidate artifact carries a different packaging revision.",
            )
        if mismatches:
            raise CandidatePolicyError(
                "marker-mismatch",
                "A candidate artifact's runtime marker does not match the release.",
            )


def _artifact_path(directory: Path, filename: str) -> Path:
    """Locate an artifact file by its plain file name inside a directory."""
    if (
        not isinstance(filename, str)
        or filename in {"", ".", ".."}
        or any(separator in filename for separator in ("/", "\\", "\x00"))
    ):
        raise CandidatePolicyError(
            "invalid-artifact-name",
            "A candidate artifact filename is not a plain file name.",
        )
    return directory / filename


def artifact_files_in(
    directory: Path, artifacts: Sequence[CandidateArtifact]
) -> dict[str, Path]:
    """Map each artifact id to its file in a directory of release files."""
    return {
        artifact.artifact_id: _artifact_path(directory, artifact.filename)
        for artifact in artifacts
    }


def _file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(64 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_artifact_files(
    artifacts: Sequence[CandidateArtifact], artifact_files: Mapping[str, Path]
) -> None:
    """Fail closed unless every artifact file exists with its recorded size and digest."""
    for artifact in artifacts:
        path = artifact_files.get(artifact.artifact_id)
        if path is None:
            raise CandidatePolicyError(
                "missing-artifact",
                "A candidate artifact file was not provided for verification.",
            )
        resolved = Path(path)
        if not resolved.is_file():
            raise CandidatePolicyError(
                "missing-artifact", "A candidate artifact file does not exist."
            )
        if resolved.stat().st_size != artifact.byte_size:
            raise CandidatePolicyError(
                "size-mismatch", "A candidate artifact size has changed."
            )
        if _file_sha256(resolved) != artifact.sha256:
            raise CandidatePolicyError(
                "hash-mismatch", "A candidate artifact digest has changed."
            )


def verify_candidate(
    candidate: ReleaseCandidate,
    *,
    expected_digest: str,
    root: Path,
    artifact_files: Mapping[str, Path],
) -> None:
    """Fail closed unless the candidate's files are intact, version-matched and signed.

    Signing is enforced only when the candidate requires it, and only as the
    presence of a signature on every artifact.
    """
    if not isinstance(expected_digest, str) or _SHA256.fullmatch(expected_digest) is None:
        raise CandidatePolicyError(
            "invalid-digest", "The expected candidate digest is not a valid SHA-256."
        )
    recomputed = candidate_digest(candidate.artifacts)
    if recomputed != expected_digest or recomputed != candidate.digest:
        raise CandidatePolicyError(
            "digest-changed",
            "The candidate artifact set no longer matches its approved digest.",
        )
    package_version = _read_package_version(root)
    if package_version != candidate.product_version:
        raise CandidatePolicyError(
            "version-mismatch",
            "The candidate product version does not match the checked-out package.",
        )
    if candidate.channel is not channel_for_tag(candidate.tag):
        raise CandidatePolicyError(
            "channel-tag-mismatch",
            "The candidate tag and channel disagree.",
        )
    if candidate.requires_signing and not candidate.signing_satisfied:
        raise CandidatePolicyError(
            "unsigned-artifact",
            "Signing was required but at least one candidate artifact is unsigned.",
        )
    verify_artifact_files(candidate.artifacts, artifact_files)


def load_evidence(path: Path) -> dict[str, Any]:
    """Load and structurally validate a public candidate-evidence document."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CandidatePolicyError(
            "evidence-unreadable", "The candidate evidence file could not be read."
        ) from error
    if not raw or len(raw) > _EVIDENCE_MAX_BYTES:
        raise CandidatePolicyError(
            "evidence-invalid", "The candidate evidence file has an invalid size."
        )
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as error:
        raise CandidatePolicyError(
            "evidence-invalid", "The candidate evidence file is not valid JSON."
        ) from error
    if (
        not isinstance(document, dict)
        or set(document) != _EVIDENCE_FIELDS
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != _EVIDENCE_SCHEMA_VERSION
        or not isinstance(document.get("artifacts"), list)
        or not isinstance(document.get("signing"), dict)
        or set(document["signing"]) != _SIGNING_FIELDS
    ):
        raise CandidatePolicyError(
            "evidence-invalid", "The candidate evidence document is malformed."
        )
    try:
        ReleaseChannel(document["channel"])
    except (KeyError, ValueError) as error:
        raise CandidatePolicyError(
            "evidence-invalid", "The candidate evidence channel is malformed."
        ) from error
    return document


def evidence_matches_tag(document: Mapping[str, Any], tag: str) -> bool:
    """Whether a validated evidence document belongs to the given tag and channel."""
    digest = document.get("digest")
    try:
        channel = channel_for_tag(tag)
    except CandidatePolicyError:
        return False
    return (
        document.get("tag") == tag
        and document.get("channel") == channel.value
        and document.get("product_version") == tag_product_version(tag)
        and isinstance(digest, str)
        and _SHA256.fullmatch(digest) is not None
    )


def _is_valid_evidence_artifact(artifact: CandidateArtifact) -> bool:
    return (
        isinstance(artifact.artifact_id, str)
        and isinstance(artifact.filename, str)
        and type(artifact.byte_size) is int
        and artifact.byte_size > 0
        and isinstance(artifact.sha256, str)
        and _SHA256.fullmatch(artifact.sha256) is not None
        and (artifact.signature is None or isinstance(artifact.signature, str))
    )


def _evidence_artifacts(entries: Any) -> tuple[CandidateArtifact, ...]:
    try:
        if any(
            not isinstance(entry, Mapping) or set(entry) != _ARTIFACT_FIELDS
            for entry in entries
        ):
            raise CandidatePolicyError(
                "evidence-invalid", "The candidate evidence artifacts are malformed."
            )
        artifacts = tuple(
            CandidateArtifact(
                artifact_id=entry["artifact_id"],
                filename=entry["filename"],
                byte_size=entry["byte_size"],
                sha256=entry["sha256"],
                signature=entry.get("signature"),
            )
            for entry in entries
        )
    except (KeyError, TypeError) as error:
        raise CandidatePolicyError(
            "evidence-invalid", "The candidate evidence artifacts are malformed."
        ) from error
    if not artifacts or not all(map(_is_valid_evidence_artifact, artifacts)):
        raise CandidatePolicyError(
            "evidence-invalid", "The candidate evidence artifacts are malformed."
        )
    _reject_duplicate_filenames(artifacts)
    return tuple(sorted(artifacts, key=lambda item: item.artifact_id))


def candidate_from_evidence(document: Mapping[str, Any]) -> ReleaseCandidate:
    """Rebuild a ReleaseCandidate from a validated public evidence document."""
    artifacts = _evidence_artifacts(document["artifacts"])
    signing = document["signing"]
    if type(signing.get("required")) is not bool or type(signing.get("satisfied")) is not bool:
        raise CandidatePolicyError(
            "evidence-invalid", "The candidate evidence signing block is malformed."
        )
    source_commit = document["source_commit"]
    if not isinstance(source_commit, str) or not source_commit:
        raise CandidatePolicyError(
            "evidence-invalid", "The candidate evidence source commit is malformed."
        )
    return ReleaseCandidate(
        tag=document["tag"],
        channel=ReleaseChannel(document["channel"]),
        product_version=document["product_version"],
        source_commit=source_commit,
        digest=document["digest"],
        artifacts=artifacts,
        requires_signing=signing["required"],
    )


def _ensure_signing_proven(
    document: Mapping[str, Any], candidate: ReleaseCandidate
) -> None:
    """Derive signing from the artifacts; the declared flag must agree with it."""
    if candidate.channel is ReleaseChannel.STABLE and not candidate.requires_signing:
        raise CandidatePolicyError(
            "candidate-signing-not-required",
            "A stable candidate must require artifact signing.",
        )
    if candidate.requires_signing and not candidate.signing_satisfied:
        raise CandidatePolicyError(
            "candidate-unsigned",
            "The candidate evidence does not prove the required artifact signing.",
        )
    if document["signing"]["satisfied"] is not candidate.signing_satisfied:
        raise CandidatePolicyError(
            "candidate-signing-inconsistent",
            "The candidate evidence signing status does not match its artifacts.",
        )


def ensure_publishable(
    document: Mapping[str, Any],
    tag: str,
    *,
    channel: ReleaseChannel,
    source_commit: str,
    artifacts_dir: Path,
) -> None:
    """Fail closed unless a tag's candidate evidence permits publishing on a channel.

    A preview candidate can never authorize a stable publish, and vice versa.
    The evidence must come from the commit being released, a stable candidate
    must require signing, and every release file must still match the size and
    digest the candidate recorded.
    """
    if not evidence_matches_tag(document, tag):
        raise CandidatePolicyError(
            "candidate-missing",
            "No verified candidate evidence matches this release tag.",
        )
    candidate = candidate_from_evidence(document)
    if candidate.channel is not channel:
        raise CandidatePolicyError(
            "candidate-channel-mismatch",
            "The candidate evidence belongs to a different release channel.",
        )
    if candidate.source_commit != source_commit:
        raise CandidatePolicyError(
            "candidate-commit-mismatch",
            "The candidate evidence was not built from the commit being released.",
        )
    _ensure_signing_proven(document, candidate)
    if candidate_digest(candidate.artifacts) != candidate.digest:
        raise CandidatePolicyError(
            "candidate-digest-mismatch",
            "The candidate evidence digest does not match its artifacts.",
        )
    verify_artifact_files(
        candidate.artifacts, artifact_files_in(artifacts_dir, candidate.artifacts)
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    artifacts_help = "Directory holding the release files named by the candidate"

    plan = commands.add_parser("plan", help="Build a candidate and emit its digest")
    plan.add_argument("--manifest", type=Path, required=True)
    plan.add_argument("--artifacts-dir", type=Path, required=True, help=artifacts_help)
    plan.add_argument("--tag", required=True)
    plan.add_argument("--commit", required=True)
    plan.add_argument("--repo", type=Path, default=Path("."))
    plan.add_argument("--evidence-out", type=Path)
    plan.add_argument(
        "--channel",
        choices=("stable", "preview"),
        default=None,
        help="Assert the candidate channel; must agree with the tag when given",
    )
    plan.add_argument(
        "--require-signing",
        choices=("true", "false"),
        default="true",
        help="Whether every artifact must carry a detached signature to publish",
    )

    verify = commands.add_parser("verify", help="Fail unless a candidate is intact")
    verify.add_argument("--evidence", type=Path, required=True)
    verify.add_argument("--artifacts-dir", type=Path, required=True, help=artifacts_help)
    verify.add_argument("--expected-digest", required=True)
    verify.add_argument("--repo", type=Path, default=Path("."))

    publish = commands.add_parser(
        "check-publish", help="Gate publishing on candidate evidence for a channel"
    )
    publish.add_argument("--evidence", type=Path, required=True)
    publish.add_argument("--artifacts-dir", type=Path, required=True, help=artifacts_help)
    publish.add_argument("--tag", required=True)
    publish.add_argument(
        "--commit",
        required=True,
        help="The commit being released; the candidate must have been built from it",
    )
    publish.add_argument(
        "--channel",
        choices=("stable", "preview"),
        default="stable",
        help="The channel being published; stable never accepts preview evidence",
    )
    return parser


def _run_plan(args: argparse.Namespace) -> None:
    manifest = ReleaseManifest.from_json(args.manifest.read_bytes())
    requested = ReleaseChannel(args.channel) if args.channel else None
    candidate = plan_candidate(
        manifest,
        tag=args.tag,
        source_commit=args.commit,
        artifact_files=artifact_files_in(
            args.artifacts_dir, _candidate_artifacts(manifest)
        ),
        requires_signing=args.require_signing == "true",
        channel=requested,
    )
    package_version = _read_package_version(args.repo)
    if package_version != candidate.product_version:
        raise CandidatePolicyError(
            "version-mismatch",
            "The candidate product version does not match the checked-out package.",
        )
    if args.evidence_out is not None:
        args.evidence_out.write_bytes(canonicalize_json(candidate.to_evidence()) + b"\n")
    print(f"tag={candidate.tag}")
    print(f"channel={candidate.channel.value}")
    print(f"product_version={candidate.product_version}")
    print(f"digest={candidate.digest}")
    print(f"artifacts={len(candidate.artifacts)}")


def _run_verify(args: argparse.Namespace) -> None:
    candidate = candidate_from_evidence(load_evidence(args.evidence))
    verify_candidate(
        candidate,
        expected_digest=args.expected_digest,
        root=args.repo,
        artifact_files=artifact_files_in(args.artifacts_dir, candidate.artifacts),
    )
    print("candidate=verified")


def _run_check_publish(args: argparse.Namespace) -> None:
    ensure_publishable(
        load_evidence(args.evidence),
        args.tag,
        channel=ReleaseChannel(args.channel),
        source_commit=args.commit,
        artifacts_dir=args.artifacts_dir,
    )
    print("candidate=verified")


_COMMANDS = {
    "plan": _run_plan,
    "verify": _run_verify,
    "check-publish": _run_check_publish,
}


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        _COMMANDS[args.command](args)
        return 0
    except CandidatePolicyError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, ManifestError):
        # Manifest/evidence data must not leak into public workflow logs.
        print(
            "::error::Release candidate check failed. Check the manifest, evidence, release files and package versions.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
