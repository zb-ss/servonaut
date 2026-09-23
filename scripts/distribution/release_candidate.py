"""Candidate-first release policy: deterministic identity and fail-closed verification.

Phase 6 replaces publish-first release automation with a candidate-first state
machine. This module is the read-only policy core: it turns a validated release
manifest into a *candidate* with a deterministic digest, and verifies that a
candidate being published is exactly the one that was built, smoke-tested,
signed and reviewed. It performs no network access and mutates nothing.
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

from servonaut.distribution.manifest import (
    ManifestError,
    ReleaseManifest,
    canonicalize_json,
)

STABLE_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")

_PYPROJECT_VERSION = re.compile(r'^version = "([0-9]+\.[0-9]+\.[0-9]+)"$', re.MULTILINE)
_INIT_VERSION = re.compile(
    r"^__version__ = ['\"]([0-9]+\.[0-9]+\.[0-9]+)['\"]$", re.MULTILINE
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_MAX_BYTES = 1_000_000
_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
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


class CandidatePolicyError(ManifestError):
    """A candidate-policy failure with a stable, public-logs-safe reason code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


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
        return bool(self.signature)


@dataclass(frozen=True, slots=True)
class ReleaseCandidate:
    """A release candidate identified by tag, source commit and artifact digest."""

    tag: str
    product_version: str
    source_commit: str
    digest: str
    artifacts: tuple[CandidateArtifact, ...]
    requires_signing: bool

    def to_evidence(self) -> dict[str, Any]:
        """Render the public candidate-evidence document."""
        satisfied = all(artifact.is_signed for artifact in self.artifacts)
        return {
            "schema_version": 1,
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
            "signing": {"required": self.requires_signing, "satisfied": satisfied},
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
    filenames = [artifact.filename for artifact in artifacts]
    if len(set(filenames)) != len(filenames):
        raise CandidatePolicyError(
            "duplicate-artifacts", "Candidate declares duplicate artifact filenames."
        )
    return tuple(sorted(artifacts, key=lambda artifact: artifact.artifact_id))


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
    requires_signing: bool = True,
) -> ReleaseCandidate:
    """Create a candidate from a validated manifest, failing closed on mismatches."""
    if not isinstance(tag, str) or STABLE_TAG.fullmatch(tag) is None:
        raise CandidatePolicyError(
            "invalid-tag", "The candidate tag must be a stable vX.Y.Z tag."
        )
    if not source_commit or not isinstance(source_commit, str):
        raise CandidatePolicyError(
            "invalid-commit", "The candidate source commit must be a non-empty string."
        )
    if tag[1:] != manifest.product_version:
        raise CandidatePolicyError(
            "version-tag-mismatch",
            "The candidate tag and manifest product version disagree.",
        )
    artifacts = _candidate_artifacts(manifest)
    if not artifacts:
        raise CandidatePolicyError(
            "no-artifacts", "A candidate must declare at least one artifact."
        )
    return ReleaseCandidate(
        tag=tag,
        product_version=manifest.product_version,
        source_commit=source_commit,
        digest=candidate_digest(artifacts),
        artifacts=artifacts,
        requires_signing=bool(requires_signing),
    )


def verify_candidate(
    candidate: ReleaseCandidate,
    *,
    expected_digest: str,
    root: Path,
    artifact_files: Optional[Mapping[str, Path]] = None,
) -> None:
    """Fail closed unless the candidate is intact, version-matched and (if required) signed."""
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
    if candidate.requires_signing and not all(
        artifact.is_signed for artifact in candidate.artifacts
    ):
        raise CandidatePolicyError(
            "unsigned-artifact",
            "Signing was required but at least one candidate artifact is unsigned.",
        )
    if artifact_files is not None:
        for artifact in candidate.artifacts:
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
            hasher = hashlib.sha256()
            with open(resolved, "rb") as stream:
                while chunk := stream.read(64 * 1024):
                    hasher.update(chunk)
            if hasher.hexdigest() != artifact.sha256:
                raise CandidatePolicyError(
                    "hash-mismatch", "A candidate artifact digest has changed."
                )


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
        or document["schema_version"] != 1
        or not isinstance(document.get("artifacts"), list)
        or not isinstance(document.get("signing"), dict)
        or set(document["signing"]) != _SIGNING_FIELDS
    ):
        raise CandidatePolicyError(
            "evidence-invalid", "The candidate evidence document is malformed."
        )
    return document


def evidence_matches_tag(document: Mapping[str, Any], tag: str) -> bool:
    """Whether a validated evidence document belongs to the given stable tag."""
    digest = document.get("digest")
    return (
        document.get("tag") == tag
        and document.get("product_version") == tag[1:]
        and isinstance(digest, str)
        and _SHA256.fullmatch(digest) is not None
    )


def candidate_from_evidence(document: Mapping[str, Any]) -> ReleaseCandidate:
    """Rebuild a ReleaseCandidate from a validated public evidence document."""
    try:
        if any(
            not isinstance(entry, Mapping) or set(entry) != _ARTIFACT_FIELDS
            for entry in document["artifacts"]
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
            for entry in document["artifacts"]
        )
    except (KeyError, TypeError) as error:
        raise CandidatePolicyError(
            "evidence-invalid", "The candidate evidence artifacts are malformed."
        ) from error
    for artifact in artifacts:
        if (
            not isinstance(artifact.artifact_id, str)
            or not isinstance(artifact.filename, str)
            or type(artifact.byte_size) is not int
            or artifact.byte_size <= 0
            or not isinstance(artifact.sha256, str)
            or _SHA256.fullmatch(artifact.sha256) is None
            or artifact.signature is not None
            and not isinstance(artifact.signature, str)
        ):
            raise CandidatePolicyError(
                "evidence-invalid", "The candidate evidence artifacts are malformed."
            )
    signing = document["signing"]
    if type(signing.get("required")) is not bool or type(signing.get("satisfied")) is not bool:
        raise CandidatePolicyError(
            "evidence-invalid", "The candidate evidence signing block is malformed."
        )
    return ReleaseCandidate(
        tag=document["tag"],
        product_version=document["product_version"],
        source_commit=document["source_commit"],
        digest=document["digest"],
        artifacts=tuple(sorted(artifacts, key=lambda item: item.artifact_id)),
        requires_signing=signing["required"],
    )


def ensure_publishable(document: Mapping[str, Any], tag: str) -> None:
    """Fail closed unless a tag's candidate evidence permits publishing."""
    if not evidence_matches_tag(document, tag):
        raise CandidatePolicyError(
            "candidate-missing",
            "No verified candidate evidence matches this release tag.",
        )
    candidate = candidate_from_evidence(document)
    if candidate.requires_signing and not document["signing"]["satisfied"]:
        raise CandidatePolicyError(
            "candidate-unsigned",
            "The candidate evidence does not prove the required artifact signing.",
        )
    if candidate_digest(candidate.artifacts) != candidate.digest:
        raise CandidatePolicyError(
            "candidate-digest-mismatch",
            "The candidate evidence digest does not match its artifacts.",
        )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    plan = commands.add_parser("plan", help="Build a candidate and emit its digest")
    plan.add_argument("--manifest", type=Path, required=True)
    plan.add_argument("--tag", required=True)
    plan.add_argument("--commit", required=True)
    plan.add_argument("--repo", type=Path, default=Path("."))
    plan.add_argument("--evidence-out", type=Path)
    plan.add_argument(
        "--require-signing",
        choices=("true", "false"),
        default="true",
        help="Whether every artifact must carry a detached signature to publish",
    )

    verify = commands.add_parser("verify", help="Fail unless a candidate is intact")
    verify.add_argument("--evidence", type=Path, required=True)
    verify.add_argument("--expected-digest", required=True)
    verify.add_argument("--repo", type=Path, default=Path("."))

    publish = commands.add_parser(
        "check-publish", help="Gate stable publishing on candidate evidence"
    )
    publish.add_argument("--evidence", type=Path, required=True)
    publish.add_argument("--tag", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            manifest = ReleaseManifest.from_json(args.manifest.read_bytes())
            candidate = plan_candidate(
                manifest,
                tag=args.tag,
                source_commit=args.commit,
                requires_signing=args.require_signing == "true",
            )
            package_version = _read_package_version(args.repo)
            if package_version != candidate.product_version:
                raise CandidatePolicyError(
                    "version-mismatch",
                    "The candidate product version does not match the checked-out package.",
                )
            if args.evidence_out is not None:
                args.evidence_out.write_bytes(
                    canonicalize_json(candidate.to_evidence()) + b"\n"
                )
            print(f"tag={candidate.tag}")
            print(f"product_version={candidate.product_version}")
            print(f"digest={candidate.digest}")
            print(f"artifacts={len(candidate.artifacts)}")
            return 0
        if args.command == "verify":
            document = load_evidence(args.evidence)
            candidate = candidate_from_evidence(document)
            verify_candidate(
                candidate, expected_digest=args.expected_digest, root=args.repo
            )
            print("candidate=verified")
            return 0
        document = load_evidence(args.evidence)
        ensure_publishable(document, args.tag)
        print("candidate=verified")
        return 0
    except CandidatePolicyError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, ManifestError):
        # Manifest/evidence data must not leak into public workflow logs.
        print(
            "::error::Release candidate check failed. Check the manifest, evidence and package versions.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
