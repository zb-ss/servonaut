"""Public facade for standalone artifact validation, evidence and archives."""

from __future__ import annotations

import shutil
import stat
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from scripts.standalone_cli import artifact_archive
from scripts.standalone_cli.artifact_archive import (
    create_archive_from_snapshot,
    delete_owned_archive,
)
from scripts.standalone_cli.artifact_filesystem import snapshot_payload
from scripts.standalone_cli.artifact_types import (
    ArchiveOwner,
    ArtifactDescriptor,
    ArtifactEvidenceError,
    EvidenceResult,
)
from scripts.standalone_cli.evidence_policy_types import EvidencePolicy
from scripts.standalone_cli.model import TargetSpec

if TYPE_CHECKING:
    from scripts.standalone_cli.sbom_normalize import SupplyChainEvidence

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_POLICY_PATH = _PROJECT_ROOT / "packaging" / "standalone_cli" / "evidence-policy.json"
_Identity = tuple[int, int]


def validate_payload(artifact: ArtifactDescriptor) -> None:
    """Run every raw payload gate without creating an archive."""
    policy = _load_policy()
    snapshot = snapshot_payload(artifact, policy.limits)
    _analyse_raw(snapshot, artifact, policy, None)


def create_archive(artifact: ArtifactDescriptor, output_dir: Path) -> Path:
    """Create an archive only after the shared raw-payload policy passes."""
    policy = _load_policy()
    snapshot = snapshot_payload(artifact, policy.limits)
    _analyse_raw(snapshot, artifact, policy, None)
    return create_archive_from_snapshot(
        snapshot, artifact.target, policy, output_dir
    ).path


def extract_archive_for_smoke(archive: Path, destination: Path) -> Path:
    """Safely extract an archive into a fresh private smoke-test directory."""
    return artifact_archive.extract_archive_for_smoke(archive, destination)


def inspect_artifact(
    artifact: ArtifactDescriptor, evidence_dir: Path
) -> EvidenceResult:
    """Generate candidate evidence and one private archive from a raw payload."""
    policy = _load_policy()
    snapshot = snapshot_payload(artifact, policy.limits)
    workspace, owned_paths = _create_private_workspace(evidence_dir)
    archive_owner: ArchiveOwner | None = None
    success = False
    try:
        supply = _generate_supply(
            snapshot,
            artifact,
            evidence_dir,
            workspace,
            policy.limits.max_payload_entries,
        )
        pre = _analyse_raw(snapshot, artifact, policy, evidence_dir)
        if pre is None:
            raise ArtifactEvidenceError("policy evidence reports are unavailable")
        archive_owner = create_archive_from_snapshot(
            snapshot, artifact.target, policy, workspace / "archive"
        )
        final = _report_archive(
            pre, supply, archive_owner, artifact.target, policy, evidence_dir
        )
        result = EvidenceResult(
            evidence_dir=evidence_dir,
            manifest=final.manifest,
            sizes=final.sizes,
            sboms=(supply.payload_sbom, supply.python_closure_sbom),
            warnings=final.warnings,
            architecture=final.architecture,
            archive=archive_owner.path,
            archive_sha256=archive_owner.sha256,
            _archive_owner=archive_owner,
        )
        _enforce(result, artifact.target, policy)
        success = True
        return result
    finally:
        _remove_owned_directory(
            workspace / "syft-cache", owned_paths[workspace / "syft-cache"]
        )
        _remove_owned_directory(
            workspace / "syft-config", owned_paths[workspace / "syft-config"]
        )
        if not success:
            if archive_owner is not None:
                delete_owned_archive(archive_owner)
            _remove_empty_owned_directory(workspace, owned_paths[workspace])


def enforce_evidence(result: EvidenceResult, policy: TargetSpec) -> None:
    """Enforce final evidence policy and remove only the owned archive on failure."""
    evidence_policy = _load_policy()
    try:
        from scripts.standalone_cli.evidence_policy import enforce_policy_evidence

        enforce_policy_evidence(result, policy, evidence_policy)
    except BaseException:
        delete_owned_archive(result._archive_owner)
        raise


def _load_policy() -> EvidencePolicy:
    from scripts.standalone_cli.evidence_policy import load_evidence_policy

    return load_evidence_policy(_POLICY_PATH)


def _analyse_raw(
    snapshot: object,
    artifact: ArtifactDescriptor,
    policy: EvidencePolicy,
    evidence_dir: Path | None,
) -> object:
    from scripts.standalone_cli.evidence_policy import analyse_policy_evidence

    return analyse_policy_evidence(snapshot, artifact, policy, evidence_dir)


def _generate_supply(
    snapshot: object,
    artifact: ArtifactDescriptor,
    evidence_dir: Path,
    workspace: Path,
    max_steps: int,
) -> SupplyChainEvidence:
    from scripts.standalone_cli.sbom_normalize import generate_supply_chain_evidence

    return generate_supply_chain_evidence(
        snapshot, artifact, evidence_dir, workspace, max_steps
    )


def _report_archive(
    pre: object,
    supply: SupplyChainEvidence,
    archive: ArchiveOwner,
    target: TargetSpec,
    policy: EvidencePolicy,
    evidence_dir: Path,
) -> object:
    from scripts.standalone_cli.evidence_policy import report_archive_policy

    return report_archive_policy(pre, supply, archive, target, policy, evidence_dir)


def _enforce(
    result: EvidenceResult, target: TargetSpec, policy: EvidencePolicy
) -> None:
    from scripts.standalone_cli.evidence_policy import enforce_policy_evidence

    enforce_policy_evidence(result, target, policy)


def _create_private_workspace(evidence_dir: Path) -> tuple[Path, dict[Path, _Identity]]:
    parent = _regular_directory(evidence_dir.parent, "evidence parent")
    workspace = Path(tempfile.mkdtemp(prefix=".artifact-evidence-", dir=parent))
    owned = {workspace: _identity(workspace)}
    try:
        for name in ("syft-cache", "syft-config"):
            child = workspace / name
            child.mkdir(mode=0o700)
            owned[child] = _identity(child)
        return workspace, owned
    except BaseException:
        for path, identity in reversed(tuple(owned.items())):
            _remove_owned_directory(path, identity)
        raise


def _regular_directory(path: Path, label: str) -> Path:
    try:
        status = path.lstat()
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} is unavailable") from error
    if not stat.S_ISDIR(status.st_mode):
        raise ArtifactEvidenceError(f"{label} is invalid")
    return path.resolve(strict=True)


def _identity(path: Path) -> _Identity:
    try:
        status = path.lstat()
    except OSError as error:
        raise ArtifactEvidenceError("private workspace is unavailable") from error
    if not stat.S_ISDIR(status.st_mode):
        raise ArtifactEvidenceError("private workspace is invalid")
    return status.st_dev, status.st_ino


def _remove_owned_directory(path: Path, identity: _Identity) -> None:
    try:
        status = path.lstat()
        if (
            not stat.S_ISDIR(status.st_mode)
            or (status.st_dev, status.st_ino) != identity
        ):
            return
        shutil.rmtree(path)
    except OSError:
        return


def _remove_empty_owned_directory(path: Path, identity: _Identity) -> None:
    """Remove an owned directory only when no unexpected content remains."""
    try:
        status = path.lstat()
        if (
            not stat.S_ISDIR(status.st_mode)
            or (status.st_dev, status.st_ino) != identity
        ):
            return
        path.rmdir()
    except OSError:
        return
