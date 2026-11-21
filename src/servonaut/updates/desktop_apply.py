"""Fresh authorization immediately before applying a privately staged update."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path

from servonaut.distribution import (
    ManifestDowngradeError, ManifestError, ManifestExpiredError, ReleaseChannel, ReleaseManifest,
    TrustPolicy, check_downgrade, verify_manifest,
)
from servonaut.distribution.apply_policy import (
    DesktopApplyPolicy,
    DesktopArtifactIdentity,
    DesktopPolicyClockError,
    policy_url_for_manifest,
    validate_policy_sequence,
    verify_apply_policy,
)
from servonaut.distribution.verify import verify_file_sha256
from servonaut.utils.atomic_file import write_json_atomic
from servonaut.utils.file_lock import FileLock

logger = logging.getLogger(__name__)
DESKTOP_STAGING_DIR = "desktop-update-stage"


class DesktopApplyDecision(Enum):
    AUTHORIZED = "authorized"
    DEFERRED = "deferred"
    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class StagedDesktopUpdate:
    identity: DesktopArtifactIdentity
    path: Path


def _previous_sequence(filename: Path) -> tuple[int, str]:
    with filename.open("rb") as handle:
        raw = handle.read(513)
    if len(raw) > 512:
        raise ValueError("Invalid saved desktop policy size.")
    previous = json.loads(raw)
    if (not isinstance(previous, dict) or set(previous) != {"sequence", "digest"}
            or not isinstance(previous["digest"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", previous["digest"])):
        raise ValueError("Invalid saved desktop policy sequence.")
    return validate_policy_sequence(previous["sequence"]), previous["digest"]


def _accept_sequence(
    state_dir: Path, policy: DesktopApplyPolicy, warn: Callable[[str], None],
) -> None:
    filename = state_dir / f"{policy.channel.value}.json"
    digest = hashlib.sha256(policy.canonical_bytes()).hexdigest()
    lock = FileLock(filename.with_suffix(".lock"), private_dir=True)
    with lock.hold(timeout=1, poll_seconds=0.05):
        if os.path.lexists(filename):
            if not stat.S_ISREG(filename.lstat().st_mode):
                raise ValueError("Invalid saved desktop policy file.")
            try:
                sequence, previous_digest = _previous_sequence(filename)
            except (ManifestError, ValueError, RecursionError):
                warn("Servonaut repaired its saved update policy history using a current signed policy.")
            else:
                if sequence > policy.sequence or (sequence == policy.sequence and previous_digest != digest):
                    raise ValueError("Desktop policy sequence was replayed.")
                if sequence == policy.sequence:
                    return
        write_json_atomic(filename, {"sequence": policy.sequence, "digest": digest})


def _staged_file(path: Path, staging_dir: Path) -> os.stat_result:
    try:
        is_staged = path.parent.resolve(strict=True) == staging_dir.resolve(strict=True)
    except RuntimeError as error:
        raise ValueError("Invalid desktop staging path.") from error
    if not is_staged:
        raise ValueError("Desktop update is outside private staging.")
    directory, file = staging_dir.lstat(), path.lstat()
    if not stat.S_ISDIR(directory.st_mode) or not stat.S_ISREG(file.st_mode):
        raise ValueError("Staged desktop update is not a regular file.")
    if hasattr(os, "geteuid"):
        if (directory.st_uid != os.geteuid() or directory.st_mode & 0o077
                or file.st_uid != os.geteuid() or file.st_mode & 0o022):
            raise ValueError("Desktop update staging is not private.")
    return file


def _discard(staged: StagedDesktopUpdate, staging_dir: Path) -> DesktopApplyDecision:
    try:
        _staged_file(staged.path, staging_dir)
        staged.path.unlink()
    except (OSError, ValueError) as error:
        logger.warning("Could not discard denied desktop update (%s).", type(error).__name__)
    return DesktopApplyDecision.DENIED


def authorize_desktop_apply(
    staged: StagedDesktopUpdate, *, data_root: Path, fetch: Callable[[str], bytes],
    manifest_url: str, trust: TrustPolicy, channel: ReleaseChannel,
    running_version: str, running_revision: int | None,
    status: Callable[[str], None] | None = None,
) -> DesktopApplyDecision:
    """Authorize only a fresh, exact match in both signed public documents."""
    def warn(message: str) -> None:
        logger.warning("%s", message)
        if status is not None:
            status(message)

    staging_dir = data_root / DESKTOP_STAGING_DIR
    state_dir = data_root / "desktop-apply-policy"
    try:
        file = _staged_file(staged.path, staging_dir)
        policy = DesktopApplyPolicy.from_json(fetch(policy_url_for_manifest(manifest_url)))
        verify_apply_policy(policy, trust, channel)
        _accept_sequence(state_dir, policy, warn)
        if staged.identity in policy.withdrawn:
            return _discard(staged, staging_dir)
        if policy.paused or staged.identity not in policy.permitted:
            return DesktopApplyDecision.DEFERRED

        manifest = ReleaseManifest.from_json(fetch(manifest_url))
        verify_manifest(manifest, replace(trust, require_freshness=True, clock_skew_tolerance_seconds=0))
        verify_apply_policy(policy, trust, channel)
        _accept_sequence(state_dir, policy, warn)
        for artifact in manifest.artifacts:
            if artifact.kind is not staged.identity.kind:
                continue
            if DesktopArtifactIdentity.from_artifact(manifest, artifact) != staged.identity:
                continue
            check_downgrade(manifest, running_version, running_revision)
            matches = file.st_size == artifact.byte_size and verify_file_sha256(staged.path, staged.identity.sha256)
            current = _staged_file(staged.path, staging_dir)
            if not os.path.samestat(file, current) or file.st_mtime_ns != current.st_mtime_ns:
                return DesktopApplyDecision.DEFERRED
            verify_apply_policy(policy, trust, channel)
            _accept_sequence(state_dir, policy, warn)
            return DesktopApplyDecision.AUTHORIZED if matches else _discard(staged, staging_dir)
        return DesktopApplyDecision.DEFERRED
    except DesktopPolicyClockError:
        warn("Check this computer's date and time before installing the update.")
        return DesktopApplyDecision.DEFERRED
    except ManifestExpiredError:
        warn("The signed desktop update information expired. Check the date and time or try again later.")
        return DesktopApplyDecision.DEFERRED
    except ManifestDowngradeError:
        return _discard(staged, staging_dir)
    except (ManifestError, OSError, ValueError, RecursionError) as error:
        logger.debug("Desktop update apply deferred (%s).", type(error).__name__)
        return DesktopApplyDecision.DEFERRED
