"""Data-only contracts shared by standalone artifact-evidence components."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from scripts.standalone_cli.model import TargetSpec


class ArtifactEvidenceError(ValueError):
    """Raised when an artifact or its evidence is malformed or unsafe."""


@dataclass(frozen=True)
class ArtifactDescriptor:
    """Validated build outputs and target inputs for one evidence run."""

    payload_root: Path
    executable: Path
    archive: Path | None
    target: TargetSpec
    wheel: Path
    pyinstaller_warning_file: Path
    build_metadata_dir: Path


@dataclass(frozen=True)
class PayloadEntry:
    """One lstat-derived entry in a validated payload tree."""

    relative_path: PurePosixPath
    kind: Literal["file", "directory", "symlink"]
    mode: int
    size: int
    sha256: str | None
    link_target: str | None


@dataclass(frozen=True)
class PayloadSnapshot:
    """A complete, bounded and link-safe view of one payload tree."""

    root: Path
    entries: tuple[PayloadEntry, ...]
    expanded_regular_bytes: int
    executable_relative_path: PurePosixPath
    marker: Mapping[str, object]
    build_provenance: Mapping[str, object]
    build_toolchain: Mapping[str, object]


@dataclass(frozen=True)
class ArchiveOwner:
    """Identity facts that permit later removal of one generated archive."""

    path: Path
    output_root: Path
    device: int
    inode: int
    sha256: str
    output_device: int
    output_inode: int
    archive_profile: Mapping[str, object]
    source_date_epoch: int


@dataclass(frozen=True)
class EvidenceResult:
    """Public-safe evidence and its private archive ownership record."""

    evidence_dir: Path
    manifest: Path
    sizes: Path
    sboms: tuple[Path, ...]
    warnings: Path
    architecture: Path
    archive: Path
    archive_sha256: str
    _archive_owner: ArchiveOwner
