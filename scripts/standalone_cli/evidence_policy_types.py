"""Data-only evidence-policy contracts shared without implementation imports."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EvidenceLimits:
    """Bounded resource limits for artifact validation and metadata parsing."""

    max_metadata_file_bytes: int
    max_payload_entries: int
    max_regular_file_bytes: int
    max_expanded_payload_bytes: int
    native_inspection_timeout_seconds: int
    native_inspection_max_output_bytes: int


@dataclass(frozen=True)
class NativeConstraints:
    """Target-native architecture and compatibility constraints."""

    windows_machine: str
    linux_machine: str
    linux_max_glibc: str
    linux_build_os_id: str
    linux_build_os_version: str


@dataclass(frozen=True)
class EvidencePolicy:
    """Typed policy values supplied by the policy loader."""

    limits: EvidenceLimits
    native: NativeConstraints
    public_file_names: frozenset[str]
    archive_compression_level: int
