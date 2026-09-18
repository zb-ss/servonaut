"""Run the fixed standalone build, evidence, and smoke sequence for CI."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import CodeType
from typing import Literal

from scripts.standalone_cli import (
    artifact_archive as _artifact_archive,
)
from scripts.standalone_cli import (
    artifact_filesystem as _artifact_filesystem,
)
from scripts.standalone_cli import (
    build as _build,
)
from scripts.standalone_cli import (
    evidence_policy as _evidence_policy,
)
from scripts.standalone_cli import (
    evidence_sanitize as _evidence_sanitize,
)
from scripts.standalone_cli import (
    inspect as _inspect_facade,
)
from scripts.standalone_cli import (
    model as _model,
)
from scripts.standalone_cli import (
    native_inspect as _native_inspect,
)
from scripts.standalone_cli import (
    runtime_marker as _runtime_marker,
)
from scripts.standalone_cli import (
    sbom_normalize as _sbom_normalize,
)
from scripts.standalone_cli import (
    smoke_artifact as _smoke_artifact,
)
from scripts.standalone_cli import (
    smoke_mcp as _smoke_mcp,
)
from scripts.standalone_cli import (
    syft_tool as _syft_tool,
)
from scripts.standalone_cli.artifact_archive import delete_owned_archive
from scripts.standalone_cli.artifact_types import ArchiveOwner, ArtifactDescriptor
from scripts.standalone_cli.build import build_standalone
from scripts.standalone_cli.evidence_policy import load_evidence_policy
from scripts.standalone_cli.evidence_sanitize import write_public_json
from scripts.standalone_cli.inspect import (
    extract_archive_for_smoke,
)
from scripts.standalone_cli.model import BuildRequest, TargetSpec, load_target_spec
from scripts.standalone_cli.smoke_artifact import (
    SmokeRequest,
    assert_smoke,
    load_smoke_policy,
    run_smoke,
)
from scripts.standalone_cli.smoke_container import (
    ContainerSmokeRequest,
    run_container_smoke,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_TARGET_POLICY = _PROJECT_ROOT / "packaging" / "standalone_cli" / "target-policy.json"
_EVIDENCE_POLICY = (
    _PROJECT_ROOT / "packaging" / "standalone_cli" / "evidence-policy.json"
)
_SMOKE_POLICY = _PROJECT_ROOT / "packaging" / "standalone_cli" / "smoke-policy.json"
_LINUX_TARGET = "linux-x64-ubuntu-22.04"
_SCALAR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_STAGES = frozenset(
    {
        "build",
        "evidence",
        "archive",
        "extract",
        "native-smoke",
        "container-smoke",
        "cleanup",
    }
)
_STATUS_NAME = "qualification-status.json"
_MAX_FAILURE_EXCEPTION_NODES = 8
_MAX_FAILURE_TRACEBACK_FRAMES = 64
_MAX_FAILURE_MESSAGE_CHARS = 128
_DirectoryIdentity = tuple[int, int]
_FailureCode = Literal[
    "archive",
    "artifact-link-validation",
    "build",
    "build-dependency-install",
    "build-metadata",
    "build-metadata-environment",
    "build-metadata-licenses",
    "build-metadata-provenance",
    "build-metadata-python-sbom",
    "build-metadata-toolchain",
    "build-pip-bootstrap",
    "build-profile",
    "build-pyinstaller-analysis",
    "build-pyinstaller-collect",
    "build-pyinstaller-data-filter",
    "build-pyinstaller-exe",
    "build-pyinstaller-filesystem-access",
    "build-pyinstaller-filesystem-capacity",
    "build-pyinstaller-filesystem-missing",
    "build-pyinstaller-hook-import",
    "build-pyinstaller-isolated-child",
    "build-pyinstaller-memory",
    "build-pyinstaller",
    "build-pyinstaller-profile",
    "build-pyinstaller-python-library",
    "build-pyinstaller-pyz",
    "build-pyinstaller-recursion",
    "build-pyinstaller-runtime-metadata",
    "build-runtime-marker",
    "build-staged",
    "build-validation",
    "build-venv",
    "cleanup",
    "container-smoke",
    "evidence-native-inspection",
    "evidence-policy",
    "evidence-warning-allowlist",
    "evidence-warning-canonical",
    "evidence-warning-classification",
    "evidence-warning-importer-list",
    "evidence-warning-importer-qualifiers",
    "evidence-warning-importers",
    "evidence-warning-input",
    "evidence-warning-preamble",
    "evidence-warning-record",
    "evidence-warning-toolchain",
    "evidence-snapshot",
    "evidence-snapshot-executable",
    "evidence-snapshot-forbidden",
    "evidence-snapshot-marker",
    "evidence-snapshot-metadata",
    "evidence-snapshot-provenance",
    "evidence-snapshot-toolchain",
    "evidence-snapshot-walk",
    "evidence-supply-dependency-reconciliation",
    "evidence-supply-environment",
    "evidence-supply-fields",
    "evidence-supply-hash",
    "evidence-supply-license-reconciliation",
    "evidence-supply-license",
    "evidence-supply-licenses",
    "evidence-supply-normalization",
    "evidence-supply-payload",
    "evidence-supply-payload-component",
    "evidence-supply-payload-component-fields",
    "evidence-supply-payload-component-file-hash",
    "evidence-supply-payload-component-package-identity",
    "evidence-supply-payload-component-purl-type",
    "evidence-supply-payload-component-runtime-identity",
    "evidence-supply-payload-component-version",
    "evidence-supply-payload-file",
    "evidence-supply-payload-path",
    "evidence-supply-payload-purl",
    "evidence-supply-payload-runtime-license",
    "evidence-supply-payload-runtime-properties",
    "evidence-supply-payload-vendor",
    "evidence-supply-policy",
    "evidence-supply-properties",
    "evidence-supply-purl",
    "evidence-supply-python",
    "evidence-supply-reference",
    "evidence-supply-dependencies",
    "evidence-supply-wheel-provenance",
    "evidence-tool-acquisition",
    "evidence-tool-download",
    "evidence-tool-scan",
    "evidence-tool-version",
    "evidence-workspace",
    "evidence-write",
    "evidence-public-sanitize",
    "extract",
    "native-smoke",
    "native-smoke-backups",
    "native-smoke-bad-argument",
    "native-smoke-caller-isolation",
    "native-smoke-cleanup",
    "native-smoke-completeness",
    "native-smoke-decode",
    "native-smoke-environment",
    "native-smoke-exit",
    "native-smoke-help",
    "native-smoke-mcp",
    "native-smoke-mcp-install",
    "native-smoke-policy",
    "native-smoke-process",
    "native-smoke-request",
    "native-smoke-run",
    "native-smoke-selftest",
    "native-smoke-transcript",
    "native-smoke-update",
    "native-smoke-version",
    "public-candidate",
    "unknown",
]
_FAILURE_CODES: frozenset[str] = frozenset(
    {
        "archive",
        "artifact-link-validation",
        "build",
        "build-dependency-install",
        "build-metadata",
        "build-metadata-environment",
        "build-metadata-licenses",
        "build-metadata-provenance",
        "build-metadata-python-sbom",
        "build-metadata-toolchain",
        "build-pip-bootstrap",
        "build-profile",
        "build-pyinstaller-analysis",
        "build-pyinstaller-collect",
        "build-pyinstaller-data-filter",
        "build-pyinstaller-exe",
        "build-pyinstaller-filesystem-access",
        "build-pyinstaller-filesystem-capacity",
        "build-pyinstaller-filesystem-missing",
        "build-pyinstaller-hook-import",
        "build-pyinstaller-isolated-child",
        "build-pyinstaller-memory",
        "build-pyinstaller",
        "build-pyinstaller-profile",
        "build-pyinstaller-python-library",
        "build-pyinstaller-pyz",
        "build-pyinstaller-recursion",
        "build-pyinstaller-runtime-metadata",
        "build-runtime-marker",
        "build-staged",
        "build-validation",
        "build-venv",
        "cleanup",
        "container-smoke",
        "evidence-native-inspection",
        "evidence-policy",
        "evidence-warning-allowlist",
        "evidence-warning-canonical",
        "evidence-warning-classification",
        "evidence-warning-importer-list",
        "evidence-warning-importer-qualifiers",
        "evidence-warning-importers",
        "evidence-warning-input",
        "evidence-warning-preamble",
        "evidence-warning-record",
        "evidence-warning-toolchain",
        "evidence-snapshot",
        "evidence-snapshot-executable",
        "evidence-snapshot-forbidden",
        "evidence-snapshot-marker",
        "evidence-snapshot-metadata",
        "evidence-snapshot-provenance",
        "evidence-snapshot-toolchain",
        "evidence-snapshot-walk",
        "evidence-supply-dependency-reconciliation",
        "evidence-supply-environment",
        "evidence-supply-fields",
        "evidence-supply-hash",
        "evidence-supply-license-reconciliation",
        "evidence-supply-license",
        "evidence-supply-licenses",
        "evidence-supply-normalization",
        "evidence-supply-payload",
        "evidence-supply-payload-component",
        "evidence-supply-payload-component-fields",
        "evidence-supply-payload-component-file-hash",
        "evidence-supply-payload-component-package-identity",
        "evidence-supply-payload-component-purl-type",
        "evidence-supply-payload-component-runtime-identity",
        "evidence-supply-payload-component-version",
        "evidence-supply-payload-file",
        "evidence-supply-payload-path",
        "evidence-supply-payload-purl",
        "evidence-supply-payload-runtime-license",
        "evidence-supply-payload-runtime-properties",
        "evidence-supply-payload-vendor",
        "evidence-supply-policy",
        "evidence-supply-properties",
        "evidence-supply-purl",
        "evidence-supply-python",
        "evidence-supply-reference",
        "evidence-supply-dependencies",
        "evidence-supply-wheel-provenance",
        "evidence-tool-acquisition",
        "evidence-tool-download",
        "evidence-tool-scan",
        "evidence-tool-version",
        "evidence-workspace",
        "evidence-write",
        "evidence-public-sanitize",
        "extract",
        "native-smoke",
        "native-smoke-backups",
        "native-smoke-bad-argument",
        "native-smoke-caller-isolation",
        "native-smoke-cleanup",
        "native-smoke-completeness",
        "native-smoke-decode",
        "native-smoke-environment",
        "native-smoke-exit",
        "native-smoke-help",
        "native-smoke-mcp",
        "native-smoke-mcp-install",
        "native-smoke-policy",
        "native-smoke-process",
        "native-smoke-request",
        "native-smoke-run",
        "native-smoke-selftest",
        "native-smoke-transcript",
        "native-smoke-update",
        "native-smoke-version",
        "public-candidate",
        "unknown",
    }
)
_SEMANTIC_FAILURE_CODES: tuple[tuple[CodeType, _FailureCode], ...] = (
    (_model.validate_build_request.__code__, "build-validation"),
    (_build._validate_host_target.__code__, "build-validation"),
    (_build._require_builder_inputs.__code__, "build-profile"),
    (_build._copy_build_profile.__code__, "build-profile"),
    (_build._write_profile.__code__, "build-profile"),
    (_build._build_staged_payload.__code__, "build-staged"),
    (_build._publish_staged_outputs.__code__, "build-staged"),
    (_build._publish_owned_directory.__code__, "build-staged"),
    (_build._venv_python.__code__, "build-venv"),
    (_build._assert_venv_prefix.__code__, "build-venv"),
    (_build._venv_site_packages.__code__, "build-venv"),
    (_build._bootstrap_venv_pip.__code__, "build-pip-bootstrap"),
    (_build._install_wheel_and_lock.__code__, "build-dependency-install"),
    (_build._run_pyinstaller.__code__, "build-pyinstaller"),
    (_build._raise_pyinstaller_profile_failure.__code__, "build-pyinstaller-profile"),
    (
        _build._raise_pyinstaller_runtime_metadata_failure.__code__,
        "build-pyinstaller-runtime-metadata",
    ),
    (_build._raise_pyinstaller_analysis_failure.__code__, "build-pyinstaller-analysis"),
    (
        _build._raise_pyinstaller_data_filter_failure.__code__,
        "build-pyinstaller-data-filter",
    ),
    (_build._raise_pyinstaller_pyz_failure.__code__, "build-pyinstaller-pyz"),
    (_build._raise_pyinstaller_exe_failure.__code__, "build-pyinstaller-exe"),
    (_build._raise_pyinstaller_collect_failure.__code__, "build-pyinstaller-collect"),
    (
        _build._raise_pyinstaller_isolated_child_failure.__code__,
        "build-pyinstaller-isolated-child",
    ),
    (
        _build._raise_pyinstaller_hook_import_failure.__code__,
        "build-pyinstaller-hook-import",
    ),
    (
        _build._raise_pyinstaller_python_library_failure.__code__,
        "build-pyinstaller-python-library",
    ),
    (
        _build._raise_pyinstaller_filesystem_missing_failure.__code__,
        "build-pyinstaller-filesystem-missing",
    ),
    (
        _build._raise_pyinstaller_filesystem_access_failure.__code__,
        "build-pyinstaller-filesystem-access",
    ),
    (
        _build._raise_pyinstaller_filesystem_capacity_failure.__code__,
        "build-pyinstaller-filesystem-capacity",
    ),
    (
        _build._raise_pyinstaller_recursion_failure.__code__,
        "build-pyinstaller-recursion",
    ),
    (_build._raise_pyinstaller_memory_failure.__code__, "build-pyinstaller-memory"),
    (_build._capture_build_metadata.__code__, "build-metadata"),
    (_build._write_environment_inventory.__code__, "build-metadata-environment"),
    (_build._write_license_inventory.__code__, "build-metadata-licenses"),
    (_build._write_python_sbom.__code__, "build-metadata-python-sbom"),
    (_build._write_build_provenance.__code__, "build-metadata-provenance"),
    (_build._write_build_toolchain.__code__, "build-metadata-toolchain"),
    (_runtime_marker.write_runtime_marker.__code__, "build-runtime-marker"),
    (_runtime_marker._validate_marker_with_runtime.__code__, "build-runtime-marker"),
    (_artifact_filesystem.snapshot_payload.__code__, "evidence-snapshot"),
    (_artifact_filesystem._walk_payload.__code__, "evidence-snapshot-walk"),
    (
        _artifact_filesystem.SnapshotPathResolver.validate_links.__code__,
        "artifact-link-validation",
    ),
    (
        _artifact_filesystem.SnapshotPathResolver.resolve_entry.__code__,
        "artifact-link-validation",
    ),
    (
        _artifact_filesystem._relative_regular_file.__code__,
        "evidence-snapshot-executable",
    ),
    (_artifact_filesystem._read_marker.__code__, "evidence-snapshot-marker"),
    (_artifact_filesystem._validate_marker.__code__, "evidence-snapshot-marker"),
    (_artifact_filesystem._validate_metadata.__code__, "evidence-snapshot-metadata"),
    (
        _artifact_filesystem._read_build_provenance.__code__,
        "evidence-snapshot-provenance",
    ),
    (
        _artifact_filesystem._read_build_toolchain.__code__,
        "evidence-snapshot-toolchain",
    ),
    (
        _artifact_filesystem._validate_forbidden_paths.__code__,
        "evidence-snapshot-forbidden",
    ),
    (_inspect_facade._create_private_workspace.__code__, "evidence-workspace"),
    (_syft_tool.acquire_syft.__code__, "evidence-tool-acquisition"),
    (_syft_tool._download.__code__, "evidence-tool-download"),
    (_syft_tool._verify_syft_version.__code__, "evidence-tool-version"),
    (_syft_tool.run_syft_scan.__code__, "evidence-tool-scan"),
    (
        _sbom_normalize.generate_supply_chain_evidence.__code__,
        "evidence-supply-normalization",
    ),
    (_sbom_normalize._load_environment.__code__, "evidence-supply-environment"),
    (_sbom_normalize._load_installed_licenses.__code__, "evidence-supply-licenses"),
    (_sbom_normalize._load_normalization_policy.__code__, "evidence-supply-policy"),
    (
        _sbom_normalize._validate_wheel_provenance.__code__,
        "evidence-supply-wheel-provenance",
    ),
    (_sbom_normalize._normalize_payload_sbom.__code__, "evidence-supply-payload"),
    (_sbom_normalize._normalize_python_sbom.__code__, "evidence-supply-python"),
    (
        _sbom_normalize._normalize_payload_component.__code__,
        "evidence-supply-payload-component",
    ),
    (_sbom_normalize._normalize_properties.__code__, "evidence-supply-properties"),
    (_sbom_normalize._payload_relative_path.__code__, "evidence-supply-payload-path"),
    (
        _sbom_normalize._windows_payload_relative_path.__code__,
        "evidence-supply-payload-path",
    ),
    (
        _sbom_normalize._snapshot_content_sha256.__code__,
        "evidence-supply-payload-file",
    ),
    (
        _sbom_normalize._embedded_python_runtime_purl.__code__,
        "evidence-supply-payload-purl",
    ),
    (
        _sbom_normalize._validate_embedded_python_runtime_properties.__code__,
        "evidence-supply-payload-runtime-properties",
    ),
    (
        _sbom_normalize._normalize_embedded_runtime_licenses.__code__,
        "evidence-supply-payload-runtime-license",
    ),
    (
        _sbom_normalize._vendored_python_component.__code__,
        "evidence-supply-payload-vendor",
    ),
    (_sbom_normalize._component.__code__, "evidence-supply-fields"),
    (_sbom_normalize._component_ref.__code__, "evidence-supply-fields"),
    (_sbom_normalize._optional_string.__code__, "evidence-supply-fields"),
    (_sbom_normalize._normalize_hashes.__code__, "evidence-supply-hash"),
    (_sbom_normalize._normalize_licenses.__code__, "evidence-supply-license"),
    (_sbom_normalize._validate_purl.__code__, "evidence-supply-purl"),
    (_sbom_normalize._parse_pypi_purl.__code__, "evidence-supply-purl"),
    (
        _sbom_normalize._normalize_external_references.__code__,
        "evidence-supply-reference",
    ),
    (
        _sbom_normalize._normalize_dependencies.__code__,
        "evidence-supply-dependencies",
    ),
    (
        _sbom_normalize._dependency_provenance.__code__,
        "evidence-supply-dependency-reconciliation",
    ),
    (
        _sbom_normalize._license_inventory.__code__,
        "evidence-supply-license-reconciliation",
    ),
    (_evidence_sanitize.encode_public_json.__code__, "evidence-public-sanitize"),
    (_evidence_sanitize.write_public_json.__code__, "evidence-write"),
    (
        _native_inspect.inspect_native_payload.__code__,
        "evidence-native-inspection",
    ),
    (_artifact_archive.create_archive_from_snapshot.__code__, "archive"),
    (_evidence_policy._canonical_warnings.__code__, "evidence-warning-canonical"),
    (
        _evidence_policy._warning_toolchain_sha256.__code__,
        "evidence-warning-toolchain",
    ),
    (_evidence_policy._parse_importers.__code__, "evidence-warning-importers"),
    (_evidence_policy._split_importers.__code__, "evidence-warning-importer-list"),
    (
        _evidence_policy._parse_qualifiers.__code__,
        "evidence-warning-importer-qualifiers",
    ),
    (_evidence_policy._load_warning_allowlist.__code__, "evidence-warning-allowlist"),
    (
        _evidence_policy._classify_warnings.__code__,
        "evidence-warning-classification",
    ),
    (_evidence_policy._write_json.__code__, "evidence-write"),
    (_evidence_policy.report_archive_policy.__code__, "archive"),
    (_evidence_policy.analyse_policy_evidence.__code__, "evidence-policy"),
    (_evidence_policy.enforce_policy_evidence.__code__, "evidence-policy"),
)

_PAYLOAD_COMPONENT_FAILURE_CODES: tuple[tuple[str, _FailureCode], ...] = (
    ("component type is invalid", "evidence-supply-payload-component-fields"),
    ("component name is invalid", "evidence-supply-payload-component-fields"),
    (
        "component has conflicting hashes",
        "evidence-supply-payload-component-file-hash",
    ),
    (
        "payload SBOM file hash does not match snapshot",
        "evidence-supply-payload-component-file-hash",
    ),
    (
        "Python payload component version is missing",
        "evidence-supply-payload-component-version",
    ),
    (
        "package name is invalid",
        "evidence-supply-payload-component-package-identity",
    ),
    (
        "payload component purl conflicts with package identity",
        "evidence-supply-payload-component-package-identity",
    ),
    (
        "payload component purl type is unsupported",
        "evidence-supply-payload-component-purl-type",
    ),
    (
        "embedded Python runtime component identity is invalid",
        "evidence-supply-payload-component-runtime-identity",
    ),
)

_WARNING_CANONICAL_FAILURE_CODES: tuple[tuple[str, _FailureCode], ...] = (
    ("PyInstaller warning file is unavailable", "evidence-warning-input"),
    ("PyInstaller warning file exceeds policy limit", "evidence-warning-input"),
    ("PyInstaller warning file is invalid", "evidence-warning-input"),
    ("PyInstaller warning preamble is invalid", "evidence-warning-preamble"),
    (
        "PyInstaller warning cannot be safely canonicalised",
        "evidence-warning-record",
    ),
)
_WARNING_DESCRIPTOR_FAILURE_CODES: frozenset[_FailureCode] = frozenset(
    {
        "evidence-warning-input",
        "evidence-warning-preamble",
        "evidence-warning-record",
    }
)
_NATIVE_SMOKE_OUTPUT_FAILURE_CODES: tuple[tuple[str, _FailureCode], ...] = (
    (
        "version output does not match the artifact",
        "native-smoke-version",
    ),
    ("version wrote to stderr", "native-smoke-version"),
    ("help output is missing a required option", "native-smoke-help"),
    ("help output exposes the private selftest", "native-smoke-help"),
    ("help wrote to stderr", "native-smoke-help"),
    (
        "update output lacks packaged-build guidance",
        "native-smoke-update",
    ),
    ("update wrote to stderr", "native-smoke-update"),
    ("isolated backup list is not empty", "native-smoke-backups"),
    ("list backups wrote to stderr", "native-smoke-backups"),
    (
        "bad argument did not return argparse's diagnostic",
        "native-smoke-bad-argument",
    ),
    ("MCP install wrote to stderr", "native-smoke-mcp-install"),
    (
        "MCP install wrote outside its configured file",
        "native-smoke-mcp-install",
    ),
    ("artifact selftest request exceeds policy", "native-smoke-selftest"),
    (
        "artifact selftest left its private home behind",
        "native-smoke-cleanup",
    ),
)
_NATIVE_SMOKE_EXIT_FAILURE_CODES: tuple[tuple[str, _FailureCode], ...] = (
    ("version returned the wrong exit code", "native-smoke-version"),
    ("help returned the wrong exit code", "native-smoke-help"),
    ("update returned the wrong exit code", "native-smoke-update"),
    ("list backups returned the wrong exit code", "native-smoke-backups"),
    ("bad argument returned the wrong exit code", "native-smoke-bad-argument"),
    ("MCP install returned the wrong exit code", "native-smoke-mcp-install"),
    ("artifact selftest returned the wrong exit code", "native-smoke-selftest"),
    (
        "invalid artifact selftest returned the wrong exit code",
        "native-smoke-selftest",
    ),
)
_NATIVE_SMOKE_COMMAND_FAILURE_CODES: frozenset[_FailureCode] = frozenset(
    {
        "native-smoke-backups",
        "native-smoke-bad-argument",
        "native-smoke-cleanup",
        "native-smoke-help",
        "native-smoke-mcp-install",
        "native-smoke-selftest",
        "native-smoke-update",
        "native-smoke-version",
    }
)
_NATIVE_SMOKE_SEMANTIC_FAILURE_CODES: tuple[tuple[CodeType, _FailureCode], ...] = (
    (_smoke_artifact.load_smoke_policy.__code__, "native-smoke-policy"),
    (_smoke_artifact._validate_request.__code__, "native-smoke-request"),
    (
        _smoke_artifact.isolated_child_environment.__code__,
        "native-smoke-environment",
    ),
    (_smoke_artifact.run_bounded_process.__code__, "native-smoke-process"),
    (_smoke_artifact._require_exit.__code__, "native-smoke-exit"),
    (_smoke_artifact._decode.__code__, "native-smoke-decode"),
    (_smoke_artifact.run_smoke.__code__, "native-smoke-run"),
    (
        _smoke_artifact._validate_selftest_success.__code__,
        "native-smoke-selftest",
    ),
    (
        _smoke_artifact._validate_selftest_failure.__code__,
        "native-smoke-selftest",
    ),
    (
        _smoke_artifact._prepare_selftest_caller.__code__,
        "native-smoke-caller-isolation",
    ),
    (
        _smoke_artifact._verify_selftest_caller.__code__,
        "native-smoke-caller-isolation",
    ),
    (
        _smoke_artifact._close_selftest_caller.__code__,
        "native-smoke-caller-isolation",
    ),
    (
        _smoke_artifact._load_claude_mcp_config.__code__,
        "native-smoke-mcp-install",
    ),
    (_smoke_artifact._mcp_environment.__code__, "native-smoke-mcp-install"),
    (_smoke_mcp.run_mcp_smoke.__code__, "native-smoke-mcp"),
    (_smoke_artifact._write_transcript.__code__, "native-smoke-transcript"),
    (_smoke_artifact.assert_smoke.__code__, "native-smoke-completeness"),
)


class QualificationError(RuntimeError):
    """Raised when the fixed CI qualification boundary is invalid."""


@dataclass(frozen=True)
class QualificationRequest:
    """All explicit inputs for one native qualification run."""

    wheel: Path
    target_name: str
    product_version: str
    build_revision: str
    source_commit: str
    checkout: Path
    qualification_root: Path
    public_evidence_dir: Path
    docker: Path | None


@dataclass(frozen=True)
class QualificationResult:
    """Bounded outcome consumed by the standalone workflow."""

    target_name: str
    status: Literal["passed", "failed"]
    completed_stages: tuple[str, ...]
    public_status: Path


@dataclass(frozen=True)
class _OwnedDirectory:
    path: Path
    identity: _DirectoryIdentity


def qualify(request: QualificationRequest) -> QualificationResult:
    """Build and qualify one target while retaining typed ownership in memory."""
    root_owner, target = _validate_request(request)
    root = root_owner.path
    public = _create_public_evidence_directory(root, request.public_evidence_dir)
    completed: list[str] = []
    owned: list[_OwnedDirectory] = []
    archive_owner: ArchiveOwner | None = None
    operation_passed = False
    cleanup_passed = False
    failure_code: _FailureCode | None = None
    fallback_failure_code: _FailureCode = "build"

    try:
        build_root = root / "build output"
        build = build_standalone(
            BuildRequest(
                wheel=request.wheel,
                target=target,
                product_version=request.product_version,
                build_revision=request.build_revision,
                source_commit=request.source_commit,
                output_dir=build_root,
                require_artifact_selftest=True,
            )
        )
        owned.append(_capture_direct_child(root, build_root, "build output"))
        completed.append("build")

        fallback_failure_code = "unknown"
        descriptor = ArtifactDescriptor(
            payload_root=build.payload_root,
            executable=build.executable,
            archive=build.archive,
            target=target,
            wheel=request.wheel,
            pyinstaller_warning_file=build.pyinstaller_warning_file,
            build_metadata_dir=build.build_metadata_dir,
        )
        fallback_failure_code = "archive"
        with _inspect_facade._collected_artifact_for_smoke(
            descriptor, public.path
        ) as evidence:
            archive_owner = evidence._archive_owner
            if evidence.archive != archive_owner.path:
                raise QualificationError("evidence archive ownership is invalid")
            owned.append(_capture_evidence_workspace(root, archive_owner))
            completed.extend(("evidence", "archive"))

            fallback_failure_code = "extract"
            extracted = extract_archive_for_smoke(
                archive_owner.path, root / "extracted payload"
            )
            owned.append(_capture_direct_child(root, extracted, "extracted payload"))
            completed.append("extract")

            fallback_failure_code = "native-smoke"
            native_evidence = _create_private_child(root, "native smoke")
            owned.append(native_evidence)
            native = run_smoke(
                SmokeRequest(
                    payload_root=extracted,
                    executable=extracted / build.executable.name,
                    product_version=request.product_version,
                    evidence_dir=native_evidence.path,
                ),
                load_smoke_policy(_SMOKE_POLICY),
            )
            assert_smoke(native)
            completed.append("native-smoke")

            if request.target_name == _LINUX_TARGET:
                fallback_failure_code = "container-smoke"
                assert request.docker is not None
                container_evidence = _create_private_child(root, "container smoke")
                owned.append(container_evidence)
                run_container_smoke(
                    ContainerSmokeRequest(
                        docker=request.docker,
                        payload_root=extracted,
                        executable=extracted / build.executable.name,
                        product_version=request.product_version,
                        evidence_dir=container_evidence.path,
                    ),
                    load_smoke_policy(_SMOKE_POLICY),
                )
                completed.append("container-smoke")
            fallback_failure_code = "evidence-policy"
        operation_passed = True
    except Exception as error:  # noqa: BLE001 - emits only a closed finite code
        operation_passed = False
        failure_code = _classify_failure(error, fallback_failure_code)
    finally:
        cleanup_passed = _cleanup_private_outputs(
            root_owner,
            public,
            archive_owner,
            owned,
        )

    if cleanup_passed:
        completed.append("cleanup")
    status: Literal["passed", "failed"] = (
        "passed" if operation_passed and cleanup_passed else "failed"
    )
    public_candidates_safe = _public_candidates_are_safe(public, request)
    if not cleanup_passed:
        failure_code = "cleanup"
    elif not public_candidates_safe:
        status = "failed"
        failure_code = "public-candidate"
    elif status == "passed":
        failure_code = None
    elif failure_code is None:
        failure_code = "unknown"
    public_status = _write_status(public, request, status, completed, failure_code)
    return QualificationResult(
        request.target_name,
        status,
        tuple(completed),
        public_status,
    )


def _classify_failure(error: BaseException, fallback: _FailureCode) -> _FailureCode:
    if not isinstance(error, BaseException):
        return "unknown"
    matched: _FailureCode | None = None
    frame_count = 0
    exception_count = 0
    seen: list[BaseException] = []
    current_error: BaseException | None = error
    while current_error is not None:
        exception_count += 1
        if exception_count > _MAX_FAILURE_EXCEPTION_NODES or any(
            current_error is previous for previous in seen
        ):
            return "unknown"
        seen.append(current_error)
        current_traceback = BaseException.__traceback__.__get__(current_error)
        while current_traceback is not None:
            frame_count += 1
            if frame_count > _MAX_FAILURE_TRACEBACK_FRAMES:
                return "unknown"
            frame_code = current_traceback.tb_frame.f_code
            matched_frame = False
            for code, semantic in _SEMANTIC_FAILURE_CODES:
                if frame_code is code:
                    if semantic == "evidence-supply-payload-component":
                        matched = _payload_component_failure_code(current_error)
                    elif semantic == "evidence-warning-canonical":
                        candidate = _warning_canonical_failure_code(current_error)
                        if not (
                            candidate == "evidence-warning-canonical"
                            and type(current_error)
                            is not _evidence_policy.ArtifactEvidenceError
                            and matched in _WARNING_DESCRIPTOR_FAILURE_CODES
                        ):
                            matched = candidate
                    else:
                        matched = semantic
                    matched_frame = True
                    break
            if not matched_frame and fallback == "native-smoke":
                for code, semantic in _NATIVE_SMOKE_SEMANTIC_FAILURE_CODES:
                    if frame_code is code:
                        if semantic == "native-smoke-run":
                            candidate = _native_smoke_run_failure_code(current_error)
                            if not (
                                candidate == "native-smoke-run"
                                and type(current_error)
                                is not _smoke_artifact.ArtifactSmokeError
                                and matched in _NATIVE_SMOKE_COMMAND_FAILURE_CODES
                            ):
                                matched = candidate
                        elif semantic == "native-smoke-exit":
                            matched = _native_smoke_exit_failure_code(current_error)
                        else:
                            matched = semantic
                        break
            current_traceback = current_traceback.tb_next
        explicit_cause = BaseException.__cause__.__get__(current_error)
        if explicit_cause is not None and not isinstance(explicit_cause, BaseException):
            return "unknown"
        current_error = explicit_cause
    return matched if matched is not None else fallback


def _payload_component_failure_code(error: BaseException) -> _FailureCode:
    fallback: _FailureCode = "evidence-supply-payload-component"
    if type(error) is not _sbom_normalize.ArtifactEvidenceError:
        return fallback
    arguments = BaseException.args.__get__(error)
    if type(arguments) is not tuple or len(arguments) != 1:
        return fallback
    message = arguments[0]
    if type(message) is not str or len(message) > _MAX_FAILURE_MESSAGE_CHARS:
        return fallback
    for expected, failure_code in _PAYLOAD_COMPONENT_FAILURE_CODES:
        if message == expected:
            return failure_code
    return fallback


def _warning_canonical_failure_code(error: BaseException) -> _FailureCode:
    fallback: _FailureCode = "evidence-warning-canonical"
    if type(error) is not _evidence_policy.ArtifactEvidenceError:
        return fallback
    arguments = BaseException.args.__get__(error)
    if type(arguments) is not tuple or len(arguments) != 1:
        return fallback
    message = arguments[0]
    if type(message) is not str or len(message) > _MAX_FAILURE_MESSAGE_CHARS:
        return fallback
    for expected, failure_code in _WARNING_CANONICAL_FAILURE_CODES:
        if message == expected:
            return failure_code
    return fallback


def _native_smoke_run_failure_code(error: BaseException) -> _FailureCode:
    fallback: _FailureCode = "native-smoke-run"
    if type(error) is not _smoke_artifact.ArtifactSmokeError:
        return fallback
    arguments = BaseException.args.__get__(error)
    if type(arguments) is not tuple or len(arguments) != 1:
        return fallback
    message = arguments[0]
    if type(message) is not str or len(message) > _MAX_FAILURE_MESSAGE_CHARS:
        return fallback
    for expected, failure_code in _NATIVE_SMOKE_OUTPUT_FAILURE_CODES:
        if message == expected:
            return failure_code
    return fallback


def _native_smoke_exit_failure_code(error: BaseException) -> _FailureCode:
    fallback: _FailureCode = "native-smoke-exit"
    if type(error) is not _smoke_artifact.ArtifactSmokeError:
        return fallback
    arguments = BaseException.args.__get__(error)
    if type(arguments) is not tuple or len(arguments) != 1:
        return fallback
    message = arguments[0]
    if type(message) is not str or len(message) > _MAX_FAILURE_MESSAGE_CHARS:
        return fallback
    for expected, failure_code in _NATIVE_SMOKE_EXIT_FAILURE_CODES:
        if message == expected:
            return failure_code
    return fallback


def _validate_request(
    request: QualificationRequest,
) -> tuple[_OwnedDirectory, TargetSpec]:
    if not isinstance(request, QualificationRequest):
        raise TypeError("request must be a QualificationRequest")
    for path in (
        request.wheel,
        request.checkout,
        request.qualification_root,
        request.public_evidence_dir,
    ):
        if not isinstance(path, Path) or not path.is_absolute():
            raise QualificationError("qualification paths must be absolute")
    if request.docker is not None and (
        not isinstance(request.docker, Path) or not request.docker.is_absolute()
    ):
        raise QualificationError("Docker path must be absolute")
    if (
        request.checkout != _PROJECT_ROOT
        or _canonical_directory(request.checkout) != _PROJECT_ROOT
    ):
        raise QualificationError("checkout does not match the qualification helper")
    _canonical_regular_file(request.wheel, "wheel")
    root = _canonical_private_directory(
        request.qualification_root, "qualification root"
    )
    if root == request.checkout or root.is_relative_to(request.checkout):
        raise QualificationError("qualification root must be outside the checkout")
    if any(root.iterdir()):
        raise QualificationError("qualification root must be empty")
    if (
        request.public_evidence_dir.parent != root
        or request.public_evidence_dir.exists()
        or request.public_evidence_dir.is_symlink()
    ):
        raise QualificationError("public evidence directory must be a fresh child")
    if not _VERSION.fullmatch(request.product_version):
        raise QualificationError("product version is invalid")
    if not _SCALAR.fullmatch(request.build_revision):
        raise QualificationError("build revision is invalid")
    if not _COMMIT.fullmatch(request.source_commit):
        raise QualificationError("source commit is invalid")
    target = load_target_spec(_TARGET_POLICY, request.target_name)
    if (target.name == _LINUX_TARGET) != (request.docker is not None):
        raise QualificationError("Docker selection does not match the target")
    if request.docker is not None:
        _canonical_regular_file(request.docker, "Docker executable", executable=True)
    return _OwnedDirectory(root, _directory_identity(root)), target


def _create_public_evidence_directory(root: Path, path: Path) -> _OwnedDirectory:
    try:
        path.mkdir(mode=0o700)
    except OSError as error:
        raise QualificationError(
            "public evidence directory could not be created"
        ) from error
    return _capture_direct_child(root, path, path.name)


def _create_private_child(root: Path, name: str) -> _OwnedDirectory:
    path = root / name
    if path.exists() or path.is_symlink():
        raise QualificationError("private qualification child already exists")
    try:
        path.mkdir(mode=0o700)
    except OSError as error:
        raise QualificationError(
            "private qualification child could not be created"
        ) from error
    return _capture_direct_child(root, path, name)


def _capture_direct_child(root: Path, path: Path, name: str) -> _OwnedDirectory:
    if path != root / name:
        raise QualificationError("qualification child has an unexpected path")
    resolved = _canonical_private_directory(path, "qualification child")
    status = resolved.lstat()
    return _OwnedDirectory(resolved, (status.st_dev, status.st_ino))


def _capture_evidence_workspace(
    root: Path, archive_owner: ArchiveOwner
) -> _OwnedDirectory:
    workspace = archive_owner.output_root.parent
    if (
        archive_owner.output_root != workspace / "archive"
        or workspace.parent != root
        or not workspace.name.startswith(".artifact-evidence-")
    ):
        raise QualificationError("artifact evidence workspace is outside qualification")
    resolved = _canonical_private_directory(workspace, "artifact evidence workspace")
    status = resolved.lstat()
    return _OwnedDirectory(resolved, (status.st_dev, status.st_ino))


def _cleanup_private_outputs(
    root_owner: _OwnedDirectory,
    public: _OwnedDirectory,
    archive_owner: ArchiveOwner | None,
    owned: Sequence[_OwnedDirectory],
) -> bool:
    root = root_owner.path
    if not _same_directory(root, root_owner.identity):
        return False
    passed = True
    archive_removed = True
    if archive_owner is not None:
        delete_owned_archive(archive_owner)
        archive_removed = (
            not archive_owner.path.exists()
            and not archive_owner.path.is_symlink()
            and not archive_owner.output_root.exists()
            and not archive_owner.output_root.is_symlink()
        )
        passed = passed and archive_removed
    for entry in reversed(owned):
        if (
            archive_owner is not None
            and entry.path == archive_owner.output_root.parent
            and not archive_removed
        ):
            continue
        passed = _remove_owned_tree(root, entry) and passed
    passed = _same_directory(public.path, public.identity) and passed
    try:
        remaining = {path.name for path in root.iterdir()}
    except OSError:
        return False
    return passed and remaining == {public.path.name}


def _remove_owned_tree(root: Path, owned: _OwnedDirectory) -> bool:
    if owned.path.parent != root:
        return False
    try:
        status = owned.path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if (
        not stat.S_ISDIR(status.st_mode)
        or (status.st_dev, status.st_ino) != owned.identity
    ):
        return False
    try:
        shutil.rmtree(owned.path)
    except OSError:
        return False
    return not owned.path.exists() and not owned.path.is_symlink()


def _public_candidates_are_safe(
    public: _OwnedDirectory, request: QualificationRequest
) -> bool:
    if not _same_directory(public.path, public.identity):
        raise QualificationError("public evidence directory ownership changed")
    if request.public_evidence_dir != public.path:
        raise QualificationError("public evidence directory changed")
    status_path = public.path / _STATUS_NAME
    if status_path.exists() or status_path.is_symlink():
        raise QualificationError("qualification status already exists")
    allowed = load_evidence_policy(_EVIDENCE_POLICY).public_file_names
    try:
        entries = tuple(public.path.iterdir())
    except OSError as error:
        raise QualificationError("public evidence directory is unavailable") from error
    safe = True
    for path in entries:
        try:
            status = path.lstat()
        except OSError as error:
            raise QualificationError(
                "public evidence candidate is unavailable"
            ) from error
        if (
            path.name not in allowed
            or not stat.S_ISREG(status.st_mode)
            or path.is_symlink()
        ):
            safe = False
    return safe


def _write_status(
    public: _OwnedDirectory,
    request: QualificationRequest,
    status: Literal["passed", "failed"],
    completed: Sequence[str],
    failure_code: _FailureCode | None,
) -> Path:
    if any(stage not in _STAGES for stage in completed) or len(set(completed)) != len(
        completed
    ):
        raise QualificationError("qualification stage result is invalid")
    if (status == "passed" and failure_code is not None) or (
        status == "failed" and failure_code not in _FAILURE_CODES
    ):
        raise QualificationError("qualification failure code is invalid")
    return write_public_json(
        public.path / _STATUS_NAME,
        {
            "schema_version": 1,
            "target": request.target_name,
            "status": status,
            "completed_stages": list(completed),
            "completed_stage_count": len(completed),
            "failure_code": failure_code,
        },
        forbidden_roots=(
            request.checkout,
            request.qualification_root,
            request.wheel.parent,
        ),
        max_bytes=load_evidence_policy(_EVIDENCE_POLICY).limits.max_metadata_file_bytes,
    )


def _canonical_regular_file(
    path: Path, label: str, *, executable: bool = False
) -> Path:
    try:
        status = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise QualificationError(f"{label} is unavailable") from error
    if (
        not stat.S_ISREG(status.st_mode)
        or resolved != path
        or (executable and not os.access(path, os.X_OK))
    ):
        raise QualificationError(f"{label} is invalid")
    return resolved


def _canonical_directory(path: Path) -> Path:
    try:
        status = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise QualificationError("qualification directory is unavailable") from error
    if not stat.S_ISDIR(status.st_mode) or resolved != path:
        raise QualificationError("qualification directory is invalid")
    return resolved


def _canonical_private_directory(path: Path, label: str) -> Path:
    resolved = _canonical_directory(path)
    if os.name != "nt" and stat.S_IMODE(path.lstat().st_mode) & 0o077:
        raise QualificationError(f"{label} permissions are not private")
    return resolved


def _directory_identity(path: Path) -> _DirectoryIdentity:
    status = path.lstat()
    if not stat.S_ISDIR(status.st_mode):
        raise QualificationError("qualification directory is invalid")
    return status.st_dev, status.st_ino


def _same_directory(path: Path, identity: _DirectoryIdentity) -> bool:
    try:
        status = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(status.st_mode) and (status.st_dev, status.st_ino) == identity


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise QualificationError("qualification arguments are invalid")


def main(argv: Sequence[str] | None = None) -> int:
    """Run one fixed qualification without exposing private diagnostics."""
    parser = _ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--target-name", required=True)
    parser.add_argument("--product-version", required=True)
    parser.add_argument("--build-revision", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--qualification-root", type=Path, required=True)
    parser.add_argument("--public-evidence-dir", type=Path, required=True)
    parser.add_argument("--docker", type=Path)
    try:
        arguments = parser.parse_args(argv)
        result = qualify(QualificationRequest(**vars(arguments)))
    except (QualificationError, OSError, TypeError, ValueError):
        return 1
    return 0 if result.status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
