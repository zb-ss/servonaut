"""Policy-driven native, warning, TOC and size evidence for standalone artifacts."""

from __future__ import annotations

import hashlib
import json
import re
import stat
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from jsonschema import Draft202012Validator, ValidationError

from scripts.standalone_cli.artifact_types import (
    ArchiveOwner,
    ArtifactDescriptor,
    ArtifactEvidenceError,
    EvidenceResult,
    PayloadSnapshot,
)
from scripts.standalone_cli.embedded_notices import load_embedded_notice_policy
from scripts.standalone_cli.evidence_policy_types import (
    EvidenceLimits,
    EvidencePolicy,
    NativeConstraints,
)
from scripts.standalone_cli.model import BuildValidationError, TargetSpec
from scripts.standalone_cli.native_inspect import inspect_native_payload
from scripts.standalone_cli.toc_policy import validate_toc_policy

if TYPE_CHECKING:
    from scripts.standalone_cli.sbom_normalize import SupplyChainEvidence

_POLICY_MAX_BYTES = 1_000_000
_NORMALIZATION_POLICY_PATH = (
    Path(__file__).resolve().parents[2]
    / "packaging"
    / "standalone_cli"
    / "sbom-normalization.json"
)
_EMBEDDED_NOTICE_POLICY_PATH = (
    Path(__file__).resolve().parents[2]
    / "packaging"
    / "standalone_cli"
    / "embedded-notices.json"
)
_WARNING_PATTERN = re.compile(
    r"^(?P<kind>missing|excluded|runtime) module named "
    r"(?P<module>'[A-Za-z_][A-Za-z0-9_.]*'|[A-Za-z_][A-Za-z0-9_.]*)"
    r"\s+-\s+imported by\s+(?P<importers>.+)$"
)
_MODULE_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_PACKAGE_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_PACKAGE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,255}$")
_PYTHON_RUNTIME_VERSION = re.compile(r"^3\.12\.[0-9]+$")
_REFERENCE_TYPE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_SYFT_LOCATION_PROPERTY = re.compile(r"^syft:location:[0-9]+:path$")
_WINDOWS_PE_MARKERS = (
    ("syft:package:foundBy", "pe-binary-package-cataloger"),
    ("syft:package:type", "binary"),
    ("syft:package:metadataType", "pe-binary"),
)
_WINDOWS_PE_REFERENCE_DOMAIN = "servonaut-windows-pe-component-v1"
_WINDOWS_PE_REFERENCE_PREFIX = "urn:servonaut:pe-component:"
_RUNTIME_NOTICE_PATH = "_internal/notices/CPython-LICENSE.txt"
_RUNTIME_NOTICE_FIELDS = frozenset(
    {
        "schema_version",
        "runtime",
        "python_implementation",
        "python_version",
        "license_id",
        "payload_path",
        "sha256",
    }
)
_THIRD_PARTY_NOTICE_REPORT_FIELDS = frozenset({"schema_version", "notices"})
_THIRD_PARTY_NOTICE_FIELDS = frozenset(
    {
        "distribution",
        "version",
        "source_wheel_sha256",
        "payload_path",
        "sha256",
    }
)
_LINUX_EMBEDDED_CPYTHON_TARGET = "linux-x64-ubuntu-22.04"
_IMPORTER_PATTERN = re.compile(
    r"^(?P<module>[A-Za-z_][A-Za-z0-9_.]*) \((?P<qualifiers>[a-z, -]+)\)$"
)
_RUNTIME_HOOK_PATTERN = re.compile(
    r"^.+/PyInstaller/hooks/rthooks/[A-Za-z0-9_.-]+\.py$"
)
_QUALIFIERS = frozenset({"top-level", "delayed", "conditional", "optional"})
_PYINSTALLER_PREAMBLE = (
    "This file lists modules PyInstaller was not able to find. This does not",
    "necessarily mean these modules are required for running your program. Both",
    "Python's standard library and 3rd-party Python packages often conditionally",
    "import optional modules, some of which may be available only on certain",
    "platforms.",
    "Types of import:",
    "* top-level: imported at the top-level - look at these first",
    "* conditional: imported within an if-statement",
    "* delayed: imported within a function",
    "* optional: imported within a try-except-statement",
    "IMPORTANT: Do NOT post this list to the issue-tracker. Use it as a basis for",
    "            tracking down the missing module yourself. Thanks!",
)
_PYINSTALLER_PREAMBLE_SHA256 = (
    "9d32fd5e4bb29d37a5b2722bde2f1e3da09297e3743c3310f3fda87bf3738646"
)
_TARGET_NAMES = frozenset(
    {"windows-x64", "macos-x64", "macos-arm64", "linux-x64-ubuntu-22.04"}
)
_INFORMATIONAL_QUALIFICATION_CODES = frozenset(
    {"local-wheel-acquisition-normalized", "non-https-optional-reference-omitted"}
)
_QUALIFICATION_FACT_FIELDS = frozenset(
    {"code", "component", "version", "reference_type", "source"}
)
_PUBLIC_REPORT_NAMES = frozenset(
    {
        "dependency-provenance.json",
        "licenses.json",
        "sbom-payload.cdx.json",
        "sbom-python-closure.cdx.json",
    }
)
_BASELINE_FIELDS = frozenset(
    {
        "schema_version",
        "target",
        "requirements_lock_sha256",
        "toolchain",
        "archive_profile",
        "observed",
        "measurement",
        "source_date_epoch",
        "max_expanded_bytes",
        "max_archive_bytes",
        "rationale",
    }
)
_WARNING_ALLOWLIST_FIELDS = frozenset(
    {
        "fingerprint",
        "code",
        "module",
        "importers",
        "target_facts",
        "collection_facts",
        "classification",
        "reason",
        "expires_on",
    }
)
_WARNING_CLASSIFICATION_FIELDS = frozenset(
    {"optional", "conditional", "collected", "origin_class"}
)
_WARNING_REPORT_FIELDS = frozenset(
    {"schema_version", "approved", "unknown", "stale", "counts", "collection_facts"}
)
_WARNING_COUNTS_FIELDS = frozenset({"approved", "unknown", "stale"})
_WARNING_COLLECTION_FIELDS = frozenset({"preamble_sha256", "record_count"})
_WARNING_RECORD_FIELDS = frozenset(
    {"fingerprint", "code", "module", "importers", "target_facts", "collection_facts"}
)
_SIZE_REPORT_FIELDS = frozenset(
    {
        "schema_version",
        "target",
        "expanded_regular_bytes",
        "regular_file_count",
        "directory_count",
        "symlink_count",
        "archive_bytes",
        "archive_sha256",
        "archive_profile",
        "source_date_epoch",
        "measurement",
    }
)
_DEPENDENCY_PROVENANCE_FIELDS = frozenset(
    {
        "schema_version",
        "scope",
        "build",
        "toolchain",
        "runtime_notice",
        "third_party_notices",
        "payload_python_components",
        "payload_vendored_python_components",
        "closure_only_components",
        "payload_additional_components",
        "bootstrap_exceptions",
        "qualification_facts",
        "unresolved_conflicts",
    }
)
_BUILD_PROVENANCE_FIELDS = frozenset(
    {
        "schema_version",
        "source_commit",
        "target",
        "product_version",
        "build_revision",
        "wheel_sha256",
    }
)
_TOOLCHAIN_FIELDS = frozenset(
    {
        "python_implementation",
        "python_version",
        "spec_sha256",
        "hooks_sha256",
        "pyinstaller_version",
        "pyinstaller_hooks_version",
        "cyclonedx_bom_version",
        "syft_version",
        "syft_asset_sha256",
    }
)
_LICENSE_REPORT_FIELDS = frozenset(
    {"schema_version", "scope", "packages", "qualifications"}
)
_LICENSE_PACKAGE_FIELDS = frozenset(
    {"name", "version", "license_ids", "license_classifiers", "provenance"}
)
_LICENSE_QUALIFICATION_FIELDS = frozenset({"code", "component", "version", "source"})
_CYCLONEDX_FIELDS = frozenset(
    {"bomFormat", "specVersion", "version", "metadata", "components", "dependencies"}
)
_SBOM_COMPONENT_FIELDS = frozenset(
    {
        "type",
        "name",
        "version",
        "bom-ref",
        "purl",
        "hashes",
        "licenses",
        "properties",
        "externalReferences",
    }
)
_LICENSE_QUALIFICATION_CODES = frozenset(
    {"unknown-license-metadata", "unstructured-license-metadata"}
)
_CANONICAL_CYCLONEDX_HASH_LENGTHS = {
    "MD5": 32,
    "SHA-1": 40,
    "SHA-256": 64,
    "SHA-384": 96,
    "SHA-512": 128,
    "SHA3-256": 64,
    "SHA3-384": 96,
    "SHA3-512": 128,
}


@dataclass(frozen=True)
class PreArchivePolicyEvidence:
    """C-owned public reports available before deterministic archiving."""

    manifest: Path
    warnings: Path
    architecture: Path


@dataclass(frozen=True)
class PolicyEvidence:
    """C-owned reports completed once archive and supply data exist."""

    manifest: Path
    sizes: Path
    warnings: Path
    architecture: Path
    unknown_warning_candidates: Path
    missing_baseline_candidate: Path | None


@dataclass(frozen=True)
class _NormalizedCycloneDx:
    root_component: dict[str, object] | None
    components: tuple[dict[str, object], ...]


def load_evidence_policy(path: Path) -> EvidencePolicy:
    """Load the exact, bounded policy adjacent to its machine schema."""
    raw = _read_json(path, _POLICY_MAX_BYTES)
    schema_path = path.with_name("evidence-policy.schema.json")
    schema = _read_json(schema_path, _POLICY_MAX_BYTES)
    try:
        Draft202012Validator(schema).validate(raw)
    except (ValidationError, ValueError) as error:
        raise ArtifactEvidenceError("evidence policy is invalid") from error
    limits = raw["limits"]
    native = raw["native"]
    names = raw["public_file_names"]
    assert (
        isinstance(limits, dict)
        and isinstance(native, dict)
        and isinstance(names, list)
    )
    return EvidencePolicy(
        limits=EvidenceLimits(**limits),
        native=NativeConstraints(**native),
        public_file_names=frozenset(names),
        archive_compression_level=raw["archive_compression_level"],
    )


def analyse_policy_evidence(
    snapshot: PayloadSnapshot,
    artifact: ArtifactDescriptor,
    policy: EvidencePolicy,
    evidence_dir: Path | None,
) -> PreArchivePolicyEvidence | None:
    """Validate raw payloads, writing public reports only when a directory is supplied."""
    validate_toc_policy(snapshot, artifact, policy.limits.max_metadata_file_bytes)
    binaries = inspect_native_payload(
        snapshot, artifact.target, policy.native, policy.limits
    )
    if evidence_dir is None:
        return None
    _require_public_directory(evidence_dir, policy)
    manifest = evidence_dir / "manifest.json"
    architecture = evidence_dir / "architecture.json"
    warnings = evidence_dir / "warnings.json"
    _write_json(manifest, _manifest_payload(snapshot))
    _write_json(
        architecture,
        {
            "schema_version": 1,
            "binaries": binaries,
        },
    )
    observed, collection_facts = _canonical_warnings(
        snapshot, artifact, policy.limits.max_metadata_file_bytes
    )
    allowlist = _load_warning_allowlist(
        artifact.target.warning_allowlist, artifact.target
    )
    approved, unknown, stale = _classify_warnings(observed, allowlist)
    _write_json(
        warnings,
        {
            "schema_version": 1,
            "approved": approved,
            "unknown": unknown,
            "stale": stale,
            "counts": {
                "approved": len(approved),
                "unknown": len(unknown),
                "stale": len(stale),
            },
            "collection_facts": collection_facts,
        },
    )
    _write_json(
        evidence_dir / "warning-candidates.json",
        {"schema_version": 1, "candidates": unknown},
    )
    return PreArchivePolicyEvidence(
        manifest=manifest, warnings=warnings, architecture=architecture
    )


def report_archive_policy(
    pre: PreArchivePolicyEvidence,
    supply: SupplyChainEvidence,
    archive: ArchiveOwner,
    target: TargetSpec,
    policy: EvidencePolicy,
    evidence_dir: Path,
) -> PolicyEvidence:
    """Record archive metrics and emit a reviewed-baseline candidate when needed."""
    target_name = target.name
    if target_name not in _TARGET_NAMES:
        raise ArtifactEvidenceError("target is invalid for evidence")
    _require_public_directory(evidence_dir, policy)
    manifest = _read_json(pre.manifest, policy.limits.max_metadata_file_bytes)
    entries = manifest.get("entries") if isinstance(manifest, dict) else None
    if not isinstance(entries, list):
        raise ArtifactEvidenceError("manifest is invalid")
    regular = [
        entry
        for entry in entries
        if isinstance(entry, dict) and entry.get("kind") == "file"
    ]
    sizes = evidence_dir / "sizes.json"
    archive_size = archive.path.stat().st_size
    if (
        not _valid_archive_profile(
            dict(archive.archive_profile), target, policy.archive_compression_level
        )
        or type(archive.source_date_epoch) is not int
    ):
        raise ArtifactEvidenceError("archive evidence profile is invalid")
    payload_bytes = sum(
        entry.get("size", 0) for entry in regular if isinstance(entry.get("size"), int)
    )
    _validate_supply_chain_evidence(supply, policy)
    supply_provenance = _read_json(
        supply.dependency_provenance, policy.limits.max_metadata_file_bytes
    )
    assert isinstance(supply_provenance, dict)
    build = supply_provenance["build"]
    toolchain = supply_provenance["toolchain"]
    assert isinstance(build, dict) and isinstance(toolchain, dict)
    metrics = {
        "schema_version": 1,
        "target": target_name,
        "expanded_regular_bytes": payload_bytes,
        "regular_file_count": len(regular),
        "directory_count": sum(
            1 for entry in entries if entry.get("kind") == "directory"
        ),
        "symlink_count": sum(1 for entry in entries if entry.get("kind") == "symlink"),
        "archive_bytes": archive_size,
        "archive_sha256": archive.sha256,
        "archive_profile": dict(archive.archive_profile),
        "source_date_epoch": archive.source_date_epoch,
        "measurement": {
            "source_commit": build["source_commit"],
            "wheel_sha256": build["wheel_sha256"],
            "measured_on": datetime.now(timezone.utc).date().isoformat(),
        },
    }
    _write_json(sizes, metrics)
    baseline_path = target.size_baselines
    baselines = _load_baselines(baseline_path)
    baseline_id = target.size_baseline_id
    baseline = baselines.get(baseline_id)
    candidate: Path | None = None
    baseline_issue = _baseline_issue(baseline, target, metrics, toolchain)
    if baseline_issue is not None:
        candidate = evidence_dir / "missing-baseline-candidate.json"
        _write_json(
            candidate,
            {
                "schema_version": 1,
                "baseline_id": baseline_id,
                "issue": baseline_issue,
                "observed": metrics,
                "toolchain": toolchain,
            },
        )
    return PolicyEvidence(
        manifest=pre.manifest,
        sizes=sizes,
        warnings=pre.warnings,
        architecture=pre.architecture,
        unknown_warning_candidates=evidence_dir / "warning-candidates.json",
        missing_baseline_candidate=candidate,
    )


def enforce_policy_evidence(
    result: EvidenceResult,
    target: TargetSpec,
    policy: EvidencePolicy,
) -> None:
    """Fail closed on unresolved warning or baseline policy evidence."""
    for path in (result.manifest, result.sizes, result.warnings, result.architecture):
        if path.name not in policy.public_file_names:
            raise ArtifactEvidenceError("evidence result has an unapproved report name")
        _read_public_report(
            path, result.evidence_dir, policy.limits.max_metadata_file_bytes
        )
    manifest_regular_files = _validate_manifest_report(
        _read_public_report(
            result.manifest, result.evidence_dir, policy.limits.max_metadata_file_bytes
        )
    )
    _validate_architecture_report(
        _read_public_report(
            result.architecture,
            result.evidence_dir,
            policy.limits.max_metadata_file_bytes,
        )
    )
    _validate_result_supply_reports(result, target, policy, manifest_regular_files)
    sizes = _read_public_report(
        result.sizes, result.evidence_dir, policy.limits.max_metadata_file_bytes
    )
    provenance = _read_public_report(
        result.evidence_dir / "dependency-provenance.json",
        result.evidence_dir,
        policy.limits.max_metadata_file_bytes,
    )
    assert isinstance(provenance, dict) and isinstance(provenance["toolchain"], dict)
    _validate_size_report(sizes, target, provenance["toolchain"], policy)
    warnings = _read_public_report(
        result.warnings, result.evidence_dir, policy.limits.max_metadata_file_bytes
    )
    _validate_warning_report(warnings, target)


def _validate_result_supply_reports(
    result: EvidenceResult,
    target: TargetSpec,
    policy: EvidencePolicy,
    manifest_regular_files: Mapping[str, str],
) -> None:
    names = {path.name for path in result.sboms}
    if names != {"sbom-payload.cdx.json", "sbom-python-closure.cdx.json"}:
        raise ArtifactEvidenceError("supply-chain report names are invalid")
    provenance = _validate_dependency_provenance(
        _public_report_path(
            result.evidence_dir / "dependency-provenance.json", result.evidence_dir
        ),
        policy.limits.max_metadata_file_bytes,
    )
    normalized: dict[str, _NormalizedCycloneDx] = {}
    for path in result.sboms:
        if path.name not in policy.public_file_names:
            raise ArtifactEvidenceError("evidence result has an unapproved report name")
        raw = _read_public_report(
            path, result.evidence_dir, policy.limits.max_metadata_file_bytes
        )
        scope = (
            "frozen-payload-filesystem"
            if path.name == "sbom-payload.cdx.json"
            else "isolated-build-input-closure"
        )
        normalized[path.name] = _validate_cyclonedx_sbom(raw, scope)
    for name in _PUBLIC_REPORT_NAMES - names:
        path = result.evidence_dir / name
        if path.name not in policy.public_file_names:
            raise ArtifactEvidenceError("evidence result has an unapproved report name")
        _read_public_report(
            path, result.evidence_dir, policy.limits.max_metadata_file_bytes
        )
    licenses = _validate_license_report(
        _read_public_report(
            result.evidence_dir / "licenses.json",
            result.evidence_dir,
            policy.limits.max_metadata_file_bytes,
        )
    )
    _reconcile_normalized_sboms(
        normalized["sbom-payload.cdx.json"],
        normalized["sbom-python-closure.cdx.json"],
        provenance,
        licenses,
        manifest_regular_files,
        target,
    )
    _validate_third_party_notice_binding(
        normalized["sbom-python-closure.cdx.json"],
        provenance,
        licenses,
        manifest_regular_files,
        target,
        policy.limits.max_metadata_file_bytes,
    )


def _validate_license_report(raw: object) -> dict[str, str]:
    if (
        not isinstance(raw, dict)
        or set(raw) != _LICENSE_REPORT_FIELDS
        or not _is_schema_version_one(raw.get("schema_version"))
        or raw.get("scope") != "isolated-build-environment-license-claims"
        or not isinstance(raw.get("packages"), list)
        or not isinstance(raw.get("qualifications"), list)
    ):
        raise ArtifactEvidenceError("license evidence report is invalid")
    identities: dict[str, str] = {}
    previous: str | None = None
    for package in raw["packages"]:
        if (
            not isinstance(package, dict)
            or set(package) != _LICENSE_PACKAGE_FIELDS
            or package.get("provenance") != "installed-distribution-metadata"
            or not isinstance(package.get("name"), str)
            or _CANONICAL_PACKAGE_NAME.fullmatch(package["name"]) is None
            or not _valid_relationship_version(package.get("version"))
            or any(
                not _valid_sorted_evidence_strings(package.get(field))
                for field in ("license_ids", "license_classifiers")
            )
            or previous is not None
            and package["name"] <= previous
        ):
            raise ArtifactEvidenceError("license evidence report is invalid")
        identities[package["name"]] = package["version"]
        previous = package["name"]
    if raw["qualifications"]:
        for qualification in raw["qualifications"]:
            if (
                not isinstance(qualification, dict)
                or set(qualification) != _LICENSE_QUALIFICATION_FIELDS
                or qualification.get("code") not in _LICENSE_QUALIFICATION_CODES
                or qualification.get("source") != "installed-distribution-metadata"
                or not all(
                    isinstance(qualification.get(field), str) and qualification[field]
                    for field in ("component", "version")
                )
            ):
                raise ArtifactEvidenceError("license evidence report is invalid")
        raise ArtifactEvidenceError("license metadata requires review")
    return identities


def _valid_sorted_evidence_strings(raw: object) -> bool:
    return (
        isinstance(raw, list)
        and all(_safe_evidence_string(value) for value in raw)
        and raw == sorted(set(raw))
    )


def _validate_cyclonedx_sbom(raw: object, scope: str) -> _NormalizedCycloneDx:
    if (
        not isinstance(raw, dict)
        or set(raw) != _CYCLONEDX_FIELDS
        or raw.get("bomFormat") != "CycloneDX"
        or raw.get("specVersion") != "1.6"
        or not _is_schema_version_one(raw.get("version"))
        or not isinstance(raw.get("metadata"), dict)
        or not isinstance(raw.get("components"), list)
        or not isinstance(raw.get("dependencies"), list)
    ):
        raise ArtifactEvidenceError("CycloneDX evidence report is invalid")
    root_component = _validate_sbom_metadata(raw["metadata"], scope)
    references, components = _validate_sbom_components(raw["components"], scope)
    if root_component is not None:
        root_reference = root_component["bom-ref"]
        assert isinstance(root_reference, str)
        references.add(root_reference)
    _validate_sbom_dependencies(raw["dependencies"], references)
    return _NormalizedCycloneDx(root_component, tuple(components))


def _validate_sbom_metadata(raw: object, scope: str) -> dict[str, object] | None:
    expected = {"properties"}
    if scope == "frozen-payload-filesystem":
        expected.add("component")
    if not isinstance(raw, dict) or set(raw) != expected:
        raise ArtifactEvidenceError("CycloneDX evidence report is invalid")
    if raw.get("properties") != [{"name": "servonaut:evidence:scope", "value": scope}]:
        raise ArtifactEvidenceError("CycloneDX evidence report is invalid")
    if scope != "frozen-payload-filesystem":
        return None
    component = raw.get("component")
    if (
        not isinstance(component, dict)
        or set(component) != {"type", "name", "version", "bom-ref"}
        or component.get("type") != "application"
        or component.get("name") != "servonaut"
        or not _safe_evidence_string(component.get("version"))
        or not isinstance(component.get("bom-ref"), str)
        or re.fullmatch(r"urn:servonaut:payload:[0-9a-f]{64}", component["bom-ref"])
        is None
    ):
        raise ArtifactEvidenceError("CycloneDX evidence report is invalid")
    return component


def _validate_sbom_components(
    raw: list[object], scope: str
) -> tuple[set[str], list[dict[str, object]]]:
    references: set[str] = set()
    components: list[dict[str, object]] = []
    previous: tuple[str, str, str, str] | None = None
    for component in raw:
        if (
            not isinstance(component, dict)
            or not {"type", "name", "bom-ref"} <= set(component)
            or not set(component) <= _SBOM_COMPONENT_FIELDS
            or not all(
                _safe_evidence_string(component.get(field))
                for field in ("type", "name", "bom-ref")
            )
        ):
            raise ArtifactEvidenceError("CycloneDX evidence report is invalid")
        if scope == "isolated-build-input-closure" and (
            component.get("type") != "library"
            or not all(
                _safe_evidence_string(component.get(field))
                for field in ("version", "purl")
            )
            or component["purl"] != component["bom-ref"]
            or not isinstance(component.get("properties"), list)
        ):
            raise ArtifactEvidenceError("CycloneDX evidence report is invalid")
        if component.get("type") == "file" and set(component) != {
            "type",
            "name",
            "bom-ref",
            "hashes",
        }:
            raise ArtifactEvidenceError("CycloneDX evidence report is invalid")
        if not _valid_sbom_component_details(component):
            raise ArtifactEvidenceError("CycloneDX evidence report is invalid")
        reference = component["bom-ref"]
        assert isinstance(reference, str)
        if reference in references:
            raise ArtifactEvidenceError("CycloneDX evidence report is invalid")
        references.add(reference)
        components.append(component)
        current = (
            str(component["type"]),
            str(component["name"]),
            str(component.get("version", "")),
            reference,
        )
        if previous is not None and current <= previous:
            raise ArtifactEvidenceError("CycloneDX evidence report is invalid")
        previous = current
    return references, components


def _valid_sbom_component_details(component: Mapping[str, object]) -> bool:
    if "version" in component and not _safe_evidence_string(component["version"]):
        return False
    if "purl" in component and not _safe_evidence_string(component["purl"]):
        return False
    if "hashes" in component and not _valid_sbom_hashes(component["hashes"]):
        return False
    if "licenses" in component and not _valid_sbom_licenses(component["licenses"]):
        return False
    if "properties" in component and not _valid_sbom_properties(
        component["properties"]
    ):
        return False
    return "externalReferences" not in component or _valid_sbom_references(
        component["externalReferences"]
    )


def _valid_sbom_hashes(raw: object) -> bool:
    if not isinstance(raw, list) or not raw:
        return False
    hashes: list[tuple[str, str]] = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"alg", "content"}:
            return False
        algorithm = item.get("alg")
        content = item.get("content")
        if not isinstance(algorithm, str) or not isinstance(content, str):
            return False
        expected_length = _CANONICAL_CYCLONEDX_HASH_LENGTHS.get(algorithm)
        if (
            expected_length is None
            or len(content) != expected_length
            or re.fullmatch(r"[0-9a-f]+", content) is None
        ):
            return False
        hashes.append((algorithm, content))
    return len(set(hashes)) == len(hashes) and hashes == sorted(hashes)


def _valid_sbom_licenses(raw: object) -> bool:
    if not isinstance(raw, list) or not raw:
        return False
    for item in raw:
        if not isinstance(item, dict) or not set(item) <= {
            "license",
            "expression",
            "acknowledgement",
        }:
            return False
        if bool("license" in item) == bool("expression" in item):
            return False
        if "expression" in item and not _safe_evidence_string(item["expression"]):
            return False
        if "license" in item:
            license_value = item["license"]
            if (
                not isinstance(license_value, dict)
                or not set(license_value) <= {"id", "name", "url", "acknowledgement"}
                or not any(field in license_value for field in ("id", "name"))
                or any(
                    not _safe_evidence_string(license_value.get(field))
                    for field in ("id", "name", "url")
                    if field in license_value
                )
            ):
                return False
    return True


def _valid_sbom_properties(raw: object) -> bool:
    return isinstance(raw, list) and all(
        isinstance(item, dict)
        and set(item) == {"name", "value"}
        and _safe_evidence_string(item.get("name"))
        and _safe_evidence_string(item.get("value"))
        for item in raw
    )


def _valid_sbom_references(raw: object) -> bool:
    if not isinstance(raw, list):
        return False
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"type", "url"}:
            return False
        reference_type = item.get("type")
        url = item.get("url")
        if not _safe_evidence_string(reference_type) or not isinstance(url, str):
            return False
        try:
            parsed = urllib.parse.urlsplit(url)
            port = parsed.port
        except ValueError:
            return False
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or port not in {None, 443}
        ):
            return False
    return True


def _validate_sbom_dependencies(raw: list[object], references: set[str]) -> None:
    previous: str | None = None
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict) or set(item) not in (
            {"ref", "dependsOn"},
            {"ref", "dependsOn", "provides"},
        ):
            raise ArtifactEvidenceError("CycloneDX evidence report is invalid")
        reference = item.get("ref")
        edges = item.get("dependsOn")
        if (
            not isinstance(reference, str)
            or not _safe_evidence_string(reference)
            or reference not in references
            or reference in seen
            or not isinstance(edges, list)
            or any(
                not isinstance(edge, str) or edge not in references for edge in edges
            )
            or edges != sorted(set(edges))
        ):
            raise ArtifactEvidenceError("CycloneDX evidence report is invalid")
        provides = item.get("provides", [])
        if (
            not isinstance(provides, list)
            or any(
                not isinstance(provided, str) or provided not in references
                for provided in provides
            )
            or provides != sorted(set(provides))
            or previous is not None
            and reference <= previous
        ):
            raise ArtifactEvidenceError("CycloneDX evidence report is invalid")
        seen.add(reference)
        previous = reference


def _reconcile_normalized_sboms(
    payload: _NormalizedCycloneDx,
    closure: _NormalizedCycloneDx,
    provenance: Mapping[str, object],
    licenses: Mapping[str, str],
    manifest_regular_files: Mapping[str, str],
    target: TargetSpec,
) -> None:
    build = provenance["build"]
    assert isinstance(build, Mapping)
    product_version = build["product_version"]
    assert isinstance(product_version, str)
    root = payload.root_component
    expected_root_reference = (
        "urn:servonaut:payload:"
        + hashlib.sha256(product_version.encode("utf-8")).hexdigest()
    )
    if (
        build.get("target") != target.name
        or root is None
        or root.get("version") != product_version
        or root.get("bom-ref") != expected_root_reference
    ):
        raise ArtifactEvidenceError("normalized SBOM provenance is invalid")

    closure_components = _python_components(closure.components)
    servonaut = closure_components.get("servonaut")
    expected_servonaut_purl = f"pkg:pypi/servonaut@{product_version}"
    if (
        servonaut is None
        or servonaut["version"] != product_version
        or servonaut["purl"] != expected_servonaut_purl
        or servonaut["bom-ref"] != expected_servonaut_purl
    ):
        raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
    _require_servonaut_wheel_hash(closure.components, build["wheel_sha256"])
    if {
        name: details["version"] for name, details in closure_components.items()
    } != dict(licenses):
        raise ArtifactEvidenceError("normalized SBOM license reconciliation is invalid")
    _validate_runtime_notice_binding(payload, provenance, manifest_regular_files)

    payload_python: list[dict[str, str]] = []
    payload_vendored: list[dict[str, str]] = []
    payload_additional: list[dict[str, object]] = []
    additional_occurrences: list[
        tuple[Mapping[str, object], tuple[str, ...] | None]
    ] = []
    reviewed_vendors = _reviewed_parent_vendors()
    for component in payload.components:
        pe_locations = _validated_windows_pe_locations(
            component, target, manifest_regular_files
        )
        identity = _pypi_component_identity(component)
        if identity is not None:
            closure_component = closure_components.get(identity[0])
            if closure_component is not None:
                if closure_component["version"] != identity[1]:
                    raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
                payload_python.append(
                    {"component": identity[0], "version": identity[1]}
                )
                continue
            vendor = _authenticated_vendored_component(
                component,
                identity,
                closure_components,
                reviewed_vendors,
                manifest_regular_files,
            )
            if vendor is None:
                raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
            payload_vendored.append(vendor)
            continue
        component_name = component["name"]
        component_type = component["type"]
        assert isinstance(component_name, str) and isinstance(component_type, str)
        payload_additional.append(
            {
                "component": component_name,
                "type": component_type,
                "version": component.get("version"),
            }
        )
        additional_occurrences.append((component, pe_locations))
    _validate_additional_component_occurrences(additional_occurrences)
    expected_payload_python = sorted(payload_python, key=lambda row: row["component"])
    expected_payload_vendored = sorted(
        payload_vendored,
        key=lambda row: (row["parent"], row["component"], row["version"]),
    )
    expected_closure_only = [
        {"component": name, "version": details["version"]}
        for name, details in sorted(closure_components.items())
        if name not in {row["component"] for row in expected_payload_python}
    ]
    expected_additional = sorted(
        payload_additional,
        key=lambda row: (
            str(row["type"]),
            str(row["component"]),
            str(row["version"] or ""),
        ),
    )
    if (
        provenance["payload_python_components"] != expected_payload_python
        or provenance["payload_vendored_python_components"] != expected_payload_vendored
        or provenance["closure_only_components"] != expected_closure_only
        or provenance["payload_additional_components"] != expected_additional
    ):
        raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
    bootstrap = provenance["bootstrap_exceptions"]
    assert isinstance(bootstrap, list)
    expected_bootstrap = (
        [
            {
                "component": "pip",
                "version": closure_components["pip"]["version"],
                "source": "venv-bootstrap",
            }
        ]
        if bootstrap and "pip" in closure_components
        else []
    )
    if bootstrap != expected_bootstrap:
        raise ArtifactEvidenceError("normalized SBOM provenance is invalid")


def _validate_additional_component_occurrences(
    components: list[tuple[Mapping[str, object], tuple[str, ...] | None]],
) -> None:
    groups: dict[tuple[str, str, str | None], list[tuple[str, ...] | None]] = {}
    references: dict[tuple[str, str, str | None], set[str]] = {}
    for component, locations in components:
        component_type = component["type"]
        component_name = component["name"]
        version = component.get("version")
        reference = component["bom-ref"]
        assert isinstance(component_type, str) and isinstance(component_name, str)
        assert version is None or isinstance(version, str)
        assert isinstance(reference, str)
        identity = (component_type, component_name, version)
        groups.setdefault(identity, []).append(locations)
        references.setdefault(identity, set()).add(reference)

    for identity, occurrences in groups.items():
        if len(occurrences) < 2:
            continue
        if any(locations is None for locations in occurrences):
            raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
        if len(references[identity]) != len(occurrences):
            raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
        seen_locations: set[str] = set()
        for locations in occurrences:
            assert locations is not None
            if seen_locations.intersection(locations):
                raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
            seen_locations.update(locations)


def _validated_windows_pe_locations(
    component: Mapping[str, object],
    target: TargetSpec,
    manifest_regular_files: Mapping[str, str],
) -> tuple[str, ...] | None:
    reference = component["bom-ref"]
    assert isinstance(reference, str)
    if (
        target.name != "windows-x64"
        or component.get("type") != "application"
        or "purl" in component
        or not isinstance(component.get("properties"), list)
    ):
        if reference.startswith(_WINDOWS_PE_REFERENCE_PREFIX):
            raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
        return None

    properties = component["properties"]
    assert isinstance(properties, list)
    for marker_name, marker_value in _WINDOWS_PE_MARKERS:
        values = [
            item["value"]
            for item in properties
            if isinstance(item, Mapping) and item.get("name") == marker_name
        ]
        if values != [marker_value]:
            if reference.startswith(_WINDOWS_PE_REFERENCE_PREFIX):
                raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
            return None

    locations = [
        item["value"]
        for item in properties
        if isinstance(item, Mapping)
        and isinstance(item.get("name"), str)
        and _SYFT_LOCATION_PROPERTY.fullmatch(item["name"])
    ]
    if (
        not locations
        or any(not isinstance(location, str) for location in locations)
        or len(locations) != len(set(locations))
        or any(
            not _safe_relative_path(location)
            or PurePosixPath(location).as_posix() != location
            or "\\" in location
            or any(":" in part for part in PurePosixPath(location).parts)
            or location not in manifest_regular_files
            for location in locations
        )
    ):
        raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
    canonical_locations = tuple(sorted(locations))
    identity = [
        _WINDOWS_PE_REFERENCE_DOMAIN,
        component["type"],
        component["name"],
        component.get("version"),
        list(canonical_locations),
    ]
    expected_reference = (
        _WINDOWS_PE_REFERENCE_PREFIX
        + hashlib.sha256(
            json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
    )
    if reference != expected_reference:
        raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
    return canonical_locations


def _authenticated_vendored_component(
    component: Mapping[str, object],
    identity: tuple[str, str],
    closure_components: Mapping[str, Mapping[str, str]],
    reviewed_vendors: Mapping[str, str],
    manifest_regular_files: Mapping[str, str],
) -> dict[str, str] | None:
    name, version = identity
    if (
        component.get("type") != "library"
        or component.get("name") != name
        or component.get("version") != version
        or component.get("bom-ref") != component.get("purl")
        or not isinstance(component.get("properties"), list)
    ):
        return None
    locations = [
        item.get("value")
        for item in component["properties"]
        if isinstance(item, dict)
        and _SYFT_LOCATION_PROPERTY.fullmatch(str(item.get("name"))) is not None
    ]
    if (
        not locations
        or not all(isinstance(location, str) for location in locations)
        or len(locations) != len(set(locations))
    ):
        return None
    child_directory = f"{name.replace('-', '_')}-{version}.dist-info"
    matches: list[dict[str, str]] = []
    for parent, prefix in reviewed_vendors.items():
        parent_details = closure_components.get(parent)
        root = f"{prefix}/{child_directory}/"
        if parent_details is not None and all(
            location.startswith(root) and location in manifest_regular_files
            for location in locations
        ):
            matches.append(
                {
                    "component": name,
                    "version": version,
                    "parent": parent,
                    "parent_version": parent_details["version"],
                    "origin": "parent-vendor-dist-info",
                }
            )
    return matches[0] if len(matches) == 1 else None


def _validate_runtime_notice_binding(
    payload: _NormalizedCycloneDx,
    provenance: Mapping[str, object],
    manifest_regular_files: Mapping[str, str],
) -> None:
    notice = provenance["runtime_notice"]
    build = provenance["build"]
    assert isinstance(notice, Mapping) and isinstance(build, Mapping)
    notice_path = notice["payload_path"]
    notice_sha256 = notice["sha256"]
    assert isinstance(notice_path, str) and isinstance(notice_sha256, str)
    if manifest_regular_files.get(notice_path) != notice_sha256:
        raise ArtifactEvidenceError("runtime notice manifest binding is invalid")

    runtime_components = [
        component
        for component in payload.components
        if component.get("name") == "python"
        or str(component.get("purl", "")).startswith("pkg:generic")
        or str(component.get("bom-ref", "")).startswith("pkg:generic")
    ]
    if not runtime_components:
        return
    if len(runtime_components) != 1:
        raise ArtifactEvidenceError("embedded Python runtime evidence is invalid")
    component = runtime_components[0]
    version = notice["python_version"]
    assert isinstance(version, str)
    major_minor = ".".join(version.split(".")[:2])
    purl = f"pkg:generic/python@{version}"
    expected_properties = [
        {
            "name": "syft:cpe23",
            "value": f"cpe:2.3:a:python:python:{version}:*:*:*:*:*:*:*",
        },
        {
            "name": "syft:location:0:path",
            "value": f"_internal/libpython{major_minor}.so.1.0",
        },
        {
            "name": "syft:package:foundBy",
            "value": "binary-classifier-cataloger",
        },
        {"name": "syft:package:metadataType", "value": "binary-signature"},
        {"name": "syft:package:type", "value": "binary"},
    ]
    if (
        build.get("target") != _LINUX_EMBEDDED_CPYTHON_TARGET
        or component.get("type") != "application"
        or component.get("name") != "python"
        or component.get("version") != version
        or component.get("purl") != purl
        or component.get("bom-ref") != purl
        or component.get("licenses") != [{"license": {"id": "Python-2.0"}}]
        or component.get("properties") != expected_properties
    ):
        raise ArtifactEvidenceError("embedded Python runtime evidence is invalid")


def _validate_third_party_notice_binding(
    closure: _NormalizedCycloneDx,
    provenance: Mapping[str, object],
    licenses: Mapping[str, str],
    manifest_regular_files: Mapping[str, str],
    target: TargetSpec,
    maximum: int,
) -> None:
    build = provenance["build"]
    toolchain = provenance["toolchain"]
    report = provenance["third_party_notices"]
    assert isinstance(build, Mapping)
    assert isinstance(toolchain, Mapping)
    assert isinstance(report, Mapping)
    rows = report["notices"]
    assert isinstance(rows, list)
    if build.get("target") != target.name:
        raise ArtifactEvidenceError("embedded notice target binding is invalid")
    try:
        trusted = load_embedded_notice_policy(_EMBEDDED_NOTICE_POLICY_PATH, maximum)
    except BuildValidationError as error:
        raise ArtifactEvidenceError("embedded notice policy is invalid") from error
    if len(trusted) != len(rows):
        raise ArtifactEvidenceError("embedded notice provenance is invalid")

    closure_components = {
        identity[0]: component
        for component in closure.components
        if (identity := _pypi_component_identity(component)) is not None
    }
    for row, expected in zip(rows, trusted, strict=True):
        assert isinstance(row, Mapping)
        expected_sha256 = expected.sha256_by_target.get(target.name)
        if (
            expected_sha256 is None
            or row["distribution"] != expected.distribution
            or row["version"] != expected.version
            or row["payload_path"] != expected.payload_path.as_posix()
            or row["sha256"] != expected_sha256
            or licenses.get(expected.distribution) != expected.version
            or manifest_regular_files.get(expected.payload_path.as_posix())
            != expected_sha256
        ):
            raise ArtifactEvidenceError("embedded notice provenance is invalid")
        component = closure_components.get(expected.distribution)
        if (
            component is None
            or component.get("version") != expected.version
            or component.get("hashes")
            != [{"alg": "SHA-256", "content": row["source_wheel_sha256"]}]
        ):
            raise ArtifactEvidenceError("embedded notice closure binding is invalid")

    versions = {row["distribution"]: row["version"] for row in rows}
    if versions.get("pyinstaller") != toolchain.get(
        "pyinstaller_version"
    ) or versions.get("pyinstaller-hooks-contrib") != toolchain.get(
        "pyinstaller_hooks_version"
    ):
        raise ArtifactEvidenceError("embedded notice toolchain binding is invalid")


def _require_servonaut_wheel_hash(
    components: tuple[dict[str, object], ...], wheel_sha256: object
) -> None:
    if (
        not isinstance(wheel_sha256, str)
        or _SHA256_PATTERN.fullmatch(wheel_sha256) is None
    ):
        raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
    servonaut = [
        component
        for component in components
        if (identity := _pypi_component_identity(component)) is not None
        and identity[0] == "servonaut"
    ]
    if len(servonaut) != 1:
        raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
    hashes = servonaut[0].get("hashes")
    if not isinstance(hashes, list):
        raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
    matches = [
        item.get("content")
        for item in hashes
        if isinstance(item, dict) and item.get("alg") == "SHA-256"
    ]
    if matches != [wheel_sha256]:
        raise ArtifactEvidenceError("normalized SBOM provenance is invalid")


def _python_components(
    components: tuple[dict[str, object], ...],
) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for component in components:
        identity = _pypi_component_identity(component)
        if identity is None:
            raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
        name, version = identity
        purl = component.get("purl")
        reference = component.get("bom-ref")
        component_name = component.get("name")
        component_version = component.get("version")
        if (
            component.get("type") != "library"
            or not isinstance(purl, str)
            or reference != purl
            or component_name != name
            or component_version != version
            or name in result
        ):
            raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
        result[name] = {"version": version, "purl": purl, "bom-ref": reference}
    return result


def _pypi_component_identity(component: Mapping[str, object]) -> tuple[str, str] | None:
    purl = component.get("purl")
    if not isinstance(purl, str) or not purl.startswith("pkg:pypi/"):
        return None
    match = re.fullmatch(
        r"pkg:pypi/(?P<name>[a-z0-9]+(?:-[a-z0-9]+)*)@"
        r"(?P<version>[A-Za-z0-9][A-Za-z0-9.+!_-]{0,255})",
        purl,
    )
    if match is None:
        raise ArtifactEvidenceError("normalized SBOM provenance is invalid")
    return match.group("name"), match.group("version")


def _safe_evidence_string(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= 4096
        and all(ord(character) >= 32 and ord(character) != 127 for character in value)
    )


def _is_schema_version_one(value: object) -> bool:
    return type(value) is int and value == 1


def _validate_warning_report(raw: object, target: TargetSpec) -> None:
    if (
        not isinstance(raw, dict)
        or set(raw) != _WARNING_REPORT_FIELDS
        or not _is_schema_version_one(raw.get("schema_version"))
    ):
        raise ArtifactEvidenceError("warning evidence report is invalid")
    approved = raw.get("approved")
    unknown = raw.get("unknown")
    stale = raw.get("stale")
    counts = raw.get("counts")
    collection = raw.get("collection_facts")
    if (
        not isinstance(approved, list)
        or not isinstance(unknown, list)
        or not isinstance(stale, list)
        or not isinstance(counts, dict)
        or set(counts) != _WARNING_COUNTS_FIELDS
        or not isinstance(collection, dict)
        or set(collection) != _WARNING_COLLECTION_FIELDS
        or collection.get("preamble_sha256") != _PYINSTALLER_PREAMBLE_SHA256
        or type(collection.get("record_count")) is not int
        or collection["record_count"] != len(approved) + len(unknown)
        or any(
            counts[name] != len(rows)
            for name, rows in (
                ("approved", approved),
                ("unknown", unknown),
                ("stale", stale),
            )
        )
    ):
        raise ArtifactEvidenceError("warning evidence report is invalid")
    if unknown or stale:
        raise ArtifactEvidenceError("PyInstaller warnings require policy review")
    records = [_validated_warning_record(row, target) for row in approved]
    allowlist = _load_warning_allowlist(target.warning_allowlist, target)
    classified, unresolved, stale_approvals = _classify_warnings(records, allowlist)
    if unresolved or stale_approvals or classified != records:
        raise ArtifactEvidenceError("PyInstaller warnings require policy review")


def _validate_manifest_report(raw: object) -> dict[str, str]:
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "expanded_regular_bytes", "entries"}
        or not _is_schema_version_one(raw.get("schema_version"))
        or type(raw.get("expanded_regular_bytes")) is not int
        or raw["expanded_regular_bytes"] < 0
        or not isinstance(raw.get("entries"), list)
    ):
        raise ArtifactEvidenceError("manifest evidence report is invalid")
    paths: set[str] = set()
    regular_files: dict[str, str] = {}
    for entry in raw["entries"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"path", "kind", "mode", "size", "sha256", "link_target"}
            or not isinstance(entry.get("path"), str)
            or not _safe_relative_path(entry["path"])
            or entry.get("kind") not in {"file", "directory", "symlink"}
            or type(entry.get("mode")) is not int
            or type(entry.get("size")) is not int
            or entry["size"] < 0
        ):
            raise ArtifactEvidenceError("manifest evidence report is invalid")
        kind = entry["kind"]
        path = entry["path"]
        assert isinstance(path, str)
        if path in paths:
            raise ArtifactEvidenceError("manifest evidence report is invalid")
        paths.add(path)
        digest = entry.get("sha256")
        link_target = entry.get("link_target")
        if kind == "file" and (
            not isinstance(digest, str)
            or _SHA256_PATTERN.fullmatch(digest) is None
            or link_target is not None
        ):
            raise ArtifactEvidenceError("manifest evidence report is invalid")
        if kind == "file":
            assert isinstance(digest, str)
            regular_files[path] = digest
        if kind == "directory" and (
            entry["size"] != 0 or digest is not None or link_target is not None
        ):
            raise ArtifactEvidenceError("manifest evidence report is invalid")
        if kind == "symlink" and (
            digest is not None or not _valid_link_target(link_target)
        ):
            raise ArtifactEvidenceError("manifest evidence report is invalid")
    return regular_files


def _validate_architecture_report(raw: object) -> None:
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "binaries"}
        or not _is_schema_version_one(raw.get("schema_version"))
        or not isinstance(raw.get("binaries"), list)
    ):
        raise ArtifactEvidenceError("architecture evidence report is invalid")
    for binary in raw["binaries"]:
        if not _valid_architecture_record(binary):
            raise ArtifactEvidenceError("architecture evidence report is invalid")


def _safe_relative_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and not path.is_absolute()
        and not any(part in {"", ".", ".."} for part in path.parts)
    )


def _valid_link_target(value: object) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and not any(":" in part for part in path.parts)


def _valid_architecture_record(raw: object) -> bool:
    if not isinstance(raw, dict) or not isinstance(raw.get("path"), str):
        return False
    if not _safe_relative_path(raw["path"]):
        return False
    kind = raw.get("kind")
    if kind == "pe":
        return (
            set(raw) == {"path", "kind", "machine"} and raw.get("machine") == "0x8664"
        )
    if kind == "elf":
        return (
            set(raw)
            == {"path", "kind", "machine", "max_glibc", "max_glibcxx", "max_cxxabi"}
            and type(raw.get("machine")) is int
            and raw["machine"] == 62
            and all(
                value is None
                or (isinstance(value, str) and re.fullmatch(r"\d+(?:\.\d+)+", value))
                for value in (
                    raw.get("max_glibc"),
                    raw.get("max_glibcxx"),
                    raw.get("max_cxxabi"),
                )
            )
        )
    return (
        kind == "macho"
        and set(raw) == {"path", "kind", "architecture", "minimum"}
        and raw.get("architecture") in {"arm64", "x86_64"}
        and isinstance(raw.get("minimum"), str)
        and re.fullmatch(r"\d+(?:\.\d+)+", raw["minimum"]) is not None
    )


def _validate_size_report(
    raw: object,
    target: TargetSpec,
    toolchain: Mapping[str, object],
    policy: EvidencePolicy,
) -> None:
    if (
        not isinstance(raw, dict)
        or set(raw) != _SIZE_REPORT_FIELDS
        or not _is_schema_version_one(raw.get("schema_version"))
        or raw.get("target") != target.name
        or not _SHA256_PATTERN.fullmatch(str(raw.get("archive_sha256")))
        or not _valid_archive_profile(
            raw.get("archive_profile"), target, policy.archive_compression_level
        )
        or type(raw.get("source_date_epoch")) is not int
        or not _valid_measurement(raw.get("measurement"))
        or any(
            type(raw.get(field)) is not int or raw[field] < 0
            for field in (
                "expanded_regular_bytes",
                "regular_file_count",
                "directory_count",
                "symlink_count",
                "archive_bytes",
            )
        )
    ):
        raise ArtifactEvidenceError("size evidence report is invalid")
    baseline = _load_baselines(target.size_baselines).get(target.size_baseline_id)
    if _baseline_issue(baseline, target, raw, toolchain) is not None:
        raise ArtifactEvidenceError("size baseline requires policy review")


def _validated_warning_record(raw: object, target: TargetSpec) -> dict[str, object]:
    if not isinstance(raw, dict) or set(raw) != _WARNING_RECORD_FIELDS:
        raise ArtifactEvidenceError("warning evidence report is invalid")
    if (
        raw.get("code") not in {"missing-module", "excluded-module", "runtime-module"}
        or not isinstance(raw.get("module"), str)
        or not _MODULE_PATTERN.fullmatch(raw["module"])
        or not isinstance(raw.get("importers"), list)
        or not isinstance(raw.get("target_facts"), dict)
        or not isinstance(raw.get("collection_facts"), dict)
        or not isinstance(raw.get("fingerprint"), str)
        or not _SHA256_PATTERN.fullmatch(raw["fingerprint"])
    ):
        raise ArtifactEvidenceError("warning evidence report is invalid")
    facts = raw["target_facts"]
    collection = raw["collection_facts"]
    if (
        set(facts) != {"target", "lock_sha256", "toolchain_sha256"}
        or facts.get("target") != target.name
        or facts.get("lock_sha256") != _sha256_file(target.requirements_lock)
        or not _SHA256_PATTERN.fullmatch(str(facts.get("toolchain_sha256")))
        or collection != {"preamble_sha256": _PYINSTALLER_PREAMBLE_SHA256}
        or any(not _valid_warning_importer(importer) for importer in raw["importers"])
        or raw["fingerprint"]
        != _fingerprint(
            {
                field: raw[field]
                for field in (
                    "code",
                    "module",
                    "importers",
                    "target_facts",
                    "collection_facts",
                )
            }
        )
    ):
        raise ArtifactEvidenceError("warning evidence report is invalid")
    return raw


def _valid_warning_importer(raw: object) -> bool:
    if not isinstance(raw, dict):
        return False
    if set(raw) == {"module", "qualifiers"}:
        valid_origin = isinstance(raw.get("module"), str) and _MODULE_PATTERN.fullmatch(
            raw["module"]
        )
    elif set(raw) == {"origin", "qualifiers"}:
        valid_origin = raw.get("origin") == "pyinstaller-runtime-hook"
    else:
        return False
    qualifiers = raw.get("qualifiers")
    return (
        bool(valid_origin)
        and isinstance(qualifiers, list)
        and bool(qualifiers)
        and qualifiers == sorted(set(qualifiers))
        and all(qualifier in _QUALIFIERS for qualifier in qualifiers)
    )


def _validate_supply_chain_evidence(
    supply: SupplyChainEvidence, policy: EvidencePolicy
) -> None:
    path = getattr(supply, "dependency_provenance", None)
    if not isinstance(path, Path) or path.name != "dependency-provenance.json":
        raise ArtifactEvidenceError("supply-chain provenance report is invalid")
    _validate_dependency_provenance(path, policy.limits.max_metadata_file_bytes)


def _validate_dependency_provenance(path: Path, maximum: int) -> dict[str, object]:
    raw = _read_json(path, maximum)
    if (
        not isinstance(raw, dict)
        or set(raw) != _DEPENDENCY_PROVENANCE_FIELDS
        or not _is_schema_version_one(raw.get("schema_version"))
        or raw.get("scope") != "resolved-python-and-payload-reconciliation"
        or not isinstance(raw.get("build"), dict)
        or set(raw["build"]) != _BUILD_PROVENANCE_FIELDS
        or not isinstance(raw.get("toolchain"), dict)
        or set(raw["toolchain"]) != _TOOLCHAIN_FIELDS
        or any(
            not isinstance(raw.get(field), list)
            for field in (
                "payload_python_components",
                "payload_vendored_python_components",
                "closure_only_components",
                "payload_additional_components",
                "bootstrap_exceptions",
                "qualification_facts",
                "unresolved_conflicts",
            )
        )
    ):
        raise ArtifactEvidenceError("supply-chain provenance report is invalid")
    _validate_provenance_relationships(raw)
    build = raw["build"]
    toolchain = raw["toolchain"]
    if (
        not all(
            isinstance(build.get(field), str) and build[field]
            for field in _BUILD_PROVENANCE_FIELDS - {"schema_version"}
        )
        or not _is_schema_version_one(build.get("schema_version"))
        or _SHA256_PATTERN.fullmatch(str(build.get("wheel_sha256"))) is None
        or not all(
            isinstance(toolchain.get(field), str) and toolchain[field]
            for field in _TOOLCHAIN_FIELDS
        )
        or any(
            not _SHA256_PATTERN.fullmatch(str(toolchain[field]))
            for field in ("spec_sha256", "hooks_sha256", "syft_asset_sha256")
        )
    ):
        raise ArtifactEvidenceError("supply-chain provenance report is invalid")
    _validate_runtime_notice(raw["runtime_notice"], toolchain)
    _validate_third_party_notices(raw["third_party_notices"])
    facts = raw["qualification_facts"]
    conflicts = raw["unresolved_conflicts"]
    reviewed_omissions, _ = _reviewed_normalization_policy()
    if conflicts:
        raise ArtifactEvidenceError("supply-chain provenance requires review")
    for fact in facts:
        if not isinstance(fact, dict):
            raise ArtifactEvidenceError("supply-chain provenance report is invalid")
        code = fact.get("code")
        if code == "local-wheel-acquisition-normalized":
            expected_fields = {"code", "component", "version", "source"}
            expected_source = "descriptor-wheel-sha256"
        elif code == "non-https-optional-reference-omitted":
            expected_fields = _QUALIFICATION_FACT_FIELDS
            expected_source = "reviewed-http-reference-policy"
        else:
            raise ArtifactEvidenceError("supply-chain provenance requires review")
        if set(fact) != expected_fields or fact.get("source") != expected_source:
            raise ArtifactEvidenceError("supply-chain provenance report is invalid")
        if not all(
            isinstance(fact.get(field), str) and fact[field]
            for field in ("component", "version", "source")
        ):
            raise ArtifactEvidenceError("supply-chain provenance report is invalid")
        if code == "local-wheel-acquisition-normalized" and (
            fact["component"] != "servonaut"
            or fact["version"] != build["product_version"]
        ):
            raise ArtifactEvidenceError("supply-chain provenance report is invalid")
        reference_type = fact.get("reference_type")
        if code == "non-https-optional-reference-omitted" and (
            not isinstance(reference_type, str)
            or (
                fact["component"],
                fact["version"],
                reference_type,
            )
            not in reviewed_omissions
        ):
            raise ArtifactEvidenceError("supply-chain provenance report is invalid")
    return raw


def _validate_runtime_notice(
    raw: object, toolchain: Mapping[str, object]
) -> dict[str, object]:
    if (
        not isinstance(raw, dict)
        or set(raw) != _RUNTIME_NOTICE_FIELDS
        or not _is_schema_version_one(raw.get("schema_version"))
        or raw.get("runtime") != "cpython"
        or raw.get("python_implementation") != "CPython"
        or raw.get("python_implementation") != toolchain.get("python_implementation")
        or raw.get("python_version") != toolchain.get("python_version")
        or not isinstance(raw.get("python_version"), str)
        or _PYTHON_RUNTIME_VERSION.fullmatch(raw["python_version"]) is None
        or raw.get("license_id") != "Python-2.0"
        or raw.get("payload_path") != _RUNTIME_NOTICE_PATH
        or not isinstance(raw.get("sha256"), str)
        or _SHA256_PATTERN.fullmatch(raw["sha256"]) is None
    ):
        raise ArtifactEvidenceError("runtime notice provenance is invalid")
    return raw


def _validate_third_party_notices(raw: object) -> tuple[dict[str, str], ...]:
    if (
        not isinstance(raw, dict)
        or set(raw) != _THIRD_PARTY_NOTICE_REPORT_FIELDS
        or not _is_schema_version_one(raw.get("schema_version"))
        or not isinstance(raw.get("notices"), list)
        or len(raw["notices"]) != 5
    ):
        raise ArtifactEvidenceError("embedded notice provenance is invalid")
    rows: list[dict[str, str]] = []
    previous: str | None = None
    paths: set[str] = set()
    for row in raw["notices"]:
        if (
            not isinstance(row, dict)
            or set(row) != _THIRD_PARTY_NOTICE_FIELDS
            or not isinstance(row.get("distribution"), str)
            or _CANONICAL_PACKAGE_NAME.fullmatch(row["distribution"]) is None
            or not _valid_relationship_version(row.get("version"))
            or not isinstance(row.get("payload_path"), str)
            or not _safe_relative_path(row["payload_path"])
            or any(
                not isinstance(row.get(field), str)
                or _SHA256_PATTERN.fullmatch(row[field]) is None
                for field in ("source_wheel_sha256", "sha256")
            )
            or previous is not None
            and row["distribution"] <= previous
            or row["payload_path"] in paths
        ):
            raise ArtifactEvidenceError("embedded notice provenance is invalid")
        rows.append(row)
        previous = row["distribution"]
        paths.add(row["payload_path"])
    return tuple(rows)


def _validate_provenance_relationships(raw: Mapping[str, object]) -> None:
    _validate_component_version_relationships(raw["payload_python_components"])
    _validate_vendored_python_relationships(raw["payload_vendored_python_components"])
    _validate_component_version_relationships(raw["closure_only_components"])
    _validate_payload_additional_relationships(raw["payload_additional_components"])
    vendor_components = {
        row["component"]
        for row in raw["payload_vendored_python_components"]
        if isinstance(row, dict)
    }
    normal_components = {
        row["component"]
        for relationship in ("payload_python_components", "closure_only_components")
        for row in raw[relationship]
        if isinstance(row, dict)
    }
    additional_components = {
        row["component"]
        for row in raw["payload_additional_components"]
        if isinstance(row, dict)
    }
    if vendor_components & (normal_components | additional_components):
        raise ArtifactEvidenceError("supply-chain provenance report is invalid")
    bootstrap = raw["bootstrap_exceptions"]
    if not isinstance(bootstrap, list) or len(bootstrap) > 1:
        raise ArtifactEvidenceError("supply-chain provenance report is invalid")
    if bootstrap and (
        not isinstance(bootstrap[0], dict)
        or bootstrap[0]
        != {
            "component": "pip",
            "version": bootstrap[0].get("version"),
            "source": "venv-bootstrap",
        }
        or not _valid_relationship_version(bootstrap[0].get("version"))
    ):
        raise ArtifactEvidenceError("supply-chain provenance report is invalid")


def _validate_component_version_relationships(raw: object) -> None:
    if not isinstance(raw, list):
        raise ArtifactEvidenceError("supply-chain provenance report is invalid")
    previous: str | None = None
    for row in raw:
        if (
            not isinstance(row, dict)
            or set(row) != {"component", "version"}
            or not isinstance(row.get("component"), str)
            or _CANONICAL_PACKAGE_NAME.fullmatch(row["component"]) is None
            or not _valid_relationship_version(row.get("version"))
        ):
            raise ArtifactEvidenceError("supply-chain provenance report is invalid")
        current = row["component"]
        if previous is not None and current <= previous:
            raise ArtifactEvidenceError("supply-chain provenance report is invalid")
        previous = current


def _validate_vendored_python_relationships(raw: object) -> None:
    if not isinstance(raw, list):
        raise ArtifactEvidenceError("supply-chain provenance report is invalid")
    previous: tuple[str, str, str] | None = None
    components: set[str] = set()
    for row in raw:
        if (
            not isinstance(row, dict)
            or set(row)
            != {"component", "version", "parent", "parent_version", "origin"}
            or not all(
                isinstance(row.get(field), str)
                and _CANONICAL_PACKAGE_NAME.fullmatch(row[field]) is not None
                for field in ("component", "parent")
            )
            or not all(
                _valid_relationship_version(row.get(field))
                for field in ("version", "parent_version")
            )
            or row.get("origin") != "parent-vendor-dist-info"
        ):
            raise ArtifactEvidenceError("supply-chain provenance report is invalid")
        component = row["component"]
        parent = row["parent"]
        version = row["version"]
        assert isinstance(component, str) and isinstance(parent, str)
        assert isinstance(version, str)
        current = (parent, component, version)
        if previous is not None and current <= previous or component in components:
            raise ArtifactEvidenceError("supply-chain provenance report is invalid")
        components.add(component)
        previous = current


def _validate_payload_additional_relationships(raw: object) -> None:
    if not isinstance(raw, list):
        raise ArtifactEvidenceError("supply-chain provenance report is invalid")
    previous: tuple[str, str, str] | None = None
    for row in raw:
        if (
            not isinstance(row, dict)
            or set(row) != {"component", "type", "version"}
            or not _safe_evidence_string(row.get("component"))
            or not _safe_evidence_string(row.get("type"))
            or row.get("version") is not None
            and not _safe_evidence_string(row["version"])
        ):
            raise ArtifactEvidenceError("supply-chain provenance report is invalid")
        version = row["version"]
        assert isinstance(row["component"], str) and isinstance(row["type"], str)
        assert version is None or isinstance(version, str)
        current = (row["type"], row["component"], version or "")
        if previous is not None and current < previous:
            raise ArtifactEvidenceError("supply-chain provenance report is invalid")
        previous = current


def _valid_relationship_version(value: object) -> bool:
    return isinstance(value, str) and _PACKAGE_VERSION.fullmatch(value) is not None


def _reviewed_parent_vendors() -> dict[str, str]:
    _, vendors = _reviewed_normalization_policy()
    return vendors


def _reviewed_normalization_policy() -> tuple[
    frozenset[tuple[str, str, str]], dict[str, str]
]:
    raw = _read_json(_NORMALIZATION_POLICY_PATH, _POLICY_MAX_BYTES)
    if (
        not isinstance(raw, dict)
        or set(raw)
        != {
            "schema_version",
            "allowed_http_reference_omissions",
            "allowed_parent_vendors",
        }
        or not _is_schema_version_one(raw.get("schema_version"))
        or not isinstance(raw.get("allowed_http_reference_omissions"), list)
        or not isinstance(raw.get("allowed_parent_vendors"), list)
    ):
        raise ArtifactEvidenceError("SBOM normalization policy is invalid")
    omissions: set[tuple[str, str, str]] = set()
    previous: tuple[str, str, str] | None = None
    for item in raw["allowed_http_reference_omissions"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "version", "reference_type", "url_sha256"}
            or not isinstance(item.get("name"), str)
            or _CANONICAL_PACKAGE_NAME.fullmatch(item["name"]) is None
            or not isinstance(item.get("version"), str)
            or _PACKAGE_VERSION.fullmatch(item["version"]) is None
            or not isinstance(item.get("reference_type"), str)
            or _REFERENCE_TYPE.fullmatch(item["reference_type"]) is None
            or not _SHA256_PATTERN.fullmatch(str(item.get("url_sha256")))
        ):
            raise ArtifactEvidenceError("SBOM normalization policy is invalid")
        tuple_value = (item["name"], item["version"], item["reference_type"])
        assert all(isinstance(value, str) for value in tuple_value)
        if tuple_value in omissions:
            raise ArtifactEvidenceError("SBOM normalization policy is invalid")
        if previous is not None and tuple_value <= previous:
            raise ArtifactEvidenceError("SBOM normalization policy is invalid")
        omissions.add(tuple_value)
        previous = tuple_value
    if not omissions:
        raise ArtifactEvidenceError("SBOM normalization policy is invalid")
    vendors: dict[str, str] = {}
    previous_vendor: tuple[str, str] | None = None
    for item in raw["allowed_parent_vendors"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"parent", "payload_prefix"}
            or not isinstance(item.get("parent"), str)
            or _CANONICAL_PACKAGE_NAME.fullmatch(item["parent"]) is None
            or not isinstance(item.get("payload_prefix"), str)
            or not _valid_parent_vendor_prefix(item["payload_prefix"])
            or item["parent"] in vendors
        ):
            raise ArtifactEvidenceError("SBOM normalization policy is invalid")
        current = (item["parent"], item["payload_prefix"])
        if previous_vendor is not None and current <= previous_vendor:
            raise ArtifactEvidenceError("SBOM normalization policy is invalid")
        vendors[item["parent"]] = item["payload_prefix"]
        previous_vendor = current
    if not vendors:
        raise ArtifactEvidenceError("SBOM normalization policy is invalid")
    return frozenset(omissions), vendors


def _valid_parent_vendor_prefix(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        len(value) <= 512
        and not path.is_absolute()
        and path.as_posix() == value
        and len(path.parts) >= 2
        and "\\" not in value
        and all(part not in {"", ".", ".."} and ":" not in part for part in path.parts)
    )


def _manifest_payload(snapshot: PayloadSnapshot) -> dict[str, object]:
    return {
        "schema_version": 1,
        "expanded_regular_bytes": snapshot.expanded_regular_bytes,
        "entries": [
            {
                "path": entry.relative_path.as_posix(),
                "kind": entry.kind,
                "mode": entry.mode,
                "size": entry.size,
                "sha256": entry.sha256,
                "link_target": entry.link_target,
            }
            for entry in snapshot.entries
        ],
    }


def _canonical_warnings(
    snapshot: PayloadSnapshot, artifact: ArtifactDescriptor, maximum: int
) -> tuple[list[dict[str, object]], dict[str, object]]:
    path = artifact.pyinstaller_warning_file
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ArtifactEvidenceError(
            "PyInstaller warning file is unavailable"
        ) from error
    if len(raw) > maximum:
        raise ArtifactEvidenceError("PyInstaller warning file exceeds policy limit")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ArtifactEvidenceError("PyInstaller warning file is invalid") from error
    target = artifact.target
    lock = target.requirements_lock
    lock_sha256 = _sha256_file(lock)
    toolchain_path = artifact.build_metadata_dir / "resolved" / "environment.json"
    toolchain_sha256 = _warning_toolchain_sha256(
        snapshot.build_toolchain, _sha256_file(toolchain_path)
    )
    facts = {
        "target": target.name,
        "lock_sha256": lock_sha256,
        "toolchain_sha256": toolchain_sha256,
    }
    nonblank = [line for line in lines if line]
    records_start = next(
        (
            index
            for index, line in enumerate(nonblank)
            if _WARNING_PATTERN.match(line) is not None
        ),
        None,
    )
    if (
        records_start is None
        or tuple(nonblank[:records_start]) != _PYINSTALLER_PREAMBLE
    ):
        raise ArtifactEvidenceError("PyInstaller warning preamble is invalid")
    records: list[dict[str, object]] = []
    for line in nonblank[records_start:]:
        match = _WARNING_PATTERN.match(line)
        if match is None:
            raise ArtifactEvidenceError(
                "PyInstaller warning cannot be safely canonicalised"
            )
        module = match.group("module").strip("'")
        importers = _parse_importers(match.group("importers"))
        record = {
            "code": f"{match.group('kind')}-module",
            "module": module,
            "importers": importers,
            "target_facts": facts,
            "collection_facts": {"preamble_sha256": _PYINSTALLER_PREAMBLE_SHA256},
        }
        record["fingerprint"] = _fingerprint(record)
        records.append(record)
    collection = {
        "preamble_sha256": _PYINSTALLER_PREAMBLE_SHA256,
        "record_count": len(records),
    }
    return sorted(records, key=lambda item: str(item["fingerprint"])), collection


def _warning_toolchain_sha256(
    toolchain: Mapping[str, object], environment_sha256: str
) -> str:
    expected = {
        "schema_version",
        "python_implementation",
        "python_version",
        "spec_sha256",
        "hooks_sha256",
    }
    if (
        set(toolchain) != expected
        or not _is_schema_version_one(toolchain.get("schema_version"))
        or not all(
            isinstance(toolchain.get(field), str) and toolchain[field]
            for field in ("python_implementation", "python_version")
        )
        or any(
            not _SHA256_PATTERN.fullmatch(str(toolchain.get(field)))
            for field in ("spec_sha256", "hooks_sha256")
        )
        or not _SHA256_PATTERN.fullmatch(environment_sha256)
    ):
        raise ArtifactEvidenceError("warning toolchain evidence is invalid")
    payload = {
        "build_toolchain": dict(toolchain),
        "environment_sha256": environment_sha256,
    }
    return _fingerprint(payload)


def _parse_importers(raw: str) -> list[dict[str, object]]:
    parts = _split_importers(raw)
    importers: list[dict[str, object]] = []
    for part in parts:
        match = _IMPORTER_PATTERN.fullmatch(part)
        if match is not None:
            module = match.group("module")
            if not _MODULE_PATTERN.fullmatch(module):
                raise ArtifactEvidenceError("PyInstaller warning has invalid importers")
            qualifiers = _parse_qualifiers(match.group("qualifiers"))
            importers.append({"module": module, "qualifiers": qualifiers})
            continue
        path, separator, qualifier_text = part.rpartition(" (")
        if (
            not separator
            or not _RUNTIME_HOOK_PATTERN.fullmatch(path)
            or not qualifier_text.endswith(")")
        ):
            raise ArtifactEvidenceError("PyInstaller warning has invalid importers")
        importers.append(
            {
                "origin": "pyinstaller-runtime-hook",
                "qualifiers": _parse_qualifiers(qualifier_text[:-1]),
            }
        )
    return sorted(importers, key=lambda item: json.dumps(item, sort_keys=True))


def _split_importers(raw: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(raw):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                raise ArtifactEvidenceError("PyInstaller warning has invalid importers")
        elif character == "," and depth == 0:
            parts.append(raw[start:index].strip())
            start = index + 1
    if depth != 0:
        raise ArtifactEvidenceError("PyInstaller warning has invalid importers")
    parts.append(raw[start:].strip())
    if not parts or any(not part for part in parts):
        raise ArtifactEvidenceError("PyInstaller warning has invalid importers")
    return parts


def _parse_qualifiers(raw: str) -> list[str]:
    values = [value.strip() for value in raw.split(",")]
    if (
        not values
        or any(value not in _QUALIFIERS for value in values)
        or len(set(values)) != len(values)
    ):
        raise ArtifactEvidenceError("PyInstaller warning has invalid qualifiers")
    return sorted(values)


def _load_warning_allowlist(path: Path, target: TargetSpec) -> list[dict[str, object]]:
    raw = _read_json(path, _POLICY_MAX_BYTES)
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "targets"}
        or not _is_schema_version_one(raw.get("schema_version"))
    ):
        raise ArtifactEvidenceError("warning allowlist is invalid")
    targets = raw.get("targets")
    name = target.name
    if not isinstance(targets, dict) or set(targets) != _TARGET_NAMES:
        raise ArtifactEvidenceError("warning allowlist is invalid")
    entries = targets[name]
    if not isinstance(entries, list):
        raise ArtifactEvidenceError("warning allowlist is invalid")
    return entries


def _classify_warnings(
    observed: list[dict[str, object]], allowlist: list[dict[str, object]]
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    today = datetime.now(timezone.utc).date().isoformat()
    by_fingerprint: dict[str, dict[str, object]] = {}
    for entry in allowlist:
        if (
            not isinstance(entry, dict)
            or set(entry) != _WARNING_ALLOWLIST_FIELDS
            or not isinstance(entry.get("fingerprint"), str)
        ):
            raise ArtifactEvidenceError("warning allowlist is invalid")
        fingerprint = entry["fingerprint"]
        if fingerprint in by_fingerprint:
            raise ArtifactEvidenceError("warning allowlist has duplicate fingerprints")
        if not _SHA256_PATTERN.fullmatch(fingerprint) or not _valid_expiry(
            entry.get("expires_on")
        ):
            raise ArtifactEvidenceError("warning allowlist is invalid")
        classification = entry.get("classification")
        if (
            not isinstance(classification, dict)
            or set(classification) != _WARNING_CLASSIFICATION_FIELDS
            or not all(
                isinstance(classification.get(field), bool)
                for field in ("optional", "conditional", "collected")
            )
            or not isinstance(classification.get("origin_class"), str)
            or not classification["origin_class"]
            or not isinstance(entry.get("reason"), str)
            or not entry["reason"]
        ):
            raise ArtifactEvidenceError("warning allowlist is invalid")
        by_fingerprint[fingerprint] = entry
    approved: list[dict[str, object]] = []
    unknown: list[dict[str, object]] = []
    seen: set[str] = set()
    for warning in observed:
        fingerprint = str(warning["fingerprint"])
        entry = by_fingerprint.get(fingerprint)
        if (
            entry is None
            or not _matches_warning_approval(entry, warning)
            or entry["expires_on"] < today
        ):
            unknown.append(warning)
        else:
            approved.append(warning)
            seen.add(fingerprint)
    stale = [
        entry
        for fingerprint, entry in by_fingerprint.items()
        if fingerprint not in seen
    ]
    return approved, unknown, stale


def _matches_warning_approval(
    entry: Mapping[str, object], warning: Mapping[str, object]
) -> bool:
    return all(
        entry.get(field) == warning.get(field)
        for field in (
            "fingerprint",
            "code",
            "module",
            "importers",
            "target_facts",
            "collection_facts",
        )
    )


def _valid_expiry(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value).date()
    except ValueError:
        return False
    return parsed.isoformat() == value


def _load_baselines(path: Path) -> Mapping[str, object]:
    raw = _read_json(path, _POLICY_MAX_BYTES)
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "baselines"}
        or not _is_schema_version_one(raw.get("schema_version"))
    ):
        raise ArtifactEvidenceError("size baseline policy is invalid")
    baselines = raw["baselines"]
    if not isinstance(baselines, dict):
        raise ArtifactEvidenceError("size baseline policy is invalid")
    return baselines


def _baseline_issue(
    baseline: object,
    target: TargetSpec,
    metrics: Mapping[str, object],
    toolchain: Mapping[str, object],
) -> str | None:
    if baseline is None:
        return "missing"
    if not isinstance(baseline, dict) or set(baseline) != _BASELINE_FIELDS:
        return "invalid"
    if (
        not _is_schema_version_one(baseline.get("schema_version"))
        or baseline.get("target") != target.name
        or baseline.get("requirements_lock_sha256")
        != _sha256_file(target.requirements_lock)
        or baseline.get("toolchain") != toolchain
        or baseline.get("archive_profile") != metrics.get("archive_profile")
    ):
        return "provenance-mismatch"
    maximum_expanded = baseline.get("max_expanded_bytes")
    maximum_archive = baseline.get("max_archive_bytes")
    rationale = baseline.get("rationale")
    if (
        type(maximum_expanded) is not int
        or type(maximum_archive) is not int
        or maximum_expanded < 1
        or maximum_archive < 1
        or not isinstance(rationale, str)
        or not rationale
        or not _valid_measurement(baseline.get("measurement"))
        or not isinstance(baseline.get("observed"), dict)
        or not _valid_observed_metrics(baseline["observed"])
        or type(baseline.get("source_date_epoch")) is not int
        or baseline["source_date_epoch"] < 0
    ):
        return "invalid"
    expanded = metrics.get("expanded_regular_bytes")
    archive = metrics.get("archive_bytes")
    if not isinstance(expanded, int) or not isinstance(archive, int):
        return "invalid"
    if expanded > maximum_expanded or archive > maximum_archive:
        return "limit-exceeded"
    return None


def _valid_archive_profile(
    raw: object, target: TargetSpec, compression_level: int
) -> bool:
    if not isinstance(raw, dict):
        return False
    expected = {
        "format",
        "compression",
        "compression_level",
        "container_format",
        "timestamp_policy",
        "ownership_policy",
    }
    if set(raw) != expected or raw.get("format") != target.archive_format:
        return False
    if raw.get("compression_level") != compression_level:
        return False
    profiles = {
        "tar.gz": ("gzip", "pax", "source-date-epoch", "uid-gid-zero-empty-names"),
        "zip": ("deflate", "zip", "zip-clamped-source-date-epoch", "zip-unix-modes"),
    }
    expected_profile = profiles.get(target.archive_format)
    return (
        expected_profile is not None
        and (
            raw.get("compression"),
            raw.get("container_format"),
            raw.get("timestamp_policy"),
            raw.get("ownership_policy"),
        )
        == expected_profile
    )


def _valid_measurement(raw: object) -> bool:
    if not isinstance(raw, dict) or set(raw) != {
        "source_commit",
        "wheel_sha256",
        "measured_on",
    }:
        return False
    return (
        isinstance(raw.get("source_commit"), str)
        and bool(raw["source_commit"])
        and _SHA256_PATTERN.fullmatch(str(raw.get("wheel_sha256"))) is not None
        and _valid_expiry(raw.get("measured_on"))
    )


def _valid_observed_metrics(raw: Mapping[str, object]) -> bool:
    return set(raw) == {
        "expanded_regular_bytes",
        "regular_file_count",
        "directory_count",
        "symlink_count",
        "archive_bytes",
    } and all(type(value) is int and value >= 0 for value in raw.values())


def _read_json(path: Path, maximum: int) -> object:
    if type(maximum) is not int or maximum < 0:
        raise ArtifactEvidenceError("evidence policy input limit is invalid")
    try:
        status = path.lstat()
        if not stat.S_ISREG(status.st_mode) or path.is_symlink():
            raise ArtifactEvidenceError("evidence policy input is unavailable")
        with path.open("rb") as handle:
            raw = handle.read(maximum + 1)
    except OSError as error:
        raise ArtifactEvidenceError("evidence policy input is unavailable") from error
    if len(raw) > maximum:
        raise ArtifactEvidenceError("evidence policy input exceeds configured limit")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ArtifactEvidenceError("evidence policy input is invalid") from error


def _public_report_path(path: Path, evidence_dir: Path) -> Path:
    try:
        root = evidence_dir.resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        resolved.lstat()
    except (OSError, ValueError) as error:
        raise ArtifactEvidenceError("public evidence report is unavailable") from error
    if not resolved.is_file() or path.is_symlink() or resolved.parent != root:
        raise ArtifactEvidenceError("public evidence report is invalid")
    return resolved


def _read_public_report(path: Path, evidence_dir: Path, maximum: int) -> object:
    return _read_json(_public_report_path(path, evidence_dir), maximum)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactEvidenceError("evidence policy input has duplicate keys")
        result[key] = value
    return result


def _write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _require_public_directory(path: Path, policy: EvidencePolicy) -> None:
    if not path.is_dir():
        raise ArtifactEvidenceError("evidence output directory is unavailable")


def _fingerprint(record: Mapping[str, object]) -> str:
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise ArtifactEvidenceError("target lock is unavailable") from error
    return digest.hexdigest()
