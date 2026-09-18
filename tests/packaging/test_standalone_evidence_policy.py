"""Policy loader and discovery-fails evidence behavior."""

from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from scripts.standalone_cli import evidence_policy
from scripts.standalone_cli.artifact_filesystem import snapshot_payload
from scripts.standalone_cli.artifact_types import (
    ArtifactDescriptor,
    ArtifactEvidenceError,
    PayloadSnapshot,
)
from scripts.standalone_cli.embedded_notices import EmbeddedNoticeRecord
from scripts.standalone_cli.evidence_policy import (
    _PYINSTALLER_PREAMBLE,
    _baseline_issue,
    _canonical_warnings,
    _classify_warnings,
    _load_baselines,
    _NormalizedCycloneDx,
    _parse_importers,
    _read_json,
    _reconcile_normalized_sboms,
    _validate_architecture_report,
    _validate_cyclonedx_sbom,
    _validate_dependency_provenance,
    _validate_license_report,
    _validate_manifest_report,
    _validate_result_supply_reports,
    _validate_size_report,
    _validate_third_party_notice_binding,
    _validate_third_party_notices,
    _validate_warning_report,
    enforce_policy_evidence,
    load_evidence_policy,
)
from scripts.standalone_cli.evidence_policy_types import EvidenceLimits, EvidencePolicy
from scripts.standalone_cli.model import TargetSpec, load_target_spec
from scripts.standalone_cli.sbom_normalize import generate_supply_chain_evidence

_ROOT = Path(__file__).resolve().parents[2]
_POLICY = _ROOT / "packaging" / "standalone_cli" / "evidence-policy.json"
_TARGET_POLICY = _ROOT / "packaging" / "standalone_cli" / "target-policy.json"
_EMBEDDED_NOTICE_POLICY = (
    _ROOT / "packaging" / "standalone_cli" / "embedded-notices.json"
)
_LINUX_TARGET = "linux-x64-ubuntu-22.04"
_RUNTIME_NOTICE_PATH = "_internal/notices/CPython-LICENSE.txt"
_RUNTIME_NOTICE_SHA256 = "9" * 64
_WINDOWS_PE_ONE_REFERENCE = (
    "urn:servonaut:pe-component:"
    "a5315590f9fd7cfa29b9a4cca424cf26d746e4532ee5669a439be4f8597e6936"
)
_WINDOWS_PE_TWO_REFERENCE = (
    "urn:servonaut:pe-component:"
    "a4ab473bd11e9e761bbdfaa8dad146c1fafb4676a637051f8da5f283e6b78d68"
)
_WINDOWS_PE_COMBINED_REFERENCE = (
    "urn:servonaut:pe-component:"
    "fc75570ede561f59f3da9f632e28a78f259c6af0fdd6e582ea26e4f4d375c9ef"
)
_WINDOWS_PE_THREE_REFERENCE = (
    "urn:servonaut:pe-component:"
    "4ef7ca3a82a1bb55d268cd5183e81df8923373d518a6640dc662d019ab88de32"
)
_WINDOWS_PE_REFERENCE_PREFIX_FOR_TEST = "urn:servonaut:pe-component:"
_SNAPSHOT_LIMITS = EvidenceLimits(
    1024 * 1024,
    1000,
    1024 * 1024,
    8 * 1024 * 1024,
    30,
    1024 * 1024,
)


def _runtime_notice() -> dict[str, object]:
    return {
        "schema_version": 1,
        "runtime": "cpython",
        "python_implementation": "CPython",
        "python_version": "3.12.14",
        "license_id": "Python-2.0",
        "payload_path": _RUNTIME_NOTICE_PATH,
        "sha256": _RUNTIME_NOTICE_SHA256,
    }


def _manifest_regular_files(
    *paths: str, target_name: str = _LINUX_TARGET
) -> dict[str, str]:
    notices = _third_party_notices(target_name)["notices"]
    assert isinstance(notices, list)
    return {
        _RUNTIME_NOTICE_PATH: _RUNTIME_NOTICE_SHA256,
        **{row["payload_path"]: row["sha256"] for row in notices},
        **dict.fromkeys(paths, "8" * 64),
    }


def _target(name: str = _LINUX_TARGET) -> TargetSpec:
    return load_target_spec(_TARGET_POLICY, name)


def _third_party_notices(
    target_name: str = _LINUX_TARGET,
) -> dict[str, object]:
    policy = json.loads(_EMBEDDED_NOTICE_POLICY.read_text(encoding="utf-8"))
    return {
        "schema_version": 1,
        "notices": [
            {
                "distribution": row["distribution"],
                "version": row["version"],
                "source_wheel_sha256": f"{index + 1}" * 64,
                "payload_path": row["payload_path"],
                "sha256": row["sha256_by_target"][target_name],
            }
            for index, row in enumerate(policy["notices"])
        ],
    }


def _notice_closure_components(
    target_name: str = _LINUX_TARGET,
) -> list[dict[str, object]]:
    rows = _third_party_notices(target_name)["notices"]
    assert isinstance(rows, list)
    return [
        {
            "type": "library",
            "name": row["distribution"],
            "version": row["version"],
            "purl": f"pkg:pypi/{row['distribution']}@{row['version']}",
            "bom-ref": f"pkg:pypi/{row['distribution']}@{row['version']}",
            "properties": [],
            "hashes": [{"alg": "SHA-256", "content": row["source_wheel_sha256"]}],
        }
        for row in rows
    ]


def _notice_license_packages(
    target_name: str = _LINUX_TARGET,
) -> list[dict[str, object]]:
    rows = _third_party_notices(target_name)["notices"]
    assert isinstance(rows, list)
    return [
        {
            "name": row["distribution"],
            "version": row["version"],
            "license_ids": ["MIT"],
            "license_classifiers": [],
            "provenance": "installed-distribution-metadata",
        }
        for row in rows
    ]


def _notice_relationships(
    target_name: str = _LINUX_TARGET,
) -> list[dict[str, str]]:
    rows = _third_party_notices(target_name)["notices"]
    assert isinstance(rows, list)
    return [
        {"component": row["distribution"], "version": row["version"]} for row in rows
    ]


def _controlled_notice_policy(
    root: Path,
) -> tuple[Path, tuple[EmbeddedNoticeRecord, ...], dict[PurePosixPath, bytes]]:
    policy = json.loads(_EMBEDDED_NOTICE_POLICY.read_text(encoding="utf-8"))
    records: list[EmbeddedNoticeRecord] = []
    payloads: dict[PurePosixPath, bytes] = {}
    for index, row in enumerate(policy["notices"]):
        data = f"reviewed notice {index}\n".encode()
        content_sha256 = hashlib.sha256(data).hexdigest()
        source_wheel_sha256 = f"{index + 1}" * 64
        row["sha256_by_target"] = {
            target_name: content_sha256
            for target_name in (
                "windows-x64",
                "macos-x64",
                "macos-arm64",
                _LINUX_TARGET,
            )
        }
        payload_path = PurePosixPath(row["payload_path"])
        payloads[payload_path] = data
        records.append(
            EmbeddedNoticeRecord(
                distribution=row["distribution"],
                version=row["version"],
                source_wheel_sha256=source_wheel_sha256,
                payload_path=payload_path,
                sha256=content_sha256,
            )
        )
    path = root / "embedded-notices.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path, tuple(records), payloads


def _snapshot(root: Path) -> PayloadSnapshot:
    return PayloadSnapshot(
        root,
        (),
        0,
        PurePosixPath("servonaut"),
        {},
        {},
        {
            "schema_version": 1,
            "python_implementation": "CPython",
            "python_version": "3.12.14",
            "spec_sha256": "5" * 64,
            "hooks_sha256": "6" * 64,
        },
        _runtime_notice(),
    )


def _warning_fixture(
    root: Path,
    target_name: str,
    *records: str,
) -> tuple[PayloadSnapshot, ArtifactDescriptor]:
    root.mkdir(parents=True, exist_ok=True)
    warning_allowlist = root / "warnings-allowlist.json"
    warning_allowlist.write_text(
        json.dumps({
            "schema_version": 1,
            "targets": {name: [] for name in ("windows-x64", "macos-x64", "macos-arm64", _LINUX_TARGET)},
        }),
        encoding="utf-8",
    )
    target = replace(_target(target_name), warning_allowlist=warning_allowlist)
    metadata = root / "metadata"
    resolved = metadata / "resolved"
    resolved.mkdir(parents=True, exist_ok=True)
    (resolved / "environment.json").write_text(
        json.dumps({"schema_version": 1, "packages": []}), encoding="utf-8"
    )
    warning_file = root / "warn-servonaut.txt"
    warning_file.write_text(
        "\n".join((*_PYINSTALLER_PREAMBLE, *records, "")), encoding="utf-8"
    )
    return _snapshot(root), ArtifactDescriptor(
        root,
        root / "servonaut",
        None,
        target,
        root / "wheel.whl",
        warning_file,
        metadata,
    )


def _provenance(
    facts: list[dict[str, object]],
    conflicts: list[object],
    *,
    payload_python: list[dict[str, str]] | None = None,
    payload_vendored: list[dict[str, str]] | None = None,
    closure_only: list[dict[str, str]] | None = None,
    payload_additional: list[dict[str, object]] | None = None,
    bootstrap: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "scope": "resolved-python-and-payload-reconciliation",
        "build": {
            "schema_version": 1,
            "source_commit": "a" * 40,
            "target": "linux-x64-ubuntu-22.04",
            "product_version": "1.2.3",
            "build_revision": "build-1",
            "wheel_sha256": "1" * 64,
        },
        "toolchain": {
            "python_implementation": "CPython",
            "python_version": "3.12.14",
            "spec_sha256": "2" * 64,
            "hooks_sha256": "3" * 64,
            "pyinstaller_version": "6.22.3",
            "pyinstaller_hooks_version": "2026.7",
            "cyclonedx_bom_version": "7.3.1",
            "syft_version": "1.51.1",
            "syft_asset_sha256": "4" * 64,
        },
        "runtime_notice": _runtime_notice(),
        "third_party_notices": _third_party_notices(),
        "payload_python_components": payload_python or [],
        "payload_vendored_python_components": payload_vendored or [],
        "closure_only_components": closure_only or [],
        "payload_additional_components": payload_additional or [],
        "bootstrap_exceptions": bootstrap or [],
        "qualification_facts": facts,
        "unresolved_conflicts": conflicts,
    }


def test_load_evidence_policy_returns_typed_bounded_values() -> None:
    policy = load_evidence_policy(_POLICY)

    assert policy.limits.max_payload_entries == 250000
    assert policy.native.linux_max_glibc == "2.35"
    assert "warnings.json" in policy.public_file_names


def test_policy_rejects_unknown_fields(tmp_path: Path) -> None:
    payload = json.loads(_POLICY.read_text(encoding="utf-8"))
    payload["unexpected"] = True
    path = tmp_path / "evidence-policy.json"
    schema = _POLICY.with_name("evidence-policy.schema.json")
    path.write_text(json.dumps(payload), encoding="utf-8")
    (tmp_path / schema.name).write_text(
        schema.read_text(encoding="utf-8"), encoding="utf-8"
    )

    with pytest.raises(ArtifactEvidenceError, match="evidence policy is invalid"):
        load_evidence_policy(path)


def test_schema_versions_require_a_json_integer(tmp_path: Path) -> None:
    policy = json.loads(_POLICY.read_text(encoding="utf-8"))
    policy["schema_version"] = True
    policy_path = tmp_path / "evidence-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    schema = _POLICY.with_name("evidence-policy.schema.json")
    (tmp_path / schema.name).write_text(
        schema.read_text(encoding="utf-8"), encoding="utf-8"
    )
    with pytest.raises(ArtifactEvidenceError, match="evidence policy is invalid"):
        load_evidence_policy(policy_path)

    with pytest.raises(
        ArtifactEvidenceError, match="manifest evidence report is invalid"
    ):
        _validate_manifest_report(
            {"schema_version": True, "expanded_regular_bytes": 0, "entries": []}
        )

    baselines = tmp_path / "size-baselines.json"
    baselines.write_text('{"schema_version":true,"baselines":{}}', encoding="utf-8")
    with pytest.raises(ArtifactEvidenceError, match="size baseline policy is invalid"):
        _load_baselines(baselines)


def test_provenance_permits_only_reviewed_informational_facts(tmp_path: Path) -> None:
    report = tmp_path / "dependency-provenance.json"
    report.write_text(
        json.dumps(
            _provenance(
                [
                    {
                        "code": "local-wheel-acquisition-normalized",
                        "component": "servonaut",
                        "version": "1.2.3",
                        "source": "descriptor-wheel-sha256",
                    }
                ],
                [],
            )
        ),
        encoding="utf-8",
    )

    _validate_dependency_provenance(report, 8192)

    report.write_text(
        json.dumps(
            _provenance(
                [
                    {
                        "code": "non-https-optional-reference-omitted",
                        "component": "sortedcontainers",
                        "version": "2.4.0",
                        "reference_type": "unreviewed-reference-kind",
                        "source": "reviewed-http-reference-policy",
                    }
                ],
                [],
            )
        ),
        encoding="utf-8",
    )
    with pytest.raises(ArtifactEvidenceError, match="report is invalid"):
        _validate_dependency_provenance(report, 8192)

    report.write_text(
        json.dumps(
            _provenance(
                [
                    {
                        "code": "non-https-optional-reference-omitted",
                        "component": "sortedcontainers",
                        "version": "2.4.0",
                        "reference_type": "website",
                        "source": "reviewed-http-reference-policy",
                    }
                ],
                [],
            )
        ),
        encoding="utf-8",
    )
    _validate_dependency_provenance(report, 8192)

    report.write_text(
        json.dumps(
            _provenance(
                [
                    {
                        "code": "local-wheel-acquisition-normalized",
                        "component": "servonaut",
                        "version": "1.2.3",
                        "source": "reviewed-http-reference-policy",
                    }
                ],
                [],
            )
        ),
        encoding="utf-8",
    )
    with pytest.raises(ArtifactEvidenceError, match="report is invalid"):
        _validate_dependency_provenance(report, 8192)

    report.write_text(
        json.dumps(
            _provenance(
                [
                    {
                        "code": "non-https-optional-reference-omitted",
                        "component": "unreviewed-package",
                        "version": "999",
                        "reference_type": "website",
                        "source": "reviewed-http-reference-policy",
                    }
                ],
                [],
            )
        ),
        encoding="utf-8",
    )
    with pytest.raises(ArtifactEvidenceError, match="report is invalid"):
        _validate_dependency_provenance(report, 8192)

    report.write_text(
        json.dumps(_provenance([], [{"code": "unknown"}])),
        encoding="utf-8",
    )
    with pytest.raises(ArtifactEvidenceError, match="requires review"):
        _validate_dependency_provenance(report, 8192)


def test_provenance_relationships_require_exact_sorted_rows(tmp_path: Path) -> None:
    report = tmp_path / "dependency-provenance.json"
    valid = _provenance(
        [],
        [],
        payload_python=[{"component": "servonaut", "version": "1.2.3"}],
        closure_only=[{"component": "pip", "version": "24.2"}],
        payload_additional=[{"component": "resource", "type": "file", "version": None}],
        bootstrap=[
            {
                "component": "pip",
                "version": "24.2",
                "source": "venv-bootstrap",
            }
        ],
    )
    report.write_text(json.dumps(valid), encoding="utf-8")
    _validate_dependency_provenance(report, 8192)

    malformed = _provenance(
        [],
        [],
        payload_python=[
            {"component": "zeta", "version": "1.0"},
            {"component": "alpha", "version": "1.0"},
        ],
    )
    report.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(ArtifactEvidenceError, match="report is invalid"):
        _validate_dependency_provenance(report, 8192)

    malformed = _provenance(
        [],
        [],
        closure_only=[
            {"component": "pip", "version": "24.1"},
            {"component": "pip", "version": "24.2"},
        ],
    )
    report.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(ArtifactEvidenceError, match="report is invalid"):
        _validate_dependency_provenance(report, 8192)

    malformed = _provenance(
        [],
        [],
        bootstrap=[
            {
                "component": "pip",
                "version": "24.2",
                "source": "unreviewed-source",
            }
        ],
    )
    report.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(ArtifactEvidenceError, match="report is invalid"):
        _validate_dependency_provenance(report, 8192)


def test_size_baseline_requires_exact_target_provenance_and_limits() -> None:
    target = load_target_spec(
        _ROOT / "packaging" / "standalone_cli" / "target-policy.json",
        "linux-x64-ubuntu-22.04",
    )
    toolchain = _provenance([], [])["toolchain"]
    assert isinstance(toolchain, dict)
    profile = {
        "format": "tar.gz",
        "compression": "gzip",
        "compression_level": 9,
        "container_format": "pax",
        "timestamp_policy": "source-date-epoch",
        "ownership_policy": "uid-gid-zero-empty-names",
    }
    observed = {
        "expanded_regular_bytes": 100,
        "regular_file_count": 2,
        "directory_count": 1,
        "symlink_count": 0,
        "archive_bytes": 50,
    }
    metrics = {
        **observed,
        "archive_profile": profile,
        "measurement": {
            "source_commit": "a" * 40,
            "wheel_sha256": "1" * 64,
            "measured_on": "2026-09-14",
        },
    }
    assert _baseline_issue(None, target, metrics, toolchain) == "missing"
    baseline = {
        "schema_version": 1,
        "target": target.name,
        "requirements_lock_sha256": sha256(
            target.requirements_lock.read_bytes()
        ).hexdigest(),
        "toolchain": toolchain,
        "archive_profile": profile,
        "observed": observed,
        "measurement": metrics["measurement"],
        "source_date_epoch": 1700000000,
        "max_expanded_bytes": 100,
        "max_archive_bytes": 50,
        "rationale": "Reviewed measured ceiling.",
    }

    assert _baseline_issue(baseline, target, metrics, toolchain) is None
    del baseline["source_date_epoch"]
    assert _baseline_issue(baseline, target, metrics, toolchain) == "invalid"
    baseline["source_date_epoch"] = 1700000000
    baseline["target"] = "windows-x64"
    assert (
        _baseline_issue(baseline, target, metrics, toolchain) == "provenance-mismatch"
    )
    baseline["target"] = target.name
    baseline["max_archive_bytes"] = 49
    assert _baseline_issue(baseline, target, metrics, toolchain) == "limit-exceeded"


def test_final_size_gate_reloads_empty_baseline_without_candidate(
    tmp_path: Path,
) -> None:
    target = load_target_spec(
        _ROOT / "packaging" / "standalone_cli" / "target-policy.json",
        "linux-x64-ubuntu-22.04",
    )
    baseline_path = tmp_path / "size-baselines.json"
    baseline_path.write_text('{"schema_version":1,"baselines":{}}', encoding="utf-8")
    target = replace(target, size_baselines=baseline_path)
    toolchain = _provenance([], [])["toolchain"]
    assert isinstance(toolchain, dict)
    report = {
        "schema_version": 1,
        "target": target.name,
        "expanded_regular_bytes": 100,
        "regular_file_count": 2,
        "directory_count": 1,
        "symlink_count": 0,
        "archive_bytes": 50,
        "archive_sha256": "7" * 64,
        "archive_profile": {
            "format": "tar.gz",
            "compression": "gzip",
            "compression_level": 9,
            "container_format": "pax",
            "timestamp_policy": "source-date-epoch",
            "ownership_policy": "uid-gid-zero-empty-names",
        },
        "source_date_epoch": 1700000000,
        "measurement": {
            "source_commit": "a" * 40,
            "wheel_sha256": "1" * 64,
            "measured_on": "2026-09-14",
        },
    }

    with pytest.raises(
        ArtifactEvidenceError, match="size baseline requires policy review"
    ):
        _validate_size_report(report, target, toolchain, load_evidence_policy(_POLICY))


def test_final_warning_gate_rejects_malformed_report() -> None:
    target = load_target_spec(
        _ROOT / "packaging" / "standalone_cli" / "target-policy.json",
        "linux-x64-ubuntu-22.04",
    )
    with pytest.raises(
        ArtifactEvidenceError, match="warning evidence report is invalid"
    ):
        _validate_warning_report({"approved": []}, target)


@pytest.mark.parametrize(
    ("payload", "validator"),
    [
        (
            {
                "schema_version": 1,
                "expanded_regular_bytes": 1,
                "entries": [
                    {
                        "path": "bin/tool",
                        "kind": "file",
                        "mode": 493,
                        "size": 1,
                        "sha256": "a" * 64,
                        "link_target": "unexpected",
                    }
                ],
            },
            _validate_manifest_report,
        ),
        (
            {
                "schema_version": 1,
                "binaries": [
                    {
                        "path": "bin/tool",
                        "kind": "elf",
                        "machine": 62,
                        "max_glibc": None,
                        "max_glibcxx": None,
                        "max_cxxabi": None,
                        "unexpected": True,
                    }
                ],
            },
            _validate_architecture_report,
        ),
    ],
)
def test_final_reports_reject_tampered_record_shapes(
    payload: dict[str, object], validator: object
) -> None:
    assert callable(validator)
    with pytest.raises(ArtifactEvidenceError):
        validator(payload)


def _normalized_sbom(scope: str) -> dict[str, object]:
    metadata: dict[str, object] = {
        "properties": [{"name": "servonaut:evidence:scope", "value": scope}]
    }
    if scope == "frozen-payload-filesystem":
        metadata["component"] = {
            "type": "application",
            "name": "servonaut",
            "version": "1.2.3",
            "bom-ref": "urn:servonaut:payload:" + sha256(b"1.2.3").hexdigest(),
        }
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": metadata,
        "components": [],
        "dependencies": [],
    }


def _windows_pe_component(
    reference: str,
    *locations: tuple[int, str],
) -> dict[str, object]:
    return {
        "type": "application",
        "name": "Native Runtime Library",
        "version": "1.0",
        "bom-ref": reference,
        "properties": [
            *[
                {"name": f"syft:location:{index}:path", "value": path}
                for index, path in locations
            ],
            {
                "name": "syft:package:foundBy",
                "value": "pe-binary-package-cataloger",
            },
            {"name": "syft:package:metadataType", "value": "pe-binary"},
            {"name": "syft:package:type", "value": "binary"},
        ],
    }


def _write_windows_pe_final_fixture(
    root: Path,
    *,
    target_name: str = "windows-x64",
) -> tuple[SimpleNamespace, TargetSpec, EvidencePolicy, dict[str, dict[str, object]]]:
    policy = load_evidence_policy(_POLICY)
    target = _target(target_name)
    baseline_path = root / "size-baselines.json"
    warning_path = root / "warnings-allowlist.json"
    target = replace(
        target,
        size_baselines=baseline_path,
        warning_allowlist=warning_path,
    )
    warning_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "targets": {
                    "windows-x64": [],
                    "macos-x64": [],
                    "macos-arm64": [],
                    _LINUX_TARGET: [],
                },
            }
        ),
        encoding="utf-8",
    )
    location_one = "_internal/pe-a.bin"
    location_two = "_internal/pe-b.bin"
    location_three = "_internal/pe-c.bin"
    resource = "assets/data.bin"
    payload = _normalized_sbom("frozen-payload-filesystem")
    payload["components"] = [
        _windows_pe_component(_WINDOWS_PE_TWO_REFERENCE, (0, location_two)),
        _windows_pe_component(_WINDOWS_PE_ONE_REFERENCE, (0, location_one)),
        {
            "type": "file",
            "name": resource,
            "bom-ref": "urn:servonaut:file:" + "7" * 64,
            "hashes": [{"alg": "SHA-256", "content": "7" * 64}],
        },
        _servonaut_payload_component(),
    ]
    payload["dependencies"] = [
        {
            "ref": "pkg:pypi/servonaut@1.2.3",
            "dependsOn": [],
            "provides": [_WINDOWS_PE_ONE_REFERENCE],
        },
        {
            "ref": payload["metadata"]["component"]["bom-ref"],  # type: ignore[index]
            "dependsOn": [_WINDOWS_PE_ONE_REFERENCE],
        },
        {"ref": _WINDOWS_PE_ONE_REFERENCE, "dependsOn": []},
    ]
    payload["dependencies"].sort(key=lambda row: row["ref"])  # type: ignore[union-attr,index]
    closure = _normalized_sbom("isolated-build-input-closure")
    closure["components"] = [
        *_notice_closure_components(target_name),
        {
            "type": "library",
            "name": "servonaut",
            "version": "1.2.3",
            "purl": "pkg:pypi/servonaut@1.2.3",
            "bom-ref": "pkg:pypi/servonaut@1.2.3",
            "properties": [],
            "hashes": [{"alg": "SHA-256", "content": "1" * 64}],
        },
    ]
    provenance = _provenance(
        [],
        [],
        payload_python=[{"component": "servonaut", "version": "1.2.3"}],
        closure_only=_notice_relationships(target_name),
        payload_additional=[
            {
                "component": "Native Runtime Library",
                "type": "application",
                "version": "1.0",
            },
            {
                "component": "Native Runtime Library",
                "type": "application",
                "version": "1.0",
            },
            {"component": resource, "type": "file", "version": None},
        ],
    )
    provenance["build"]["target"] = target_name  # type: ignore[index]
    provenance["third_party_notices"] = _third_party_notices(target_name)
    licenses = {
        "schema_version": 1,
        "scope": "isolated-build-environment-license-claims",
        "packages": [
            *_notice_license_packages(target_name),
            {
                "name": "servonaut",
                "version": "1.2.3",
                "license_ids": [],
                "license_classifiers": [],
                "provenance": "installed-distribution-metadata",
            },
        ],
        "qualifications": [],
    }
    manifest_files = {
        **_manifest_regular_files(
            location_one,
            location_two,
            location_three,
            resource,
            target_name=target_name,
        ),
    }
    manifest = {
        "schema_version": 1,
        "expanded_regular_bytes": len(manifest_files),
        "entries": [
            {
                "path": path,
                "kind": "file",
                "mode": 0o644,
                "size": 1,
                "sha256": digest,
                "link_target": None,
            }
            for path, digest in sorted(manifest_files.items())
        ],
    }
    profile = {
        "format": target.archive_format,
        "compression": "deflate" if target.archive_format == "zip" else "gzip",
        "compression_level": 9,
        "container_format": "zip" if target.archive_format == "zip" else "pax",
        "timestamp_policy": (
            "zip-clamped-source-date-epoch"
            if target.archive_format == "zip"
            else "source-date-epoch"
        ),
        "ownership_policy": (
            "zip-unix-modes"
            if target.archive_format == "zip"
            else "uid-gid-zero-empty-names"
        ),
    }
    measurement = {
        "source_commit": "a" * 40,
        "wheel_sha256": "1" * 64,
        "measured_on": "2026-09-14",
    }
    observed = {
        "expanded_regular_bytes": len(manifest_files),
        "regular_file_count": len(manifest_files),
        "directory_count": 0,
        "symlink_count": 0,
        "archive_bytes": 1,
    }
    sizes = {
        "schema_version": 1,
        "target": target_name,
        **observed,
        "archive_sha256": "8" * 64,
        "archive_profile": profile,
        "source_date_epoch": 1_700_000_000,
        "measurement": measurement,
    }
    toolchain = provenance["toolchain"]
    baseline_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "baselines": {
                    target.size_baseline_id: {
                        "schema_version": 1,
                        "target": target_name,
                        "requirements_lock_sha256": sha256(
                            target.requirements_lock.read_bytes()
                        ).hexdigest(),
                        "toolchain": toolchain,
                        "archive_profile": profile,
                        "observed": observed,
                        "measurement": measurement,
                        "source_date_epoch": 1_700_000_000,
                        "max_expanded_bytes": 1024,
                        "max_archive_bytes": 1024,
                        "rationale": "Reviewed test fixture ceiling.",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    warnings = {
        "schema_version": 1,
        "approved": [],
        "unknown": [],
        "stale": [],
        "counts": {"approved": 0, "unknown": 0, "stale": 0},
        "collection_facts": {
            "preamble_sha256": (
                "9d32fd5e4bb29d37a5b2722bde2f1e3da09297e3743c3310f3fda87bf3738646"
            ),
            "record_count": 0,
        },
    }
    documents = {
        "manifest.json": manifest,
        "sizes.json": sizes,
        "warnings.json": warnings,
        "architecture.json": {"schema_version": 1, "binaries": []},
        "sbom-payload.cdx.json": payload,
        "sbom-python-closure.cdx.json": closure,
        "dependency-provenance.json": provenance,
        "licenses.json": licenses,
    }
    _write_final_fixture_documents(root, documents)
    result = SimpleNamespace(
        evidence_dir=root,
        manifest=root / "manifest.json",
        sizes=root / "sizes.json",
        sboms=(
            root / "sbom-payload.cdx.json",
            root / "sbom-python-closure.cdx.json",
        ),
        warnings=root / "warnings.json",
        architecture=root / "architecture.json",
    )
    return result, target, policy, documents


def _write_final_fixture_documents(
    root: Path, documents: dict[str, dict[str, object]]
) -> None:
    for name, document in documents.items():
        (root / name).write_text(json.dumps(document), encoding="utf-8")


def _runtime_component() -> dict[str, object]:
    return {
        "type": "application",
        "name": "python",
        "version": "3.12.14",
        "purl": "pkg:generic/python@3.12.14",
        "bom-ref": "pkg:generic/python@3.12.14",
        "licenses": [{"license": {"id": "Python-2.0"}}],
        "properties": [
            {
                "name": "syft:cpe23",
                "value": "cpe:2.3:a:python:python:3.12.14:*:*:*:*:*:*:*",
            },
            {
                "name": "syft:location:0:path",
                "value": "_internal/libpython3.12.so.1.0",
            },
            {
                "name": "syft:package:foundBy",
                "value": "binary-classifier-cataloger",
            },
            {"name": "syft:package:metadataType", "value": "binary-signature"},
            {"name": "syft:package:type", "value": "binary"},
        ],
    }


def _servonaut_payload_component() -> dict[str, object]:
    return {
        "type": "library",
        "name": "servonaut",
        "version": "1.2.3",
        "purl": "pkg:pypi/servonaut@1.2.3",
        "bom-ref": "pkg:pypi/servonaut@1.2.3",
    }


def _servonaut_closure() -> _NormalizedCycloneDx:
    closure = _normalized_sbom("isolated-build-input-closure")
    closure["components"] = [
        {
            "type": "library",
            "name": "servonaut",
            "version": "1.2.3",
            "purl": "pkg:pypi/servonaut@1.2.3",
            "bom-ref": "pkg:pypi/servonaut@1.2.3",
            "properties": [],
            "hashes": [{"alg": "SHA-256", "content": "1" * 64}],
        }
    ]
    return _validate_cyclonedx_sbom(closure, "isolated-build-input-closure")


def test_windows_pe_occurrences_pass_final_facade_with_exact_multiset(
    tmp_path: Path,
) -> None:
    result, target, policy, documents = _write_windows_pe_final_fixture(tmp_path)

    enforce_policy_evidence(result, target, policy)

    payload = documents["sbom-payload.cdx.json"]
    components = payload["components"]
    assert isinstance(components, list)
    assert [component["bom-ref"] for component in components[:2]] == [
        _WINDOWS_PE_TWO_REFERENCE,
        _WINDOWS_PE_ONE_REFERENCE,
    ]
    provenance = documents["dependency-provenance.json"]
    assert provenance["payload_additional_components"][:2] == [
        {
            "component": "Native Runtime Library",
            "type": "application",
            "version": "1.0",
        },
        {
            "component": "Native Runtime Library",
            "type": "application",
            "version": "1.0",
        },
    ]
    dependencies = payload["dependencies"]
    assert isinstance(dependencies, list)
    assert not any(
        dependency.get("ref") == _WINDOWS_PE_TWO_REFERENCE
        for dependency in dependencies
        if isinstance(dependency, dict)
    )


def test_windows_pe_reference_uses_sorted_location_values_not_property_indices(
    tmp_path: Path,
) -> None:
    result, target, policy, documents = _write_windows_pe_final_fixture(tmp_path)
    payload = documents["sbom-payload.cdx.json"]
    components = payload["components"]
    assert isinstance(components, list)
    components[0] = _windows_pe_component(
        _WINDOWS_PE_COMBINED_REFERENCE,
        (0, "_internal/pe-b.bin"),
        (1, "_internal/pe-a.bin"),
    )
    components.pop(1)
    dependencies = payload["dependencies"]
    assert isinstance(dependencies, list)
    for dependency in dependencies:
        assert isinstance(dependency, dict)
        if dependency.get("ref") == _WINDOWS_PE_ONE_REFERENCE:
            dependency["ref"] = _WINDOWS_PE_COMBINED_REFERENCE
        dependency["dependsOn"] = [
            _WINDOWS_PE_COMBINED_REFERENCE
            if reference == _WINDOWS_PE_ONE_REFERENCE
            else reference
            for reference in dependency.get("dependsOn", [])
        ]
        if "provides" in dependency:
            dependency["provides"] = [
                _WINDOWS_PE_COMBINED_REFERENCE
                if reference == _WINDOWS_PE_ONE_REFERENCE
                else reference
                for reference in dependency["provides"]
            ]
    dependencies.sort(key=lambda row: row["ref"])
    provenance = documents["dependency-provenance.json"]
    additional = provenance["payload_additional_components"]
    assert isinstance(additional, list)
    additional.pop(1)
    _write_final_fixture_documents(tmp_path, documents)

    enforce_policy_evidence(result, target, policy)


def test_windows_near_pe_singleton_retains_legacy_acceptance(tmp_path: Path) -> None:
    result, target, policy, documents = _write_windows_pe_final_fixture(tmp_path)
    payload = documents["sbom-payload.cdx.json"]
    components = payload["components"]
    assert isinstance(components, list)
    legacy_reference = "urn:servonaut:component:" + "6" * 64
    components[0]["bom-ref"] = legacy_reference
    properties = components[0]["properties"]
    assert isinstance(properties, list)
    marker = next(
        item for item in properties if item["name"] == "syft:package:metadataType"
    )
    marker["value"] = "other-binary"
    components.pop(1)
    dependencies = payload["dependencies"]
    assert isinstance(dependencies, list)
    for dependency in dependencies:
        assert isinstance(dependency, dict)
        if dependency.get("ref") == _WINDOWS_PE_ONE_REFERENCE:
            dependency["ref"] = legacy_reference
        dependency["dependsOn"] = [
            legacy_reference if reference == _WINDOWS_PE_ONE_REFERENCE else reference
            for reference in dependency.get("dependsOn", [])
        ]
        if "provides" in dependency:
            dependency["provides"] = [
                legacy_reference
                if reference == _WINDOWS_PE_ONE_REFERENCE
                else reference
                for reference in dependency["provides"]
            ]
    dependencies.sort(key=lambda row: row["ref"])
    provenance = documents["dependency-provenance.json"]
    additional = provenance["payload_additional_components"]
    assert isinstance(additional, list)
    additional.pop(1)
    _write_final_fixture_documents(tmp_path, documents)

    enforce_policy_evidence(result, target, policy)


@pytest.mark.parametrize(
    "mutation",
    [
        "non-windows",
        "missing-marker",
        "duplicate-marker",
        "duplicate-location",
        "overlapping-locations",
        "wrong-reference",
        "missing-manifest-location",
        "sbom-occurrence-removed",
        "sbom-occurrence-added",
        "provenance-occurrence-removed",
        "provenance-occurrence-added",
        "decreasing-summary",
        "wrong-summary",
        "generic-duplicate",
        "purl-pe-reference",
    ],
)
def test_final_facade_rejects_windows_pe_occurrence_tampering(
    tmp_path: Path,
    mutation: str,
) -> None:
    target_name = _LINUX_TARGET if mutation == "non-windows" else "windows-x64"
    result, target, policy, documents = _write_windows_pe_final_fixture(
        tmp_path, target_name=target_name
    )
    payload = documents["sbom-payload.cdx.json"]
    components = payload["components"]
    assert isinstance(components, list)
    provenance = documents["dependency-provenance.json"]
    additional = provenance["payload_additional_components"]
    assert isinstance(additional, list)
    if mutation == "missing-marker":
        properties = components[1]["properties"]
        assert isinstance(properties, list)
        properties.pop()
    elif mutation == "duplicate-marker":
        properties = components[1]["properties"]
        assert isinstance(properties, list)
        properties.append({"name": "syft:package:type", "value": "binary"})
    elif mutation == "duplicate-location":
        properties = components[1]["properties"]
        assert isinstance(properties, list)
        properties.insert(
            1,
            {"name": "syft:location:1:path", "value": "_internal/pe-a.bin"},
        )
    elif mutation == "overlapping-locations":
        components[1] = _windows_pe_component(
            _WINDOWS_PE_COMBINED_REFERENCE,
            (0, "_internal/pe-b.bin"),
            (1, "_internal/pe-a.bin"),
        )
        payload["dependencies"] = []
    elif mutation == "wrong-reference":
        components[1]["bom-ref"] = _WINDOWS_PE_REFERENCE_PREFIX_FOR_TEST + "f" * 64
        payload["dependencies"] = []
    elif mutation == "missing-manifest-location":
        manifest = documents["manifest.json"]
        entries = manifest["entries"]
        assert isinstance(entries, list)
        entry = next(item for item in entries if item["path"] == "_internal/pe-a.bin")
        entry["path"] = "_internal/unrelated.bin"
        entries.sort(key=lambda item: item["path"])
    elif mutation == "sbom-occurrence-removed":
        components.pop(0)
    elif mutation == "sbom-occurrence-added":
        components.append(
            _windows_pe_component(
                _WINDOWS_PE_THREE_REFERENCE, (0, "_internal/pe-c.bin")
            )
        )
        components.sort(
            key=lambda component: (
                component["type"],
                component["name"],
                component.get("version", ""),
                component["bom-ref"],
            )
        )
    elif mutation == "provenance-occurrence-removed":
        additional.pop(1)
    elif mutation == "provenance-occurrence-added":
        additional.insert(0, dict(additional[0]))
    elif mutation == "decreasing-summary":
        additional[0]["component"] = "Zeta Runtime"
    elif mutation == "wrong-summary":
        additional[1]["component"] = "Zeta Runtime"
    elif mutation == "generic-duplicate":
        for index, component in enumerate(components[:2]):
            component["bom-ref"] = "urn:servonaut:component:" + str(index + 1) * 64
            component["properties"] = []
        payload["dependencies"] = []
    elif mutation == "purl-pe-reference":
        components[-1]["bom-ref"] = _WINDOWS_PE_REFERENCE_PREFIX_FOR_TEST + "e" * 64
        payload["dependencies"] = []
    if mutation in {"generic-duplicate", "overlapping-locations", "wrong-reference"}:
        _validate_cyclonedx_sbom(payload, "frozen-payload-filesystem")
    _write_final_fixture_documents(tmp_path, documents)

    with pytest.raises(ArtifactEvidenceError, match="provenance|CycloneDX"):
        enforce_policy_evidence(result, target, policy)


def test_final_sbom_gate_requires_normalized_cyclonedx_documents() -> None:
    for scope in ("frozen-payload-filesystem", "isolated-build-input-closure"):
        _validate_cyclonedx_sbom(_normalized_sbom(scope), scope)
        with pytest.raises(ArtifactEvidenceError, match="CycloneDX"):
            _validate_cyclonedx_sbom({"not": "CycloneDX"}, scope)

    malformed_component = _normalized_sbom("isolated-build-input-closure")
    malformed_component["components"] = [
        {
            "type": "library",
            "name": "example",
            "version": "1.0",
            "purl": "pkg:pypi/example@1.0",
            "bom-ref": "pkg:pypi/example@1.0",
            "properties": [],
            "unexpected": True,
        }
    ]
    with pytest.raises(ArtifactEvidenceError, match="CycloneDX"):
        _validate_cyclonedx_sbom(malformed_component, "isolated-build-input-closure")


def test_final_sbom_gate_requires_typed_version_and_canonical_hashes() -> None:
    document = _normalized_sbom("isolated-build-input-closure")
    document["version"] = True
    with pytest.raises(ArtifactEvidenceError, match="CycloneDX"):
        _validate_cyclonedx_sbom(document, "isolated-build-input-closure")

    document = _normalized_sbom("isolated-build-input-closure")
    component = {
        "type": "library",
        "name": "example",
        "version": "1.0",
        "purl": "pkg:pypi/example@1.0",
        "bom-ref": "pkg:pypi/example@1.0",
        "properties": [],
        "hashes": [{"alg": "SHA3-512", "content": "a" * 128}],
    }
    document["components"] = [component]
    _validate_cyclonedx_sbom(document, "isolated-build-input-closure")

    component["hashes"] = [
        {"alg": "SHA-512", "content": "a" * 128},
        {"alg": "MD5", "content": "b" * 32},
    ]
    with pytest.raises(ArtifactEvidenceError, match="CycloneDX"):
        _validate_cyclonedx_sbom(document, "isolated-build-input-closure")


def test_manifest_reload_retains_regular_file_digests() -> None:
    report = {
        "schema_version": 1,
        "expanded_regular_bytes": 1,
        "entries": [
            {
                "path": _RUNTIME_NOTICE_PATH,
                "kind": "file",
                "mode": 0o644,
                "size": 1,
                "sha256": _RUNTIME_NOTICE_SHA256,
                "link_target": None,
            },
            {
                "path": "runtime-link",
                "kind": "symlink",
                "mode": 0o777,
                "size": 0,
                "sha256": None,
                "link_target": _RUNTIME_NOTICE_PATH,
            },
        ],
    }

    assert _validate_manifest_report(report) == {
        _RUNTIME_NOTICE_PATH: _RUNTIME_NOTICE_SHA256
    }


def test_provenance_requires_exact_runtime_notice_bound_to_toolchain(
    tmp_path: Path,
) -> None:
    report = tmp_path / "dependency-provenance.json"
    valid = _provenance([], [])
    report.write_text(json.dumps(valid), encoding="utf-8")
    _validate_dependency_provenance(report, 8192)

    mutations: tuple[tuple[str, object], ...] = (
        ("schema_version", True),
        ("runtime", "python"),
        ("python_implementation", "PyPy"),
        ("python_version", "3.12"),
        ("python_version", "3.12.99"),
        ("license_id", "PSF-2.0"),
        ("payload_path", "_internal/notices/other.txt"),
        ("sha256", "A" * 64),
    )
    for field, value in mutations:
        malformed = deepcopy(valid)
        malformed["runtime_notice"][field] = value  # type: ignore[index]
        report.write_text(json.dumps(malformed), encoding="utf-8")
        with pytest.raises(ArtifactEvidenceError, match="runtime notice provenance"):
            _validate_dependency_provenance(report, 8192)

    malformed = deepcopy(valid)
    malformed.pop("runtime_notice")
    report.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(ArtifactEvidenceError, match="provenance report"):
        _validate_dependency_provenance(report, 8192)


def test_third_party_notice_provenance_requires_exact_object_and_rows() -> None:
    valid = _third_party_notices()
    assert _validate_third_party_notices(valid) == tuple(valid["notices"])

    malformed_reports: list[object] = [
        valid["notices"],
        {**valid, "schema_version": True},
        {**valid, "unexpected": True},
        {**valid, "notices": valid["notices"][:-1]},
        {**valid, "notices": None},
    ]
    for malformed in malformed_reports:
        with pytest.raises(ArtifactEvidenceError, match="notice provenance"):
            _validate_third_party_notices(malformed)

    row_mutations = (
        ("distribution", "Not-Canonical"),
        ("version", ""),
        ("source_wheel_sha256", "A" * 64),
        ("payload_path", "../LICENSE"),
        ("sha256", "A" * 64),
    )
    for field, value in row_mutations:
        malformed = deepcopy(valid)
        malformed["notices"][0][field] = value  # type: ignore[index]
        with pytest.raises(ArtifactEvidenceError, match="notice provenance"):
            _validate_third_party_notices(malformed)

    for rows in (
        [*valid["notices"][:1], *valid["notices"][:1], *valid["notices"][2:]],
        list(reversed(valid["notices"])),
    ):
        with pytest.raises(ArtifactEvidenceError, match="notice provenance"):
            _validate_third_party_notices({"schema_version": 1, "notices": rows})

    duplicate_path = deepcopy(valid)
    duplicate_path["notices"][1]["payload_path"] = duplicate_path["notices"][0][  # type: ignore[index]
        "payload_path"
    ]
    with pytest.raises(ArtifactEvidenceError, match="notice provenance"):
        _validate_third_party_notices(duplicate_path)


def test_third_party_notices_bind_target_closure_license_toolchain_and_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _target()
    closure_document = _normalized_sbom("isolated-build-input-closure")
    closure_document["components"] = _notice_closure_components()
    closure = _validate_cyclonedx_sbom(closure_document, "isolated-build-input-closure")
    provenance = _provenance([], [])
    licenses = {row["component"]: row["version"] for row in _notice_relationships()}
    manifest = _manifest_regular_files()

    _validate_third_party_notice_binding(
        closure, provenance, licenses, manifest, target, 1_000_000
    )

    cases: list[
        tuple[_NormalizedCycloneDx, dict[str, object], dict[str, str], dict[str, str]]
    ] = []
    wrong_target = deepcopy(provenance)
    wrong_target["build"]["target"] = "windows-x64"  # type: ignore[index]
    cases.append((closure, wrong_target, licenses, manifest))
    wrong_record = deepcopy(provenance)
    wrong_record["third_party_notices"]["notices"][0]["sha256"] = "8" * 64  # type: ignore[index]
    cases.append((closure, wrong_record, licenses, manifest))
    forged_manifest = dict(manifest)
    forged_path = wrong_record["third_party_notices"]["notices"][0]["payload_path"]  # type: ignore[index]
    forged_manifest[forged_path] = "8" * 64
    cases.append((closure, wrong_record, licenses, forged_manifest))
    wrong_version = deepcopy(provenance)
    wrong_version["third_party_notices"]["notices"][0]["version"] = "9.9.9"  # type: ignore[index]
    cases.append((closure, wrong_version, licenses, manifest))
    wrong_path = deepcopy(provenance)
    wrong_path["third_party_notices"]["notices"][0]["payload_path"] = (  # type: ignore[index]
        "_internal/notices/other-LICENSE.txt"
    )
    cases.append((closure, wrong_path, licenses, manifest))
    wrong_source = deepcopy(provenance)
    wrong_source["third_party_notices"]["notices"][0]["source_wheel_sha256"] = (  # type: ignore[index]
        "9" * 64
    )
    cases.append((closure, wrong_source, licenses, manifest))
    wrong_toolchain = deepcopy(provenance)
    wrong_toolchain["toolchain"]["pyinstaller_version"] = "9.9.9"  # type: ignore[index]
    cases.append((closure, wrong_toolchain, licenses, manifest))
    cases.append((closure, provenance, {**licenses, "pyinstaller": "9.9.9"}, manifest))
    missing_manifest = dict(manifest)
    missing_manifest.pop(_third_party_notices()["notices"][0]["payload_path"])
    cases.append((closure, provenance, licenses, missing_manifest))

    for candidate_closure, candidate, candidate_licenses, candidate_manifest in cases:
        with pytest.raises(ArtifactEvidenceError, match="notice"):
            _validate_third_party_notice_binding(
                candidate_closure,
                candidate,
                candidate_licenses,
                candidate_manifest,
                target,
                1_000_000,
            )

    for hashes in (
        [{"alg": "SHA-256", "content": "9" * 64}],
        [
            {"alg": "SHA-1", "content": "a" * 40},
            {"alg": "SHA-256", "content": "1" * 64},
        ],
    ):
        malformed = deepcopy(closure_document)
        malformed["components"][0]["hashes"] = hashes  # type: ignore[index]
        with pytest.raises(ArtifactEvidenceError, match="closure binding"):
            _validate_third_party_notice_binding(
                _validate_cyclonedx_sbom(malformed, "isolated-build-input-closure"),
                provenance,
                licenses,
                manifest,
                target,
                1_000_000,
            )

    missing_component = deepcopy(closure_document)
    missing_component["components"] = missing_component["components"][1:]  # type: ignore[index]
    with pytest.raises(ArtifactEvidenceError, match="closure binding"):
        _validate_third_party_notice_binding(
            _validate_cyclonedx_sbom(missing_component, "isolated-build-input-closure"),
            provenance,
            licenses,
            manifest,
            target,
            1_000_000,
        )

    windows_target = _target("windows-x64")
    windows_provenance = _provenance([], [])
    windows_provenance["build"]["target"] = windows_target.name  # type: ignore[index]
    windows_provenance["third_party_notices"] = _third_party_notices(
        windows_target.name
    )
    windows_rows = windows_provenance["third_party_notices"]["notices"]  # type: ignore[index]
    windows_manifest = {row["payload_path"]: row["sha256"] for row in windows_rows}
    _validate_third_party_notice_binding(
        closure,
        windows_provenance,
        licenses,
        windows_manifest,
        windows_target,
        1_000_000,
    )

    invalid_policy = tmp_path / "embedded-notices.json"
    invalid_policy.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        "scripts.standalone_cli.evidence_policy._EMBEDDED_NOTICE_POLICY_PATH",
        invalid_policy,
    )
    with pytest.raises(ArtifactEvidenceError, match="notice policy is invalid"):
        _validate_third_party_notice_binding(
            closure, provenance, licenses, manifest, target, 1_000_000
        )


def test_runtime_notice_reconciles_manifest_and_linux_generic_component() -> None:
    payload = _normalized_sbom("frozen-payload-filesystem")
    payload["components"] = [_runtime_component(), _servonaut_payload_component()]
    normalized_payload = _validate_cyclonedx_sbom(payload, "frozen-payload-filesystem")
    provenance = _provenance(
        [],
        [],
        payload_python=[{"component": "servonaut", "version": "1.2.3"}],
        payload_additional=[
            {"component": "python", "type": "application", "version": "3.12.14"}
        ],
    )

    _reconcile_normalized_sboms(
        normalized_payload,
        _servonaut_closure(),
        provenance,
        {"servonaut": "1.2.3"},
        _manifest_regular_files(),
        _target(),
    )

    for field, value in (
        ("version", "3.12.15"),
        ("purl", "pkg:generic/python@3.12.15"),
        ("licenses", None),
        (
            "licenses",
            [
                {"license": {"id": "Python-2.0"}},
                {"license": {"id": "MIT"}},
            ],
        ),
        ("properties", []),
    ):
        malformed = deepcopy(payload)
        component = malformed["components"][0]  # type: ignore[index]
        if value is None:
            component.pop(field)
        else:
            component[field] = value
        with pytest.raises(ArtifactEvidenceError, match="embedded Python runtime"):
            _reconcile_normalized_sboms(
                _validate_cyclonedx_sbom(malformed, "frozen-payload-filesystem"),
                _servonaut_closure(),
                provenance,
                {"servonaut": "1.2.3"},
                _manifest_regular_files(),
                _target(),
            )


def test_runtime_notice_requires_exact_pinned_syft_properties() -> None:
    payload = _normalized_sbom("frozen-payload-filesystem")
    payload["components"] = [_runtime_component(), _servonaut_payload_component()]
    provenance = _provenance(
        [],
        [],
        payload_python=[{"component": "servonaut", "version": "1.2.3"}],
        payload_additional=[
            {"component": "python", "type": "application", "version": "3.12.14"}
        ],
    )
    properties = deepcopy(payload["components"][0]["properties"])
    assert isinstance(properties, list)
    wrong_cpe = deepcopy(properties)
    wrong_cpe[0]["value"] = "cpe:2.3:a:python:python:3.12.13:*:*:*:*:*:*:*"
    wrong_type = deepcopy(properties)
    wrong_type[-1]["value"] = "shared-library"
    wrong_path = deepcopy(properties)
    wrong_path[1]["value"] = "_internal/libpython3.12.so.1.1"
    cases = (
        ("missing", properties[:-1]),
        (
            "extra",
            [*properties, {"name": "syft:package:source", "value": "unknown"}],
        ),
        ("reordered", [properties[1], properties[0], *properties[2:]]),
        ("duplicate", [*properties, deepcopy(properties[-1])]),
        ("wrong-cpe", wrong_cpe),
        ("wrong-type", wrong_type),
        ("wrong-path", wrong_path),
    )
    for _name, candidate_properties in cases:
        malformed = deepcopy(payload)
        component = malformed["components"][0]
        assert isinstance(component, dict)
        component["properties"] = candidate_properties
        with pytest.raises(ArtifactEvidenceError, match="embedded Python runtime"):
            _reconcile_normalized_sboms(
                _validate_cyclonedx_sbom(malformed, "frozen-payload-filesystem"),
                _servonaut_closure(),
                provenance,
                {"servonaut": "1.2.3"},
                _manifest_regular_files(),
                _target(),
            )


def test_runtime_notice_rejects_manifest_drift_and_non_linux_generic() -> None:
    payload = _normalized_sbom("frozen-payload-filesystem")
    payload["components"] = [_runtime_component(), _servonaut_payload_component()]
    normalized_payload = _validate_cyclonedx_sbom(payload, "frozen-payload-filesystem")
    provenance = _provenance(
        [],
        [],
        payload_python=[{"component": "servonaut", "version": "1.2.3"}],
        payload_additional=[
            {"component": "python", "type": "application", "version": "3.12.14"}
        ],
    )

    linked_notice_manifest = _validate_manifest_report(
        {
            "schema_version": 1,
            "expanded_regular_bytes": 0,
            "entries": [
                {
                    "path": _RUNTIME_NOTICE_PATH,
                    "kind": "symlink",
                    "mode": 0o777,
                    "size": 0,
                    "sha256": None,
                    "link_target": "elsewhere",
                }
            ],
        }
    )
    for manifest in (
        {},
        {_RUNTIME_NOTICE_PATH: "8" * 64},
        linked_notice_manifest,
    ):
        with pytest.raises(ArtifactEvidenceError, match="manifest binding"):
            _reconcile_normalized_sboms(
                normalized_payload,
                _servonaut_closure(),
                provenance,
                {"servonaut": "1.2.3"},
                manifest,
                _target(),
            )

    non_linux = deepcopy(provenance)
    non_linux["build"]["target"] = "windows-x64"  # type: ignore[index]
    with pytest.raises(ArtifactEvidenceError, match="embedded Python runtime"):
        _reconcile_normalized_sboms(
            normalized_payload,
            _servonaut_closure(),
            non_linux,
            {"servonaut": "1.2.3"},
            _manifest_regular_files(),
            _target("windows-x64"),
        )

    unsupported_generic = deepcopy(payload)
    unsupported_generic["components"] = [
        {
            **_runtime_component(),
            "name": "cpython",
            "purl": "pkg:generic/cpython@3.12.14",
            "bom-ref": "pkg:generic/cpython@3.12.14",
        },
        _servonaut_payload_component(),
    ]
    with pytest.raises(ArtifactEvidenceError, match="embedded Python runtime"):
        _reconcile_normalized_sboms(
            _validate_cyclonedx_sbom(unsupported_generic, "frozen-payload-filesystem"),
            _servonaut_closure(),
            provenance,
            {"servonaut": "1.2.3"},
            _manifest_regular_files(),
            _target(),
        )

    payload["components"] = [_servonaut_payload_component()]
    non_linux["payload_additional_components"] = []
    _reconcile_normalized_sboms(
        _validate_cyclonedx_sbom(payload, "frozen-payload-filesystem"),
        _servonaut_closure(),
        non_linux,
        {"servonaut": "1.2.3"},
        _manifest_regular_files(),
        _target("windows-x64"),
    )


def test_normalized_sboms_bind_product_and_relationships(tmp_path: Path) -> None:
    report = tmp_path / "dependency-provenance.json"
    report.write_text(
        json.dumps(
            _provenance(
                [],
                [],
                payload_python=[{"component": "servonaut", "version": "1.2.3"}],
            )
        ),
        encoding="utf-8",
    )
    provenance = _validate_dependency_provenance(report, 8192)
    payload = _normalized_sbom("frozen-payload-filesystem")
    payload["components"] = [
        {
            "type": "library",
            "name": "servonaut",
            "version": "1.2.3",
            "purl": "pkg:pypi/servonaut@1.2.3",
            "bom-ref": "pkg:pypi/servonaut@1.2.3",
        }
    ]
    closure = _normalized_sbom("isolated-build-input-closure")
    closure["components"] = [
        {
            "type": "library",
            "name": "servonaut",
            "version": "1.2.3",
            "purl": "pkg:pypi/servonaut@1.2.3",
            "bom-ref": "pkg:pypi/servonaut@1.2.3",
            "properties": [],
            "hashes": [{"alg": "SHA-256", "content": "1" * 64}],
        }
    ]
    _reconcile_normalized_sboms(
        _validate_cyclonedx_sbom(payload, "frozen-payload-filesystem"),
        _validate_cyclonedx_sbom(closure, "isolated-build-input-closure"),
        provenance,
        {"servonaut": "1.2.3"},
        _manifest_regular_files(),
        _target(),
    )

    payload["metadata"]["component"]["version"] = "9.9.9"  # type: ignore[index]
    with pytest.raises(ArtifactEvidenceError, match="provenance"):
        _reconcile_normalized_sboms(
            _validate_cyclonedx_sbom(payload, "frozen-payload-filesystem"),
            _validate_cyclonedx_sbom(closure, "isolated-build-input-closure"),
            provenance,
            {"servonaut": "1.2.3"},
            _manifest_regular_files(),
            _target(),
        )


def test_vendored_python_relationship_requires_regular_policy_bound_locations(
    tmp_path: Path,
) -> None:
    location = (
        "_internal/setuptools/_vendor/importlib_metadata-8.7.1.dist-info/METADATA"
    )
    payload = _normalized_sbom("frozen-payload-filesystem")
    payload["components"] = [
        {
            "type": "library",
            "name": "importlib-metadata",
            "version": "8.7.1",
            "purl": "pkg:pypi/importlib-metadata@8.7.1",
            "bom-ref": "pkg:pypi/importlib-metadata@8.7.1",
            "properties": [{"name": "syft:location:0:path", "value": location}],
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        },
        {
            "type": "library",
            "name": "servonaut",
            "version": "1.2.3",
            "purl": "pkg:pypi/servonaut@1.2.3",
            "bom-ref": "pkg:pypi/servonaut@1.2.3",
        },
    ]
    closure = _normalized_sbom("isolated-build-input-closure")
    closure["components"] = [
        {
            "type": "library",
            "name": "servonaut",
            "version": "1.2.3",
            "purl": "pkg:pypi/servonaut@1.2.3",
            "bom-ref": "pkg:pypi/servonaut@1.2.3",
            "properties": [],
            "hashes": [{"alg": "SHA-256", "content": "1" * 64}],
        },
        {
            "type": "library",
            "name": "setuptools",
            "version": "84.0.0",
            "purl": "pkg:pypi/setuptools@84.0.0",
            "bom-ref": "pkg:pypi/setuptools@84.0.0",
            "properties": [],
        },
    ]
    vendor = {
        "component": "importlib-metadata",
        "version": "8.7.1",
        "parent": "setuptools",
        "parent_version": "84.0.0",
        "origin": "parent-vendor-dist-info",
    }
    provenance = _provenance(
        [],
        [],
        payload_python=[{"component": "servonaut", "version": "1.2.3"}],
        payload_vendored=[vendor],
        closure_only=[{"component": "setuptools", "version": "84.0.0"}],
    )
    normalized_payload = _validate_cyclonedx_sbom(payload, "frozen-payload-filesystem")
    normalized_closure = _validate_cyclonedx_sbom(
        closure, "isolated-build-input-closure"
    )
    licenses = {"servonaut": "1.2.3", "setuptools": "84.0.0"}
    _reconcile_normalized_sboms(
        normalized_payload,
        normalized_closure,
        provenance,
        licenses,
        _manifest_regular_files(location),
        _target(),
    )
    assert payload["components"][0]["licenses"] == [{"license": {"id": "Apache-2.0"}}]

    with pytest.raises(ArtifactEvidenceError, match="provenance"):
        _reconcile_normalized_sboms(
            normalized_payload,
            normalized_closure,
            provenance,
            licenses,
            _manifest_regular_files(),
            _target(),
        )

    for kind, link_target in (("directory", None), ("symlink", "elsewhere")):
        manifest_files = _validate_manifest_report(
            {
                "schema_version": 1,
                "expanded_regular_bytes": 0,
                "entries": [
                    {
                        "path": _RUNTIME_NOTICE_PATH,
                        "kind": "file",
                        "mode": 0o644,
                        "size": 1,
                        "sha256": _RUNTIME_NOTICE_SHA256,
                        "link_target": None,
                    },
                    {
                        "path": location,
                        "kind": kind,
                        "mode": 0o755,
                        "size": 0,
                        "sha256": None,
                        "link_target": link_target,
                    },
                ],
            }
        )
        with pytest.raises(ArtifactEvidenceError, match="provenance"):
            _reconcile_normalized_sboms(
                normalized_payload,
                normalized_closure,
                provenance,
                licenses,
                manifest_files,
                _target(),
            )

    for invalid_location in (
        "_internal/setuptools/_vendor/importlib_metadata-8.7.1.dist-info",
        "_internal/setuptools/_vendor/importlib_metadata-9.9.9.dist-info/METADATA",
        "_internal/other/_vendor/importlib_metadata-8.7.1.dist-info/METADATA",
    ):
        malformed_payload = deepcopy(payload)
        malformed_payload["components"][0]["properties"] = [
            {"name": "syft:location:0:path", "value": invalid_location}
        ]
        with pytest.raises(ArtifactEvidenceError, match="provenance"):
            _reconcile_normalized_sboms(
                _validate_cyclonedx_sbom(
                    malformed_payload, "frozen-payload-filesystem"
                ),
                normalized_closure,
                provenance,
                licenses,
                _manifest_regular_files(invalid_location),
                _target(),
            )

    duplicate_location_payload = deepcopy(payload)
    duplicate_location_payload["components"][0]["properties"].append(
        {"name": "syft:location:1:path", "value": location}
    )
    with pytest.raises(ArtifactEvidenceError, match="provenance"):
        _reconcile_normalized_sboms(
            _validate_cyclonedx_sbom(
                duplicate_location_payload, "frozen-payload-filesystem"
            ),
            normalized_closure,
            provenance,
            licenses,
            _manifest_regular_files(location),
            _target(),
        )

    forged_provenance = deepcopy(provenance)
    forged_provenance["payload_vendored_python_components"][0]["parent_version"] = (
        "9.9.9"
    )
    with pytest.raises(ArtifactEvidenceError, match="provenance"):
        _reconcile_normalized_sboms(
            normalized_payload,
            normalized_closure,
            forged_provenance,
            licenses,
            _manifest_regular_files(location),
            _target(),
        )

    conflicting_provenance = deepcopy(provenance)
    conflicting_provenance["payload_python_components"].append(
        {"component": "importlib-metadata", "version": "8.7.1"}
    )
    report = tmp_path / "dependency-provenance.json"
    report.write_text(json.dumps(conflicting_provenance), encoding="utf-8")
    with pytest.raises(ArtifactEvidenceError, match="provenance"):
        _validate_dependency_provenance(report, 8192)


def test_final_supply_gate_reloads_and_reconciles_reports(tmp_path: Path) -> None:
    payload = _normalized_sbom("frozen-payload-filesystem")
    payload["components"] = [
        _runtime_component(),
        {
            "type": "library",
            "name": "servonaut",
            "version": "1.2.3",
            "purl": "pkg:pypi/servonaut@1.2.3",
            "bom-ref": "pkg:pypi/servonaut@1.2.3",
        },
    ]
    closure = _normalized_sbom("isolated-build-input-closure")
    closure["components"] = [
        *_notice_closure_components(),
        {
            "type": "library",
            "name": "servonaut",
            "version": "1.2.3",
            "purl": "pkg:pypi/servonaut@1.2.3",
            "bom-ref": "pkg:pypi/servonaut@1.2.3",
            "properties": [],
            "hashes": [{"alg": "SHA-256", "content": "1" * 64}],
        },
    ]
    provenance = _provenance(
        [],
        [],
        payload_python=[{"component": "servonaut", "version": "1.2.3"}],
        closure_only=_notice_relationships(),
        payload_additional=[
            {"component": "python", "type": "application", "version": "3.12.14"}
        ],
    )
    paths = {
        "sbom-payload.cdx.json": payload,
        "sbom-python-closure.cdx.json": closure,
        "dependency-provenance.json": provenance,
        "licenses.json": {
            "schema_version": 1,
            "scope": "isolated-build-environment-license-claims",
            "packages": [
                *_notice_license_packages(),
                {
                    "name": "servonaut",
                    "version": "1.2.3",
                    "license_ids": [],
                    "license_classifiers": [],
                    "provenance": "installed-distribution-metadata",
                },
            ],
            "qualifications": [],
        },
    }
    for name, document in paths.items():
        (tmp_path / name).write_text(json.dumps(document), encoding="utf-8")
    result = SimpleNamespace(
        evidence_dir=tmp_path,
        sboms=(
            tmp_path / "sbom-payload.cdx.json",
            tmp_path / "sbom-python-closure.cdx.json",
        ),
    )
    policy = load_evidence_policy(_POLICY)
    _validate_result_supply_reports(
        result, _target(), policy, _manifest_regular_files()
    )

    provenance["payload_python_components"] = []
    (tmp_path / "dependency-provenance.json").write_text(
        json.dumps(provenance), encoding="utf-8"
    )
    with pytest.raises(ArtifactEvidenceError, match="provenance"):
        _validate_result_supply_reports(
            result, _target(), policy, _manifest_regular_files()
        )

    provenance["payload_python_components"] = [
        {"component": "servonaut", "version": "1.2.3"}
    ]
    (tmp_path / "dependency-provenance.json").write_text(
        json.dumps(provenance), encoding="utf-8"
    )
    license_report = paths["licenses.json"]
    assert isinstance(license_report, dict)
    license_report["packages"] = []
    (tmp_path / "licenses.json").write_text(
        json.dumps(license_report), encoding="utf-8"
    )
    with pytest.raises(ArtifactEvidenceError, match="license reconciliation"):
        _validate_result_supply_reports(
            result, _target(), policy, _manifest_regular_files()
        )

    license_report["packages"] = [
        {
            "name": "servonaut",
            "version": "1.2.3",
            "license_ids": [],
            "license_classifiers": [],
            "provenance": "installed-distribution-metadata",
        },
        {
            "name": "zeta",
            "version": "1.0",
            "license_ids": [],
            "license_classifiers": [],
            "provenance": "installed-distribution-metadata",
        },
    ]
    (tmp_path / "licenses.json").write_text(
        json.dumps(license_report), encoding="utf-8"
    )
    with pytest.raises(ArtifactEvidenceError, match="license reconciliation"):
        _validate_result_supply_reports(
            result, _target(), policy, _manifest_regular_files()
        )

    license_report["packages"] = [
        {
            "name": "servonaut",
            "version": "9.9.9",
            "license_ids": [],
            "license_classifiers": [],
            "provenance": "installed-distribution-metadata",
        }
    ]
    (tmp_path / "licenses.json").write_text(
        json.dumps(license_report), encoding="utf-8"
    )
    with pytest.raises(ArtifactEvidenceError, match="license reconciliation"):
        _validate_result_supply_reports(
            result, _target(), policy, _manifest_regular_files()
        )


def test_license_report_requires_canonical_unique_ordered_identities() -> None:
    report = {
        "schema_version": 1,
        "scope": "isolated-build-environment-license-claims",
        "packages": [
            {
                "name": "alpha",
                "version": "1.0",
                "license_ids": ["MIT"],
                "license_classifiers": ["License :: OSI Approved :: MIT License"],
                "provenance": "installed-distribution-metadata",
            },
            {
                "name": "servonaut",
                "version": "1.2.3",
                "license_ids": [],
                "license_classifiers": [],
                "provenance": "installed-distribution-metadata",
            },
        ],
        "qualifications": [],
    }
    assert _validate_license_report(report) == {"alpha": "1.0", "servonaut": "1.2.3"}

    report["packages"].reverse()
    with pytest.raises(ArtifactEvidenceError, match="license evidence"):
        _validate_license_report(report)

    report["packages"].reverse()
    report["packages"].append(dict(report["packages"][1]))
    with pytest.raises(ArtifactEvidenceError, match="license evidence"):
        _validate_license_report(report)


def test_final_supply_gate_rejects_payload_closure_license_and_wheel_drift(
    tmp_path: Path,
) -> None:
    payload = _normalized_sbom("frozen-payload-filesystem")
    payload["components"] = [
        {
            "type": "library",
            "name": "servonaut",
            "version": "1.2.3",
            "purl": "pkg:pypi/servonaut@1.2.3",
            "bom-ref": "pkg:pypi/servonaut@1.2.3",
        }
    ]
    closure = _normalized_sbom("isolated-build-input-closure")
    closure["components"] = [
        *_notice_closure_components(),
        {
            "type": "library",
            "name": "servonaut",
            "version": "1.2.3",
            "purl": "pkg:pypi/servonaut@1.2.3",
            "bom-ref": "pkg:pypi/servonaut@1.2.3",
            "properties": [],
            "hashes": [{"alg": "SHA-256", "content": "1" * 64}],
        },
    ]
    provenance = _provenance(
        [],
        [],
        payload_python=[{"component": "servonaut", "version": "1.2.3"}],
        closure_only=_notice_relationships(),
    )
    licenses = {
        "schema_version": 1,
        "scope": "isolated-build-environment-license-claims",
        "packages": [
            *_notice_license_packages(),
            {
                "name": "servonaut",
                "version": "1.2.3",
                "license_ids": [],
                "license_classifiers": [],
                "provenance": "installed-distribution-metadata",
            },
        ],
        "qualifications": [],
    }
    paths = {
        "sbom-payload.cdx.json": payload,
        "sbom-python-closure.cdx.json": closure,
        "dependency-provenance.json": provenance,
        "licenses.json": licenses,
    }
    for name, document in paths.items():
        (tmp_path / name).write_text(json.dumps(document), encoding="utf-8")
    result = SimpleNamespace(
        evidence_dir=tmp_path,
        sboms=(
            tmp_path / "sbom-payload.cdx.json",
            tmp_path / "sbom-python-closure.cdx.json",
        ),
    )
    policy = load_evidence_policy(_POLICY)
    _validate_result_supply_reports(
        result, _target(), policy, _manifest_regular_files()
    )

    payload["components"][0]["purl"] = "pkg:pypi/absent@1.0"  # type: ignore[index]
    payload["components"][0]["bom-ref"] = "pkg:pypi/absent@1.0"  # type: ignore[index]
    (tmp_path / "sbom-payload.cdx.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    with pytest.raises(ArtifactEvidenceError, match="provenance"):
        _validate_result_supply_reports(
            result, _target(), policy, _manifest_regular_files()
        )

    payload["components"][0]["purl"] = "pkg:pypi/servonaut@1.2.3"  # type: ignore[index]
    payload["components"][0]["bom-ref"] = "pkg:pypi/servonaut@1.2.3"  # type: ignore[index]
    payload["components"][0]["purl"] = "pkg:pypi/servonaut@9.9.9"  # type: ignore[index]
    payload["components"][0]["bom-ref"] = "pkg:pypi/servonaut@9.9.9"  # type: ignore[index]
    (tmp_path / "sbom-payload.cdx.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    with pytest.raises(ArtifactEvidenceError, match="provenance"):
        _validate_result_supply_reports(
            result, _target(), policy, _manifest_regular_files()
        )

    payload["components"][0]["purl"] = "pkg:pypi/servonaut@1.2.3"  # type: ignore[index]
    payload["components"][0]["bom-ref"] = "pkg:pypi/servonaut@1.2.3"  # type: ignore[index]
    closure["components"][-1]["hashes"] = [  # type: ignore[index]
        {"alg": "SHA-256", "content": "2" * 64}
    ]
    (tmp_path / "sbom-payload.cdx.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    (tmp_path / "sbom-python-closure.cdx.json").write_text(
        json.dumps(closure), encoding="utf-8"
    )
    with pytest.raises(ArtifactEvidenceError, match="provenance"):
        _validate_result_supply_reports(
            result, _target(), policy, _manifest_regular_files()
        )

    closure["components"][-1]["hashes"] = [  # type: ignore[index]
        {"alg": "SHA-256", "content": "1" * 64}
    ]
    provenance["build"]["wheel_sha256"] = "g" * 64  # type: ignore[index]
    (tmp_path / "sbom-python-closure.cdx.json").write_text(
        json.dumps(closure), encoding="utf-8"
    )
    (tmp_path / "dependency-provenance.json").write_text(
        json.dumps(provenance), encoding="utf-8"
    )
    with pytest.raises(ArtifactEvidenceError, match="provenance"):
        _validate_result_supply_reports(
            result, _target(), policy, _manifest_regular_files()
        )

    provenance["build"].pop("wheel_sha256")  # type: ignore[index]
    (tmp_path / "sbom-python-closure.cdx.json").write_text(
        json.dumps(closure), encoding="utf-8"
    )
    (tmp_path / "dependency-provenance.json").write_text(
        json.dumps(provenance), encoding="utf-8"
    )
    with pytest.raises(ArtifactEvidenceError, match="provenance"):
        _validate_result_supply_reports(
            result, _target(), policy, _manifest_regular_files()
        )


def test_cyclonedx_reference_rejects_invalid_https_port() -> None:
    document = _normalized_sbom("frozen-payload-filesystem")
    document["components"] = [
        {
            "type": "library",
            "name": "example",
            "version": "1.0",
            "bom-ref": "urn:servonaut:component:" + "a" * 64,
            "externalReferences": [
                {"type": "website", "url": "https://example.invalid:99999/"}
            ],
        }
    ]
    with pytest.raises(ArtifactEvidenceError, match="CycloneDX"):
        _validate_cyclonedx_sbom(document, "frozen-payload-filesystem")


def test_strict_reload_accepts_real_normalizer_closure_relationships(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = load_target_spec(
        _ROOT / "packaging" / "standalone_cli" / "target-policy.json",
        "linux-x64-ubuntu-22.04",
    )
    notice_policy, notice_records, notice_payloads = _controlled_notice_policy(tmp_path)
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize._EMBEDDED_NOTICE_POLICY",
        notice_policy,
    )
    monkeypatch.setattr(
        "scripts.standalone_cli.artifact_filesystem._EMBEDDED_NOTICE_POLICY",
        notice_policy,
    )
    monkeypatch.setattr(
        "scripts.standalone_cli.evidence_policy._EMBEDDED_NOTICE_POLICY_PATH",
        notice_policy,
    )
    payload_root = tmp_path / "payload"
    metadata_file = payload_root / "_internal" / "example.dist-info" / "METADATA"
    metadata_file.parent.mkdir(parents=True)
    metadata_file.write_text("Name: example\n", encoding="utf-8")
    vendor_files = tuple(
        payload_root / "_internal" / "setuptools" / "_vendor" / name
        for name in (
            "importlib_metadata-8.7.1.dist-info/METADATA",
            "importlib_metadata-8.7.1.dist-info/RECORD",
            "importlib_metadata-8.7.1.dist-info/top_level.txt",
        )
    )
    for vendor_file in vendor_files:
        vendor_file.parent.mkdir(parents=True, exist_ok=True)
        vendor_file.write_text("vendor metadata\n", encoding="utf-8")
    runtime_notice_file = payload_root / _RUNTIME_NOTICE_PATH
    runtime_notice_file.parent.mkdir(parents=True)
    runtime_notice_file.write_bytes(b"runtime license\n")
    for relative_path, data in notice_payloads.items():
        notice_file = payload_root / relative_path
        notice_file.parent.mkdir(parents=True, exist_ok=True)
        notice_file.write_bytes(data)
    runtime_notice = _runtime_notice()
    runtime_notice["sha256"] = hashlib.sha256(
        runtime_notice_file.read_bytes()
    ).hexdigest()
    executable = payload_root / "servonaut"
    executable.write_bytes(b"executable")
    executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    wheel = tmp_path / "servonaut-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "servonaut-1.2.3.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: servonaut\nVersion: 1.2.3\n",
        )
    wheel_sha256 = hashlib.sha256(wheel.read_bytes()).hexdigest()
    metadata = tmp_path / "metadata"
    resolved = metadata / "resolved"
    resolved.mkdir(parents=True)
    pyinstaller_metadata = metadata / "pyinstaller"
    pyinstaller_metadata.mkdir()
    warning = pyinstaller_metadata / "warn-servonaut.txt"
    warning.write_text("", encoding="utf-8")
    (pyinstaller_metadata / "Analysis-00.toc").write_text("[]", encoding="utf-8")
    (pyinstaller_metadata / "PYZ-00.toc").write_text("[]", encoding="utf-8")

    packages = sorted(
        [(record.distribution, record.version) for record in notice_records]
        + [
            ("cyclonedx-bom", "7.3.1"),
            ("pip", "25.0"),
            ("servonaut", "1.2.3"),
            ("setuptools", "84.0.0"),
        ]
    )
    notice_source_hashes = {
        record.distribution: record.source_wheel_sha256 for record in notice_records
    }
    environment = {
        "schema_version": 1,
        "packages": [
            {
                "name": name,
                "version": version,
                "hashes": [
                    "sha256:"
                    + (
                        wheel_sha256
                        if name == "servonaut"
                        else notice_source_hashes.get(name, "a" * 64)
                    )
                ],
            }
            for name, version in packages
            if name != "pip"
        ],
    }
    licenses = {
        "schema_version": 1,
        "packages": [
            {
                "name": name,
                "version": version,
                "license": "MIT",
                "license_expression": "MIT",
                "license_classifiers": ["License :: OSI Approved :: MIT License"],
                "license_files": ["LICENSE"],
            }
            for name, version in packages
        ],
    }
    closure = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
                "bom-ref": f"raw-{name}",
                "licenses": [{"license": {"id": "MIT"}}],
                **(
                    {"hashes": [{"alg": "SHA-256", "content": wheel_sha256}]}
                    if name == "servonaut"
                    else {}
                ),
            }
            for name, version in packages
        ],
        "dependencies": [{"ref": f"raw-{name}"} for name, _version in packages],
    }
    (resolved / "environment.json").write_text(
        json.dumps(environment), encoding="utf-8"
    )
    (resolved / "licenses.json").write_text(json.dumps(licenses), encoding="utf-8")
    (resolved / "sbom-python.cdx.json").write_text(
        json.dumps(closure), encoding="utf-8"
    )
    build_provenance = {
        "schema_version": 1,
        "source_commit": "a" * 40,
        "target": target.name,
        "product_version": "1.2.3",
        "build_revision": "build-1",
        "wheel_sha256": wheel_sha256,
    }
    build_toolchain = {
        "schema_version": 1,
        "python_implementation": "CPython",
        "python_version": "3.12.14",
        "spec_sha256": "5" * 64,
        "hooks_sha256": "6" * 64,
    }
    third_party_notice_metadata = {
        "schema_version": 1,
        "notices": [
            {
                "distribution": record.distribution,
                "version": record.version,
                "source_wheel_sha256": record.source_wheel_sha256,
                "payload_path": record.payload_path.as_posix(),
                "sha256": record.sha256,
            }
            for record in notice_records
        ],
    }
    for name, document in (
        ("build-provenance.json", build_provenance),
        ("build-toolchain.json", build_toolchain),
        ("runtime-notice.json", runtime_notice),
        ("third-party-notices.json", third_party_notice_metadata),
    ):
        (resolved / name).write_text(json.dumps(document), encoding="utf-8")
    (payload_root / "servonaut-runtime.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "distribution": "frozen-cli",
                "product_version": "1.2.3",
                "build_revision": "build-1",
                "console_helper": "servonaut",
                "desktop_child": None,
            }
        ),
        encoding="utf-8",
    )
    artifact = ArtifactDescriptor(
        payload_root,
        executable,
        None,
        target,
        wheel,
        warning,
        metadata,
    )
    snapshot = snapshot_payload(artifact, _SNAPSHOT_LIMITS)
    assert snapshot.third_party_notices == notice_records
    raw_payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {"type": "file", "name": "servonaut", "bom-ref": "root"}
        },
        "components": [
            {
                "type": "file",
                "name": str(metadata_file),
                "bom-ref": "raw-metadata",
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": hashlib.sha256(
                            metadata_file.read_bytes()
                        ).hexdigest(),
                    }
                ],
            },
            {
                "type": "library",
                "name": "importlib-metadata",
                "version": "8.7.1",
                "purl": "pkg:pypi/importlib-metadata@8.7.1",
                "bom-ref": "raw-vendor",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "properties": [
                    {
                        "name": f"syft:location:{index}:path",
                        "value": str(vendor_file.relative_to(payload_root)),
                    }
                    for index, vendor_file in enumerate(vendor_files)
                ],
            },
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["raw-metadata", "raw-vendor"]},
            {"ref": "raw-metadata"},
            {"ref": "raw-vendor"},
        ],
    }
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    (workspace / "syft-cache").mkdir(mode=0o700)
    (workspace / "syft-config").mkdir(mode=0o700)
    fake_tool = tmp_path / "syft"
    fake_tool.write_bytes(b"tool")
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.acquire_syft", lambda *_args: fake_tool
    )
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.run_syft_scan",
        lambda *_args: _args[5].write_text(json.dumps(raw_payload), encoding="utf-8"),
    )

    supply = generate_supply_chain_evidence(
        snapshot,
        artifact,
        evidence_dir,
        workspace,
        load_evidence_policy(_POLICY).limits.max_payload_entries,
    )
    result = SimpleNamespace(
        evidence_dir=evidence_dir,
        sboms=(supply.payload_sbom, supply.python_closure_sbom),
    )
    provenance = json.loads(supply.dependency_provenance.read_text(encoding="utf-8"))
    assert provenance["payload_vendored_python_components"] == [
        {
            "component": "importlib-metadata",
            "version": "8.7.1",
            "parent": "setuptools",
            "parent_version": "84.0.0",
            "origin": "parent-vendor-dist-info",
        }
    ]
    assert not any(
        row["component"] == "importlib-metadata"
        for row in provenance["payload_additional_components"]
    )
    payload = json.loads(supply.payload_sbom.read_text(encoding="utf-8"))
    child = next(
        item
        for item in payload["components"]
        if item.get("purl") == "pkg:pypi/importlib-metadata@8.7.1"
    )
    assert child["licenses"] == [{"license": {"id": "Apache-2.0"}}]
    licenses = json.loads(
        supply.sanitised_license_inventory.read_text(encoding="utf-8")
    )
    assert "importlib-metadata" not in {
        package["name"] for package in licenses["packages"]
    }
    manifest_regular_files = {
        entry.relative_path.as_posix(): entry.sha256
        for entry in snapshot.entries
        if entry.kind == "file" and entry.sha256 is not None
    }
    _validate_result_supply_reports(
        result, target, load_evidence_policy(_POLICY), manifest_regular_files
    )


def test_json_reader_limits_read_size_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "report.json"
    path.write_text("{}", encoding="utf-8")
    read_sizes: list[int] = []

    class _SpyReader:
        def __enter__(self) -> _SpyReader:  # noqa: PYI034 - Python 3.10 lacks Self
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, size: int) -> bytes:
            read_sizes.append(size)
            return b"{}!"

    monkeypatch.setattr(Path, "open", lambda *_args, **_kwargs: _SpyReader())

    with pytest.raises(ArtifactEvidenceError, match="exceeds configured limit"):
        _read_json(path, 2)
    assert read_sizes == [3]


def test_warning_records_preserve_qualifier_and_fail_unknown_expired_and_stale(
    tmp_path: Path,
) -> None:
    target = load_target_spec(
        _ROOT / "packaging" / "standalone_cli" / "target-policy.json",
        "linux-x64-ubuntu-22.04",
    )
    metadata = tmp_path / "metadata"
    (metadata / "resolved").mkdir(parents=True)
    (metadata / "resolved" / "environment.json").write_text(
        json.dumps({"schema_version": 1, "packages": []}), encoding="utf-8"
    )
    warning_file = tmp_path / "warn-servonaut.txt"
    warning_file.write_text(
        """This file lists modules PyInstaller was not able to find. This does not
necessarily mean these modules are required for running your program. Both
Python's standard library and 3rd-party Python packages often conditionally
import optional modules, some of which may be available only on certain
platforms.
Types of import:
* top-level: imported at the top-level - look at these first
* conditional: imported within an if-statement
* delayed: imported within a function
* optional: imported within a try-except-statement
IMPORTANT: Do NOT post this list to the issue-tracker. Use it as a basis for
            tracking down the missing module yourself. Thanks!
missing module named 'optional_sdk' - imported by client (delayed, optional), helper (top-level)
excluded module named readline - imported by site (delayed, optional)
runtime module named six.moves - imported by dateutil.tz (top-level)
missing module named pyimod02_importers - imported by /build/PyInstaller/hooks/rthooks/pyi_rth_pkgutil.py (delayed)
""",
        encoding="utf-8",
    )
    artifact = ArtifactDescriptor(
        tmp_path,
        tmp_path / "servonaut",
        None,
        target,
        tmp_path / "wheel.whl",
        warning_file,
        metadata,
    )
    observed, collection = _canonical_warnings(_snapshot(tmp_path), artifact, 4096)
    missing = next(record for record in observed if record["module"] == "optional_sdk")
    assert missing["importers"] == [
        {"module": "client", "qualifiers": ["delayed", "optional"]},
        {"module": "helper", "qualifiers": ["top-level"]},
    ]
    runtime_hook = next(
        record for record in observed if record["module"] == "pyimod02_importers"
    )
    assert runtime_hook["importers"] == [
        {"origin": "pyinstaller-runtime-hook", "qualifiers": ["delayed"]}
    ]
    assert collection["record_count"] == 4

    approved, unknown, stale = _classify_warnings(observed, [])
    assert not approved and unknown == observed and not stale

    entry = {
        **{
            field: observed[0][field]
            for field in (
                "fingerprint",
                "code",
                "module",
                "importers",
                "target_facts",
                "collection_facts",
            )
        },
        "classification": {
            "optional": True,
            "conditional": True,
            "collected": False,
            "origin_class": "hook-or-source",
        },
        "reason": "Reviewed optional import.",
        "expires_on": "2000-01-01",
    }
    approved, unknown, stale = _classify_warnings(observed, [entry])
    assert not approved and unknown == observed and stale == [entry]

    drifted = {**entry, "fingerprint": "0" * 64, "expires_on": "2999-01-01"}
    approved, unknown, stale = _classify_warnings(observed, [drifted])
    assert not approved and unknown == observed and stale == [drifted]


def test_warning_importer_parser_canonicalizes_reordering_and_rejects_unknowns() -> (
    None
):
    target = _target()
    first = _parse_importers("client (delayed, optional), helper (top-level)", target)
    second = _parse_importers("helper (top-level), client (optional, delayed)", target)

    assert first == second
    with pytest.raises(ArtifactEvidenceError, match="invalid qualifiers"):
        _parse_importers("client (unknown)", target)
    with pytest.raises(ArtifactEvidenceError, match="invalid importers"):
        _parse_importers("client (optional", target)


@pytest.mark.parametrize(
    ("path", "qualifiers"),
    [
        (
            r"C:\build\PyInstaller\hooks\rthooks\pyi_rth_pkgutil.py",
            ["delayed"],
        ),
        (
            r"D:\path with spaces\PyInstaller\hooks\rthooks\runtime-hook.py",
            ["top-level"],
        ),
        (
            "C:\\café\\PyInstaller\\hooks\\rthooks\\hook_name.py",
            ["optional"],
        ),
        (
            r"\\server\share\PyInstaller\hooks\rthooks\hook.name.py",
            ["conditional"],
        ),
        (
            r"C:\build\PyInstaller\hooks\rthooks\hook-name_1.2.py",
            ["conditional", "delayed"],
        ),
        (
            r"C:\Program Files (x86)\PyInstaller\hooks\rthooks\hook.py",
            ["delayed"],
        ),
        (
            r"C:\prefix (delayed)\PyInstaller\hooks\rthooks\hook.py",
            ["optional"],
        ),
    ],
)
def test_windows_runtime_hook_importers_are_canonical_and_path_private(
    tmp_path: Path,
    path: str,
    qualifiers: list[str],
) -> None:
    qualifier_text = ", ".join(reversed(qualifiers))
    snapshot, artifact = _warning_fixture(
        tmp_path,
        "windows-x64",
        f"missing module named optional_sdk - imported by {path} ({qualifier_text})",
    )

    observed, collection = _canonical_warnings(snapshot, artifact, 4096)

    assert observed[0]["importers"] == [
        {"origin": "pyinstaller-runtime-hook", "qualifiers": qualifiers}
    ]
    assert collection["record_count"] == 1
    approved, unknown, stale = _classify_warnings(observed, [])
    assert approved == []
    assert unknown == observed
    assert stale == []


def test_windows_runtime_hook_prefix_does_not_change_warning_fingerprint(
    tmp_path: Path,
) -> None:
    records: list[list[dict[str, object]]] = []
    for root_name, hook_path in (
        (
            "first",
            r"C:\first path\PyInstaller\hooks\rthooks\pyi_rth_pkgutil.py",
        ),
        (
            "second",
            "D:\\café\\PyInstaller\\hooks\\rthooks\\pyi_rth_pkgutil.py",
        ),
    ):
        snapshot, artifact = _warning_fixture(
            tmp_path / root_name,
            "windows-x64",
            "missing module named optional_sdk - imported by "
            f"{hook_path} (delayed), client (top-level)",
        )
        observed, _collection = _canonical_warnings(snapshot, artifact, 4096)
        records.append(observed)

    assert records[0] == records[1]


def test_runtime_hook_importer_keeps_legacy_grammar_and_separates_targets() -> None:
    windows = _target("windows-x64")
    posix = "/build/PyInstaller/hooks/rthooks/pyi_rth_pkgutil.py (delayed)"
    legacy_mixed_prefix = (
        r"C:\legacy/PyInstaller/hooks/rthooks/pyi_rth_pkgutil.py (delayed)"
    )
    legacy_balanced_comma = (
        "/build(a,b)/PyInstaller/hooks/rthooks/pyi_rth_pkgutil.py (delayed)"
    )
    native = r"C:\build\PyInstaller\hooks\rthooks\pyi_rth_pkgutil.py (delayed)"
    expected = [{"origin": "pyinstaller-runtime-hook", "qualifiers": ["delayed"]}]

    assert _parse_importers(posix, windows) == expected
    assert _parse_importers(legacy_mixed_prefix, windows) == expected
    assert _parse_importers(legacy_balanced_comma, windows) == expected
    assert _parse_importers(native, windows) == expected
    for target_name in (_LINUX_TARGET, "macos-x64", "macos-arm64"):
        target = _target(target_name)
        assert _parse_importers(posix, target) == expected
        assert _parse_importers(legacy_mixed_prefix, target) == expected
        assert _parse_importers(legacy_balanced_comma, target) == expected
        with pytest.raises(ArtifactEvidenceError, match="invalid importers"):
            _parse_importers(native, target)
    with pytest.raises(ArtifactEvidenceError, match="invalid importers"):
        _parse_importers(native, replace(windows, platform="linux"))
    with pytest.raises(ArtifactEvidenceError, match="invalid importers"):
        _parse_importers(native, replace(windows, name=_LINUX_TARGET))


@pytest.mark.parametrize(
    "path",
    [
        r"PyInstaller\hooks\rthooks\hook.py",
        r"\build\PyInstaller\hooks\rthooks\hook.py",
        r"C:build\PyInstaller\hooks\rthooks\hook.py",
        r"C:\build/PyInstaller\hooks\rthooks\hook.py",
        r"C:\build\\PyInstaller\hooks\rthooks\hook.py",
        r"C:\build\.\PyInstaller\hooks\rthooks\hook.py",
        r"C:\build\..\PyInstaller\hooks\rthooks\hook.py",
        r"\\?\C:\build\PyInstaller\hooks\rthooks\hook.py",
        r"\\.\C:\build\PyInstaller\hooks\rthooks\hook.py",
        r"\\server\PyInstaller\hooks\rthooks\hook.py",
        r"C:\bad:name\PyInstaller\hooks\rthooks\hook.py",
        "C:\\bad\tname\\PyInstaller\\hooks\\rthooks\\hook.py",
        "C:\\bad\x00name\\PyInstaller\\hooks\\rthooks\\hook.py",
        r"C:\trailing.\PyInstaller\hooks\rthooks\hook.py",
        "C:\\trailing \\PyInstaller\\hooks\\rthooks\\hook.py",
        r"\\bad:server\share\PyInstaller\hooks\rthooks\hook.py",
        r"\\server\bad:share\PyInstaller\hooks\rthooks\hook.py",
        r"C:\build\pyinstaller\hooks\rthooks\hook.py",
        r"C:\build\PyInstaller\hook\rthooks\hook.py",
        r"C:\build\PyInstaller\hooks\rthooks\nested\hook.py",
        r"C:\build\PyInstaller\hooks\rthooks\hook.pyc",
        r"C:\build\PyInstaller\hooks\rthooks\hook.py trailing",
        r"C:\build\custom\rthooks\hook.py",
        r"C:\prefix(unclosed\PyInstaller\hooks\rthooks\hook.py",
        r"C:\prefix)unopened\PyInstaller\hooks\rthooks\hook.py",
    ],
)
def test_windows_runtime_hook_importer_rejects_malformed_paths(path: str) -> None:
    with pytest.raises(ArtifactEvidenceError, match="invalid importers"):
        _parse_importers(f"{path} (delayed)", _target("windows-x64"))


@pytest.mark.parametrize(
    "path",
    [
        r"C:\plain,comma\PyInstaller\hooks\rthooks\hook.py",
        r"C:\balanced(a,b)\PyInstaller\hooks\rthooks\hook.py",
        r"\\server,name\share\PyInstaller\hooks\rthooks\hook.py",
        r"\\server\share,name\PyInstaller\hooks\rthooks\hook.py",
        r"\\server\share\prefix(a,b)\PyInstaller\hooks\rthooks\hook.py",
    ],
)
def test_windows_runtime_hook_importer_rejects_commas(path: str) -> None:
    assert not evidence_policy._is_windows_runtime_hook_path(path)
    with pytest.raises(ArtifactEvidenceError, match="invalid importers"):
        _parse_importers(f"{path} (delayed)", _target("windows-x64"))


@pytest.mark.parametrize("reserved", ["<", ">", ":", '"', "|", "?", "*"])
def test_windows_runtime_hook_importer_rejects_reserved_component_characters(
    reserved: str,
) -> None:
    importer = f"C:\\bad{reserved}name\\PyInstaller\\hooks\\rthooks\\hook.py (delayed)"
    with pytest.raises(ArtifactEvidenceError, match="invalid importers"):
        _parse_importers(importer, _target("windows-x64"))


@pytest.mark.parametrize(
    "importer",
    [
        r"C:\build\PyInstaller\hooks\rthooks\hook.py (unknown)",
        r"C:\build\PyInstaller\hooks\rthooks\hook.py (delayed, delayed)",
        r"C:\build\PyInstaller\hooks\rthooks\hook.py (delayed",
    ],
)
def test_windows_runtime_hook_importer_keeps_qualifiers_strict(importer: str) -> None:
    with pytest.raises(ArtifactEvidenceError):
        _parse_importers(importer, _target("windows-x64"))


def test_windows_runtime_hook_reports_are_path_private_and_policy_red(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_path = "C:\\private-drive-canary café\\PyInstaller\\hooks\\rthooks\\hook.py"
    snapshot, artifact = _warning_fixture(
        tmp_path / "fixture",
        "windows-x64",
        "missing module named optional_sdk - imported by "
        f"{private_path} (optional, delayed)",
    )
    policy = load_evidence_policy(_POLICY)
    monkeypatch.setattr(evidence_policy, "validate_toc_policy", lambda *_args: None)
    monkeypatch.setattr(evidence_policy, "inspect_native_payload", lambda *_args: [])
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(mode=0o700)

    result = evidence_policy.analyse_policy_evidence(
        snapshot, artifact, policy, evidence_dir
    )

    assert result is not None
    warning_report = json.loads(result.warnings.read_text(encoding="utf-8"))
    candidate_report = json.loads(
        (evidence_dir / "warning-candidates.json").read_text(encoding="utf-8")
    )
    expected_importers = [
        {
            "origin": "pyinstaller-runtime-hook",
            "qualifiers": ["delayed", "optional"],
        }
    ]
    assert warning_report["approved"] == []
    assert warning_report["unknown"] == candidate_report["candidates"]
    assert warning_report["unknown"][0]["importers"] == expected_importers
    assert warning_report["counts"] == {"approved": 0, "unknown": 1, "stale": 0}

    def strings(value: object) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [item for child in value for item in strings(child)]
        if isinstance(value, dict):
            return [
                item
                for key, child in value.items()
                for item in (*strings(key), *strings(child))
            ]
        return []

    retained_strings = strings(warning_report) + strings(candidate_report)
    assert private_path not in retained_strings
    assert not any("private-drive-canary" in value for value in retained_strings)
    assert not any("café" in value for value in retained_strings)
    with pytest.raises(ArtifactEvidenceError, match="require policy review"):
        _validate_warning_report(warning_report, artifact.target)

    observed = warning_report["unknown"][0]
    approval = {
        **observed,
        "classification": {
            "optional": True,
            "conditional": False,
            "collected": False,
            "origin_class": "hook-or-source",
        },
        "reason": "Reviewed optional import.",
        "expires_on": "2999-01-01",
    }
    allowlist = tmp_path / "warnings-allowlist.json"
    allowlist.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "targets": {
                    "windows-x64": [approval],
                    "macos-x64": [],
                    "macos-arm64": [],
                    _LINUX_TARGET: [],
                },
            }
        ),
        encoding="utf-8",
    )
    approved_target = replace(artifact.target, warning_allowlist=allowlist)
    approved_artifact = replace(artifact, target=approved_target)
    approved_dir = tmp_path / "approved-evidence"
    approved_dir.mkdir(mode=0o700)

    approved_result = evidence_policy.analyse_policy_evidence(
        snapshot, approved_artifact, policy, approved_dir
    )

    assert approved_result is not None
    approved_report = json.loads(approved_result.warnings.read_text(encoding="utf-8"))
    assert approved_report["approved"] == [observed]
    assert approved_report["unknown"] == []
    assert approved_report["stale"] == []
    _validate_warning_report(approved_report, approved_target)
    approved_strings = strings(approved_report)
    assert not any("private-drive-canary" in value for value in approved_strings)
    assert not any("café" in value for value in approved_strings)
