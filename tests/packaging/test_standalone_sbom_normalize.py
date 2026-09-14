"""Supply-chain SBOM normalization and reconciliation tests."""

from __future__ import annotations

import copy
import hashlib
import json
import stat
import sys
import zipfile
from dataclasses import replace
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest
from jsonschema import Draft202012Validator

from scripts.standalone_cli import artifact_filesystem
from scripts.standalone_cli.artifact_filesystem import (
    SnapshotPathResolver,
    snapshot_payload,
)
from scripts.standalone_cli.artifact_types import (
    ArtifactDescriptor,
    ArtifactEvidenceError,
    PayloadEntry,
    PayloadSnapshot,
)
from scripts.standalone_cli.embedded_notices import (
    EmbeddedNoticePolicy,
    EmbeddedNoticeRecord,
)
from scripts.standalone_cli.evidence_policy import (
    _validate_cyclonedx_sbom,
    _validate_dependency_provenance,
    load_evidence_policy,
)
from scripts.standalone_cli.evidence_policy_types import EvidenceLimits
from scripts.standalone_cli.evidence_sanitize import write_public_json
from scripts.standalone_cli.model import load_target_spec
from scripts.standalone_cli.sbom_normalize import (
    _dependency_provenance,
    _HttpReferenceOmission,
    _InstalledLicense,
    _load_environment,
    _load_installed_licenses,
    _load_normalization_policy,
    _normalize_external_references,
    _normalize_payload_component,
    _normalize_payload_sbom,
    _normalize_properties,
    _normalize_python_sbom,
    _ParentVendor,
    _payload_relative_path,
    _third_party_notice_attestation,
    _toolchain_provenance,
    _vendored_python_component,
    _VendoredPythonComponent,
    _windows_file_component_relative_path,
    generate_supply_chain_evidence,
)
from scripts.standalone_cli.syft_tool import SyftPolicy, load_syft_policy

_ROOT = Path(__file__).resolve().parents[2]
_POLICY_ROOT = _ROOT / "packaging" / "standalone_cli"
_TARGET_POLICY = _POLICY_ROOT / "target-policy.json"
_HTTP_URL = "http://example.invalid/project"
_MACHOLIB_REFERENCES = [
    {
        "comment": "from packaging metadata: Download-URL",
        "type": "distribution",
        "url": "http://pypi.python.org/pypi/macholib",
    },
    {
        "comment": "from packaging metadata Project-URL: Documentation",
        "type": "documentation",
        "url": "https://macholib.readthedocs.io/en/latest/",
    },
    {
        "comment": "from packaging metadata Project-URL: Issue tracker",
        "type": "issue-tracker",
        "url": "https://github.com/ronaldoussoren/macholib/issues",
    },
    {
        "comment": "from packaging metadata Project-URL: Repository",
        "type": "vcs",
        "url": "https://github.com/ronaldoussoren/macholib",
    },
    {
        "comment": "from packaging metadata: Home-page",
        "type": "website",
        "url": "http://github.com/ronaldoussoren/macholib",
    },
]
_MAX_RESOLUTION_STEPS = 10_000
_SNAPSHOT_LIMITS = EvidenceLimits(
    1024 * 1024,
    1000,
    1024 * 1024,
    8 * 1024 * 1024,
    30,
    1024 * 1024,
)
_NOTICE_IDENTITIES = (
    (
        "charset-normalizer",
        "3.5.1",
        "_internal/notices/charset-normalizer-LICENSE.txt",
    ),
    (
        "pydantic-core",
        "2.46.5",
        "_internal/notices/pydantic-core-LICENSE.txt",
    ),
    ("pyinstaller", "6.22.3", "_internal/notices/PyInstaller-COPYING.txt"),
    (
        "pyinstaller-hooks-contrib",
        "2026.7",
        "_internal/notices/pyinstaller-hooks-contrib-LICENSE.txt",
    ),
    ("rpds-py", "2026.6.3", "_internal/notices/rpds-py-LICENSE.txt"),
)
_NOTICE_BYTES = tuple(
    f"notice-{index}\r\n".encode("ascii")
    if index == 0
    else f"notice-{index}\n".encode("ascii")
    for index in range(len(_NOTICE_IDENTITIES))
)
_NOTICE_WHEEL_HASHES = tuple(
    hashlib.sha256(f"wheel-{name}".encode("ascii")).hexdigest()
    for name, _version, _path in _NOTICE_IDENTITIES
)
_NOTICE_POLICIES = tuple(
    EmbeddedNoticePolicy(
        distribution=name,
        version=version,
        source_relative_path=PurePosixPath(
            f"{name.replace('-', '_')}-{version}.dist-info/licenses/LICENSE"
        ),
        payload_path=PurePosixPath(payload_path),
        sha256_by_target={
            target: hashlib.sha256(_NOTICE_BYTES[index]).hexdigest()
            for target in (
                "windows-x64",
                "macos-x64",
                "macos-arm64",
                "linux-x64-ubuntu-22.04",
            )
        },
    )
    for index, (name, version, payload_path) in enumerate(_NOTICE_IDENTITIES)
)


@pytest.fixture(autouse=True)
def _trusted_embedded_notice_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.load_embedded_notice_policy",
        lambda _path, _max_bytes: _NOTICE_POLICIES,
    )


def test_normalization_policy_is_schema_valid() -> None:
    policy = json.loads(
        (_POLICY_ROOT / "sbom-normalization.json").read_text(encoding="utf-8")
    )
    schema = json.loads(
        (_POLICY_ROOT / "sbom-normalization.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(policy)
    loaded = _load_normalization_policy(
        _POLICY_ROOT / "sbom-normalization.json",
        load_syft_policy(_POLICY_ROOT / "syft-tools.json"),
    )
    assert loaded.parent_vendors == (
        _ParentVendor("setuptools", "_internal/setuptools/_vendor"),
    )


def test_external_reference_normalization_is_exact_and_path_free(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "servonaut-1.2.3-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    facts: list[dict[str, object]] = []
    omission = _HttpReferenceOmission(
        "example",
        "1.0",
        "website",
        hashlib.sha256(_HTTP_URL.encode()).hexdigest(),
    )

    kept = _normalize_external_references(
        [
            {
                "type": "distribution",
                "url": wheel.as_uri(),
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                    }
                ],
            },
            {"type": "website", "url": "https://example.invalid/project"},
        ],
        "servonaut",
        "1.2.3",
        facts,
        frozenset(),
        local_wheel=(wheel, hashlib.sha256(wheel.read_bytes()).hexdigest()),
    )

    assert kept == [{"type": "website", "url": "https://example.invalid/project"}]
    assert facts == [
        {
            "code": "local-wheel-acquisition-normalized",
            "component": "servonaut",
            "version": "1.2.3",
            "source": "descriptor-wheel-sha256",
        }
    ]
    with pytest.raises(ArtifactEvidenceError, match="unexpected local"):
        _normalize_external_references(
            [
                {
                    "type": "distribution",
                    "url": wheel.as_uri(),
                    "hashes": [{"alg": "SHA-256", "content": "0" * 64}],
                }
            ],
            "servonaut",
            "1.2.3",
            [],
            frozenset(),
            local_wheel=(wheel, hashlib.sha256(wheel.read_bytes()).hexdigest()),
        )
    http_facts: list[dict[str, object]] = []
    assert not _normalize_external_references(
        [{"type": "website", "url": _HTTP_URL}],
        "example",
        "1.0",
        http_facts,
        frozenset({omission}),
        local_wheel=None,
    )
    assert http_facts[0]["code"] == "non-https-optional-reference-omitted"
    assert _HTTP_URL not in json.dumps(http_facts)

    foreign = tmp_path / "foreign"
    foreign.mkdir()
    foreign_wheel = foreign / "different-1.2.3-py3-none-any.whl"
    foreign_wheel.write_bytes(b"other wheel")
    with pytest.raises(ArtifactEvidenceError, match="unexpected local"):
        _normalize_external_references(
            [{"type": "distribution", "url": foreign_wheel.as_uri()}],
            "servonaut",
            "1.2.3",
            [],
            frozenset(),
            local_wheel=(wheel, hashlib.sha256(wheel.read_bytes()).hexdigest()),
        )


def test_macholib_metadata_references_use_exact_reviewed_omissions(
    tmp_path: Path,
) -> None:
    _snapshot, artifact, _payload_sbom = _fixture(tmp_path)
    policy = _load_normalization_policy(
        _POLICY_ROOT / "sbom-normalization.json",
        load_syft_policy(_POLICY_ROOT / "syft-tools.json"),
    )
    facts: list[dict[str, object]] = []
    raw = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "macholib",
                "version": "1.16.4",
                "purl": "pkg:pypi/macholib@1.16.4",
                "bom-ref": "raw-macholib",
                "externalReferences": copy.deepcopy(_MACHOLIB_REFERENCES),
                "licenses": [{"license": {"id": "MIT"}}],
            }
        ],
        "dependencies": [{"ref": "raw-macholib"}],
    }
    installed = _InstalledLicense(
        "macholib",
        "1.16.4",
        None,
        "MIT",
        ("License :: OSI Approved :: MIT License",),
        ("LICENSE",),
    )

    document, versions, license_ids = _normalize_python_sbom(
        raw,
        {
            "macholib": {
                "name": "macholib",
                "version": "1.16.4",
                "hashes": ["sha256:" + "a" * 64],
            }
        },
        {"macholib": installed},
        artifact,
        "1.2.3",
        "b" * 64,
        facts,
        policy.http_reference_omissions,
    )

    component = document["components"][0]
    assert component["purl"] == "pkg:pypi/macholib@1.16.4"
    assert component["licenses"] == [
        {"expression": "MIT", "acknowledgement": "declared"},
        {"license": {"id": "MIT"}},
    ]
    assert component["externalReferences"] == [
        {
            "type": "documentation",
            "url": "https://macholib.readthedocs.io/en/latest/",
        },
        {
            "type": "issue-tracker",
            "url": "https://github.com/ronaldoussoren/macholib/issues",
        },
        {"type": "vcs", "url": "https://github.com/ronaldoussoren/macholib"},
    ]
    assert versions == {"macholib": "1.16.4"}
    assert license_ids == {"macholib": frozenset({"MIT"})}
    assert facts == [
        {
            "code": "non-https-optional-reference-omitted",
            "component": "macholib",
            "version": "1.16.4",
            "reference_type": "distribution",
            "source": "reviewed-http-reference-policy",
        },
        {
            "code": "non-https-optional-reference-omitted",
            "component": "macholib",
            "version": "1.16.4",
            "reference_type": "website",
            "source": "reviewed-http-reference-policy",
        },
    ]
    serialized = json.dumps(document) + json.dumps(facts)
    assert "http://" not in serialized


@pytest.mark.parametrize(
    ("name", "version", "references"),
    [
        ("macholib-extra", "1.16.4", _MACHOLIB_REFERENCES),
        ("macholib", "1.16.3", _MACHOLIB_REFERENCES),
        (
            "macholib",
            "1.16.4",
            [
                {
                    **_MACHOLIB_REFERENCES[0],
                    "type": "website",
                },
                *_MACHOLIB_REFERENCES[1:],
            ],
        ),
        (
            "macholib",
            "1.16.4",
            [
                {
                    **_MACHOLIB_REFERENCES[0],
                    "url": _MACHOLIB_REFERENCES[0]["url"] + "?source=other",
                },
                *_MACHOLIB_REFERENCES[1:],
            ],
        ),
        (
            "macholib",
            "1.16.4",
            [
                *_MACHOLIB_REFERENCES,
                {
                    "type": "documentation",
                    "url": "http://example.invalid/unreviewed",
                },
            ],
        ),
    ],
    ids=("name", "version", "type", "digest", "extra-reference"),
)
def test_macholib_http_omissions_reject_near_matches(
    name: str,
    version: str,
    references: list[dict[str, str]],
) -> None:
    policy = _load_normalization_policy(
        _POLICY_ROOT / "sbom-normalization.json",
        load_syft_policy(_POLICY_ROOT / "syft-tools.json"),
    )
    with pytest.raises(ArtifactEvidenceError, match="unreviewed HTTP"):
        _normalize_external_references(
            references,
            name,
            version,
            [],
            policy.http_reference_omissions,
            local_wheel=None,
        )


def test_generation_preserves_file_components_and_reconciles_scopes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot, artifact, payload_sbom = _fixture(tmp_path)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    (workspace / "syft-cache").mkdir(mode=0o700)
    (workspace / "syft-config").mkdir(mode=0o700)
    fake_tool = tmp_path / "syft"
    fake_tool.write_bytes(b"tool")

    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.acquire_syft",
        lambda *_args: fake_tool,
    )

    def fake_scan(
        _executable: Path,
        _policy: object,
        _target: object,
        _payload_root: Path,
        _product_version: str,
        raw_output: Path,
        _config_root: Path,
    ) -> None:
        raw_output.write_text(json.dumps(payload_sbom), encoding="utf-8")

    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.run_syft_scan", fake_scan
    )

    result = generate_supply_chain_evidence(
        snapshot, artifact, evidence, workspace, _MAX_RESOLUTION_STEPS
    )

    payload = json.loads(result.payload_sbom.read_text(encoding="utf-8"))
    closure = json.loads(result.python_closure_sbom.read_text(encoding="utf-8"))
    provenance = json.loads(result.dependency_provenance.read_text(encoding="utf-8"))
    licenses = json.loads(
        result.sanitised_license_inventory.read_text(encoding="utf-8")
    )
    files = [item for item in payload["components"] if item["type"] == "file"]
    assert files[0]["name"] == "_internal/example.dist-info/METADATA"
    assert files[0]["hashes"][1]["alg"] == "SHA-256"
    assert {
        component["name"]
        for component in payload["components"]
        if component["type"] == "library"
    } == {"example"}
    assert payload["specVersion"] == closure["specVersion"] == "1.6"
    assert provenance["unresolved_conflicts"] == []
    assert provenance["payload_vendored_python_components"] == []
    assert provenance["runtime_notice"] == snapshot.runtime_notice
    assert provenance["third_party_notices"] == {
        "schema_version": 1,
        "notices": [
            {
                "distribution": policy.distribution,
                "version": policy.version,
                "source_wheel_sha256": _NOTICE_WHEEL_HASHES[index],
                "payload_path": policy.payload_path.as_posix(),
                "sha256": policy.sha256_by_target[artifact.target.name],
            }
            for index, policy in enumerate(_NOTICE_POLICIES)
        ],
    }
    assert provenance["build"]["source_commit"] == "abc1234"
    assert provenance["toolchain"] == {
        "python_implementation": "CPython",
        "python_version": "3.12.14",
        "spec_sha256": "5" * 64,
        "hooks_sha256": "6" * 64,
        "pyinstaller_version": "6.22.3",
        "pyinstaller_hooks_version": "2026.7",
        "cyclonedx_bom_version": "7.3.1",
        "syft_version": "1.51.1",
        "syft_asset_sha256": (
            "8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3"
        ),
    }
    assert provenance["bootstrap_exceptions"] == [
        {"component": "pip", "source": "venv-bootstrap", "version": "25.0"}
    ]
    assert any(
        fact["code"] == "local-wheel-acquisition-normalized"
        for fact in provenance["qualification_facts"]
    )
    assert all("license_expression" not in item for item in licenses["packages"])
    serialized = "".join(
        path.read_text(encoding="utf-8") for path in evidence.iterdir()
    )
    assert str(tmp_path) not in serialized

    interrupted_evidence = tmp_path / "interrupted-evidence"
    interrupted_evidence.mkdir()
    interrupted_workspace = tmp_path / "interrupted-workspace"
    interrupted_workspace.mkdir(mode=0o700)
    (interrupted_workspace / "syft-cache").mkdir(mode=0o700)
    (interrupted_workspace / "syft-config").mkdir(mode=0o700)

    def interrupt_after_publish(*args: object, **kwargs: object) -> Path:
        write_public_json(*args, **kwargs)
        raise KeyboardInterrupt

    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.write_public_json",
        interrupt_after_publish,
    )
    with pytest.raises(KeyboardInterrupt):
        generate_supply_chain_evidence(
            snapshot,
            artifact,
            interrupted_evidence,
            interrupted_workspace,
            _MAX_RESOLUTION_STEPS,
        )
    assert not tuple(interrupted_evidence.iterdir())


@pytest.mark.parametrize(
    "references",
    (
        [],
        [{"type": "website", "url": "https://example.invalid/runtime"}],
    ),
    ids=("no-references", "https-reference"),
)
def test_generation_preserves_non_pypi_application_display_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    references: list[dict[str, str]],
) -> None:
    snapshot, artifact, payload_sbom = _fixture(tmp_path, target_name="windows-x64")
    components = payload_sbom["components"]
    dependencies = payload_sbom["dependencies"]
    assert isinstance(components, list) and isinstance(dependencies, list)
    file_component = components[0]
    assert isinstance(file_component, dict)
    file_component["name"] = r"\_internal\example.dist-info\METADATA"
    package_component = components[1]
    assert isinstance(package_component, dict)
    package_properties = package_component["properties"]
    assert isinstance(package_properties, list)
    package_location = package_properties[1]
    assert isinstance(package_location, dict)
    package_location["value"] = r"\_internal\example.dist-info\METADATA"
    components.append(
        {
            "type": "application",
            "name": "Native Runtime Library",
            "version": "1.0",
            "bom-ref": "raw-native-runtime",
            "properties": [
                {
                    "name": "syft:location:0:path",
                    "value": r"\_internal\example.dist-info\METADATA",
                }
            ],
            "externalReferences": references,
        }
    )
    dependencies[0]["dependsOn"].append("raw-native-runtime")
    dependencies.append({"ref": "raw-native-runtime"})

    evidence = tmp_path / "native-runtime-evidence"
    workspace = tmp_path / "native-runtime-workspace"
    evidence.mkdir()
    workspace.mkdir(mode=0o700)
    (workspace / "syft-cache").mkdir(mode=0o700)
    (workspace / "syft-config").mkdir(mode=0o700)
    tool = tmp_path / "native-runtime-syft"
    tool.write_bytes(b"tool")
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.acquire_syft", lambda *_args: tool
    )
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.run_syft_scan",
        lambda *_args: _args[5].write_text(json.dumps(payload_sbom), encoding="utf-8"),
    )

    result = generate_supply_chain_evidence(
        snapshot, artifact, evidence, workspace, _MAX_RESOLUTION_STEPS
    )
    payload = json.loads(result.payload_sbom.read_text(encoding="utf-8"))
    provenance = json.loads(result.dependency_provenance.read_text(encoding="utf-8"))
    application = next(
        component
        for component in payload["components"]
        if component["name"] == "Native Runtime Library"
    )
    assert "purl" not in application
    assert application.get("externalReferences", []) == references
    assert application["properties"] == [
        {
            "name": "syft:location:0:path",
            "value": "_internal/example.dist-info/METADATA",
        }
    ]
    assert {
        "component": "Native Runtime Library",
        "type": "application",
        "version": "1.0",
    } in provenance["payload_additional_components"]
    strict_payload = _validate_cyclonedx_sbom(payload, "frozen-payload-filesystem")
    strict_provenance = _validate_dependency_provenance(
        result.dependency_provenance,
        load_evidence_policy(
            _POLICY_ROOT / "evidence-policy.json"
        ).limits.max_metadata_file_bytes,
    )
    assert application in strict_payload.components
    assert {
        "component": "Native Runtime Library",
        "type": "application",
        "version": "1.0",
    } in strict_provenance["payload_additional_components"]


def test_non_pypi_application_rejects_unreviewed_http_reference(
    tmp_path: Path,
) -> None:
    snapshot, artifact, _payload_sbom = _fixture(tmp_path, target_name="windows-x64")
    component = {
        "type": "application",
        "name": "Native Runtime Library",
        "version": "1.0",
        "bom-ref": "raw-native-runtime",
        "properties": [
            {
                "name": "syft:location:0:path",
                "value": r"\_internal\example.dist-info\METADATA",
            }
        ],
        "externalReferences": [
            {"type": "website", "url": "http://example.invalid/runtime"}
        ],
    }
    resolver, regular_files = _payload_resolution(snapshot)

    with pytest.raises(ArtifactEvidenceError, match="unreviewed HTTP"):
        _normalize_payload_component(
            component,
            snapshot,
            resolver,
            regular_files,
            [],
            frozenset(),
            target=artifact.target,
        )


@pytest.mark.parametrize(
    "scanner_path",
    [
        r"\_internal\example.dist-info\METADATA",
        r"_internal\example.dist-info\METADATA",
        "/_internal/example.dist-info/METADATA",
        "_internal/example.dist-info/METADATA",
    ],
    ids=(
        "one-leading-backslash",
        "relative-backslashes",
        "one-leading-forward-slash",
        "relative-forward-slashes",
    ),
)
def test_generation_normalizes_pinned_windows_syft_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner_path: str
) -> None:
    snapshot, artifact, payload_sbom = _fixture(tmp_path, target_name="windows-x64")
    file_component = payload_sbom["components"][0]
    package_component = payload_sbom["components"][1]
    assert isinstance(file_component, dict)
    assert isinstance(package_component, dict)
    file_component["name"] = scanner_path
    properties = package_component["properties"]
    assert isinstance(properties, list)
    location = properties[1]
    assert isinstance(location, dict)
    location["value"] = scanner_path

    evidence = tmp_path / "windows-evidence"
    evidence.mkdir()
    workspace = tmp_path / "windows-workspace"
    workspace.mkdir(mode=0o700)
    (workspace / "syft-cache").mkdir(mode=0o700)
    (workspace / "syft-config").mkdir(mode=0o700)
    tool = tmp_path / "windows-syft"
    tool.write_bytes(b"tool")
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.acquire_syft", lambda *_args: tool
    )
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.run_syft_scan",
        lambda *_args: _args[5].write_text(json.dumps(payload_sbom), encoding="utf-8"),
    )

    result = generate_supply_chain_evidence(
        snapshot, artifact, evidence, workspace, _MAX_RESOLUTION_STEPS
    )

    normalized = json.loads(result.payload_sbom.read_text(encoding="utf-8"))
    file_entry = next(
        item for item in normalized["components"] if item["type"] == "file"
    )
    package_entry = next(
        item
        for item in normalized["components"]
        if item.get("purl") == "pkg:pypi/example@1.0"
    )
    assert file_entry["name"] == "_internal/example.dist-info/METADATA"
    assert package_entry["properties"] == [
        {
            "name": "syft:location:0:path",
            "value": "_internal/example.dist-info/METADATA",
        },
        {"name": "syft:package:type", "value": "python"},
    ]


def test_windows_full_file_component_path_uses_exact_trusted_root() -> None:
    trusted_root = PureWindowsPath(r"C:\owned\Payload")

    assert (
        _windows_file_component_relative_path(
            "/c/owned/Payload/_internal/example.dist-info/METADATA", trusted_root
        )
        == "_internal/example.dist-info/METADATA"
    )


@pytest.mark.parametrize(
    "value",
    (
        "/C/owned/Payload/_internal/file.bin",
        "/d/owned/Payload/_internal/file.bin",
        "/c/owned/payload/_internal/file.bin",
        "/c/other/Payload/_internal/file.bin",
        "/c/owned/Payloadish/_internal/file.bin",
        "/c/owned/Payload",
        "/c/owned/Payload/",
        "/c//owned/Payload/_internal/file.bin",
        "/c/owned/./Payload/_internal/file.bin",
        "/c/owned/../Payload/_internal/file.bin",
        "/c/owned/Payload/_internal/file:stream",
        "/c/owned/Payload/_internal/\x00file.bin",
        "/c/owned\\Payload/_internal/file.bin",
        "//c/owned/Payload/_internal/file.bin",
        "/?/owned/Payload/_internal/file.bin",
    ),
)
def test_windows_full_file_component_path_rejects_untrusted_raw_spelling(
    value: str,
) -> None:
    with pytest.raises(ArtifactEvidenceError, match="payload SBOM path is invalid"):
        _windows_file_component_relative_path(
            value, PureWindowsPath(r"C:\owned\Payload")
        )


@pytest.mark.parametrize(
    "trusted_root",
    (PureWindowsPath(r"C:owned\Payload"), PureWindowsPath(r"\\server\share")),
)
def test_windows_full_file_component_path_requires_drive_root(
    trusted_root: PureWindowsPath,
) -> None:
    with pytest.raises(ArtifactEvidenceError, match="payload SBOM path is invalid"):
        _windows_file_component_relative_path(
            "/c/owned/Payload/_internal/file.bin", trusted_root
        )


@pytest.mark.skipif(sys.platform != "win32", reason="requires a native Windows root")
def test_native_windows_generation_normalizes_full_syft_file_component_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot, artifact, payload_sbom = _fixture(tmp_path, target_name="windows-x64")
    root = PureWindowsPath(str(snapshot.root))
    relative = PurePosixPath("_internal/example.dist-info/METADATA")
    assert root.drive and root.root == "\\"
    file_component = payload_sbom["components"][0]
    assert isinstance(file_component, dict)
    file_component["name"] = "/" + "/".join(
        (root.drive[0].lower(), *root.parts[1:], *relative.parts)
    )
    package_component = payload_sbom["components"][1]
    assert isinstance(package_component, dict)
    properties = package_component["properties"]
    assert isinstance(properties, list)
    location = properties[1]
    assert isinstance(location, dict)
    location["value"] = r"\_internal\example.dist-info\METADATA"

    evidence = tmp_path / "windows-full-file-evidence"
    workspace = tmp_path / "windows-full-file-workspace"
    evidence.mkdir()
    workspace.mkdir(mode=0o700)
    (workspace / "syft-cache").mkdir(mode=0o700)
    (workspace / "syft-config").mkdir(mode=0o700)
    tool = tmp_path / "windows-full-file-syft"
    tool.write_bytes(b"tool")
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.acquire_syft", lambda *_args: tool
    )
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.run_syft_scan",
        lambda *_args: _args[5].write_text(json.dumps(payload_sbom), encoding="utf-8"),
    )

    result = generate_supply_chain_evidence(
        snapshot, artifact, evidence, workspace, _MAX_RESOLUTION_STEPS
    )
    normalized = json.loads(result.payload_sbom.read_text(encoding="utf-8"))
    file_entry = next(
        item for item in normalized["components"] if item["type"] == "file"
    )
    package_entry = next(
        item
        for item in normalized["components"]
        if item.get("purl") == "pkg:pypi/example@1.0"
    )
    assert file_entry["name"] == relative.as_posix()
    assert package_entry["properties"] == [
        {
            "name": "syft:location:0:path",
            "value": relative.as_posix(),
        },
        {"name": "syft:package:type", "value": "python"},
    ]


@pytest.mark.parametrize(
    "value",
    [
        "",
        "\x00internal",
        "\x01internal",
        "\u0085internal",
        r"C:\payload\file",
        r"C:payload\file",
        r"\\server\share\file",
        r"\Device\file",
        r"\??\C\file",
        "/?/C/file",
        r"\GLOBALROOT\Device\file",
        r"\_internal\file:stream",
        r"\_internal\\file",
        "\\_internal\\",
        r"\.\_internal\file",
        r"\..\_internal\file",
        r"\_internal/file",
    ],
    ids=(
        "empty",
        "nul",
        "control",
        "unicode-control",
        "drive-absolute",
        "drive-relative",
        "unc",
        "device",
        "nt-namespace",
        "forward-nt-namespace",
        "globalroot-namespace",
        "ads",
        "repeated-separator",
        "trailing-separator",
        "dot",
        "dotdot",
        "mixed-separators",
    ),
)
def test_windows_payload_paths_reject_unsafe_raw_spellings(
    tmp_path: Path, value: str
) -> None:
    snapshot, artifact, _payload_sbom = _fixture(tmp_path, target_name="windows-x64")

    with pytest.raises(ArtifactEvidenceError, match="payload SBOM path is invalid"):
        _payload_relative_path(value, snapshot.root, artifact.target)


def test_posix_payload_paths_continue_to_reject_backslashes(tmp_path: Path) -> None:
    snapshot, artifact, _payload_sbom = _fixture(tmp_path)

    with pytest.raises(ArtifactEvidenceError, match="payload SBOM path is invalid"):
        _payload_relative_path(
            r"\_internal\example.dist-info\METADATA", snapshot.root, artifact.target
        )


def test_valid_payload_document_requires_explicit_validated_target(
    tmp_path: Path,
) -> None:
    snapshot, _artifact, payload_sbom = _fixture(tmp_path)
    policy = _load_normalization_policy(
        _POLICY_ROOT / "sbom-normalization.json",
        load_syft_policy(_POLICY_ROOT / "syft-tools.json"),
    )

    with pytest.raises(ArtifactEvidenceError, match="target is unavailable"):
        _normalize_payload_sbom(
            payload_sbom,
            snapshot,
            "1.2.3",
            frozenset({"example"}),
            [],
            policy,
            _MAX_RESOLUTION_STEPS,
        )


@pytest.mark.parametrize(
    ("scanner_path", "error"),
    [
        (r"\missing\METADATA", "dangling"),
        (r"\_internal", "not a file"),
    ],
    ids=("missing-manifest-entry", "nonregular-manifest-entry"),
)
def test_windows_payload_paths_keep_manifest_regular_file_checks(
    tmp_path: Path, scanner_path: str, error: str
) -> None:
    snapshot, artifact, payload_sbom = _fixture(tmp_path, target_name="windows-x64")
    component = copy.deepcopy(payload_sbom["components"][0])
    assert isinstance(component, dict)
    component["name"] = scanner_path
    resolver, regular_files = _payload_resolution(snapshot)

    with pytest.raises(ArtifactEvidenceError, match=error):
        _normalize_payload_component(
            component,
            snapshot,
            resolver,
            regular_files,
            [],
            frozenset(),
            target=artifact.target,
        )


def test_windows_payload_file_hash_check_remains_bound_to_manifest(
    tmp_path: Path,
) -> None:
    snapshot, artifact, payload_sbom = _fixture(tmp_path, target_name="windows-x64")
    component = copy.deepcopy(payload_sbom["components"][0])
    assert isinstance(component, dict)
    component["name"] = r"\_internal\example.dist-info\METADATA"
    component["hashes"] = [{"alg": "SHA-256", "content": "0" * 64}]
    resolver, regular_files = _payload_resolution(snapshot)

    with pytest.raises(ArtifactEvidenceError, match="file hash"):
        _normalize_payload_component(
            component,
            snapshot,
            resolver,
            regular_files,
            [],
            frozenset(),
            target=artifact.target,
        )


def test_generation_accepts_a_snapshot_with_embedded_notices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fixture_snapshot, artifact, payload_sbom = _fixture(tmp_path)
    monkeypatch.setattr(
        artifact_filesystem,
        "load_embedded_notice_policy",
        lambda _path, _max_bytes: _NOTICE_POLICIES,
    )
    snapshot = snapshot_payload(artifact, _SNAPSHOT_LIMITS)
    assert snapshot.third_party_notices == tuple(
        EmbeddedNoticeRecord(
            policy.distribution,
            policy.version,
            _NOTICE_WHEEL_HASHES[index],
            policy.payload_path,
            policy.sha256_by_target[artifact.target.name],
        )
        for index, policy in enumerate(_NOTICE_POLICIES)
    )
    evidence = tmp_path / "evidence"
    workspace = tmp_path / "workspace"
    evidence.mkdir()
    workspace.mkdir(mode=0o700)
    (workspace / "syft-cache").mkdir(mode=0o700)
    (workspace / "syft-config").mkdir(mode=0o700)
    fake_tool = tmp_path / "syft"
    fake_tool.write_bytes(b"tool")
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.acquire_syft",
        lambda *_args: fake_tool,
    )
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.run_syft_scan",
        lambda *_args: _args[5].write_text(json.dumps(payload_sbom), encoding="utf-8"),
    )

    result = generate_supply_chain_evidence(
        snapshot, artifact, evidence, workspace, _MAX_RESOLUTION_STEPS
    )

    provenance = json.loads(result.dependency_provenance.read_text(encoding="utf-8"))
    assert provenance["third_party_notices"]["notices"][0]["distribution"] == (
        "charset-normalizer"
    )


def test_third_party_notice_attestation_rejects_invalid_typed_records(
    tmp_path: Path,
) -> None:
    snapshot, artifact, policy, environment, licenses, closure, toolchain = (
        _notice_attestation_context(tmp_path)
    )
    records = snapshot.third_party_notices
    invalid_records = (
        (),
        records + (records[0],),
        tuple(reversed(records)),
        records[:1] + (replace(records[1], source_wheel_sha256=True),) + records[2:],
        records[:1] + (replace(records[1], version="9.9"),) + records[2:],
        records[:1]
        + (replace(records[1], payload_path=PurePosixPath("_internal/notices/other")),)
        + records[2:],
        records[:1] + (replace(records[1], sha256="0" * 64),) + records[2:],
        records[:1]
        + (replace(records[1], source_wheel_sha256="0" * 64),)
        + records[2:],
    )
    for candidate in invalid_records:
        with pytest.raises(ArtifactEvidenceError, match="third-party notice"):
            _third_party_notice_attestation(
                replace(snapshot, third_party_notices=candidate),
                artifact,
                policy,
                environment,
                licenses,
                closure,
                toolchain,
            )


def test_third_party_notice_attestation_rejects_private_evidence_conflicts(
    tmp_path: Path,
) -> None:
    snapshot, artifact, policy, environment, licenses, closure, toolchain = (
        _notice_attestation_context(tmp_path)
    )
    record = snapshot.third_party_notices[0]
    multiple_hashes = {
        **environment,
        record.distribution: {
            **environment[record.distribution],
            "hashes": (
                f"sha256:{record.source_wheel_sha256}",
                "sha256:" + "f" * 64,
            ),
        },
    }
    wrong_license = {
        **licenses,
        record.distribution: replace(licenses[record.distribution], version="9.9"),
    }
    wrong_toolchain = {**toolchain, "pyinstaller_version": "9.9"}
    wrong_hooks_toolchain = {**toolchain, "pyinstaller_hooks_version": "9.9"}
    for (
        candidate_environment,
        candidate_licenses,
        candidate_closure,
        candidate_toolchain,
    ) in (
        (multiple_hashes, licenses, closure, toolchain),
        (environment, wrong_license, closure, toolchain),
        (environment, licenses, closure, wrong_toolchain),
        (environment, licenses, closure, wrong_hooks_toolchain),
    ):
        with pytest.raises(ArtifactEvidenceError, match="third-party notice"):
            _third_party_notice_attestation(
                snapshot,
                artifact,
                policy,
                candidate_environment,
                candidate_licenses,
                candidate_closure,
                candidate_toolchain,
            )
    for notice in snapshot.third_party_notices:
        with pytest.raises(ArtifactEvidenceError, match="third-party notice"):
            _third_party_notice_attestation(
                snapshot,
                artifact,
                policy,
                environment,
                licenses,
                {**closure, notice.distribution: "9.9"},
                toolchain,
            )


def test_generation_canonicalizes_framework_aliases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot, artifact, payload_sbom = _fixture(tmp_path)
    physical = PurePosixPath("_internal/Python.framework/Versions/3.12/Python")
    physical_sha256 = hashlib.sha256(b"framework executable").hexdigest()
    framework_entries = (
        PayloadEntry(
            PurePosixPath("_internal/Python.framework"),
            "directory",
            0o755,
            0,
            None,
            None,
        ),
        PayloadEntry(
            PurePosixPath("_internal/Python.framework/Versions"),
            "directory",
            0o755,
            0,
            None,
            None,
        ),
        PayloadEntry(
            PurePosixPath("_internal/Python.framework/Versions/3.12"),
            "directory",
            0o755,
            0,
            None,
            None,
        ),
        PayloadEntry(physical, "file", 0o755, 20, physical_sha256, None),
        PayloadEntry(
            PurePosixPath("_internal/Python.framework/Versions/Current"),
            "symlink",
            0o777,
            4,
            None,
            "3.12",
        ),
        PayloadEntry(
            PurePosixPath("_internal/Python.framework/Python"),
            "symlink",
            0o777,
            23,
            None,
            "Versions/Current/Python",
        ),
    )
    snapshot = replace(snapshot, entries=(*snapshot.entries, *framework_entries))
    components = payload_sbom["components"]
    assert isinstance(components, list)
    file_component = components[0]
    python_component = components[1]
    assert isinstance(file_component, dict) and isinstance(python_component, dict)
    file_component["name"] = str(snapshot.root / "_internal/Python.framework/Python")
    file_component["hashes"] = [{"alg": "SHA-256", "content": physical_sha256}]
    python_component["properties"] = [
        {"name": "syft:package:type", "value": "python"},
        {
            "name": "syft:location:0:path",
            "value": "/_internal/Python.framework/Versions/Current/Python",
        },
    ]
    evidence = tmp_path / "framework-evidence"
    evidence.mkdir()
    workspace = tmp_path / "framework-workspace"
    workspace.mkdir(mode=0o700)
    (workspace / "syft-cache").mkdir(mode=0o700)
    (workspace / "syft-config").mkdir(mode=0o700)
    fake_tool = tmp_path / "framework-syft"
    fake_tool.write_bytes(b"tool")
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.acquire_syft",
        lambda *_args: fake_tool,
    )
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.run_syft_scan",
        lambda *_args: _args[5].write_text(json.dumps(payload_sbom), encoding="utf-8"),
    )

    result = generate_supply_chain_evidence(
        snapshot, artifact, evidence, workspace, _MAX_RESOLUTION_STEPS
    )

    payload = json.loads(result.payload_sbom.read_text(encoding="utf-8"))
    normalized_file = next(
        item for item in payload["components"] if item["type"] == "file"
    )
    normalized_package = next(
        item
        for item in payload["components"]
        if item.get("purl") == "pkg:pypi/example@1.0"
    )
    assert normalized_file["name"] == physical.as_posix()
    assert normalized_file["hashes"] == [{"alg": "SHA-256", "content": physical_sha256}]
    location = next(
        item
        for item in normalized_package["properties"]
        if item["name"] == "syft:location:0:path"
    )
    assert location["value"] == physical.as_posix()


def test_generation_preserves_embedded_python_runtime_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot, artifact, payload_sbom = _fixture(tmp_path)
    snapshot = _add_embedded_python_runtime(snapshot, payload_sbom)
    evidence = tmp_path / "runtime-evidence"
    evidence.mkdir()
    workspace = tmp_path / "runtime-workspace"
    workspace.mkdir(mode=0o700)
    (workspace / "syft-cache").mkdir(mode=0o700)
    (workspace / "syft-config").mkdir(mode=0o700)
    fake_tool = tmp_path / "runtime-syft"
    fake_tool.write_bytes(b"tool")
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.acquire_syft",
        lambda *_args: fake_tool,
    )

    def fake_scan(
        _executable: Path,
        _policy: object,
        _target: object,
        _payload_root: Path,
        _product_version: str,
        raw_output: Path,
        _config_root: Path,
    ) -> None:
        raw_output.write_text(json.dumps(payload_sbom), encoding="utf-8")

    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.run_syft_scan", fake_scan
    )

    result = generate_supply_chain_evidence(
        snapshot, artifact, evidence, workspace, _MAX_RESOLUTION_STEPS
    )
    payload = json.loads(result.payload_sbom.read_text(encoding="utf-8"))
    provenance = json.loads(result.dependency_provenance.read_text(encoding="utf-8"))

    runtime = next(item for item in payload["components"] if item["name"] == "python")
    assert runtime == {
        "type": "application",
        "name": "python",
        "version": "3.12.14",
        "purl": "pkg:generic/python@3.12.14",
        "bom-ref": "pkg:generic/python@3.12.14",
        "hashes": [{"alg": "SHA-256", "content": "8" * 64}],
        "licenses": [{"license": {"id": "Python-2.0"}}],
        "properties": [
            {
                "name": "syft:location:0:path",
                "value": "_internal/libpython3.12.so.1.0",
            },
            {"name": "syft:package:type", "value": "binary"},
        ],
    }
    assert provenance["runtime_notice"] == snapshot.runtime_notice
    assert {
        "component": "python",
        "type": "application",
        "version": "3.12.14",
    } in provenance["payload_additional_components"]
    assert provenance["payload_python_components"] == [
        {"component": "example", "version": "1.0"}
    ]
    licenses = json.loads(
        result.sanitised_license_inventory.read_text(encoding="utf-8")
    )
    assert all(item["name"] != "python" for item in licenses["packages"])
    runtime_dependency = next(
        item
        for item in payload["dependencies"]
        if item["ref"] == "pkg:generic/python@3.12.14"
    )
    assert runtime_dependency == {
        "ref": "pkg:generic/python@3.12.14",
        "dependsOn": ["pkg:pypi/example@1.0"],
    }


@pytest.mark.parametrize(
    ("raw_licenses", "valid"),
    [
        ([], True),
        ([{"license": {"id": "Python-2.0"}}], True),
        (
            [
                {"license": {"id": "Python-2.0"}},
                {"license": {"id": "Python-2.0"}},
            ],
            False,
        ),
        ([{"license": {"id": "MIT"}}], False),
        ([{"license": {"id": "Python-2.0", "name": "Python"}}], False),
        ([{"expression": "Python-2.0"}], False),
        ([{"license": {"id": "Python-2.0", "url": "https://example.invalid"}}], False),
        (
            [
                {
                    "license": {"id": "Python-2.0"},
                    "acknowledgement": "declared",
                }
            ],
            False,
        ),
    ],
    ids=(
        "empty",
        "canonical",
        "duplicate",
        "different",
        "named",
        "expression",
        "url",
        "acknowledgement",
    ),
)
def test_embedded_python_runtime_license_claim_is_sole_and_attested(
    tmp_path: Path, raw_licenses: list[dict[str, object]], valid: bool
) -> None:
    snapshot, artifact, payload_sbom = _fixture(tmp_path)
    snapshot = _add_embedded_python_runtime(snapshot, payload_sbom)
    component = next(
        item
        for item in payload_sbom["components"]
        if isinstance(item, dict) and item.get("name") == "python"
    )
    component["licenses"] = raw_licenses
    resolver, regular_files = _payload_resolution(snapshot)

    if valid:
        normalized, _ = _normalize_payload_component(
            component,
            snapshot,
            resolver,
            regular_files,
            [],
            frozenset(),
            target=artifact.target,
        )
        assert normalized["licenses"] == [{"license": {"id": "Python-2.0"}}]
    else:
        with pytest.raises(ArtifactEvidenceError, match="license claim"):
            _normalize_payload_component(
                component,
                snapshot,
                resolver,
                regular_files,
                [],
                frozenset(),
                target=artifact.target,
            )


@pytest.mark.parametrize(
    "runtime_notice",
    [
        None,
        {"schema_version": 1},
        {
            "schema_version": 1,
            "runtime": "cpython",
            "python_implementation": "CPython",
            "python_version": "3.12.14",
            "license_id": "Python-2.0",
            "payload_path": "_internal/notices/CPython-LICENSE.txt",
            "sha256": "A" * 64,
        },
    ],
    ids=("missing", "incomplete", "noncanonical-digest"),
)
def test_generation_requires_a_valid_runtime_notice_attestation(
    tmp_path: Path, runtime_notice: dict[str, object] | None
) -> None:
    snapshot, artifact, _payload_sbom = _fixture(tmp_path)
    snapshot = replace(snapshot, runtime_notice=runtime_notice)

    with pytest.raises(ArtifactEvidenceError, match="runtime notice attestation"):
        generate_supply_chain_evidence(
            snapshot,
            artifact,
            tmp_path / "unavailable-evidence",
            tmp_path / "unavailable-workspace",
            _MAX_RESOLUTION_STEPS,
        )


def test_embedded_python_runtime_rejects_unapproved_identities(
    tmp_path: Path,
) -> None:
    snapshot, artifact, payload_sbom = _fixture(tmp_path)
    snapshot = _add_embedded_python_runtime(snapshot, payload_sbom)
    component = next(
        item
        for item in payload_sbom["components"]
        if isinstance(item, dict) and item.get("name") == "python"
    )
    cases: list[tuple[str, dict[str, object]]] = [
        ("unknown-family", {"purl": "pkg:deb/ubuntu/python@3.12.14"}),
        ("alternate-package", {"purl": "pkg:generic/pypy@3.12.14"}),
        ("namespace", {"purl": "pkg:generic/runtime/python@3.12.14"}),
        ("qualifier", {"purl": "pkg:generic/python@3.12.14?arch=x86_64"}),
        ("fragment", {"purl": "pkg:generic/python@3.12.14#runtime"}),
        ("encoded-name", {"purl": "pkg:generic/py%74hon@3.12.14"}),
        ("name", {"name": "Python"}),
        ("type", {"type": "library"}),
        ("version", {"version": "3.12.13"}),
        ("missing-version", {"version": None}),
        ("missing-purl", {"purl": None}),
        ("whitespace", {"purl": "pkg:generic/python@3.12.14 "}),
        ("overlong", {"purl": "pkg:generic/" + "x" * 2048}),
    ]
    resolver, regular_files = _payload_resolution(snapshot)
    for case_name, replacements in cases:
        candidate = copy.deepcopy(component)
        for field, value in replacements.items():
            if value is None:
                candidate.pop(field)
            else:
                candidate[field] = value
        with pytest.raises(ArtifactEvidenceError) as error:
            _normalize_payload_component(
                candidate,
                snapshot,
                resolver,
                regular_files,
                [],
                frozenset(),
                target=artifact.target,
            )
        assert str(error.value), case_name


@pytest.mark.parametrize(
    ("properties", "error"),
    [
        (
            [
                {
                    "name": "syft:location:0:path",
                    "value": "/_internal/libpython3.12.so.1.0",
                }
            ],
            "properties",
        ),
        (
            [
                {"name": "syft:package:type", "value": "python"},
                {
                    "name": "syft:location:0:path",
                    "value": "/_internal/libpython3.12.so.1.0",
                },
            ],
            "properties",
        ),
        ([{"name": "syft:package:type", "value": "binary"}], "properties"),
        (
            [
                {"name": "syft:package:type", "value": "binary"},
                {
                    "name": "syft:location:0:path",
                    "value": "/outside/libpython3.12.so.1.0",
                },
            ],
            "payload|location",
        ),
        (
            [
                {"name": "syft:package:type", "value": "binary"},
                {"name": "syft:location:0:path", "value": "/_internal"},
            ],
            "regular payload file",
        ),
    ],
    ids=("missing-type", "wrong-type", "missing-location", "outside", "directory"),
)
def test_embedded_python_runtime_requires_binary_regular_file_location(
    tmp_path: Path, properties: list[dict[str, str]], error: str
) -> None:
    snapshot, artifact, payload_sbom = _fixture(tmp_path)
    snapshot = _add_embedded_python_runtime(snapshot, payload_sbom)
    component = next(
        item
        for item in payload_sbom["components"]
        if isinstance(item, dict) and item.get("name") == "python"
    )
    component["properties"] = properties
    resolver, regular_files = _payload_resolution(snapshot)
    with pytest.raises(ArtifactEvidenceError, match=error):
        _normalize_payload_component(
            component,
            snapshot,
            resolver,
            regular_files,
            [],
            frozenset(),
            target=artifact.target,
        )


@pytest.mark.parametrize(
    ("toolchain", "provenance"),
    [
        ({"python_implementation": "PyPy"}, {}),
        ({"python_version": "3.12.13"}, {}),
        ({}, {"target": "macos-x64"}),
    ],
    ids=("implementation", "toolchain-version", "target"),
)
def test_embedded_python_runtime_is_bound_to_build_facts(
    tmp_path: Path,
    toolchain: dict[str, str],
    provenance: dict[str, str],
) -> None:
    snapshot, artifact, payload_sbom = _fixture(tmp_path)
    snapshot = _add_embedded_python_runtime(snapshot, payload_sbom)
    snapshot = replace(
        snapshot,
        build_toolchain={**snapshot.build_toolchain, **toolchain},
        build_provenance={**snapshot.build_provenance, **provenance},
    )
    component = next(
        item
        for item in payload_sbom["components"]
        if isinstance(item, dict) and item.get("name") == "python"
    )
    resolver, regular_files = _payload_resolution(snapshot)
    with pytest.raises(ArtifactEvidenceError, match="runtime component identity"):
        _normalize_payload_component(
            component,
            snapshot,
            resolver,
            regular_files,
            [],
            frozenset(),
            target=artifact.target,
        )


def test_malformed_pypi_purl_never_falls_back_to_runtime_identity(
    tmp_path: Path,
) -> None:
    snapshot, artifact, payload_sbom = _fixture(tmp_path)
    component = next(
        item
        for item in payload_sbom["components"]
        if isinstance(item, dict) and item.get("purl") == "pkg:pypi/example@1.0"
    )
    component["purl"] = "pkg:pypi/example"
    resolver, regular_files = _payload_resolution(snapshot)
    with pytest.raises(ArtifactEvidenceError, match="Python component purl is invalid"):
        _normalize_payload_component(
            component,
            snapshot,
            resolver,
            regular_files,
            [],
            frozenset(),
            target=artifact.target,
        )


def test_generation_records_reviewed_parent_vendored_python_component(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot, artifact, payload_sbom = _fixture(tmp_path)
    snapshot = _add_vendored_component(snapshot, artifact, payload_sbom)
    evidence = tmp_path / "vendor-evidence"
    evidence.mkdir()
    workspace = tmp_path / "vendor-workspace"
    workspace.mkdir(mode=0o700)
    (workspace / "syft-cache").mkdir(mode=0o700)
    (workspace / "syft-config").mkdir(mode=0o700)
    fake_tool = tmp_path / "vendor-syft"
    fake_tool.write_bytes(b"tool")
    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.acquire_syft",
        lambda *_args: fake_tool,
    )

    def fake_scan(
        _executable: Path,
        _policy: object,
        _target: object,
        _payload_root: Path,
        _product_version: str,
        raw_output: Path,
        _config_root: Path,
    ) -> None:
        raw_output.write_text(json.dumps(payload_sbom), encoding="utf-8")

    monkeypatch.setattr(
        "scripts.standalone_cli.sbom_normalize.run_syft_scan", fake_scan
    )

    result = generate_supply_chain_evidence(
        snapshot, artifact, evidence, workspace, _MAX_RESOLUTION_STEPS
    )
    payload = json.loads(result.payload_sbom.read_text(encoding="utf-8"))
    provenance = json.loads(result.dependency_provenance.read_text(encoding="utf-8"))
    licenses = json.loads(
        result.sanitised_license_inventory.read_text(encoding="utf-8")
    )

    vendored = next(
        item for item in payload["components"] if item["name"] == "importlib-metadata"
    )
    assert vendored["purl"] == "pkg:pypi/importlib-metadata@8.7.1"
    assert vendored["licenses"] == [{"license": {"id": "Apache-2.0"}}]
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
        item["component"] == "importlib-metadata"
        for item in provenance["payload_additional_components"]
    )
    assert not any(
        item["name"] == "importlib-metadata" for item in licenses["packages"]
    )
    assert any(item["name"] == "setuptools" for item in licenses["packages"])


@pytest.mark.parametrize(
    "locations",
    [
        [],
        [
            "_internal/setuptools/_vendor/importlib_metadata-8.7.1.dist-info/METADATA",
            "_internal/other/importlib_metadata-8.7.1.dist-info/RECORD",
        ],
        ["_internal/other/_vendor/importlib_metadata-8.7.1.dist-info/METADATA"],
        ["_internal/setuptools/_vendor/other-8.7.1.dist-info/METADATA"],
        ["_internal/setuptools/_vendor/importlib_metadata-8.7.0.dist-info/METADATA"],
    ],
    ids=("no-location", "mixed", "other-parent", "name-mismatch", "version-mismatch"),
)
def test_vendored_python_component_rejects_unreviewed_locations(
    locations: list[str],
) -> None:
    component = _vendored_component(locations)
    with pytest.raises(ArtifactEvidenceError, match="location|reviewed vendor"):
        _vendored_python_component(
            component,
            (_ParentVendor("setuptools", "_internal/setuptools/_vendor"),),
        )


def test_vendored_python_component_requires_one_reviewed_parent() -> None:
    location = (
        "_internal/setuptools/_vendor/importlib_metadata-8.7.1.dist-info/METADATA"
    )
    component = _vendored_component([location])
    assert _vendored_python_component(
        component,
        (_ParentVendor("setuptools", "_internal/setuptools/_vendor"),),
    ) == _VendoredPythonComponent("importlib-metadata", "8.7.1", "setuptools")
    with pytest.raises(ArtifactEvidenceError, match="reviewed vendor"):
        _vendored_python_component(component, ())


def test_payload_location_requires_snapshot_regular_file(tmp_path: Path) -> None:
    snapshot, artifact, _payload_sbom = _fixture(tmp_path)
    resolver, regular_files = _payload_resolution(snapshot)
    properties = [
        {
            "name": "syft:location:0:path",
            "value": "/_internal",
        }
    ]
    with pytest.raises(ArtifactEvidenceError, match="regular payload file"):
        _normalize_properties(
            properties,
            payload_root=snapshot.root,
            target=artifact.target,
            snapshot_regular_files=regular_files,
            payload_resolver=resolver,
        )


def test_payload_location_alias_requires_physical_regular_file(tmp_path: Path) -> None:
    snapshot, artifact, _payload_sbom = _fixture(tmp_path)
    snapshot = replace(
        snapshot,
        entries=(
            *snapshot.entries,
            PayloadEntry(
                PurePosixPath("runtime-alias"),
                "symlink",
                0o777,
                9,
                None,
                "_internal",
            ),
        ),
    )
    resolver, regular_files = _payload_resolution(snapshot)

    with pytest.raises(ArtifactEvidenceError, match="regular payload file"):
        _normalize_properties(
            [{"name": "syft:location:0:path", "value": "/runtime-alias"}],
            payload_root=snapshot.root,
            target=artifact.target,
            snapshot_regular_files=regular_files,
            payload_resolver=resolver,
        )


def test_vendored_python_component_requires_parent_in_closure(tmp_path: Path) -> None:
    snapshot, artifact, _payload_sbom = _fixture(tmp_path)
    with pytest.raises(ArtifactEvidenceError, match="parent is not in the closure"):
        _dependency_provenance(
            snapshot,
            artifact,
            load_syft_policy(_POLICY_ROOT / "syft-tools.json"),
            {},
            {},
            {},
            {},
            (_VendoredPythonComponent("importlib-metadata", "8.7.1", "setuptools"),),
            [],
            [],
        )


def test_vendored_python_relationship_rejects_duplicates(tmp_path: Path) -> None:
    snapshot, artifact, _payload_sbom = _fixture(tmp_path)
    relation = _VendoredPythonComponent("importlib-metadata", "8.7.1", "setuptools")
    installed = _InstalledLicense("setuptools", "84.0.0", None, "MIT", (), ())
    with pytest.raises(ArtifactEvidenceError, match="duplicated"):
        _dependency_provenance(
            snapshot,
            artifact,
            load_syft_policy(_POLICY_ROOT / "syft-tools.json"),
            {},
            {"setuptools": installed},
            {"setuptools": "84.0.0"},
            {},
            (relation, relation),
            [],
            [],
        )


def _vendored_component(locations: list[str]) -> dict[str, object]:
    return {
        "type": "library",
        "name": "importlib-metadata",
        "version": "8.7.1",
        "purl": "pkg:pypi/importlib-metadata@8.7.1",
        "bom-ref": "pkg:pypi/importlib-metadata@8.7.1",
        "licenses": [{"license": {"id": "Apache-2.0"}}],
        "properties": [
            {"name": f"syft:location:{index}:path", "value": location}
            for index, location in enumerate(locations)
        ],
    }


def _add_embedded_python_runtime(
    snapshot: PayloadSnapshot, payload_sbom: dict[str, object]
) -> PayloadSnapshot:
    relative = PurePosixPath("_internal/libpython3.12.so.1.0")
    path = snapshot.root / relative
    path.write_bytes(b"embedded CPython runtime")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    entries = list(snapshot.entries)
    entries.append(
        PayloadEntry(relative, "file", 0o755, path.stat().st_size, digest, None)
    )
    components = payload_sbom["components"]
    dependencies = payload_sbom["dependencies"]
    assert isinstance(components, list) and isinstance(dependencies, list)
    components.extend(
        [
            {
                "type": "file",
                "name": str(path),
                "bom-ref": "raw-runtime-file",
                "hashes": [{"alg": "SHA-256", "content": digest}],
            },
            {
                "type": "application",
                "name": "python",
                "version": "3.12.14",
                "purl": "pkg:generic/python@3.12.14",
                "bom-ref": "raw-runtime-package",
                "hashes": [{"alg": "SHA-256", "content": "8" * 64}],
                "licenses": [{"license": {"id": "Python-2.0"}}],
                "properties": [
                    {"name": "syft:package:type", "value": "binary"},
                    {"name": "syft:location:0:path", "value": str(path)},
                ],
            },
        ]
    )
    root_dependency = dependencies[0]
    assert isinstance(root_dependency, dict)
    root_edges = root_dependency["dependsOn"]
    assert isinstance(root_edges, list)
    root_edges.extend(("raw-runtime-file", "raw-runtime-package"))
    dependencies.extend(
        (
            {"ref": "raw-runtime-file"},
            {"ref": "raw-runtime-package", "dependsOn": ["raw-payload-example"]},
        )
    )
    return replace(
        snapshot,
        entries=tuple(entries),
        expanded_regular_bytes=snapshot.expanded_regular_bytes + path.stat().st_size,
    )


def _add_vendored_component(
    snapshot: PayloadSnapshot,
    artifact: ArtifactDescriptor,
    payload_sbom: dict[str, object],
) -> PayloadSnapshot:
    relative_root = PurePosixPath(
        "_internal/setuptools/_vendor/importlib_metadata-8.7.1.dist-info"
    )
    contents = {
        "METADATA": "Name: importlib_metadata\nVersion: 8.7.1\nLicense-Expression: Apache-2.0\n",
        "RECORD": "importlib_metadata-8.7.1.dist-info/METADATA,,\n",
        "top_level.txt": "importlib_metadata\n",
        "licenses/LICENSE": "Apache License\n",
    }
    entries = list(snapshot.entries)
    for directory in (
        PurePosixPath("_internal/setuptools"),
        PurePosixPath("_internal/setuptools/_vendor"),
        relative_root,
        relative_root / "licenses",
    ):
        (snapshot.root / directory).mkdir(exist_ok=True)
        entries.append(PayloadEntry(directory, "directory", 0o755, 0, None, None))
    regular_bytes = snapshot.expanded_regular_bytes
    raw_files: list[dict[str, object]] = []
    locations: list[str] = []
    for index, (suffix, content) in enumerate(contents.items()):
        relative = relative_root / suffix
        path = snapshot.root / relative
        path.write_text(content, encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(
            PayloadEntry(relative, "file", 0o644, path.stat().st_size, digest, None)
        )
        regular_bytes += path.stat().st_size
        if suffix == "licenses/LICENSE":
            continue
        locations.append(relative.as_posix())
        raw_files.append(
            {
                "type": "file",
                "name": str(path),
                "bom-ref": f"raw-vendor-file-{index}",
                "hashes": [{"alg": "SHA-256", "content": digest}],
            }
        )

    resolved = artifact.build_metadata_dir / "resolved"
    environment_path = resolved / "environment.json"
    environment = json.loads(environment_path.read_text(encoding="utf-8"))
    environment["packages"].append(
        {
            "name": "setuptools",
            "version": "84.0.0",
            "hashes": ["sha256:" + "7" * 64],
        }
    )
    environment_path.write_text(json.dumps(environment), encoding="utf-8")
    licenses_path = resolved / "licenses.json"
    licenses = json.loads(licenses_path.read_text(encoding="utf-8"))
    licenses["packages"].append(
        {
            "name": "setuptools",
            "version": "84.0.0",
            "license": "MIT",
            "license_expression": "MIT",
            "license_classifiers": [],
            "license_files": ["LICENSE"],
        }
    )
    licenses_path.write_text(json.dumps(licenses), encoding="utf-8")
    python_path = resolved / "sbom-python.cdx.json"
    python_sbom = json.loads(python_path.read_text(encoding="utf-8"))
    python_sbom["components"].append(
        _python_component("setuptools", "84.0.0", "raw-setuptools")
    )
    python_sbom["dependencies"].append({"ref": "raw-setuptools"})
    python_path.write_text(json.dumps(python_sbom), encoding="utf-8")

    components = payload_sbom["components"]
    dependencies = payload_sbom["dependencies"]
    assert isinstance(components, list) and isinstance(dependencies, list)
    components.extend(raw_files)
    components.append(
        {
            "type": "library",
            "name": "importlib_metadata",
            "version": "8.7.1",
            "purl": "pkg:pypi/importlib-metadata@8.7.1",
            "bom-ref": "raw-vendored-importlib-metadata",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
            "properties": [
                {
                    "name": f"syft:location:{index}:path",
                    "value": "/" + location,
                }
                for index, location in enumerate(locations)
            ],
        }
    )
    root_dependency = dependencies[0]
    assert isinstance(root_dependency, dict)
    root_edges = root_dependency["dependsOn"]
    assert isinstance(root_edges, list)
    root_edges.extend(item["bom-ref"] for item in raw_files)
    root_edges.append("raw-vendored-importlib-metadata")
    dependencies.extend({"ref": item["bom-ref"]} for item in raw_files)
    dependencies.append({"ref": "raw-vendored-importlib-metadata"})
    return replace(
        snapshot,
        entries=tuple(entries),
        expanded_regular_bytes=regular_bytes,
    )


def _notice_attestation_context(
    tmp_path: Path,
) -> tuple[
    PayloadSnapshot,
    ArtifactDescriptor,
    SyftPolicy,
    dict[str, dict[str, object]],
    dict[str, _InstalledLicense],
    dict[str, str],
    dict[str, object],
]:
    snapshot, artifact, _payload_sbom = _fixture(tmp_path)
    policy = load_syft_policy(_POLICY_ROOT / "syft-tools.json")
    resolved = artifact.build_metadata_dir / "resolved"
    environment = _load_environment(resolved / "environment.json", policy)
    licenses = _load_installed_licenses(resolved / "licenses.json", policy)
    raw_closure = json.loads((resolved / "sbom-python.cdx.json").read_text("utf-8"))
    _document, closure, _license_ids = _normalize_python_sbom(
        raw_closure,
        environment,
        licenses,
        artifact,
        "1.2.3",
        hashlib.sha256(artifact.wheel.read_bytes()).hexdigest(),
        [],
        frozenset(),
    )
    toolchain = _toolchain_provenance(snapshot, artifact, policy, environment)
    return snapshot, artifact, policy, environment, licenses, closure, toolchain


def _fixture(
    tmp_path: Path,
    *,
    target_name: str = "linux-x64-ubuntu-22.04",
) -> tuple[PayloadSnapshot, ArtifactDescriptor, dict[str, object]]:
    target = load_target_spec(_TARGET_POLICY, target_name)
    payload = tmp_path / "payload"
    metadata_file = payload / "_internal" / "example.dist-info" / "METADATA"
    metadata_file.parent.mkdir(parents=True)
    metadata_file.write_text("Name: example\n", encoding="utf-8")
    executable_name = "servonaut.exe" if target.platform == "win32" else "servonaut"
    executable = payload / executable_name
    executable.write_bytes(b"executable")
    executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    wheel = tmp_path / "servonaut-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "servonaut-1.2.3.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: servonaut\nVersion: 1.2.3\n",
        )
    wheel_sha = hashlib.sha256(wheel.read_bytes()).hexdigest()
    metadata = tmp_path / "build-metadata"
    resolved = metadata / "resolved"
    pyinstaller = metadata / "pyinstaller"
    resolved.mkdir(parents=True)
    pyinstaller.mkdir()
    warning = pyinstaller / "warn-servonaut.txt"
    warning.write_text("", encoding="utf-8")
    (pyinstaller / "Analysis-00.toc").write_text("[]", encoding="utf-8")
    (pyinstaller / "PYZ-00.toc").write_text("[]", encoding="utf-8")
    environment = {
        "schema_version": 1,
        "packages": [
            {
                "name": "cyclonedx-bom",
                "version": "7.3.1",
                "hashes": ["sha256:" + "2" * 64],
            },
            {"name": "example", "version": "1.0", "hashes": ["sha256:" + "1" * 64]},
            {
                "name": "pyinstaller",
                "version": "6.22.3",
                "hashes": ["sha256:" + _NOTICE_WHEEL_HASHES[2]],
            },
            {
                "name": "pyinstaller-hooks-contrib",
                "version": "2026.7",
                "hashes": ["sha256:" + _NOTICE_WHEEL_HASHES[3]],
            },
            {
                "name": "servonaut",
                "version": "1.2.3",
                "hashes": ["sha256:" + wheel_sha],
            },
            *[
                {
                    "name": name,
                    "version": version,
                    "hashes": ["sha256:" + _NOTICE_WHEEL_HASHES[index]],
                }
                for index, (name, version, _path) in enumerate(_NOTICE_IDENTITIES)
                if name not in {"pyinstaller", "pyinstaller-hooks-contrib"}
            ],
        ],
    }
    license_packages = [
        {
            "name": name,
            "version": version,
            "license": "MIT",
            "license_expression": "MIT",
            "license_classifiers": ["License :: OSI Approved :: MIT License"],
            "license_files": ["LICENSE"],
        }
        for name, version in (
            ("cyclonedx-bom", "7.3.1"),
            ("example", "1.0"),
            ("pip", "25.0"),
            ("pyinstaller", "6.22.3"),
            ("pyinstaller-hooks-contrib", "2026.7"),
            ("charset-normalizer", "3.5.1"),
            ("pydantic-core", "2.46.5"),
            ("rpds-py", "2026.6.3"),
            ("servonaut", "1.2.3"),
        )
    ]
    python_components = [
        _python_component("cyclonedx-bom", "7.3.1", "raw-cyclonedx"),
        _python_component("example", "1.0", "raw-example"),
        _python_component("pip", "25.0", "raw-pip"),
        _python_component("pyinstaller", "6.22.3", "raw-pyinstaller"),
        _python_component("pyinstaller-hooks-contrib", "2026.7", "raw-hooks"),
        _python_component("charset-normalizer", "3.5.1", "raw-charset-normalizer"),
        _python_component("pydantic-core", "2.46.5", "raw-pydantic-core"),
        _python_component("rpds-py", "2026.6.3", "raw-rpds-py"),
        {
            **_python_component("servonaut", "1.2.3", "raw-servonaut"),
            "hashes": [{"alg": "SHA-256", "content": wheel_sha}],
            "externalReferences": [
                {
                    "type": "distribution",
                    "url": wheel.as_uri(),
                    "hashes": [{"alg": "SHA-256", "content": wheel_sha}],
                },
                {"type": "website", "url": "https://example.invalid/servonaut"},
            ],
        },
    ]
    python_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": python_components,
        "dependencies": [
            {"ref": "raw-cyclonedx"},
            {"ref": "raw-example"},
            {"ref": "raw-pip"},
            {"ref": "raw-pyinstaller"},
            {"ref": "raw-hooks"},
            {"ref": "raw-charset-normalizer"},
            {"ref": "raw-pydantic-core"},
            {"ref": "raw-rpds-py"},
            {"ref": "raw-servonaut", "dependsOn": ["raw-example"]},
        ],
    }
    (resolved / "environment.json").write_text(
        json.dumps(environment), encoding="utf-8"
    )
    (resolved / "licenses.json").write_text(
        json.dumps({"schema_version": 1, "packages": license_packages}),
        encoding="utf-8",
    )
    (resolved / "sbom-python.cdx.json").write_text(
        json.dumps(python_sbom), encoding="utf-8"
    )
    provenance = {
        "schema_version": 1,
        "source_commit": "abc1234",
        "target": target.name,
        "product_version": "1.2.3",
        "build_revision": "build-1",
        "wheel_sha256": wheel_sha,
    }
    (resolved / "build-provenance.json").write_text(
        json.dumps(provenance), encoding="utf-8"
    )
    toolchain = {
        "schema_version": 1,
        "python_implementation": "CPython",
        "python_version": "3.12.14",
        "spec_sha256": "5" * 64,
        "hooks_sha256": "6" * 64,
    }
    (resolved / "build-toolchain.json").write_text(
        json.dumps(toolchain), encoding="utf-8"
    )
    notices = payload / "_internal" / "notices"
    notices.mkdir()
    runtime_notice_bytes = b"CPython license\n"
    (notices / "CPython-LICENSE.txt").write_bytes(runtime_notice_bytes)
    (resolved / "runtime-notice.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "runtime": "cpython",
                "python_implementation": "CPython",
                "python_version": "3.12.14",
                "license_id": "Python-2.0",
                "payload_path": "_internal/notices/CPython-LICENSE.txt",
                "sha256": hashlib.sha256(runtime_notice_bytes).hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    metadata_notices = []
    for index, policy in enumerate(_NOTICE_POLICIES):
        payload_notice = payload.joinpath(*policy.payload_path.parts)
        payload_notice.write_bytes(_NOTICE_BYTES[index])
        metadata_notices.append(
            {
                "distribution": policy.distribution,
                "version": policy.version,
                "source_wheel_sha256": _NOTICE_WHEEL_HASHES[index],
                "payload_path": policy.payload_path.as_posix(),
                "sha256": policy.sha256_by_target[target.name],
            }
        )
    (resolved / "third-party-notices.json").write_text(
        json.dumps({"schema_version": 1, "notices": metadata_notices}),
        encoding="utf-8",
    )
    (payload / "servonaut-runtime.json").write_text(
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
    snapshot = PayloadSnapshot(
        root=payload,
        entries=(
            PayloadEntry(PurePosixPath("_internal"), "directory", 0o755, 0, None, None),
            PayloadEntry(
                PurePosixPath("_internal/example.dist-info"),
                "directory",
                0o755,
                0,
                None,
                None,
            ),
            PayloadEntry(
                PurePosixPath("_internal/example.dist-info/METADATA"),
                "file",
                0o644,
                metadata_file.stat().st_size,
                hashlib.sha256(metadata_file.read_bytes()).hexdigest(),
                None,
            ),
            PayloadEntry(
                PurePosixPath(executable_name),
                "file",
                0o700,
                executable.stat().st_size,
                hashlib.sha256(executable.read_bytes()).hexdigest(),
                None,
            ),
        ),
        expanded_regular_bytes=metadata_file.stat().st_size + executable.stat().st_size,
        executable_relative_path=PurePosixPath(executable_name),
        marker={"product_version": "1.2.3"},
        build_provenance=provenance,
        build_toolchain=toolchain,
        runtime_notice={
            "schema_version": 1,
            "runtime": "cpython",
            "python_implementation": "CPython",
            "python_version": "3.12.14",
            "license_id": "Python-2.0",
            "payload_path": "_internal/notices/CPython-LICENSE.txt",
            "sha256": "7" * 64,
        },
        third_party_notices=tuple(
            EmbeddedNoticeRecord(
                policy.distribution,
                policy.version,
                _NOTICE_WHEEL_HASHES[index],
                policy.payload_path,
                policy.sha256_by_target[target.name],
            )
            for index, policy in enumerate(_NOTICE_POLICIES)
        ),
    )
    artifact = ArtifactDescriptor(
        payload, executable, None, target, wheel, warning, metadata
    )
    file_sha = hashlib.sha256(metadata_file.read_bytes()).hexdigest()
    payload_sbom: dict[str, object] = {
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
                "bom-ref": "raw-file",
                "hashes": [
                    {
                        "alg": "SHA-1",
                        "content": hashlib.sha1(metadata_file.read_bytes()).hexdigest(),
                    },
                    {"alg": "SHA-256", "content": file_sha},
                ],
            },
            {
                "type": "library",
                "name": "example",
                "version": "1.0",
                "purl": "pkg:pypi/example@1.0",
                "bom-ref": "raw-payload-example",
                "properties": [
                    {"name": "syft:package:type", "value": "python"},
                    {
                        "name": "syft:location:0:path",
                        "value": "/_internal/example.dist-info/METADATA",
                    },
                ],
            },
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["raw-file", "raw-payload-example"]},
            {"ref": "raw-file"},
            {"ref": "raw-payload-example"},
        ],
    }
    return snapshot, artifact, payload_sbom


def _payload_resolution(
    snapshot: PayloadSnapshot,
) -> tuple[SnapshotPathResolver, frozenset[str]]:
    return (
        SnapshotPathResolver(snapshot.entries, _MAX_RESOLUTION_STEPS),
        frozenset(
            entry.relative_path.as_posix()
            for entry in snapshot.entries
            if entry.kind == "file"
        ),
    )


def _python_component(name: str, version: str, reference: str) -> dict[str, object]:
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{name}@{version}",
        "bom-ref": reference,
        "licenses": [{"license": {"id": "MIT", "acknowledgement": "declared"}}],
    }
