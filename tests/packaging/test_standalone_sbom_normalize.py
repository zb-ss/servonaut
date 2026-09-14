"""Supply-chain SBOM normalization and reconciliation tests."""

from __future__ import annotations

import copy
import hashlib
import json
import stat
from dataclasses import replace
from pathlib import Path, PurePosixPath

import pytest
from jsonschema import Draft202012Validator

from scripts.standalone_cli.artifact_types import (
    ArtifactDescriptor,
    ArtifactEvidenceError,
    PayloadEntry,
    PayloadSnapshot,
)
from scripts.standalone_cli.evidence_sanitize import write_public_json
from scripts.standalone_cli.model import load_target_spec
from scripts.standalone_cli.sbom_normalize import (
    _dependency_provenance,
    _HttpReferenceOmission,
    _InstalledLicense,
    _load_normalization_policy,
    _normalize_external_references,
    _normalize_payload_component,
    _normalize_properties,
    _ParentVendor,
    _vendored_python_component,
    _VendoredPythonComponent,
    generate_supply_chain_evidence,
)
from scripts.standalone_cli.syft_tool import load_syft_policy

_ROOT = Path(__file__).resolve().parents[2]
_POLICY_ROOT = _ROOT / "packaging" / "standalone_cli"
_TARGET_POLICY = _POLICY_ROOT / "target-policy.json"
_HTTP_URL = "http://example.invalid/project"


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

    result = generate_supply_chain_evidence(snapshot, artifact, evidence, workspace)

    payload = json.loads(result.payload_sbom.read_text(encoding="utf-8"))
    closure = json.loads(result.python_closure_sbom.read_text(encoding="utf-8"))
    provenance = json.loads(result.dependency_provenance.read_text(encoding="utf-8"))
    licenses = json.loads(
        result.sanitised_license_inventory.read_text(encoding="utf-8")
    )
    files = [item for item in payload["components"] if item["type"] == "file"]
    assert files[0]["name"] == "_internal/example.dist-info/METADATA"
    assert files[0]["hashes"][1]["alg"] == "SHA-256"
    assert payload["specVersion"] == closure["specVersion"] == "1.6"
    assert provenance["unresolved_conflicts"] == []
    assert provenance["payload_vendored_python_components"] == []
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
            snapshot, artifact, interrupted_evidence, interrupted_workspace
        )
    assert not tuple(interrupted_evidence.iterdir())


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

    result = generate_supply_chain_evidence(snapshot, artifact, evidence, workspace)
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
    assert {
        "component": "python",
        "type": "application",
        "version": "3.12.14",
    } in provenance["payload_additional_components"]
    assert provenance["payload_python_components"] == [
        {"component": "example", "version": "1.0"}
    ]
    runtime_dependency = next(
        item
        for item in payload["dependencies"]
        if item["ref"] == "pkg:generic/python@3.12.14"
    )
    assert runtime_dependency == {
        "ref": "pkg:generic/python@3.12.14",
        "dependsOn": ["pkg:pypi/example@1.0"],
    }


def test_embedded_python_runtime_rejects_unapproved_identities(
    tmp_path: Path,
) -> None:
    snapshot, _artifact, payload_sbom = _fixture(tmp_path)
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
    entries = {entry.relative_path.as_posix(): entry for entry in snapshot.entries}
    for case_name, replacements in cases:
        candidate = copy.deepcopy(component)
        for field, value in replacements.items():
            if value is None:
                candidate.pop(field)
            else:
                candidate[field] = value
        with pytest.raises(ArtifactEvidenceError) as error:
            _normalize_payload_component(candidate, snapshot, entries, [], frozenset())
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
    snapshot, _artifact, payload_sbom = _fixture(tmp_path)
    snapshot = _add_embedded_python_runtime(snapshot, payload_sbom)
    component = next(
        item
        for item in payload_sbom["components"]
        if isinstance(item, dict) and item.get("name") == "python"
    )
    component["properties"] = properties
    entries = {entry.relative_path.as_posix(): entry for entry in snapshot.entries}
    with pytest.raises(ArtifactEvidenceError, match=error):
        _normalize_payload_component(component, snapshot, entries, [], frozenset())


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
    snapshot, _artifact, payload_sbom = _fixture(tmp_path)
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
    entries = {entry.relative_path.as_posix(): entry for entry in snapshot.entries}
    with pytest.raises(ArtifactEvidenceError, match="runtime component identity"):
        _normalize_payload_component(component, snapshot, entries, [], frozenset())


def test_malformed_pypi_purl_never_falls_back_to_runtime_identity(
    tmp_path: Path,
) -> None:
    snapshot, _artifact, payload_sbom = _fixture(tmp_path)
    component = next(
        item
        for item in payload_sbom["components"]
        if isinstance(item, dict) and item.get("purl") == "pkg:pypi/example@1.0"
    )
    component["purl"] = "pkg:pypi/example"
    entries = {entry.relative_path.as_posix(): entry for entry in snapshot.entries}
    with pytest.raises(ArtifactEvidenceError, match="Python component purl is invalid"):
        _normalize_payload_component(component, snapshot, entries, [], frozenset())


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

    result = generate_supply_chain_evidence(snapshot, artifact, evidence, workspace)
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


def test_payload_location_requires_snapshot_regular_file() -> None:
    properties = [
        {
            "name": "syft:location:0:path",
            "value": "/_internal/setuptools/_vendor/metadata/METADATA",
        }
    ]
    with pytest.raises(ArtifactEvidenceError, match="regular payload file"):
        _normalize_properties(
            properties,
            payload_root=Path("/payload"),
            snapshot_regular_files=frozenset(),
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


def _fixture(
    tmp_path: Path,
) -> tuple[PayloadSnapshot, ArtifactDescriptor, dict[str, object]]:
    target = load_target_spec(_TARGET_POLICY, "linux-x64-ubuntu-22.04")
    payload = tmp_path / "payload"
    metadata_file = payload / "_internal" / "example.dist-info" / "METADATA"
    metadata_file.parent.mkdir(parents=True)
    metadata_file.write_text("Name: example\n", encoding="utf-8")
    executable = payload / "servonaut"
    executable.write_bytes(b"executable")
    executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    wheel = tmp_path / "servonaut-1.2.3-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    wheel_sha = hashlib.sha256(wheel.read_bytes()).hexdigest()
    metadata = tmp_path / "build-metadata"
    resolved = metadata / "resolved"
    pyinstaller = metadata / "pyinstaller"
    resolved.mkdir(parents=True)
    pyinstaller.mkdir()
    warning = pyinstaller / "warn-servonaut.txt"
    warning.write_text("", encoding="utf-8")
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
                "hashes": ["sha256:" + "3" * 64],
            },
            {
                "name": "pyinstaller-hooks-contrib",
                "version": "2026.7",
                "hashes": ["sha256:" + "4" * 64],
            },
            {
                "name": "servonaut",
                "version": "1.2.3",
                "hashes": ["sha256:" + wheel_sha],
            },
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
            ("servonaut", "1.2.3"),
        )
    ]
    python_components = [
        _python_component("cyclonedx-bom", "7.3.1", "raw-cyclonedx"),
        _python_component("example", "1.0", "raw-example"),
        _python_component("pip", "25.0", "raw-pip"),
        _python_component("pyinstaller", "6.22.3", "raw-pyinstaller"),
        _python_component("pyinstaller-hooks-contrib", "2026.7", "raw-hooks"),
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
                PurePosixPath("servonaut"),
                "file",
                0o700,
                executable.stat().st_size,
                hashlib.sha256(executable.read_bytes()).hexdigest(),
                None,
            ),
        ),
        expanded_regular_bytes=metadata_file.stat().st_size + executable.stat().st_size,
        executable_relative_path=PurePosixPath("servonaut"),
        marker={"product_version": "1.2.3"},
        build_provenance=provenance,
        build_toolchain={
            "schema_version": 1,
            "python_implementation": "CPython",
            "python_version": "3.12.14",
            "spec_sha256": "5" * 64,
            "hooks_sha256": "6" * 64,
        },
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


def _python_component(name: str, version: str, reference: str) -> dict[str, object]:
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{name}@{version}",
        "bom-ref": reference,
        "licenses": [{"license": {"id": "MIT", "acknowledgement": "declared"}}],
    }
