"""Deterministic SBOM, dependency, and license evidence generation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from scripts.standalone_cli.artifact_filesystem import SnapshotPathResolver
from scripts.standalone_cli.artifact_types import (
    ArtifactDescriptor,
    ArtifactEvidenceError,
    PayloadSnapshot,
)
from scripts.standalone_cli.evidence_sanitize import (
    encode_public_json,
    load_bounded_json,
    write_public_json,
)
from scripts.standalone_cli.syft_tool import (
    SyftPolicy,
    acquire_syft,
    load_syft_policy,
    run_syft_scan,
)

_POLICY_ROOT = Path(__file__).resolve().parents[2] / "packaging" / "standalone_cli"
_SYFT_POLICY = _POLICY_ROOT / "syft-tools.json"
_NORMALIZATION_POLICY = _POLICY_ROOT / "sbom-normalization.json"
_NORMALIZATION_FIELDS = frozenset(
    {
        "schema_version",
        "allowed_http_reference_omissions",
        "allowed_parent_vendors",
    }
)
_HTTP_OMISSION_FIELDS = frozenset({"name", "version", "reference_type", "url_sha256"})
_PARENT_VENDOR_FIELDS = frozenset({"parent", "payload_prefix"})
_ENVIRONMENT_FIELDS = frozenset({"schema_version", "packages"})
_ENVIRONMENT_PACKAGE_FIELDS = frozenset({"name", "version", "hashes"})
_LICENSE_FIELDS = frozenset({"schema_version", "packages"})
_LICENSE_PACKAGE_FIELDS = frozenset(
    {
        "name",
        "version",
        "license",
        "license_expression",
        "license_classifiers",
        "license_files",
    }
)
_CYCLONEDX_FIELDS = frozenset(
    {
        "$schema",
        "bomFormat",
        "specVersion",
        "serialNumber",
        "version",
        "metadata",
        "components",
        "dependencies",
    }
)
_COMPONENT_FIELDS = frozenset(
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
        "group",
        "supplier",
        "author",
        "publisher",
        "cpe",
        "description",
        "evidence",
    }
)
_DEPENDENCY_FIELDS = frozenset({"ref", "dependsOn", "provides"})
_REFERENCE_FIELDS = frozenset({"type", "url", "comment", "hashes"})
_PROPERTY_FIELDS = frozenset({"name", "value"})
_HASH_FIELDS = frozenset({"alg", "content"})
_LICENSE_ENTRY_FIELDS = frozenset({"license", "expression", "acknowledgement"})
_LICENSE_VALUE_FIELDS = frozenset({"id", "name", "url", "acknowledgement"})
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
_RUNTIME_NOTICE_PAYLOAD_PATH = "_internal/notices/CPython-LICENSE.txt"
_CANONICAL_RUNTIME_LICENSE = {"license": {"id": "Python-2.0"}}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,255}$")
_REFERENCE_TYPE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_LOCATION_PROPERTY = re.compile(r"^syft:location:[0-9]+:path$")
_HASH_LENGTHS = {
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
class SupplyChainEvidence:
    """Public-safe supply-chain evidence written for one artifact."""

    payload_sbom: Path
    python_closure_sbom: Path
    dependency_provenance: Path
    sanitised_license_inventory: Path


@dataclass(frozen=True)
class _HttpReferenceOmission:
    name: str
    version: str
    reference_type: str
    url_sha256: str


@dataclass(frozen=True)
class _ParentVendor:
    parent: str
    payload_prefix: str


@dataclass(frozen=True)
class _NormalizationPolicy:
    http_reference_omissions: frozenset[_HttpReferenceOmission]
    parent_vendors: tuple[_ParentVendor, ...]


@dataclass(frozen=True)
class _VendoredPythonComponent:
    component: str
    version: str
    parent: str


@dataclass(frozen=True)
class _InstalledLicense:
    name: str
    version: str
    legacy_name: str | None
    expression: str | None
    classifiers: tuple[str, ...]
    files: tuple[str, ...]


def generate_supply_chain_evidence(
    snapshot: PayloadSnapshot,
    artifact: ArtifactDescriptor,
    evidence_dir: Path,
    tool_cache: Path,
    max_steps: int,
) -> SupplyChainEvidence:
    """Generate two reconciled SBOM scopes and public-safe provenance reports."""
    if not isinstance(snapshot, PayloadSnapshot):
        raise TypeError("snapshot must be a PayloadSnapshot")
    if not isinstance(artifact, ArtifactDescriptor):
        raise TypeError("artifact must be an ArtifactDescriptor")
    _runtime_notice_attestation(snapshot)
    evidence_root = _require_directory(evidence_dir, "evidence directory")
    workspace = _require_private_directory(tool_cache, "evidence workspace")
    syft_cache = _require_child_directory(workspace, "syft-cache")
    syft_config = _require_child_directory(workspace, "syft-config")
    policy = load_syft_policy(_SYFT_POLICY)
    executable = acquire_syft(_SYFT_POLICY, artifact.target, syft_cache)
    product_version = _provenance_string(snapshot, "product_version")
    raw_payload_sbom = syft_config / "raw-payload-sbom.cdx.json"
    run_syft_scan(
        executable,
        policy,
        artifact.target,
        snapshot.root,
        product_version,
        raw_payload_sbom,
        syft_config,
    )
    raw_payload = load_bounded_json(
        raw_payload_sbom, "raw payload SBOM", policy.max_sbom_bytes
    )
    resolved = _resolved_metadata_root(artifact)
    environment = _load_environment(resolved / "environment.json", policy)
    installed_licenses = _load_installed_licenses(resolved / "licenses.json", policy)
    raw_python = load_bounded_json(
        resolved / "sbom-python.cdx.json",
        "raw Python closure SBOM",
        policy.max_sbom_bytes,
    )
    normalization_policy = _load_normalization_policy(_NORMALIZATION_POLICY, policy)
    wheel_sha256 = _validate_wheel_provenance(snapshot, artifact, environment)
    qualification_facts: list[dict[str, object]] = []
    payload_document, payload_python, payload_vendored, payload_other = (
        _normalize_payload_sbom(
            raw_payload,
            snapshot,
            product_version,
            frozenset(installed_licenses),
            qualification_facts,
            normalization_policy,
            max_steps,
        )
    )
    closure_document, closure_components, license_ids = _normalize_python_sbom(
        raw_python,
        environment,
        installed_licenses,
        artifact,
        product_version,
        wheel_sha256,
        qualification_facts,
        normalization_policy.http_reference_omissions,
    )
    provenance_document = _dependency_provenance(
        snapshot,
        artifact,
        policy,
        environment,
        installed_licenses,
        closure_components,
        payload_python,
        payload_vendored,
        payload_other,
        qualification_facts,
    )
    license_document = _license_inventory(installed_licenses, license_ids)
    documents = {
        "sbom-payload.cdx.json": payload_document,
        "sbom-python-closure.cdx.json": closure_document,
        "dependency-provenance.json": provenance_document,
        "licenses.json": license_document,
    }
    forbidden_roots = (
        snapshot.root,
        artifact.build_metadata_dir,
        artifact.wheel.parent,
        workspace,
    )
    for name, document in documents.items():
        encode_public_json(
            document,
            name,
            forbidden_roots=forbidden_roots,
            max_bytes=policy.max_sbom_bytes,
        )
    paths = {name: evidence_root / name for name in documents}
    if any(path.exists() or path.is_symlink() for path in paths.values()):
        raise ArtifactEvidenceError("supply-chain evidence output already exists")
    written: list[tuple[Path, tuple[int, int]]] = []
    try:
        for name, document in documents.items():
            write_public_json(
                paths[name],
                document,
                forbidden_roots=forbidden_roots,
                max_bytes=policy.max_sbom_bytes,
                ownership_ledger=written,
            )
    except BaseException:
        for path, identity in reversed(written):
            _remove_owned_file(path, identity)
        raise
    return SupplyChainEvidence(
        payload_sbom=paths["sbom-payload.cdx.json"],
        python_closure_sbom=paths["sbom-python-closure.cdx.json"],
        dependency_provenance=paths["dependency-provenance.json"],
        sanitised_license_inventory=paths["licenses.json"],
    )


def _normalize_payload_sbom(
    raw: object,
    snapshot: PayloadSnapshot,
    product_version: str,
    closure_names: frozenset[str],
    qualification_facts: list[dict[str, object]],
    policy: _NormalizationPolicy,
    max_steps: int,
) -> tuple[
    dict[str, object],
    dict[str, str],
    tuple[_VendoredPythonComponent, ...],
    list[dict[str, object]],
]:
    document = _cyclonedx_document(raw, "payload SBOM")
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        raise ArtifactEvidenceError("payload SBOM metadata is invalid")
    raw_root = metadata.get("component")
    if not isinstance(raw_root, dict):
        raise ArtifactEvidenceError("payload SBOM root component is missing")
    raw_root_ref = _component_ref(raw_root, "payload SBOM root")
    root_name = raw_root.get("name")
    if root_name not in {"servonaut", str(snapshot.root)}:
        raise ArtifactEvidenceError("payload SBOM root does not match the payload")
    root_ref = f"urn:servonaut:payload:{_sha256_text(product_version)}"
    raw_components = document.get("components")
    if not isinstance(raw_components, list):
        raise ArtifactEvidenceError("payload SBOM components are invalid")
    resolver = SnapshotPathResolver(snapshot.entries, max_steps)
    snapshot_regular_files = frozenset(
        entry.relative_path.as_posix()
        for entry in snapshot.entries
        if entry.kind == "file"
    )
    references = {raw_root_ref: root_ref}
    components: list[dict[str, object]] = []
    payload_python: dict[str, str] = {}
    payload_vendored: dict[str, _VendoredPythonComponent] = {}
    payload_other: list[dict[str, object]] = []
    new_refs = {root_ref}
    for raw_component in raw_components:
        component, old_ref = _normalize_payload_component(
            raw_component,
            snapshot,
            resolver,
            snapshot_regular_files,
            qualification_facts,
            policy.http_reference_omissions,
        )
        new_ref = _required_string(component.get("bom-ref"), "component reference")
        if old_ref in references or new_ref in new_refs:
            raise ArtifactEvidenceError("payload SBOM component identity is duplicated")
        references[old_ref] = new_ref
        new_refs.add(new_ref)
        components.append(component)
        pypi = _pypi_identity(component)
        if pypi is not None:
            name, version = pypi
            if name in closure_names:
                previous = payload_python.get(name)
                if previous is not None and previous != version:
                    raise ArtifactEvidenceError(
                        "payload Python package versions conflict"
                    )
                payload_python[name] = version
                continue
            vendored = _vendored_python_component(component, policy.parent_vendors)
            previous_vendored = payload_vendored.get(name)
            if previous_vendored is not None and previous_vendored != vendored:
                raise ArtifactEvidenceError(
                    "payload vendored Python package versions conflict"
                )
            payload_vendored[name] = vendored
        else:
            payload_other.append(
                {
                    "component": _required_string(
                        component.get("name"), "component name"
                    ),
                    "type": _required_string(component.get("type"), "component type"),
                    "version": component.get("version"),
                }
            )
    dependencies = _normalize_dependencies(
        document.get("dependencies", []), references, "payload SBOM"
    )
    output = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "servonaut",
                "version": product_version,
                "bom-ref": root_ref,
            },
            "properties": [
                {
                    "name": "servonaut:evidence:scope",
                    "value": "frozen-payload-filesystem",
                }
            ],
        },
        "components": sorted(components, key=_component_sort_key),
        "dependencies": dependencies,
    }
    return (
        output,
        payload_python,
        tuple(
            sorted(
                payload_vendored.values(),
                key=lambda item: (item.parent, item.component, item.version),
            )
        ),
        sorted(
            payload_other,
            key=lambda item: (
                str(item["type"]),
                str(item["component"]),
                str(item["version"] or ""),
            ),
        ),
    )


def _vendored_python_component(
    component: Mapping[str, object], vendors: tuple[_ParentVendor, ...]
) -> _VendoredPythonComponent:
    identity = _pypi_identity(component)
    if identity is None or component.get("type") != "library":
        raise ArtifactEvidenceError("payload vendored Python component is invalid")
    properties = component.get("properties")
    if not isinstance(properties, list):
        raise ArtifactEvidenceError("payload vendored Python component has no location")
    locations = [
        item["value"]
        for item in properties
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and _LOCATION_PROPERTY.fullmatch(item["name"])
        and isinstance(item.get("value"), str)
    ]
    if not locations or len(locations) != len(set(locations)):
        raise ArtifactEvidenceError("payload vendored Python locations are invalid")
    name, version = identity
    distribution_dir = f"{name.replace('-', '_')}-{version}.dist-info"
    matches: list[_ParentVendor] = []
    for vendor in vendors:
        expected_root = PurePosixPath(vendor.payload_prefix, distribution_dir)
        if all(
            PurePosixPath(location) != expected_root
            and PurePosixPath(location).is_relative_to(expected_root)
            for location in locations
        ):
            matches.append(vendor)
    if len(matches) != 1:
        raise ArtifactEvidenceError(
            "payload Python component is not in the closure or a reviewed vendor"
        )
    return _VendoredPythonComponent(name, version, matches[0].parent)


def _normalize_payload_component(
    raw: object,
    snapshot: PayloadSnapshot,
    resolver: SnapshotPathResolver,
    snapshot_regular_files: frozenset[str],
    qualification_facts: list[dict[str, object]],
    omissions: frozenset[_HttpReferenceOmission],
) -> tuple[dict[str, object], str]:
    component = _component(raw, "payload SBOM component")
    old_ref = _component_ref(component, "payload SBOM component")
    component_type = _required_string(component.get("type"), "component type")
    name = _required_string(component.get("name"), "component name")
    version = _optional_string(component.get("version"), "component version")
    hashes = _normalize_hashes(component.get("hashes", []), "component hashes")
    if component_type == "file":
        relative_name = _payload_relative_path(name, snapshot.root)
        relative_name, expected_sha256 = _snapshot_content_sha256(
            relative_name, resolver
        )
        observed_sha256 = _hash_value(hashes, "SHA-256")
        if observed_sha256 != expected_sha256:
            raise ArtifactEvidenceError(
                "payload SBOM file hash does not match snapshot"
            )
        new_ref = f"urn:servonaut:file:{_sha256_text(relative_name)}"
        output: dict[str, object] = {
            "type": "file",
            "name": relative_name,
            "bom-ref": new_ref,
            "hashes": hashes,
        }
        return output, old_ref
    purl = _optional_string(component.get("purl"), "component purl")
    if purl is not None:
        if version is None:
            raise ArtifactEvidenceError("Python payload component version is missing")
        if purl.startswith("pkg:pypi/"):
            purl_name, purl_version = _parse_pypi_purl(purl)
            canonical_name = _canonicalize_name(name)
            if (purl_name, purl_version) != (canonical_name, version):
                raise ArtifactEvidenceError(
                    "payload component purl conflicts with package identity"
                )
            name = canonical_name
            purl = _pypi_purl(name, version)
        elif purl.startswith("pkg:generic"):
            purl = _embedded_python_runtime_purl(
                component_type, name, version, purl, snapshot
            )
        else:
            _validate_purl(purl)
            raise ArtifactEvidenceError("payload component purl type is unsupported")
        new_ref = purl
    else:
        if component_type == "application" and name == "python":
            raise ArtifactEvidenceError(
                "embedded Python runtime component identity is invalid"
            )
        new_ref = "urn:servonaut:component:" + _sha256_text(
            "\0".join((component_type, name, version or ""))
        )
    output = {
        "type": component_type,
        "name": name,
        "bom-ref": new_ref,
    }
    if version is not None:
        output["version"] = version
    if purl is not None:
        output["purl"] = purl
    if hashes:
        output["hashes"] = hashes
    if purl is not None and purl.startswith("pkg:generic/"):
        licenses = _normalize_embedded_runtime_licenses(
            component.get("licenses", []), snapshot
        )
    else:
        licenses = _normalize_licenses(component.get("licenses", []))
    if licenses:
        output["licenses"] = licenses
    properties = _normalize_properties(
        component.get("properties", []),
        payload_root=snapshot.root,
        snapshot_regular_files=snapshot_regular_files,
        payload_resolver=resolver,
    )
    if purl is not None and purl.startswith("pkg:generic/"):
        _validate_embedded_python_runtime_properties(properties, version)
    if properties:
        output["properties"] = properties
    references = _normalize_external_references(
        component.get("externalReferences", []),
        _canonicalize_name(name),
        version or "0",
        qualification_facts,
        omissions,
        local_wheel=None,
    )
    if references:
        output["externalReferences"] = references
    return output, old_ref


def _embedded_python_runtime_purl(
    component_type: str,
    name: str,
    version: str,
    purl: str,
    snapshot: PayloadSnapshot,
) -> str:
    """Validate the exact embedded CPython identity emitted on Ubuntu 22."""
    _validate_purl(purl)
    toolchain = snapshot.build_toolchain
    provenance = snapshot.build_provenance
    if (
        component_type != "application"
        or name != "python"
        or toolchain.get("python_implementation") != "CPython"
        or toolchain.get("python_version") != version
        or provenance.get("target") != "linux-x64-ubuntu-22.04"
        or purl != f"pkg:generic/python@{version}"
    ):
        raise ArtifactEvidenceError(
            "embedded Python runtime component identity is invalid"
        )
    return purl


def _validate_embedded_python_runtime_properties(
    properties: list[dict[str, str]], version: str
) -> None:
    package_types = [
        item["value"] for item in properties if item["name"] == "syft:package:type"
    ]
    locations = [
        item["value"]
        for item in properties
        if _LOCATION_PROPERTY.fullmatch(item["name"])
    ]
    major_minor = ".".join(version.split(".")[:2])
    if package_types != ["binary"] or locations != [
        f"_internal/libpython{major_minor}.so.1.0"
    ]:
        raise ArtifactEvidenceError(
            "embedded Python runtime component properties are invalid"
        )


def _normalize_embedded_runtime_licenses(
    raw: object, snapshot: PayloadSnapshot
) -> list[dict[str, object]]:
    """Accept only the attested runtime's exact canonical license claim."""
    _runtime_notice_attestation(snapshot)
    if raw == [] or raw == [_CANONICAL_RUNTIME_LICENSE]:
        return [{"license": {"id": "Python-2.0"}}]
    raise ArtifactEvidenceError("embedded Python runtime license claim is invalid")


def _snapshot_content_sha256(
    relative_name: str, resolver: SnapshotPathResolver
) -> tuple[str, str]:
    resolved = resolver.resolve_entry(PurePosixPath(relative_name))
    if resolved.entry.kind != "file" or resolved.entry.sha256 is None:
        raise ArtifactEvidenceError("payload SBOM component is not a file")
    return resolved.relative_path.as_posix(), resolved.entry.sha256


def _normalize_python_sbom(
    raw: object,
    environment: Mapping[str, dict[str, object]],
    installed_licenses: Mapping[str, _InstalledLicense],
    artifact: ArtifactDescriptor,
    product_version: str,
    wheel_sha256: str,
    qualification_facts: list[dict[str, object]],
    omissions: frozenset[_HttpReferenceOmission],
) -> tuple[dict[str, object], dict[str, str], Mapping[str, frozenset[str]]]:
    document = _cyclonedx_document(raw, "Python closure SBOM")
    raw_components = document.get("components")
    if not isinstance(raw_components, list):
        raise ArtifactEvidenceError("Python closure SBOM components are invalid")
    raw_by_name: dict[str, dict[str, object]] = {}
    for raw_component in raw_components:
        component = _component(raw_component, "Python closure component")
        name = _canonicalize_name(
            _required_string(component.get("name"), "Python component name")
        )
        if name in raw_by_name:
            raise ArtifactEvidenceError("Python closure package is duplicated")
        raw_by_name[name] = component
    expected_names = set(installed_licenses)
    if set(raw_by_name) != expected_names:
        raise ArtifactEvidenceError(
            "Python SBOM and installed license inventory conflict"
        )
    if set(environment) - expected_names:
        raise ArtifactEvidenceError("Python environment is missing license metadata")
    components: list[dict[str, object]] = []
    references: dict[str, str] = {}
    closure_versions: dict[str, str] = {}
    license_ids: dict[str, frozenset[str]] = {}
    for name in sorted(raw_by_name):
        raw_component = raw_by_name[name]
        installed = installed_licenses[name]
        version = _required_string(raw_component.get("version"), "Python version")
        if version != installed.version:
            raise ArtifactEvidenceError("Python package versions conflict")
        environment_record = environment.get(name)
        if environment_record is None:
            if name != "pip":
                raise ArtifactEvidenceError("Python package lacks archive provenance")
            hashes: list[dict[str, str]] = []
            provenance_source = "venv-bootstrap"
        else:
            if environment_record["version"] != version:
                raise ArtifactEvidenceError("Python package versions conflict")
            hashes = [
                {"alg": "SHA-256", "content": digest.removeprefix("sha256:")}
                for digest in environment_record["hashes"]
            ]
            provenance_source = "pip-report-sha256"
        expected_purl = _pypi_purl(name, version)
        raw_purl = _optional_string(raw_component.get("purl"), "Python component purl")
        if raw_purl is not None and _parse_pypi_purl(raw_purl) != (name, version):
            raise ArtifactEvidenceError(
                "Python component purl conflicts with package identity"
            )
        old_ref = _component_ref(raw_component, "Python closure component")
        if old_ref in references or expected_purl in references.values():
            raise ArtifactEvidenceError("Python component reference is duplicated")
        references[old_ref] = expected_purl
        raw_licenses = _normalize_licenses(raw_component.get("licenses", []))
        combined_licenses = _merge_license_claims(raw_licenses, installed)
        ids = frozenset(
            license_value["id"]
            for entry in combined_licenses
            if isinstance(entry.get("license"), dict)
            for license_value in [entry["license"]]
            if isinstance(license_value.get("id"), str)
        )
        license_ids[name] = ids
        properties = _normalize_properties(raw_component.get("properties", []))
        properties.append(
            {
                "name": "servonaut:evidence:provenance-source",
                "value": provenance_source,
            }
        )
        for classifier in installed.classifiers:
            properties.append(
                {
                    "name": "servonaut:evidence:license-classifier",
                    "value": classifier,
                }
            )
        for filename in installed.files:
            properties.append(
                {
                    "name": "servonaut:evidence:license-file",
                    "value": filename,
                }
            )
        local_wheel = None
        if name == "servonaut":
            if version != product_version or not hashes:
                raise ArtifactEvidenceError("Servonaut closure identity is invalid")
            if _hash_value(hashes, "SHA-256") != wheel_sha256:
                raise ArtifactEvidenceError("Servonaut wheel provenance conflicts")
            local_wheel = (artifact.wheel, wheel_sha256)
        external_references = _normalize_external_references(
            raw_component.get("externalReferences", []),
            name,
            version,
            qualification_facts,
            omissions,
            local_wheel=local_wheel,
        )
        component: dict[str, object] = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": expected_purl,
            "bom-ref": expected_purl,
            "properties": _unique_sorted(properties),
        }
        if hashes:
            component["hashes"] = sorted(hashes, key=lambda item: item["content"])
        if combined_licenses:
            component["licenses"] = combined_licenses
        if external_references:
            component["externalReferences"] = external_references
        components.append(component)
        closure_versions[name] = version
    dependencies = _normalize_dependencies(
        document.get("dependencies", []), references, "Python closure SBOM"
    )
    output = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "properties": [
                {
                    "name": "servonaut:evidence:scope",
                    "value": "isolated-build-input-closure",
                }
            ]
        },
        "components": sorted(components, key=_component_sort_key),
        "dependencies": dependencies,
    }
    return output, closure_versions, license_ids


def _dependency_provenance(
    snapshot: PayloadSnapshot,
    artifact: ArtifactDescriptor,
    policy: SyftPolicy,
    environment: Mapping[str, dict[str, object]],
    installed_licenses: Mapping[str, _InstalledLicense],
    closure: Mapping[str, str],
    payload_python: Mapping[str, str],
    payload_vendored: tuple[_VendoredPythonComponent, ...],
    payload_other: list[dict[str, object]],
    qualification_facts: list[dict[str, object]],
) -> dict[str, object]:
    runtime_notice = _runtime_notice_attestation(snapshot)
    if set(closure) != set(installed_licenses):
        raise ArtifactEvidenceError("Python closure inventories conflict")
    if set(environment) - set(closure):
        raise ArtifactEvidenceError("Python environment is not in the closure")
    for name, version in payload_python.items():
        if name not in closure:
            raise ArtifactEvidenceError(
                "payload Python component is not in the closure"
            )
        if closure[name] != version:
            raise ArtifactEvidenceError("payload and closure package versions conflict")
    vendored_components: list[dict[str, str]] = []
    vendored_identities: set[tuple[str, str, str]] = set()
    for relation in payload_vendored:
        if relation.component in closure or relation.parent == relation.component:
            raise ArtifactEvidenceError(
                "payload vendored Python relationship conflicts"
            )
        identity = (relation.parent, relation.component, relation.version)
        if identity in vendored_identities:
            raise ArtifactEvidenceError(
                "payload vendored Python relationship is duplicated"
            )
        vendored_identities.add(identity)
        parent_version = closure.get(relation.parent)
        if parent_version is None:
            raise ArtifactEvidenceError(
                "payload vendored Python parent is not in the closure"
            )
        vendored_components.append(
            {
                "component": relation.component,
                "version": relation.version,
                "parent": relation.parent,
                "parent_version": parent_version,
                "origin": "parent-vendor-dist-info",
            }
        )
    vendored_components.sort(
        key=lambda item: (item["parent"], item["component"], item["version"])
    )
    if "servonaut" not in closure:
        raise ArtifactEvidenceError("Servonaut is missing from the Python closure")
    bootstrap = (
        [{"component": "pip", "version": closure["pip"], "source": "venv-bootstrap"}]
        if "pip" in closure and "pip" not in environment
        else []
    )
    closure_only = [
        {"component": name, "version": closure[name]}
        for name in sorted(set(closure) - set(payload_python))
    ]
    payload_components = [
        {"component": name, "version": payload_python[name]}
        for name in sorted(payload_python)
    ]
    return {
        "schema_version": 1,
        "scope": "resolved-python-and-payload-reconciliation",
        "build": _build_provenance(snapshot, artifact),
        "toolchain": _toolchain_provenance(snapshot, artifact, policy, environment),
        "runtime_notice": runtime_notice,
        "payload_python_components": payload_components,
        "payload_vendored_python_components": vendored_components,
        "closure_only_components": closure_only,
        "payload_additional_components": payload_other,
        "bootstrap_exceptions": bootstrap,
        "qualification_facts": _unique_sorted(qualification_facts),
        "unresolved_conflicts": [],
    }


def _build_provenance(
    snapshot: PayloadSnapshot, artifact: ArtifactDescriptor
) -> dict[str, object]:
    raw = snapshot.build_provenance
    fields = {
        "schema_version",
        "source_commit",
        "target",
        "product_version",
        "build_revision",
        "wheel_sha256",
    }
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise ArtifactEvidenceError("build provenance fields are invalid")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ArtifactEvidenceError("build provenance version is unsupported")
    result: dict[str, object] = {"schema_version": 1}
    for field in fields - {"schema_version"}:
        result[field] = _required_string(raw[field], "build provenance")
    if result["target"] != artifact.target.name:
        raise ArtifactEvidenceError("build provenance target conflicts")
    result["wheel_sha256"] = _validate_digest(
        result["wheel_sha256"], "build provenance wheel"
    )
    return result


def _toolchain_provenance(
    snapshot: PayloadSnapshot,
    artifact: ArtifactDescriptor,
    policy: SyftPolicy,
    environment: Mapping[str, dict[str, object]],
) -> dict[str, object]:
    raw = snapshot.build_toolchain
    fields = {
        "schema_version",
        "python_implementation",
        "python_version",
        "spec_sha256",
        "hooks_sha256",
    }
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise ArtifactEvidenceError("build toolchain fields are invalid")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ArtifactEvidenceError("build toolchain version is unsupported")
    implementation = _required_string(
        raw["python_implementation"], "Python implementation"
    )
    python_version = _required_string(raw["python_version"], "Python version")
    if implementation != "CPython" or not re.fullmatch(
        r"3\.12\.[0-9]+", python_version
    ):
        raise ArtifactEvidenceError("build Python identity is invalid")
    target_tool = policy.targets.get(artifact.target.name)
    if target_tool is None:
        raise ArtifactEvidenceError("Syft target is unsupported")
    return {
        "python_implementation": implementation,
        "python_version": python_version,
        "spec_sha256": _validate_digest(raw["spec_sha256"], "spec profile"),
        "hooks_sha256": _validate_digest(raw["hooks_sha256"], "hooks profile"),
        "pyinstaller_version": _inventory_version(environment, "pyinstaller"),
        "pyinstaller_hooks_version": _inventory_version(
            environment, "pyinstaller-hooks-contrib"
        ),
        "cyclonedx_bom_version": _inventory_version(environment, "cyclonedx-bom"),
        "syft_version": policy.version,
        "syft_asset_sha256": target_tool.sha256,
    }


def _runtime_notice_attestation(snapshot: PayloadSnapshot) -> dict[str, object]:
    """Return the exact runtime notice record bound by the payload snapshot."""
    raw = snapshot.runtime_notice
    if not isinstance(raw, Mapping) or set(raw) != _RUNTIME_NOTICE_FIELDS:
        raise ArtifactEvidenceError("runtime notice attestation is invalid")
    if (
        type(raw.get("schema_version")) is not int
        or raw.get("schema_version") != 1
        or raw.get("runtime") != "cpython"
        or raw.get("python_implementation") != "CPython"
        or raw.get("license_id") != "Python-2.0"
        or raw.get("payload_path") != _RUNTIME_NOTICE_PAYLOAD_PATH
    ):
        raise ArtifactEvidenceError("runtime notice attestation is invalid")
    python_version = _required_string(
        raw.get("python_version"), "runtime notice Python version"
    )
    toolchain = snapshot.build_toolchain
    if (
        not re.fullmatch(r"3\.12\.[0-9]+", python_version)
        or raw.get("python_implementation") != toolchain.get("python_implementation")
        or python_version != toolchain.get("python_version")
    ):
        raise ArtifactEvidenceError("runtime notice attestation is invalid")
    digest = raw.get("sha256")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ArtifactEvidenceError("runtime notice attestation is invalid")
    return {
        "schema_version": 1,
        "runtime": "cpython",
        "python_implementation": "CPython",
        "python_version": python_version,
        "license_id": "Python-2.0",
        "payload_path": _RUNTIME_NOTICE_PAYLOAD_PATH,
        "sha256": digest,
    }


def _inventory_version(environment: Mapping[str, dict[str, object]], name: str) -> str:
    package = environment.get(name)
    if package is None:
        raise ArtifactEvidenceError("required build tool is missing from inventory")
    return _version(package.get("version"))


def _license_inventory(
    installed: Mapping[str, _InstalledLicense],
    license_ids: Mapping[str, frozenset[str]],
) -> dict[str, object]:
    packages: list[dict[str, object]] = []
    qualifications: list[dict[str, object]] = []
    for name in sorted(installed):
        record = installed[name]
        ids = sorted(license_ids.get(name, frozenset()))
        packages.append(
            {
                "name": name,
                "version": record.version,
                "license_ids": ids,
                "license_classifiers": list(record.classifiers),
                "provenance": "installed-distribution-metadata",
            }
        )
        has_claim = bool(
            ids or record.classifiers or record.expression or record.legacy_name
        )
        if not has_claim:
            qualifications.append(
                {
                    "code": "unknown-license-metadata",
                    "component": name,
                    "version": record.version,
                    "source": "installed-distribution-metadata",
                }
            )
        elif not (ids or record.classifiers or record.expression):
            qualifications.append(
                {
                    "code": "unstructured-license-metadata",
                    "component": name,
                    "version": record.version,
                    "source": "installed-distribution-metadata",
                }
            )
    return {
        "schema_version": 1,
        "scope": "isolated-build-environment-license-claims",
        "packages": packages,
        "qualifications": qualifications,
    }


def _load_environment(path: Path, policy: SyftPolicy) -> dict[str, dict[str, object]]:
    raw = load_bounded_json(path, "Python environment inventory", policy.max_sbom_bytes)
    if not isinstance(raw, dict) or set(raw) != _ENVIRONMENT_FIELDS:
        raise ArtifactEvidenceError("Python environment inventory fields are invalid")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ArtifactEvidenceError(
            "Python environment inventory version is unsupported"
        )
    packages = raw["packages"]
    if not isinstance(packages, list):
        raise ArtifactEvidenceError("Python environment packages are invalid")
    result: dict[str, dict[str, object]] = {}
    for item in packages:
        if not isinstance(item, dict) or set(item) != _ENVIRONMENT_PACKAGE_FIELDS:
            raise ArtifactEvidenceError("Python environment package fields are invalid")
        name = _canonicalize_name(item["name"])
        version = _version(item["version"])
        hashes = item["hashes"]
        if not isinstance(hashes, list) or not hashes:
            raise ArtifactEvidenceError("Python package archive provenance is missing")
        normalized_hashes: list[str] = []
        for digest in hashes:
            if (
                not isinstance(digest, str)
                or not digest.startswith("sha256:")
                or not _SHA256.fullmatch(digest[7:])
            ):
                raise ArtifactEvidenceError(
                    "Python package archive checksum is invalid"
                )
            normalized_hashes.append(digest)
        if len(set(normalized_hashes)) != len(normalized_hashes) or name in result:
            raise ArtifactEvidenceError("Python environment package is duplicated")
        result[name] = {
            "version": version,
            "hashes": tuple(sorted(normalized_hashes)),
        }
    return result


def _load_installed_licenses(
    path: Path, policy: SyftPolicy
) -> dict[str, _InstalledLicense]:
    raw = load_bounded_json(path, "installed license inventory", policy.max_sbom_bytes)
    if not isinstance(raw, dict) or set(raw) != _LICENSE_FIELDS:
        raise ArtifactEvidenceError("installed license inventory fields are invalid")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ArtifactEvidenceError(
            "installed license inventory version is unsupported"
        )
    packages = raw["packages"]
    if not isinstance(packages, list):
        raise ArtifactEvidenceError("installed license packages are invalid")
    result: dict[str, _InstalledLicense] = {}
    for item in packages:
        if not isinstance(item, dict) or set(item) != _LICENSE_PACKAGE_FIELDS:
            raise ArtifactEvidenceError("installed license package fields are invalid")
        name = _canonicalize_name(item["name"])
        if name in result:
            raise ArtifactEvidenceError("installed license package is duplicated")
        version = _version(item["version"])
        legacy_name = _nullable_string(item["license"], "legacy license")
        expression = _nullable_string(item["license_expression"], "license expression")
        classifiers = _string_tuple(item["license_classifiers"], "license classifiers")
        files = _license_files(item["license_files"])
        result[name] = _InstalledLicense(
            name=name,
            version=version,
            legacy_name=legacy_name,
            expression=expression,
            classifiers=classifiers,
            files=files,
        )
    return result


def _load_normalization_policy(
    path: Path, syft_policy: SyftPolicy
) -> _NormalizationPolicy:
    raw = load_bounded_json(
        path.resolve(), "SBOM normalization policy", syft_policy.max_sbom_bytes
    )
    if not isinstance(raw, dict) or set(raw) != _NORMALIZATION_FIELDS:
        raise ArtifactEvidenceError("SBOM normalization policy fields are invalid")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ArtifactEvidenceError("SBOM normalization policy version is unsupported")
    omission_rows = raw["allowed_http_reference_omissions"]
    if (
        not isinstance(omission_rows, list)
        or not omission_rows
        or len(omission_rows) > 16
    ):
        raise ArtifactEvidenceError("SBOM normalization policy rows are invalid")
    omissions: set[_HttpReferenceOmission] = set()
    previous: tuple[str, str, str, str] | None = None
    for row in omission_rows:
        if not isinstance(row, dict) or set(row) != _HTTP_OMISSION_FIELDS:
            raise ArtifactEvidenceError("SBOM normalization policy row is invalid")
        name = _canonicalize_name(row["name"])
        version = _version(row["version"])
        reference_type = _reference_type(row["reference_type"])
        url_sha256 = _required_string(row["url_sha256"], "URL checksum")
        if not _SHA256.fullmatch(url_sha256):
            raise ArtifactEvidenceError("SBOM normalization URL checksum is invalid")
        current = (name, version, reference_type, url_sha256)
        if previous is not None and current <= previous:
            raise ArtifactEvidenceError(
                "SBOM normalization rows are not sorted and unique"
            )
        previous = current
        omissions.add(_HttpReferenceOmission(*current))
    vendor_rows = raw["allowed_parent_vendors"]
    if not isinstance(vendor_rows, list) or not vendor_rows or len(vendor_rows) > 16:
        raise ArtifactEvidenceError("SBOM parent vendor policy rows are invalid")
    vendors: list[_ParentVendor] = []
    previous_vendor: tuple[str, str] | None = None
    for row in vendor_rows:
        if not isinstance(row, dict) or set(row) != _PARENT_VENDOR_FIELDS:
            raise ArtifactEvidenceError("SBOM parent vendor policy row is invalid")
        parent = _canonicalize_name(row["parent"])
        payload_prefix = _parent_vendor_prefix(row["payload_prefix"])
        current_vendor = (parent, payload_prefix)
        if previous_vendor is not None and current_vendor <= previous_vendor:
            raise ArtifactEvidenceError(
                "SBOM parent vendor rows are not sorted and unique"
            )
        previous_vendor = current_vendor
        vendors.append(_ParentVendor(*current_vendor))
    return _NormalizationPolicy(frozenset(omissions), tuple(vendors))


def _parent_vendor_prefix(value: object) -> str:
    prefix = _required_string(value, "parent vendor payload prefix")
    path = PurePosixPath(prefix)
    if (
        len(prefix) > 512
        or path.is_absolute()
        or path.as_posix() != prefix
        or len(path.parts) < 2
        or any(part in {"", ".", ".."} or ":" in part for part in path.parts)
        or "\\" in prefix
    ):
        raise ArtifactEvidenceError("parent vendor payload prefix is invalid")
    return prefix


def _cyclonedx_document(raw: object, label: str) -> dict[str, object]:
    if not isinstance(raw, dict) or not set(raw) <= _CYCLONEDX_FIELDS:
        raise ArtifactEvidenceError(f"{label} fields are invalid")
    if raw.get("bomFormat") != "CycloneDX" or raw.get("specVersion") not in {
        "1.6",
        "1.7",
    }:
        raise ArtifactEvidenceError(f"{label} format is unsupported")
    if type(raw.get("version")) is not int or raw["version"] < 1:
        raise ArtifactEvidenceError(f"{label} version is invalid")
    return raw


def _component(raw: object, label: str) -> dict[str, object]:
    if not isinstance(raw, dict) or not set(raw) <= _COMPONENT_FIELDS:
        raise ArtifactEvidenceError(f"{label} fields are invalid")
    return raw


def _component_ref(component: Mapping[str, object], label: str) -> str:
    return _required_string(component.get("bom-ref"), f"{label} reference")


def _normalize_hashes(raw: object, label: str) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        raise ArtifactEvidenceError(f"{label} are invalid")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in raw:
        if not isinstance(item, dict) or set(item) != _HASH_FIELDS:
            raise ArtifactEvidenceError(f"{label} are invalid")
        algorithm = _required_string(item["alg"], "hash algorithm")
        content = _required_string(item["content"], "hash content").casefold()
        expected_length = _HASH_LENGTHS.get(algorithm)
        if (
            expected_length is None
            or len(content) != expected_length
            or not re.fullmatch(r"[0-9a-f]+", content)
        ):
            raise ArtifactEvidenceError(f"{label} are invalid")
        identity = (algorithm, content)
        if identity in seen:
            raise ArtifactEvidenceError(f"{label} contain duplicates")
        seen.add(identity)
        result.append({"alg": algorithm, "content": content})
    return sorted(result, key=lambda item: (item["alg"], item["content"]))


def _normalize_licenses(raw: object) -> list[dict[str, object]]:
    if not isinstance(raw, list):
        raise ArtifactEvidenceError("component licenses are invalid")
    result: list[dict[str, object]] = []
    for item in raw:
        if not isinstance(item, dict) or not set(item) <= _LICENSE_ENTRY_FIELDS:
            raise ArtifactEvidenceError("component license entry is invalid")
        acknowledgement = item.get("acknowledgement")
        if acknowledgement is not None and acknowledgement not in {
            "declared",
            "concluded",
        }:
            raise ArtifactEvidenceError("component license acknowledgement is invalid")
        if "expression" in item:
            if "license" in item:
                raise ArtifactEvidenceError("component license entry is ambiguous")
            entry: dict[str, object] = {
                "expression": _required_string(item["expression"], "license expression")
            }
        else:
            license_value = item.get("license")
            if (
                not isinstance(license_value, dict)
                or not set(license_value) <= _LICENSE_VALUE_FIELDS
            ):
                raise ArtifactEvidenceError("component license value is invalid")
            normalized: dict[str, str] = {}
            for field in ("id", "name"):
                if field in license_value:
                    normalized[field] = _required_string(
                        license_value[field], f"license {field}"
                    )
            if "url" in license_value:
                normalized["url"] = _required_string(
                    license_value["url"], "license URL"
                )
            inner_acknowledgement = license_value.get("acknowledgement")
            if inner_acknowledgement is not None:
                if inner_acknowledgement not in {"declared", "concluded"}:
                    raise ArtifactEvidenceError(
                        "component license acknowledgement is invalid"
                    )
                normalized["acknowledgement"] = inner_acknowledgement
            if not normalized:
                raise ArtifactEvidenceError("component license value is empty")
            entry = {"license": normalized}
        if acknowledgement is not None:
            entry["acknowledgement"] = acknowledgement
        result.append(entry)
    return _unique_sorted(result)


def _merge_license_claims(
    raw_licenses: list[dict[str, object]], installed: _InstalledLicense
) -> list[dict[str, object]]:
    claims = list(raw_licenses)
    if installed.expression:
        claims.append(
            {"expression": installed.expression, "acknowledgement": "declared"}
        )
    if installed.legacy_name:
        claims.append(
            {
                "license": {"name": installed.legacy_name},
                "acknowledgement": "declared",
            }
        )
    return _unique_sorted(claims)


def _normalize_properties(
    raw: object,
    *,
    payload_root: Path | None = None,
    snapshot_regular_files: frozenset[str] | None = None,
    payload_resolver: SnapshotPathResolver | None = None,
) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        raise ArtifactEvidenceError("component properties are invalid")
    result: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != _PROPERTY_FIELDS:
            raise ArtifactEvidenceError("component property is invalid")
        name = _required_string(item["name"], "property name")
        value = _required_string(item["value"], "property value")
        if _LOCATION_PROPERTY.fullmatch(name):
            if (
                payload_root is None
                or snapshot_regular_files is None
                or payload_resolver is None
            ):
                raise ArtifactEvidenceError("unexpected local component location")
            value = _payload_relative_path(
                value, payload_root, allow_base_relative=True
            )
            resolved = payload_resolver.resolve_entry(PurePosixPath(value))
            if resolved.entry.kind != "file":
                raise ArtifactEvidenceError(
                    "component location is not a regular payload file"
                )
            value = resolved.relative_path.as_posix()
            if value not in snapshot_regular_files:
                raise ArtifactEvidenceError(
                    "component location is not a regular payload file"
                )
        result.append({"name": name, "value": value})
    return _unique_sorted(result)


def _normalize_external_references(
    raw: object,
    name: str,
    version: str,
    qualification_facts: list[dict[str, object]],
    omissions: frozenset[_HttpReferenceOmission],
    *,
    local_wheel: tuple[Path, str] | None,
) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        raise ArtifactEvidenceError("component external references are invalid")
    result: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict) or not set(item) <= _REFERENCE_FIELDS:
            raise ArtifactEvidenceError("component external reference is invalid")
        reference_type = _reference_type(item.get("type"))
        url = _required_string(item.get("url"), "external reference URL")
        reference_hashes = _normalize_hashes(
            item.get("hashes", []), "external reference hashes"
        )
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError as error:
            raise ArtifactEvidenceError(
                "component external reference is invalid"
            ) from error
        if parsed.scheme == "https":
            try:
                port = parsed.port
            except ValueError as error:
                raise ArtifactEvidenceError(
                    "component external reference is unsafe"
                ) from error
            if (
                not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or port not in {None, 443}
            ):
                raise ArtifactEvidenceError("component external reference is unsafe")
            if reference_hashes:
                raise ArtifactEvidenceError("unexpected external reference checksum")
            result.append({"type": reference_type, "url": url})
            continue
        if parsed.scheme == "http":
            if reference_hashes:
                raise ArtifactEvidenceError("unexpected external reference checksum")
            identity = _HttpReferenceOmission(
                name,
                version,
                reference_type,
                hashlib.sha256(url.encode("utf-8")).hexdigest(),
            )
            if identity not in omissions:
                raise ArtifactEvidenceError("unreviewed HTTP component reference")
            qualification_facts.append(
                {
                    "code": "non-https-optional-reference-omitted",
                    "component": name,
                    "version": version,
                    "reference_type": reference_type,
                    "source": "reviewed-http-reference-policy",
                }
            )
            continue
        if parsed.scheme == "file":
            wheel_path = local_wheel[0] if local_wheel is not None else None
            decoded_path = urllib.parse.unquote(parsed.path)
            reference_path = PurePosixPath(decoded_path)
            if (
                local_wheel is None
                or name != "servonaut"
                or reference_type != "distribution"
                or parsed.netloc not in {"", "localhost"}
                or parsed.query
                or parsed.fragment
                or "\x00" in decoded_path
                or not reference_path.is_absolute()
                or any(part in {"", ".", ".."} for part in reference_path.parts[1:])
                or reference_path.name != wheel_path.name
                or _hash_value(reference_hashes, "SHA-256") != local_wheel[1]
            ):
                raise ArtifactEvidenceError("unexpected local component reference")
            qualification_facts.append(
                {
                    "code": "local-wheel-acquisition-normalized",
                    "component": name,
                    "version": version,
                    "source": "descriptor-wheel-sha256",
                }
            )
            continue
        raise ArtifactEvidenceError("component external reference scheme is unsafe")
    return sorted(result, key=lambda item: (item["type"], item["url"]))


def _normalize_dependencies(
    raw: object, references: Mapping[str, str], label: str
) -> list[dict[str, object]]:
    if not isinstance(raw, list):
        raise ArtifactEvidenceError(f"{label} dependencies are invalid")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict) or not set(item) <= _DEPENDENCY_FIELDS:
            raise ArtifactEvidenceError(f"{label} dependency is invalid")
        old_ref = _required_string(item.get("ref"), "dependency reference")
        new_ref = references.get(old_ref)
        if new_ref is None or new_ref in seen:
            raise ArtifactEvidenceError(f"{label} dependency reference is invalid")
        seen.add(new_ref)
        depends_on = item.get("dependsOn", [])
        if not isinstance(depends_on, list):
            raise ArtifactEvidenceError(f"{label} dependency edges are invalid")
        mapped: list[str] = []
        for dependency in depends_on:
            old_dependency = _required_string(dependency, "dependency edge")
            new_dependency = references.get(old_dependency)
            if new_dependency is None:
                raise ArtifactEvidenceError(f"{label} dependency edge is dangling")
            mapped.append(new_dependency)
        if len(set(mapped)) != len(mapped):
            raise ArtifactEvidenceError(f"{label} dependency edges are duplicated")
        normalized: dict[str, object] = {
            "ref": new_ref,
            "dependsOn": sorted(mapped),
        }
        if "provides" in item:
            provides = item["provides"]
            if not isinstance(provides, list):
                raise ArtifactEvidenceError(
                    f"{label} provided-component edges are invalid"
                )
            mapped_provides: list[str] = []
            for provided in provides:
                old_provided = _required_string(provided, "provided component edge")
                new_provided = references.get(old_provided)
                if new_provided is None:
                    raise ArtifactEvidenceError(
                        f"{label} provided-component edge is dangling"
                    )
                mapped_provides.append(new_provided)
            if len(set(mapped_provides)) != len(mapped_provides):
                raise ArtifactEvidenceError(
                    f"{label} provided-component edges are duplicated"
                )
            normalized["provides"] = sorted(mapped_provides)
        result.append(normalized)
    return sorted(result, key=lambda item: str(item["ref"]))


def _validate_wheel_provenance(
    snapshot: PayloadSnapshot,
    artifact: ArtifactDescriptor,
    environment: Mapping[str, dict[str, object]],
) -> str:
    expected = _provenance_string(snapshot, "wheel_sha256")
    if not _SHA256.fullmatch(expected):
        raise ArtifactEvidenceError("build provenance wheel checksum is invalid")
    wheel = artifact.wheel
    try:
        status = wheel.lstat()
        resolved = wheel.resolve(strict=True)
    except OSError as error:
        raise ArtifactEvidenceError("descriptor wheel is unavailable") from error
    if not stat.S_ISREG(status.st_mode) or resolved != wheel:
        raise ArtifactEvidenceError("descriptor wheel is not a regular file")
    digest = hashlib.sha256()
    try:
        with wheel.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise ArtifactEvidenceError("descriptor wheel could not be read") from error
    if digest.hexdigest() != expected:
        raise ArtifactEvidenceError("descriptor wheel conflicts with build provenance")
    servonaut = environment.get("servonaut")
    if servonaut is None or f"sha256:{expected}" not in servonaut["hashes"]:
        raise ArtifactEvidenceError("Servonaut archive provenance is missing")
    if servonaut["version"] != _provenance_string(snapshot, "product_version"):
        raise ArtifactEvidenceError("Servonaut version conflicts with build provenance")
    return expected


def _resolved_metadata_root(artifact: ArtifactDescriptor) -> Path:
    root = artifact.build_metadata_dir
    try:
        status = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise ArtifactEvidenceError(
            "build metadata directory is unavailable"
        ) from error
    if not stat.S_ISDIR(status.st_mode) or resolved != root:
        raise ArtifactEvidenceError("build metadata directory is invalid")
    candidate = root / "resolved"
    try:
        candidate_status = candidate.lstat()
        candidate_resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ArtifactEvidenceError("resolved build metadata is unavailable") from error
    if not stat.S_ISDIR(candidate_status.st_mode) or candidate_resolved.parent != root:
        raise ArtifactEvidenceError("resolved build metadata is invalid")
    return candidate_resolved


def _payload_relative_path(
    value: str, payload_root: Path, *, allow_base_relative: bool = False
) -> str:
    if "\x00" in value or "\\" in value:
        raise ArtifactEvidenceError("payload SBOM path is invalid")
    path = Path(value)
    try:
        if path.is_absolute():
            if allow_base_relative and not path.is_relative_to(payload_root):
                relative = Path(*path.parts[1:])
            else:
                relative = path.relative_to(payload_root)
        else:
            relative = path
    except ValueError as error:
        raise ArtifactEvidenceError("payload SBOM path escapes the payload") from error
    pure = PurePosixPath(relative.as_posix())
    if (
        not pure.parts
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.as_posix().split("/"))
    ):
        raise ArtifactEvidenceError("payload SBOM path is invalid")
    return pure.as_posix()


def _pypi_identity(component: Mapping[str, object]) -> tuple[str, str] | None:
    purl = component.get("purl")
    if not isinstance(purl, str) or not purl.startswith("pkg:pypi/"):
        return None
    return _parse_pypi_purl(purl)


def _parse_pypi_purl(purl: str) -> tuple[str, str]:
    _validate_purl(purl)
    if not purl.startswith("pkg:pypi/"):
        raise ArtifactEvidenceError("Python component purl is invalid")
    parsed = purl.removeprefix("pkg:pypi/")
    if "?" in parsed or "#" in parsed or parsed.count("@") != 1:
        raise ArtifactEvidenceError("Python component purl is invalid")
    name, version = parsed.rsplit("@", 1)
    return (
        _canonicalize_name(urllib.parse.unquote(name)),
        _version(urllib.parse.unquote(version)),
    )


def _validate_purl(purl: str) -> None:
    if (
        not purl.startswith("pkg:")
        or any(character.isspace() for character in purl)
        or len(purl) > 2048
    ):
        raise ArtifactEvidenceError("component purl is invalid")


def _pypi_purl(name: str, version: str) -> str:
    return (
        "pkg:pypi/"
        + urllib.parse.quote(name, safe="-")
        + "@"
        + urllib.parse.quote(version, safe=".+!_-")
    )


def _canonicalize_name(value: object) -> str:
    if not isinstance(value, str):
        raise ArtifactEvidenceError("package name is invalid")
    canonical = re.sub(r"[-_.]+", "-", value).casefold()
    if not _CANONICAL_NAME.fullmatch(canonical) or len(canonical) > 128:
        raise ArtifactEvidenceError("package name is invalid")
    return canonical


def _version(value: object) -> str:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise ArtifactEvidenceError("package version is invalid")
    return value


def _reference_type(value: object) -> str:
    if not isinstance(value, str) or not _REFERENCE_TYPE.fullmatch(value):
        raise ArtifactEvidenceError("external reference type is invalid")
    return value


def _license_files(value: object) -> tuple[str, ...]:
    files = _string_tuple(value, "license files")
    for filename in files:
        path = PurePosixPath(filename)
        if (
            path.is_absolute()
            or "\\" in filename
            or len(filename) > 512
            or any(part in {"", ".", ".."} or ":" in part for part in path.parts)
        ):
            raise ArtifactEvidenceError("license file name is invalid")
    return files


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ArtifactEvidenceError(f"{label} are invalid")
    result = tuple(_required_string(item, label) for item in value)
    if len(set(result)) != len(result):
        raise ArtifactEvidenceError(f"{label} contain duplicates")
    return tuple(sorted(result))


def _nullable_string(value: object, label: str) -> str | None:
    if value is None or value == "":
        return None
    return _required_string(value, label)


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _required_string(value, label)


def _required_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ArtifactEvidenceError(f"{label} is invalid")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ArtifactEvidenceError(f"{label} is invalid")
    return value


def _provenance_string(snapshot: PayloadSnapshot, field: str) -> str:
    return _required_string(snapshot.build_provenance.get(field), "build provenance")


def _hash_value(hashes: list[dict[str, str]], algorithm: str) -> str | None:
    values = [item["content"] for item in hashes if item["alg"] == algorithm]
    if len(values) > 1:
        raise ArtifactEvidenceError("component has conflicting hashes")
    return values[0] if values else None


def _validate_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ArtifactEvidenceError(f"{label} checksum is invalid")
    return value


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _component_sort_key(component: Mapping[str, object]) -> tuple[str, str, str, str]:
    return (
        str(component.get("type", "")),
        str(component.get("name", "")),
        str(component.get("version", "")),
        str(component.get("bom-ref", "")),
    )


def _unique_sorted(items: list[dict[str, object]]) -> list[dict[str, object]]:
    encoded = {
        json.dumps(item, sort_keys=True, separators=(",", ":")): item for item in items
    }
    return [encoded[key] for key in sorted(encoded)]


def _require_directory(path: Path, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ArtifactEvidenceError(f"{label} path is invalid")
    try:
        status = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ArtifactEvidenceError(f"{label} is unavailable") from error
    if not stat.S_ISDIR(status.st_mode) or resolved != path:
        raise ArtifactEvidenceError(f"{label} is invalid")
    return resolved


def _require_private_directory(path: Path, label: str) -> Path:
    resolved = _require_directory(path, label)
    status = path.lstat()
    if os.name != "nt" and stat.S_IMODE(status.st_mode) & 0o077:
        raise ArtifactEvidenceError(f"{label} permissions are not private")
    return resolved


def _require_child_directory(root: Path, name: str) -> Path:
    candidate = root / name
    resolved = _require_private_directory(candidate, f"{name} directory")
    if resolved.parent != root:
        raise ArtifactEvidenceError(f"{name} directory escapes the workspace")
    return resolved


def _remove_owned_file(path: Path, identity: tuple[int, int]) -> None:
    try:
        status = path.lstat()
        if stat.S_ISREG(status.st_mode) and (status.st_dev, status.st_ino) == identity:
            path.unlink()
    except OSError:
        return
