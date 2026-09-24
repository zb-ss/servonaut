"""The reviewed SBOM normalisation policy, loaded one way by producer and gate."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from jsonschema import Draft202012Validator, ValidationError

from scripts.standalone_cli.artifact_types import ArtifactEvidenceError
from scripts.standalone_cli.evidence_sanitize import load_bounded_json

NORMALIZATION_SCHEMA_NAME = "sbom-normalization.schema.json"


@dataclass(frozen=True)
class HttpReferenceOmission:
    """One reviewed plain-HTTP reference that may be omitted from an SBOM."""

    name: str
    version: str
    reference_type: str
    url_sha256: str


@dataclass(frozen=True)
class ParentVendor:
    """A distribution whose vendored dist-info may appear under a payload prefix."""

    parent: str
    payload_prefix: str


@dataclass(frozen=True)
class NormalizationPolicy:
    """Validated normalisation rules shared by SBOM generation and the gate."""

    http_reference_omissions: frozenset[HttpReferenceOmission]
    parent_vendors: tuple[ParentVendor, ...]


def load_normalization_policy(path: Path, max_bytes: int) -> NormalizationPolicy:
    """Load the policy, applying its shipped JSON schema and the ordering rules.

    The schema fixes the field shapes, canonical names and row counts. Rows
    must also be sorted and unique, a parent may be vendored under only one
    prefix, and every prefix must be a plain relative payload path.
    """
    raw = load_bounded_json(path, "SBOM normalization policy", max_bytes)
    schema = load_bounded_json(
        path.with_name(NORMALIZATION_SCHEMA_NAME),
        "SBOM normalization schema",
        max_bytes,
    )
    try:
        Draft202012Validator(schema).validate(raw)
    except (ValidationError, ValueError) as error:
        raise ArtifactEvidenceError("SBOM normalization policy is invalid") from error
    assert isinstance(raw, dict)
    return NormalizationPolicy(
        _http_reference_omissions(raw["allowed_http_reference_omissions"]),
        _parent_vendors(raw["allowed_parent_vendors"]),
    )


def _http_reference_omissions(
    rows: Sequence[dict[str, str]],
) -> frozenset[HttpReferenceOmission]:
    omissions = [
        HttpReferenceOmission(
            row["name"], row["version"], row["reference_type"], row["url_sha256"]
        )
        for row in rows
    ]
    keys = [
        (row.name, row.version, row.reference_type, row.url_sha256)
        for row in omissions
    ]
    if keys != sorted(set(keys)):
        raise ArtifactEvidenceError("SBOM normalization rows are not sorted and unique")
    return frozenset(omissions)


def _parent_vendors(rows: Sequence[dict[str, str]]) -> tuple[ParentVendor, ...]:
    vendors = tuple(ParentVendor(row["parent"], row["payload_prefix"]) for row in rows)
    keys = [(vendor.parent, vendor.payload_prefix) for vendor in vendors]
    parents = {vendor.parent for vendor in vendors}
    if keys != sorted(set(keys)) or len(parents) != len(vendors):
        raise ArtifactEvidenceError(
            "SBOM parent vendor rows are not sorted and unique"
        )
    if any(not _is_payload_prefix(vendor.payload_prefix) for vendor in vendors):
        raise ArtifactEvidenceError("parent vendor payload prefix is invalid")
    return vendors


def _is_payload_prefix(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and len(path.parts) >= 2
        and not any(part in {"", ".", ".."} or ":" in part for part in path.parts)
        and "\\" not in value
    )
