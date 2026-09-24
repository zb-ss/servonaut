"""One SBOM normalisation contract for the evidence producer and the gate."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

from scripts.standalone_cli import evidence_policy, sbom_normalize
from scripts.standalone_cli.artifact_types import ArtifactEvidenceError
from scripts.standalone_cli.supply_contract import (
    HttpReferenceOmission,
    ParentVendor,
    load_normalization_policy,
)
from scripts.standalone_cli.syft_tool import load_syft_policy

_POLICY_ROOT = Path(__file__).parents[2] / "packaging" / "standalone_cli"
_POLICY = _POLICY_ROOT / "sbom-normalization.json"
_SCHEMA = _POLICY_ROOT / "sbom-normalization.schema.json"


def _shipped() -> dict[str, object]:
    return json.loads(_POLICY.read_text(encoding="utf-8"))


def _write(tmp_path: Path, document: dict[str, object]) -> Path:
    root = tmp_path.resolve()
    shutil.copyfile(_SCHEMA, root / _SCHEMA.name)
    path = root / _POLICY.name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _producer_accepts(path: Path) -> bool:
    try:
        sbom_normalize._load_normalization_policy(
            path, load_syft_policy(_POLICY_ROOT / "syft-tools.json")
        )
    except ArtifactEvidenceError:
        return False
    return True


def _gate_accepts(path: Path, monkeypatch: pytest.MonkeyPatch) -> bool:
    with monkeypatch.context() as patch:
        patch.setattr(evidence_policy, "_NORMALIZATION_POLICY_PATH", path)
        try:
            evidence_policy._reviewed_normalization_policy()
        except ArtifactEvidenceError:
            return False
    return True


def _second_url_for_one_reference() -> dict[str, object]:
    document = _shipped()
    rows = document["allowed_http_reference_omissions"]
    assert isinstance(rows, list)
    rows.insert(3, {**rows[2], "url_sha256": "f" * 64})
    return document


def _renamed(name: str) -> dict[str, object]:
    document = _shipped()
    document["allowed_http_reference_omissions"][0]["name"] = name  # type: ignore[index]
    return document


def _row_count(count: int) -> dict[str, object]:
    document = _shipped()
    document["allowed_http_reference_omissions"] = [
        {
            "name": f"package-{index:02d}",
            "version": "1.0",
            "reference_type": "website",
            "url_sha256": "a" * 64,
        }
        for index in range(count)
    ]
    return document


def _vendor_prefix(prefix: str) -> dict[str, object]:
    document = _shipped()
    document["allowed_parent_vendors"][0]["payload_prefix"] = prefix  # type: ignore[index]
    return document


def _duplicate_parent() -> dict[str, object]:
    document = _shipped()
    vendors = document["allowed_parent_vendors"]
    assert isinstance(vendors, list)
    vendors.append({**vendors[0], "payload_prefix": "_internal/zz/_vendor"})
    return document


def _unknown_field() -> dict[str, object]:
    document = _shipped()
    document["unexpected"] = True
    return document


def _unsorted_rows() -> dict[str, object]:
    document = _shipped()
    rows = document["allowed_http_reference_omissions"]
    assert isinstance(rows, list)
    rows.reverse()
    return document


@pytest.mark.parametrize(
    ("document", "accepted"),
    (
        (_shipped(), True),
        (_second_url_for_one_reference(), True),
        (_row_count(16), True),
        (_renamed("AltGraph"), False),
        (_renamed("alt_graph"), False),
        (_row_count(17), False),
        (_vendor_prefix("_internal/../setuptools/_vendor"), False),
        (_vendor_prefix("_internal//_vendor"), False),
        (_duplicate_parent(), False),
        (_unknown_field(), False),
        (_unsorted_rows(), False),
    ),
    ids=(
        "shipped",
        "second-url-for-one-reference",
        "sixteen-rows",
        "uppercase-name",
        "underscore-name",
        "seventeen-rows",
        "parent-traversal-prefix",
        "empty-prefix-segment",
        "duplicate-parent",
        "unknown-field",
        "unsorted-rows",
    ),
)
def test_producer_and_gate_apply_one_normalisation_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, object],
    accepted: bool,
) -> None:
    path = _write(tmp_path, copy.deepcopy(document))

    assert _producer_accepts(path) is accepted
    assert _gate_accepts(path, monkeypatch) is accepted


def test_shared_loader_returns_the_reviewed_rows() -> None:
    policy = load_normalization_policy(_POLICY.resolve(), 1 << 20)

    assert HttpReferenceOmission(
        "macholib",
        "1.16.4",
        "website",
        "7b464ba702211e9cea8022d4de76e30a9ffc8c48ba07f6a91ccc1fe5d3fff287",
    ) in policy.http_reference_omissions
    assert policy.parent_vendors == (
        ParentVendor("setuptools", "_internal/setuptools/_vendor"),
    )


def test_shared_loader_requires_the_shipped_schema(tmp_path: Path) -> None:
    path = _write(tmp_path, _shipped())
    (path.parent / _SCHEMA.name).unlink()

    with pytest.raises(ArtifactEvidenceError, match="schema"):
        load_normalization_policy(path, 1 << 20)
