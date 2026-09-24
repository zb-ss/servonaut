"""Refresh reviewed PyInstaller warning approvals after their target facts change.

    python -m scripts.standalone_cli.warning_allowlist \
        --target <target> --candidates <warning-candidates.json>

A qualification run lists every warning without a current approval in
``warning-candidates.json``. When only the target facts moved, each candidate
replaces the reviewed approval with the same code, module and importers. The
approval keeps its classification, reason and expiry, and its fingerprint is
recomputed. A candidate without a reviewed approval needs human review, so the
refresh is refused and nothing is written. Only counts are printed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

from scripts.standalone_cli.artifact_types import ArtifactEvidenceError
from scripts.standalone_cli.evidence_policy import (
    _POLICY_MAX_BYTES,
    _TARGET_NAMES,
    _WARNING_ALLOWLIST_FIELDS,
    _WARNING_RECORD_FIELDS,
    _fingerprint,
    load_evidence_policy,
)
from scripts.standalone_cli.evidence_sanitize import load_bounded_json

_POLICY_ROOT = Path(__file__).resolve().parents[2] / "packaging" / "standalone_cli"
_ALLOWLIST = _POLICY_ROOT / "warnings-allowlist.json"
_EVIDENCE_POLICY = _POLICY_ROOT / "evidence-policy.json"
_TARGET_FACT_FIELDS = frozenset({"target", "lock_sha256", "toolchain_sha256"})
_REVIEWED_FIELDS = ("classification", "reason", "expires_on")

_ApprovalKey = tuple[str, str, str]


def refresh_warning_allowlist(
    allowlist_path: Path, target: str, candidates_path: Path
) -> tuple[int, int]:
    """Rewrite one target's approvals; return (refreshed, unchanged) counts."""
    if target not in _TARGET_NAMES:
        raise ArtifactEvidenceError("warning allowlist target is unknown")
    allowlist = _load_allowlist(allowlist_path)
    entries = allowlist["targets"][target]
    candidates = _load_candidates(candidates_path, target)
    approvals = _index_by_approval_key(entries, "warning allowlist")
    replacements = _index_by_approval_key(candidates, "warning candidates")
    unreviewed = replacements.keys() - approvals.keys()
    if unreviewed:
        raise ArtifactEvidenceError(
            f"{len(unreviewed)} warning candidates have no reviewed approval"
        )
    refreshed = [
        _refreshed_entry(approvals[key], replacements[key])
        if key in replacements
        else entry
        for key, entry in approvals.items()
    ]
    allowlist["targets"][target] = sorted(
        refreshed, key=lambda entry: str(entry["fingerprint"])
    )
    _write_allowlist(allowlist_path, allowlist)
    return len(replacements), len(approvals) - len(replacements)


def _load_allowlist(path: Path) -> dict[str, dict[str, list[dict[str, object]]]]:
    raw = load_bounded_json(path, "warning allowlist", _POLICY_MAX_BYTES)
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "targets"}
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
        or not isinstance(raw["targets"], dict)
        or set(raw["targets"]) != _TARGET_NAMES
        or any(
            not isinstance(entries, list)
            or any(
                not isinstance(entry, dict) or set(entry) != _WARNING_ALLOWLIST_FIELDS
                for entry in entries
            )
            for entries in raw["targets"].values()
        )
    ):
        raise ArtifactEvidenceError("warning allowlist is invalid")
    return raw


def _load_candidates(path: Path, target: str) -> list[dict[str, object]]:
    maximum = load_evidence_policy(_EVIDENCE_POLICY).limits.max_metadata_file_bytes
    raw = load_bounded_json(path, "warning candidates", maximum)
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "candidates"}
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
        or not isinstance(raw["candidates"], list)
    ):
        raise ArtifactEvidenceError("warning candidates are invalid")
    candidates = raw["candidates"]
    if any(not _valid_candidate(candidate, target) for candidate in candidates):
        raise ArtifactEvidenceError("warning candidates are invalid")
    runs = {json.dumps(item["target_facts"], sort_keys=True) for item in candidates}
    if len(runs) > 1:
        raise ArtifactEvidenceError("warning candidates mix qualification runs")
    return candidates


def _valid_candidate(candidate: object, target: str) -> bool:
    if not isinstance(candidate, dict) or set(candidate) != _WARNING_RECORD_FIELDS:
        return False
    facts = candidate["target_facts"]
    return (
        isinstance(facts, dict)
        and set(facts) == _TARGET_FACT_FIELDS
        and facts["target"] == target
        and isinstance(candidate["code"], str)
        and isinstance(candidate["module"], str)
        and isinstance(candidate["importers"], list)
        and candidate["fingerprint"] == _fingerprint(_warning_record(candidate))
    )


def _warning_record(record: Mapping[str, object]) -> dict[str, object]:
    return {field: record[field] for field in _WARNING_RECORD_FIELDS - {"fingerprint"}}


def _approval_key(record: Mapping[str, object]) -> _ApprovalKey:
    return (
        str(record["code"]),
        str(record["module"]),
        json.dumps(record["importers"], sort_keys=True, separators=(",", ":")),
    )


def _index_by_approval_key(
    records: Sequence[dict[str, object]], label: str
) -> dict[_ApprovalKey, dict[str, object]]:
    indexed: dict[_ApprovalKey, dict[str, object]] = {}
    for record in records:
        key = _approval_key(record)
        if key in indexed:
            raise ArtifactEvidenceError(f"{label} repeats one warning")
        indexed[key] = record
    return indexed


def _refreshed_entry(
    approval: Mapping[str, object], candidate: Mapping[str, object]
) -> dict[str, object]:
    record = _warning_record(candidate)
    return {
        **record,
        "fingerprint": _fingerprint(record),
        **{field: approval[field] for field in _REVIEWED_FIELDS},
    }


def _write_allowlist(path: Path, allowlist: Mapping[str, object]) -> None:
    encoded = (json.dumps(allowlist, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > _POLICY_MAX_BYTES:
        raise ArtifactEvidenceError("warning allowlist would exceed its size limit")
    descriptor, temporary = tempfile.mkstemp(
        prefix=".warnings-allowlist-", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    """Refresh one target's warning approvals from a qualification run."""
    parser = argparse.ArgumentParser(
        description="Refresh reviewed PyInstaller warning approvals"
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--allowlist", type=Path, default=_ALLOWLIST)
    arguments = parser.parse_args(argv)
    try:
        refreshed, unchanged = refresh_warning_allowlist(
            arguments.allowlist.resolve(),
            arguments.target,
            arguments.candidates.resolve(),
        )
    except ArtifactEvidenceError as error:
        print(f"warning allowlist refresh refused: {error}", file=sys.stderr)
        return 1
    except OSError:
        print(
            "warning allowlist refresh refused: a file was unavailable",
            file=sys.stderr,
        )
        return 1
    print(f"refreshed {refreshed} warning approvals; {unchanged} unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
