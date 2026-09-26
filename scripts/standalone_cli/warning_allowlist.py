"""Refresh reviewed PyInstaller warning approvals after their target facts change.

    python -m scripts.standalone_cli.warning_allowlist \
        --target <target> --candidates <warning-candidates.json> \
        [--prune-stale --warnings <warnings.json>]

A qualification run lists every warning without a current approval in
``warning-candidates.json``. When only the target facts moved, each candidate
replaces the reviewed approval with the same code, module and importers. The
approval keeps its classification, reason and expiry, and its fingerprint is
recomputed. A candidate without a reviewed approval needs human review, so the
refresh is refused and nothing is written. Only counts are printed.

The candidates list only the warnings a run could not approve, so an approval
missing from them may still be current. ``--prune-stale`` therefore reads the
same run's ``warnings.json``, whose ``stale`` list names every approval the run
did not observe. The report must list every current approval exactly once, as
approved or stale, with counts that match its lists; otherwise the refresh is
refused. Each stale approval is then resolved:

* a candidate with the same code and module whose importers are a strict
  subset of the stale approval's, with the same set of qualifiers, inherits
  that review (the build now reaches the reviewed warning from fewer places);
* every other stale approval is removed.

A candidate that still has no reviewed approval refuses the refresh as before.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from scripts.standalone_cli.artifact_types import ArtifactEvidenceError
from scripts.standalone_cli.evidence_policy import (
    _POLICY_MAX_BYTES,
    _TARGET_NAMES,
    _WARNING_ALLOWLIST_FIELDS,
    _WARNING_COUNTS_FIELDS,
    _WARNING_RECORD_FIELDS,
    _WARNING_REPORT_FIELDS,
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


@dataclass(frozen=True)
class RefreshCounts:
    """How a refresh resolved each reviewed approval of one target."""

    refreshed: int
    narrowed: int
    unchanged: int
    pruned: int


def refresh_warning_allowlist(
    allowlist_path: Path,
    target: str,
    candidates_path: Path,
    warnings_path: Path | None = None,
) -> RefreshCounts:
    """Rewrite one target's approvals; prune stale ones when a report is given."""
    if target not in _TARGET_NAMES:
        raise ArtifactEvidenceError("warning allowlist target is unknown")
    allowlist = _load_allowlist(allowlist_path)
    entries = allowlist["targets"][target]
    candidates = _load_candidates(candidates_path, target)
    approvals = _index_by_approval_key(entries, "warning allowlist")
    replacements = _index_by_approval_key(candidates, "warning candidates")
    stale: frozenset[_ApprovalKey] = frozenset()
    if warnings_path is not None:
        stale = _load_stale_approvals(warnings_path, entries, candidates)
    narrowed = _narrowed_reviews(replacements, approvals, stale)
    unreviewed = replacements.keys() - approvals.keys() - narrowed.keys()
    if unreviewed:
        raise ArtifactEvidenceError(
            f"{len(unreviewed)} warning candidates have no reviewed approval"
        )
    inherited_by = {approval: candidate for candidate, approval in narrowed.items()}
    resolved: list[dict[str, object]] = []
    pruned = 0
    for key, entry in approvals.items():
        candidate_key = key if key in replacements else inherited_by.get(key)
        if candidate_key is not None:
            resolved.append(_refreshed_entry(entry, replacements[candidate_key]))
        elif key in stale:
            pruned += 1
        else:
            resolved.append(entry)
    allowlist["targets"][target] = sorted(
        resolved, key=lambda entry: str(entry["fingerprint"])
    )
    _write_allowlist(allowlist_path, allowlist)
    refreshed = len(replacements) - len(narrowed)
    return RefreshCounts(
        refreshed=refreshed,
        narrowed=len(narrowed),
        unchanged=len(approvals) - refreshed - len(narrowed) - pruned,
        pruned=pruned,
    )


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
        or not all(
            _fingerprints_identify_rows(entries) for entries in raw["targets"].values()
        )
    ):
        raise ArtifactEvidenceError("warning allowlist is invalid")
    return raw


def _fingerprints_identify_rows(entries: Sequence[Mapping[str, object]]) -> bool:
    """Each fingerprint is unique and recomputes from its own row's warning."""
    fingerprints = [entry["fingerprint"] for entry in entries]
    return len(set(map(str, fingerprints))) == len(fingerprints) and all(
        entry["fingerprint"] == _fingerprint(_warning_record(entry))
        for entry in entries
    )


def _load_candidates(path: Path, target: str) -> list[dict[str, object]]:
    raw = load_bounded_json(path, "warning candidates", _metadata_max_bytes())
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


def _load_stale_approvals(
    path: Path,
    entries: Sequence[Mapping[str, object]],
    candidates: Sequence[Mapping[str, object]],
) -> frozenset[_ApprovalKey]:
    """Return the current approvals that the candidates' own run found stale.

    The run classified every approval as either approved or stale, so the two
    lists must partition exactly the approvals being refreshed.
    """
    raw = load_bounded_json(path, "warning report", _metadata_max_bytes())
    if not _valid_report(raw):
        raise ArtifactEvidenceError("warning report is invalid")
    if raw["unknown"] != list(candidates):
        raise ArtifactEvidenceError(
            "warning report and candidates come from different runs"
        )
    by_fingerprint = {str(entry["fingerprint"]): entry for entry in entries}
    reported = [str(row["fingerprint"]) for row in (*raw["approved"], *raw["stale"])]
    if (
        len(reported) != len(entries)
        or set(reported) != by_fingerprint.keys()
        or any(
            row != _warning_record_with_fingerprint(by_fingerprint[row["fingerprint"]])
            for row in raw["approved"]
        )
        or any(row != by_fingerprint[row["fingerprint"]] for row in raw["stale"])
    ):
        raise ArtifactEvidenceError(
            "warning report does not match the current allowlist"
        )
    return frozenset(_approval_key(row) for row in raw["stale"])


def _valid_report(raw: object) -> bool:
    if (
        not isinstance(raw, dict)
        or set(raw) != _WARNING_REPORT_FIELDS
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
    ):
        return False
    rows = {name: raw[name] for name in _WARNING_COUNTS_FIELDS}
    if any(
        not isinstance(listed, list)
        or any(
            not isinstance(row, dict) or not isinstance(row.get("fingerprint"), str)
            for row in listed
        )
        for listed in rows.values()
    ):
        return False
    counts = raw["counts"]
    collection = raw["collection_facts"]
    return (
        isinstance(counts, dict)
        and set(counts) == _WARNING_COUNTS_FIELDS
        and all(
            type(counts[name]) is int and counts[name] == len(listed)
            for name, listed in rows.items()
        )
        and isinstance(collection, dict)
        and (
            "record_count" not in collection
            or (
                type(collection["record_count"]) is int
                and collection["record_count"]
                == len(rows["approved"]) + len(rows["unknown"])
            )
        )
    )


def _metadata_max_bytes() -> int:
    return load_evidence_policy(_EVIDENCE_POLICY).limits.max_metadata_file_bytes


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


def _warning_record_with_fingerprint(
    record: Mapping[str, object],
) -> dict[str, object]:
    return {field: record[field] for field in _WARNING_RECORD_FIELDS}


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


def _narrowed_reviews(
    replacements: Mapping[_ApprovalKey, Mapping[str, object]],
    approvals: Mapping[_ApprovalKey, Mapping[str, object]],
    stale: Collection[_ApprovalKey],
) -> dict[_ApprovalKey, _ApprovalKey]:
    """Pair each unreviewed candidate with the single stale approval it narrows."""
    available = {
        key: approval
        for key, approval in approvals.items()
        if key in stale and key not in replacements
    }
    pairs: dict[_ApprovalKey, _ApprovalKey] = {}
    for key in sorted(replacements.keys() - approvals.keys()):
        matches = [
            approval_key
            for approval_key, approval in available.items()
            if _narrows(replacements[key], approval)
        ]
        if len(matches) == 1 and matches[0] not in pairs.values():
            pairs[key] = matches[0]
    return pairs


def _narrows(candidate: Mapping[str, object], approval: Mapping[str, object]) -> bool:
    """Whether a candidate is the reviewed warning reached from fewer importers."""
    if (
        candidate["code"] != approval["code"]
        or candidate["module"] != approval["module"]
    ):
        return False
    remaining = _importer_keys(candidate["importers"])
    reviewed = _importer_keys(approval["importers"])
    return (
        remaining is not None
        and reviewed is not None
        and bool(remaining)
        and remaining < reviewed
        and _qualifiers(candidate["importers"]) == _qualifiers(approval["importers"])
    )


def _importer_keys(importers: object) -> frozenset[str] | None:
    if not isinstance(importers, list) or any(
        not isinstance(importer, dict)
        or not isinstance(importer.get("qualifiers"), list)
        for importer in importers
    ):
        return None
    return frozenset(
        json.dumps(importer, sort_keys=True, separators=(",", ":"))
        for importer in importers
    )


def _qualifiers(importers: object) -> frozenset[str]:
    assert isinstance(importers, list)
    return frozenset(
        str(qualifier) for importer in importers for qualifier in importer["qualifiers"]
    )


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
    mode = stat.S_IMODE(path.stat().st_mode)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".warnings-allowlist-", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        # mkstemp creates the file owner-only; keep the reviewed file's mode.
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _summary(counts: RefreshCounts, *, pruning: bool) -> str:
    summary = (
        f"refreshed {counts.refreshed} warning approvals; "
        f"{counts.unchanged} unchanged"
    )
    if not pruning:
        return summary
    return (
        f"{summary}; {counts.narrowed} narrowed to fewer importers; "
        f"{counts.pruned} stale pruned"
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Refresh one target's warning approvals from a qualification run."""
    parser = argparse.ArgumentParser(
        description="Refresh reviewed PyInstaller warning approvals"
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--allowlist", type=Path, default=_ALLOWLIST)
    parser.add_argument(
        "--prune-stale",
        action="store_true",
        help="resolve every approval the run reported stale (needs --warnings)",
    )
    parser.add_argument(
        "--warnings",
        type=Path,
        help="the warnings.json report of the run that wrote the candidates",
    )
    arguments = parser.parse_args(argv)
    if arguments.prune_stale != (arguments.warnings is not None):
        parser.error("--prune-stale and --warnings must be given together")
    try:
        counts = refresh_warning_allowlist(
            arguments.allowlist.resolve(),
            arguments.target,
            arguments.candidates.resolve(),
            arguments.warnings.resolve() if arguments.prune_stale else None,
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
    print(_summary(counts, pruning=arguments.prune_stale))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
