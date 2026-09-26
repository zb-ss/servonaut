"""Per-platform release qualification: a pure, read-only stability gate.

A release candidate is qualified per artifact family and platform row. The
platform matrix (``packaging/distribution/qualification-matrix.json``) lists
every supported row and the checks a tester runs on a clean machine. Testers
fill in a qualification record (``qualification-record.json``) for one
candidate: for each row that applies to one of its artifacts, the artifact's
SHA-256, the machine image, the result and each check, the test date, a tester
handle and, for a failed or blocked row, a link to a public issue or workflow
run.

A stable release requires every applicable row to pass against the same
artifact SHA-256 and candidate digest. The record must name the candidate's
own tag or, for a stable candidate, a preview tag of the same product version
with an identical digest, so a qualified preview whose artifacts ship
unchanged carries over. A preview release requires no passes, but a record
that is present must still be valid. A platform whose row fails stays preview
or absent: cut the stable candidate without that artifact.

The publish workflow applies this gate only while the REQUIRE_RELEASE_CANDIDATE
repository variable is on. Then every stable release, including its PyPI
upload, needs at least one fully qualified binary artifact, and the release
must carry ``candidate-evidence.json`` and ``qualification-record.json``, for
example attached to a draft release before it is published. The Release
workflow attaches neither file.

Errors carry stable reason codes and fixed messages. Record contents are never
echoed, so the output is safe for public workflow logs.
"""

from __future__ import annotations

import argparse
import json
import re
import string
import sys
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Optional

from scripts.distribution.release_candidate import (
    ARTIFACT_KINDS,
    SHA256_HEX,
    CandidateArtifact,
    CandidatePolicyError,
    ReleaseCandidate,
    channel_for_tag,
    is_artifact_id,
    is_member,
    load_evidence,
    read_json,
    tag_product_version,
    verified_candidate,
)
from servonaut.distribution.manifest import (
    SUPPORTED_ARCHITECTURES,
    SUPPORTED_PLATFORMS,
    ManifestError,
    ReleaseChannel,
)

DEFAULT_MATRIX = (
    Path(__file__).resolve().parents[2]
    / "packaging"
    / "distribution"
    / "qualification-matrix.json"
)

UNQUALIFIABLE_ARTIFACT = "unqualifiable-artifact"
ROW_MISSING = "row-missing"
ROW_FAILED = "row-failed"
ROW_STALE = "row-stale"
CHECK_MISSING = "check-missing"
RECORD_INVALID = "record-invalid"
MATRIX_INVALID = "matrix-invalid"

_MATRIX_SCHEMA_VERSION = 1
_RECORD_SCHEMA_VERSION = 1
_MATRIX_MAX_BYTES = 262_144
_RECORD_MAX_BYTES = 1_000_000
_MAX_ROWS = 128
_MAX_CHECKS = 128
_MAX_LIST_CHECKS = 32
_MAX_FAMILIES = 8
_MAX_PREFIXES = 8
_MAX_RECORD_ENTRIES = 512
_MAX_LINK_LENGTH = 256

_MATRIX_KEYS = frozenset(
    {"schema_version", "failure_link_prefixes", "checks", "families", "rows"}
)
_FAMILY_KEYS = frozenset({"title", "checks"})
_ROW_KEYS = frozenset(
    {"row_id", "family", "artifact_kind", "platform", "arch", "baseline", "extra_checks"}
)
_RECORD_KEYS = frozenset({"schema_version", "tag", "candidate_digest", "rows"})
_ENTRY_KEYS = frozenset(
    {
        "row_id",
        "artifact_id",
        "artifact_sha256",
        "machine_image",
        "result",
        "checks",
        "tested_on",
        "tester",
        "failure_link",
    }
)
_TEST_DETAILS = ("machine_image", "tested_on", "tester", "failure_link")
# A tester east of UTC can already be on the next calendar day.
_DATE_LINE_ALLOWANCE = timedelta(days=1)

_CHECK_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_FAMILY_ID = re.compile(r"[a-z][a-z0-9-]{0,31}")
_ROW_ID = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .,()+-]{0,63}")
_DESCRIPTION = re.compile(r"[ -~]{1,240}")
_LINK_PREFIX = re.compile(
    r"https://github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/"
    r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}/(?:issues|actions/runs)/"
)
# After an allowed prefix only a numeric issue or run path may follow, so a
# link can never climb out of the repository with dot segments or a query.
_LINK_SUFFIX = re.compile(r"[0-9]{1,20}(?:/[a-z]{1,16}/[0-9]{1,20})*(?:#[a-z0-9-]{1,64})?")
_TESTER = re.compile(r"[A-Za-z0-9._-]{1,64}")
_MACHINE_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._,:()+-]{0,127}")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_MARKDOWN_SPECIAL = frozenset(string.punctuation)


class QualificationError(Exception):
    """A qualification failure with a stable, public-logs-safe reason code.

    ``failures`` lists every platform row that stopped a stable release.
    """

    def __init__(
        self, code: str, message: str, failures: tuple[RowEvaluation, ...] = ()
    ) -> None:
        super().__init__(message)
        self.code = code
        self.failures = failures


class RowResult(str, Enum):
    """A tester's overall result for one row and artifact."""

    PASS = "pass"
    FAIL = "fail"
    BLOCKED = "blocked"
    UNTESTED = "untested"


class CheckResult(str, Enum):
    """A tester's result for one required check."""

    PASS = "pass"
    FAIL = "fail"
    UNTESTED = "untested"


class RowStatus(str, Enum):
    """Whether a row qualifies one candidate artifact."""

    QUALIFIED = "qualified"
    FAILED = "failed"
    MISSING = "missing"
    STALE = "stale"


@dataclass(frozen=True, slots=True)
class MatrixRow:
    """One supported platform row and every check it requires."""

    row_id: str
    family: str
    family_title: str
    artifact_kind: str
    platform: str
    arch: str
    baseline: str
    checks: tuple[str, ...]

    def applies_to(self, artifact: CandidateArtifact) -> bool:
        """Whether this row qualifies the artifact's kind, platform and arch."""
        return (artifact.kind, artifact.platform, artifact.arch) == (
            self.artifact_kind,
            self.platform,
            self.arch,
        )


@dataclass(frozen=True, slots=True)
class QualificationMatrix:
    """The supported platform rows and where failure links may point."""

    rows: tuple[MatrixRow, ...]
    failure_link_prefixes: tuple[str, ...]

    def row(self, row_id: str) -> Optional[MatrixRow]:
        """The row with this id, if the matrix has one."""
        return next((row for row in self.rows if row.row_id == row_id), None)

    def rows_for(self, artifact: CandidateArtifact) -> tuple[MatrixRow, ...]:
        """Every row that qualifies the artifact."""
        return tuple(row for row in self.rows if row.applies_to(artifact))


@dataclass(frozen=True, slots=True)
class RecordEntry:
    """A tester's result for one row and one candidate artifact."""

    row_id: str
    artifact_id: str
    artifact_sha256: str
    machine_image: Optional[str]
    result: RowResult
    checks: Mapping[str, CheckResult]
    tested_on: Optional[str]
    tester: Optional[str]
    failure_link: Optional[str]


@dataclass(frozen=True, slots=True)
class QualificationRecord:
    """The qualification results recorded for one candidate."""

    tag: str
    candidate_digest: str
    entries: tuple[RecordEntry, ...]

    def entry(self, row_id: str, artifact_id: str) -> Optional[RecordEntry]:
        """The result recorded for a row and artifact, if any."""
        return next(
            (
                entry
                for entry in self.entries
                if (entry.row_id, entry.artifact_id) == (row_id, artifact_id)
            ),
            None,
        )

    def describes(self, candidate: ReleaseCandidate) -> bool:
        """Whether the record was made for exactly this candidate's artifacts.

        The digest must match, and the tag must be the candidate's own or, for
        a stable candidate, a preview tag of the same product version.
        """
        return self.candidate_digest == candidate.digest and (
            self.tag == candidate.tag or _is_preview_of(self.tag, candidate)
        )


@dataclass(frozen=True, slots=True)
class RowEvaluation:
    """A row's status for one candidate artifact; ``reason`` is None when qualified."""

    row: MatrixRow
    artifact: CandidateArtifact
    status: RowStatus
    reason: Optional[str]
    entry: Optional[RecordEntry]


def _load_json(path: Path, max_bytes: int, code: str, label: str) -> Any:
    try:
        return read_json(path, max_bytes)
    except OSError as error:
        raise QualificationError(code, f"The {label} could not be read.") from error
    except ValueError as error:
        raise QualificationError(
            code, f"The {label} is empty, too large or not valid JSON."
        ) from error


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise QualificationError(code, message)


def _exact_object(value: Any, keys: frozenset[str], code: str, message: str) -> dict:
    _require(isinstance(value, dict) and set(value) == keys, code, message)
    return value


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _is_version(value: Any, expected: int) -> bool:
    return type(value) is int and value == expected


def _is_list_of(value: Any, pattern: re.Pattern[str], max_items: int) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= max_items
        and all(_matches(pattern, item) for item in value)
        and len(set(value)) == len(value)
    )


def _matrix_prefixes(value: Any) -> tuple[str, ...]:
    _require(
        _is_list_of(value, _LINK_PREFIX, _MAX_PREFIXES) and bool(value),
        MATRIX_INVALID,
        "The matrix failure-link prefixes must be GitHub issue or workflow-run URLs.",
    )
    return tuple(value)


def _matrix_checks(value: Any) -> frozenset[str]:
    _require(
        isinstance(value, dict)
        and 0 < len(value) <= _MAX_CHECKS
        and all(_matches(_CHECK_ID, check) for check in value)
        and all(_matches(_DESCRIPTION, text) for text in value.values()),
        MATRIX_INVALID,
        "The matrix check definitions are malformed.",
    )
    return frozenset(value)


def _matrix_check_list(value: Any, defined: frozenset[str]) -> tuple[str, ...]:
    _require(
        _is_list_of(value, _CHECK_ID, _MAX_LIST_CHECKS) and set(value) <= defined,
        MATRIX_INVALID,
        "A matrix check list names an undefined or repeated check.",
    )
    return tuple(value)


def _matrix_families(
    value: Any, defined: frozenset[str]
) -> dict[str, tuple[str, tuple[str, ...]]]:
    _require(
        isinstance(value, dict)
        and 0 < len(value) <= _MAX_FAMILIES
        and all(_matches(_FAMILY_ID, family) for family in value),
        MATRIX_INVALID,
        "The matrix families are malformed.",
    )
    families = {}
    for family_id, family in value.items():
        entry = _exact_object(
            family, _FAMILY_KEYS, MATRIX_INVALID, "A matrix family is malformed."
        )
        checks = _matrix_check_list(entry["checks"], defined)
        _require(
            _matches(_LABEL, entry["title"]) and bool(checks),
            MATRIX_INVALID,
            "A matrix family needs a title and at least one check.",
        )
        families[family_id] = (entry["title"], checks)
    return families


def _matrix_row(
    value: Any,
    families: Mapping[str, tuple[str, tuple[str, ...]]],
    defined: frozenset[str],
) -> MatrixRow:
    row = _exact_object(value, _ROW_KEYS, MATRIX_INVALID, "A matrix row is malformed.")
    _require(
        _matches(_ROW_ID, row["row_id"])
        and _matches(_LABEL, row["baseline"])
        and is_member(row["family"], families)
        and is_member(row["artifact_kind"], ARTIFACT_KINDS)
        and is_member(row["platform"], SUPPORTED_PLATFORMS)
        and is_member(row["arch"], SUPPORTED_ARCHITECTURES),
        MATRIX_INVALID,
        "A matrix row has a malformed id, family, artifact kind, platform or arch.",
    )
    title, family_checks = families[row["family"]]
    extra_checks = _matrix_check_list(row["extra_checks"], defined)
    _require(
        not set(extra_checks) & set(family_checks),
        MATRIX_INVALID,
        "A matrix row repeats a check its family already requires.",
    )
    return MatrixRow(
        row_id=row["row_id"],
        family=row["family"],
        family_title=title,
        artifact_kind=row["artifact_kind"],
        platform=row["platform"],
        arch=row["arch"],
        baseline=row["baseline"],
        checks=family_checks + extra_checks,
    )


def _matrix_rows(
    value: Any,
    families: Mapping[str, tuple[str, tuple[str, ...]]],
    defined: frozenset[str],
) -> tuple[MatrixRow, ...]:
    _require(
        isinstance(value, list) and 0 < len(value) <= _MAX_ROWS,
        MATRIX_INVALID,
        "The matrix rows are malformed.",
    )
    rows = tuple(_matrix_row(row, families, defined) for row in value)
    _require(
        len({row.row_id for row in rows}) == len(rows),
        MATRIX_INVALID,
        "The matrix repeats a row id.",
    )
    return rows


def load_matrix(path: Path = DEFAULT_MATRIX) -> QualificationMatrix:
    """Load the platform matrix, refusing anything its schema does not allow.

    The rules of ``qualification-matrix.schema.json`` are enforced here without
    a schema library, plus the cross-references a schema cannot express: every
    row's family and checks are defined, and every defined check is required.
    """
    document = _exact_object(
        _load_json(path, _MATRIX_MAX_BYTES, MATRIX_INVALID, "qualification matrix"),
        _MATRIX_KEYS,
        MATRIX_INVALID,
        "The qualification matrix has missing or unknown fields.",
    )
    _require(
        _is_version(document["schema_version"], _MATRIX_SCHEMA_VERSION),
        MATRIX_INVALID,
        "The qualification matrix schema version is not supported.",
    )
    prefixes = _matrix_prefixes(document["failure_link_prefixes"])
    checks = _matrix_checks(document["checks"])
    families = _matrix_families(document["families"], checks)
    rows = _matrix_rows(document["rows"], families, checks)
    _require(
        checks == {check for row in rows for check in row.checks}
        and set(families) == {row.family for row in rows},
        MATRIX_INVALID,
        "The matrix defines a check or family that no row uses.",
    )
    return QualificationMatrix(rows=rows, failure_link_prefixes=prefixes)


def _record_error(message: str) -> QualificationError:
    return QualificationError(RECORD_INVALID, message)


def _require_record(condition: bool, message: str) -> None:
    _require(condition, RECORD_INVALID, message)


def _result(kind: type[Enum], value: Any, message: str) -> Any:
    try:
        return kind(value)
    except ValueError as error:
        raise _record_error(message) from error


def _entry_checks(value: Any, row: MatrixRow) -> Mapping[str, CheckResult]:
    _require_record(
        isinstance(value, dict) and set(value) <= set(row.checks),
        "A record row names a check its platform row does not require.",
    )
    return MappingProxyType(
        {
            check: _result(CheckResult, result, "A record check result is not recognised.")
            for check, result in value.items()
        }
    )


def _is_past_date(value: Any, latest: date) -> bool:
    if not _matches(_DATE, value):
        return False
    try:
        return date.fromisoformat(value) <= latest
    except ValueError:
        return False


def _is_failure_link(value: Any, prefixes: Iterable[str]) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= _MAX_LINK_LENGTH
        and any(
            value.startswith(prefix)
            and _LINK_SUFFIX.fullmatch(value[len(prefix) :]) is not None
            for prefix in prefixes
        )
    )


def _require_untested(item: Mapping[str, Any], checks: Mapping[str, CheckResult]) -> None:
    _require_record(
        all(item[field] is None for field in _TEST_DETAILS)
        and all(result is CheckResult.UNTESTED for result in checks.values()),
        "An untested record row must not carry test details or results.",
    )


def _require_tested(
    item: Mapping[str, Any],
    result: RowResult,
    checks: Mapping[str, CheckResult],
    prefixes: Iterable[str],
    latest: date,
) -> None:
    _require_record(
        _matches(_MACHINE_IMAGE, item["machine_image"]),
        "A record machine image is missing or malformed.",
    )
    _require_record(
        _is_past_date(item["tested_on"], latest),
        "A record test date is not a YYYY-MM-DD date that has already begun.",
    )
    _require_record(
        _matches(_TESTER, item["tester"]),
        "A record tester must be a short handle, not a name or email address.",
    )
    if result is RowResult.PASS:
        _require_record(
            item["failure_link"] is None
            and all(check is CheckResult.PASS for check in checks.values()),
            "A passing record row must have only passing checks and no failure link.",
        )
        return
    _require_record(
        _is_failure_link(item["failure_link"], prefixes),
        "A failed or blocked record row needs a link to a public issue or workflow run.",
    )


def _record_entry(value: Any, matrix: QualificationMatrix, latest: date) -> RecordEntry:
    item = _exact_object(
        value, _ENTRY_KEYS, RECORD_INVALID, "A record row has missing or unknown fields."
    )
    row = matrix.row(item["row_id"]) if isinstance(item["row_id"], str) else None
    if row is None:
        raise _record_error("A record row is not in the platform matrix.")
    _require_record(
        is_artifact_id(item["artifact_id"])
        and _matches(SHA256_HEX, item["artifact_sha256"]),
        "A record row names a malformed artifact id or SHA-256.",
    )
    result = _result(RowResult, item["result"], "A record row result is not recognised.")
    checks = _entry_checks(item["checks"], row)
    if result is RowResult.UNTESTED:
        _require_untested(item, checks)
    else:
        _require_tested(item, result, checks, matrix.failure_link_prefixes, latest)
    return RecordEntry(
        row_id=row.row_id,
        artifact_id=item["artifact_id"],
        artifact_sha256=item["artifact_sha256"],
        machine_image=item["machine_image"],
        result=result,
        checks=checks,
        tested_on=item["tested_on"],
        tester=item["tester"],
        failure_link=item["failure_link"],
    )


def _is_release_tag(value: Any) -> bool:
    try:
        channel_for_tag(value)
    except CandidatePolicyError:
        return False
    return True


def _utc_today() -> date:
    return datetime.now(timezone.utc).date()


def load_record(
    path: Path, matrix: QualificationMatrix, *, today: Optional[date] = None
) -> QualificationRecord:
    """Load a qualification record, refusing unknown fields and malformed values.

    ``today`` is the current UTC date; a test date after it, allowing one day
    for time zones east of UTC, is refused.
    """
    latest = (today if today is not None else _utc_today()) + _DATE_LINE_ALLOWANCE
    document = _exact_object(
        _load_json(path, _RECORD_MAX_BYTES, RECORD_INVALID, "qualification record"),
        _RECORD_KEYS,
        RECORD_INVALID,
        "The qualification record has missing or unknown fields.",
    )
    _require_record(
        _is_version(document["schema_version"], _RECORD_SCHEMA_VERSION)
        and _is_release_tag(document["tag"])
        and _matches(SHA256_HEX, document["candidate_digest"]),
        "The qualification record version, tag or candidate digest is malformed.",
    )
    rows = document["rows"]
    _require_record(
        isinstance(rows, list) and len(rows) <= _MAX_RECORD_ENTRIES,
        "The qualification record rows are malformed.",
    )
    entries = tuple(_record_entry(row, matrix, latest) for row in rows)
    keys = {(entry.row_id, entry.artifact_id) for entry in entries}
    _require_record(
        len(keys) == len(entries),
        "The qualification record lists a row and artifact more than once.",
    )
    return QualificationRecord(
        tag=document["tag"],
        candidate_digest=document["candidate_digest"],
        entries=entries,
    )


def _is_preview_of(tag: str, candidate: ReleaseCandidate) -> bool:
    return (
        candidate.channel is ReleaseChannel.STABLE
        and channel_for_tag(tag) is ReleaseChannel.PREVIEW
        and tag_product_version(tag) == candidate.product_version
    )


def _applicable_pairs(
    matrix: QualificationMatrix, candidate: ReleaseCandidate
) -> tuple[tuple[MatrixRow, CandidateArtifact], ...]:
    return tuple(
        (row, artifact)
        for row in matrix.rows
        for artifact in candidate.artifacts
        if row.applies_to(artifact)
    )


def _require_record_targets(
    record: QualificationRecord,
    pairs: tuple[tuple[MatrixRow, CandidateArtifact], ...],
) -> None:
    applicable = {(row.row_id, artifact.artifact_id) for row, artifact in pairs}
    _require_record(
        all((entry.row_id, entry.artifact_id) in applicable for entry in record.entries),
        "The qualification record lists a row that does not apply to the candidate's artifacts.",
    )


def _row_status(
    row: MatrixRow,
    artifact: CandidateArtifact,
    entry: Optional[RecordEntry],
    is_current: bool,
) -> tuple[RowStatus, Optional[str]]:
    if entry is None or entry.result is RowResult.UNTESTED:
        return RowStatus.MISSING, ROW_MISSING
    if not is_current or entry.artifact_sha256 != artifact.sha256:
        return RowStatus.STALE, ROW_STALE
    if entry.result is not RowResult.PASS:
        return RowStatus.FAILED, ROW_FAILED
    if any(entry.checks.get(check) is not CheckResult.PASS for check in row.checks):
        return RowStatus.MISSING, CHECK_MISSING
    return RowStatus.QUALIFIED, None


def _evaluate(
    matrix: QualificationMatrix,
    record: Optional[QualificationRecord],
    candidate: ReleaseCandidate,
) -> tuple[RowEvaluation, ...]:
    pairs = _applicable_pairs(matrix, candidate)
    is_current = record is not None and record.describes(candidate)
    if record is not None and is_current:
        _require_record_targets(record, pairs)
    evaluations = []
    for row, artifact in pairs:
        entry = None if record is None else record.entry(row.row_id, artifact.artifact_id)
        status, reason = _row_status(row, artifact, entry, is_current)
        evaluations.append(RowEvaluation(row, artifact, status, reason, entry))
    return tuple(evaluations)


def evaluate(
    matrix: QualificationMatrix,
    record: Optional[QualificationRecord],
    evidence: Mapping[str, Any],
) -> tuple[RowEvaluation, ...]:
    """The status of every row that applies to one of the candidate's artifacts.

    A row is stale when the record does not describe the candidate (another
    digest, or a tag that is neither the candidate's own nor, for stable, a
    preview of the same version) or names a different artifact SHA-256;
    missing when it is absent, untested or passed without every required
    check; and failed when failed or blocked.
    """
    return _evaluate(matrix, record, verified_candidate(evidence))


def _unqualifiable(
    matrix: QualificationMatrix, candidate: ReleaseCandidate
) -> tuple[CandidateArtifact, ...]:
    return tuple(
        artifact for artifact in candidate.artifacts if not matrix.rows_for(artifact)
    )


def unqualifiable_artifacts(
    matrix: QualificationMatrix, evidence: Mapping[str, Any]
) -> tuple[CandidateArtifact, ...]:
    """The candidate's artifacts that no platform row covers."""
    return _unqualifiable(matrix, verified_candidate(evidence))


def _require_qualifiable(matrix: QualificationMatrix, candidate: ReleaseCandidate) -> None:
    _require(
        not _unqualifiable(matrix, candidate),
        UNQUALIFIABLE_ARTIFACT,
        "A candidate artifact matches no platform row, so it cannot be released as stable.",
    )


def _require_all_qualified(evaluations: tuple[RowEvaluation, ...]) -> None:
    first = next((item.reason for item in evaluations if item.reason is not None), None)
    if first is not None:
        raise QualificationError(
            first,
            "A stable release needs every applicable platform row to pass.",
            failures=tuple(item for item in evaluations if item.reason is not None),
        )


def ensure_qualified(
    matrix: QualificationMatrix,
    record: Optional[QualificationRecord],
    evidence: Mapping[str, Any],
    *,
    channel: ReleaseChannel,
) -> tuple[RowEvaluation, ...]:
    """Fail closed unless the record qualifies the candidate for a channel.

    Stable needs every artifact to map to at least one row and every
    applicable row to pass against the candidate. Preview needs no passes, but
    a present record must still be valid for the candidate.
    """
    candidate = verified_candidate(evidence)
    if candidate.channel is not channel:
        raise CandidatePolicyError(
            "candidate-channel-mismatch",
            "The candidate evidence belongs to a different release channel.",
        )
    is_stable = channel is ReleaseChannel.STABLE
    if is_stable:
        _require_qualifiable(matrix, candidate)
    evaluations = _evaluate(matrix, record, candidate)
    if is_stable:
        _require_all_qualified(evaluations)
    return evaluations


def supported_rows(
    matrix: QualificationMatrix,
    record: Optional[QualificationRecord],
    evidence: Mapping[str, Any],
) -> tuple[RowEvaluation, ...]:
    """The rows and artifacts that qualified; only these may be advertised."""
    return tuple(
        item
        for item in evaluate(matrix, record, evidence)
        if item.status is RowStatus.QUALIFIED
    )


def _template_entry(row: MatrixRow, artifact: CandidateArtifact) -> dict[str, Any]:
    return {
        "row_id": row.row_id,
        "artifact_id": artifact.artifact_id,
        "artifact_sha256": artifact.sha256,
        "machine_image": None,
        "result": RowResult.UNTESTED.value,
        "checks": {check: CheckResult.UNTESTED.value for check in row.checks},
        "tested_on": None,
        "tester": None,
        "failure_link": None,
    }


def record_template(
    matrix: QualificationMatrix, evidence: Mapping[str, Any]
) -> dict[str, Any]:
    """An untested record with one entry per applicable row and artifact.

    A stable candidate with an artifact no row covers is refused, because it
    could never qualify; a preview template leaves such artifacts out.
    """
    candidate = verified_candidate(evidence)
    if candidate.channel is ReleaseChannel.STABLE:
        _require_qualifiable(matrix, candidate)
    return {
        "schema_version": _RECORD_SCHEMA_VERSION,
        "tag": candidate.tag,
        "candidate_digest": candidate.digest,
        "rows": [
            _template_entry(row, artifact)
            for row, artifact in _applicable_pairs(matrix, candidate)
        ],
    }


def _markdown_text(value: str) -> str:
    return "".join(
        f"\\{char}" if char in _MARKDOWN_SPECIAL else char
        for char in value
        if char.isprintable()
    )


def summarize(
    matrix: QualificationMatrix,
    record: Optional[QualificationRecord],
    evidence: Mapping[str, Any],
) -> str:
    """A Markdown table of the qualified rows, built from policy and evidence only."""
    lines = [
        f"| {item.row.baseline} | {item.row.family_title} | {item.row.arch} "
        f"| {_markdown_text(item.artifact.filename)} | {item.entry.tested_on} |"
        for item in supported_rows(matrix, record, evidence)
        if item.entry is not None
    ]
    if not lines:
        return "No platform rows are qualified for this candidate.\n"
    header = [
        "| Platform | Family | Architecture | Artifact | Tested on |",
        "| --- | --- | --- | --- | --- |",
    ]
    return "\n".join(header + lines) + "\n"


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--evidence",
        type=Path,
        required=True,
        help="Candidate evidence written by release_candidate.py plan",
    )
    parser.add_argument(
        "--matrix",
        type=Path,
        default=DEFAULT_MATRIX,
        help="Platform qualification matrix",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check release qualification records against the platform matrix."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    template = commands.add_parser(
        "template", help="Write an untested record for a candidate's applicable rows"
    )
    _add_common_arguments(template)
    template.add_argument("--out", type=Path, help="Write here instead of stdout")

    check = commands.add_parser("check", help="Gate a channel on a qualification record")
    _add_common_arguments(check)
    check.add_argument("--record", type=Path, required=True)
    check.add_argument(
        "--channel",
        choices=("stable", "preview"),
        default="stable",
        help="Stable needs every applicable row to pass; preview only validates",
    )

    summary = commands.add_parser(
        "summarize", help="Print a Markdown table of the qualified rows"
    )
    _add_common_arguments(summary)
    summary.add_argument("--record", type=Path, required=True)
    return parser


def _run_template(args: argparse.Namespace) -> None:
    matrix = load_matrix(args.matrix)
    evidence = load_evidence(args.evidence)
    rendered = json.dumps(record_template(matrix, evidence), indent=2) + "\n"
    omitted = len(unqualifiable_artifacts(matrix, evidence))
    if omitted:
        print(
            f"::warning::{omitted} candidate artifact(s) match no platform row"
            " and are left out of the template.",
            file=sys.stderr,
        )
    if args.out is None:
        sys.stdout.write(rendered)
    else:
        args.out.write_text(rendered, encoding="utf-8")


def _run_check(args: argparse.Namespace) -> None:
    matrix = load_matrix(args.matrix)
    evaluations = ensure_qualified(
        matrix,
        load_record(args.record, matrix),
        load_evidence(args.evidence),
        channel=ReleaseChannel(args.channel),
    )
    qualified = sum(item.status is RowStatus.QUALIFIED for item in evaluations)
    print(f"channel={args.channel}")
    print(f"rows={len(evaluations)}")
    print(f"qualified={qualified}")


def _run_summarize(args: argparse.Namespace) -> None:
    matrix = load_matrix(args.matrix)
    record = load_record(args.record, matrix)
    sys.stdout.write(summarize(matrix, record, load_evidence(args.evidence)))


_COMMANDS = {
    "template": _run_template,
    "check": _run_check,
    "summarize": _run_summarize,
}


def _report(error: QualificationError) -> None:
    print(f"::error::{error.code}: {error}", file=sys.stderr)
    # Row ids come from the committed matrix, never from the record.
    for failure in error.failures:
        print(f"::error::{failure.reason}: {failure.row.row_id}", file=sys.stderr)


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        _COMMANDS[args.command](args)
        return 0
    except QualificationError as error:
        _report(error)
        return 1
    except CandidatePolicyError as error:
        print(f"::error::{error.code}: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, ManifestError):
        # Record and evidence data must not leak into public workflow logs.
        print(
            "::error::Qualification check failed. Check the matrix, record and candidate evidence.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
