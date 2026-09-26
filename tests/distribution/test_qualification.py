"""Per-platform release qualification: matrix policy, records and the stability gate."""

from __future__ import annotations

import copy
import json
from datetime import date
from pathlib import Path
from typing import Any, Callable, Optional
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from scripts.distribution.qualification import (
    CHECK_MISSING,
    DEFAULT_MATRIX,
    MATRIX_INVALID,
    RECORD_INVALID,
    ROW_FAILED,
    ROW_MISSING,
    ROW_STALE,
    UNQUALIFIABLE_ARTIFACT,
    QualificationError,
    QualificationMatrix,
    QualificationRecord,
    RowStatus,
    ensure_qualified,
    evaluate,
    load_matrix,
    load_record,
    main,
    record_template,
    summarize,
    supported_rows,
)
from scripts.distribution import release_candidate
from scripts.distribution.release_candidate import (
    CandidatePolicyError,
    candidate_digest,
    candidate_from_evidence,
    plan_candidate,
)
from servonaut.distribution.builder import ManifestBuilder
from servonaut.distribution.manifest import (
    SUPPORTED_ARCHITECTURES,
    SUPPORTED_PLATFORMS,
    ArtifactKind,
    ReleaseChannel,
    canonicalize_json,
)
from servonaut.runtime import DistributionKind

SCHEMA = DEFAULT_MATRIX.with_name("qualification-matrix.schema.json")
CLI_LINUX = (ArtifactKind.STANDALONE_CLI, "linux", "x86_64")
DEB_LINUX = (ArtifactKind.UBUNTU_DEB, "linux", "x86_64")
CLI_ROWS = ("cli-ubuntu-22.04-x64", "cli-ubuntu-24.04-x64")
DEB_ROWS = (
    "desktop-ubuntu-22.04-x64-x11",
    "desktop-ubuntu-22.04-x64-wayland",
    "desktop-ubuntu-24.04-x64-x11",
    "desktop-ubuntu-24.04-x64-wayland",
)
UNCOVERED = (ArtifactKind.STANDALONE_CLI, "linux", "arm64")
ISSUE_LINK = "https://github.com/zb-ss/servonaut/issues/12"
_DISTRIBUTIONS = {ArtifactKind.STANDALONE_CLI: DistributionKind.FROZEN_CLI}


def _evidence(
    tmp_path: Path,
    *labels: tuple[ArtifactKind, str, str],
    tag: str = "v2.27.0",
    channel: ReleaseChannel = ReleaseChannel.STABLE,
    artifact_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Real candidate evidence planned from a signed manifest.

    The same labels in the same directory always give the same digest, so a
    preview and a stable candidate can share identical artifacts.

    The artifacts are placeholder bytes, not built packages, so the runtime
    marker check that planning performs (covered by the release-candidate
    tests) is skipped: qualification only consumes the planned evidence.
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    builder = ManifestBuilder(
        product_version="2.27.0",
        channel=channel,
        packaging_revision=1,
        expires_at="2099-01-01T00:00:00Z",
    )
    key = Ed25519PrivateKey.generate()
    files: dict[str, Path] = {}
    for index, (kind, platform, arch) in enumerate(labels or (CLI_LINUX,)):
        artifact = tmp_path / f"servonaut-{index}_{kind.value}.bin"
        artifact.write_bytes(f"PAYLOAD-{index}".encode())
        record = builder.add_artifact_file(
            artifact,
            kind=kind,
            distribution=_DISTRIBUTIONS.get(kind, DistributionKind.PACKAGED_DESKTOP),
            platform=platform,
            arch=arch,
            download_url=f"https://example.com/{artifact.name}",
            artifact_id=artifact_ids[index] if artifact_ids else None,
        )
        builder.sign_artifact(record.artifact_id, key)
        files[record.artifact_id] = artifact
    with patch.object(release_candidate, "_require_marker_identity"):
        candidate = plan_candidate(
            builder.build(), tag=tag, source_commit="a" * 40, artifact_files=files
        )
    return candidate.to_evidence()


@pytest.fixture(scope="module")
def matrix() -> QualificationMatrix:
    return load_matrix()


def _write(path: Path, document: Any) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _pass(entry: dict[str, Any]) -> dict[str, Any]:
    entry.update(
        machine_image="Clean VM, Ubuntu 24.04.1",
        result="pass",
        checks={check: "pass" for check in entry["checks"]},
        tested_on="2026-09-20",
        tester="qa-1",
        failure_link=None,
    )
    return entry


def _fail(entry: dict[str, Any], result: str = "fail") -> dict[str, Any]:
    _pass(entry).update(result=result, failure_link=ISSUE_LINK)
    first = next(iter(entry["checks"]))
    entry["checks"][first] = "fail"
    return entry


def _passing(matrix: QualificationMatrix, evidence: dict[str, Any]) -> dict[str, Any]:
    document = record_template(matrix, evidence)
    for entry in document["rows"]:
        _pass(entry)
    return document


def _entry(document: dict[str, Any], row_id: str) -> dict[str, Any]:
    return next(entry for entry in document["rows"] if entry["row_id"] == row_id)


def _desktop_entry_for_cli_artifact(document: dict[str, Any]) -> dict[str, Any]:
    """A well-formed passing entry for a desktop row, naming the CLI artifact."""
    entry = copy.deepcopy(document["rows"][0])
    entry["row_id"] = DEB_ROWS[0]
    entry["checks"] = {check: "pass" for check in load_matrix().row(DEB_ROWS[0]).checks}
    return entry


def _record(
    tmp_path: Path, matrix: QualificationMatrix, document: dict[str, Any]
) -> QualificationRecord:
    return load_record(_write(tmp_path / "qualification-record.json", document), matrix)


# --- Platform matrix -------------------------------------------------------


def test_committed_matrix_covers_the_supported_platforms(matrix) -> None:
    rows = {row.row_id: row for row in matrix.rows}
    assert {row.family for row in matrix.rows} == {"cli", "desktop"}
    for family in ("cli", "desktop"):
        for platform in ("windows-10-x64", "windows-11-x64", "macos-13-x64", "macos-13-arm64"):
            assert f"{family}-{platform}" in rows
    assert set(CLI_ROWS) <= set(rows)
    assert set(DEB_ROWS) <= set(rows)
    assert rows["desktop-macos-13-arm64"].arch == "arm64"
    assert rows["cli-windows-10-x64"].baseline == "Windows 10 22H2"
    assert rows["cli-ubuntu-22.04-x64"].checks == (
        "verify-integrity",
        "version-help",
        "tui-boot-navigate",
        "mcp-stdio",
        "update-check-no-self-mutation",
        "native-terminal",
    )
    assert "voice-runtime" in rows["desktop-ubuntu-24.04-x64-wayland"].checks


def test_failure_links_may_only_point_at_this_repository(matrix) -> None:
    assert matrix.failure_link_prefixes == (
        "https://github.com/zb-ss/servonaut/issues/",
        "https://github.com/zb-ss/servonaut/actions/runs/",
    )


def test_committed_matrix_satisfies_its_schema() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(
        json.loads(DEFAULT_MATRIX.read_text(encoding="utf-8"))
    )
    row = schema["$defs"]["row"]["properties"]
    assert set(row["artifact_kind"]["enum"]) == {kind.value for kind in ArtifactKind}
    assert set(row["platform"]["enum"]) == SUPPORTED_PLATFORMS
    assert set(row["arch"]["enum"]) == SUPPORTED_ARCHITECTURES


def _matrix_document() -> dict[str, Any]:
    return json.loads(DEFAULT_MATRIX.read_text(encoding="utf-8"))


def _first_row(document: dict[str, Any]) -> dict[str, Any]:
    return document["rows"][0]


_SCHEMA_REFUSALS: dict[str, Callable[[dict[str, Any]], None]] = {
    "unknown-field": lambda doc: doc.update(notes="x"),
    "missing-field": lambda doc: doc.pop("failure_link_prefixes"),
    "schema-version": lambda doc: doc.update(schema_version=2),
    "boolean-version": lambda doc: doc.update(schema_version=True),
    "no-rows": lambda doc: doc.update(rows=[]),
    "unknown-row-field": lambda doc: _first_row(doc).update(notes="x"),
    "unknown-platform": lambda doc: _first_row(doc).update(platform="freebsd"),
    "unknown-arch": lambda doc: _first_row(doc).update(arch="riscv64"),
    "unknown-kind": lambda doc: _first_row(doc).update(artifact_kind="tarball"),
    "list-kind": lambda doc: _first_row(doc).update(artifact_kind=["standalone_cli"]),
    "row-id": lambda doc: _first_row(doc).update(row_id="Windows 10"),
    "baseline": lambda doc: _first_row(doc).update(baseline="Windows\n10"),
    "repeated-check": lambda doc: _first_row(doc).update(
        extra_checks=["native-arm64", "native-arm64"]
    ),
    "family-title": lambda doc: doc["families"]["cli"].update(title=""),
    "family-no-checks": lambda doc: doc["families"]["cli"].update(checks=[]),
    "check-description": lambda doc: doc["checks"].update({"version-help": "a\nb"}),
    "check-id": lambda doc: doc["checks"].update({"Bad Check": "text"}),
    "other-host": lambda doc: doc.update(
        failure_link_prefixes=["https://tracker.example.com/issues/"]
    ),
    "plain-http": lambda doc: doc.update(
        failure_link_prefixes=["http://github.com/zb-ss/servonaut/issues/"]
    ),
    "not-issues": lambda doc: doc.update(
        failure_link_prefixes=["https://github.com/zb-ss/servonaut/wiki/"]
    ),
    "no-trailing-slash": lambda doc: doc.update(
        failure_link_prefixes=["https://github.com/zb-ss/servonaut/issues"]
    ),
    "dot-segment": lambda doc: doc.update(
        failure_link_prefixes=["https://github.com/zb-ss/../issues/"]
    ),
    "newline-row-id": lambda doc: _first_row(doc).update(row_id="cli-windows-10-x64\n"),
    "newline-baseline": lambda doc: _first_row(doc).update(baseline="Windows 10\n"),
    "newline-family": lambda doc: _first_row(doc).update(family="cli\n"),
    "newline-title": lambda doc: doc["families"]["cli"].update(title="Standalone CLI\n"),
    "newline-description": lambda doc: doc["checks"].update({"version-help": "text\n"}),
    "newline-check-id": lambda doc: _first_row(doc).update(extra_checks=["native-arm64\n"]),
    "newline-prefix": lambda doc: doc.update(
        failure_link_prefixes=["https://github.com/zb-ss/servonaut/issues/\n"]
    ),
}


def _schema_errors(document: dict[str, Any]) -> list:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    return list(Draft202012Validator(schema).iter_errors(document))


@pytest.mark.parametrize("mutation", sorted(_SCHEMA_REFUSALS))
def test_loader_and_schema_refuse_the_same_malformed_matrix(
    tmp_path: Path, mutation: str
) -> None:
    document = _matrix_document()
    _SCHEMA_REFUSALS[mutation](document)
    assert _schema_errors(document)
    with pytest.raises(QualificationError) as raised:
        load_matrix(_write(tmp_path / "matrix.json", document))
    assert raised.value.code == MATRIX_INVALID


# Structurally valid variants that both the schema and the loader accept. The
# loader is authoritative: it also enforces what a schema cannot express
# (cross-references between checks, families and rows, and an integer
# version), so agreement is only expected on documents like these.
_VALID_VARIANTS: dict[str, Callable[[dict[str, Any]], None]] = {
    "new-row": lambda doc: doc["rows"].append(
        dict(
            copy.deepcopy(_first_row(doc)),
            row_id="cli-windows-12-x64",
            baseline="Windows 12",
        )
    ),
    "drop-a-row": lambda doc: doc.update(
        rows=[row for row in doc["rows"] if row["row_id"] != "cli-ubuntu-24.04-x64"]
    ),
    "new-check": lambda doc: (
        doc["checks"].update({"offline-start": "The app starts without a network."}),
        _first_row(doc)["extra_checks"].append("offline-start"),
    ),
    "new-family": lambda doc: (
        doc["families"].update(server={"title": "Server", "checks": ["version-help"]}),
        doc["rows"].append(
            dict(copy.deepcopy(_first_row(doc)), row_id="server-windows-10-x64", family="server")
        ),
    ),
    "no-extra-checks": lambda doc: next(
        row for row in doc["rows"] if row["row_id"] == "cli-macos-13-arm64"
    ).update(extra_checks=[]),
    "longest-labels": lambda doc: (
        _first_row(doc).update(baseline="W" * 64),
        doc["checks"].update({"version-help": "d" * 240}),
    ),
    "one-prefix": lambda doc: doc.update(
        failure_link_prefixes=["https://github.com/example-org/my.repo_name/issues/"]
    ),
}


@pytest.mark.parametrize("variant", sorted(_VALID_VARIANTS))
def test_loader_and_schema_accept_the_same_valid_matrix(
    tmp_path: Path, variant: str
) -> None:
    document = _matrix_document()
    _VALID_VARIANTS[variant](document)
    assert not _schema_errors(document)
    assert load_matrix(_write(tmp_path / "matrix.json", document)).rows


def test_the_loader_is_stricter_than_the_schema_on_the_version(tmp_path: Path) -> None:
    document = _matrix_document()
    document["schema_version"] = 1.0
    assert not _schema_errors(document)
    with pytest.raises(QualificationError) as raised:
        load_matrix(_write(tmp_path / "matrix.json", document))
    assert raised.value.code == MATRIX_INVALID


_CROSS_REFERENCE_REFUSALS: dict[str, Callable[[dict[str, Any]], None]] = {
    "undefined-check": lambda doc: _first_row(doc).update(extra_checks=["undefined"]),
    "unused-check": lambda doc: doc["checks"].update({"unused": "Never required."}),
    "undefined-family": lambda doc: _first_row(doc).update(family="server"),
    "unused-family": lambda doc: doc["families"].update(
        server={"title": "Server", "checks": ["version-help"]}
    ),
    "duplicate-row": lambda doc: doc["rows"].append(copy.deepcopy(_first_row(doc))),
    "repeats-family-check": lambda doc: _first_row(doc).update(
        extra_checks=["version-help"]
    ),
}


@pytest.mark.parametrize("mutation", sorted(_CROSS_REFERENCE_REFUSALS))
def test_matrix_cross_references_are_enforced(tmp_path: Path, mutation: str) -> None:
    document = _matrix_document()
    _CROSS_REFERENCE_REFUSALS[mutation](document)
    with pytest.raises(QualificationError) as raised:
        load_matrix(_write(tmp_path / "matrix.json", document))
    assert raised.value.code == MATRIX_INVALID


@pytest.mark.parametrize(
    "payload",
    [b"", b"not json", b"[]", b'{"schema_version": 1, "schema_version": 1}', b" " * 262_145],
)
def test_malformed_matrix_files_are_refused(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "matrix.json"
    path.write_bytes(payload)
    with pytest.raises(QualificationError) as raised:
        load_matrix(path)
    assert raised.value.code == MATRIX_INVALID


def test_missing_matrix_is_refused(tmp_path: Path) -> None:
    with pytest.raises(QualificationError) as raised:
        load_matrix(tmp_path / "absent.json")
    assert raised.value.code == MATRIX_INVALID


# --- Qualification record ---------------------------------------------------


def test_template_lists_every_applicable_row_untested(tmp_path: Path, matrix) -> None:
    evidence = _evidence(tmp_path, CLI_LINUX, DEB_LINUX)
    template = record_template(matrix, evidence)
    assert template["tag"] == "v2.27.0"
    assert template["candidate_digest"] == evidence["digest"]
    assert [entry["row_id"] for entry in template["rows"]] == [*CLI_ROWS, *DEB_ROWS]
    shas = {artifact["artifact_id"]: artifact["sha256"] for artifact in evidence["artifacts"]}
    for entry in template["rows"]:
        assert entry["artifact_sha256"] == shas[entry["artifact_id"]]
        assert entry["result"] == "untested"
        assert set(entry["checks"].values()) == {"untested"}
        assert entry["checks"].keys() == set(matrix.row(entry["row_id"]).checks)
    record = _record(tmp_path, matrix, template)
    assert len(record.entries) == 6


def test_stable_template_refuses_an_artifact_no_row_covers(
    tmp_path: Path, matrix, capsys
) -> None:
    evidence = _evidence(tmp_path, CLI_LINUX, UNCOVERED)
    with pytest.raises(QualificationError) as raised:
        record_template(matrix, evidence)
    assert raised.value.code == UNQUALIFIABLE_ARTIFACT
    out = tmp_path / "template.json"
    assert main(["template", *_files(tmp_path, evidence, None), "--out", str(out)]) == 1
    assert not out.exists()
    assert "::error::unqualifiable-artifact:" in capsys.readouterr().err


def test_preview_template_leaves_out_an_artifact_no_row_covers(
    tmp_path: Path, matrix, capsys
) -> None:
    evidence = _preview_evidence(tmp_path, CLI_LINUX, UNCOVERED)
    rows = record_template(matrix, evidence)["rows"]
    assert [entry["row_id"] for entry in rows] == list(CLI_ROWS)
    assert main(["template", *_files(tmp_path, evidence, None)]) == 0
    captured = capsys.readouterr()
    assert captured.err == (
        "::warning::1 candidate artifact(s) match no platform row"
        " and are left out of the template.\n"
    )
    assert json.loads(captured.out)["rows"] == rows


def test_a_fully_covered_template_warns_about_nothing(tmp_path: Path, capsys) -> None:
    evidence = _evidence(tmp_path, CLI_LINUX, DEB_LINUX)
    assert main(["template", *_files(tmp_path, evidence, None)]) == 0
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize(
    "artifact_id", ["servonaut cli linux", "cli-linux-x64-\u00fc", "x" * 256]
)
def test_printable_artifact_ids_round_trip(
    tmp_path: Path, matrix, artifact_id: str
) -> None:
    evidence = _evidence(tmp_path, artifact_ids=(artifact_id,))
    record = _record(tmp_path, matrix, _passing(matrix, evidence))
    assert {entry.artifact_id for entry in record.entries} == {artifact_id}
    evaluations = _stable(matrix, record, evidence)
    assert {item.status for item in evaluations} == {RowStatus.QUALIFIED}


def test_a_filled_record_loads(tmp_path: Path, matrix) -> None:
    evidence = _evidence(tmp_path)
    document = _passing(matrix, evidence)
    _fail(_entry(document, CLI_ROWS[1]))
    record = _record(tmp_path, matrix, document)
    assert record.tag == "v2.27.0"
    assert [entry.result.value for entry in record.entries] == ["pass", "fail"]


def _row(document: dict[str, Any]) -> dict[str, Any]:
    return document["rows"][0]


_RECORD_REFUSALS: dict[str, Callable[[dict[str, Any]], None]] = {
    "unknown-field": lambda doc: doc.update(notes="x"),
    "missing-field": lambda doc: doc.pop("candidate_digest"),
    "schema-version": lambda doc: doc.update(schema_version=2),
    "boolean-version": lambda doc: doc.update(schema_version=True),
    "tag": lambda doc: doc.update(tag="2.27.0"),
    "digest-case": lambda doc: doc.update(candidate_digest=doc["candidate_digest"].upper()),
    "digest-length": lambda doc: doc.update(candidate_digest="0" * 63),
    "rows-type": lambda doc: doc.update(rows={}),
    "too-many-rows": lambda doc: doc.update(rows=doc["rows"] * 257),
    "duplicate-row": lambda doc: doc["rows"].append(copy.deepcopy(_row(doc))),
    "unknown-row-field": lambda doc: _row(doc).update(notes="x"),
    "missing-row-field": lambda doc: _row(doc).pop("tester"),
    "unknown-row": lambda doc: _row(doc).update(row_id="cli-freebsd-14-x64"),
    "artifact-id-empty": lambda doc: _row(doc).update(artifact_id=""),
    "artifact-id-control": lambda doc: _row(doc).update(artifact_id="cli\nlinux"),
    "artifact-id-length": lambda doc: _row(doc).update(artifact_id="x" * 257),
    "artifact-id-type": lambda doc: _row(doc).update(artifact_id=["cli"]),
    "artifact-sha": lambda doc: _row(doc).update(artifact_sha256="abc"),
    "result": lambda doc: _row(doc).update(result="passed"),
    "check-result": lambda doc: _row(doc)["checks"].update({"version-help": "ok"}),
    "foreign-check": lambda doc: _row(doc)["checks"].update({"desktop-ux": "pass"}),
    "checks-type": lambda doc: _row(doc).update(checks=["version-help"]),
    "tester-email": lambda doc: _row(doc).update(tester="qa-1@example.com"),
    "tester-name": lambda doc: _row(doc).update(tester="QA Tester"),
    "tester-length": lambda doc: _row(doc).update(tester="q" * 65),
    "tester-missing": lambda doc: _row(doc).update(tester=None),
    "date-order": lambda doc: _row(doc).update(tested_on="20-09-2026"),
    "date-invalid": lambda doc: _row(doc).update(tested_on="2026-02-30"),
    "date-padding": lambda doc: _row(doc).update(tested_on="2026-9-1"),
    "date-time": lambda doc: _row(doc).update(tested_on="2026-09-20T10:00:00"),
    "image-missing": lambda doc: _row(doc).update(machine_image=None),
    "image-path": lambda doc: _row(doc).update(machine_image="/home/user/vm.img"),
    "image-length": lambda doc: _row(doc).update(machine_image="v" * 129),
    "pass-with-link": lambda doc: _row(doc).update(failure_link=ISSUE_LINK),
    "pass-with-failed-check": lambda doc: _row(doc)["checks"].update(
        {"version-help": "fail"}
    ),
    "pass-with-untested-check": lambda doc: _row(doc)["checks"].update(
        {"version-help": "untested"}
    ),
    "fail-without-link": lambda doc: _row(doc).update(result="fail"),
    "blocked-without-link": lambda doc: _row(doc).update(result="blocked"),
    "untested-with-details": lambda doc: _row(doc).update(result="untested"),
}

_FAILURE_LINK_REFUSALS = [
    "https://github.com/another/project/issues/12",
    "https://github.com/zb-ss/servonaut/issues/12/../../../another/project",
    "https://github.com/zb-ss/servonaut/issues/12?redirect=elsewhere",
    "https://github.com/zb-ss/servonaut/issues/",
    "https://github.com/zb-ss/servonaut/pull/12",
    "http://github.com/zb-ss/servonaut/issues/12",
    "https://github.com/zb-ss/servonaut/issues/12\n",
    "https://github.com/zb-ss/servonaut/actions/runs/1" + "0" * 300,
]


@pytest.mark.parametrize("mutation", sorted(_RECORD_REFUSALS))
def test_malformed_records_are_refused(
    tmp_path: Path, matrix, mutation: str
) -> None:
    document = _passing(matrix, _evidence(tmp_path))
    _RECORD_REFUSALS[mutation](document)
    with pytest.raises(QualificationError) as raised:
        _record(tmp_path, matrix, document)
    assert raised.value.code == RECORD_INVALID


@pytest.mark.parametrize("link", _FAILURE_LINK_REFUSALS)
def test_failure_links_outside_this_repository_are_refused(
    tmp_path: Path, matrix, link: str
) -> None:
    document = _passing(matrix, _evidence(tmp_path))
    _fail(_row(document))["failure_link"] = link
    with pytest.raises(QualificationError) as raised:
        _record(tmp_path, matrix, document)
    assert raised.value.code == RECORD_INVALID


@pytest.mark.parametrize(
    "link",
    [
        "https://github.com/zb-ss/servonaut/issues/12",
        "https://github.com/zb-ss/servonaut/issues/12#issuecomment-345",
        "https://github.com/zb-ss/servonaut/actions/runs/123456",
        "https://github.com/zb-ss/servonaut/actions/runs/123456/job/789",
    ],
)
def test_public_issue_and_run_links_are_accepted(
    tmp_path: Path, matrix, link: str
) -> None:
    document = _passing(matrix, _evidence(tmp_path))
    _fail(_row(document), result="blocked")["failure_link"] = link
    assert _record(tmp_path, matrix, document).entries[0].failure_link == link


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not json",
        b"[]",
        b'{"schema_version": 1, "schema_version": 1}',
        b"[" * 100_000,
        b" " * 1_000_001,
    ],
)
def test_malformed_record_files_are_refused(
    tmp_path: Path, matrix, payload: bytes
) -> None:
    path = tmp_path / "qualification-record.json"
    path.write_bytes(payload)
    with pytest.raises(QualificationError) as raised:
        load_record(path, matrix)
    assert raised.value.code == RECORD_INVALID


def test_a_duplicate_key_cannot_hide_a_recorded_value(tmp_path: Path, matrix) -> None:
    document = _passing(matrix, _evidence(tmp_path))
    text = json.dumps(document)
    path = tmp_path / "qualification-record.json"
    path.write_text(
        text.replace('"result": "pass"', '"result": "fail", "result": "pass"', 1),
        encoding="utf-8",
    )
    with pytest.raises(QualificationError) as raised:
        load_record(path, matrix)
    assert raised.value.code == RECORD_INVALID


def test_missing_record_is_refused(tmp_path: Path, matrix) -> None:
    with pytest.raises(QualificationError) as raised:
        load_record(tmp_path / "absent.json", matrix)
    assert raised.value.code == RECORD_INVALID


# --- Evaluation ---------------------------------------------------------------


def _statuses(evaluations) -> dict[str, tuple[RowStatus, Optional[str]]]:
    return {item.row.row_id: (item.status, item.reason) for item in evaluations}


def test_evaluate_reports_every_status(tmp_path: Path, matrix) -> None:
    evidence = _evidence(tmp_path, CLI_LINUX, DEB_LINUX)
    document = _passing(matrix, evidence)
    _fail(_entry(document, DEB_ROWS[0]))
    _fail(_entry(document, DEB_ROWS[1]), result="blocked")
    _entry(document, DEB_ROWS[2])["artifact_sha256"] = "0" * 64
    del _entry(document, DEB_ROWS[3])["checks"]["voice-runtime"]
    template = _entry(record_template(matrix, evidence), CLI_ROWS[1])
    document["rows"][1] = template
    statuses = _statuses(evaluate(matrix, _record(tmp_path, matrix, document), evidence))
    assert statuses == {
        CLI_ROWS[0]: (RowStatus.QUALIFIED, None),
        CLI_ROWS[1]: (RowStatus.MISSING, ROW_MISSING),
        DEB_ROWS[0]: (RowStatus.FAILED, ROW_FAILED),
        DEB_ROWS[1]: (RowStatus.FAILED, ROW_FAILED),
        DEB_ROWS[2]: (RowStatus.STALE, ROW_STALE),
        DEB_ROWS[3]: (RowStatus.MISSING, CHECK_MISSING),
    }


@pytest.mark.parametrize("field", ["tag", "candidate_digest"])
def test_a_record_for_another_candidate_is_stale(
    tmp_path: Path, matrix, field: str
) -> None:
    evidence = _evidence(tmp_path)
    document = _passing(matrix, evidence)
    document[field] = "v2.26.0" if field == "tag" else "f" * 64
    statuses = _statuses(evaluate(matrix, _record(tmp_path, matrix, document), evidence))
    assert set(statuses.values()) == {(RowStatus.STALE, ROW_STALE)}


def test_a_qualified_preview_carries_over_to_a_stable_candidate(
    tmp_path: Path, matrix
) -> None:
    preview = _preview_evidence(tmp_path, CLI_LINUX, DEB_LINUX)
    stable = _evidence(tmp_path, CLI_LINUX, DEB_LINUX)
    assert preview["digest"] == stable["digest"]
    record = _record(tmp_path, matrix, _passing(matrix, preview))
    assert record.tag == "v2.27.0-preview.2"
    evaluations = _stable(matrix, record, stable)
    assert {item.status for item in evaluations} == {RowStatus.QUALIFIED}
    assert len(supported_rows(matrix, record, stable)) == 6


@pytest.mark.parametrize(
    "tag", ["v2.26.0-preview.2", "v2.27.1-preview.1", "v2.26.0", "v2.27.1"]
)
def test_a_record_for_another_version_does_not_carry_over(
    tmp_path: Path, matrix, tag: str
) -> None:
    stable = _evidence(tmp_path)
    document = _passing(matrix, stable)
    document["tag"] = tag
    statuses = _statuses(evaluate(matrix, _record(tmp_path, matrix, document), stable))
    assert set(statuses.values()) == {(RowStatus.STALE, ROW_STALE)}


def test_a_preview_record_for_other_artifacts_does_not_carry_over(
    tmp_path: Path, matrix
) -> None:
    preview = _preview_evidence(tmp_path / "preview")
    rebuilt = _evidence(tmp_path / "rebuilt", CLI_LINUX, DEB_LINUX)
    assert preview["digest"] != rebuilt["digest"]
    record = _record(tmp_path, matrix, _passing(matrix, preview))
    with pytest.raises(QualificationError) as raised:
        _stable(matrix, record, rebuilt)
    assert raised.value.code == ROW_STALE


@pytest.mark.parametrize(
    "record_tag,candidate_tag",
    [("v2.27.0", "v2.27.0-preview.2"), ("v2.27.0-preview.1", "v2.27.0-preview.2")],
)
def test_other_tags_never_carry_over_to_a_preview(
    tmp_path: Path, matrix, record_tag: str, candidate_tag: str
) -> None:
    preview = _evidence(tmp_path, tag=candidate_tag, channel=ReleaseChannel.PREVIEW)
    document = _passing(matrix, preview)
    document["tag"] = record_tag
    record = _record(tmp_path, matrix, document)
    statuses = _statuses(_preview(matrix, record, preview))
    assert set(statuses.values()) == {(RowStatus.STALE, ROW_STALE)}


def test_test_dates_after_today_are_refused(tmp_path: Path, matrix) -> None:
    path = _write(tmp_path / "record.json", _passing(matrix, _evidence(tmp_path)))
    assert load_record(path, matrix, today=date(2026, 9, 20)).entries
    # A tester east of UTC can already be on the next calendar day.
    assert load_record(path, matrix, today=date(2026, 9, 19)).entries
    with pytest.raises(QualificationError) as raised:
        load_record(path, matrix, today=date(2026, 9, 18))
    assert raised.value.code == RECORD_INVALID


def test_the_command_line_refuses_a_test_date_in_the_future(
    tmp_path: Path, matrix, capsys
) -> None:
    evidence = _evidence(tmp_path)
    document = _passing(matrix, evidence)
    document["rows"][0]["tested_on"] = "2999-01-01"
    assert main(["check", *_files(tmp_path, evidence, document)]) == 1
    assert "::error::record-invalid:" in capsys.readouterr().err


def test_evaluating_without_a_record_reports_missing_rows(tmp_path: Path, matrix) -> None:
    statuses = _statuses(evaluate(matrix, None, _evidence(tmp_path)))
    assert statuses == {row: (RowStatus.MISSING, ROW_MISSING) for row in CLI_ROWS}


def test_evaluate_refuses_tampered_evidence(tmp_path: Path, matrix) -> None:
    evidence = _evidence(tmp_path)
    evidence["artifacts"][0]["arch"] = "arm64"
    with pytest.raises(CandidatePolicyError) as raised:
        evaluate(matrix, None, evidence)
    assert raised.value.code == "candidate-digest-mismatch"


# --- Stability gate -----------------------------------------------------------


def _stable(matrix, record, evidence):
    return ensure_qualified(matrix, record, evidence, channel=ReleaseChannel.STABLE)


def _preview(matrix, record, evidence):
    return ensure_qualified(matrix, record, evidence, channel=ReleaseChannel.PREVIEW)


def test_stable_accepts_a_fully_qualified_candidate(tmp_path: Path, matrix) -> None:
    evidence = _evidence(tmp_path, CLI_LINUX, DEB_LINUX)
    record = _record(tmp_path, matrix, _passing(matrix, evidence))
    evaluations = _stable(matrix, record, evidence)
    assert len(evaluations) == 6
    assert {item.status for item in evaluations} == {RowStatus.QUALIFIED}


def _gate_code(tmp_path: Path, matrix, change: Callable[[dict], None], *labels) -> str:
    evidence = _evidence(tmp_path, *labels)
    document = _passing(matrix, evidence)
    change(document)
    record = _record(tmp_path, matrix, document)
    with pytest.raises(QualificationError) as raised:
        _stable(matrix, record, evidence)
    return raised.value.code


@pytest.mark.parametrize(
    "labels",
    [(CLI_LINUX, UNCOVERED), ((ArtifactKind.MACOS_DMG, "linux", "x86_64"),)],
    ids=["uncovered-arch", "desktop-kind-on-wrong-platform"],
)
def test_stable_refuses_an_artifact_no_row_covers(
    tmp_path: Path, matrix, labels
) -> None:
    """Checked before any record is read: such an artifact can never qualify."""
    with pytest.raises(QualificationError) as raised:
        _stable(matrix, None, _evidence(tmp_path, *labels))
    assert raised.value.code == UNQUALIFIABLE_ARTIFACT


@pytest.mark.parametrize(
    "change,expected",
    [
        (lambda doc: doc["rows"].pop(), ROW_MISSING),
        (lambda doc: _fail(doc["rows"][1]), ROW_FAILED),
        (lambda doc: _fail(doc["rows"][1], result="blocked"), ROW_FAILED),
        (lambda doc: doc["rows"][1].update(artifact_sha256="0" * 64), ROW_STALE),
        (lambda doc: doc.update(tag="v2.26.0"), ROW_STALE),
        (lambda doc: doc["rows"][1]["checks"].pop("mcp-stdio"), CHECK_MISSING),
        (
            lambda doc: doc["rows"].append(_desktop_entry_for_cli_artifact(doc)),
            RECORD_INVALID,
        ),
        (
            lambda doc: doc["rows"][1].update(artifact_id="ubuntu_deb-linux-x86_64"),
            RECORD_INVALID,
        ),
    ],
)
def test_stable_refuses_each_unqualified_row(
    tmp_path: Path, matrix, change, expected: str
) -> None:
    assert _gate_code(tmp_path, matrix, change) == expected


def test_a_stable_gate_needs_at_least_one_binary_artifact(tmp_path: Path, matrix) -> None:
    """A PyPI-only release cannot pass the gate: evidence needs an artifact."""
    evidence = _evidence(tmp_path)
    evidence["artifacts"] = []
    evidence["digest"] = candidate_digest(())
    with pytest.raises(CandidatePolicyError) as raised:
        _stable(matrix, None, evidence)
    assert raised.value.code == "evidence-invalid"


def test_stable_refuses_a_missing_record(tmp_path: Path, matrix) -> None:
    with pytest.raises(QualificationError) as raised:
        _stable(matrix, None, _evidence(tmp_path))
    assert raised.value.code == ROW_MISSING


def test_stable_refuses_an_untested_template(tmp_path: Path, matrix) -> None:
    evidence = _evidence(tmp_path)
    record = _record(tmp_path, matrix, record_template(matrix, evidence))
    with pytest.raises(QualificationError) as raised:
        _stable(matrix, record, evidence)
    assert raised.value.code == ROW_MISSING


def test_stable_failure_lists_every_unqualified_row(tmp_path: Path, matrix) -> None:
    evidence = _evidence(tmp_path, CLI_LINUX, DEB_LINUX)
    document = _passing(matrix, evidence)
    _fail(_entry(document, DEB_ROWS[3]))
    del _entry(document, CLI_ROWS[1])["checks"]["native-terminal"]
    with pytest.raises(QualificationError) as raised:
        _stable(matrix, _record(tmp_path, matrix, document), evidence)
    assert raised.value.code == CHECK_MISSING
    assert [(item.row.row_id, item.reason) for item in raised.value.failures] == [
        (CLI_ROWS[1], CHECK_MISSING),
        (DEB_ROWS[3], ROW_FAILED),
    ]


def test_a_failing_desktop_row_does_not_block_a_cli_only_candidate(
    tmp_path: Path, matrix
) -> None:
    """Dropping the failing artifact from the candidate keeps the CLI stable."""
    with_desktop = _evidence(tmp_path / "both", CLI_LINUX, DEB_LINUX)
    document = _passing(matrix, with_desktop)
    _fail(_entry(document, DEB_ROWS[0]))
    with pytest.raises(QualificationError):
        _stable(matrix, _record(tmp_path, matrix, document), with_desktop)

    cli_only = _evidence(tmp_path / "cli", CLI_LINUX)
    record = _record(tmp_path, matrix, _passing(matrix, cli_only))
    assert _stable(matrix, record, cli_only)


def test_stable_never_accepts_preview_evidence(tmp_path: Path, matrix) -> None:
    evidence = _evidence(
        tmp_path, tag="v2.27.0-preview.1", channel=ReleaseChannel.PREVIEW
    )
    record = _record(tmp_path, matrix, _passing(matrix, evidence))
    with pytest.raises(CandidatePolicyError) as raised:
        _stable(matrix, record, evidence)
    assert raised.value.code == "candidate-channel-mismatch"
    with pytest.raises(CandidatePolicyError):
        _preview(matrix, record, _evidence(tmp_path / "stable"))


def _preview_evidence(tmp_path: Path, *labels) -> dict[str, Any]:
    return _evidence(
        tmp_path, *labels, tag="v2.27.0-preview.2", channel=ReleaseChannel.PREVIEW
    )


def test_preview_requires_no_passes(tmp_path: Path, matrix) -> None:
    evidence = _preview_evidence(tmp_path, CLI_LINUX, UNCOVERED)
    document = record_template(matrix, evidence)
    _fail(document["rows"][0])
    record = _record(tmp_path, matrix, document)
    statuses = _statuses(_preview(matrix, record, evidence))
    assert statuses[CLI_ROWS[0]] == (RowStatus.FAILED, ROW_FAILED)
    assert statuses[CLI_ROWS[1]] == (RowStatus.MISSING, ROW_MISSING)
    assert _preview(matrix, None, evidence)


def test_preview_accepts_a_stale_record(tmp_path: Path, matrix) -> None:
    evidence = _preview_evidence(tmp_path)
    document = _passing(matrix, evidence)
    document["candidate_digest"] = "f" * 64
    statuses = _statuses(_preview(matrix, _record(tmp_path, matrix, document), evidence))
    assert set(statuses.values()) == {(RowStatus.STALE, ROW_STALE)}


def test_preview_still_validates_a_present_record(tmp_path: Path, matrix) -> None:
    evidence = _preview_evidence(tmp_path)
    document = _passing(matrix, evidence)
    document["rows"][0] = _desktop_entry_for_cli_artifact(document)
    record = _record(tmp_path, matrix, document)
    with pytest.raises(QualificationError) as raised:
        _preview(matrix, record, evidence)
    assert raised.value.code == RECORD_INVALID


def test_supported_rows_are_only_the_qualified_ones(tmp_path: Path, matrix) -> None:
    evidence = _evidence(tmp_path, CLI_LINUX, DEB_LINUX)
    document = _passing(matrix, evidence)
    _fail(_entry(document, DEB_ROWS[1]))
    rows = supported_rows(matrix, _record(tmp_path, matrix, document), evidence)
    assert [item.row.row_id for item in rows] == [
        *CLI_ROWS,
        DEB_ROWS[0],
        DEB_ROWS[2],
        DEB_ROWS[3],
    ]
    assert supported_rows(matrix, None, evidence) == ()


# --- Summary --------------------------------------------------------------------


def test_summary_lists_passing_rows_from_policy_and_evidence_only(
    tmp_path: Path, matrix
) -> None:
    evidence = _evidence(tmp_path, CLI_LINUX, DEB_LINUX)
    document = _passing(matrix, evidence)
    _fail(_entry(document, DEB_ROWS[1]))
    text = summarize(matrix, _record(tmp_path, matrix, document), evidence)
    lines = text.splitlines()
    assert lines[0] == "| Platform | Family | Architecture | Artifact | Tested on |"
    assert len(lines) == 2 + 5
    artifact = "servonaut\\-0\\_standalone\\_cli\\.bin"
    assert f"| Ubuntu 22.04 | Standalone CLI | x86_64 | {artifact} | 2026-09-20 |" in lines
    assert "Ubuntu 22.04 (Wayland)" not in text
    assert "qa-1" not in text
    assert "Clean VM" not in text


def test_summary_without_qualified_rows_says_so(tmp_path: Path, matrix) -> None:
    evidence = _evidence(tmp_path)
    assert summarize(matrix, None, evidence) == (
        "No platform rows are qualified for this candidate.\n"
    )


def test_summary_escapes_artifact_file_names(tmp_path: Path, matrix) -> None:
    evidence = _evidence(tmp_path)
    evidence["artifacts"][0]["filename"] = "[x](https://example.com)|`<b>`.zip"
    evidence["digest"] = candidate_digest(candidate_from_evidence(evidence).artifacts)
    record = _record(tmp_path, matrix, _passing(matrix, evidence))
    text = summarize(matrix, record, evidence)
    assert "\\[x\\]\\(https\\:\\/\\/example\\.com\\)\\|\\`\\<b\\>\\`\\.zip" in text


# --- Command line -----------------------------------------------------------------


def _files(tmp_path: Path, evidence: dict[str, Any], record: Optional[dict]) -> list[str]:
    evidence_path = tmp_path / "candidate-evidence.json"
    evidence_path.write_bytes(canonicalize_json(evidence) + b"\n")
    argv = ["--evidence", str(evidence_path)]
    if record is not None:
        argv += ["--record", str(_write(tmp_path / "qualification-record.json", record))]
    return argv


def test_cli_template_writes_a_loadable_record(tmp_path: Path, matrix, capsys) -> None:
    evidence = _evidence(tmp_path, CLI_LINUX, DEB_LINUX)
    out = tmp_path / "template.json"
    assert main(["template", *_files(tmp_path, evidence, None), "--out", str(out)]) == 0
    assert len(load_record(out, matrix).entries) == 6
    assert main(["template", *_files(tmp_path, evidence, None)]) == 0
    assert json.loads(capsys.readouterr().out) == json.loads(out.read_text())


def test_cli_check_passes_a_qualified_stable_candidate(
    tmp_path: Path, matrix, capsys
) -> None:
    evidence = _evidence(tmp_path)
    argv = _files(tmp_path, evidence, _passing(matrix, evidence))
    assert main(["check", *argv, "--channel", "stable"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "channel=stable",
        "rows=2",
        "qualified=2",
    ]


def test_cli_check_defaults_to_the_stable_channel(tmp_path: Path, matrix) -> None:
    evidence = _evidence(tmp_path)
    assert main(["check", *_files(tmp_path, evidence, record_template(matrix, evidence))]) == 1


def test_cli_check_reports_codes_and_matrix_rows_only(
    tmp_path: Path, matrix, capsys
) -> None:
    evidence = _evidence(tmp_path)
    document = _passing(matrix, evidence)
    _fail(document["rows"][1])
    assert main(["check", *_files(tmp_path, evidence, document)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "::error::row-failed: A stable release needs every applicable platform row to pass.",
        f"::error::row-failed: {CLI_ROWS[1]}",
    ]


def test_cli_never_echoes_record_contents(tmp_path: Path, matrix, capsys) -> None:
    evidence = _evidence(tmp_path)
    document = _passing(matrix, evidence)
    marker = "qa-1@example.com"
    document["rows"][0]["tester"] = marker
    assert main(["check", *_files(tmp_path, evidence, document)]) == 1
    captured = capsys.readouterr()
    assert "::error::record-invalid:" in captured.err
    assert marker not in captured.err + captured.out


def test_cli_check_refuses_a_missing_record(tmp_path: Path, capsys) -> None:
    argv = _files(tmp_path, _evidence(tmp_path), None)
    assert main(["check", *argv, "--record", str(tmp_path / "absent.json")]) == 1
    assert "::error::record-invalid:" in capsys.readouterr().err


def test_cli_check_requires_a_record_argument(tmp_path: Path, capsys) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["check", *_files(tmp_path, _evidence(tmp_path), None)])
    assert raised.value.code == 2
    assert "--record" in capsys.readouterr().err


def test_cli_preview_check_validates_an_untested_template(
    tmp_path: Path, matrix, capsys
) -> None:
    evidence = _preview_evidence(tmp_path)
    argv = _files(tmp_path, evidence, record_template(matrix, evidence))
    assert main(["check", *argv, "--channel", "preview"]) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "qualified=0"


def test_cli_refuses_malformed_evidence(tmp_path: Path, matrix, capsys) -> None:
    evidence = _evidence(tmp_path)
    record = _passing(matrix, evidence)
    evidence["schema_version"] = 2
    assert main(["check", *_files(tmp_path, evidence, record)]) == 1
    assert "::error::evidence-invalid:" in capsys.readouterr().err


def test_cli_summarize_prints_the_passing_rows(tmp_path: Path, matrix, capsys) -> None:
    evidence = _evidence(tmp_path)
    document = _passing(matrix, evidence)
    _fail(document["rows"][0])
    assert main(["summarize", *_files(tmp_path, evidence, document)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 3
    assert lines[2].startswith("| Ubuntu 24.04 | Standalone CLI | x86_64 |")


def test_cli_summarize_refuses_a_malformed_record(tmp_path: Path, matrix, capsys) -> None:
    evidence = _evidence(tmp_path)
    document = _passing(matrix, evidence)
    document["rows"][0] = _desktop_entry_for_cli_artifact(document)
    assert main(["summarize", *_files(tmp_path, evidence, document)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "::error::record-invalid:" in captured.err


def test_cli_uses_an_explicit_matrix(tmp_path: Path, matrix, capsys) -> None:
    document = _matrix_document()
    document["rows"] = [row for row in document["rows"] if row["row_id"] != CLI_ROWS[1]]
    document["checks"].pop("frozen-payload-compat")
    for row in document["rows"]:
        row["extra_checks"] = [
            check for check in row["extra_checks"] if check != "frozen-payload-compat"
        ]
    custom = _write(tmp_path / "matrix.json", document)
    evidence = _evidence(tmp_path)
    argv = _files(tmp_path, evidence, None)
    assert main(["template", *argv, "--matrix", str(custom)]) == 0
    rows = json.loads(capsys.readouterr().out)["rows"]
    assert [row["row_id"] for row in rows] == [CLI_ROWS[0]]
