"""Refreshing reviewed PyInstaller warning approvals for new target facts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.standalone_cli.evidence_policy import (
    _TARGET_NAMES,
    _classify_warnings,
    _fingerprint,
)
from scripts.standalone_cli.warning_allowlist import main

_TARGET = "linux-x64-ubuntu-22.04"
_OLD_FACTS = {"target": _TARGET, "lock_sha256": "1" * 64, "toolchain_sha256": "2" * 64}
_NEW_FACTS = {"target": _TARGET, "lock_sha256": "1" * 64, "toolchain_sha256": "3" * 64}


_CLIENT = {"module": "client", "qualifiers": ["optional"]}
_WORKER = {"module": "desktop_worker", "qualifiers": ["optional"]}
_GUARDED = {"module": "guarded_client", "qualifiers": ["conditional"]}


def _warning(
    module: str,
    facts: dict[str, str],
    importers: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "code": "missing-module",
        "module": module,
        "importers": importers or [_CLIENT],
        "target_facts": facts,
        "collection_facts": {"preamble_sha256": "4" * 64},
    }
    return {**record, "fingerprint": _fingerprint(record)}


def _approval(
    module: str, importers: list[dict[str, object]] | None = None
) -> dict[str, object]:
    return {
        **_warning(module, _OLD_FACTS, importers),
        "classification": {
            "optional": True,
            "conditional": False,
            "collected": False,
            "origin_class": "hook-or-source",
        },
        "reason": f"Reviewed optional import of {module}.",
        "expires_on": "2999-01-01",
    }


def _write_allowlist(tmp_path: Path, entries: list[dict[str, object]]) -> Path:
    targets = {name: [] for name in sorted(_TARGET_NAMES)}
    targets["windows-x64"] = [_approval("windows_only")]
    targets[_TARGET] = entries
    path = tmp_path / "warnings-allowlist.json"
    path.write_text(
        json.dumps({"schema_version": 1, "targets": targets}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return path


def _write_candidates(tmp_path: Path, candidates: list[dict[str, object]]) -> Path:
    path = tmp_path / "warning-candidates.json"
    path.write_text(
        json.dumps({"schema_version": 1, "candidates": candidates}), encoding="utf-8"
    )
    return path


def _write_report(
    tmp_path: Path,
    *,
    approved: list[dict[str, object]],
    unknown: list[dict[str, object]],
    stale: list[dict[str, object]],
) -> Path:
    path = tmp_path / "warnings.json"
    report = {
        "schema_version": 1,
        "approved": approved,
        "unknown": unknown,
        "stale": stale,
        "counts": {
            "approved": len(approved),
            "unknown": len(unknown),
            "stale": len(stale),
        },
        "collection_facts": {
            "preamble_sha256": "4" * 64,
            "record_count": len(approved) + len(unknown),
        },
    }
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _refresh(allowlist: Path, candidates: Path, *extra: str) -> int:
    return main(
        [
            "--target",
            _TARGET,
            "--candidates",
            str(candidates),
            "--allowlist",
            str(allowlist),
            *extra,
        ]
    )


def _prune(allowlist: Path, candidates: Path, report: Path) -> int:
    return _refresh(allowlist, candidates, "--prune-stale", "--warnings", str(report))


def test_refresh_moves_reviewed_approvals_to_the_new_target_facts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    allowlist = _write_allowlist(
        tmp_path, [_approval("optional_a"), _approval("optional_b"), _approval("kept")]
    )
    candidates = [
        _warning("optional_a", _NEW_FACTS),
        _warning("optional_b", _NEW_FACTS),
    ]
    before = json.loads(allowlist.read_text(encoding="utf-8"))

    assert _refresh(allowlist, _write_candidates(tmp_path, candidates)) == 0

    output = capsys.readouterr()
    assert output.out == "refreshed 2 warning approvals; 1 unchanged\n"
    assert "optional_a" not in output.out + output.err
    raw = allowlist.read_text(encoding="utf-8")
    after = json.loads(raw)
    assert raw == json.dumps(after, indent=2, sort_keys=True) + "\n"
    assert after["targets"]["windows-x64"] == before["targets"]["windows-x64"]
    entries = after["targets"][_TARGET]
    assert [entry["fingerprint"] for entry in entries] == sorted(
        entry["fingerprint"] for entry in entries
    )
    by_module = {entry["module"]: entry for entry in entries}
    assert by_module["kept"] == _approval("kept")
    for module in ("optional_a", "optional_b"):
        reviewed = _approval(module)
        assert by_module[module]["target_facts"] == _NEW_FACTS
        for field in ("classification", "reason", "expires_on"):
            assert by_module[module][field] == reviewed[field]
    approved, unknown, stale = _classify_warnings(
        candidates, [by_module["optional_a"], by_module["optional_b"]]
    )
    assert (len(approved), unknown, stale) == (2, [], [])


def test_refresh_refuses_warnings_without_a_reviewed_approval(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    allowlist = _write_allowlist(tmp_path, [_approval("optional_a")])
    original = allowlist.read_bytes()
    candidates = _write_candidates(
        tmp_path,
        [_warning("optional_a", _NEW_FACTS), _warning("brand_new", _NEW_FACTS)],
    )

    assert _refresh(allowlist, candidates) == 1

    output = capsys.readouterr()
    assert "1 warning candidates have no reviewed approval" in output.err
    assert "brand_new" not in output.out + output.err
    assert allowlist.read_bytes() == original


@pytest.mark.parametrize(
    "candidates",
    (
        [{**_warning("optional_a", _NEW_FACTS), "fingerprint": "5" * 64}],
        [_warning("optional_a", {**_NEW_FACTS, "target": "windows-x64"})],
        [
            _warning("optional_a", _NEW_FACTS),
            _warning("optional_b", {**_NEW_FACTS, "lock_sha256": "6" * 64}),
        ],
        [_warning("optional_a", _NEW_FACTS), _warning("optional_a", _NEW_FACTS)],
    ),
    ids=("tampered-fingerprint", "other-target", "mixed-runs", "repeated-warning"),
)
def test_refresh_rejects_inconsistent_candidates(
    tmp_path: Path, candidates: list[dict[str, object]]
) -> None:
    allowlist = _write_allowlist(
        tmp_path, [_approval("optional_a"), _approval("optional_b")]
    )
    original = allowlist.read_bytes()

    assert _refresh(allowlist, _write_candidates(tmp_path, candidates)) == 1
    assert allowlist.read_bytes() == original


def test_prune_stale_keeps_current_approvals_the_candidates_do_not_list(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Candidates omit approved warnings, so only the run's stale list is pruned."""
    narrowed = _warning("audio", _OLD_FACTS, [_CLIENT])
    reviewed_audio = _approval("audio", [_CLIENT, _WORKER])
    disappeared = _approval("worker_only", [_WORKER])
    allowlist = _write_allowlist(
        tmp_path,
        [_approval("kept_a"), _approval("kept_b"), reviewed_audio, disappeared],
    )
    before = json.loads(allowlist.read_text(encoding="utf-8"))
    current = [_warning("kept_a", _OLD_FACTS), _warning("kept_b", _OLD_FACTS)]
    report = _write_report(
        tmp_path,
        approved=current,
        unknown=[narrowed],
        stale=[reviewed_audio, disappeared],
    )

    assert _prune(allowlist, _write_candidates(tmp_path, [narrowed]), report) == 0

    output = capsys.readouterr()
    assert output.out == (
        "refreshed 0 warning approvals; 2 unchanged; "
        "1 narrowed to fewer importers; 1 stale pruned\n"
    )
    assert "audio" not in output.out + output.err
    after = json.loads(allowlist.read_text(encoding="utf-8"))
    assert after["targets"]["windows-x64"] == before["targets"]["windows-x64"]
    by_module = {entry["module"]: entry for entry in after["targets"][_TARGET]}
    assert set(by_module) == {"kept_a", "kept_b", "audio"}
    assert by_module["kept_a"] == _approval("kept_a")
    assert by_module["audio"]["importers"] == [_CLIENT]
    assert by_module["audio"]["fingerprint"] == narrowed["fingerprint"]
    for field in ("classification", "reason", "expires_on"):
        assert by_module["audio"][field] == reviewed_audio[field]
    approved, unknown, stale = _classify_warnings(
        [*current, narrowed], after["targets"][_TARGET]
    )
    assert (len(approved), unknown, stale) == (3, [], [])


def test_prune_stale_refreshes_moved_facts_and_drops_unobserved_approvals(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    reviewed = [_approval("optional_a"), _approval("optional_b"), _approval("gone")]
    allowlist = _write_allowlist(tmp_path, reviewed)
    candidates = [_warning("optional_a", _NEW_FACTS), _warning("optional_b", _NEW_FACTS)]
    report = _write_report(tmp_path, approved=[], unknown=candidates, stale=reviewed)

    assert _prune(allowlist, _write_candidates(tmp_path, candidates), report) == 0

    assert capsys.readouterr().out == (
        "refreshed 2 warning approvals; 0 unchanged; "
        "0 narrowed to fewer importers; 1 stale pruned\n"
    )
    entries = json.loads(allowlist.read_text(encoding="utf-8"))["targets"][_TARGET]
    assert {entry["module"] for entry in entries} == {"optional_a", "optional_b"}
    approved, unknown, stale = _classify_warnings(candidates, entries)
    assert (len(approved), unknown, stale) == (2, [], [])


@pytest.mark.parametrize(
    ("reviewed_importers", "observed_importers"),
    (
        ([_CLIENT], [_CLIENT, _WORKER]),
        ([_CLIENT, _GUARDED], [_CLIENT]),
        ([_CLIENT, _WORKER], [{"module": "client", "qualifiers": ["delayed"]}]),
    ),
    ids=("gained-importer", "lost-qualifier", "changed-qualifier"),
)
def test_prune_stale_refuses_a_warning_that_is_not_a_pure_narrowing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    reviewed_importers: list[dict[str, object]],
    observed_importers: list[dict[str, object]],
) -> None:
    reviewed = _approval("audio", reviewed_importers)
    allowlist = _write_allowlist(tmp_path, [reviewed])
    original = allowlist.read_bytes()
    observed = _warning("audio", _OLD_FACTS, observed_importers)
    report = _write_report(tmp_path, approved=[], unknown=[observed], stale=[reviewed])

    assert _prune(allowlist, _write_candidates(tmp_path, [observed]), report) == 1

    output = capsys.readouterr()
    assert "1 warning candidates have no reviewed approval" in output.err
    assert "audio" not in output.out + output.err
    assert allowlist.read_bytes() == original


@pytest.mark.parametrize(
    "report_change",
    ("other-run", "edited-approval", "invalid-report"),
)
def test_prune_stale_refuses_a_report_that_does_not_match_the_inputs(
    tmp_path: Path, report_change: str
) -> None:
    reviewed = _approval("gone")
    allowlist = _write_allowlist(tmp_path, [_approval("kept"), reviewed])
    original = allowlist.read_bytes()
    unknown: list[dict[str, object]] = []
    stale = [reviewed]
    if report_change == "other-run":
        unknown = [_warning("elsewhere", _OLD_FACTS)]
    elif report_change == "edited-approval":
        stale = [{**reviewed, "reason": "Different review."}]
    report = _write_report(tmp_path, approved=[], unknown=unknown, stale=stale)
    if report_change == "invalid-report":
        report.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")

    assert _prune(allowlist, _write_candidates(tmp_path, []), report) == 1
    assert allowlist.read_bytes() == original


@pytest.mark.parametrize(
    "extra",
    (("--prune-stale",), ("--warnings", "warnings.json")),
    ids=("prune-without-report", "report-without-prune"),
)
def test_prune_stale_and_its_report_are_required_together(
    tmp_path: Path, extra: tuple[str, ...]
) -> None:
    allowlist = _write_allowlist(tmp_path, [_approval("kept")])
    original = allowlist.read_bytes()

    with pytest.raises(SystemExit) as error:
        _refresh(allowlist, _write_candidates(tmp_path, []), *extra)

    assert error.value.code == 2
    assert allowlist.read_bytes() == original
