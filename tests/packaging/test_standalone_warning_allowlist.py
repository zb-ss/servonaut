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


def _warning(module: str, facts: dict[str, str]) -> dict[str, object]:
    record: dict[str, object] = {
        "code": "missing-module",
        "module": module,
        "importers": [{"module": "client", "qualifiers": ["optional"]}],
        "target_facts": facts,
        "collection_facts": {"preamble_sha256": "4" * 64},
    }
    return {**record, "fingerprint": _fingerprint(record)}


def _approval(module: str) -> dict[str, object]:
    return {
        **_warning(module, _OLD_FACTS),
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


def _refresh(allowlist: Path, candidates: Path) -> int:
    return main(
        [
            "--target",
            _TARGET,
            "--candidates",
            str(candidates),
            "--allowlist",
            str(allowlist),
        ]
    )


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
