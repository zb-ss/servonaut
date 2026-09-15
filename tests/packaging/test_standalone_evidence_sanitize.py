"""Public evidence sanitisation and bounded-file boundary tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from scripts.standalone_cli.artifact_types import ArtifactEvidenceError
from scripts.standalone_cli.evidence_sanitize import (
    encode_public_json,
    load_bounded_json,
    write_public_json,
)


@pytest.mark.parametrize(
    "unsafe",
    (
        "/tmp/example/build/output.bin",
        "C:\\Users\\example\\build\\output.bin",
        "file:///tmp/archive.whl",
        "http://example.invalid/project",
        "https://user:" + "password" + "@" + "example.invalid/project",
        "https://example.invalid/project?access_token=value",
        "-----BEGIN " + "PRIVATE KEY-----",
        "AK" + "IA" + "ABCDEFGHIJKLMNOP",
    ),
)
def test_public_json_rejects_local_paths_unsafe_urls_and_credentials(
    tmp_path: Path, unsafe: str
) -> None:
    forbidden = tmp_path / "private-build"
    forbidden.mkdir()

    with pytest.raises(ArtifactEvidenceError, match="rejected"):
        encode_public_json(
            {"value": unsafe},
            "report.json",
            forbidden_roots=(forbidden,),
            max_bytes=4096,
        )


def test_public_json_is_canonical_and_refuses_overwrite(tmp_path: Path) -> None:
    forbidden = tmp_path / "private-build"
    forbidden.mkdir()
    destination = tmp_path / "report.json"
    document = {
        "url": "https://example.invalid/project",
        "purl": "pkg:pypi/example@1.2.3",
        "items": [2, 1],
    }

    written = write_public_json(
        destination,
        document,
        forbidden_roots=(forbidden,),
        max_bytes=4096,
    )

    assert written == destination
    assert destination.read_bytes() == (
        b'{"items":[2,1],"purl":"pkg:pypi/example@1.2.3",'
        b'"url":"https://example.invalid/project"}\n'
    )
    with pytest.raises(ArtifactEvidenceError):
        write_public_json(
            destination,
            {"replacement": True},
            forbidden_roots=(forbidden,),
            max_bytes=4096,
        )
    assert json.loads(destination.read_text(encoding="utf-8")) == document


def test_bounded_json_rejects_duplicate_fields_symlinks_and_oversize(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"value":1,"value":2}', encoding="utf-8")
    with pytest.raises(ArtifactEvidenceError, match="duplicate"):
        load_bounded_json(duplicate, "fixture", 1024)

    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    alias = tmp_path / "alias.json"
    alias.symlink_to(target)
    with pytest.raises(ArtifactEvidenceError, match="regular file"):
        load_bounded_json(alias, "fixture", 1024)

    oversized = tmp_path / "oversized.json"
    oversized.write_text('{"value":"long"}', encoding="utf-8")
    with pytest.raises(ArtifactEvidenceError, match="size limit"):
        load_bounded_json(oversized, "fixture", 4)


def test_public_write_failure_removes_only_its_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forbidden = tmp_path / "private-build"
    forbidden.mkdir()
    destination = tmp_path / "report.json"

    def fail_sync(_descriptor: int) -> None:
        raise OSError("simulated write failure")

    monkeypatch.setattr(os, "fsync", fail_sync)
    with pytest.raises(ArtifactEvidenceError, match="could not be written"):
        write_public_json(
            destination,
            {"value": "safe"},
            forbidden_roots=(forbidden,),
            max_bytes=4096,
        )
    assert not destination.exists()
