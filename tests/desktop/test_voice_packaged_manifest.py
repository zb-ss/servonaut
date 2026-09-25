"""Tests for the strict loader of the bundled voice-runtime manifest."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from servonaut.desktop.voice.packaged_manifest import (
    BundledFile,
    PackagedVoiceManifest,
    PackagedVoiceManifestError,
    ProvisionTimeouts,
    load_packaged_manifest,
    parse_packaged_manifest,
)

VALID: dict[str, Any] = {
    "schema_version": 1,
    "target": "linux-x64",
    "python_version": "3.12.7",
    "uv": {"filename": "uv", "sha256": "a" * 64},
    "wheel": {"filename": "servonaut-2.30.0-py3-none-any.whl", "sha256": "b" * 64},
    "requirements": {"filename": "voice-requirements.txt", "sha256": "c" * 64},
    "timeouts": {"uv_command_seconds": 600, "stall_seconds": 120, "provision_seconds": 3600},
}


def _encode(document: object) -> bytes:
    return json.dumps(document).encode("utf-8")


def _with(path: tuple[str, ...], value: object) -> dict[str, Any]:
    document = copy.deepcopy(VALID)
    target = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return document


def _without(path: tuple[str, ...]) -> dict[str, Any]:
    document = copy.deepcopy(VALID)
    target = document
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]
    return document


def test_valid_manifest_parses_to_frozen_dataclasses() -> None:
    manifest = parse_packaged_manifest(_encode(VALID))

    assert manifest == PackagedVoiceManifest(
        schema_version=1,
        target="linux-x64",
        python_version="3.12.7",
        uv=BundledFile("uv", "a" * 64),
        wheel=BundledFile("servonaut-2.30.0-py3-none-any.whl", "b" * 64),
        requirements=BundledFile("voice-requirements.txt", "c" * 64),
        timeouts=ProvisionTimeouts(
            uv_command_seconds=600, stall_seconds=120, provision_seconds=3600
        ),
    )
    with pytest.raises(AttributeError):
        manifest.target = "other"  # type: ignore[misc]


def test_load_reads_the_file(tmp_path: Path) -> None:
    path = tmp_path / "voice-runtime.json"
    path.write_bytes(_encode(VALID))

    assert load_packaged_manifest(path).target == "linux-x64"


def test_load_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PackagedVoiceManifestError, match="could not be read"):
        load_packaged_manifest(tmp_path / "voice-runtime.json")


def test_load_rejects_an_oversized_file(tmp_path: Path) -> None:
    path = tmp_path / "voice-runtime.json"
    path.write_bytes(b" " * (64 * 1024) + _encode(VALID))

    with pytest.raises(PackagedVoiceManifestError, match="too large"):
        load_packaged_manifest(path)


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"\xff\xfe",
        b"[]",
        b'{"schema_version": 1, "schema_version": 1}',
        b'{"schema_version": NaN}',
    ],
)
def test_malformed_documents_are_rejected(raw: bytes) -> None:
    with pytest.raises(PackagedVoiceManifestError):
        parse_packaged_manifest(raw)


@pytest.mark.parametrize(
    "document",
    [
        _without(("target",)),
        {**VALID, "extra": 1},
        _without(("uv", "sha256")),
        _with(("wheel", "size"), 1),
        _without(("timeouts", "stall_seconds")),
        _with(("timeouts", "retries"), 3),
    ],
)
def test_keys_must_match_exactly(document: dict[str, Any]) -> None:
    with pytest.raises(PackagedVoiceManifestError, match="keys"):
        parse_packaged_manifest(_encode(document))


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("schema_version",), 2),
        (("schema_version",), True),
        (("schema_version",), "1"),
        (("target",), ""),
        (("target",), "linux/x64"),
        (("python_version",), "3.12"),
        (("python_version",), "3.12.07"),
        (("python_version",), "3.12.7rc1"),
        (("python_version",), 3.12),
        (("uv", "sha256"), "A" * 64),
        (("uv", "sha256"), "a" * 63),
        (("uv", "filename"), "../uv"),
        (("uv", "filename"), "bin/uv"),
        (("uv", "filename"), "-uv"),
        (("wheel", "filename"), "servonaut.tar.gz"),
        (("requirements", "filename"), "requirements.txt"),
        (("uv",), "uv"),
        (("timeouts",), [600, 120, 3600]),
        (("timeouts", "stall_seconds"), 0),
        (("timeouts", "stall_seconds"), -1),
        (("timeouts", "stall_seconds"), 1.5),
        (("timeouts", "stall_seconds"), True),
        (("timeouts", "provision_seconds"), 10**9),
        (("timeouts", "stall_seconds"), 700),
        (("timeouts", "uv_command_seconds"), 4000),
    ],
)
def test_field_values_are_validated(path: tuple[str, ...], value: object) -> None:
    with pytest.raises(PackagedVoiceManifestError):
        parse_packaged_manifest(_encode(_with(path, value)))


def test_windows_uv_filename_is_accepted() -> None:
    manifest = parse_packaged_manifest(_encode(_with(("uv", "filename"), "uv.exe")))

    assert manifest.uv.filename == "uv.exe"


def test_target_length_matches_the_build_policy() -> None:
    # The build accepts target names of up to 128 characters, so the reader
    # must accept every name the build can write, and nothing longer.
    longest = "t" * 128
    assert parse_packaged_manifest(_encode(_with(("target",), longest))).target == longest

    with pytest.raises(PackagedVoiceManifestError):
        parse_packaged_manifest(_encode(_with(("target",), longest + "t")))
