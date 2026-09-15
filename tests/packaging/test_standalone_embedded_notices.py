"""Tests for the finite, hash-bound standalone notice set."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from scripts.standalone_cli.embedded_notices import (
    EmbeddedNoticeRecord,
    load_embedded_notice_policy,
    prepare_embedded_notices,
    validate_payload_embedded_notices,
    write_embedded_notice_metadata,
)
from scripts.standalone_cli.model import BuildValidationError, load_target_spec

_ROOT = Path(__file__).resolve().parents[2]
_POLICY_ROOT = _ROOT / "packaging" / "standalone_cli"
_TARGET_POLICY = _POLICY_ROOT / "target-policy.json"
_TARGETS = (
    "linux-x64-ubuntu-22.04",
    "macos-arm64",
    "macos-x64",
    "windows-x64",
)
_EXPECTED_DIGESTS = {
    "charset-normalizer": {
        "posix": "6d0d41bfe170ac6c7dc248c9a63e254d0fb45a60d50a8257d0af92c6e249b887",
        "windows-x64": "18577485d3704f1a479ded8e573c0976cfed315fd2fd17983fa988da4c2f70d1",
    },
    "pydantic-core": {
        "posix": "2afdd30d54b4d62b6f488a6bcc1546e84ec5061f13f4209c03d012348783795a",
        "windows-x64": "fbe7f615f18d135c07000e5a86325db27f42c7729699ef166ac1f7a3f4586bf4",
    },
    "pyinstaller": {
        "posix": "0598064c7d2718e38d7914a7d08343b2fa008e3bea9ebba2aa7a6ffa5900dd64",
        "windows-x64": "0598064c7d2718e38d7914a7d08343b2fa008e3bea9ebba2aa7a6ffa5900dd64",
    },
    "pyinstaller-hooks-contrib": {
        "posix": "91d0baaff00773038e72c0a1fc9d5d2d38706b7a2b9c04f34296608f931b9cd0",
        "windows-x64": "91d0baaff00773038e72c0a1fc9d5d2d38706b7a2b9c04f34296608f931b9cd0",
    },
    "rpds-py": {
        "posix": "314e4e91be3baa93c0fb4bccc9e4e97cd643eb839b065af921782c2175fe9909",
        "windows-x64": "8bcb72c82ea8ae74802293c41d93ad7d51434001b0ae45a603a5af0f507aee0a",
    },
}


def test_embedded_notice_policy_is_schema_valid_and_exact() -> None:
    raw = json.loads(
        (_POLICY_ROOT / "embedded-notices.json").read_text(encoding="utf-8")
    )
    schema = json.loads(
        (_POLICY_ROOT / "embedded-notices.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(raw)

    policy = load_embedded_notice_policy(
        _POLICY_ROOT / "embedded-notices.json", 1_000_000
    )

    assert tuple(row.distribution for row in policy) == tuple(_EXPECTED_DIGESTS)
    assert all(set(row.sha256_by_target) == set(_TARGETS) for row in policy)
    for row in policy:
        expected = _EXPECTED_DIGESTS[row.distribution]
        assert row.sha256_by_target["windows-x64"] == expected["windows-x64"]
        assert all(
            row.sha256_by_target[target] == expected["posix"]
            for target in _TARGETS
            if target != "windows-x64"
        )


@pytest.mark.parametrize(
    ("target_name", "newline"),
    [
        ("linux-x64-ubuntu-22.04", b"\n"),
        ("windows-x64", b"\r\n"),
    ],
)
def test_prepare_validate_and_serialize_exact_notice_bytes(
    tmp_path: Path, target_name: str, newline: bytes
) -> None:
    fixture = _fixture(tmp_path, target_name, newline)

    staged = prepare_embedded_notices(
        fixture.config,
        fixture.site_packages,
        fixture.pip_report,
        fixture.target,
        fixture.metadata_root,
        10_000,
    )

    assert staged.staging_root == fixture.metadata_root / "third-party-notices"
    assert tuple(row.distribution for row in staged.records) == tuple(
        f"package-{index}" for index in range(5)
    )
    for record in staged.records:
        source = fixture.site_packages / (
            f"{record.distribution.replace('-', '_')}-1.0.dist-info/licenses/LICENSE"
        )
        retained = staged.staging_root / record.payload_path.name
        assert retained.read_bytes() == source.read_bytes()
        assert record.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
        assert record.source_wheel_sha256 == fixture.wheel_hashes[record.distribution]

    payload = tmp_path / "payload"
    for record in staged.records:
        destination = payload.joinpath(*record.payload_path.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(
            (staged.staging_root / record.payload_path.name).read_bytes()
        )
    validate_payload_embedded_notices(payload, staged, 10_000)

    resolved = fixture.metadata_root / "resolved"
    resolved.mkdir()
    metadata = resolved / "third-party-notices.json"
    write_embedded_notice_metadata(metadata, staged)
    output = json.loads(metadata.read_text(encoding="utf-8"))
    assert set(output) == {"schema_version", "notices"}
    assert output["schema_version"] == 1
    assert output["notices"] == [
        {
            "distribution": record.distribution,
            "version": record.version,
            "source_wheel_sha256": record.source_wheel_sha256,
            "payload_path": record.payload_path.as_posix(),
            "sha256": record.sha256,
        }
        for record in staged.records
    ]
    assert str(tmp_path) not in metadata.read_text(encoding="utf-8")


def test_prepare_allows_a_hash_bound_source_hardlink(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, "linux-x64-ubuntu-22.04", b"\n")
    first = fixture.site_packages / "package_0-1.0.dist-info/licenses/LICENSE"
    replacement = tmp_path / "same-bytes"
    replacement.write_bytes(first.read_bytes())
    first.unlink()
    os.link(replacement, first)

    staged = prepare_embedded_notices(
        fixture.config,
        fixture.site_packages,
        fixture.pip_report,
        fixture.target,
        fixture.metadata_root,
        10_000,
    )

    assert first.stat().st_nlink == 2
    assert all(path.stat().st_nlink == 1 for path in staged.staging_root.iterdir())


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong-version",
        "wrong-content-hash",
        "missing-source",
        "empty-source",
        "directory-source",
        "symlink-source",
        "parent-symlink",
        "oversized-source",
    ],
)
def test_prepare_rejects_invalid_sources_and_provenance(
    tmp_path: Path, mutation: str
) -> None:
    fixture = _fixture(tmp_path, "linux-x64-ubuntu-22.04", b"\n")
    source = fixture.site_packages / "package_0-1.0.dist-info/licenses/LICENSE"
    if mutation == "wrong-version":
        report = json.loads(fixture.pip_report.read_text(encoding="utf-8"))
        item = report["install"][0]
        item["metadata"]["version"] = "2.0"
        fixture.pip_report.write_text(json.dumps(report), encoding="utf-8")
    elif mutation == "wrong-content-hash":
        source.write_bytes(b"changed\n")
    elif mutation == "missing-source":
        source.unlink()
    elif mutation == "empty-source":
        source.write_bytes(b"")
    elif mutation == "directory-source":
        source.unlink()
        source.mkdir()
    elif mutation == "symlink-source":
        replacement = tmp_path / "replacement"
        replacement.write_bytes(source.read_bytes())
        source.unlink()
        source.symlink_to(replacement)
    elif mutation == "parent-symlink":
        parent = source.parent.parent
        replacement = tmp_path / "foreign-dist-info"
        parent.rename(replacement)
        parent.symlink_to(replacement, target_is_directory=True)
    elif mutation == "oversized-source":
        source.write_bytes(b"x" * 10_001)

    with pytest.raises(BuildValidationError):
        prepare_embedded_notices(
            fixture.config,
            fixture.site_packages,
            fixture.pip_report,
            fixture.target,
            fixture.metadata_root,
            10_000,
        )


@pytest.mark.parametrize(
    "mutation",
    ["missing", "changed", "directory", "symlink", "hardlink", "extra-record"],
)
def test_payload_validation_rejects_incomplete_or_substituted_notices(
    tmp_path: Path, mutation: str
) -> None:
    fixture = _fixture(tmp_path, "linux-x64-ubuntu-22.04", b"\n")
    staged = prepare_embedded_notices(
        fixture.config,
        fixture.site_packages,
        fixture.pip_report,
        fixture.target,
        fixture.metadata_root,
        10_000,
    )
    payload = tmp_path / "payload"
    for record in staged.records:
        destination = payload.joinpath(*record.payload_path.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(
            (staged.staging_root / record.payload_path.name).read_bytes()
        )
    candidate = payload.joinpath(*staged.records[0].payload_path.parts)
    if mutation == "missing":
        candidate.unlink()
    elif mutation == "changed":
        candidate.write_bytes(b"changed")
    elif mutation == "directory":
        candidate.unlink()
        candidate.mkdir()
    elif mutation == "symlink":
        source = tmp_path / "foreign-notice"
        source.write_bytes(
            (staged.staging_root / staged.records[0].payload_path.name).read_bytes()
        )
        candidate.unlink()
        candidate.symlink_to(source)
    elif mutation == "hardlink":
        source = tmp_path / "linked-notice"
        source.write_bytes(candidate.read_bytes())
        candidate.unlink()
        os.link(source, candidate)
    elif mutation == "extra-record":
        extra = EmbeddedNoticeRecord(
            "package-extra", "1.0", "a" * 64, staged.records[0].payload_path, "b" * 64
        )
        staged = replace(staged, records=(*staged.records, extra))

    with pytest.raises(BuildValidationError):
        validate_payload_embedded_notices(payload, staged, 10_000)


@pytest.mark.parametrize(
    "raw",
    [
        '{"schema_version":1,"schema_version":1,"notices":[]}',
        '{"schema_version":1,"notices":[]}',
        '{"schema_version":1,"notices":[{}, {}, {}, {}, {}, {}]}',
        "[1, 2, 3]",
    ],
)
def test_policy_loader_rejects_malformed_and_duplicate_json(
    tmp_path: Path, raw: str
) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(raw, encoding="utf-8")

    with pytest.raises(BuildValidationError):
        load_embedded_notice_policy(policy, 10_000)


@pytest.mark.parametrize(
    "mutation",
    (
        "escape",
        "duplicate-identity",
        "duplicate-payload",
        "extra-target",
        "extra-field",
    ),
)
def test_policy_loader_rejects_noncanonical_rows(tmp_path: Path, mutation: str) -> None:
    fixture = _fixture(tmp_path, "linux-x64-ubuntu-22.04", b"\n")
    raw = json.loads(fixture.config.read_text(encoding="utf-8"))
    if mutation == "escape":
        raw["notices"][0]["source_relative_path"] = "../licenses/LICENSE"
    elif mutation == "duplicate-identity":
        raw["notices"][1]["distribution"] = raw["notices"][0]["distribution"]
        raw["notices"][1]["source_relative_path"] = raw["notices"][0][
            "source_relative_path"
        ]
    elif mutation == "duplicate-payload":
        raw["notices"][1]["payload_path"] = raw["notices"][0]["payload_path"]
    elif mutation == "extra-target":
        raw["notices"][0]["sha256_by_target"]["other-target"] = "a" * 64
    elif mutation == "extra-field":
        raw["notices"][0]["description"] = "unexpected"
    fixture.config.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(BuildValidationError):
        load_embedded_notice_policy(fixture.config, 10_000)


def test_prepare_rejects_an_unknown_target_and_duplicate_pip_identity(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, "linux-x64-ubuntu-22.04", b"\n")
    with pytest.raises(BuildValidationError, match="target"):
        prepare_embedded_notices(
            fixture.config,
            fixture.site_packages,
            fixture.pip_report,
            replace(fixture.target, name="other-target"),
            fixture.metadata_root,
            10_000,
        )

    report = json.loads(fixture.pip_report.read_text(encoding="utf-8"))
    report["install"].append(report["install"][0])
    fixture.pip_report.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(BuildValidationError, match="pip installation report"):
        prepare_embedded_notices(
            fixture.config,
            fixture.site_packages,
            fixture.pip_report,
            fixture.target,
            fixture.metadata_root,
            10_000,
        )


class _Fixture:
    def __init__(
        self,
        config: Path,
        site_packages: Path,
        pip_report: Path,
        metadata_root: Path,
        target_name: str,
        wheel_hashes: dict[str, str],
    ) -> None:
        self.config = config
        self.site_packages = site_packages
        self.pip_report = pip_report
        self.metadata_root = metadata_root
        self.target = load_target_spec(_TARGET_POLICY, target_name)
        self.wheel_hashes = wheel_hashes


def _fixture(tmp_path: Path, target_name: str, newline: bytes) -> _Fixture:
    site_packages = tmp_path / "venv" / "lib" / "python3.12" / "site-packages"
    site_packages.mkdir(parents=True)
    metadata_root = tmp_path / "output" / ".build-metadata-staging"
    metadata_root.mkdir(parents=True)
    notices: list[dict[str, object]] = []
    installs: list[dict[str, object]] = []
    wheel_hashes: dict[str, str] = {}
    for index in range(5):
        distribution = f"package-{index}"
        dist_info = f"package_{index}-1.0.dist-info"
        source_relative_path = f"{dist_info}/licenses/LICENSE"
        payload_path = f"_internal/notices/package-{index}-LICENSE.txt"
        data = f"notice {index}".encode() + newline
        source = site_packages / source_relative_path
        source.parent.mkdir(parents=True)
        source.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        target_hashes = {target: digest for target in _TARGETS}
        notices.append(
            {
                "distribution": distribution,
                "version": "1.0",
                "source_relative_path": source_relative_path,
                "payload_path": payload_path,
                "sha256_by_target": target_hashes,
            }
        )
        wheel_hash = hashlib.sha256(f"wheel {index}".encode()).hexdigest()
        wheel_hashes[distribution] = wheel_hash
        installs.append(
            {
                "metadata": {"name": distribution, "version": "1.0"},
                "download_info": {"archive_info": {"hashes": {"sha256": wheel_hash}}},
            }
        )
    config = tmp_path / "embedded-notices.json"
    config.write_text(
        json.dumps({"schema_version": 1, "notices": notices}), encoding="utf-8"
    )
    pip_report = tmp_path / "pip-report.json"
    pip_report.write_text(
        json.dumps({"version": "1", "install": installs}), encoding="utf-8"
    )
    return _Fixture(
        config,
        site_packages,
        pip_report,
        metadata_root,
        target_name,
        wheel_hashes,
    )
