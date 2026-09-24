"""Strict policy-boundary tests for standalone build models."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

import scripts.standalone_cli.model as standalone_model
from scripts.standalone_cli.model import (
    BuildRequest,
    BuildValidationError,
    load_target_spec,
    validate_build_request,
)

_LINUX_TARGET = "linux-x64-ubuntu-22.04"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_TARGET_IDENTITIES = {
    "windows-x64": ("win32", "x86_64", "zip", None),
    "macos-x64": ("darwin", "x86_64", "tar.gz", "13.0"),
    "macos-arm64": ("darwin", "arm64", "tar.gz", "13.0"),
    _LINUX_TARGET: ("linux", "x86_64", "tar.gz", None),
}


def _target(name: str) -> dict[str, object]:
    platform, architecture, archive_format, minimum_version = _TARGET_IDENTITIES[name]
    return {
        "platform": platform,
        "architecture": architecture,
        "python_version": "3.12",
        "requirements_lock": f"requirements/{name}.txt",
        "archive": {
            "format": archive_format,
            "extension": archive_format,
            "name_template": "servonaut-{product_version}-{target}.{extension}",
        },
        "forbidden_modules": ["unused_module"],
        "forbidden_path_patterns": ["tests/**"],
        "warning_allowlist": "warnings-allowlist.json",
        "size_baselines": "size-baselines.json",
        "size_baseline_id": name,
        "macos_minimum_version": minimum_version,
    }


def _write_policy(tmp_path: Path, mutation: tuple[str, object] | None = None) -> Path:
    targets = {name: _target(name) for name in _TARGET_IDENTITIES}
    if mutation is not None:
        field, value = mutation
        targets[_LINUX_TARGET][field] = value
    requirements = tmp_path / "requirements"
    requirements.mkdir()
    for name in _TARGET_IDENTITIES:
        (requirements / f"{name}.txt").write_text(
            "--require-hashes\n", encoding="utf-8"
        )
    policy_path = tmp_path / "target-policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "build_command_timeout_seconds": 1800,
                "targets": targets,
            }
        ),
        encoding="utf-8",
    )
    return policy_path


def _wheel(tmp_path: Path, *, direct_url: str | None = None) -> Path:
    wheel = tmp_path / "servonaut-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "servonaut-1.2.3.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: servonaut\nVersion: 1.2.3\n",
        )
        if direct_url is not None:
            archive.writestr(
                "servonaut-1.2.3.dist-info/direct_url.json", direct_url
            )
    return wheel


def _request(tmp_path: Path, policy_path: Path) -> BuildRequest:
    return BuildRequest(
        wheel=_wheel(tmp_path),
        target=load_target_spec(policy_path, _LINUX_TARGET),
        product_version="1.2.3",
        build_revision="build-1",
        source_commit="abc1234",
        output_dir=tmp_path / "output",
        require_artifact_selftest=False,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("forbidden_modules", []),
        ("forbidden_path_patterns", []),
        ("forbidden_path_patterns", ["segment/./child"]),
        ("forbidden_path_patterns", ["line\nbreak"]),
        ("forbidden_path_patterns", ["x" * 256]),
        ("warning_allowlist", "other-warnings.json"),
        ("size_baselines", "other-sizes.json"),
    ],
)
def test_loader_rejects_values_outside_the_machine_schema(
    tmp_path: Path, field: str, value: object
) -> None:
    policy_path = _write_policy(tmp_path, (field, value))

    with pytest.raises(BuildValidationError):
        load_target_spec(policy_path, _LINUX_TARGET)


def test_target_records_resolved_policy_provenance(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path)

    target = load_target_spec(policy_path, _LINUX_TARGET)

    assert target.policy_path == policy_path.resolve()


def test_build_request_rejects_target_modified_after_policy_load(tmp_path: Path) -> None:
    request = _request(tmp_path, _write_policy(tmp_path))
    modified_target = replace(
        request.target,
        forbidden_path_patterns=request.target.forbidden_path_patterns + ("extra/**",),
    )

    with pytest.raises(BuildValidationError, match="validated policy"):
        validate_build_request(replace(request, target=modified_target))


def test_build_request_rejects_target_when_policy_changes(tmp_path: Path) -> None:
    policy_path = _write_policy(tmp_path)
    request = _request(tmp_path, policy_path)
    raw = json.loads(policy_path.read_text(encoding="utf-8"))
    changed = copy.deepcopy(raw)
    changed["targets"][_LINUX_TARGET]["forbidden_modules"].append("another_module")
    policy_path.write_text(json.dumps(changed), encoding="utf-8")

    with pytest.raises(BuildValidationError, match="validated policy"):
        validate_build_request(request)


def test_build_request_accepts_target_reloaded_from_unchanged_policy(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path, _write_policy(tmp_path))

    validate_build_request(request)


def test_cli_rejects_deeply_nested_policy_without_traceback(tmp_path: Path) -> None:
    policy_path = tmp_path / "target-policy.json"
    policy_path.write_text("[" * 10_000 + "0" + "]" * 10_000, encoding="utf-8")
    output_dir = tmp_path / "output"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.standalone_cli.build",
            "--wheel",
            str(tmp_path / "unused.whl"),
            "--target",
            _LINUX_TARGET,
            "--policy",
            str(policy_path),
            "--product-version",
            "1.2.3",
            "--revision",
            "build-1",
            "--commit",
            "abc1234",
            "--output",
            str(output_dir),
        ],
        cwd=_REPOSITORY_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "target policy" in completed.stderr
    assert "Traceback" not in completed.stderr
    assert not output_dir.exists()


def test_policy_json_recursion_is_a_bounded_validation_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_path = tmp_path / "target-policy.json"
    policy_path.write_text("{}", encoding="utf-8")

    def recursive_decoder(*_args: object, **_kwargs: object) -> object:
        raise RecursionError("JSON nesting limit exceeded")

    monkeypatch.setattr(standalone_model.json, "loads", recursive_decoder)

    with pytest.raises(BuildValidationError, match="valid UTF-8 JSON"):
        load_target_spec(policy_path, _LINUX_TARGET)


def test_wheel_json_recursion_is_a_bounded_validation_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_path = _write_policy(tmp_path)
    nested_json = "[" * 10_000 + "0" + "]" * 10_000
    request = _request(tmp_path, policy_path)
    request = replace(request, wheel=_wheel(tmp_path, direct_url=nested_json))
    original_loads = standalone_model.json.loads

    def recursive_decoder(document: str, *args: object, **kwargs: object) -> object:
        if document == nested_json:
            raise RecursionError("JSON nesting limit exceeded")
        return original_loads(document, *args, **kwargs)

    monkeypatch.setattr(standalone_model.json, "loads", recursive_decoder)

    with pytest.raises(BuildValidationError, match="wheel metadata could not be read"):
        validate_build_request(request)

    assert not request.output_dir.exists()
