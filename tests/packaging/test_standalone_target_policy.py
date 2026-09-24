"""Contract tests for standalone target policy and hash-locked profiles."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from scripts.standalone_cli.model import load_target_spec


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_POLICY_ROOT = _REPOSITORY_ROOT / "packaging" / "standalone_cli"
_POLICY_PATH = _POLICY_ROOT / "target-policy.json"
_SCHEMA_PATH = _POLICY_ROOT / "build-policy.schema.json"
_TARGETS = {
    "windows-x64",
    "macos-x64",
    "macos-arm64",
    "linux-x64-ubuntu-22.04",
}
_EXCLUDED_DISTRIBUTIONS = {
    "aiohttp",
    "ctranslate2",
    "faster-whisper",
    "numpy",
    "pywebview",
    "sherpa-onnx",
    "sounddevice",
    "textual-serve",
}
_BUNDLED_EXTRAS = ("mcp", "ovh", "hetzner")
_BUILD_TOOL_REQUIREMENTS = {
    "pyinstaller==6.22.3",
    "pyinstaller-hooks-contrib==2026.7",
    "cyclonedx-bom==7.3.1",
}
_REQUIREMENT_START = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^ ;\\]+)")
_HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}(?:\\|$)")


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validator() -> Draft202012Validator:
    schema = _read_json(_SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _policy() -> dict[str, object]:
    return _read_json(_POLICY_PATH)


def _pyproject_runtime_requirements() -> set[str]:
    """Return the declared runtime and bundled-integration requirements."""
    tomllib = pytest.importorskip("tomllib")
    pyproject = _REPOSITORY_ROOT / "pyproject.toml"
    project = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]
    optional = project["optional-dependencies"]
    return {
        *project["dependencies"],
        *(requirement for extra in _BUNDLED_EXTRAS for requirement in optional[extra]),
    }


def _locked_versions(lock: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    current: str | None = None
    has_hash = False
    for raw_line in lock.read_text(encoding="utf-8").splitlines():
        match = _REQUIREMENT_START.match(raw_line)
        if match:
            if current is not None:
                assert has_hash, f"{lock.name}: {current} has no SHA-256 hash"
            current = match.group(1).lower().replace("_", "-")
            assert current not in versions, f"{lock.name}: duplicate requirement {current}"
            versions[current] = match.group(2)
            has_hash = bool(_HASH.search(raw_line))
        elif current is not None and _HASH.search(raw_line):
            has_hash = True
    if current is not None:
        assert has_hash, f"{lock.name}: {current} has no SHA-256 hash"
    return versions


def test_requirements_input_is_the_complete_supported_standalone_surface() -> None:
    requirements_input = _POLICY_ROOT / "requirements" / "requirements.in"
    requirements = {
        line.strip()
        for line in requirements_input.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert requirements == _pyproject_runtime_requirements() | _BUILD_TOOL_REQUIREMENTS


def test_every_target_lock_satisfies_the_declared_runtime_requirements() -> None:
    requirements = [
        Requirement(value) for value in sorted(_pyproject_runtime_requirements())
    ]
    for target in _policy()["targets"].values():  # type: ignore[union-attr]
        versions = _locked_versions(_POLICY_ROOT / target["requirements_lock"])
        for requirement in requirements:
            name = canonicalize_name(requirement.name)
            assert name in versions, f"{target['requirements_lock']}: {name} is missing"
            assert requirement.specifier.contains(
                versions[name], prereleases=True
            ), f"{target['requirements_lock']}: {requirement} is not satisfied"


def test_policy_validates_against_strict_schema() -> None:
    _validator().validate(_policy())


def test_schema_rejects_unknown_missing_and_cross_target_values() -> None:
    validator = _validator()
    policy = _policy()

    unknown = copy.deepcopy(policy)
    unknown["unexpected"] = True
    with pytest.raises(ValidationError):
        validator.validate(unknown)

    missing = copy.deepcopy(policy)
    del missing["targets"]["windows-x64"]["requirements_lock"]  # type: ignore[index]
    with pytest.raises(ValidationError):
        validator.validate(missing)

    wrong_archive = copy.deepcopy(policy)
    wrong_archive["targets"]["windows-x64"]["archive"]["format"] = "tar.gz"  # type: ignore[index]
    with pytest.raises(ValidationError):
        validator.validate(wrong_archive)

    wrong_arch = copy.deepcopy(policy)
    wrong_arch["targets"]["macos-arm64"]["architecture"] = "x86_64"  # type: ignore[index]
    with pytest.raises(ValidationError):
        validator.validate(wrong_arch)


@pytest.mark.parametrize(
    "field,value",
    [
        ("requirements_lock", "../requirements.txt"),
        ("warning_allowlist", "/tmp/warnings.json"),
        ("size_baselines", "evidence\\sizes.json"),
    ],
)
def test_schema_rejects_unsafe_policy_paths(field: str, value: str) -> None:
    policy = _policy()
    policy["targets"]["windows-x64"][field] = value  # type: ignore[index]

    with pytest.raises(ValidationError):
        _validator().validate(policy)


def test_schema_rejects_unsafe_or_incomplete_archive_templates() -> None:
    for template in (
        "../servonaut-{product_version}-{target}.{extension}",
        "servonaut-{product_version}.{extension}",
        "servonaut-{product_version}-{target}-{unknown}.{extension}",
    ):
        policy = _policy()
        archive = policy["targets"]["windows-x64"]["archive"]  # type: ignore[index]
        archive["name_template"] = template  # type: ignore[index]
        with pytest.raises(ValidationError):
            _validator().validate(policy)


def test_policy_declares_only_the_four_native_python312_targets() -> None:
    targets = _policy()["targets"]
    assert isinstance(targets, dict)
    assert set(targets) == _TARGETS
    assert {target["python_version"] for target in targets.values()} == {"3.12"}
    assert targets["windows-x64"]["archive"]["format"] == "zip"
    for name in _TARGETS - {"windows-x64"}:
        assert targets[name]["archive"]["format"] == "tar.gz"
    assert targets["macos-x64"]["macos_minimum_version"] == "13.0"
    assert targets["macos-arm64"]["macos_minimum_version"] == "13.0"
    assert targets["windows-x64"]["macos_minimum_version"] is None
    assert targets["linux-x64-ubuntu-22.04"]["macos_minimum_version"] is None
    assert len({target["size_baseline_id"] for target in targets.values()}) == len(_TARGETS)
    assert not (_POLICY_ROOT.parent / "__init__.py").exists()


def test_builder_loads_every_declared_target_and_confines_lock_paths() -> None:
    for target_name in sorted(_TARGETS):
        target = load_target_spec(_POLICY_PATH, target_name)
        assert target.name == target_name
        assert target.python_version == "3.12"
        assert target.requirements_lock.is_file()
        assert target.requirements_lock.parent == (_POLICY_ROOT / "requirements").resolve()
        assert target.warning_allowlist == (_POLICY_ROOT / "warnings-allowlist.json").resolve()
        assert target.size_baselines == (_POLICY_ROOT / "size-baselines.json").resolve()


def test_profiles_are_complete_exact_hash_locks_with_required_tooling() -> None:
    policy = _policy()
    for target_name, target in policy["targets"].items():  # type: ignore[union-attr]
        lock = _POLICY_ROOT / target["requirements_lock"]
        lock_text = lock.read_text(encoding="utf-8")
        assert "--only-binary :all:" in lock_text
        assert "--editable" not in lock_text
        assert " @ " not in lock_text
        for line in lock_text.splitlines():
            if line and not line[0].isspace() and not line.startswith(("#", "--")):
                assert _REQUIREMENT_START.match(line), f"{lock.name}: unpinned line {line!r}"
        versions = _locked_versions(lock)
        assert len(versions) >= 80, f"{target_name}: unexpectedly small dependency closure"
        assert versions["pyinstaller"] == "6.22.3"
        assert versions["pyinstaller-hooks-contrib"] == "2026.7"
        assert versions["cyclonedx-bom"] == "7.3.1"
        assert versions["mcp"].startswith("1.")
        assert {
            "bcrypt",
            "boto3",
            "cryptography",
            "hcloud",
            "httpx",
            "httpx-sse",
            "keyring",
            "ovh",
            "pynacl",
            "tabulate",
            "textual",
        } <= versions.keys()
        assert not (_EXCLUDED_DISTRIBUTIONS & versions.keys())


def test_profiles_resolve_platform_specific_transitive_dependencies() -> None:
    policy = _policy()
    resolution_platforms = {
        "windows-x64": "x86_64-pc-windows-msvc",
        "macos-x64": "x86_64-apple-darwin",
        "macos-arm64": "aarch64-apple-darwin",
        "linux-x64-ubuntu-22.04": "x86_64-manylinux_2_17",
    }
    closures = {
        name: _locked_versions(_POLICY_ROOT / target["requirements_lock"])
        for name, target in policy["targets"].items()  # type: ignore[union-attr]
    }
    for name, target in policy["targets"].items():  # type: ignore[union-attr]
        lock_text = (_POLICY_ROOT / target["requirements_lock"]).read_text(encoding="utf-8")
        assert f"--python-platform {resolution_platforms[name]}" in lock_text
        assert "--python-version 3.12" in lock_text

    assert "pywin32" in closures["windows-x64"]
    assert "pywin32-ctypes" in closures["windows-x64"]
    assert all(
        "pywin32" not in closure
        for name, closure in closures.items()
        if name != "windows-x64"
    )
    assert "secretstorage" in closures["linux-x64-ubuntu-22.04"]
    assert "jeepney" in closures["linux-x64-ubuntu-22.04"]
    assert all(
        "secretstorage" not in closure
        for name, closure in closures.items()
        if name != "linux-x64-ubuntu-22.04"
    )
    assert "macholib" in closures["macos-x64"]
    assert "macholib" in closures["macos-arm64"]


def test_policy_excludes_desktop_voice_readline_and_development_content() -> None:
    targets = _policy()["targets"]
    assert isinstance(targets, dict)
    required_modules = {
        "readline",
        "webview",
        "pywebview",
        "textual_serve",
        "faster_whisper",
        "ctranslate2",
        "sherpa_onnx",
        "sounddevice",
        "numpy",
    }
    required_paths = {
        "**/__pycache__/**",
        "src/**",
        "tests/**",
        ".*",
        ".*/**",
        "**/servonaut/desktop/**",
        "**/*.onnx",
    }
    for target in targets.values():
        assert required_modules <= set(target["forbidden_modules"])
        assert required_paths <= set(target["forbidden_path_patterns"])
        assert "**/*.pyc" not in target["forbidden_path_patterns"]
        assert "**/*" not in target["forbidden_path_patterns"]
        assert not {
            pattern
            for pattern in target["forbidden_path_patterns"]
            if pattern.startswith(".") and pattern not in {".*", ".*/**"}
        }
