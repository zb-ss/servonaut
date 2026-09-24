"""Contract tests for desktop target policy, dependency locks, and isolation."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

import pytest

from scripts.desktop_shell.model import (
    EMBEDDED_NOTICE_POLICY_PATH,
    DesktopPolicyValidationError,
    DesktopTargetSpec,
    load_desktop_target_policy,
    load_desktop_target_spec,
    load_size_baseline,
)
from scripts.standalone_cli.artifact_filesystem import matches_forbidden_path
from scripts.standalone_cli.embedded_notices import load_embedded_notice_policy

_REPO_ROOT = Path(__file__).resolve().parents[2]
_POLICY_ROOT = _REPO_ROOT / "packaging" / "desktop_shell"
_POLICY_PATH = _POLICY_ROOT / "target-policy.json"
_REQUIREMENTS_ROOT = _POLICY_ROOT / "requirements"

_TARGETS = {
    "windows-x64",
    "macos-x64",
    "macos-arm64",
    "linux-x64-ubuntu-22.04",
}

_EXCLUDED_VOICE_DISTRIBUTIONS = {
    "ctranslate2",
    "faster-whisper",
    "numpy",
    "onnxruntime",
    "sherpa-onnx",
    "sounddevice",
    "torch",
}

_DIRECT_REQUIREMENTS = {
    "boto3",
    "tabulate",
    "textual>=8.0.0",
    "cryptography>=42.0",
    'cryptography<49 ; sys_platform == "darwin" and platform_machine == "x86_64"',
    "bcrypt>=3.2",
    "pynacl>=1.5",
    "httpx>=0.25.0",
    "httpx-sse>=0.4",
    "keyring>=24",
    "mcp>=1.0.0,<2",
    "ovh",
    "hcloud>=2.0",
    "textual-serve==1.1.3",
    "pywebview==6.2.1",
    "aiohttp==3.14.3",
    "aiohttp-jinja2>=1.6",
    "pyinstaller==6.22.3",
    "pyinstaller-hooks-contrib==2026.7",
    "cyclonedx-bom==7.3.1",
}

_REQUIREMENT_START = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^ ;\\]+)")
_HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}(?:\\|$)")


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
            assert current not in versions, (
                f"{lock.name}: duplicate requirement {current}"
            )
            versions[current] = match.group(2)
            has_hash = bool(_HASH.search(raw_line))
        elif current is not None and _HASH.search(raw_line):
            has_hash = True
    if current is not None:
        assert has_hash, f"{lock.name}: {current} has no SHA-256 hash"
    return versions


def test_desktop_requirements_input_declares_supported_surface() -> None:
    req_input = _REQUIREMENTS_ROOT / "requirements.in"
    requirements = {
        line.strip()
        for line in req_input.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert requirements == _DIRECT_REQUIREMENTS


def test_desktop_policy_declares_exact_four_targets() -> None:
    policy = load_desktop_target_policy(_POLICY_PATH)
    assert set(policy.targets) == _TARGETS
    assert {t.python_version for t in policy.targets.values()} == {"3.12"}


def test_desktop_target_spec_loader() -> None:
    for name in _TARGETS:
        target = load_desktop_target_spec(name, _POLICY_PATH)
        assert isinstance(target, DesktopTargetSpec)
        assert target.name == name
        assert target.python_version == "3.12"
        assert target.requirements_lock.is_file()
        assert target.frontend_assets_lock.is_file()
        assert target.frontend_licenses.is_file()

    with pytest.raises(DesktopPolicyValidationError):
        load_desktop_target_spec("invalid-target", _POLICY_PATH)


def test_desktop_target_archive_conventions() -> None:
    policy = load_desktop_target_policy(_POLICY_PATH)
    win = policy.targets["windows-x64"]
    assert win.archive_format == "zip"
    assert win.archive_extension == "zip"
    assert win.macos_minimum_version is None
    assert win.linux_abi is None

    for mac_name in ("macos-x64", "macos-arm64"):
        mac = policy.targets[mac_name]
        assert mac.archive_format == "tar.gz"
        assert mac.archive_extension == "tar.gz"
        assert mac.macos_minimum_version == "13.0"
        assert mac.linux_abi is None

    linux = policy.targets["linux-x64-ubuntu-22.04"]
    assert linux.archive_format == "tar.gz"
    assert linux.archive_extension == "tar.gz"
    assert linux.macos_minimum_version is None
    assert linux.linux_abi is not None
    assert linux.linux_abi.python_version == "3.12"
    assert linux.linux_abi.pygobject_version == "3.48.2"
    assert linux.linux_abi.glib_floor == "2.72"
    assert linux.linux_abi.webkit_api == "4.1"


def test_desktop_target_locks_are_exact_hashes_and_pinned() -> None:
    policy = load_desktop_target_policy(_POLICY_PATH)
    for name, target in policy.targets.items():
        lock = target.requirements_lock
        assert lock.is_file()
        text = lock.read_text(encoding="utf-8")
        assert "--editable" not in text
        assert " @ " not in text

        versions = _locked_versions(lock)
        assert len(versions) >= 80, f"{name}: unexpectedly small closure"

        # Required desktop and CLI packages
        assert versions["textual"] == "8.2.8"
        assert versions["textual-serve"] == "1.1.3"
        assert versions["pywebview"] == "6.2.1"
        assert versions["aiohttp"] == "3.14.3"
        assert versions["pyinstaller"] == "6.22.3"
        assert versions["pyinstaller-hooks-contrib"] == "2026.7"
        assert versions["cyclonedx-bom"] == "7.3.1"

        assert {
            "bcrypt",
            "boto3",
            "cryptography",
            "hcloud",
            "httpx",
            "httpx-sse",
            "keyring",
            "mcp",
            "ovh",
            "pynacl",
            "tabulate",
        } <= versions.keys()

        # Strict exclusion of voice packages
        excluded_found = set(versions.keys()) & _EXCLUDED_VOICE_DISTRIBUTIONS
        assert not excluded_found, f"{name}: found voice packages {excluded_found}"


def test_desktop_profiles_resolve_platform_specific_dependencies() -> None:
    policy = load_desktop_target_policy(_POLICY_PATH)
    closures = {
        name: _locked_versions(target.requirements_lock)
        for name, target in policy.targets.items()
    }

    assert "pywin32" in closures["windows-x64"]
    assert "pywin32-ctypes" in closures["windows-x64"]
    assert all("pywin32" not in closures[name] for name in _TARGETS - {"windows-x64"})

    assert "secretstorage" in closures["linux-x64-ubuntu-22.04"]
    assert "jeepney" in closures["linux-x64-ubuntu-22.04"]
    assert all(
        "secretstorage" not in closures[name]
        for name in _TARGETS - {"linux-x64-ubuntu-22.04"}
    )

    assert "macholib" in closures["macos-x64"]
    assert "macholib" in closures["macos-arm64"]


def test_desktop_policy_forbidden_modules_and_patterns() -> None:
    policy = load_desktop_target_policy(_POLICY_PATH)
    required_forbidden_modules = {
        "readline",
        "faster_whisper",
        "ctranslate2",
        "sherpa_onnx",
        "sounddevice",
        "numpy",
        "_sounddevice",
        "_sounddevice_data",
    }
    required_forbidden_patterns = {
        "__pycache__/**",
        "**/__pycache__/**",
        "src/**",
        "**/tests/**",
        "**/*.onnx",
        "**/voice/**",
        "**/_sounddevice_data/**",
        "**/readline.*",
        "**/libreadline*",
    }
    for target in policy.targets.values():
        assert required_forbidden_modules <= set(target.forbidden_modules)
        assert required_forbidden_patterns <= set(target.forbidden_path_patterns)


@pytest.mark.parametrize(
    "relative",
    [
        "_internal/_sounddevice_data/portaudio-binaries/libportaudio.dylib",
        "_internal/tests/test_payload.py",
        "_internal/lib-dynload/readline.cpython-312-darwin.so",
        "_internal/libreadline.so.8",
        "model.onnx",
    ],
)
def test_desktop_forbidden_patterns_match_nested_paths(relative: str) -> None:
    """Policy globs are root-anchored, so nested payload paths need ``**/``."""
    for target in load_desktop_target_policy(_POLICY_PATH).targets.values():
        assert matches_forbidden_path(
            PurePosixPath(relative), target.forbidden_path_patterns
        ), (target.name, relative)


def test_desktop_policy_validation_errors(tmp_path: Path) -> None:
    # Malformed JSON
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(DesktopPolicyValidationError):
        load_desktop_target_policy(bad_json)

    # Missing file
    with pytest.raises(DesktopPolicyValidationError):
        load_desktop_target_policy(tmp_path / "nonexistent.json")

    # Wrong schema version
    bad_ver = tmp_path / "bad_ver.json"
    bad_ver.write_text(
        json.dumps({"schema_version": 99, "targets": {}}), encoding="utf-8"
    )
    with pytest.raises(DesktopPolicyValidationError):
        load_desktop_target_policy(bad_ver)

    # Traversal in lock path
    raw = json.loads(_POLICY_PATH.read_text(encoding="utf-8"))
    raw["targets"]["windows-x64"]["requirements_lock"] = "../../../etc/passwd"
    traversal = tmp_path / "traversal.json"
    traversal.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(DesktopPolicyValidationError):
        load_desktop_target_policy(traversal)


def _locked_blocks(lock: Path) -> dict[str, list[str]]:
    """Return each pinned requirement with its hash lines, comments removed."""
    blocks: dict[str, list[str]] = {}
    current: list[str] | None = None
    for raw_line in lock.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        match = _REQUIREMENT_START.match(raw_line)
        if match:
            current = blocks.setdefault(match.group(1).lower().replace("_", "-"), [])
            current.append(line)
        elif current is not None and line.startswith("--hash="):
            current.append(line)
        else:
            current = None
    return blocks


def test_source_build_tools_match_every_target_lock() -> None:
    """Source builds run without isolation on exactly the locked, hashed backend."""
    tools = _locked_blocks(_REQUIREMENTS_ROOT / "source-build-tools.txt")
    assert set(tools) == {"setuptools"}
    for target in load_desktop_target_policy(_POLICY_PATH).targets.values():
        lock_text = target.requirements_lock.read_text(encoding="utf-8")
        blocks = _locked_blocks(target.requirements_lock)
        assert "--no-binary proxy-tools" in lock_text
        assert blocks["setuptools"] == tools["setuptools"], target.name


def test_intel_macos_lock_pins_cryptography_with_published_wheels() -> None:
    """Locks install without build isolation, so an sdist-only pin cannot build."""
    lock = load_desktop_target_policy(_POLICY_PATH).targets["macos-x64"].requirements_lock
    major = int(_locked_versions(lock)["cryptography"].split(".")[0])
    assert major < 49
    req_input = (_REQUIREMENTS_ROOT / "requirements.in").read_text(encoding="utf-8")
    assert 'cryptography<49 ; sys_platform == "darwin" and platform_machine == "x86_64"' in req_input


def test_desktop_locks_pin_the_embedded_notice_versions() -> None:
    """The shared notice policy applies only while every lock pins its versions."""
    notices = load_embedded_notice_policy(EMBEDDED_NOTICE_POLICY_PATH, 1024 * 1024)
    for target in load_desktop_target_policy(_POLICY_PATH).targets.values():
        versions = _locked_versions(target.requirements_lock)
        for notice in notices:
            assert versions.get(notice.distribution) == notice.version, (
                f"{target.name}: {notice.distribution}"
            )


def test_every_target_declares_a_size_baseline() -> None:
    for name, target in load_desktop_target_policy(_POLICY_PATH).targets.items():
        baseline = load_size_baseline(target.size_baselines, name)
        assert baseline.max_expanded_bytes > 0
        assert baseline.max_regular_file_count > 0


def test_size_baseline_must_match_its_target(tmp_path: Path) -> None:
    baselines = tmp_path / "size-baselines.json"
    baselines.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "baselines": {
                    "windows-x64": {
                        "target": "macos-x64",
                        "max_expanded_bytes": 1,
                        "max_regular_file_count": 1,
                        "rationale": "mismatched",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(DesktopPolicyValidationError, match="missing or invalid"):
        load_size_baseline(baselines, "windows-x64")


def test_unenforced_policy_files_are_not_shipped() -> None:
    # PyInstaller selects hooks by import name; pywebview imports as ``webview``.
    assert not (_POLICY_ROOT / "hooks" / "hook-pywebview.py").exists()
    assert not (_POLICY_ROOT / "warnings-allowlist.json").exists()
