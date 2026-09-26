"""Contract coverage for standalone build input and marker tooling."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import time
import venv
import zipfile
from dataclasses import replace
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

import scripts.standalone_cli.build as standalone_build
from scripts.standalone_cli.build import (
    _PYINSTALLER_DIAGNOSTIC_RAISERS,
    _assert_venv_prefix,
    _bootstrap_venv_pip,
    _build_environment,
    _capture_build_metadata,
    _copy_build_profile,
    _install_wheel_and_lock,
    _prepare_output_directory,
    _run_capture,
    _sanitized_environment,
    _venv_python,
    _venv_site_packages,
    _write_environment_inventory,
    _write_license_inventory,
    build_standalone,
    main,
)
from scripts.standalone_cli.embedded_notices import (
    EmbeddedNoticeRecord,
    StagedEmbeddedNotices,
    prepare_embedded_notices,
)
from scripts.standalone_cli.model import (
    BuildRequest,
    BuildValidationError,
    TargetSpec,
    _wheel_product_version,
    load_target_spec,
    validate_build_request,
)
from scripts.standalone_cli.runtime_marker import (
    _marker_environment,
    write_runtime_marker,
)

_LINUX_TARGET = "linux-x64-ubuntu-22.04"


def test_pyinstaller_diagnostic_codes_are_an_explicit_closed_protocol() -> None:
    expected = frozenset(
        {
            64,
            65,
            66,
            67,
            68,
            69,
            70,
            71,
            72,
            80,
            81,
            82,
            83,
            84,
            85,
            86,
            87,
            88,
            96,
            97,
            98,
            99,
            100,
            101,
            102,
            103,
            104,
            112,
            113,
            114,
            115,
            116,
            117,
            118,
            119,
            120,
            128,
            129,
            130,
            131,
            132,
            133,
            134,
            135,
            136,
            144,
            145,
            146,
            147,
            148,
            149,
            150,
            151,
            152,
            160,
            161,
            162,
            163,
            164,
            165,
            166,
            167,
            168,
        }
    )

    assert frozenset(_PYINSTALLER_DIAGNOSTIC_RAISERS) == expected
    assert len(_PYINSTALLER_DIAGNOSTIC_RAISERS) == 63
    assert all(type(code) is int and 0 <= code < 256 for code in expected)


def test_pyinstaller_return_code_translation_reads_only_exact_return_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Poison:
        def __str__(self) -> str:
            raise AssertionError("unexpected diagnostic access")

        def __repr__(self) -> str:
            raise AssertionError("unexpected diagnostic access")

    error = subprocess.CalledProcessError(101, _Poison())
    error.output = _Poison()
    error.stderr = _Poison()
    monkeypatch.setattr(
        standalone_build, "_run", lambda *_args: (_ for _ in ()).throw(error)
    )

    with pytest.raises(BuildValidationError):
        standalone_build._run_pyinstaller(
            tmp_path / "python",
            tmp_path / "work",
            tmp_path / "staging",
            {},
            tmp_path,
            tmp_path / "profile.spec",
            30,
        )


@pytest.mark.parametrize("returncode", (-1, 73, 169, True, "101"))
def test_pyinstaller_unreserved_return_codes_remain_generic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, returncode: object
) -> None:
    error = subprocess.CalledProcessError(returncode, "ignored")
    monkeypatch.setattr(
        standalone_build, "_run", lambda *_args: (_ for _ in ()).throw(error)
    )

    with pytest.raises(subprocess.CalledProcessError) as raised:
        standalone_build._run_pyinstaller(
            tmp_path / "python",
            tmp_path / "work",
            tmp_path / "staging",
            {},
            tmp_path,
            tmp_path / "profile.spec",
            30,
        )

    assert raised.value is error


def _policy(target: dict[str, object] | None = None) -> dict[str, object]:
    targets = {
        "windows-x64": _target("windows-x64"),
        "macos-x64": _target("macos-x64"),
        "macos-arm64": _target("macos-arm64"),
        _LINUX_TARGET: _target(_LINUX_TARGET),
    }
    if target is not None:
        targets[_LINUX_TARGET] = target
    return {
        "schema_version": 1,
        "build_command_timeout_seconds": 1800,
        "targets": targets,
    }


def _target(name: str = _LINUX_TARGET) -> dict[str, object]:
    platform, architecture, archive, macos_minimum = {
        "windows-x64": ("win32", "x86_64", "zip", None),
        "macos-x64": ("darwin", "x86_64", "tar.gz", "13.0"),
        "macos-arm64": ("darwin", "arm64", "tar.gz", "13.0"),
        _LINUX_TARGET: ("linux", "x86_64", "tar.gz", None),
    }[name]
    return {
        "platform": platform,
        "architecture": architecture,
        "python_version": "3.12",
        "requirements_lock": f"requirements/{name}.txt",
        "archive": {
            "format": archive,
            "extension": archive,
            "name_template": "servonaut-{product_version}-{target}.{extension}",
        },
        "forbidden_modules": ["pywebview"],
        "forbidden_path_patterns": ["tests/**"],
        "warning_allowlist": "warnings-allowlist.json",
        "size_baselines": "size-baselines.json",
        "size_baseline_id": name,
        "macos_minimum_version": macos_minimum,
    }


def _write_policy(tmp_path: Path, target: dict[str, object] | None = None) -> Path:
    policy = tmp_path / "target-policy.json"
    requirements = tmp_path / "requirements"
    requirements.mkdir()
    for name in ("windows-x64", "macos-x64", "macos-arm64", _LINUX_TARGET):
        (requirements / f"{name}.txt").write_text(
            "--require-hashes\n", encoding="utf-8"
        )
    policy.write_text(json.dumps(_policy(target)), encoding="utf-8")
    return policy


def _wheel(tmp_path: Path, version: str = "1.2.3") -> Path:
    wheel = tmp_path / f"servonaut-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            f"servonaut-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: servonaut\nVersion: {version}\n",
        )
    return wheel


def test_load_target_spec_resolves_only_policy_contained_paths(tmp_path: Path) -> None:
    target = load_target_spec(_write_policy(tmp_path), _LINUX_TARGET)

    assert (
        target.requirements_lock
        == (tmp_path / "requirements" / f"{_LINUX_TARGET}.txt").resolve()
    )
    assert target.warning_allowlist == (tmp_path / "warnings-allowlist.json").resolve()
    assert target.size_baselines == (tmp_path / "size-baselines.json").resolve()


def test_load_target_spec_rejects_duplicate_keys_and_boolean_schema_version(
    tmp_path: Path,
) -> None:
    policy = _write_policy(tmp_path)
    duplicate = policy.read_text(encoding="utf-8").replace(
        '"schema_version": 1,', '"schema_version": 1, "schema_version": 1,'
    )
    policy.write_text(duplicate, encoding="utf-8")
    with pytest.raises(BuildValidationError, match="duplicates key"):
        load_target_spec(policy, _LINUX_TARGET)

    policy.write_text(
        json.dumps({**_policy(), "schema_version": True}),
        encoding="utf-8",
    )
    with pytest.raises(BuildValidationError, match="unsupported schema version"):
        load_target_spec(policy, _LINUX_TARGET)


@pytest.mark.parametrize("timeout", (0, True, 1.5, "1800", 21601))
def test_load_target_spec_requires_a_bounded_build_command_timeout(
    tmp_path: Path, timeout: object
) -> None:
    policy = _write_policy(tmp_path)
    policy.write_text(
        json.dumps({**_policy(), "build_command_timeout_seconds": timeout}),
        encoding="utf-8",
    )

    with pytest.raises(BuildValidationError, match="build command timeout"):
        load_target_spec(policy, _LINUX_TARGET)

    missing = _policy()
    del missing["build_command_timeout_seconds"]
    policy.write_text(json.dumps(missing), encoding="utf-8")
    with pytest.raises(BuildValidationError, match="unsupported or missing fields"):
        load_target_spec(policy, _LINUX_TARGET)


def test_build_commands_are_stopped_at_the_policy_timeout(tmp_path: Path) -> None:
    started = time.monotonic()

    with pytest.raises(subprocess.TimeoutExpired):
        standalone_build._run(
            [sys.executable, "-c", "import time; time.sleep(30)"], {}, tmp_path, 1
        )
    with pytest.raises(subprocess.TimeoutExpired):
        standalone_build._run_capture(
            [sys.executable, "-c", "import time; time.sleep(30)"], {}, tmp_path, 1
        )

    assert time.monotonic() - started < 10


def test_validate_build_request_requires_exact_wheel_version(tmp_path: Path) -> None:
    target = load_target_spec(_write_policy(tmp_path), _LINUX_TARGET)
    request = BuildRequest(
        wheel=_wheel(tmp_path),
        target=target,
        product_version="1.2.4",
        build_revision="build-1",
        source_commit="abc1234",
        output_dir=tmp_path / "output",
        require_artifact_selftest=False,
    )

    with pytest.raises(BuildValidationError, match="wheel version"):
        validate_build_request(request)


def test_wheel_version_reads_servonaut_distribution_metadata(tmp_path: Path) -> None:
    assert _wheel_product_version(_wheel(tmp_path)) == "1.2.3"


@pytest.mark.parametrize(
    "target_name", ("windows-x64", "macos-x64", "macos-arm64", _LINUX_TARGET)
)
def test_resolved_profile_excludes_every_forbidden_module_of_the_policy(
    tmp_path: Path, target_name: str
) -> None:
    target = load_target_spec(standalone_build._POLICY_PATH, target_name)
    request = BuildRequest(
        wheel=tmp_path / "servonaut-1.2.3-py3-none-any.whl",
        target=target,
        product_version="1.2.3",
        build_revision="build-1",
        source_commit="abc1234",
        output_dir=tmp_path / "output",
        require_artifact_selftest=False,
    )
    profile_path = tmp_path / "profile.json"

    standalone_build._write_profile(
        profile_path, request, tmp_path / "site-packages", tmp_path / "hooks"
    )

    excluded = json.loads(profile_path.read_text(encoding="utf-8"))["excluded_modules"]
    assert set(target.forbidden_modules) <= set(excluded)
    assert "servonaut.desktop" in excluded


def test_build_environment_removes_inherited_python_and_profile_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PYTHONPATH", "untrusted")
    monkeypatch.setenv("PYTHONHOME", "untrusted")
    monkeypatch.setenv("pYtHoNcUsToM", "untrusted")
    monkeypatch.setenv("PiP_CUSTOM", "untrusted")
    monkeypatch.setenv("SERVONAUT_STANDALONE_OUTPUT_DIR", "untrusted")
    monkeypatch.setenv("SeRvOnAuT_StAnDaLoNe_CUSTOM", "untrusted")
    runtime_notice = (
        tmp_path / "build-metadata" / "runtime-notice" / "CPython-LICENSE.txt"
    )
    runtime_notice.parent.mkdir(parents=True)
    runtime_notice.write_bytes(b"notice\n")
    embedded_notices = _staged_embedded_notices(tmp_path, tmp_path / "build-metadata")
    environment = _build_environment(
        entry_script=tmp_path / "venv" / "entry.py",
        site_packages=tmp_path / "venv" / "site-packages",
        profile_path=tmp_path / "profile.json",
        output_dir=tmp_path / "staging",
        metadata_dir=tmp_path / "build-metadata",
        runtime_notice_source=runtime_notice,
        embedded_notices_root=embedded_notices.staging_root,
        require_artifact_selftest=True,
        pyinstaller_config_dir=tmp_path / "pyinstaller-config",
    )

    assert {name for name in environment if name.casefold().startswith("python")} == {
        "PYTHONNOUSERSITE"
    }
    assert {name for name in environment if name.casefold().startswith("pip_")} == {
        "PIP_CONFIG_FILE"
    }
    assert environment["SERVONAUT_STANDALONE_REQUIRE_ARTIFACT_SELFTEST"] == "1"
    assert {
        name for name in environment if name.startswith("SERVONAUT_STANDALONE_")
    } == {
        "SERVONAUT_STANDALONE_ENTRY_SCRIPT",
        "SERVONAUT_STANDALONE_ISOLATED_SITE_PACKAGES",
        "SERVONAUT_STANDALONE_PROFILE_PATH",
        "SERVONAUT_STANDALONE_OUTPUT_DIR",
        "SERVONAUT_STANDALONE_BUILD_METADATA_DIR",
        "SERVONAUT_STANDALONE_RUNTIME_NOTICE_SOURCE",
        "SERVONAUT_STANDALONE_THIRD_PARTY_NOTICES_ROOT",
        "SERVONAUT_STANDALONE_REQUIRE_ARTIFACT_SELFTEST",
    }
    assert environment["SERVONAUT_STANDALONE_THIRD_PARTY_NOTICES_ROOT"] == str(
        embedded_notices.staging_root
    )


def test_build_keeps_the_pyinstaller_cache_in_its_private_temporary_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared_cache = tmp_path / "shared-user-cache"
    shared_cache.mkdir()
    (shared_cache / "keep").write_text("keep", encoding="utf-8")
    monkeypatch.setenv("PYINSTALLER_CONFIG_DIR", str(shared_cache))
    request = _orchestration_request(tmp_path)
    _stub_build_orchestration(monkeypatch, None)
    original_run_pyinstaller = standalone_build._run_pyinstaller
    configured: list[Path] = []

    def run_pyinstaller(*args: object) -> None:
        environment, working_directory = args[3], args[4]
        assert isinstance(environment, dict) and isinstance(working_directory, Path)
        config_dir = Path(environment["PYINSTALLER_CONFIG_DIR"])
        assert config_dir.parent == working_directory
        assert config_dir.is_dir()
        configured.append(config_dir)
        original_run_pyinstaller(*args)

    monkeypatch.setattr(standalone_build, "_run_pyinstaller", run_pyinstaller)

    build_standalone(request)

    assert len(configured) == 1
    assert not configured[0].exists()
    assert (shared_cache / "keep").read_text(encoding="utf-8") == "keep"


def test_build_environment_rejects_a_substituted_runtime_notice(
    tmp_path: Path,
) -> None:
    metadata_dir = tmp_path / "build-metadata"
    runtime_notice = metadata_dir / "runtime-notice" / "CPython-LICENSE.txt"
    runtime_notice.parent.mkdir(parents=True)
    replacement = tmp_path / "replacement.txt"
    replacement.write_bytes(b"replacement\n")
    try:
        runtime_notice.symlink_to(replacement)
    except OSError:
        pytest.skip("symlinks are unavailable on this test host")

    with pytest.raises(BuildValidationError, match="staged Python notice"):
        _build_environment(
            entry_script=tmp_path / "venv" / "entry.py",
            site_packages=tmp_path / "venv" / "site-packages",
            profile_path=tmp_path / "profile.json",
            output_dir=tmp_path / "staging",
            metadata_dir=metadata_dir,
            runtime_notice_source=runtime_notice,
            embedded_notices_root=None,
            require_artifact_selftest=False,
            pyinstaller_config_dir=tmp_path / "pyinstaller-config",
        )


def test_build_environment_rejects_a_substituted_embedded_notice_root(
    tmp_path: Path,
) -> None:
    metadata_dir = tmp_path / "build-metadata"
    runtime_notice = metadata_dir / "runtime-notice" / "CPython-LICENSE.txt"
    runtime_notice.parent.mkdir(parents=True)
    runtime_notice.write_bytes(b"notice\n")
    foreign = tmp_path / "third-party-notices"
    foreign.mkdir()

    with pytest.raises(BuildValidationError, match="staged embedded notices"):
        _build_environment(
            entry_script=tmp_path / "venv" / "entry.py",
            site_packages=tmp_path / "venv" / "site-packages",
            profile_path=tmp_path / "profile.json",
            output_dir=tmp_path / "staging",
            metadata_dir=metadata_dir,
            runtime_notice_source=runtime_notice,
            embedded_notices_root=foreign,
            require_artifact_selftest=False,
            pyinstaller_config_dir=tmp_path / "pyinstaller-config",
        )


def _runtime_notice_facts(base_prefix: Path, stdlib: Path) -> str:
    return json.dumps(
        {
            "base_prefix": str(base_prefix),
            "stdlib": str(stdlib),
            "python_implementation": "CPython",
            "python_version": "3.12.14",
        }
    )


def test_prepare_runtime_notice_uses_the_target_selected_source_and_copies_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base_prefix = tmp_path / "base"
    stdlib = base_prefix / "lib" / "python3.12"
    stdlib.mkdir(parents=True)
    (base_prefix / "LICENSE.txt").write_bytes(b"windows notice\n")
    source = stdlib / "LICENSE.txt"
    source.write_bytes(b"posix notice\n")
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    monkeypatch.setattr(
        standalone_build,
        "_run_capture",
        lambda *_args: _runtime_notice_facts(base_prefix, stdlib),
    )
    monkeypatch.setattr(
        standalone_build,
        "load_evidence_policy",
        lambda _path: SimpleNamespace(
            limits=SimpleNamespace(max_metadata_file_bytes=1024)
        ),
    )

    notice = standalone_build._prepare_runtime_notice(
        tmp_path / "venv-python",
        _target_spec(tmp_path),
        metadata_dir,
        {},
        tmp_path,
    )

    assert (
        notice.staged_path
        == (metadata_dir / "runtime-notice" / "CPython-LICENSE.txt").resolve()
    )
    assert notice.staged_path.read_bytes() == b"posix notice\n"
    assert notice.sha256 == standalone_build._sha256_file(source)
    assert notice.python_version == "3.12.14"


def test_prepare_runtime_notice_uses_base_prefix_for_windows_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base_prefix = tmp_path / "base"
    stdlib = base_prefix / "lib" / "python3.12"
    stdlib.mkdir(parents=True)
    source = base_prefix / "LICENSE.txt"
    source.write_bytes(b"windows notice\n")
    (stdlib / "LICENSE.txt").write_bytes(b"posix notice\n")
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    monkeypatch.setattr(
        standalone_build,
        "_run_capture",
        lambda *_args: _runtime_notice_facts(base_prefix, stdlib),
    )
    monkeypatch.setattr(
        standalone_build,
        "load_evidence_policy",
        lambda _path: SimpleNamespace(
            limits=SimpleNamespace(max_metadata_file_bytes=1024)
        ),
    )

    notice = standalone_build._prepare_runtime_notice(
        tmp_path / "venv-python",
        replace(_target_spec(tmp_path), platform="win32"),
        metadata_dir,
        {},
        tmp_path,
    )

    assert notice.staged_path.read_bytes() == b"windows notice\n"


def test_prepare_runtime_notice_copies_the_selected_private_venv_source(
    tmp_path: Path,
) -> None:
    venv_root = tmp_path / "private-venv"
    venv.EnvBuilder(with_pip=False, symlinks=os.name != "nt").create(venv_root)
    python = _venv_python(venv_root)
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()

    notice = standalone_build._prepare_runtime_notice(
        python,
        _target_spec(tmp_path),
        metadata_dir,
        _sanitized_environment(),
        tmp_path,
    )

    assert notice.staged_path.read_bytes()
    assert notice.sha256 == standalone_build._sha256_file(notice.staged_path)
    assert notice.python_version == platform.python_version()


def test_build_stages_notices_in_the_required_build_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _orchestration_request(tmp_path)
    _stub_build_orchestration(monkeypatch, None)
    original_prepare = standalone_build._prepare_runtime_notice
    original_prepare_embedded = standalone_build.prepare_embedded_notices
    original_build_environment = standalone_build._build_environment
    events: list[str] = []

    def prepare(*args: object) -> standalone_build._RuntimeNoticeSource:
        events.append("notice")
        return original_prepare(*args)

    def build_environment(**kwargs: object) -> dict[str, str]:
        assert events and events[0] == "notice"
        events.append("environment")
        return original_build_environment(**kwargs)

    def prepare_embedded(*args: object) -> StagedEmbeddedNotices:
        assert events == ["notice", "environment"]
        events.append("embedded-notices")
        return original_prepare_embedded(*args)

    monkeypatch.setattr(standalone_build, "_prepare_runtime_notice", prepare)
    monkeypatch.setattr(standalone_build, "_build_environment", build_environment)
    monkeypatch.setattr(standalone_build, "prepare_embedded_notices", prepare_embedded)

    build_standalone(request)

    assert events == ["notice", "environment", "embedded-notices", "environment"]


def test_build_standalone_requires_the_payload_notice_to_match_staged_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _orchestration_request(tmp_path)
    _stub_build_orchestration(monkeypatch, None)

    result = build_standalone(request)

    staged_notice = result.build_metadata_dir / "runtime-notice" / "CPython-LICENSE.txt"
    payload_notice = (
        result.payload_root / "_internal" / "notices" / "CPython-LICENSE.txt"
    )
    assert payload_notice.read_bytes() == staged_notice.read_bytes()
    assert standalone_build._sha256_file(
        payload_notice
    ) == standalone_build._sha256_file(staged_notice)
    embedded_root = result.build_metadata_dir / "third-party-notices"
    for source in embedded_root.iterdir():
        payload_copy = result.payload_root / "_internal" / "notices" / source.name
        assert payload_copy.read_bytes() == source.read_bytes()


def test_build_standalone_rejects_a_tampered_embedded_notice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _orchestration_request(tmp_path)
    _stub_build_orchestration(monkeypatch, None)
    original_run_pyinstaller = standalone_build._run_pyinstaller

    def run_pyinstaller(*args: object) -> None:
        original_run_pyinstaller(*args)
        staging_dir = args[2]
        assert isinstance(staging_dir, Path)
        notice_root = staging_dir / "servonaut" / "_internal" / "notices"
        next(
            path for path in notice_root.iterdir() if path.name != "CPython-LICENSE.txt"
        ).write_bytes(b"changed\n")

    monkeypatch.setattr(standalone_build, "_run_pyinstaller", run_pyinstaller)

    with pytest.raises(BuildValidationError, match="embedded notice"):
        build_standalone(request)
    assert not request.output_dir.exists()


@pytest.mark.parametrize(
    "kind", ("missing", "directory", "symlink", "changed", "oversized")
)
def test_build_standalone_rejects_an_invalid_payload_runtime_notice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    request = _orchestration_request(tmp_path)
    _stub_build_orchestration(monkeypatch, None)
    original_run_pyinstaller = standalone_build._run_pyinstaller

    def run_pyinstaller(*args: object) -> None:
        original_run_pyinstaller(*args)
        staging_dir = args[2]
        assert isinstance(staging_dir, Path)
        notice = (
            staging_dir / "servonaut" / "_internal" / "notices" / "CPython-LICENSE.txt"
        )
        if kind == "missing":
            notice.unlink()
        elif kind == "directory":
            notice.unlink()
            notice.mkdir()
        elif kind == "symlink":
            replacement = tmp_path / "replacement.txt"
            replacement.write_bytes(b"replacement\n")
            try:
                notice.unlink()
                notice.symlink_to(replacement)
            except OSError:
                pytest.skip("symlinks are unavailable on this test host")
        elif kind == "changed":
            notice.write_bytes(b"changed\n")
        else:
            notice.write_bytes(b"payload too large")

    monkeypatch.setattr(standalone_build, "_run_pyinstaller", run_pyinstaller)
    if kind == "oversized":
        monkeypatch.setattr(
            standalone_build,
            "load_evidence_policy",
            lambda _path: SimpleNamespace(
                limits=SimpleNamespace(max_metadata_file_bytes=3)
            ),
        )

    with pytest.raises(BuildValidationError, match="PyInstaller runtime notice"):
        build_standalone(request)

    _assert_no_published_output(request.output_dir)


@pytest.mark.parametrize("kind", ("missing", "directory", "outside", "oversized"))
def test_prepare_runtime_notice_rejects_invalid_selected_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    base_prefix = tmp_path / "base"
    stdlib = base_prefix / "lib" / "python3.12"
    stdlib.mkdir(parents=True)
    source = stdlib / "LICENSE.txt"
    if kind == "directory":
        source.mkdir()
    elif kind == "outside":
        stdlib = tmp_path / "outside"
        stdlib.mkdir()
        (stdlib / "LICENSE.txt").write_bytes(b"outside\n")
    elif kind == "oversized":
        source.write_bytes(b"too large")
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    monkeypatch.setattr(
        standalone_build,
        "_run_capture",
        lambda *_args: _runtime_notice_facts(base_prefix, stdlib),
    )
    monkeypatch.setattr(
        standalone_build,
        "load_evidence_policy",
        lambda _path: SimpleNamespace(
            limits=SimpleNamespace(
                max_metadata_file_bytes=3 if kind == "oversized" else 1024
            )
        ),
    )

    with pytest.raises(BuildValidationError):
        standalone_build._prepare_runtime_notice(
            tmp_path / "venv-python", _target_spec(tmp_path), metadata_dir, {}, tmp_path
        )

    assert not (metadata_dir / "runtime-notice").exists()


def test_prepare_runtime_notice_keeps_its_specific_validation_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base_prefix = tmp_path / "base"
    stdlib = base_prefix / "lib" / "python3.12"
    stdlib.mkdir(parents=True)
    (stdlib / "LICENSE.txt").write_bytes(b"too large")
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    monkeypatch.setattr(
        standalone_build,
        "_run_capture",
        lambda *_args: _runtime_notice_facts(base_prefix, stdlib),
    )
    monkeypatch.setattr(
        standalone_build,
        "load_evidence_policy",
        lambda _path: SimpleNamespace(
            limits=SimpleNamespace(max_metadata_file_bytes=3)
        ),
    )

    with pytest.raises(BuildValidationError) as raised:
        standalone_build._prepare_runtime_notice(
            tmp_path / "venv-python", _target_spec(tmp_path), metadata_dir, {}, tmp_path
        )

    assert str(raised.value) == "private Python notice source has an invalid size"
    assert raised.value.__cause__ is None


def test_prepare_runtime_notice_rejects_a_substituted_symlink_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base_prefix = tmp_path / "base"
    stdlib = base_prefix / "lib" / "python3.12"
    stdlib.mkdir(parents=True)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"replacement\n")
    try:
        (stdlib / "LICENSE.txt").symlink_to(replacement)
    except OSError:
        pytest.skip("symlinks are unavailable on this test host")
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    monkeypatch.setattr(
        standalone_build,
        "_run_capture",
        lambda *_args: _runtime_notice_facts(base_prefix, stdlib),
    )
    monkeypatch.setattr(
        standalone_build,
        "load_evidence_policy",
        lambda _path: SimpleNamespace(
            limits=SimpleNamespace(max_metadata_file_bytes=1024)
        ),
    )

    with pytest.raises(BuildValidationError):
        standalone_build._prepare_runtime_notice(
            tmp_path / "venv-python", _target_spec(tmp_path), metadata_dir, {}, tmp_path
        )


def test_windows_sysconfig_site_packages_supports_embedded_notice_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    venv_root = tmp_path / "private-venv"
    site_packages = venv_root / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    monkeypatch.setattr(
        standalone_build,
        "_run_capture",
        lambda *_args: json.dumps(
            {"purelib": str(site_packages), "platlib": str(site_packages)}
        ),
    )

    selected = _venv_site_packages(tmp_path / "python.exe", venv_root, {}, tmp_path, 30)
    policy_rows: list[dict[str, object]] = []
    installations: list[dict[str, object]] = []
    target_names = (
        "windows-x64",
        "macos-x64",
        "macos-arm64",
        _LINUX_TARGET,
    )
    for index in range(5):
        distribution = f"package-{index}"
        data = f"notice {index}\n".encode()
        digest = standalone_build.hashlib.sha256(data).hexdigest()
        source_path = (
            site_packages / f"package_{index}-1.0.dist-info" / "licenses" / "LICENSE"
        )
        source_path.parent.mkdir(parents=True)
        source_path.write_bytes(data)
        policy_rows.append(
            {
                "distribution": distribution,
                "version": "1.0",
                "source_relative_path": source_path.relative_to(
                    site_packages
                ).as_posix(),
                "payload_path": f"_internal/notices/{distribution}-LICENSE.txt",
                "sha256_by_target": dict.fromkeys(target_names, digest),
            }
        )
        installations.append(
            {
                "metadata": {"name": distribution, "version": "1.0"},
                "download_info": {
                    "archive_info": {"hashes": {"sha256": f"{index + 1:064x}"}}
                },
            }
        )
    notice_policy = tmp_path / "embedded-notices.json"
    notice_policy.write_text(
        json.dumps({"schema_version": 1, "notices": policy_rows}), encoding="utf-8"
    )
    pip_report = tmp_path / "pip-report.json"
    pip_report.write_text(
        json.dumps({"version": "1", "install": installations}), encoding="utf-8"
    )
    policy_root = tmp_path / "policy"
    policy_root.mkdir()
    target = load_target_spec(_write_policy(policy_root), "windows-x64")
    metadata = tmp_path / "metadata"
    metadata.mkdir()

    staged = prepare_embedded_notices(
        notice_policy, selected, pip_report, target, metadata, 64 * 1024
    )

    assert selected == site_packages
    assert selected != venv_root
    assert len(staged.records) == 5


@pytest.mark.parametrize(
    "case",
    (
        "invalid-json",
        "wrong-shape",
        "extra-field",
        "non-string",
        "relative",
        "mismatch",
        "venv-root",
        "outside",
    ),
)
def test_venv_site_packages_rejects_invalid_sysconfig_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    venv_root = tmp_path / "private-venv"
    valid = venv_root / "lib" / "site-packages"
    valid.mkdir(parents=True)
    other = venv_root / "other"
    other.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    values: dict[str, object] = {"purelib": str(valid), "platlib": str(valid)}
    if case == "invalid-json":
        output = "{"
    elif case == "wrong-shape":
        output = json.dumps([str(valid), str(valid)])
    else:
        if case == "extra-field":
            values["unexpected"] = str(valid)
        elif case == "non-string":
            values["purelib"] = True
        elif case == "relative":
            values["purelib"] = values["platlib"] = "lib/site-packages"
        elif case == "mismatch":
            values["platlib"] = str(other)
        elif case == "venv-root":
            values["purelib"] = values["platlib"] = str(venv_root)
        elif case == "outside":
            values["purelib"] = values["platlib"] = str(outside)
        output = json.dumps(values)
    monkeypatch.setattr(standalone_build, "_run_capture", lambda *_args: output)

    with pytest.raises(BuildValidationError, match="site-packages is invalid"):
        _venv_site_packages(tmp_path / "python", venv_root, {}, tmp_path, 30)


def test_venv_site_packages_rejects_a_symlinked_sysconfig_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    venv_root = tmp_path / "private-venv"
    physical = venv_root / "lib" / "physical-site-packages"
    physical.mkdir(parents=True)
    linked = venv_root / "lib" / "site-packages"
    try:
        linked.symlink_to(physical, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are unavailable on this test host")
    monkeypatch.setattr(
        standalone_build,
        "_run_capture",
        lambda *_args: json.dumps({"purelib": str(linked), "platlib": str(linked)}),
    )

    with pytest.raises(BuildValidationError, match="site-packages is invalid"):
        _venv_site_packages(tmp_path / "python", venv_root, {}, tmp_path, 30)


def test_marker_validation_imports_only_the_isolated_wheel_runtime(
    tmp_path: Path,
) -> None:
    """Marker validation cannot fall back to the checkout's Servonaut package."""
    policy = load_target_spec(_write_policy(tmp_path), _LINUX_TARGET)
    request = BuildRequest(
        wheel=_wheel(tmp_path),
        target=policy,
        product_version="1.2.3",
        build_revision="build-1",
        source_commit="abc1234",
        output_dir=tmp_path / "output",
        require_artifact_selftest=False,
    )
    venv_root = tmp_path / "isolated"
    venv.EnvBuilder(with_pip=False, symlinks=os.name != "nt").create(venv_root)
    python = venv_root / (
        "Scripts/python.exe" if sys.platform == "win32" else "bin/python"
    )
    environment = _sanitized_environment()
    site_packages = _venv_site_packages(python, venv_root, environment, tmp_path, 60)
    package = site_packages / "servonaut"
    package.mkdir()
    source_package = Path(__file__).parents[2] / "src" / "servonaut"
    shutil.copy2(source_package / "__init__.py", package / "__init__.py")
    shutil.copy2(source_package / "runtime.py", package / "runtime.py")
    payload = tmp_path / "payload"
    payload.mkdir()
    executable = payload / "servonaut"
    executable.write_text("fixture", encoding="utf-8")
    workdir = tmp_path / "marker-check"
    workdir.mkdir()

    marker = write_runtime_marker(
        payload,
        executable,
        request,
        isolated_python=python,
        isolated_site_packages=site_packages,
        working_directory=workdir,
    )

    assert (
        json.loads(marker.read_text(encoding="utf-8"))["distribution"] == "frozen-cli"
    )


def test_real_venv_interpreter_keeps_private_prefix_and_base_unchanged(
    tmp_path: Path,
) -> None:
    """A symlinked venv interpreter must not become the base interpreter path."""
    base_python = Path(sys.executable).resolve()
    before = base_python.stat()
    venv_root = tmp_path / "private venv"
    venv.EnvBuilder(with_pip=False, symlinks=os.name != "nt").create(venv_root)
    venv_python = _venv_python(venv_root)
    environment = _sanitized_environment()

    _assert_venv_prefix(venv_python, venv_root, environment, tmp_path, 60)
    site_packages = _venv_site_packages(
        venv_python, venv_root, environment, tmp_path, 60
    )
    sysconfig_paths = json.loads(
        subprocess.check_output(
            [
                str(venv_python),
                "-c",
                (
                    "import json, sysconfig; paths = sysconfig.get_paths(); "
                    "print(json.dumps({'purelib': paths['purelib'], "
                    "'platlib': paths['platlib']}))"
                ),
            ],
            text=True,
            env=environment,
            cwd=tmp_path,
        )
    )
    prefix = Path(
        subprocess.check_output(
            [str(venv_python), "-c", "import sys; print(sys.prefix)"],
            text=True,
            env=environment,
        ).strip()
    )

    assert prefix.resolve() == venv_root.resolve()
    assert Path(sysconfig_paths["purelib"]).resolve() == site_packages
    assert Path(sysconfig_paths["platlib"]).resolve() == site_packages
    assert site_packages.is_relative_to(venv_root.resolve())
    assert base_python.stat().st_mtime_ns == before.st_mtime_ns
    if os.name != "nt":
        assert venv_python.is_symlink()


def test_sanitized_environment_blocks_pip_redirection_and_child_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A local wheel installs privately despite hostile inherited pip settings."""
    redirected = tmp_path / "redirected"
    for name in ("PIP_TARGET", "PIP_PREFIX", "PIP_USER", "PIP_CONFIG_FILE"):
        monkeypatch.setenv(name, str(redirected) if name != "PIP_USER" else "1")
    venv_root = tmp_path / "private venv"
    venv.EnvBuilder(with_pip=False, symlinks=os.name != "nt").create(venv_root)
    monkeypatch.setenv("PYTHONPLATLIBDIR", str(tmp_path / "missing-platform-libraries"))
    environment = _sanitized_environment()
    assert {name for name in environment if name.casefold().startswith("python")} == {
        "PYTHONNOUSERSITE"
    }
    assert {name for name in environment if name.casefold().startswith("pip_")} == {
        "PIP_CONFIG_FILE"
    }
    assert not any(
        name.casefold().startswith("servonaut_standalone_") for name in environment
    )
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PIP_CONFIG_FILE"] == os.devnull
    assert _run_capture(
        [sys.executable, "-c", "import os; print(os.getcwd())"],
        environment,
        tmp_path,
        60,
    ).strip() == str(tmp_path)

    python = _venv_python(venv_root)
    _assert_venv_prefix(python, venv_root, environment, tmp_path, 60)
    _bootstrap_venv_pip(python, environment, tmp_path, 120)
    site_packages = _venv_site_packages(python, venv_root, environment, tmp_path, 60)
    lock = tmp_path / "lock.txt"
    lock.write_text("--require-hashes\n", encoding="utf-8")
    report = tmp_path / "report.json"
    _install_wheel_and_lock(
        python, _installable_wheel(tmp_path), lock, report, environment, tmp_path, 120
    )
    _run_capture(
        [str(python), "-m", "pip", "check", "--isolated"], environment, tmp_path, 60
    )

    assert (site_packages / "servonaut").is_dir()
    assert not redirected.exists()


def test_install_rejects_a_lock_that_misses_a_declared_requirement(
    tmp_path: Path,
) -> None:
    """A --no-deps install still proves the lock satisfies the wheel metadata."""
    venv_root = tmp_path / "private venv"
    venv.EnvBuilder(with_pip=False, symlinks=os.name != "nt").create(venv_root)
    environment = _sanitized_environment()
    python = _venv_python(venv_root)
    _bootstrap_venv_pip(python, environment, tmp_path, 120)
    stale_dependency = _installable_wheel(
        tmp_path, name="lockfixture", version="1.0.0"
    )
    wheel = _installable_wheel(tmp_path, requires=("lockfixture>=2.0",))
    digest = standalone_build._sha256_file(stale_dependency)
    lock = tmp_path / "lock.txt"
    lock.write_text(
        f"lockfixture @ {stale_dependency.as_uri()} --hash=sha256:{digest}\n",
        encoding="utf-8",
    )

    with pytest.raises(subprocess.CalledProcessError) as raised:
        _install_wheel_and_lock(
            python, wheel, lock, tmp_path / "report.json", environment, tmp_path, 120
        )

    assert raised.value.cmd[1:4] == ["-m", "pip", "check"]


def test_windows_marker_environment_preserves_only_valid_system_root(
    tmp_path: Path,
) -> None:
    system_root = tmp_path / "Windows"
    system_root.mkdir()
    environment = _marker_environment(
        tmp_path / "venv" / "Scripts" / "python.exe",
        platform_name="nt",
        inherited={"sYsTeMrOoT": str(system_root), "PIP_TARGET": "discard"},
    )

    assert environment == {
        "PATH": str(tmp_path / "venv" / "Scripts"),
        "SystemRoot": str(system_root),
    }


def test_capture_metadata_uses_spec_stem_and_persists_stable_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PyInstaller names transient work files after the supplied spec file."""
    work_dir = tmp_path / "pyinstaller-work"
    spec_work_dir = work_dir / "servonaut_cli"
    spec_work_dir.mkdir(parents=True)
    (spec_work_dir / "warn-servonaut_cli.txt").write_text("warning\n", encoding="utf-8")
    (spec_work_dir / "Analysis-00.toc").write_text("analysis\n", encoding="utf-8")
    (spec_work_dir / "PYZ-00.toc").write_text("pyz\n", encoding="utf-8")
    metadata_dir = tmp_path / "build-metadata"
    metadata_dir.mkdir()
    pip_report = tmp_path / "pip-report.json"
    pip_report.write_text('{"version": "1", "install": []}', encoding="utf-8")
    monkeypatch.setattr(
        "scripts.standalone_cli.build._write_license_inventory", lambda *args: None
    )
    monkeypatch.setattr(
        "scripts.standalone_cli.build._write_python_sbom", lambda *args: None
    )

    copied_profile = _copy_build_profile(tmp_path / "profile")
    assert (
        copied_profile.spec_path.parent / "embedded-notices.json"
    ).read_bytes() == standalone_build._EMBEDDED_NOTICES_PATH.read_bytes()
    warning = _capture_build_metadata(
        work_dir,
        metadata_dir,
        Path(sys.executable),
        pip_report,
        _sanitized_environment(),
        tmp_path,
        _orchestration_request(tmp_path),
        "a" * 64,
        copied_profile,
        standalone_build._RuntimeNoticeSource(
            staged_path=tmp_path / "runtime-notice" / "CPython-LICENSE.txt",
            sha256="b" * 64,
            python_version=platform.python_version(),
        ),
        _staged_embedded_notices(tmp_path),
    )

    pyinstaller_dir = metadata_dir / "pyinstaller"
    assert warning == pyinstaller_dir / "warn-servonaut.txt"
    assert warning.read_text(encoding="utf-8") == "warning\n"
    assert (pyinstaller_dir / "Analysis-00.toc").read_text(
        encoding="utf-8"
    ) == "analysis\n"
    assert (pyinstaller_dir / "PYZ-00.toc").read_text(encoding="utf-8") == "pyz\n"
    assert json.loads(
        (metadata_dir / "resolved" / "build-provenance.json").read_text(
            encoding="utf-8"
        )
    ) == {
        "build_revision": "build-1",
        "product_version": "1.2.3",
        "schema_version": 1,
        "source_commit": "abc1234",
        "target": _LINUX_TARGET,
        "wheel_sha256": "a" * 64,
    }
    toolchain = json.loads(
        (metadata_dir / "resolved" / "build-toolchain.json").read_text(encoding="utf-8")
    )
    assert toolchain["schema_version"] == 1
    assert toolchain["python_implementation"] == "CPython"
    assert len(toolchain["python_version"].split(".")) == 3
    assert toolchain["spec_sha256"] == standalone_build._sha256_file(
        standalone_build._SPEC_PATH
    )
    assert len(toolchain["hooks_sha256"]) == 64
    assert json.loads(
        (metadata_dir / "resolved" / "runtime-notice.json").read_text(encoding="utf-8")
    ) == {
        "license_id": "Python-2.0",
        "payload_path": "_internal/notices/CPython-LICENSE.txt",
        "python_implementation": "CPython",
        "python_version": platform.python_version(),
        "runtime": "cpython",
        "schema_version": 1,
        "sha256": "b" * 64,
    }
    assert (
        len(
            json.loads(
                (metadata_dir / "resolved" / "third-party-notices.json").read_text(
                    encoding="utf-8"
                )
            )["notices"]
        )
        == 5
    )


def test_environment_inventory_requires_report_v1_sha256_and_canonical_names(
    tmp_path: Path,
) -> None:
    report = tmp_path / "pip-report.json"
    report.write_text(
        json.dumps(
            {
                "version": "1",
                "install": [
                    {
                        "metadata": {"name": "Example__Package", "version": "1.0"},
                        "download_info": {
                            "archive_info": {"hashes": {"sha256": "A" * 64}}
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    destination = tmp_path / "environment.json"

    _write_environment_inventory(report, destination)

    assert json.loads(destination.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "packages": [
            {
                "hashes": [f"sha256:{'a' * 64}"],
                "name": "example-package",
                "version": "1.0",
            }
        ],
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"version": "2", "install": []},
        {
            "version": "1",
            "install": [{"metadata": {"name": "example", "version": "1.0"}}],
        },
        {
            "version": "1",
            "install": [
                {
                    "metadata": {"name": "example-package", "version": "1.0"},
                    "download_info": {"archive_info": {"hashes": {"sha256": "a" * 64}}},
                },
                {
                    "metadata": {"name": "example_package", "version": "2.0"},
                    "download_info": {"archive_info": {"hashes": {"sha256": "b" * 64}}},
                },
            ],
        },
    ],
)
def test_environment_inventory_rejects_invalid_or_duplicate_records(
    tmp_path: Path, payload: dict[str, object]
) -> None:
    report = tmp_path / "pip-report.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(BuildValidationError):
        _write_environment_inventory(report, tmp_path / "environment.json")


def test_license_inventory_normalizes_package_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        standalone_build,
        "_run_capture",
        lambda *args: (
            '[{"name":"Example__Package","version":"1.0","license":"MIT",'
            '"license_expression":"MIT","license_classifiers":["License :: OSI :: MIT License"],'
            '"license_files":["LICENSE"]}]'
        ),
    )
    destination = tmp_path / "licenses.json"

    _write_license_inventory(Path(sys.executable), destination, {}, tmp_path, 60)

    assert json.loads(destination.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "packages": [
            {
                "license": "MIT",
                "license_classifiers": ["License :: OSI :: MIT License"],
                "license_expression": "MIT",
                "license_files": ["LICENSE"],
                "name": "example-package",
                "version": "1.0",
            }
        ],
    }


@pytest.mark.parametrize(
    ("stage", "exception_type"),
    [
        ("initialization", BuildValidationError),
        ("metadata", BuildValidationError),
        ("marker", BuildValidationError),
        ("payload-promotion", KeyboardInterrupt),
        ("metadata-promotion", KeyboardInterrupt),
    ],
)
def test_build_standalone_cleans_only_its_staging_after_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    exception_type: type[BaseException],
) -> None:
    """Every failure before or during publication leaves the output retryable."""
    request = _orchestration_request(tmp_path)
    _stub_build_orchestration(monkeypatch, stage)

    with pytest.raises(exception_type):
        build_standalone(request)

    _assert_no_published_output(request.output_dir)
    _stub_build_orchestration(monkeypatch, None)
    result = build_standalone(request)

    assert result.executable.is_file()
    assert result.marker.is_file()
    assert result.pyinstaller_warning_file.is_file()
    assert result.build_metadata_dir.is_dir()


def test_build_standalone_bootstraps_pip_with_a_sanitized_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first child Python process tolerates a poisoned parent environment."""
    monkeypatch.setenv("PYTHONPLATLIBDIR", str(tmp_path / "missing-libraries"))
    request = _orchestration_request(tmp_path)
    _stub_build_orchestration(monkeypatch, None, real_private_venv=True)

    result = build_standalone(request)

    assert result.executable.is_file()
    assert result.marker.is_file()


def test_build_standalone_rolls_back_after_successful_publication_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The outer ledger owns publication until the success commit point."""
    request = _orchestration_request(tmp_path)
    _stub_build_orchestration(monkeypatch, None)
    real_publish = standalone_build._publish_staged_outputs

    def interrupt_after_real_publish(*args: object) -> None:
        real_publish(*args)
        raise KeyboardInterrupt()

    monkeypatch.setattr(
        standalone_build, "_publish_staged_outputs", interrupt_after_real_publish
    )

    with pytest.raises(KeyboardInterrupt):
        build_standalone(request)

    _assert_no_published_output(request.output_dir)
    monkeypatch.setattr(standalone_build, "_publish_staged_outputs", real_publish)
    result = build_standalone(request)
    assert result.executable.is_file()
    assert result.marker.is_file()


def test_build_standalone_preserves_a_new_unowned_promotion_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cleanup must not remove an output another process creates after preflight."""
    request = _orchestration_request(tmp_path)
    _stub_build_orchestration(monkeypatch, None)
    original_publish = standalone_build._publish_owned_directory

    def create_collision_then_publish(*args: object) -> None:
        source, destination, published = args
        assert isinstance(source, Path)
        assert isinstance(destination, Path)
        assert isinstance(published, dict)
        destination.mkdir()
        (destination / "foreign.txt").write_text("keep", encoding="utf-8")
        original_publish(source, destination, published)

    monkeypatch.setattr(
        standalone_build, "_publish_owned_directory", create_collision_then_publish
    )

    with pytest.raises(BuildValidationError, match="already exists"):
        build_standalone(request)

    collision = request.output_dir / "servonaut"
    assert (collision / "foreign.txt").read_text(encoding="utf-8") == "keep"
    assert not (request.output_dir / "build-metadata").exists()
    assert not (request.output_dir / ".pyinstaller-dist").exists()
    assert not (request.output_dir / ".build-metadata-staging").exists()


@pytest.mark.parametrize("kind", ("file", "directory", "symlink"))
def test_prepare_output_directory_preserves_existing_targets(
    tmp_path: Path, kind: str
) -> None:
    output = tmp_path / "output"
    if kind == "file":
        output.write_text("keep", encoding="utf-8")
    elif kind == "directory":
        output.mkdir()
        (output / "foreign.txt").write_text("keep", encoding="utf-8")
    else:
        target = tmp_path / "target"
        target.mkdir()
        try:
            output.symlink_to(target, target_is_directory=True)
        except OSError:
            pytest.skip("symlinks are unavailable on this test host")

    with pytest.raises(BuildValidationError, match="new private directory"):
        _prepare_output_directory(output)

    if kind == "file":
        assert output.read_text(encoding="utf-8") == "keep"
    elif kind == "directory":
        assert (output / "foreign.txt").read_text(encoding="utf-8") == "keep"
    else:
        assert output.is_symlink()


def test_main_normalizes_an_invalid_output_path_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "output-file"
    output.write_text("keep", encoding="utf-8")
    target = _target_spec(tmp_path)
    monkeypatch.setattr(standalone_build, "load_target_spec", lambda *_args: target)
    monkeypatch.setattr(
        standalone_build, "validate_build_request", lambda _request: None
    )
    monkeypatch.setattr(standalone_build, "_validate_host_target", lambda _target: None)

    with pytest.raises(SystemExit) as error:
        main(
            [
                "--wheel",
                str(_wheel(tmp_path)),
                "--target",
                _LINUX_TARGET,
                "--product-version",
                "1.2.3",
                "--revision",
                "build-1",
                "--commit",
                "abc1234",
                "--output",
                str(output),
            ]
        )

    assert error.value.code == 2
    assert "output directory must be a new private directory" in capsys.readouterr().err
    assert output.read_text(encoding="utf-8") == "keep"


def test_main_rejects_a_release_tag_it_would_not_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    builds: list[BuildRequest] = []
    target = _target_spec(tmp_path)
    monkeypatch.setattr(standalone_build, "load_target_spec", lambda *_args: target)
    monkeypatch.setattr(standalone_build, "build_standalone", builds.append)

    with pytest.raises(SystemExit) as error:
        main(
            [
                "--wheel",
                str(_wheel(tmp_path)),
                "--target",
                _LINUX_TARGET,
                "--product-version",
                "1.2.3",
                "--release-tag",
                "v1.2.3",
                "--revision",
                "build-1",
                "--commit",
                "abc1234",
                "--output",
                str(tmp_path / "output"),
            ]
        )

    assert error.value.code == 2
    assert "--release-tag" in capsys.readouterr().err
    assert builds == []


def _orchestration_request(tmp_path: Path) -> BuildRequest:
    return BuildRequest(
        wheel=_wheel(tmp_path),
        target=_target_spec(tmp_path),
        product_version="1.2.3",
        build_revision="build-1",
        source_commit="abc1234",
        output_dir=tmp_path / "output",
        require_artifact_selftest=False,
    )


def _staged_embedded_notices(
    tmp_path: Path, metadata_root: Path | None = None
) -> StagedEmbeddedNotices:
    staging_root = (metadata_root or tmp_path) / "third-party-notices"
    staging_root.mkdir()
    records: list[EmbeddedNoticeRecord] = []
    for index in range(5):
        data = f"notice {index}\n".encode()
        path = PurePosixPath(f"_internal/notices/package-{index}-LICENSE.txt")
        (staging_root / path.name).write_bytes(data)
        records.append(
            EmbeddedNoticeRecord(
                distribution=f"package-{index}",
                version="1.0",
                source_wheel_sha256=f"{index + 1:064x}",
                payload_path=path,
                sha256=standalone_build.hashlib.sha256(data).hexdigest(),
            )
        )
    return StagedEmbeddedNotices(staging_root.resolve(), tuple(records))


def _stub_build_orchestration(
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str | None,
    *,
    real_private_venv: bool = False,
) -> None:
    monkeypatch.setattr(
        standalone_build, "validate_build_request", lambda request: None
    )
    monkeypatch.setattr(standalone_build, "_validate_host_target", lambda target: None)
    monkeypatch.setattr(standalone_build, "_require_builder_inputs", lambda: None)

    def prepare_runtime_notice(
        _python: Path,
        _target: TargetSpec,
        metadata_dir: Path,
        _environment: dict[str, str],
        _working_directory: Path,
    ) -> standalone_build._RuntimeNoticeSource:
        notice = metadata_dir / "runtime-notice" / "CPython-LICENSE.txt"
        notice.parent.mkdir()
        notice.write_bytes(b"CPython notice fixture\n")
        return standalone_build._RuntimeNoticeSource(
            staged_path=notice.resolve(),
            sha256=standalone_build._sha256_file(notice),
            python_version="3.12.14",
        )

    if not real_private_venv:
        monkeypatch.setattr(
            standalone_build, "_prepare_runtime_notice", prepare_runtime_notice
        )
    if not real_private_venv:
        monkeypatch.setattr(standalone_build, "_assert_venv_prefix", lambda *args: None)
        monkeypatch.setattr(
            standalone_build, "_venv_site_packages", lambda *args: Path(args[0]).parent
        )
        monkeypatch.setattr(standalone_build, "_bootstrap_venv_pip", lambda *args: None)
        monkeypatch.setattr(standalone_build.venv, "EnvBuilder", _FakeEnvBuilder)

    if failure_stage == "initialization":
        original_create = standalone_build._create_staging_directory
        calls = 0

        def fail_second_initialization(path: Path) -> tuple[int, int]:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise BuildValidationError("metadata staging failed")
            return original_create(path)

        monkeypatch.setattr(
            standalone_build, "_create_staging_directory", fail_second_initialization
        )

    def install(*args: object, **_kwargs: object) -> None:
        report = args[3]
        assert isinstance(report, Path)
        report.write_text('{"install": []}', encoding="utf-8")

    monkeypatch.setattr(standalone_build, "_install_wheel_and_lock", install)
    monkeypatch.setattr(
        standalone_build,
        "prepare_embedded_notices",
        lambda _config, _site, _report, _target, metadata, _limit: (
            _staged_embedded_notices(metadata.parent, metadata)
        ),
    )
    monkeypatch.setattr(standalone_build, "_write_profile", lambda *args: None)

    def run_pyinstaller(*args: object) -> None:
        staging_dir = args[2]
        environment = args[3]
        assert isinstance(staging_dir, Path)
        assert isinstance(environment, dict)
        payload = staging_dir / "servonaut"
        payload.mkdir()
        (payload / "servonaut").write_text("fixture", encoding="utf-8")
        notice = payload / "_internal" / "notices" / "CPython-LICENSE.txt"
        notice.parent.mkdir(parents=True)
        notice.write_bytes(
            Path(environment["SERVONAUT_STANDALONE_RUNTIME_NOTICE_SOURCE"]).read_bytes()
        )
        embedded_root = Path(
            environment["SERVONAUT_STANDALONE_THIRD_PARTY_NOTICES_ROOT"]
        )
        for source in embedded_root.iterdir():
            (notice.parent / source.name).write_bytes(source.read_bytes())

    monkeypatch.setattr(standalone_build, "_run_pyinstaller", run_pyinstaller)

    def capture_metadata(*args: object) -> Path:
        if failure_stage == "metadata":
            raise BuildValidationError("metadata capture failed")
        metadata_dir = args[1]
        assert isinstance(metadata_dir, Path)
        warning = metadata_dir / "pyinstaller" / "warn-servonaut.txt"
        warning.parent.mkdir()
        warning.write_text("fixture", encoding="utf-8")
        return warning

    monkeypatch.setattr(standalone_build, "_capture_build_metadata", capture_metadata)

    def write_marker(payload: Path, *_args: object, **_kwargs: object) -> Path:
        if failure_stage == "marker":
            raise BuildValidationError("marker validation failed")
        marker = payload / "servonaut-runtime.json"
        marker.write_text("{}\n", encoding="utf-8")
        return marker

    monkeypatch.setattr(standalone_build, "write_runtime_marker", write_marker)

    if failure_stage in {"payload-promotion", "metadata-promotion"}:
        original_publish = standalone_build._publish_owned_directory
        fail_after_call = 1 if failure_stage == "payload-promotion" else 2
        calls = 0

        def interrupt_after_publish(*args: object) -> None:
            nonlocal calls
            original_publish(*args)
            calls += 1
            if calls == fail_after_call:
                raise KeyboardInterrupt()

        monkeypatch.setattr(
            standalone_build, "_publish_owned_directory", interrupt_after_publish
        )


class _FakeEnvBuilder:
    def __init__(self, **_kwargs: object) -> None:
        pass

    def create(self, venv_root: Path) -> None:
        interpreter = venv_root / (
            "Scripts/python.exe" if os.name == "nt" else "bin/python"
        )
        interpreter.parent.mkdir(parents=True)
        interpreter.write_text("fixture", encoding="utf-8")


def _assert_no_published_output(output_dir: Path) -> None:
    assert not output_dir.exists()
    assert not output_dir.is_symlink()
    for name in (
        "servonaut",
        "build-metadata",
        ".pyinstaller-dist",
        ".build-metadata-staging",
    ):
        assert not (output_dir / name).exists()
        assert not (output_dir / name).is_symlink()


def _target_spec(tmp_path: Path) -> TargetSpec:
    return load_target_spec(_write_policy(tmp_path), _LINUX_TARGET)


def _installable_wheel(
    tmp_path: Path,
    *,
    name: str = "servonaut",
    version: str = "1.2.3",
    requires: tuple[str, ...] = (),
) -> Path:
    wheel = tmp_path / f"{name}-{version}-py3-none-any.whl"
    requirements = "".join(f"Requires-Dist: {item}\n" for item in requires)
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(f"{name}/__init__.py", f"__version__ = '{version}'\n")
        archive.writestr(
            f"{name}-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
            + requirements,
        )
        archive.writestr(
            f"{name}-{version}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(f"{name}-{version}.dist-info/RECORD", "")
    return wheel
