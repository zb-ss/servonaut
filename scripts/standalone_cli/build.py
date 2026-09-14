"""Build a wheel-only, console PyInstaller onedir standalone payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform as host_platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import venv
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from scripts.standalone_cli.evidence_policy import load_evidence_policy
from scripts.standalone_cli.model import (
    BuildRequest,
    BuildResult,
    BuildValidationError,
    TargetSpec,
    load_target_spec,
    validate_build_request,
)
from scripts.standalone_cli.runtime_marker import write_runtime_marker

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_POLICY_PATH = _PROJECT_ROOT / "packaging" / "standalone_cli" / "target-policy.json"
_EVIDENCE_POLICY_PATH = (
    _PROJECT_ROOT / "packaging" / "standalone_cli" / "evidence-policy.json"
)
_SPEC_PATH = _PROJECT_ROOT / "packaging" / "standalone_cli" / "servonaut_cli.spec"
_HOOK_DIRECTORY = _PROJECT_ROOT / "packaging" / "standalone_cli" / "hooks"
_PAYLOAD_NAME = "servonaut"
_METADATA_NAME = "build-metadata"
_METADATA_STAGING_NAME = ".build-metadata-staging"
_DirectoryIdentity = tuple[int, int]


@dataclass(frozen=True)
class _StagedBuild:
    payload_root: Path
    executable: Path
    marker: Path
    warning_file: Path


@dataclass(frozen=True)
class _OwnedOutputDirectory:
    path: Path
    identity: _DirectoryIdentity


@dataclass(frozen=True)
class _BuildProfile:
    spec_path: Path
    hook_directory: Path
    spec_sha256: str
    hooks_sha256: str


@dataclass(frozen=True)
class _RuntimeNoticeSource:
    """One attested CPython notice copied from the selected isolated runtime."""

    staged_path: Path
    sha256: str
    python_version: str


def build_standalone(request: BuildRequest) -> BuildResult:
    """Build one target from an installed wheel in a fresh isolated venv."""
    validate_build_request(request)
    _validate_host_target(request.target)
    output = _prepare_output_directory(request.output_dir)
    output_dir = output.path
    payload_root = output_dir / _PAYLOAD_NAME
    metadata_dir = output_dir / _METADATA_NAME
    staging_dir = output_dir / ".pyinstaller-dist"
    metadata_staging_dir = output_dir / _METADATA_STAGING_NAME
    owned_staging: dict[Path, _DirectoryIdentity] = {}
    owned_published: dict[Path, _DirectoryIdentity] = {}
    completed = False

    try:
        for candidate in (
            payload_root,
            metadata_dir,
            staging_dir,
            metadata_staging_dir,
        ):
            if candidate.exists() or candidate.is_symlink():
                raise BuildValidationError(
                    f"output destination already exists: {candidate.name}"
                )
        _require_builder_inputs()
        owned_staging[staging_dir] = _create_staging_directory(staging_dir)
        owned_staging[metadata_staging_dir] = _create_staging_directory(
            metadata_staging_dir
        )
        staged = _build_staged_payload(request, staging_dir, metadata_staging_dir)
        _publish_staged_outputs(
            staged.payload_root,
            payload_root,
            metadata_staging_dir,
            metadata_dir,
            owned_published,
        )
        result = BuildResult(
            payload_root=payload_root,
            executable=payload_root / staged.executable.name,
            marker=payload_root / staged.marker.name,
            pyinstaller_warning_file=metadata_dir
            / "pyinstaller"
            / staged.warning_file.name,
            build_metadata_dir=metadata_dir,
            archive=None,
        )
        completed = True
        return result
    except (OSError, subprocess.SubprocessError) as error:
        raise BuildValidationError("standalone build failed") from error
    finally:
        if not completed:
            _remove_published_outputs(owned_published)
        for path, identity in owned_staging.items():
            _remove_owned_directory(path, identity)
        if not completed:
            _remove_empty_owned_output_directory(output)


def _build_staged_payload(
    request: BuildRequest, staging_dir: Path, metadata_staging_dir: Path
) -> _StagedBuild:
    with tempfile.TemporaryDirectory(prefix="servonaut-standalone-") as temporary:
        temporary_root = Path(temporary).resolve()
        venv_root = temporary_root / "venv"
        work_dir = temporary_root / "pyinstaller-work"
        copied_profile = _copy_build_profile(temporary_root / "build-profile")
        profile_path = temporary_root / "resolved-profile.json"
        pip_report = temporary_root / "pip-report.json"
        wheel_sha256 = _sha256_file(request.wheel)
        venv.EnvBuilder(with_pip=False, clear=True).create(venv_root)
        venv_python = _venv_python(venv_root)
        bootstrap_environment = _sanitized_environment()
        _assert_venv_prefix(
            venv_python, venv_root, bootstrap_environment, temporary_root
        )
        _bootstrap_venv_pip(venv_python, bootstrap_environment, temporary_root)
        runtime_notice = _prepare_runtime_notice(
            venv_python,
            request.target,
            metadata_staging_dir,
            bootstrap_environment,
            temporary_root,
        )
        entry_script = venv_root / "servonaut-entry.py"
        build_env = _build_environment(
            entry_script=entry_script,
            site_packages=_venv_site_packages(
                venv_python, bootstrap_environment, temporary_root
            ),
            profile_path=profile_path,
            output_dir=staging_dir,
            metadata_dir=metadata_staging_dir,
            runtime_notice_source=runtime_notice.staged_path,
            require_artifact_selftest=request.require_artifact_selftest,
        )
        _install_wheel_and_lock(
            venv_python,
            request.wheel.resolve(),
            request.target.requirements_lock,
            pip_report,
            build_env,
            temporary_root,
            wheel_sha256=wheel_sha256,
        )
        site_packages = _venv_site_packages(venv_python, build_env, temporary_root)
        entry_script.write_text(
            "from servonaut.main import main\nmain()\n", encoding="utf-8"
        )
        _write_profile(
            profile_path, request, site_packages, copied_profile.hook_directory
        )
        build_env = _build_environment(
            entry_script=entry_script,
            site_packages=site_packages,
            profile_path=profile_path,
            output_dir=staging_dir,
            metadata_dir=metadata_staging_dir,
            runtime_notice_source=runtime_notice.staged_path,
            require_artifact_selftest=request.require_artifact_selftest,
        )
        _run_pyinstaller(
            venv_python,
            work_dir,
            staging_dir,
            build_env,
            temporary_root,
            copied_profile.spec_path,
        )
        staged_payload = staging_dir / _PAYLOAD_NAME
        executable = staged_payload / _executable_name(request.target)
        if not staged_payload.is_dir() or not executable.is_file():
            raise BuildValidationError(
                "PyInstaller did not create the expected onedir payload"
            )
        _validate_payload_runtime_notice(staged_payload, runtime_notice)
        warning_file = _capture_build_metadata(
            work_dir,
            metadata_staging_dir,
            venv_python,
            pip_report,
            build_env,
            temporary_root,
            request,
            wheel_sha256,
            copied_profile,
            runtime_notice,
        )
        marker = write_runtime_marker(
            staged_payload,
            executable,
            request,
            isolated_python=venv_python,
            isolated_site_packages=site_packages,
            working_directory=temporary_root,
        )
        return _StagedBuild(staged_payload, executable, marker, warning_file)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the standalone builder CLI without requiring a release tag in CI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--policy", type=Path, default=_POLICY_PATH)
    parser.add_argument("--product-version", required=True)
    parser.add_argument("--release-tag")
    parser.add_argument("--revision", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-artifact-selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.release_tag is not None and args.release_tag != f"v{args.product_version}":
        parser.error("--release-tag must equal v<product-version>")
    try:
        request = BuildRequest(
            wheel=args.wheel,
            target=load_target_spec(args.policy, args.target),
            product_version=args.product_version,
            build_revision=args.revision,
            source_commit=args.commit,
            output_dir=args.output,
            require_artifact_selftest=args.require_artifact_selftest,
        )
        build_standalone(request)
    except (BuildValidationError, TypeError) as error:
        parser.error(str(error))
    return 0


def _prepare_output_directory(path: Path) -> _OwnedOutputDirectory:
    if not isinstance(path, Path):
        raise TypeError("output_dir must be a Path")
    if path.exists() or path.is_symlink():
        raise BuildValidationError("output directory must be a new private directory")
    try:
        path.mkdir(mode=0o700)
        resolved = path.resolve(strict=True)
        identity = _directory_identity(resolved)
    except OSError as error:
        raise BuildValidationError("output directory could not be created") from error
    return _OwnedOutputDirectory(resolved, identity)


def _require_builder_inputs() -> None:
    for path, label in (
        (_SPEC_PATH, "PyInstaller spec"),
        (_HOOK_DIRECTORY, "hook directory"),
    ):
        if (
            not path.exists()
            or (label == "PyInstaller spec" and not path.is_file())
            or (label == "hook directory" and not path.is_dir())
        ):
            raise BuildValidationError(f"{label} is unavailable")


def _validate_host_target(target: TargetSpec) -> None:
    if sys.version_info[:2] != (3, 12):
        raise BuildValidationError(
            "standalone builds require the Python 3.12 interpreter"
        )
    current_platform = "darwin" if sys.platform == "darwin" else sys.platform
    if current_platform != target.platform:
        raise BuildValidationError(
            "standalone builds must run on their target platform"
        )
    machine = host_platform.machine().casefold()
    current_architecture = (
        "arm64"
        if machine in {"arm64", "aarch64"}
        else "x86_64"
        if machine in {"x86_64", "amd64"}
        else machine
    )
    if current_architecture != target.architecture:
        raise BuildValidationError(
            "standalone builds must run on their target architecture"
        )


def _install_wheel_and_lock(
    python: Path,
    wheel: Path,
    lock: Path,
    report: Path,
    environment: dict[str, str],
    working_directory: Path,
    *,
    wheel_sha256: str | None = None,
) -> None:
    wheel_hash = _sha256_file(wheel) if wheel_sha256 is None else wheel_sha256
    wheel_requirement = f"{wheel.as_uri()}#sha256={wheel_hash}"
    _run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--isolated",
            "--disable-pip-version-check",
            "--no-input",
            "--require-hashes",
            "--report",
            str(report),
            "--no-deps",
            wheel_requirement,
            "-r",
            str(lock),
        ],
        environment,
        working_directory,
    )


def _bootstrap_venv_pip(
    python: Path, environment: dict[str, str], working_directory: Path
) -> None:
    """Install pip only after the venv interpreter is running in a clean environment."""
    _run(
        [str(python), "-m", "ensurepip", "--upgrade"],
        environment,
        working_directory,
    )


def _venv_python(venv_root: Path) -> Path:
    candidate = venv_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not candidate.is_file():
        raise BuildValidationError("isolated venv did not provide a Python interpreter")
    # POSIX venv Python is usually a symlink to the base interpreter. Its
    # lexical venv path selects pyvenv.cfg and must never be dereferenced.
    return candidate.absolute()


def _assert_venv_prefix(
    python: Path,
    venv_root: Path,
    environment: dict[str, str],
    working_directory: Path,
) -> None:
    prefix = Path(
        _run_capture(
            [str(python), "-c", "import sys; print(sys.prefix)"],
            environment,
            working_directory,
        ).strip()
    )
    try:
        if prefix.resolve(strict=True) != venv_root.resolve(strict=True):
            raise BuildValidationError(
                "isolated interpreter does not use the private venv"
            )
    except OSError as error:
        raise BuildValidationError(
            "isolated interpreter prefix is unavailable"
        ) from error


def _venv_site_packages(
    python: Path, environment: dict[str, str], working_directory: Path
) -> Path:
    output = _run_capture(
        [str(python), "-c", "import site; print(site.getsitepackages()[0])"],
        environment,
        working_directory,
    )
    path = Path(output.strip())
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise BuildValidationError(
            "isolated venv site-packages is unavailable"
        ) from error


def _build_environment(
    *,
    entry_script: Path,
    site_packages: Path,
    profile_path: Path,
    output_dir: Path,
    metadata_dir: Path,
    runtime_notice_source: Path,
    require_artifact_selftest: bool,
) -> dict[str, str]:
    runtime_notice = _validated_runtime_notice_source(
        metadata_dir, runtime_notice_source
    )
    environment = _sanitized_environment()
    environment.update(
        {
            "SERVONAUT_STANDALONE_ENTRY_SCRIPT": str(entry_script.resolve()),
            "SERVONAUT_STANDALONE_ISOLATED_SITE_PACKAGES": str(site_packages.resolve()),
            "SERVONAUT_STANDALONE_PROFILE_PATH": str(profile_path.resolve()),
            "SERVONAUT_STANDALONE_OUTPUT_DIR": str(output_dir.resolve()),
            "SERVONAUT_STANDALONE_BUILD_METADATA_DIR": str(metadata_dir.resolve()),
            "SERVONAUT_STANDALONE_RUNTIME_NOTICE_SOURCE": str(runtime_notice),
            "SERVONAUT_STANDALONE_REQUIRE_ARTIFACT_SELFTEST": "1"
            if require_artifact_selftest
            else "0",
        }
    )
    return environment


def _validated_runtime_notice_source(metadata_dir: Path, source: Path) -> Path:
    expected = metadata_dir.resolve() / "runtime-notice" / "CPython-LICENSE.txt"
    source = source.absolute()
    try:
        source_status = source.lstat()
    except OSError as error:
        raise BuildValidationError("staged Python notice is unavailable") from error
    if (
        source != expected
        or not stat.S_ISREG(source_status.st_mode)
        or source.is_symlink()
    ):
        raise BuildValidationError("staged Python notice is invalid")
    return source


def _runtime_notice_max_bytes() -> int:
    try:
        limit = load_evidence_policy(
            _EVIDENCE_POLICY_PATH
        ).limits.max_metadata_file_bytes
    except ValueError as error:
        raise BuildValidationError("runtime notice policy is unavailable") from error
    if type(limit) is not int or limit <= 0:
        raise BuildValidationError("runtime notice policy is invalid")
    return limit


def _prepare_runtime_notice(
    python: Path,
    target: TargetSpec,
    metadata_dir: Path,
    environment: dict[str, str],
    working_directory: Path,
) -> _RuntimeNoticeSource:
    """Copy the one CPython notice selected by the isolated target interpreter."""
    output = _run_capture(
        [
            str(python),
            "-c",
            (
                "import json, platform, sys, sysconfig; "
                "print(json.dumps({'base_prefix': sys.base_prefix, "
                "'stdlib': sysconfig.get_path('stdlib'), "
                "'python_implementation': platform.python_implementation(), "
                "'python_version': platform.python_version()}))"
            ),
        ],
        environment,
        working_directory,
    )
    try:
        facts = json.loads(output)
    except json.JSONDecodeError as error:
        raise BuildValidationError(
            "private Python runtime facts are invalid"
        ) from error
    if (
        not isinstance(facts, dict)
        or set(facts)
        != {
            "base_prefix",
            "stdlib",
            "python_implementation",
            "python_version",
        }
        or any(not isinstance(value, str) or not value for value in facts.values())
        or facts["python_implementation"] != "CPython"
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", facts["python_version"])
    ):
        raise BuildValidationError("private Python runtime facts are invalid")
    limit = _runtime_notice_max_bytes()
    try:
        base_prefix = Path(facts["base_prefix"]).resolve(strict=True)
        if not base_prefix.is_dir():
            raise BuildValidationError("private Python base prefix is invalid")
        candidate_root = (
            base_prefix if target.platform == "win32" else Path(facts["stdlib"])
        )
        if not candidate_root.is_absolute():
            raise BuildValidationError("private Python notice source is invalid")
        resolved_candidate_root = candidate_root.resolve(strict=True)
        if not resolved_candidate_root.is_dir():
            raise BuildValidationError("private Python notice source is invalid")
        resolved_candidate_root.relative_to(base_prefix)
        source = candidate_root / "LICENSE.txt"
        source_status = source.lstat()
        if not stat.S_ISREG(source_status.st_mode) or source.is_symlink():
            raise BuildValidationError("private Python notice source is invalid")
        resolved_source = source.resolve(strict=True)
        resolved_source.relative_to(base_prefix)
        if source_status.st_size <= 0 or source_status.st_size > limit:
            raise BuildValidationError(
                "private Python notice source has an invalid size"
            )
        notice_directory = metadata_dir / "runtime-notice"
        notice_directory.mkdir()
        destination = notice_directory / "CPython-LICENSE.txt"
        shutil.copyfile(resolved_source, destination)
        destination_status = destination.lstat()
        if not stat.S_ISREG(destination_status.st_mode) or destination.is_symlink():
            raise BuildValidationError("staged Python notice is invalid")
        if destination_status.st_size <= 0 or destination_status.st_size > limit:
            raise BuildValidationError("staged Python notice has an invalid size")
    except (OSError, ValueError) as error:
        raise BuildValidationError(
            "private Python notice source is unavailable"
        ) from error
    return _RuntimeNoticeSource(
        staged_path=destination.resolve(strict=True),
        sha256=_sha256_file(destination),
        python_version=facts["python_version"],
    )


def _validate_payload_runtime_notice(
    payload_root: Path, runtime_notice: _RuntimeNoticeSource
) -> None:
    """Bind the PyInstaller data copy to the retained isolated-runtime record."""
    notice = payload_root / "_internal" / "notices" / "CPython-LICENSE.txt"
    try:
        notice_status = notice.lstat()
        limit = _runtime_notice_max_bytes()
        if not stat.S_ISREG(notice_status.st_mode) or notice.is_symlink():
            raise BuildValidationError("PyInstaller runtime notice is invalid")
        resolved_notice = notice.resolve(strict=True)
        resolved_notice.relative_to(payload_root.resolve(strict=True))
        if (
            notice_status.st_size <= 0
            or notice_status.st_size > limit
            or _sha256_file(notice) != runtime_notice.sha256
        ):
            raise BuildValidationError("PyInstaller runtime notice is invalid")
    except BuildValidationError:
        raise
    except (OSError, ValueError) as error:
        raise BuildValidationError(
            "PyInstaller runtime notice is unavailable"
        ) from error


def _sanitized_environment() -> dict[str, str]:
    """Remove inherited Python and standalone-build state before child Python runs."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.casefold().startswith(("python", "pip_", "servonaut_standalone_"))
    }
    environment["PIP_CONFIG_FILE"] = os.devnull
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def _write_profile(
    profile_path: Path,
    request: BuildRequest,
    site_packages: Path,
    hook_directory: Path,
) -> None:
    exclusions = tuple(dict.fromkeys((*request.target.forbidden_modules, "readline")))
    profile = {
        "schema_version": 1,
        "target_name": request.target.name,
        "target_platform": request.target.platform,
        "target_architecture": request.target.architecture,
        "python_version": request.target.python_version,
        "payload_name": _PAYLOAD_NAME,
        "product_version": request.product_version,
        "excluded_modules": list(exclusions),
        "hook_directory": str(hook_directory.resolve()),
        "require_artifact_selftest": request.require_artifact_selftest,
    }
    profile_path.write_text(
        json.dumps(profile, sort_keys=True) + "\n", encoding="utf-8"
    )


def _copy_build_profile(destination: Path) -> _BuildProfile:
    """Copy the exact spec and hooks passed to one isolated PyInstaller run."""
    try:
        destination.mkdir()
        spec_path = destination / _SPEC_PATH.name
        hook_directory = destination / "hooks"
        shutil.copy2(_SPEC_PATH, spec_path)
        shutil.copytree(_HOOK_DIRECTORY, hook_directory)
    except OSError as error:
        raise BuildValidationError(
            "could not prepare the standalone build profile"
        ) from error
    return _BuildProfile(
        spec_path=spec_path,
        hook_directory=hook_directory,
        spec_sha256=_sha256_file(spec_path),
        hooks_sha256=_hook_directory_sha256(hook_directory),
    )


def _hook_directory_sha256(directory: Path) -> str:
    records: list[dict[str, str]] = []
    try:
        for path in sorted(directory.rglob("*"), key=lambda item: item.as_posix()):
            if not path.is_file() or path.is_symlink():
                raise BuildValidationError(
                    "standalone build profile contains an invalid hook"
                )
            records.append(
                {
                    "relative_name": path.relative_to(directory).as_posix(),
                    "content_sha256": _sha256_file(path),
                }
            )
    except OSError as error:
        raise BuildValidationError(
            "could not read the standalone build profile"
        ) from error
    if not records:
        raise BuildValidationError("standalone build profile has no hooks")
    encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _run_pyinstaller(
    python: Path,
    work_dir: Path,
    staging_dir: Path,
    environment: dict[str, str],
    working_directory: Path,
    spec_path: Path,
) -> None:
    try:
        _run(
            [
                str(python),
                "-m",
                "PyInstaller",
                "--noconfirm",
                "--clean",
                "--workpath",
                str(work_dir),
                "--distpath",
                str(staging_dir),
                str(spec_path.resolve()),
            ],
            environment,
            working_directory,
        )
    except subprocess.CalledProcessError as error:
        if type(error) is not subprocess.CalledProcessError:
            raise
        returncode = error.returncode
        if type(returncode) is not int:
            raise
        raiser = _PYINSTALLER_DIAGNOSTIC_RAISERS.get(returncode)
        if raiser is None:
            raise
        raiser()


def _raise_pyinstaller_profile_failure() -> None:
    raise BuildValidationError("PyInstaller profile phase failed")


def _raise_pyinstaller_runtime_metadata_failure() -> None:
    raise BuildValidationError("PyInstaller metadata phase failed")


def _raise_pyinstaller_analysis_failure() -> None:
    raise BuildValidationError("PyInstaller analysis phase failed")


def _raise_pyinstaller_data_filter_failure() -> None:
    raise BuildValidationError("PyInstaller data filtering phase failed")


def _raise_pyinstaller_pyz_failure() -> None:
    raise BuildValidationError("PyInstaller PYZ phase failed")


def _raise_pyinstaller_exe_failure() -> None:
    raise BuildValidationError("PyInstaller EXE phase failed")


def _raise_pyinstaller_collect_failure() -> None:
    raise BuildValidationError("PyInstaller COLLECT phase failed")


def _raise_pyinstaller_isolated_child_failure() -> None:
    raise BuildValidationError("PyInstaller isolated child failed")


def _raise_pyinstaller_hook_import_failure() -> None:
    raise BuildValidationError("PyInstaller hook import failed")


def _raise_pyinstaller_python_library_failure() -> None:
    raise BuildValidationError("PyInstaller Python library failed")


def _raise_pyinstaller_filesystem_missing_failure() -> None:
    raise BuildValidationError("PyInstaller filesystem missing")


def _raise_pyinstaller_filesystem_access_failure() -> None:
    raise BuildValidationError("PyInstaller filesystem access failed")


def _raise_pyinstaller_filesystem_capacity_failure() -> None:
    raise BuildValidationError("PyInstaller filesystem capacity failed")


def _raise_pyinstaller_recursion_failure() -> None:
    raise BuildValidationError("PyInstaller recursion limit failed")


def _raise_pyinstaller_memory_failure() -> None:
    raise BuildValidationError("PyInstaller memory exhausted")


_PYINSTALLER_DIAGNOSTIC_RAISERS = MappingProxyType(
    {
        64: _raise_pyinstaller_profile_failure,
        65: _raise_pyinstaller_isolated_child_failure,
        66: _raise_pyinstaller_hook_import_failure,
        67: _raise_pyinstaller_python_library_failure,
        68: _raise_pyinstaller_filesystem_missing_failure,
        69: _raise_pyinstaller_filesystem_access_failure,
        70: _raise_pyinstaller_filesystem_capacity_failure,
        71: _raise_pyinstaller_recursion_failure,
        72: _raise_pyinstaller_memory_failure,
        80: _raise_pyinstaller_runtime_metadata_failure,
        81: _raise_pyinstaller_isolated_child_failure,
        82: _raise_pyinstaller_hook_import_failure,
        83: _raise_pyinstaller_python_library_failure,
        84: _raise_pyinstaller_filesystem_missing_failure,
        85: _raise_pyinstaller_filesystem_access_failure,
        86: _raise_pyinstaller_filesystem_capacity_failure,
        87: _raise_pyinstaller_recursion_failure,
        88: _raise_pyinstaller_memory_failure,
        96: _raise_pyinstaller_analysis_failure,
        97: _raise_pyinstaller_isolated_child_failure,
        98: _raise_pyinstaller_hook_import_failure,
        99: _raise_pyinstaller_python_library_failure,
        100: _raise_pyinstaller_filesystem_missing_failure,
        101: _raise_pyinstaller_filesystem_access_failure,
        102: _raise_pyinstaller_filesystem_capacity_failure,
        103: _raise_pyinstaller_recursion_failure,
        104: _raise_pyinstaller_memory_failure,
        112: _raise_pyinstaller_data_filter_failure,
        113: _raise_pyinstaller_isolated_child_failure,
        114: _raise_pyinstaller_hook_import_failure,
        115: _raise_pyinstaller_python_library_failure,
        116: _raise_pyinstaller_filesystem_missing_failure,
        117: _raise_pyinstaller_filesystem_access_failure,
        118: _raise_pyinstaller_filesystem_capacity_failure,
        119: _raise_pyinstaller_recursion_failure,
        120: _raise_pyinstaller_memory_failure,
        128: _raise_pyinstaller_pyz_failure,
        129: _raise_pyinstaller_isolated_child_failure,
        130: _raise_pyinstaller_hook_import_failure,
        131: _raise_pyinstaller_python_library_failure,
        132: _raise_pyinstaller_filesystem_missing_failure,
        133: _raise_pyinstaller_filesystem_access_failure,
        134: _raise_pyinstaller_filesystem_capacity_failure,
        135: _raise_pyinstaller_recursion_failure,
        136: _raise_pyinstaller_memory_failure,
        144: _raise_pyinstaller_exe_failure,
        145: _raise_pyinstaller_isolated_child_failure,
        146: _raise_pyinstaller_hook_import_failure,
        147: _raise_pyinstaller_python_library_failure,
        148: _raise_pyinstaller_filesystem_missing_failure,
        149: _raise_pyinstaller_filesystem_access_failure,
        150: _raise_pyinstaller_filesystem_capacity_failure,
        151: _raise_pyinstaller_recursion_failure,
        152: _raise_pyinstaller_memory_failure,
        160: _raise_pyinstaller_collect_failure,
        161: _raise_pyinstaller_isolated_child_failure,
        162: _raise_pyinstaller_hook_import_failure,
        163: _raise_pyinstaller_python_library_failure,
        164: _raise_pyinstaller_filesystem_missing_failure,
        165: _raise_pyinstaller_filesystem_access_failure,
        166: _raise_pyinstaller_filesystem_capacity_failure,
        167: _raise_pyinstaller_recursion_failure,
        168: _raise_pyinstaller_memory_failure,
    }
)


def _capture_build_metadata(
    work_dir: Path,
    metadata_dir: Path,
    python: Path,
    pip_report: Path,
    environment: dict[str, str],
    working_directory: Path,
    request: BuildRequest,
    wheel_sha256: str,
    build_profile: _BuildProfile,
    runtime_notice: _RuntimeNoticeSource,
) -> Path:
    pyinstaller_dir = metadata_dir / "pyinstaller"
    resolved_dir = metadata_dir / "resolved"
    pyinstaller_dir.mkdir()
    resolved_dir.mkdir()
    work_spec_dir = work_dir / build_profile.spec_path.stem
    sources = (
        (
            work_spec_dir / f"warn-{build_profile.spec_path.stem}.txt",
            pyinstaller_dir / "warn-servonaut.txt",
        ),
        (work_spec_dir / "Analysis-00.toc", pyinstaller_dir / "Analysis-00.toc"),
        (work_spec_dir / "PYZ-00.toc", pyinstaller_dir / "PYZ-00.toc"),
    )
    for source, destination in sources:
        if not source.is_file():
            raise BuildValidationError(f"PyInstaller did not produce {source.name}")
        shutil.copy2(source, destination)
    _write_environment_inventory(pip_report, resolved_dir / "environment.json")
    _write_build_provenance(
        resolved_dir / "build-provenance.json", request, wheel_sha256
    )
    toolchain_python_version = _write_build_toolchain(
        resolved_dir / "build-toolchain.json",
        python,
        environment,
        working_directory,
        build_profile,
    )
    if runtime_notice.python_version != toolchain_python_version:
        raise BuildValidationError("private Python notice does not match the toolchain")
    _write_runtime_notice(resolved_dir / "runtime-notice.json", runtime_notice)
    _write_license_inventory(
        python, resolved_dir / "licenses.json", environment, working_directory
    )
    _write_python_sbom(
        python, resolved_dir / "sbom-python.cdx.json", environment, working_directory
    )
    return pyinstaller_dir / "warn-servonaut.txt"


def _write_runtime_notice(
    destination: Path, runtime_notice: _RuntimeNoticeSource
) -> None:
    """Write the public attestation from the retained private source record."""
    if (
        not isinstance(runtime_notice, _RuntimeNoticeSource)
        or not re.fullmatch(r"[0-9a-f]{64}", runtime_notice.sha256)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", runtime_notice.python_version)
    ):
        raise BuildValidationError("private Python notice record is invalid")
    destination.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "runtime": "cpython",
                "python_implementation": "CPython",
                "python_version": runtime_notice.python_version,
                "license_id": "Python-2.0",
                "payload_path": "_internal/notices/CPython-LICENSE.txt",
                "sha256": runtime_notice.sha256,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_environment_inventory(report: Path, destination: Path) -> None:
    try:
        payload = json.loads(report.read_text(encoding="utf-8"))
        installs = payload["install"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise BuildValidationError(
            "pip did not produce a valid dependency report"
        ) from error
    if (
        not isinstance(payload, dict)
        or payload.get("version") != "1"
        or not isinstance(installs, list)
    ):
        raise BuildValidationError("pip dependency report has an invalid install list")
    packages: list[dict[str, object]] = []
    seen_names: set[str] = set()
    for item in installs:
        if not isinstance(item, dict) or not isinstance(item.get("metadata"), dict):
            raise BuildValidationError("pip dependency report has an invalid package")
        metadata = item["metadata"]
        name, version = metadata.get("name"), metadata.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise BuildValidationError("pip dependency report omits package identity")
        canonical_name = _canonical_package_name(name)
        if canonical_name in seen_names:
            raise BuildValidationError(
                "pip dependency report has duplicate package identities"
            )
        seen_names.add(canonical_name)
        download_info = item.get("download_info")
        archive_info = (
            download_info.get("archive_info")
            if isinstance(download_info, dict)
            else None
        )
        hashes = archive_info.get("hashes") if isinstance(archive_info, dict) else None
        sha256 = hashes.get("sha256") if isinstance(hashes, dict) else None
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
            raise BuildValidationError(
                "pip dependency report omits a SHA256 package hash"
            )
        packages.append(
            {
                "name": canonical_name,
                "version": version,
                "hashes": [f"sha256:{sha256.casefold()}"],
            }
        )
    destination.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "packages": sorted(packages, key=lambda item: str(item["name"])),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_build_provenance(
    destination: Path, request: BuildRequest, wheel_sha256: str
) -> None:
    destination.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_commit": request.source_commit,
                "target": request.target.name,
                "product_version": request.product_version,
                "build_revision": request.build_revision,
                "wheel_sha256": wheel_sha256,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_build_toolchain(
    destination: Path,
    python: Path,
    environment: dict[str, str],
    working_directory: Path,
    build_profile: _BuildProfile,
) -> str:
    output = _run_capture(
        [
            str(python),
            "-c",
            "import json, platform; print(json.dumps({'python_implementation': platform.python_implementation(), 'python_version': platform.python_version()}))",
        ],
        environment,
        working_directory,
    )
    try:
        facts = json.loads(output)
    except json.JSONDecodeError as error:
        raise BuildValidationError(
            "could not capture the private Python runtime"
        ) from error
    if (
        not isinstance(facts, dict)
        or facts.get("python_implementation") != "CPython"
        or not isinstance(facts.get("python_version"), str)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", facts["python_version"])
    ):
        raise BuildValidationError("private Python runtime facts are invalid")
    destination.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "python_implementation": facts["python_implementation"],
                "python_version": facts["python_version"],
                "spec_sha256": build_profile.spec_sha256,
                "hooks_sha256": build_profile.hooks_sha256,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return facts["python_version"]


def _write_license_inventory(
    python: Path,
    destination: Path,
    environment: dict[str, str],
    working_directory: Path,
) -> None:
    script = (
        "import importlib.metadata as m, json\n"
        "items=[]\n"
        "for d in m.distributions():\n"
        "  meta=d.metadata; name=meta.get('Name')\n"
        "  if name:\n"
        "    classifiers=[c for c in meta.get_all('Classifier', []) if c.startswith('License :: ')]\n"
        "    license=meta.get('License') or ''\n"
        "    if not license:\n"
        "      license=classifiers[0] if classifiers else ''\n"
        "    items.append({'name':name,'version':d.version,'license':license,"
        "'license_expression':meta.get('License-Expression') or '',"
        "'license_classifiers':classifiers,'license_files':meta.get_all('License-File') or []})\n"
        "print(json.dumps(sorted(items, key=lambda item:item['name']), sort_keys=True))\n"
    )
    output = _run_capture([str(python), "-c", script], environment, working_directory)
    try:
        packages = json.loads(output)
    except json.JSONDecodeError as error:
        raise BuildValidationError("could not collect resolved licenses") from error
    if not isinstance(packages, list):
        raise BuildValidationError("resolved licenses have an invalid package list")
    normalized_packages: list[dict[str, object]] = []
    seen_names: set[str] = set()
    for package in packages:
        if not isinstance(package, dict):
            raise BuildValidationError("resolved licenses have an invalid package")
        name, version, license_name, license_expression, classifiers, license_files = (
            package.get("name"),
            package.get("version"),
            package.get("license"),
            package.get("license_expression"),
            package.get("license_classifiers"),
            package.get("license_files"),
        )
        if not all(
            isinstance(value, str)
            for value in (name, version, license_name, license_expression)
        ):
            raise BuildValidationError("resolved licenses omit package identity")
        if not _is_string_list(classifiers) or not _is_string_list(license_files):
            raise BuildValidationError("resolved licenses have invalid license claims")
        canonical_name = _canonical_package_name(name)
        if canonical_name in seen_names:
            raise BuildValidationError(
                "resolved licenses have duplicate package identities"
            )
        seen_names.add(canonical_name)
        normalized_packages.append(
            {
                "name": canonical_name,
                "version": version,
                "license": license_name,
                "license_expression": license_expression,
                "license_classifiers": sorted(classifiers),
                "license_files": sorted(license_files),
            }
        )
    destination.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "packages": sorted(normalized_packages, key=lambda item: item["name"]),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _canonical_package_name(name: str) -> str:
    canonical_name = re.sub(r"[-_.]+", "-", name).casefold()
    if not canonical_name or canonical_name == "-":
        raise BuildValidationError("package name is invalid")
    return canonical_name


def _is_string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _write_python_sbom(
    python: Path,
    destination: Path,
    environment: dict[str, str],
    working_directory: Path,
) -> None:
    _run(
        [
            str(python),
            "-m",
            "cyclonedx_py",
            "environment",
            "--output-file",
            str(destination),
        ],
        environment,
        working_directory,
    )
    if not destination.is_file():
        raise BuildValidationError("CycloneDX did not produce an environment SBOM")


def _run(
    command: list[str], environment: dict[str, str], working_directory: Path
) -> None:
    subprocess.run(command, check=True, env=environment, cwd=working_directory)


def _run_capture(
    command: list[str], environment: dict[str, str], working_directory: Path
) -> str:
    completed = subprocess.run(
        command,
        check=True,
        env=environment,
        cwd=working_directory,
        text=True,
        capture_output=True,
    )
    return completed.stdout


def _executable_name(target: TargetSpec) -> str:
    return f"{_PAYLOAD_NAME}.exe" if target.platform == "win32" else _PAYLOAD_NAME


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _create_staging_directory(path: Path) -> _DirectoryIdentity:
    path.mkdir()
    return _directory_identity(path)


def _publish_staged_outputs(
    staged_payload: Path,
    payload_root: Path,
    staged_metadata: Path,
    metadata_dir: Path,
    published: dict[Path, _DirectoryIdentity],
) -> None:
    """Publish within a fresh private root for cooperative same-user callers.

    The exclusive output-root contract prevents accidental reuse, but is not a
    security boundary against a hostile process running as the same user.
    """
    _publish_owned_directory(staged_payload, payload_root, published)
    _publish_owned_directory(staged_metadata, metadata_dir, published)


def _publish_owned_directory(
    source: Path, destination: Path, published: dict[Path, _DirectoryIdentity]
) -> None:
    identity = _directory_identity(source)
    if destination.exists() or destination.is_symlink():
        raise BuildValidationError(
            f"output destination already exists: {destination.name}"
        )
    try:
        source.rename(destination)
        if _directory_identity(destination) != identity:
            raise BuildValidationError(
                "published output ownership could not be verified"
            )
        published[destination] = identity
    except BaseException:
        _remove_owned_directory(destination, identity)
        raise


def _directory_identity(path: Path) -> _DirectoryIdentity:
    try:
        status = path.lstat()
    except OSError as error:
        raise BuildValidationError(f"directory is unavailable: {path.name}") from error
    if not stat.S_ISDIR(status.st_mode):
        raise BuildValidationError(f"directory is not a regular directory: {path.name}")
    return status.st_dev, status.st_ino


def _remove_owned_directory(path: Path, identity: _DirectoryIdentity) -> None:
    """Best-effort cleanup limited to the directory created by this invocation."""
    try:
        if _directory_identity(path) != identity:
            return
        shutil.rmtree(path)
    except (BuildValidationError, OSError):
        return


def _remove_published_outputs(published: dict[Path, _DirectoryIdentity]) -> None:
    for path, identity in reversed(tuple(published.items())):
        _remove_owned_directory(path, identity)


def _remove_empty_owned_output_directory(output: _OwnedOutputDirectory) -> None:
    """Remove only an unchanged, empty output root created by this invocation."""
    try:
        if _directory_identity(output.path) != output.identity:
            return
        output.path.rmdir()
    except (BuildValidationError, OSError):
        return


if __name__ == "__main__":
    raise SystemExit(main())
