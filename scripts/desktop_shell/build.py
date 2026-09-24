"""Build engine for Servonaut's multi-executable desktop onedir payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform as host_platform
import shutil
import stat
import subprocess
import sys
import venv
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from scripts.desktop_shell.assets import stage_frontend_assets
from scripts.desktop_shell.model import (
    EMBEDDED_NOTICE_POLICY_PATH,
    EXECUTABLE_ROLES,
    PYINSTALLER_WARNING_NAME,
    DesktopBuildPolicy,
    DesktopBuildRequest,
    DesktopBuildResult,
    DesktopPolicyValidationError,
    DesktopTargetSpec,
    _wheel_product_version,
    executable_toc_directory,
    load_desktop_build_policy,
    load_desktop_target_spec,
    validate_desktop_build_request,
)

# The desktop payload embeds the same CPython and third-party notices as the
# standalone payload, staged and verified by the same code.
from scripts.standalone_cli.build import (
    _prepare_runtime_notice,
    _RuntimeNoticeSource,
    _validate_payload_runtime_notice,
    _write_runtime_notice,
)
from scripts.standalone_cli.embedded_notices import (
    StagedEmbeddedNotices,
    prepare_embedded_notices,
    validate_payload_embedded_notices,
    write_embedded_notice_metadata,
)
from scripts.standalone_cli.model import (
    BuildValidationError,
    TargetSpec,
    load_target_spec,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PACKAGING_DIR = _REPO_ROOT / "packaging" / "desktop_shell"
_POLICY_PATH = _PACKAGING_DIR / "target-policy.json"
_SPEC_PATH = _PACKAGING_DIR / "servonaut_desktop.spec"
_ENTRIES_DIR = _PACKAGING_DIR / "entries"
_GUI_ENTRY = _ENTRIES_DIR / "servonaut_desktop.py"
_CHILD_ENTRY = _ENTRIES_DIR / "servonaut_desktop_child.py"
_HOOKS_DIR = _PACKAGING_DIR / "hooks"
_SOURCE_BUILD_TOOLS_LOCK = _PACKAGING_DIR / "requirements" / "source-build-tools.txt"
_STANDALONE_POLICY_PATH = (
    _REPO_ROOT / "packaging" / "standalone_cli" / "target-policy.json"
)
_PAYLOAD_NAME = "servonaut-desktop"
_METADATA_NAME = "build-metadata"
_STAGING_NAME = ".staging"
_MACHINE_ARCHITECTURES = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "arm64": "arm64",
    "aarch64": "arm64",
}
# Inherited interpreter, installer and spec settings must not steer the
# isolated build interpreter.
_REMOVED_ENVIRONMENT_PREFIXES = ("python", "pip_", "servonaut_desktop_")

_DirectoryIdentity = tuple[int, int]


@dataclass(frozen=True)
class _OwnedDirectory:
    path: Path
    identity: _DirectoryIdentity
    created: bool = True


@dataclass(frozen=True)
class _BuildContext:
    """Interpreter, environment and bounds shared by one build's subprocesses."""

    python: Path
    environment: dict[str, str]
    working_directory: Path
    policy: DesktopBuildPolicy


@dataclass(frozen=True)
class _StagedNotices:
    runtime: _RuntimeNoticeSource
    embedded: StagedEmbeddedNotices


@dataclass(frozen=True)
class _SpecInputs:
    """Staged inputs the PyInstaller spec validates before analysis."""

    cli_entry: Path
    profile: Path
    site_packages: Path
    metadata_dir: Path
    frontend_dir: Path
    notices: _StagedNotices
    require_artifact_selftest: bool

    def spec_environment(
        self, base: dict[str, str], dist_dir: Path
    ) -> dict[str, str]:
        return {
            **base,
            "SERVONAUT_DESKTOP_GUI_ENTRY_SCRIPT": str(_GUI_ENTRY.resolve()),
            "SERVONAUT_DESKTOP_CHILD_ENTRY_SCRIPT": str(_CHILD_ENTRY.resolve()),
            "SERVONAUT_DESKTOP_CLI_ENTRY_SCRIPT": str(self.cli_entry.resolve()),
            "SERVONAUT_DESKTOP_ISOLATED_SITE_PACKAGES": str(self.site_packages),
            "SERVONAUT_DESKTOP_PROFILE_PATH": str(self.profile.resolve()),
            "SERVONAUT_DESKTOP_OUTPUT_DIR": str(dist_dir.resolve()),
            "SERVONAUT_DESKTOP_BUILD_METADATA_DIR": str(self.metadata_dir.resolve()),
            "SERVONAUT_DESKTOP_FRONTEND_DIR": str(self.frontend_dir.resolve()),
            "SERVONAUT_DESKTOP_RUNTIME_NOTICE_SOURCE": str(
                self.notices.runtime.staged_path
            ),
            "SERVONAUT_DESKTOP_THIRD_PARTY_NOTICES_ROOT": str(
                self.notices.embedded.staging_root
            ),
            "SERVONAUT_DESKTOP_REQUIRE_ARTIFACT_SELFTEST": (
                "1" if self.require_artifact_selftest else "0"
            ),
        }


def build_desktop(request: DesktopBuildRequest) -> DesktopBuildResult:
    """Build one desktop onedir payload on its own target host.

    The output directory must be new or empty. On failure nothing this build
    published is left behind.
    """
    validate_desktop_build_request(request)
    _validate_host_target(request.target)
    _require_builder_inputs()
    policy = load_desktop_build_policy()
    output = _prepare_output_directory(request.output_dir)
    staging: _OwnedDirectory | None = None
    published: list[_OwnedDirectory] = []
    completed = False
    try:
        staging = _create_owned_directory(output.path / _STAGING_NAME)
        payload, metadata = _build_staged_payload(request, staging.path, policy)
        _require_unchanged(output)
        result = _publish_outputs(payload, metadata, output.path, request, published)
        completed = True
        return result
    except OSError as error:
        raise DesktopPolicyValidationError(f"desktop build failed: {error}") from error
    finally:
        if staging is not None:
            _remove_owned_directory(staging)
        if not completed:
            for directory in reversed(published):
                _remove_owned_directory(directory)
            if output.created:
                _remove_empty_directory(output)


def _build_staged_payload(
    request: DesktopBuildRequest, staging_root: Path, policy: DesktopBuildPolicy
) -> tuple[Path, Path]:
    context = _bootstrap_build_venv(staging_root, policy)
    inputs = _prepare_spec_inputs(context, request, staging_root)
    dist_dir = staging_root / "dist"
    work_dir = staging_root / "build"
    dist_dir.mkdir()
    _run_pyinstaller(context, inputs, dist_dir, work_dir)

    payload = dist_dir / _PAYLOAD_NAME
    _verify_staged_executables(payload, request.target)
    _validate_payload_notices(payload, inputs.notices, policy.max_metadata_file_bytes)
    _expose_frontend(payload, inputs.frontend_dir)
    _write_runtime_marker(payload, request)
    _capture_build_metadata(work_dir, inputs.metadata_dir, request, inputs.notices)
    return payload, inputs.metadata_dir


def _bootstrap_build_venv(
    staging_root: Path, policy: DesktopBuildPolicy
) -> _BuildContext:
    python = _create_build_venv(staging_root / "build-venv")
    context = _BuildContext(python, _sanitized_environment(), staging_root, policy)
    _run(
        context,
        [str(python), "-m", "ensurepip"],
        timeout_seconds=policy.venv_bootstrap_timeout_seconds,
        step="pip bootstrap",
    )
    return context


def _prepare_spec_inputs(
    context: _BuildContext, request: DesktopBuildRequest, staging_root: Path
) -> _SpecInputs:
    metadata_dir = staging_root / _METADATA_NAME
    metadata_dir.mkdir()
    pip_report = staging_root / "pip-report.json"
    _install_locked_environment(context, request, pip_report)
    site_packages = _site_packages(context)
    frontend_dir = _stage_frontend(
        staging_root / "frontend", site_packages, request.target
    )
    notices = _stage_notices(
        context, request.target, site_packages, pip_report, metadata_dir
    )
    return _SpecInputs(
        cli_entry=_write_cli_entry(staging_root),
        profile=_write_profile(staging_root, request),
        site_packages=site_packages,
        metadata_dir=metadata_dir,
        frontend_dir=frontend_dir,
        notices=notices,
        require_artifact_selftest=request.require_artifact_selftest,
    )


def _validate_host_target(target: DesktopTargetSpec) -> None:
    """Refuse to label a payload with a platform or CPU it was not built on."""
    interpreter = f"{sys.version_info.major}.{sys.version_info.minor}"
    if interpreter != target.python_version:
        raise DesktopPolicyValidationError(
            f"desktop builds require Python {target.python_version}, not {interpreter}"
        )
    if sys.platform != target.platform:
        raise DesktopPolicyValidationError(
            f"target {target.name} must be built on {target.platform}, "
            f"not {sys.platform}"
        )
    machine = host_platform.machine().casefold()
    architecture = _MACHINE_ARCHITECTURES.get(machine, machine)
    if architecture != target.architecture:
        raise DesktopPolicyValidationError(
            f"target {target.name} must be built on {target.architecture}, "
            f"not {architecture}"
        )


def _require_builder_inputs() -> None:
    for path in (
        _SPEC_PATH,
        _GUI_ENTRY,
        _CHILD_ENTRY,
        _SOURCE_BUILD_TOOLS_LOCK,
        EMBEDDED_NOTICE_POLICY_PATH,
    ):
        if not path.is_file():
            raise DesktopPolicyValidationError(
                f"required build input is missing: {path.name}"
            )
    if not _HOOKS_DIR.is_dir():
        raise DesktopPolicyValidationError("PyInstaller hook directory is missing")


def _sanitized_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.casefold().startswith(_REMOVED_ENVIRONMENT_PREFIXES)
    }
    environment["PIP_CONFIG_FILE"] = os.devnull
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def _create_build_venv(venv_dir: Path) -> Path:
    """Create a pip-less venv; pip is bootstrapped from the bundled wheel only."""
    venv.EnvBuilder(with_pip=False, clear=True).create(venv_dir)
    python = venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    if not python.is_file():
        raise DesktopPolicyValidationError("build venv has no Python interpreter")
    # A POSIX venv interpreter is usually a symlink; its lexical path selects
    # pyvenv.cfg and must not be resolved.
    return python.absolute()


def _install_locked_environment(
    context: _BuildContext, request: DesktopBuildRequest, pip_report: Path
) -> None:
    """Install only hash-verified artifacts; source builds reuse hashed tools."""
    install = [
        str(context.python),
        "-m",
        "pip",
        "install",
        "--isolated",
        "--disable-pip-version-check",
        "--no-input",
        "--require-hashes",
        "--no-deps",
    ]
    timeout = context.policy.dependency_install_timeout_seconds
    _run(
        context,
        [*install, "-r", str(_SOURCE_BUILD_TOOLS_LOCK)],
        timeout_seconds=timeout,
        step="source build tool installation",
    )
    wheel = request.wheel.resolve(strict=True)
    _run(
        context,
        [
            *install,
            "--no-build-isolation",
            "--report",
            str(pip_report),
            f"{wheel.as_uri()}#sha256={_sha256_file(wheel)}",
            "-r",
            str(request.target.requirements_lock.resolve(strict=True)),
        ],
        timeout_seconds=timeout,
        step="locked dependency installation",
    )


def _site_packages(context: _BuildContext) -> Path:
    output = _run(
        context,
        [
            str(context.python),
            "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))",
        ],
        timeout_seconds=context.policy.interpreter_probe_timeout_seconds,
        step="site-packages probe",
    )
    site_packages = Path(output.strip()).resolve(strict=True)
    if not site_packages.is_relative_to(context.working_directory.resolve()):
        raise DesktopPolicyValidationError("site-packages is outside the build venv")
    return site_packages


def _stage_frontend(
    frontend_dir: Path, site_packages: Path, target: DesktopTargetSpec
) -> Path:
    upstream_static = site_packages / "textual_serve" / "static"
    if not upstream_static.is_dir():
        raise DesktopPolicyValidationError(
            "textual-serve static assets are missing from the build venv"
        )
    stage_frontend_assets(
        frontend_dir,
        lock_path=target.frontend_assets_lock,
        licenses_path=target.frontend_licenses,
        upstream_source_dir=upstream_static,
    )
    return frontend_dir.resolve(strict=True)


@contextmanager
def _notice_errors() -> Iterator[None]:
    """Report failures of the shared notice code as desktop build errors."""
    try:
        yield
    except (BuildValidationError, subprocess.CalledProcessError) as error:
        raise DesktopPolicyValidationError(
            f"license notice staging failed: {error}"
        ) from error


def _notice_target(target: DesktopTargetSpec) -> TargetSpec:
    """Return the target identity that keys the shared notice policy hashes."""
    notice_target = load_target_spec(_STANDALONE_POLICY_PATH, target.name)
    if (notice_target.platform, notice_target.architecture) != (
        target.platform,
        target.architecture,
    ):
        raise DesktopPolicyValidationError(
            "notice policy target does not match the desktop target"
        )
    return notice_target


def _stage_notices(
    context: _BuildContext,
    target: DesktopTargetSpec,
    site_packages: Path,
    pip_report: Path,
    metadata_dir: Path,
) -> _StagedNotices:
    with _notice_errors():
        notice_target = _notice_target(target)
        runtime = _prepare_runtime_notice(
            context.python,
            notice_target,
            metadata_dir,
            context.environment,
            context.working_directory,
        )
        embedded = prepare_embedded_notices(
            EMBEDDED_NOTICE_POLICY_PATH,
            site_packages,
            pip_report,
            notice_target,
            metadata_dir,
            context.policy.max_metadata_file_bytes,
        )
    return _StagedNotices(runtime, embedded)


def _validate_payload_notices(
    payload_root: Path, notices: _StagedNotices, max_bytes: int
) -> None:
    with _notice_errors():
        _validate_payload_runtime_notice(payload_root, notices.runtime)
        validate_payload_embedded_notices(payload_root, notices.embedded, max_bytes)


def _write_cli_entry(staging_root: Path) -> Path:
    cli_entry = staging_root / "servonaut-cli-entry.py"
    cli_entry.write_text("from servonaut.main import main\nmain()\n", encoding="utf-8")
    return cli_entry


def _write_profile(staging_root: Path, request: DesktopBuildRequest) -> Path:
    target = request.target
    profile_path = staging_root / "desktop_profile.json"
    profile_data = {
        "schema_version": 1,
        "target_name": target.name,
        "target_platform": target.platform,
        "target_architecture": target.architecture,
        "python_version": target.python_version,
        "payload_name": _PAYLOAD_NAME,
        "product_version": request.product_version,
        "excluded_modules": list(target.forbidden_modules),
        "hook_directory": str(_HOOKS_DIR.resolve()),
        "require_artifact_selftest": request.require_artifact_selftest,
    }
    profile_path.write_text(json.dumps(profile_data, indent=2) + "\n", encoding="utf-8")
    return profile_path


def _run_pyinstaller(
    context: _BuildContext, inputs: _SpecInputs, dist_dir: Path, work_dir: Path
) -> None:
    _run(
        context,
        [
            str(context.python),
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--distpath",
            str(dist_dir),
            "--workpath",
            str(work_dir),
            str(_SPEC_PATH.resolve()),
        ],
        environment=inputs.spec_environment(context.environment, dist_dir),
        timeout_seconds=context.policy.pyinstaller_timeout_seconds,
        step="PyInstaller",
    )


def _run(
    context: _BuildContext,
    command: list[str],
    *,
    timeout_seconds: int,
    step: str,
    environment: dict[str, str] | None = None,
) -> str:
    """Run one build subprocess; report failures with a bounded stderr tail."""
    tail_chars = context.policy.failure_output_tail_chars
    try:
        completed = subprocess.run(
            command,
            env=context.environment if environment is None else environment,
            cwd=context.working_directory,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise DesktopPolicyValidationError(
            f"{step} timed out after {timeout_seconds}s"
            f"{_output_tail(error.stderr, tail_chars)}"
        ) from error
    except OSError as error:
        raise DesktopPolicyValidationError(f"{step} could not start: {error}") from error
    if completed.returncode != 0:
        raise DesktopPolicyValidationError(
            f"{step} failed with exit code {completed.returncode}"
            f"{_output_tail(completed.stderr, tail_chars)}"
        )
    return completed.stdout.decode("utf-8", errors="replace")


def _output_tail(stderr: bytes | None, limit: int) -> str:
    text = (stderr or b"").decode("utf-8", errors="replace").strip()
    if not text:
        return ""
    if len(text) > limit:
        text = "..." + text[-limit:]
    return f":\n{text}"


def _executable_names(target: DesktopTargetSpec) -> tuple[str, str, str]:
    ext = ".exe" if target.platform == "win32" else ""
    return (
        f"servonaut-desktop{ext}",
        f"servonaut-desktop-child{ext}",
        f"servonaut{ext}",
    )


def _verify_staged_executables(payload: Path, target: DesktopTargetSpec) -> None:
    if not payload.is_dir():
        raise DesktopPolicyValidationError(
            f"PyInstaller did not create payload directory: {payload.name}"
        )
    gui, child, console = (payload / name for name in _executable_names(target))
    for exe_path, label in (
        (gui, "GUI executable"),
        (child, "Child executable"),
        (console, "Console executable"),
    ):
        if not exe_path.is_file():
            raise DesktopPolicyValidationError(
                f"{label} missing from payload: {exe_path.name}"
            )
    if child.samefile(console) or gui.samefile(child) or gui.samefile(console):
        raise DesktopPolicyValidationError(
            "Executables in payload must be distinct files"
        )


def _expose_frontend(payload: Path, frontend_staging: Path) -> None:
    payload_frontend = payload / "frontend"
    if payload_frontend.is_dir():
        return
    collected_frontend = payload / "_internal" / "frontend"
    source = collected_frontend if collected_frontend.is_dir() else frontend_staging
    shutil.copytree(source, payload_frontend)


def _write_runtime_marker(payload_root: Path, request: DesktopBuildRequest) -> Path:
    """Write the packaged-desktop runtime marker."""
    _, child_name, console_name = _executable_names(request.target)
    marker_data = {
        "schema_version": 1,
        "distribution": "packaged-desktop",
        "product_version": request.product_version,
        "build_revision": request.build_revision,
        "console_helper": console_name,
        "desktop_child": child_name,
    }
    marker_file = payload_root / "servonaut-runtime.json"
    marker_file.write_text(
        json.dumps(marker_data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return marker_file


def _capture_build_metadata(
    work_dir: Path,
    metadata_dir: Path,
    request: DesktopBuildRequest,
    notices: _StagedNotices,
) -> None:
    """Persist PyInstaller records before the staging work directory is removed."""
    spec_work_dir = work_dir / _SPEC_PATH.stem
    pyinstaller_dir = metadata_dir / "pyinstaller"
    pyinstaller_dir.mkdir()
    _copy_build_record(
        spec_work_dir / PYINSTALLER_WARNING_NAME,
        pyinstaller_dir / PYINSTALLER_WARNING_NAME,
    )
    # One directory per executable keeps each Analysis in the layout the shared
    # TOC policy reads: <root>/pyinstaller/{Analysis,PYZ}-00.toc.
    for index, role in enumerate(EXECUTABLE_ROLES):
        toc_dir = executable_toc_directory(metadata_dir, role) / "pyinstaller"
        toc_dir.mkdir(parents=True)
        for kind in ("Analysis", "PYZ"):
            _copy_build_record(
                spec_work_dir / f"{kind}-{index:02d}.toc", toc_dir / f"{kind}-00.toc"
            )
    with _notice_errors():
        _write_runtime_notice(metadata_dir / "runtime-notice.json", notices.runtime)
        write_embedded_notice_metadata(
            metadata_dir / "third-party-notices.json", notices.embedded
        )
    _write_build_provenance(metadata_dir, request)


def _copy_build_record(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise DesktopPolicyValidationError(f"PyInstaller did not produce {source.name}")
    shutil.copy2(source, destination)


def _write_build_provenance(metadata_dir: Path, request: DesktopBuildRequest) -> None:
    """Write dependency provenance, environment, and build facts."""
    target = request.target
    provenance = {
        "schema_version": 1,
        "product_version": request.product_version,
        "build_revision": request.build_revision,
        "source_commit": request.source_commit,
        "target": target.name,
        "platform": target.platform,
        "architecture": target.architecture,
        "python_version": target.python_version,
        "wheel": request.wheel.name,
        "require_artifact_selftest": request.require_artifact_selftest,
    }
    (metadata_dir / "dependency-provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _publish_outputs(
    staged_payload: Path,
    staged_metadata: Path,
    output_dir: Path,
    request: DesktopBuildRequest,
    published: list[_OwnedDirectory],
) -> DesktopBuildResult:
    payload = _publish_directory(staged_payload, output_dir / _PAYLOAD_NAME, published)
    metadata = _publish_directory(
        staged_metadata, output_dir / _METADATA_NAME, published
    )
    gui_name, child_name, console_name = _executable_names(request.target)
    return DesktopBuildResult(
        payload_root=payload,
        gui_executable=payload / gui_name,
        child_executable=payload / child_name,
        console_executable=payload / console_name,
        marker=payload / "servonaut-runtime.json",
        pyinstaller_warning_file=metadata / "pyinstaller" / PYINSTALLER_WARNING_NAME,
        build_metadata_dir=metadata,
        frontend_dir=payload / "frontend",
    )


def _publish_directory(
    source: Path, destination: Path, published: list[_OwnedDirectory]
) -> Path:
    identity = _directory_identity(source)
    if destination.exists() or destination.is_symlink():
        raise DesktopPolicyValidationError(
            f"output destination already exists: {destination.name}"
        )
    source.rename(destination)
    published.append(_OwnedDirectory(destination, identity))
    if _directory_identity(destination) != identity:
        raise DesktopPolicyValidationError(
            "published output ownership could not be verified"
        )
    return destination


def _prepare_output_directory(path: Path) -> _OwnedDirectory:
    """Accept only a new or empty output directory, before any build work."""
    if not isinstance(path, Path):
        raise TypeError("output_dir must be a Path")
    if path.is_symlink():
        raise DesktopPolicyValidationError("output directory must not be a symlink")
    try:
        created = not path.exists()
        if created:
            path.mkdir(mode=0o700, parents=True)
        elif not path.is_dir():
            raise DesktopPolicyValidationError("output directory cannot be a file")
        elif any(path.iterdir()):
            raise DesktopPolicyValidationError(
                f"output directory must be empty: {path.name}"
            )
        resolved = path.resolve(strict=True)
        identity = _directory_identity(resolved)
    except OSError as error:
        raise DesktopPolicyValidationError(
            "output directory could not be prepared"
        ) from error
    return _OwnedDirectory(resolved, identity, created)


def _create_owned_directory(path: Path) -> _OwnedDirectory:
    path.mkdir(mode=0o700)
    return _OwnedDirectory(path, _directory_identity(path))


def _require_unchanged(directory: _OwnedDirectory) -> None:
    if _directory_identity(directory.path) != directory.identity:
        raise DesktopPolicyValidationError("output directory changed during the build")


def _remove_owned_directory(directory: _OwnedDirectory) -> None:
    """Best-effort cleanup limited to a directory this build created."""
    try:
        if _directory_identity(directory.path) == directory.identity:
            shutil.rmtree(directory.path)
    except (DesktopPolicyValidationError, OSError):
        return


def _remove_empty_directory(directory: _OwnedDirectory) -> None:
    try:
        if _directory_identity(directory.path) == directory.identity:
            directory.path.rmdir()
    except (DesktopPolicyValidationError, OSError):
        return


def _directory_identity(path: Path) -> _DirectoryIdentity:
    try:
        status = path.lstat()
    except OSError as error:
        raise DesktopPolicyValidationError(
            f"directory is unavailable: {path.name}"
        ) from error
    if not stat.S_ISDIR(status.st_mode):
        raise DesktopPolicyValidationError(
            f"directory is not a regular directory: {path.name}"
        )
    return status.st_dev, status.st_ino


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for the desktop builder."""
    parser = argparse.ArgumentParser(
        description="Build Servonaut desktop onedir payload."
    )
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--policy", type=Path, default=_POLICY_PATH)
    parser.add_argument("--product-version", default=None)
    parser.add_argument("--release-tag")
    parser.add_argument("--revision", default=None)
    parser.add_argument("--commit", default=None)
    parser.add_argument(
        "--output", "--output-dir", dest="output", type=Path, required=True
    )
    parser.add_argument(
        "--require-artifact-selftest",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Embed the authenticated artifact self-test in the GUI executable.",
    )

    args = parser.parse_args(argv)
    commit = args.commit or os.environ.get("GITHUB_SHA", "HEAD")
    revision = args.revision or os.environ.get("GITHUB_RUN_ID", "1")

    try:
        product_version = args.product_version or _wheel_product_version(args.wheel)
        if args.release_tag is not None and args.release_tag != f"v{product_version}":
            parser.error("--release-tag must equal v<product-version>")
        target_spec = load_desktop_target_spec(args.policy, args.target)
        request = DesktopBuildRequest(
            wheel=args.wheel,
            target=target_spec,
            product_version=product_version,
            build_revision=revision,
            source_commit=commit,
            output_dir=args.output,
            require_artifact_selftest=args.require_artifact_selftest,
        )
        build_desktop(request)
    except (DesktopPolicyValidationError, TypeError) as err:
        parser.error(str(err))

    return 0


if __name__ == "__main__":
    sys.exit(main())
