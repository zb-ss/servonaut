"""Build engine for Servonaut's multi-executable desktop onedir payload."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import venv
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from scripts.desktop_shell.assets import stage_frontend_assets
from scripts.desktop_shell.model import (
    DesktopBuildRequest,
    DesktopBuildResult,
    DesktopPolicyValidationError,
    DesktopTargetSpec,
    load_desktop_target_spec,
    validate_desktop_build_request,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_POLICY_PATH = _REPO_ROOT / "packaging" / "desktop_shell" / "target-policy.json"
_SPEC_PATH = _REPO_ROOT / "packaging" / "desktop_shell" / "servonaut_desktop.spec"
_ENTRIES_DIR = _REPO_ROOT / "packaging" / "desktop_shell" / "entries"
_HOOKS_DIR = _REPO_ROOT / "packaging" / "desktop_shell" / "hooks"

_DirectoryIdentity = tuple[int, int]


@dataclass(frozen=True)
class _OwnedOutputDirectory:
    path: Path
    identity: _DirectoryIdentity


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


def _prepare_output_directory(path: Path) -> _OwnedOutputDirectory:
    if not isinstance(path, Path):
        raise TypeError("output_dir must be a Path")
    if path.exists() or path.is_symlink():
        raise DesktopPolicyValidationError(
            "output directory must be a new private directory"
        )
    try:
        path.mkdir(mode=0o700, parents=True)
        resolved = path.resolve(strict=True)
        identity = _directory_identity(resolved)
    except OSError as error:
        raise DesktopPolicyValidationError(
            "output directory could not be created"
        ) from error
    return _OwnedOutputDirectory(resolved, identity)


def _executable_names(target: DesktopTargetSpec) -> tuple[str, str, str]:
    ext = ".exe" if target.platform == "win32" else ""
    return (
        f"servonaut-desktop{ext}",
        f"servonaut-desktop-child{ext}",
        f"servonaut{ext}",
    )


def _write_runtime_marker(
    payload_root: Path,
    request: DesktopBuildRequest,
    *,
    gui_name: str,
    child_name: str,
    console_name: str,
) -> Path:
    """Write the packaged-desktop runtime marker."""
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


def _write_build_metadata(
    metadata_dir: Path,
    request: DesktopBuildRequest,
    *,
    target: DesktopTargetSpec,
) -> None:
    """Write dependency provenance, environment, and build facts."""
    metadata_dir.mkdir(parents=True, exist_ok=True)

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
    }
    (metadata_dir / "dependency-provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def build_desktop(request: DesktopBuildRequest) -> DesktopBuildResult:
    """Orchestrate the multi-executable desktop onedir build."""
    validate_desktop_build_request(request)

    target = request.target
    gui_name, child_name, console_name = _executable_names(target)

    # Validate required entry scripts and spec
    gui_entry = _ENTRIES_DIR / "servonaut_desktop.py"
    child_entry = _ENTRIES_DIR / "servonaut_desktop_child.py"
    cli_entry = _ENTRIES_DIR / "servonaut_cli.py"

    if not gui_entry.is_file():
        raise DesktopPolicyValidationError(f"GUI entry script missing: {gui_entry}")
    if not child_entry.is_file():
        raise DesktopPolicyValidationError(f"Child entry script missing: {child_entry}")
    if not _SPEC_PATH.is_file():
        raise DesktopPolicyValidationError(
            f"PyInstaller spec file missing: {_SPEC_PATH}"
        )

    # Create temporary staging root
    owned_output = _prepare_output_directory(request.output_dir)
    staging_root = owned_output.path / ".staging"
    staging_root.mkdir(mode=0o700, exist_ok=True)

    try:
        # 1. Create isolated build venv
        venv_dir = staging_root / "build-venv"
        venv.create(venv_dir, with_pip=True)
        py_bin = (
            venv_dir / "Scripts" / "python.exe"
            if sys.platform == "win32"
            else venv_dir / "bin" / "python"
        )

        # 2. Generate CLI entry point
        cli_entry = staging_root / "servonaut-cli-entry.py"
        cli_entry.write_text(
            "from servonaut.main import main\nmain()\n", encoding="utf-8"
        )

        # 3. Stage frontend assets
        frontend_staging = staging_root / "frontend"
        stage_frontend_assets(frontend_staging)

        # 4. Install wheel and locked requirements into build venv
        subprocess.run(
            [str(py_bin), "-m", "pip", "install", "--upgrade", "pip"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                str(py_bin),
                "-m",
                "pip",
                "install",
                "--no-deps",
                str(request.wheel.resolve()),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                str(py_bin),
                "-m",
                "pip",
                "install",
                "-r",
                str(target.requirements_lock.resolve()),
            ],
            check=True,
            capture_output=True,
        )

        # Locate site-packages in the isolated venv
        site_packages_output = subprocess.run(
            [
                str(py_bin),
                "-c",
                "import site; print(site.getsitepackages()[0])",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        site_packages = Path(site_packages_output.stdout.strip()).resolve()

        # 5. Write profile JSON
        profile_path = staging_root / "desktop_profile.json"
        profile_data = {
            "schema_version": 1,
            "target_name": target.name,
            "target_platform": target.platform,
            "target_architecture": target.architecture,
            "python_version": target.python_version,
            "payload_name": "servonaut-desktop",
            "product_version": request.product_version,
            "excluded_modules": list(target.forbidden_modules),
            "hook_directory": str(_HOOKS_DIR.resolve()),
            "require_artifact_selftest": request.require_artifact_selftest,
        }
        profile_path.write_text(
            json.dumps(profile_data, indent=2) + "\n", encoding="utf-8"
        )

        # 6. Execute PyInstaller
        dist_dir = staging_root / "dist"
        work_dir = staging_root / "build"
        metadata_staging_dir = staging_root / "build-metadata"
        metadata_staging_dir.mkdir(parents=True, exist_ok=True)

        pyinstaller_env = {
            **os.environ,
            "SERVONAUT_DESKTOP_GUI_ENTRY_SCRIPT": str(gui_entry.resolve()),
            "SERVONAUT_DESKTOP_CHILD_ENTRY_SCRIPT": str(child_entry.resolve()),
            "SERVONAUT_DESKTOP_CLI_ENTRY_SCRIPT": str(cli_entry.resolve()),
            "SERVONAUT_DESKTOP_ISOLATED_SITE_PACKAGES": str(site_packages),
            "SERVONAUT_DESKTOP_PROFILE_PATH": str(profile_path.resolve()),
            "SERVONAUT_DESKTOP_OUTPUT_DIR": str(dist_dir.resolve()),
            "SERVONAUT_DESKTOP_BUILD_METADATA_DIR": str(metadata_staging_dir.resolve()),
            "SERVONAUT_DESKTOP_FRONTEND_DIR": str(frontend_staging.resolve()),
            "SERVONAUT_DESKTOP_REQUIRE_ARTIFACT_SELFTEST": (
                "1" if request.require_artifact_selftest else "0"
            ),
        }
        dist_dir.mkdir(parents=True, exist_ok=True)

        completed_pyi = subprocess.run(
            [
                str(py_bin),
                "-m",
                "PyInstaller",
                "--noconfirm",
                "--distpath",
                str(dist_dir),
                "--workpath",
                str(work_dir),
                str(_SPEC_PATH.resolve()),
            ],
            env=pyinstaller_env,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed_pyi.returncode != 0:
            raise DesktopPolicyValidationError(
                f"PyInstaller failed with code {completed_pyi.returncode}:\n"
                f"STDOUT:\n{completed_pyi.stdout}\nSTDERR:\n{completed_pyi.stderr}"
            )

        staged_payload = dist_dir / "servonaut-desktop"
        if not staged_payload.is_dir():
            raise DesktopPolicyValidationError(
                f"PyInstaller did not create payload directory: {staged_payload}"
            )

        # 7. Verify the three executables
        staged_gui = staged_payload / gui_name
        staged_child = staged_payload / child_name
        staged_console = staged_payload / console_name

        for exe_path, label in (
            (staged_gui, "GUI executable"),
            (staged_child, "Child executable"),
            (staged_console, "Console executable"),
        ):
            if not exe_path.is_file():
                raise DesktopPolicyValidationError(
                    f"{label} missing from payload: {exe_path.name}"
                )

        # Verify distinct identities
        if staged_child.samefile(staged_console) or staged_gui.samefile(staged_child):
            raise DesktopPolicyValidationError(
                "Executables in payload must be distinct files"
            )

        # Ensure frontend assets are present in payload
        payload_frontend = staged_payload / "frontend"
        if not payload_frontend.is_dir():
            # If collected in _internal/frontend
            alt_frontend = staged_payload / "_internal" / "frontend"
            if alt_frontend.is_dir():
                shutil.copytree(alt_frontend, payload_frontend, dirs_exist_ok=True)
            else:
                shutil.copytree(frontend_staging, payload_frontend)

        # 8. Write runtime marker
        _write_runtime_marker(
            staged_payload,
            request,
            gui_name=gui_name,
            child_name=child_name,
            console_name=console_name,
        )

        # 9. Generate metadata
        _write_build_metadata(
            metadata_staging_dir,
            request,
            target=target,
        )

        # Publish final directories to owned_output.path
        final_payload = owned_output.path / "servonaut-desktop"
        final_metadata = owned_output.path / "build-metadata"
        staged_payload.rename(final_payload)
        metadata_staging_dir.rename(final_metadata)

        # Locate warnings file if generated
        warning_file = work_dir / "servonaut_desktop" / "warn-servonaut_desktop.txt"
        if not warning_file.is_file():
            # Create empty warning file if none produced
            warning_file = final_metadata / "pyinstaller-warnings.txt"
            warning_file.write_text("", encoding="utf-8")

        return DesktopBuildResult(
            payload_root=final_payload,
            gui_executable=final_payload / gui_name,
            child_executable=final_payload / child_name,
            console_executable=final_payload / console_name,
            marker=final_payload / "servonaut-runtime.json",
            pyinstaller_warning_file=warning_file,
            build_metadata_dir=final_metadata,
            frontend_dir=final_payload / "frontend",
        )

    finally:
        # Clean up staging temporary directory
        if staging_root.is_dir():
            shutil.rmtree(staging_root, ignore_errors=True)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for the desktop builder."""
    parser = argparse.ArgumentParser(
        description="Build Servonaut desktop onedir payload."
    )
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--policy", type=Path, default=_POLICY_PATH)
    parser.add_argument("--product-version", required=True)
    parser.add_argument("--release-tag")
    parser.add_argument("--revision", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--require-artifact-selftest",
        action="store_true",
        default=True,
    )

    args = parser.parse_args(argv)
    if args.release_tag is not None and args.release_tag != f"v{args.product_version}":
        parser.error("--release-tag must equal v<product-version>")

    try:
        target_spec = load_desktop_target_spec(args.policy, args.target)
        request = DesktopBuildRequest(
            wheel=args.wheel,
            target=target_spec,
            product_version=args.product_version,
            build_revision=args.revision,
            source_commit=args.commit,
            output_dir=args.output,
            require_artifact_selftest=args.require_artifact_selftest,
        )
        build_desktop(request)
    except (DesktopPolicyValidationError, TypeError) as err:
        parser.error(str(err))

    return 0


if __name__ == "__main__":
    sys.exit(main())
