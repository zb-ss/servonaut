"""Runtime-marker creation for completed standalone onedir payloads."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Mapping
from pathlib import Path

from scripts.standalone_cli.model import BuildRequest, BuildValidationError


def write_runtime_marker(
    payload_root: Path,
    executable: Path,
    request: BuildRequest,
    *,
    isolated_python: Path,
    isolated_site_packages: Path,
    working_directory: Path,
) -> Path:
    """Write and validate the strict marker beside a frozen executable."""
    resolved_root = payload_root.resolve(strict=True)
    resolved_executable = executable.resolve(strict=True)
    if not resolved_executable.is_file():
        raise BuildValidationError("standalone executable must be a regular file")
    try:
        relative_executable = resolved_executable.relative_to(resolved_root).as_posix()
    except ValueError as error:
        raise BuildValidationError("standalone executable escapes its payload root") from error
    marker_data = {
        "schema_version": 1,
        "distribution": "frozen-cli",
        "product_version": request.product_version,
        "build_revision": request.build_revision,
        **request.release_identity.marker_fields(),
        "console_helper": relative_executable,
        "desktop_child": None,
    }
    _validate_marker_with_runtime(
        marker_data,
        resolved_root,
        isolated_python=isolated_python,
        isolated_site_packages=isolated_site_packages,
        working_directory=working_directory,
    )
    marker = resolved_root / "servonaut-runtime.json"
    marker.write_text(json.dumps(marker_data, sort_keys=True) + "\n", encoding="utf-8")
    return marker


def _validate_marker_with_runtime(
    marker: dict[str, object],
    executable_root: Path,
    *,
    isolated_python: Path,
    isolated_site_packages: Path,
    working_directory: Path,
) -> None:
    """Use the wheel venv's runtime parser without importing checkout source."""
    script = (
        "import json, sys\n"
        "from pathlib import Path\n"
        "import servonaut\n"
        "from servonaut.runtime import RuntimeEvidence, resolve_runtime\n"
        "site_packages = Path(sys.argv[1]).resolve()\n"
        "origin = Path(servonaut.__file__).resolve()\n"
        "try:\n"
        "    origin.relative_to(site_packages)\n"
        "except ValueError:\n"
        "    raise SystemExit('servonaut did not import from isolated site-packages')\n"
        "marker = json.loads(sys.stdin.read())\n"
        "root = Path(sys.argv[2]).resolve()\n"
        "resolve_runtime(RuntimeEvidence(\n"
        "    executable=root / str(marker['console_helper']), executable_root=root,\n"
        "    resource_root=root / '_internal', home=root, is_frozen=True,\n"
        "    package_version=str(marker['product_version']), package_is_installed=False,\n"
        "    source_install_path=None, path_console=None, pipx_executable=None,\n"
        "    pipx_contains_servonaut=False, marker=marker))\n"
    )
    completed = subprocess.run(
        [str(isolated_python), "-c", script, str(isolated_site_packages), str(executable_root)],
        input=json.dumps(marker),
        text=True,
        capture_output=True,
        cwd=working_directory,
        check=False,
        env=_marker_environment(isolated_python),
    )
    if completed.returncode != 0:
        raise BuildValidationError("isolated runtime rejected the generated marker")


def _marker_environment(
    isolated_python: Path,
    *,
    platform_name: str | None = None,
    inherited: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return the minimal environment required by the isolated parser process."""
    selected_platform = os.name if platform_name is None else platform_name
    environment = {"PATH": str(isolated_python.parent)}
    if selected_platform != "nt":
        return environment
    source = os.environ if inherited is None else inherited
    roots = [value for key, value in source.items() if key.casefold() == "systemroot"]
    if len(roots) != 1:
        raise BuildValidationError("Windows marker validation requires one SystemRoot")
    root = Path(roots[0])
    if not root.is_absolute() or not root.is_dir():
        raise BuildValidationError("Windows SystemRoot is invalid")
    environment["SystemRoot"] = str(root)
    return environment
