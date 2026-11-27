"""Read the pipx installation profile without modifying its environment."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from servonaut.updates.index import ManualUpdateRequired, UpdateUnavailable
from servonaut.updates.status import PIPX_METADATA, public_version, read_json
from servonaut.utils.login_path import well_known_bin_dirs
from servonaut.utils.package_version import PackageVersion

_INDEX_SPEC = re.compile(
    r"[a-z0-9][a-z0-9_.-]*(?:\[[a-z0-9_.-]+(?:,[a-z0-9_.-]+)*\])?(?:={2,3}[a-z0-9.+]+)?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Profile:
    interpreter: str
    requirement: str
    injections: tuple[str, ...]
    pipx_command: tuple[str, ...] = field(default=(), compare=False, repr=False)

    @property
    def fingerprint(self) -> str:
        profile = asdict(self)
        del profile["pipx_command"]
        return hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest()


class PipxUnavailable(UpdateUnavailable):
    """The launching process cannot reach this install's pipx command."""


def exact_pipx_request(root: Path) -> tuple[PackageVersion, str] | None:
    try:
        path = root / PIPX_METADATA
        metadata = read_json(path)
        spec = metadata.get("main_package", {}).get("package_or_url", "")
        if not isinstance(spec, str) or not _INDEX_SPEC.fullmatch(spec):
            return None
        parts = re.split(r"={2,3}", spec, maxsplit=1)
        if len(parts) == 2 and parts[0].partition("[")[0].lower() == "servonaut":
            version = public_version(parts[1])
            if version is not None:
                return version, spec
    except (OSError, ValueError, AttributeError, TypeError):
        pass
    return None


def _standard_requirement(package: dict, *, main: bool = False) -> str:
    spec = package.get("package_or_url")
    if (not isinstance(spec, str) or not _INDEX_SPEC.fullmatch(spec)
            or package.get("pip_args") or package.get("suffix") or package.get("pinned")):
        raise ManualUpdateRequired("The installation uses custom package settings")
    # pipx upgrade strips the previous package version restriction. Preserve the
    # name and extras and use our independently verified target constraint.
    if main:
        requirement = spec.partition("==")[0]
        if requirement.partition("[")[0].lower() != "servonaut":
            raise ManualUpdateRequired("The installation is not a Servonaut pipx environment")
        return requirement
    return spec


def _usual_locations() -> tuple[Path, ...]:
    home = Path.home()
    if os.name == "nt":
        python_tag = f"Python{sys.version_info.major}{sys.version_info.minor}"
        appdata = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
        return (home / ".local" / "bin" / "pipx.exe",
                appdata / "Python" / python_tag / "Scripts" / "pipx.exe")
    directories = (home / ".local" / "bin", home / "bin", *well_known_bin_dirs(home), Path("/usr/bin"))
    return tuple(dict.fromkeys(directory / "pipx" for directory in directories))


def _pipx_candidates(root: Path, recorded: object) -> list[tuple[str, ...]]:
    candidates = []
    if (isinstance(recorded, list) and recorded and all(isinstance(item, str) for item in recorded)
            and recorded[1:] in ([], ["-m", "pipx"]) and Path(recorded[0]).is_file()):
        candidates.append(tuple(recorded))
    command = shutil.which("pipx")
    if command:
        candidates.append((command,))
    candidates.extend((str(path),) for path in _usual_locations() if path.is_file())
    shared = root.parent.parent / "shared"
    python = shared / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if python.is_file():
        candidates.append((str(python), "-m", "pipx"))
    return list(dict.fromkeys(candidates))


def _pipx_command(root: Path, timeout: float, recorded: object) -> tuple[str, ...]:
    for command in _pipx_candidates(root, recorded):
        executable = Path(command[0])
        if not executable.is_absolute() or executable.resolve().is_relative_to(root):
            continue
        try:
            result = subprocess.check_output(
                [*command, "environment", "--value", "PIPX_LOCAL_VENVS"],
                cwd=root, stderr=subprocess.DEVNULL, timeout=timeout, text=True,
            ).strip()
        except (OSError, subprocess.SubprocessError):
            continue
        if result and (Path(result) / "servonaut").resolve() == root:
            return command
    raise PipxUnavailable("An external pipx command is unavailable")


def load_profile(root: Path, timeout: float, recorded: object = None) -> Profile:
    metadata = json.loads((root / PIPX_METADATA).read_bytes())
    if metadata.get("backend", "pip") not in (None, "pip") or metadata.get("venv_args"):
        raise ManualUpdateRequired("The installation uses a custom environment")
    requirement = _standard_requirement(metadata["main_package"], main=True)
    injected = metadata.get("injected_packages") or {}
    packages = tuple(_standard_requirement(value) for _, value in sorted(injected.items()))
    interpreter = metadata.get("source_interpreter")
    if isinstance(interpreter, dict):
        interpreter = interpreter.get("__Path__")
    interpreter = interpreter or os.environ.get("PIPX_DEFAULT_PYTHON") or sys._base_executable
    path = Path(interpreter)
    if not path.is_absolute() or not path.is_file() or path.resolve().is_relative_to(root):
        raise ManualUpdateRequired("The base Python environment is unavailable")
    return Profile(str(path), requirement, packages, _pipx_command(root, timeout, recorded))
