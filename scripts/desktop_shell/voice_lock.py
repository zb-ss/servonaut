"""Generate the hash-locked, binary-only voice runtime lock of a desktop target.

pip resolves ``voice.in`` for the target's wheel tags, but it evaluates
environment markers for the interpreter that runs it, not for ``--platform``.
The generator therefore recomputes the dependency closure with the target's
markers, resolves again with any dependency that only the target selects, and
keeps the single wheel pip chose for each distribution in that closure.

Only wheels uploaded before the policy's supply-chain cooldown
(``minimum_release_age_days``) are considered, through pip
``--uploaded-prior-to``, so every pin is at least that old when it is chosen.

Run it with CPython 3.12 and network access, then review the diff:

    python -m scripts.desktop_shell.voice_lock --target windows-x64
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from scripts.desktop_shell.model import (
    DESKTOP_TARGET_NAMES,
    VOICE_REQUIREMENTS_INPUT,
    DesktopPolicyValidationError,
    DesktopTargetSpec,
    load_desktop_build_policy,
    load_desktop_target_spec,
    load_voice_runtime_policy,
    voice_lock_path,
    voice_release_cutoff,
    voice_wheel_platforms,
)
from scripts.desktop_shell.voice_bundle import parse_voice_lock

_MAX_RESOLUTION_ROUNDS = 3
_CUTOFF_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_TARGET_MARKERS = {
    "windows-x64": {
        "os_name": "nt",
        "sys_platform": "win32",
        "platform_system": "Windows",
        "platform_machine": "AMD64",
    },
    "macos-x64": {
        "os_name": "posix",
        "sys_platform": "darwin",
        "platform_system": "Darwin",
        "platform_machine": "x86_64",
    },
    "macos-arm64": {
        "os_name": "posix",
        "sys_platform": "darwin",
        "platform_system": "Darwin",
        "platform_machine": "arm64",
    },
    "linux-x64-ubuntu-22.04": {
        "os_name": "posix",
        "sys_platform": "linux",
        "platform_system": "Linux",
        "platform_machine": "x86_64",
    },
}


class VoiceLockError(DesktopPolicyValidationError):
    """Raised when a voice lock cannot be resolved for its target."""


@dataclass(frozen=True)
class LockedWheel:
    """The one wheel pip selected for a distribution, with its digest."""

    name: str
    version: str
    filename: str
    sha256: str


@dataclass(frozen=True)
class ResolvedDistribution:
    """A distribution from a pip installation report."""

    wheel: LockedWheel
    requires: tuple[str, ...]


def marker_environment(target_name: str, python_version: str) -> dict[str, str]:
    """Return the PEP 508 marker environment of the target's managed runtime."""
    return {
        "implementation_name": "cpython",
        "implementation_version": python_version,
        "platform_python_implementation": "CPython",
        "python_version": ".".join(python_version.split(".")[:2]),
        "python_full_version": python_version,
        "platform_release": "",
        "platform_version": "",
        **_TARGET_MARKERS[target_name],
    }


def parse_pip_report(report: Mapping[str, object]) -> dict[str, ResolvedDistribution]:
    """Index a ``pip install --report`` by canonical distribution name."""
    install = report.get("install")
    if report.get("version") != "1" or not isinstance(install, list):
        raise VoiceLockError("unsupported pip installation report")
    resolved: dict[str, ResolvedDistribution] = {}
    for item in install:
        metadata = item["metadata"]
        info = item["download_info"]
        name = canonicalize_name(metadata["name"])
        filename = unquote(PurePosixPath(urlsplit(info["url"]).path).name)
        sha256 = info.get("archive_info", {}).get("hashes", {}).get("sha256")
        if not filename.endswith(".whl") or not isinstance(sha256, str):
            raise VoiceLockError(f"{name} did not resolve to a hashed wheel")
        resolved[name] = ResolvedDistribution(
            wheel=LockedWheel(name, metadata["version"], filename, sha256),
            requires=tuple(metadata.get("requires_dist", ())),
        )
    return resolved


def target_closure(
    roots: Iterable[Requirement],
    resolved: Mapping[str, ResolvedDistribution],
    environment: Mapping[str, str],
) -> tuple[set[str], list[Requirement]]:
    """Return the resolved names the target needs and requirements left unresolved."""
    needed: set[str] = set()
    missing: list[Requirement] = []
    expanded: set[tuple[str, str]] = set()
    pending = [(requirement, "") for requirement in roots]
    while pending:
        requirement, extra = pending.pop()
        if requirement.marker is not None and not requirement.marker.evaluate(
            {**environment, "extra": extra}
        ):
            continue
        name = canonicalize_name(requirement.name)
        found = resolved.get(name)
        if found is None:
            missing.append(requirement)
            continue
        if not requirement.specifier.contains(found.wheel.version, prereleases=True):
            raise VoiceLockError(f"{name} {found.wheel.version} violates {requirement}")
        needed.add(name)
        for wanted in ("", *sorted(requirement.extras)):
            if (name, wanted) not in expanded:
                expanded.add((name, wanted))
                pending.extend((Requirement(dep), wanted) for dep in found.requires)
    return needed, missing


def render_lock(
    target: DesktopTargetSpec,
    wheels: Sequence[LockedWheel],
    python_version: str,
    added: Sequence[str],
    pip_version: str,
    uploaded_prior_to: str,
) -> str:
    """Render the lock with a header that records how it was produced."""
    platforms = voice_wheel_platforms(target)
    shown = platforms if len(platforms) <= 2 else (platforms[0], "...", platforms[-1])
    extra = f" {' '.join(added)}" if added else ""
    lines = [
        f"# Managed voice runtime lock for the {target.name} desktop target.",
        "# Generated from voice.in by scripts/desktop_shell/voice_lock.py with",
        f"# pip {pip_version}:",
        "#   pip install --dry-run --ignore-installed --report <report.json>",
        f"#     --only-binary :all: --platform {' '.join(shown)}",
        f"#     --python-version {python_version} --implementation cp --abi cp312",
        f"#     --uploaded-prior-to {uploaded_prior_to}",
        f"#     --target <empty directory> -r voice.in{extra}",
        "# The cutoff enforces the supply-chain cooldown in voice-runtime.json: pins",
        "# must be at least minimum_release_age_days old when they are chosen.",
        "# The generator evaluates environment markers for the target rather than the",
        "# build host, adds dependencies only the target selects to that command, and",
        "# keeps the one wheel pip selected for each distribution. The desktop app",
        "# installs this file with --require-hashes --only-binary :all: --no-deps.",
        f"# Regenerate: python -m scripts.desktop_shell.voice_lock --target {target.name}",
        "",
    ]
    for wheel in sorted(wheels, key=lambda item: item.name):
        lines += [
            f"{wheel.name}=={wheel.version} \\",
            f"    --hash=sha256:{wheel.sha256}",
            f"    # {wheel.filename}",
        ]
    return "\n".join(lines) + "\n"


def resolve_target(
    target: DesktopTargetSpec, python_version: str, uploaded_prior_to: str
) -> str:
    """Resolve ``voice.in`` for one target and return the rendered lock."""
    roots = _read_requirements(VOICE_REQUIREMENTS_INPUT)
    environment = marker_environment(target.name, python_version)
    added: list[Requirement] = []
    for _ in range(_MAX_RESOLUTION_ROUNDS):
        report = _pip_report(target, python_version, uploaded_prior_to, added)
        resolved = parse_pip_report(report)
        needed, missing = target_closure([*roots, *added], resolved, environment)
        if not missing:
            return render_lock(
                target,
                [resolved[name].wheel for name in needed],
                python_version,
                [str(requirement) for requirement in added],
                str(report.get("pip_version", "unknown")),
                uploaded_prior_to,
            )
        added += [_without_marker(requirement) for requirement in missing]
    raise VoiceLockError(f"{target.name} did not converge on a closed dependency set")


def _read_requirements(path: Path) -> list[Requirement]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [
        Requirement(line) for line in lines if line.strip() and not line.startswith("#")
    ]


def _without_marker(requirement: Requirement) -> Requirement:
    extras = f"[{','.join(sorted(requirement.extras))}]" if requirement.extras else ""
    return Requirement(f"{requirement.name}{extras}{requirement.specifier}")


def _pip_report(
    target: DesktopTargetSpec,
    python_version: str,
    uploaded_prior_to: str,
    added: Sequence[Requirement],
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="servonaut-voice-lock-") as scratch:
        report = Path(scratch) / "report.json"
        command = [
            sys.executable,
            "-m",
            "pip",
            "--isolated",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--quiet",
            "--dry-run",
            "--ignore-installed",
            "--uploaded-prior-to",
            uploaded_prior_to,
            "--report",
            str(report),
            "--only-binary",
            ":all:",
            *(
                argument
                for tag in voice_wheel_platforms(target)
                for argument in ("--platform", tag)
            ),
            "--python-version",
            python_version,
            "--implementation",
            "cp",
            "--abi",
            "cp312",
            "--target",
            str(Path(scratch) / "target"),
            "-r",
            str(VOICE_REQUIREMENTS_INPUT),
            *(str(requirement) for requirement in added),
        ]
        subprocess.run(
            command,
            check=True,
            timeout=load_desktop_build_policy().dependency_install_timeout_seconds,
        )
        return json.loads(report.read_text(encoding="utf-8"))


def main(argv: Sequence[str] | None = None) -> int:
    """Regenerate one or every target's voice runtime lock."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--target", required=True, choices=sorted(DESKTOP_TARGET_NAMES | {"all"})
    )
    parser.add_argument(
        "--uploaded-prior-to",
        help="reproduce an earlier lock; defaults to the policy's cooldown cutoff",
    )
    args = parser.parse_args(argv)
    if sys.version_info[:2] != (3, 12):
        parser.error("run the generator with CPython 3.12")
    policy = load_voice_runtime_policy()
    newest = voice_release_cutoff(policy.minimum_release_age_days)
    cutoff = args.uploaded_prior_to or newest
    # Fixed-width UTC timestamps compare correctly as strings.
    if not _CUTOFF_RE.fullmatch(cutoff) or cutoff > newest:
        parser.error(f"--uploaded-prior-to must be a UTC time no later than {newest}")
    names = sorted(DESKTOP_TARGET_NAMES) if args.target == "all" else [args.target]
    for name in names:
        output = voice_lock_path(name)
        text = resolve_target(load_desktop_target_spec(name), policy.python_version, cutoff)
        # Validate before touching the committed lock; always write LF endings.
        parse_voice_lock(text, output.name)
        output.write_text(text, encoding="ascii", newline="\n")
        print(f"wrote {output.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
