"""Check that every pinned voice runtime input can still be fetched as reviewed.

Upstream can withdraw or replace a release asset or a wheel, so this check:

- fetches each pinned uv archive and verifies its digest and native identity;
- runs the host's pinned uv and requires its version and a download of the
  pinned Python for every desktop target in uv's own download list;
- requires the uv release to be older than the supply-chain cooldown; and
- downloads each voice lock's wheels for their target by hash, considering
  only uploads older than that cooldown.

Run it on an x86_64 Linux, macOS or Windows host with network access and
pip 26.0 or later.
"""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import urllib.request
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from scripts.desktop_shell.model import (
    DESKTOP_TARGET_NAMES,
    DesktopPolicyValidationError,
    VoiceRuntimePolicy,
    load_desktop_build_policy,
    load_desktop_target_spec,
    load_voice_runtime_policy,
    voice_lock_path,
    voice_release_cutoff,
    voice_wheel_platforms,
)
from scripts.desktop_shell.voice_bundle import Opener, fetch_uv

# uv's (os, arch, libc) for the Python each desktop target installs.
_UV_PYTHON_PLATFORMS = {
    "windows-x64": ("windows", "x86_64", "none"),
    "macos-x64": ("macos", "x86_64", "none"),
    "macos-arm64": ("macos", "aarch64", "none"),
    "linux-x64-ubuntu-22.04": ("linux", "x86_64", "gnu"),
}
_HOST_ARCHITECTURES = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "arm64": "arm64",
    "aarch64": "arm64",
}
# pip gained --uploaded-prior-to in 26.0.
_MINIMUM_PIP = (26, 0)
_GITHUB_API = "https://api.github.com"
_MAX_RELEASE_JSON_BYTES = 4 * 1024 * 1024
_MAX_UV_OUTPUT_BYTES = 4 * 1024 * 1024


class VoiceDriftError(DesktopPolicyValidationError):
    """Raised when a pinned voice runtime input no longer resolves as reviewed."""


def check_uv_archives(
    policy: VoiceRuntimePolicy, work_dir: Path, opener: Opener | None = None
) -> dict[str, Path]:
    """Fetch every target's pinned uv; return the extracted executables."""
    executables = {}
    for name, spec in sorted(policy.uv_archives.items()):
        executable = work_dir / f"{name}-{spec.executable_name}"
        fetch_uv(policy, load_desktop_target_spec(name), executable, opener=opener)
        executables[name] = executable
    return executables


def check_uv_can_install_the_pinned_python(
    policy: VoiceRuntimePolicy, uv: Path, work_dir: Path
) -> None:
    """Run the host's uv offline: its version and Python downloads must match."""
    version = _run_uv(policy, uv, ["--version"], work_dir)
    if not re.fullmatch(rf"uv {re.escape(policy.uv_version)}( \(.*\))?\s*", version):
        raise VoiceDriftError(f"pinned uv reports {version.strip()!r}")
    listing = _run_uv(
        policy,
        uv,
        [
            *("python", "list", "--only-downloads", "--all-platforms", "--all-arches"),
            *("--output-format", "json", policy.python_version),
        ],
        work_dir,
    )
    try:
        downloads = json.loads(listing)
    except json.JSONDecodeError as error:
        raise VoiceDriftError("uv python list output is not JSON") from error
    missing = missing_python_downloads(downloads, policy.python_version)
    if missing:
        raise VoiceDriftError(
            f"uv {policy.uv_version} has no Python {policy.python_version} "
            f"download for {', '.join(missing)}"
        )


def missing_python_downloads(downloads: object, python_version: str) -> list[str]:
    """Return the desktop targets uv lists no default CPython download for."""
    offered = set()
    if isinstance(downloads, list):
        for entry in downloads:
            if (
                isinstance(entry, dict)
                and entry.get("implementation") == "cpython"
                and entry.get("version") == python_version
                and entry.get("variant") == "default"
            ):
                offered.add((entry.get("os"), entry.get("arch"), entry.get("libc")))
    return sorted(
        name
        for name, identity in _UV_PYTHON_PLATFORMS.items()
        if identity not in offered
    )


def check_uv_release_age(
    policy: VoiceRuntimePolicy,
    release: Mapping[str, object] | None = None,
    now: datetime | None = None,
) -> None:
    """Require the pinned uv release to be published and older than the cooldown."""
    release = release if release is not None else _fetch_release(policy)
    published = release.get("published_at")
    if (
        release.get("tag_name") != policy.uv_version
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or not isinstance(published, str)
    ):
        raise VoiceDriftError(f"uv {policy.uv_version} is not a published release")
    try:
        published_at = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except ValueError as error:
        raise VoiceDriftError("uv release date is invalid") from error
    newest = (now or datetime.now(timezone.utc)) - timedelta(
        days=policy.minimum_release_age_days
    )
    if published_at > newest:
        raise VoiceDriftError(
            f"uv {policy.uv_version} was published {published}, inside the "
            f"{policy.minimum_release_age_days}-day cooldown"
        )


def lock_download_command(
    target_name: str, python_version: str, uploaded_prior_to: str, dest: Path
) -> list[str]:
    """Return the pip command that fetches a target's locked wheels by hash."""
    platforms = voice_wheel_platforms(load_desktop_target_spec(target_name))
    return [
        *(sys.executable, "-m", "pip", "--isolated", "download", "--quiet"),
        *("--disable-pip-version-check", "--no-input", "--no-deps", "--require-hashes"),
        *("--only-binary", ":all:", "--implementation", "cp", "--abi", "cp312"),
        *(argument for tag in platforms for argument in ("--platform", tag)),
        *("--python-version", python_version, "--uploaded-prior-to", uploaded_prior_to),
        *("--dest", str(dest), "-r", str(voice_lock_path(target_name))),
    ]


def check_locks(
    policy: VoiceRuntimePolicy,
    work_dir: Path,
    run=subprocess.run,
    now: datetime | None = None,
) -> None:
    """Require every voice lock to download by hash, from uploads past the cooldown."""
    cutoff = voice_release_cutoff(policy.minimum_release_age_days, now)
    timeout = load_desktop_build_policy().dependency_install_timeout_seconds
    for name in sorted(DESKTOP_TARGET_NAMES):
        command = lock_download_command(
            name, policy.python_version, cutoff, work_dir / name
        )
        if run(command, check=False, timeout=timeout).returncode != 0:
            raise VoiceDriftError(
                f"voice lock for {name} no longer downloads from uploads before {cutoff}"
            )


def require_pip_with_upload_cutoff(version_output: str) -> None:
    """Require a pip that understands --uploaded-prior-to."""
    match = re.match(r"pip (\d+)\.(\d+)", version_output)
    if match is None or (int(match[1]), int(match[2])) < _MINIMUM_PIP:
        raise VoiceDriftError(
            "the drift check needs pip 26.0 or later for --uploaded-prior-to"
        )


def host_target(policy: VoiceRuntimePolicy) -> str:
    """Return the desktop target this host runs, whose uv the check executes."""
    architecture = _HOST_ARCHITECTURES.get(platform.machine().casefold())
    for name in sorted(policy.uv_archives):
        spec = load_desktop_target_spec(name)
        if (spec.platform, spec.architecture) == (sys.platform, architecture):
            return name
    raise VoiceDriftError("run the drift check on a desktop target host")


def _run_uv(
    policy: VoiceRuntimePolicy, uv: Path, arguments: Iterable[str], home: Path
) -> str:
    """Run uv offline with its caches and configuration confined to ``home``."""
    arguments = list(arguments)
    environment = {
        "HOME": str(home),
        "UV_NO_CONFIG": "1",
        "UV_OFFLINE": "1",
        "UV_CACHE_DIR": str(home / "uv-cache"),
        "UV_PYTHON_INSTALL_DIR": str(home / "uv-python"),
    }
    if "SystemRoot" in os.environ:
        environment["SystemRoot"] = os.environ["SystemRoot"]
    try:
        completed = subprocess.run(
            [str(uv), *arguments],
            env=environment,
            cwd=home,
            capture_output=True,
            timeout=policy.uv_command_timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VoiceDriftError(f"pinned uv could not run: {error}") from error
    if completed.returncode != 0 or len(completed.stdout) > _MAX_UV_OUTPUT_BYTES:
        raise VoiceDriftError(f"pinned uv {' '.join(arguments)} failed")
    return completed.stdout.decode("utf-8", errors="replace")


def _fetch_release(policy: VoiceRuntimePolicy) -> Mapping[str, object]:
    """Read the pinned uv release from the GitHub API (read-only)."""
    if policy.uv_origin_host != "github.com":
        raise VoiceDriftError("uv release age can be checked only for GitHub releases")
    url = next(iter(policy.uv_archives.values())).url
    parts = PurePosixPath(urlsplit(url).path).parts
    # ("/", owner, repository, "releases", "download", version, asset)
    if len(parts) != 7 or parts[3:6] != ("releases", "download", policy.uv_version):
        raise VoiceDriftError("uv archive URL is not a GitHub release asset")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "servonaut-voice-drift",
    }
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"{_GITHUB_API}/repos/{parts[1]}/{parts[2]}/releases/tags/{policy.uv_version}",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(
            request, timeout=policy.socket_timeout_seconds
        ) as response:
            body = response.read(_MAX_RELEASE_JSON_BYTES + 1)
    except OSError as error:
        raise VoiceDriftError(f"uv release could not be read: {error}") from error
    if len(body) > _MAX_RELEASE_JSON_BYTES:
        raise VoiceDriftError("uv release response is too large")
    try:
        release = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VoiceDriftError("uv release response is not JSON") from error
    if not isinstance(release, dict):
        raise VoiceDriftError("uv release response is not an object")
    return release


def main() -> int:
    policy = load_voice_runtime_policy()
    pip_version = subprocess.run(
        [sys.executable, "-m", "pip", "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=load_desktop_build_policy().interpreter_probe_timeout_seconds,
    ).stdout
    try:
        require_pip_with_upload_cutoff(pip_version)
        host = host_target(policy)
        check_uv_release_age(policy)
        with tempfile.TemporaryDirectory(prefix="servonaut-voice-drift-") as scratch:
            work = Path(scratch)
            executables = check_uv_archives(policy, work)
            check_uv_can_install_the_pinned_python(policy, executables[host], work)
            check_locks(policy, work / "wheels")
    except DesktopPolicyValidationError as error:
        print(f"voice runtime drift: {error}", file=sys.stderr)
        return 1
    print(
        f"uv {policy.uv_version} and Python {policy.python_version} pins and every "
        "voice lock still resolve within the cooldown"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
