"""Behaviour tests for the scheduled voice runtime drift check (no network)."""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path

import pytest

import scripts.desktop_shell.voice_drift as voice_drift
from scripts.desktop_shell.model import (
    DESKTOP_TARGET_NAMES,
    load_voice_runtime_policy,
    voice_lock_path,
)
from scripts.desktop_shell.voice_bundle import VoiceBundleError
from scripts.desktop_shell.voice_drift import VoiceDriftError

_ELF = b"\x7fELF\x02\x01" + bytes(12) + (0x3E).to_bytes(2, "little") + bytes(44)
_PE = bytearray(0x80 + 26)
_PE[:2] = b"MZ"
_PE[0x3C:0x40] = (0x80).to_bytes(4, "little")
_PE[0x80:0x86] = b"PE\0\0" + (0x8664).to_bytes(2, "little")
_PE[0x98:0x9A] = (0x20B).to_bytes(2, "little")
_MACHO = {
    "x86_64": b"\xcf\xfa\xed\xfe" + (0x01000007).to_bytes(4, "little") + bytes(24),
    "arm64": b"\xcf\xfa\xed\xfe" + (0x0100000C).to_bytes(4, "little") + bytes(24),
}


def _archive(spec: object, payload: bytes) -> bytes:
    buffer = io.BytesIO()
    if spec.archive_format == "zip":
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(str(spec.member), payload)
    else:
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            info = tarfile.TarInfo(str(spec.member))
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


class _Response(io.BytesIO):
    headers = Message()

    def __init__(self, body: bytes, url: str) -> None:
        super().__init__(body)
        self._url = url

    def geturl(self) -> str:
        return self._url

    def read1(self, amount: int = -1) -> bytes:
        return self.read(amount)


def _fake_upstream(payloads: dict[str, bytes]) -> tuple[object, dict[str, bytes]]:
    """Pin every target to a local archive and serve it by URL."""
    policy = load_voice_runtime_policy()
    served: dict[str, bytes] = {}
    archives = {}
    for name, spec in policy.uv_archives.items():
        body = _archive(spec, payloads[name])
        served[spec.url] = body
        archives[name] = dataclasses.replace(spec, sha256=hashlib.sha256(body).hexdigest())
    return dataclasses.replace(policy, uv_archives=archives), served


def _payloads() -> dict[str, bytes]:
    return {
        "windows-x64": bytes(_PE),
        "macos-x64": _MACHO["x86_64"],
        "macos-arm64": _MACHO["arm64"],
        "linux-x64-ubuntu-22.04": _ELF,
    }


def test_uv_check_verifies_every_pinned_archive(tmp_path: Path) -> None:
    policy, served = _fake_upstream(_payloads())
    fetched: list[str] = []

    def opener(request: object, timeout: float) -> _Response:
        fetched.append(request.full_url)
        return _Response(served[request.full_url], request.full_url)

    executables = voice_drift.check_uv_archives(policy, tmp_path, opener=opener)

    assert sorted(fetched) == sorted(served)
    assert set(executables) == DESKTOP_TARGET_NAMES
    assert executables["windows-x64"].name.endswith("uv.exe")


def test_uv_check_reports_an_archive_that_now_holds_another_cpu(tmp_path: Path) -> None:
    payloads = _payloads()
    payloads["macos-arm64"] = _MACHO["x86_64"]
    policy, served = _fake_upstream(payloads)

    with pytest.raises(VoiceBundleError, match="architecture"):
        voice_drift.check_uv_archives(
            policy,
            tmp_path,
            opener=lambda request, timeout: _Response(
                served[request.full_url], request.full_url
            ),
        )


def test_lock_check_downloads_every_lock_by_hash_for_its_target(tmp_path: Path) -> None:
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    now = datetime(2026, 9, 25, 1, 40, tzinfo=timezone.utc)
    voice_drift.check_locks(load_voice_runtime_policy(), tmp_path, run=run, now=now)

    assert len(commands) == len(DESKTOP_TARGET_NAMES)
    for name, command in zip(sorted(DESKTOP_TARGET_NAMES), commands, strict=True):
        assert command[1:5] == ["-m", "pip", "--isolated", "download"]
        for flag in ("--require-hashes", "--no-deps"):
            assert flag in command
        assert command[command.index("--only-binary") + 1] == ":all:"
        # The cooldown: only uploads older than minimum_release_age_days count.
        assert command[command.index("--uploaded-prior-to") + 1] == (
            "2026-09-18T00:00:00Z"
        )
        assert command[-2:] == ["-r", str(voice_lock_path(name))]
    assert commands[-1][commands[-1].index("--platform") + 1] == "win_amd64"


def test_lock_check_names_the_target_that_no_longer_downloads(tmp_path: Path) -> None:
    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        failed = str(voice_lock_path("macos-x64")) in command
        return subprocess.CompletedProcess(command, 1 if failed else 0)

    with pytest.raises(VoiceDriftError, match="macos-x64"):
        voice_drift.check_locks(load_voice_runtime_policy(), tmp_path, run=run)


def _download_entry(os_name: str, arch: str, libc: str, **changes: str) -> dict:
    return {
        "key": f"cpython-3.12.14-{os_name}-{arch}-{libc}",
        "version": "3.12.14",
        "implementation": "cpython",
        "variant": "default",
        "os": os_name,
        "arch": arch,
        "libc": libc,
        **changes,
    }


_EVERY_TARGET = [
    _download_entry("windows", "x86_64", "none"),
    _download_entry("macos", "x86_64", "none"),
    _download_entry("macos", "aarch64", "none"),
    _download_entry("linux", "x86_64", "gnu"),
    _download_entry("linux", "x86_64", "musl"),
    _download_entry("linux", "aarch64", "gnu"),
]


def test_python_downloads_cover_every_desktop_target() -> None:
    assert voice_drift.missing_python_downloads(_EVERY_TARGET, "3.12.14") == []


@pytest.mark.parametrize(
    ("downloads", "missing"),
    [
        (_EVERY_TARGET[1:], ["windows-x64"]),
        (
            [entry for entry in _EVERY_TARGET if entry["libc"] != "gnu"],
            ["linux-x64-ubuntu-22.04"],
        ),
        (
            [
                _download_entry("macos", "aarch64", "none", variant="freethreaded")
                if entry["arch"] == "aarch64" and entry["os"] == "macos"
                else entry
                for entry in _EVERY_TARGET
            ],
            ["macos-arm64"],
        ),
        (
            [
                _download_entry("macos", "x86_64", "none", implementation="pypy"),
                *_EVERY_TARGET[2:],
                _EVERY_TARGET[0],
            ],
            ["macos-x64"],
        ),
        ([], sorted(DESKTOP_TARGET_NAMES)),
        ({"not": "a list"}, sorted(DESKTOP_TARGET_NAMES)),
    ],
)
def test_python_downloads_report_each_uncovered_target(
    downloads: object, missing: list[str]
) -> None:
    assert voice_drift.missing_python_downloads(downloads, "3.12.14") == missing


def test_python_downloads_must_be_the_pinned_patch_release() -> None:
    assert voice_drift.missing_python_downloads(_EVERY_TARGET, "3.12.13") == sorted(
        DESKTOP_TARGET_NAMES
    )


@pytest.mark.skipif(sys.platform == "win32", reason="the fake uv is a POSIX script")
@pytest.mark.parametrize(
    ("version", "listing", "message"),
    [
        ("uv {pinned} (x86_64-unknown-linux-gnu)", _EVERY_TARGET, None),
        ("uv 0.0.1 (x86_64-unknown-linux-gnu)", _EVERY_TARGET, "pinned uv reports"),
        ("uv {pinned}", _EVERY_TARGET[1:], "no Python 3.12.14 download for windows-x64"),
    ],
)
def test_the_pinned_uv_is_asked_for_its_version_and_python_downloads(
    tmp_path: Path, version: str, listing: list, message: str | None
) -> None:
    policy = dataclasses.replace(load_voice_runtime_policy(), python_version="3.12.14")
    listing_file = tmp_path / "listing.json"
    listing_file.write_text(json.dumps(listing))
    arguments = tmp_path / "arguments"
    uv = tmp_path / "uv"
    uv.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> "{arguments}"\n'
        'if [ "$1" = "--version" ]; then\n'
        f'  echo "{version.format(pinned=policy.uv_version)}"\n'
        "else\n"
        f'  cat "{listing_file}"\n'
        "fi\n"
    )
    uv.chmod(0o755)

    if message is None:
        voice_drift.check_uv_can_install_the_pinned_python(policy, uv, tmp_path)
        assert arguments.read_text().splitlines() == [
            "--version",
            "python list --only-downloads --all-platforms --all-arches "
            "--output-format json 3.12.14",
        ]
    else:
        with pytest.raises(VoiceDriftError, match=message):
            voice_drift.check_uv_can_install_the_pinned_python(policy, uv, tmp_path)


_NOW = datetime(2026, 9, 25, 1, 40, tzinfo=timezone.utc)


def _release(**changes: object) -> dict:
    policy = load_voice_runtime_policy()
    return {
        "tag_name": policy.uv_version,
        "draft": False,
        "prerelease": False,
        "published_at": "2026-09-18T01:01:42Z",
        **changes,
    }


def test_uv_release_older_than_the_cooldown_passes() -> None:
    voice_drift.check_uv_release_age(load_voice_runtime_policy(), _release(), _NOW)


@pytest.mark.parametrize(
    ("release", "message"),
    [
        (_release(published_at="2026-09-18T18:59:24Z"), "inside the 7-day cooldown"),
        (_release(prerelease=True), "not a published release"),
        (_release(draft=True), "not a published release"),
        (_release(tag_name="0.0.1"), "not a published release"),
        (_release(published_at=None), "not a published release"),
        (_release(published_at="last week"), "date is invalid"),
    ],
)
def test_uv_release_inside_the_cooldown_or_unpublished_fails(
    release: dict, message: str
) -> None:
    with pytest.raises(VoiceDriftError, match=message):
        voice_drift.check_uv_release_age(load_voice_runtime_policy(), release, _NOW)


@pytest.mark.parametrize(
    ("output", "accepted"),
    [
        ("pip 26.0.1 from /venv/lib/python3.12/site-packages/pip (python 3.12)", True),
        ("pip 27.1 from /venv (python 3.12)", True),
        ("pip 25.3 from /venv (python 3.12)", False),
        ("", False),
    ],
)
def test_the_drift_check_needs_a_pip_with_the_upload_cutoff(
    output: str, accepted: bool
) -> None:
    if accepted:
        voice_drift.require_pip_with_upload_cutoff(output)
    else:
        with pytest.raises(VoiceDriftError, match="pip 26.0"):
            voice_drift.require_pip_with_upload_cutoff(output)


def test_drift_tools_lock_pins_a_pip_with_the_upload_cutoff() -> None:
    from scripts.desktop_shell.voice_bundle import load_voice_lock

    lock = voice_lock_path("windows-x64").with_name("voice-drift-tools.txt")
    (pin,) = load_voice_lock(lock)
    assert pin.name == "pip"
    voice_drift.require_pip_with_upload_cutoff(f"pip {pin.version} from /venv")


@pytest.mark.parametrize(
    ("machine", "platform", "expected"),
    [
        ("x86_64", "linux", "linux-x64-ubuntu-22.04"),
        ("AMD64", "win32", "windows-x64"),
        ("arm64", "darwin", "macos-arm64"),
        ("x86_64", "darwin", "macos-x64"),
    ],
)
def test_the_host_runs_its_own_targets_uv(
    monkeypatch: pytest.MonkeyPatch, machine: str, platform: str, expected: str
) -> None:
    monkeypatch.setattr(voice_drift.platform, "machine", lambda: machine)
    monkeypatch.setattr(voice_drift.sys, "platform", platform)

    assert voice_drift.host_target(load_voice_runtime_policy()) == expected


def test_an_unsupported_host_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(voice_drift.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(voice_drift.sys, "platform", "linux")

    with pytest.raises(VoiceDriftError, match="desktop target host"):
        voice_drift.host_target(load_voice_runtime_policy())
