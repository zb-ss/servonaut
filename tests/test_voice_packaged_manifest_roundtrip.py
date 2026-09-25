"""The desktop build's voice manifest must read back exactly in the app.

The build stages the managed voice runtime inputs and writes their manifest
(``scripts.desktop_shell.voice_bundle.stage_voice_bundle``); the packaged app
reads it with ``servonaut.desktop.voice.packaged_manifest``. The two sides are
separate code, so these tests run the real writer and feed its output to the
real reader and to the app's runtime manager. Nothing touches the network: the
pinned uv download is served from memory and the uv executable is a header
stub, never run.
"""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import os
import struct
import tarfile
import zipfile
from collections.abc import Callable
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

import servonaut
from scripts.desktop_shell.model import (
    _VOICE_POLICY_BOUNDS,
    DESKTOP_TARGET_NAMES,
    VOICE_MANIFEST_NAME,
    VOICE_PAYLOAD_DIRECTORY,
    VOICE_REQUIREMENTS_NAME,
    DesktopTargetSpec,
    VoiceRuntimePolicy,
    load_desktop_target_spec,
    load_voice_runtime_policy,
    voice_lock_path,
)
from scripts.desktop_shell.voice_bundle import (
    expected_wheel_name,
    stage_voice_bundle,
    verify_voice_bundle,
)
from servonaut.desktop.voice.packaged_manifest import (
    PACKAGED_MANIFEST_FILENAME,
    PACKAGED_VOICE_DIRNAME,
    REQUIREMENTS_FILENAME,
    BundledFile,
    PackagedVoiceManifest,
    PackagedVoiceManifestError,
    ProvisionTimeouts,
    load_packaged_manifest,
)
from servonaut.desktop.voice.runtime import (
    VoiceRuntimeIntegrityError,
    VoiceRuntimeManager,
    VoiceRuntimeState,
)
from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)

_PRODUCT_VERSION = servonaut.__version__
_WHEEL_BYTES = b"product wheel stand-in"


def _elf(machine: int) -> bytes:
    return b"\x7fELF\x02\x01" + bytes(12) + machine.to_bytes(2, "little") + bytes(44)


def _pe_x86_64() -> bytes:
    header = bytearray(0x80)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", header, 0x44, 0x8664)
    struct.pack_into("<H", header, 0x58, 0x20B)
    return bytes(header)


def _macho(cpu_type: int) -> bytes:
    return b"\xcf\xfa\xed\xfe" + struct.pack("<I", cpu_type) + bytes(24)


# Header-only stand-ins that pass the writer's native identity check per target.
_UV_STUBS = {
    "linux-x64-ubuntu-22.04": _elf(0x3E),
    "windows-x64": _pe_x86_64(),
    "macos-x64": _macho(0x01000007),
    "macos-arm64": _macho(0x0100000C),
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _archive(archive_format: str, member: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    if archive_format == "zip":
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(zipfile.ZipInfo(member), data)
    else:
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            info = tarfile.TarInfo(member)
            info.mode = 0o755
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class _ArchiveResponse:
    """The pinned uv archive, served from memory at the URL it was asked for."""

    def __init__(self, url: str, body: bytes) -> None:
        self._url = url
        self._body = io.BytesIO(body)
        self.headers = Message()

    def read1(self, amount: int) -> bytes:
        return self._body.read(amount)

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> _ArchiveResponse:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


@dataclasses.dataclass(frozen=True)
class _Staged:
    target: DesktopTargetSpec
    policy: VoiceRuntimePolicy
    resource_root: Path
    voice_dir: Path
    uv_bytes: bytes

    @property
    def manifest_path(self) -> Path:
        return self.voice_dir / PACKAGED_MANIFEST_FILENAME


@pytest.fixture(params=sorted(DESKTOP_TARGET_NAMES))
def staged(request: pytest.FixtureRequest, tmp_path: Path) -> _Staged:
    """Run the build's writer for one desktop target into ``resources/voice``."""
    target = load_desktop_target_spec(request.param)
    if os.name == "nt" and target.platform != "win32":
        pytest.skip("a POSIX uv executable cannot carry its executable bit on Windows")
    uv_bytes = _UV_STUBS[target.name]
    policy = load_voice_runtime_policy()
    spec = policy.uv_archives[target.name]
    archive = _archive(spec.archive_format, str(spec.member), uv_bytes)
    # Only the digest changes: the stand-in archive replaces the upstream one.
    pinned = dataclasses.replace(spec, sha256=_sha256(archive))
    policy = dataclasses.replace(
        policy, uv_archives={**policy.uv_archives, target.name: pinned}
    )
    wheel = tmp_path / "dist" / expected_wheel_name(_PRODUCT_VERSION)
    wheel.parent.mkdir()
    wheel.write_bytes(_WHEEL_BYTES)
    resource_root = tmp_path / "resources"
    resource_root.mkdir()

    def open_url(url_request: Any, timeout: float) -> _ArchiveResponse:
        assert url_request.full_url == spec.url
        return _ArchiveResponse(url_request.full_url, archive)

    voice_dir = stage_voice_bundle(
        resource_root, target, wheel, _PRODUCT_VERSION, policy, opener=open_url
    )
    return _Staged(target, policy, resource_root, voice_dir, uv_bytes)


def _layout(staged: _Staged, data_root: Path) -> RuntimeLayout:
    return RuntimeLayout(
        kind=DistributionKind.PACKAGED_DESKTOP,
        product_version=_PRODUCT_VERSION,
        build_revision=None,
        resource_root=staged.resource_root,
        executable_root=data_root.parent / "app",
        data_root=data_root,
        executable=data_root.parent / "app" / "servonaut-desktop",
        python_executable=None,
        path_console=None,
        console_helper=data_root.parent / "app" / "servonaut",
        desktop_child=None,
        package_management=PackageManagementCapability(
            kind=PackageManagementKind.UNSUPPORTED,
            argv_prefix=(),
            allows_automatic_mutation=False,
        ),
        is_frozen=True,
    )


def _rewrite(path: Path, change: Callable[[dict[str, Any]], None]) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    change(document)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# --- layout ---------------------------------------------------------------------


def test_build_and_app_agree_on_the_bundle_layout() -> None:
    assert VOICE_MANIFEST_NAME == PACKAGED_MANIFEST_FILENAME
    assert VOICE_REQUIREMENTS_NAME == REQUIREMENTS_FILENAME
    # The build copies the bundle into PyInstaller's contents directory, which
    # is the frozen app's resource root (sys._MEIPASS).
    assert VOICE_PAYLOAD_DIRECTORY.parts == ("_internal", PACKAGED_VOICE_DIRNAME)


# --- round trip -----------------------------------------------------------------


def test_every_field_the_build_records_reads_back_in_the_app(staged: _Staged) -> None:
    target, policy = staged.target, staged.policy
    lock_bytes = voice_lock_path(target.name).read_bytes()

    manifest = load_packaged_manifest(staged.manifest_path)

    assert manifest == PackagedVoiceManifest(
        schema_version=1,
        target=target.name,
        python_version=policy.python_version,
        uv=BundledFile(
            filename=policy.uv_archives[target.name].executable_name,
            sha256=_sha256(staged.uv_bytes),
        ),
        wheel=BundledFile(
            filename=expected_wheel_name(_PRODUCT_VERSION), sha256=_sha256(_WHEEL_BYTES)
        ),
        requirements=BundledFile(filename=REQUIREMENTS_FILENAME, sha256=_sha256(lock_bytes)),
        timeouts=ProvisionTimeouts(
            uv_command_seconds=policy.uv_command_timeout_seconds,
            stall_seconds=policy.stall_timeout_seconds,
            provision_seconds=policy.provision_timeout_seconds,
        ),
    )
    # Every recorded file name resolves to the staged bytes it pins.
    for bundled in (manifest.uv, manifest.wheel, manifest.requirements):
        assert _sha256((staged.voice_dir / bundled.filename).read_bytes()) == bundled.sha256


def test_the_build_verifier_and_the_app_reader_see_the_same_manifest(
    staged: _Staged,
) -> None:
    built = verify_voice_bundle(
        staged.voice_dir, staged.target, _PRODUCT_VERSION, staged.policy
    )
    read = load_packaged_manifest(staged.manifest_path)

    assert (read.target, read.python_version) == (built.target, built.python_version)
    for name in ("uv", "wheel", "requirements"):
        written = getattr(built, name)
        assert getattr(read, name) == BundledFile(written.filename, written.sha256)
    assert read.timeouts == ProvisionTimeouts(
        uv_command_seconds=built.uv_command_seconds,
        stall_seconds=built.stall_seconds,
        provision_seconds=built.provision_seconds,
    )


def test_the_app_finds_the_build_output_through_its_runtime_layout(
    staged: _Staged, tmp_path: Path
) -> None:
    manager = VoiceRuntimeManager.for_runtime(_layout(staged, tmp_path / "data"))

    assert manager is not None
    assert manager.packaged_manifest == load_packaged_manifest(staged.manifest_path)
    assert manager.status().state is VoiceRuntimeState.NOT_INSTALLED


_TIMEOUT_FIELDS = (
    "stall_timeout_seconds",
    "uv_command_timeout_seconds",
    "provision_timeout_seconds",
)


@pytest.mark.parametrize("bound", [0, 1], ids=["shortest", "longest"])
def test_time_limits_at_the_build_policy_bounds_read_back(
    staged: _Staged, tmp_path: Path, bound: int
) -> None:
    # The build's policy loader accepts each limit within these bounds; the
    # app must accept whatever the build can write.
    stall, uv_command, provision = (
        _VOICE_POLICY_BOUNDS[field][bound] for field in _TIMEOUT_FIELDS
    )
    policy = dataclasses.replace(
        staged.policy,
        stall_timeout_seconds=stall,
        uv_command_timeout_seconds=uv_command,
        provision_timeout_seconds=provision,
    )
    # Restaging with other limits needs a fresh resource root.
    resource_root = tmp_path / "bounds"
    resource_root.mkdir()
    wheel = staged.voice_dir / expected_wheel_name(_PRODUCT_VERSION)
    spec = policy.uv_archives[staged.target.name]
    archive = _archive(spec.archive_format, str(spec.member), staged.uv_bytes)

    voice_dir = stage_voice_bundle(
        resource_root,
        staged.target,
        wheel,
        _PRODUCT_VERSION,
        policy,
        opener=lambda url_request, timeout: _ArchiveResponse(url_request.full_url, archive),
    )

    assert load_packaged_manifest(voice_dir / PACKAGED_MANIFEST_FILENAME).timeouts == (
        ProvisionTimeouts(
            uv_command_seconds=uv_command, stall_seconds=stall, provision_seconds=provision
        )
    )


# --- tampering ------------------------------------------------------------------


_TAMPERING = {
    "schema version bump": lambda raw: raw.update(schema_version=2),
    "schema version as text": lambda raw: raw.update(schema_version="1"),
    "missing root key": lambda raw: raw.pop("timeouts"),
    "unknown root key": lambda raw: raw.update(extra="x"),
    "missing file key": lambda raw: raw["wheel"].pop("sha256"),
    "unknown file key": lambda raw: raw["uv"].update(size=1),
    "missing timeout": lambda raw: raw["timeouts"].pop("stall_seconds"),
    "unknown timeout": lambda raw: raw["timeouts"].update(download_seconds=1),
    "upper-case digest": lambda raw: raw["uv"].update(sha256=raw["uv"]["sha256"].upper()),
    "short digest": lambda raw: raw["wheel"].update(sha256=raw["wheel"]["sha256"][:-1]),
    "non-hex digest": lambda raw: raw["requirements"].update(sha256="g" * 64),
    "renamed requirements": lambda raw: raw["requirements"].update(filename="voice.txt"),
    "non-wheel product file": lambda raw: raw["wheel"].update(filename="servonaut.zip"),
    "path in file name": lambda raw: raw["uv"].update(filename="../uv"),
    "inexact python": lambda raw: raw.update(python_version="3.12"),
    "target with a path": lambda raw: raw.update(target="linux/x64"),
    "stall above command limit": lambda raw: raw["timeouts"].update(
        stall_seconds=raw["timeouts"]["uv_command_seconds"] + 1
    ),
    "zero time limit": lambda raw: raw["timeouts"].update(stall_seconds=0),
    "fractional time limit": lambda raw: raw["timeouts"].update(stall_seconds=1.5),
}


@pytest.mark.parametrize("change", list(_TAMPERING.values()), ids=list(_TAMPERING))
def test_the_app_refuses_a_tampered_build_manifest(
    staged: _Staged, change: Callable[[dict[str, Any]], None]
) -> None:
    _rewrite(staged.manifest_path, change)

    with pytest.raises(PackagedVoiceManifestError):
        load_packaged_manifest(staged.manifest_path)


def test_the_app_refuses_a_repeated_key_in_the_build_manifest(staged: _Staged) -> None:
    text = staged.manifest_path.read_text(encoding="utf-8")
    staged.manifest_path.write_text(
        text.replace('"schema_version": 1', '"schema_version": 1,\n  "schema_version": 1'),
        encoding="utf-8",
    )

    with pytest.raises(PackagedVoiceManifestError, match="Duplicate"):
        load_packaged_manifest(staged.manifest_path)


@pytest.mark.parametrize("entry", ["uv", "wheel", "requirements"])
def test_a_well_formed_but_wrong_digest_is_refused_before_provisioning(
    staged: _Staged, tmp_path: Path, entry: str
) -> None:
    # The reader checks each digest's form; the runtime manager compares it with
    # the bundled bytes before it runs uv or stages anything.
    _rewrite(staged.manifest_path, lambda raw: raw[entry].update(sha256="0" * 64))
    manager = VoiceRuntimeManager.for_runtime(_layout(staged, tmp_path / "data"))
    assert manager is not None

    with pytest.raises(VoiceRuntimeIntegrityError, match="recorded checksum"):
        manager.provision()

    assert manager.status().state is VoiceRuntimeState.NOT_INSTALLED
