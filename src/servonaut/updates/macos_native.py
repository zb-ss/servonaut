"""macOS platform checks for an application replacement."""

from __future__ import annotations

import ctypes
import json
import os
import plistlib
import re
import stat
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from servonaut.distribution.apply_policy import DesktopArtifactIdentity
from servonaut.distribution.manifest import build_version_text
from servonaut.updates.macho import macho_architectures
from servonaut.updates.macos_transaction import BUNDLE_NAME, MacUpdateError
from servonaut.updates.processes import UnknownProcess, birth

BUNDLE_ID = "dev.servonaut.desktop"
ADMISSION_VERSION_KEY = "ServonautUpdateAdmission"
ADMISSION_VERSION = 1
ROLLBACK_EPOCH_KEY = "ServonautRollbackEpoch"
ROLLBACK_EPOCH = 1
EXECUTABLES = ("servonaut-desktop", "servonaut-desktop-child", "servonaut")
WORKER_SUFFIX = ".runtime"

_TEAM = re.compile(r"^[A-Z0-9]{10}$")
_RUNTIME = re.compile(r"^CodeDirectory .*flags=0x[0-9a-f]+\((?:[a-z,-]*,)?runtime(?:[,)]).*")
_UNCACHED_ASSESSMENT = ("/usr/sbin/spctl", "--assess", "--type", "execute", "--ignore-cache", "--no-cache", "-vv")
_QUARANTINE = "com.apple.quarantine"
_PROC_UID_ONLY = 4
_PROC_PATH_SIZE = 4096
_DETACH_BACKOFF = (0.2, 0.5, 1.0)
_SYSTEM_TOOLS = (
    "/bin/ls", "/bin/ps", "/usr/bin/codesign", "/usr/bin/ditto", "/usr/bin/hdiutil",
    "/usr/bin/open", "/usr/bin/xattr", "/usr/sbin/lsof", "/usr/sbin/spctl",
)


def require_replacement_tools() -> None:
    if not all(os.access(tool, os.X_OK) for tool in _SYSTEM_TOOLS):
        raise MacUpdateError("The macOS tools required for automatic installation are unavailable.")


def native_command(*args: str | Path, timeout: float = 30) -> str:
    """Run an absolute system utility without inheriting shell configuration."""
    try:
        result = subprocess.run(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors="replace", timeout=timeout, check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise MacUpdateError(f"{Path(args[0]).name} could not complete.") from exc
    if result.returncode != 0:
        raise MacUpdateError(f"{Path(args[0]).name} could not verify or prepare the update.")
    return result.stdout


def read_info(bundle: Path) -> dict:
    path = bundle / "Contents" / "Info.plist"
    try:
        if not stat.S_ISREG(path.lstat().st_mode) or not path.resolve().is_relative_to(bundle):
            raise ValueError("Unexpected Info.plist")
        with path.open("rb") as stream:
            data = plistlib.loads(stream.read(65537))
        if not isinstance(data, dict) or data.get("CFBundleIdentifier") != BUNDLE_ID:
            raise ValueError("Unexpected bundle identifier")
        if data.get("CFBundleExecutable") != EXECUTABLES[0]:
            raise ValueError("Unexpected launcher")
        return data
    except (OSError, ValueError, plistlib.InvalidFileException) as exc:
        raise MacUpdateError("The application bundle metadata could not be verified.") from exc


def _signed_details(path: Path) -> str:
    output = native_command("/usr/bin/codesign", "-dvvv", path)
    if not any(_RUNTIME.fullmatch(line) for line in output.splitlines()):
        raise MacUpdateError("The application does not use the hardened runtime.")
    return output


def _signed_team(path: Path) -> str:
    team, = _signature_values(_signed_details(path), "TeamIdentifier")
    if not _TEAM.fullmatch(team):
        raise MacUpdateError("The application has no valid signing team.")
    return team


def _signature_values(output: str, key: str) -> list[str]:
    values = [line.split("=", 1)[1] for line in output.splitlines() if line.startswith(f"{key}=")]
    if len(values) != 1:
        raise MacUpdateError("The application signature could not be identified.")
    return values


def require_developer_id(path: Path, team: str, identifier: str | None = None) -> None:
    if not _TEAM.fullmatch(team):
        raise MacUpdateError("The signing team is invalid.")
    requirement = (
        'anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists'
        ' and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
        f' and certificate leaf[subject.OU] = "{team}"'
    )
    if identifier is not None:
        requirement += f' and identifier "{identifier}"'
    native_command(
        "/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "-R", f"={requirement}", path,
    )


def _require_notarization(bundle: Path) -> None:
    output = native_command(*_UNCACHED_ASSESSMENT, bundle, timeout=60)
    if "source=Notarized Developer ID" not in output.splitlines():
        raise MacUpdateError("Gatekeeper did not verify a notarized Developer ID application.")


def require_bootstrap(bundle: Path, info: dict) -> None:
    if type(info.get(ADMISSION_VERSION_KEY)) is not int or info[ADMISSION_VERSION_KEY] != ADMISSION_VERSION:
        raise MacUpdateError("This application does not support coordinated replacement.")
    if type(info.get(ROLLBACK_EPOCH_KEY)) is not int or info[ROLLBACK_EPOCH_KEY] != ROLLBACK_EPOCH:
        raise MacUpdateError("This application has an incompatible rollback format.")
    for name in (*EXECUTABLES, *(f"{entry}{WORKER_SUFFIX}" for entry in EXECUTABLES)):
        executable = bundle / "Contents" / "MacOS" / name
        if not stat.S_ISREG(executable.lstat().st_mode):
            raise MacUpdateError("The application launch layout is invalid.")


def validate_bundle(
    bundle: Path, *, expected_team: str | None = None, artifact: DesktopArtifactIdentity | None = None,
) -> str:
    """Assess the canonical or privately copied app and return its trusted signing team."""
    if bundle.is_symlink() or bundle.resolve(strict=True) != bundle:
        raise MacUpdateError("The application bundle path is not canonical.")
    info = read_info(bundle)
    require_bootstrap(bundle, info)
    if artifact is not None:
        _require_build(bundle, info, artifact)
    team = expected_team or _signed_team(bundle)
    native_command("/usr/bin/codesign", "--verify", "--strict", "--deep", "--all-architectures", bundle)
    require_developer_id(bundle, team, BUNDLE_ID)
    for name in (*EXECUTABLES, *(f"{entry}{WORKER_SUFFIX}" for entry in EXECUTABLES)):
        executable = bundle / "Contents" / "MacOS" / name
        require_developer_id(executable, team)
        _signed_details(executable)
    _require_notarization(bundle)
    return team


def _require_build(bundle: Path, info: dict, artifact: DesktopArtifactIdentity) -> None:
    version = build_version_text(artifact.product_version)
    if info.get("CFBundleShortVersionString") != version:
        raise MacUpdateError("The application version does not match the signed update.")
    marker = bundle / "Contents" / "Resources" / "servonaut-runtime.json"
    try:
        with marker.open("rb") as stream:
            release = json.loads(stream.read(16385))
        if (
            release["product_version"] != version
            or release["packaging_revision"] != artifact.packaging_revision
            or type(release["packaging_revision"]) is not int
            or release["distribution"] != "packaged-desktop"
        ):
            raise ValueError("Unexpected runtime identity")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise MacUpdateError("The application revision does not match the signed update.") from exc
    for name in (*EXECUTABLES, *(f"{entry}{WORKER_SUFFIX}" for entry in EXECUTABLES)):
        executable = bundle / "Contents" / "MacOS" / name
        try:
            architectures = macho_architectures(executable)
        except (OSError, ValueError) as exc:
            raise MacUpdateError("The application architecture could not be verified.") from exc
        if architectures != {artifact.arch}:
            raise MacUpdateError("The application architecture does not match the signed update.")


def _quarantine_hex(path: Path) -> str | None:
    names = native_command("/usr/bin/xattr", path).splitlines()
    if _QUARANTINE not in names:
        return None
    return "".join(native_command("/usr/bin/xattr", "-px", _QUARANTINE, path).split())


def copy_bundle(source: Path, destination: Path, *, image: Path | None = None) -> None:
    """Keep resource forks, ACLs and extended attributes through staging."""
    if source.is_symlink() or not source.is_dir() or os.path.lexists(destination):
        raise MacUpdateError("The application cannot be copied into its staging directory.")
    quarantine = _quarantine_hex(source)
    if quarantine is None and image is not None:
        quarantine = _quarantine_hex(image)
    native_command("/usr/bin/ditto", "--rsrc", "--extattr", "--acl", "--qtn", source, destination, timeout=180)
    if quarantine is not None and _quarantine_hex(destination) != quarantine:
        native_command("/usr/bin/xattr", "-wx", _QUARANTINE, quarantine, destination)
        if _quarantine_hex(destination) != quarantine:
            raise MacUpdateError("The staging copy lost its quarantine information.")


def detach_application_image(mountpoint: Path) -> None:
    """Retry a private mount's detach before resorting to a forced detach."""
    if mountpoint.is_symlink():
        raise MacUpdateError("The application update mount path changed.")
    for delay in _DETACH_BACKOFF:
        if not mountpoint.is_mount():
            return
        try:
            native_command("/usr/bin/hdiutil", "detach", mountpoint)
        except MacUpdateError:
            pass
        if not mountpoint.is_mount():
            return
        time.sleep(delay)
    if mountpoint.is_mount():
        try:
            native_command("/usr/bin/hdiutil", "detach", "-force", mountpoint)
        except MacUpdateError:
            if mountpoint.is_mount():
                raise
    if mountpoint.is_mount():
        raise MacUpdateError("The application update disk image is still mounted.")


@contextmanager
def mounted_application(image: Path, mountpoint: Path) -> Iterator[Path]:
    """Mount a verified image read-only, with no Finder window or password prompt."""
    mountpoint.mkdir(mode=0o700)
    try:
        native_command(
            "/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen",
            "-mountpoint", mountpoint, image, timeout=90,
        )
        if not mountpoint.is_mount() or not os.statvfs(mountpoint).f_flag & os.ST_RDONLY:
            raise MacUpdateError("The disk image could not be mounted read-only.")
        yield mountpoint / BUNDLE_NAME
    finally:
        detach_application_image(mountpoint)
        mountpoint.rmdir()


@dataclass(frozen=True)
class Process:
    pid: int
    started: str
    executable: Path


def _uid_pids(library: ctypes.CDLL) -> list[int]:
    call = library.proc_listpids
    call.argtypes = (ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int)
    call.restype = ctypes.c_int
    uid = os.getuid()
    size = call(_PROC_UID_ONLY, uid, None, 0)
    if size < ctypes.sizeof(ctypes.c_int) or size > 1 << 20:
        raise MacUpdateError("The application could not check for active processes.")
    entries = (ctypes.c_int * (size // ctypes.sizeof(ctypes.c_int) + 128))()
    copied = call(_PROC_UID_ONLY, uid, entries, ctypes.sizeof(entries))
    if copied <= 0 or copied >= ctypes.sizeof(entries) or copied % ctypes.sizeof(ctypes.c_int):
        raise MacUpdateError("The application could not check for active processes.")
    return [pid for pid in entries[:copied // ctypes.sizeof(ctypes.c_int)] if pid > 0]


def bundle_processes(bundle: Path) -> tuple[Process, ...]:
    """Take a same-user snapshot while admission is exclusive."""
    library = ctypes.CDLL("libproc.dylib")
    pidpath = library.proc_pidpath
    pidpath.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
    pidpath.restype = ctypes.c_int
    matches = []
    try:
        for pid in _uid_pids(library):
            before = birth(pid)
            if before is None:
                continue
            buffer = ctypes.create_string_buffer(_PROC_PATH_SIZE)
            read = pidpath(pid, buffer, len(buffer))
            if birth(pid) != before:
                continue
            if read <= 0:
                raise MacUpdateError("A running process could not be identified.")
            executable = Path(os.fsdecode(buffer.value))
            if executable.is_relative_to(bundle) or executable.resolve().is_relative_to(bundle):
                matches.append(Process(pid, before, executable))
    except UnknownProcess as exc:
        raise MacUpdateError("A running process could not be identified.") from exc
    return tuple(matches)


def legacy_files_in_use(bundle: Path, *, shared: bool) -> bool:
    """Check open files and executable mappings left by pre-admission apps."""
    if shared:
        _require_observable_users()
    try:
        result = subprocess.run(
            ["/usr/sbin/lsof", "-nP", "-Fp", "+D", bundle],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=12, check=False,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise MacUpdateError("Servonaut could not check which processes are using this installation.") from exc
    lines = result.stdout.splitlines()
    if any(re.fullmatch(r"p[0-9]+", line) for line in lines):
        return True
    if result.returncode != 1 or lines or result.stderr.strip():
        raise MacUpdateError("Servonaut could not check which processes are using this installation.")
    return False


def _require_observable_users() -> None:
    """Defer if unprivileged file inspection may miss another login's legacy app."""
    import pwd

    list_uids = native_command("/bin/ps", "-axo", "uid=").split()
    if not list_uids or any(not entry.isascii() or not entry.isdecimal() for entry in list_uids):
        raise MacUpdateError("Servonaut could not check for other users of this installation.")
    for uid in {int(entry) for entry in list_uids} - {os.getuid(), 0}:
        try:
            shell = Path(pwd.getpwuid(uid).pw_shell).name
        except KeyError as exc:
            raise MacUpdateError("Servonaut could not check for other users of this installation.") from exc
        if shell not in {"nologin", "false", ""}:
            raise MacUpdateError("Another user has active processes. Open the disk image to install the update.")
