"""Local snapshot and preferences for the Updates panel."""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, Literal

from servonaut import get_version
from servonaut.utils.package_version import PackageVersion

if TYPE_CHECKING:
    from servonaut.runtime import RuntimeLayout

if os.name == "nt":
    import msvcrt
else:
    import fcntl

UpdateState = Literal[
    "up_to_date", "offered", "building", "ready", "failed", "rolled_back", "managed_elsewhere"
]
Channel = Literal["stable", "rc"]
UpdateCheckOutcome = Literal["queued", "busy", "skipped", "failed"]
ADMISSION_DEFAULT = 3.0
POSTPONE_LIMIT = 24 * 60 * 60
MARKER_NAME = ".servonaut-generation.json"
PIPX_METADATA = "pipx_metadata.json"
_GENERATION_ID = re.compile(r"[a-f0-9]{32}")


class UpdateBusy(OSError):
    """Another process is using the update state."""


class InvalidUpdateState(ValueError):
    """The local updater state cannot be used safely."""


def storage_for(root: Path) -> Path:
    key = hashlib.sha256(os.fsencode(os.path.normcase(str(root.resolve())))).hexdigest()
    return (Path.home() / ".servonaut" / "updates" / "installs" / key).resolve()


def acknowledgement_path(directory: Path, lease_id: object) -> Path | None:
    if isinstance(lease_id, str) and _GENERATION_ID.fullmatch(lease_id):
        return directory / "acks" / lease_id
    return None


def lease_acknowledged_at(directory: Path, lease: dict) -> float | None:
    if lease.get("started") is not False:
        timestamp = lease.get("launched_at", 0)
        return timestamp if type(timestamp) in (int, float) else 0
    marker = acknowledgement_path(directory, lease.get("id"))
    if marker is not None:
        try:
            info = marker.stat()
        except OSError:
            return None
        if stat.S_ISREG(info.st_mode):
            return info.st_mtime
    return None


def lease_acknowledged(directory: Path, lease: dict) -> bool:
    return lease_acknowledged_at(directory, lease) is not None


def locate_install(prefix: Path | None = None) -> tuple[Path, str | None] | None:
    """Return the pipx anchor and, inside a published copy, its generation ID."""
    if getattr(sys, "frozen", False):
        return None
    root = (prefix or Path(sys.prefix)).resolve()
    marker = root / MARKER_NAME
    if marker.is_file():
        try:
            record = read_json(marker)
            anchor, generation = Path(record["anchor"]), record["generation"]
            if (anchor.is_absolute() and isinstance(generation, str)
                    and _GENERATION_ID.fullmatch(generation)
                    and root == (storage_for(anchor) / "generations" / generation).resolve()):
                return anchor.resolve(), generation
        except (OSError, TypeError, ValueError, KeyError):
            pass
    if root.name == "servonaut" and (root / PIPX_METADATA).is_file():
        return root, None
    return None


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except FileNotFoundError:
        return {}
    except (UnicodeError, ValueError) as exc:
        raise InvalidUpdateState("Updater state could not be read") from exc
    if not isinstance(value, dict):
        raise InvalidUpdateState("Updater state is invalid")
    return value


def replace_bytes(path: Path, payload: bytes) -> None:
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        if hasattr(os, "O_DIRECTORY"):
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path: Path, value: dict[str, Any]) -> None:
    replace_bytes(path, (json.dumps(value, allow_nan=False) + "\n").encode())


def positive(value: object, default: float) -> float:
    if type(value) not in (float, int):
        return default
    try:
        number = float(value)
    except OverflowError:
        return default
    if math.isfinite(number) and number > 0:
        return number
    return default


def _set_lock(handle: BinaryIO, *, acquire: bool) -> None:
    if os.name == "nt":
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK if acquire else msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB if acquire else fcntl.LOCK_UN)


@contextmanager
def update_gate(directory: Path, timeout: float) -> Iterator[int]:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    limit = time.monotonic() + timeout
    descriptor = os.open(directory / "gate.lock", os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(descriptor, "r+b") as handle:
        while True:
            try:
                _set_lock(handle, acquire=True)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                    raise
                remaining = limit - time.monotonic()
                if remaining <= 0:
                    raise UpdateBusy("Update settings are busy. Try again shortly.") from None
                time.sleep(min(0.05, remaining))
        try:
            yield handle.fileno()
        finally:
            _set_lock(handle, acquire=False)


@dataclass(frozen=True)
class UpdateStatus:
    state: UpdateState
    installed_version: str
    install_kind: str
    channel: Channel
    target_version: str | None = None
    postponed_until: float | None = None
    can_postpone: bool = False
    old_sessions: tuple[str, ...] = ()
    required_minimum: str | None = None
    last_failure: str | None = None
    pinned_version: str | None = None
    pinned_until_newer_than: str | None = None


def public_version(value: object) -> PackageVersion | None:
    return PackageVersion.parse(value.partition("+")[0]) if isinstance(value, str) else None


def default_channel(version: str) -> Channel:
    parsed = public_version(version)
    return "rc" if parsed and parsed.is_prerelease else "stable"


def _minimum(policy: dict, version: str) -> str | None:
    current, floor = public_version(version), public_version(policy.get("minimum_version"))
    if policy.get("mode") == "enforce" and current is not None and floor is not None:
        return floor.text if current < floor else None
    return None


def _kind(runtime: RuntimeLayout | None) -> str:
    if runtime is None:
        from servonaut.runtime import detect_runtime

        runtime = detect_runtime()
    return runtime.kind.value


def _read_status(directory: Path, version: str) -> UpdateStatus:
    from servonaut.services.version_policy import VersionPolicyClient

    (
        state, prefs, leases,
    ) = (read_json(directory / name) for name in ("state.json", "preferences.json", "leases.json"))
    offer = state.get("offered")
    postponed = state.get("postponed", {}).get(offer)
    channel = prefs.get("channel", default_channel(version))
    comparison = public_version(offer or version)
    cached = VersionPolicyClient().cached()
    policy = ({"mode": cached.mode, "minimum_version": cached.minimum_version}
              if cached else state.get("policy", {}))
    roles = []
    for lease in leases.values():
        if not isinstance(lease, dict) or not lease_acknowledged(directory, lease):
            continue
        running = public_version(lease.get("version"))
        if comparison is not None and running is not None and running < comparison:
            roles.append(str(lease["role"]))
    pin = state.get("pin", {})
    return UpdateStatus(
        state.get("status", "up_to_date"), version, "pipx", channel,
        offer, postponed if postponed and postponed > time.time() else None,
        bool(offer and postponed is None), tuple(sorted(roles)),
        _minimum(policy, version), state.get("failure", {}).get("message"),
        pin.get("version"), pin.get("from"),
    )


def read_update_status(runtime: RuntimeLayout | None = None) -> UpdateStatus:
    """Read the last known status and session snapshot without an HTTP request."""
    version = runtime.product_version if runtime else get_version()
    try:
        layout = locate_install()
        if layout is None or os.environ.get("SERVONAUT_SKIP_AUTO_APPLY") == "1":
            return UpdateStatus("managed_elsewhere", version, _kind(runtime), default_channel(version))
        return _read_status(storage_for(layout[0]), version)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return UpdateStatus("failed", version, "pipx", "stable",
                            last_failure="Update status is unavailable.")


def set_update_channel(channel: Channel, runtime: RuntimeLayout | None = None) -> bool:
    layout = locate_install()
    if layout is None or channel not in ("stable", "rc"):
        return False
    directory = storage_for(layout[0])
    path = directory / "preferences.json"
    try:
        prefs = read_json(path)
        with update_gate(directory, positive(prefs.get("admission_timeout"), ADMISSION_DEFAULT)):
            prefs = read_json(path)
            if prefs.get("channel") == channel:
                return True
            write_json(path, {**prefs, "channel": channel})
            state = read_json(directory / "state.json")
            state["checked_at"] = 0
            write_json(directory / "state.json", state)
        return True
    except (OSError, ValueError):
        return False


def postpone_update(version: str, runtime: RuntimeLayout | None = None) -> bool:
    layout = locate_install()
    if layout is None or public_version(version) is None:
        return False
    directory = storage_for(layout[0])
    try:
        prefs = read_json(directory / "preferences.json")
        with update_gate(directory, positive(prefs.get("admission_timeout"), ADMISSION_DEFAULT)):
            state = read_json(directory / "state.json")
            history = state.setdefault("postponed", {})
            if state.get("offered") != version or version in history:
                return False
            seconds = min(positive(prefs.get("postpone_max_seconds"), POSTPONE_LIMIT), POSTPONE_LIMIT)
            history[version] = time.time() + seconds
            write_json(directory / "state.json", state)
        return True
    except (OSError, ValueError, TypeError):
        return False


def mark_update_presented(version: str) -> bool:
    """Record that an interactive UI displayed the offer for this version."""
    layout = locate_install()
    if layout is None or public_version(version) is None:
        return False
    directory = storage_for(layout[0])
    try:
        prefs = read_json(directory / "preferences.json")
        with update_gate(directory, positive(prefs.get("admission_timeout"), ADMISSION_DEFAULT)):
            state = read_json(directory / "state.json")
            if state.get("offered") != version:
                return False
            if "presented_at" not in state:
                state["presented_at"] = time.time()
                write_json(directory / "state.json", state)
        return True
    except (OSError, ValueError, TypeError):
        return False
