"""Update engine configuration and process leases."""

from __future__ import annotations

import math
import os
import secrets
import time
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

from servonaut import get_version
from servonaut.updates.processes import birth, boot_identity
from servonaut.updates.status import (
    ADMISSION_DEFAULT, POSTPONE_LIMIT, STATUS_POLL_SECONDS, InvalidUpdateState, acknowledgement_path,
    default_channel, lease_acknowledged_at, positive, read_json, replace_bytes,
    storage_for, update_gate, write_json,
)


@dataclass(frozen=True)
class Preferences:
    channel: str = "stable"
    discovery_timeout: float = 5.0
    admission_timeout: float = ADMISSION_DEFAULT
    health_timeout: float = 10.0
    upgrade_timeout: float = 180.0
    retry_base_seconds: float = 900.0
    retry_max_seconds: float = 86400.0
    check_retry_max_seconds: float = 3600.0
    postpone_max_seconds: float = POSTPONE_LIMIT
    retain_healthy: int = 2
    # A standard environment uses about 110 MiB. Leave room for the next
    # environment and transient wheel/dependency downloads.
    minimum_free_bytes: int = 256 * 1024 * 1024
    check_interval_seconds: float = 30 * 60.0
    validation_max_age_seconds: float = 5 * 60.0
    launch_validation_timeout: float = 2.0
    tui_refresh_interval_seconds: float = 3600.0
    crash_loop_count: int = 3
    startup_attempt_window_seconds: float = 10 * 60.0
    lease_quarantine_max_seconds: float = 7 * 24 * 3600.0
    build_timeout: float = 300.0
    status_poll_seconds: float = STATUS_POLL_SECONDS

    @classmethod
    def parse(cls, data: dict[str, Any], version: str = "") -> Preferences:
        defaults = cls(channel=default_channel(version))
        values = asdict(defaults)
        if data.get("channel") in ("stable", "rc"):
            values["channel"] = data["channel"]
        for field in fields(defaults):
            if field.name != "channel":
                default = values[field.name]
                values[field.name] = type(default)(positive(data.get(field.name), default))
        values["retain_healthy"] = max(2, values["retain_healthy"])
        values["crash_loop_count"] = max(1, values["crash_loop_count"])
        values["postpone_max_seconds"] = min(POSTPONE_LIMIT, values["postpone_max_seconds"])
        if not 60 <= values["check_retry_max_seconds"] <= 24 * 3600:
            values["check_retry_max_seconds"] = defaults.check_retry_max_seconds
        return cls(**values)


class InstallState:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.directory = storage_for(self.root)

    def read(self, name: str) -> dict[str, Any]:
        return read_json(self.directory / name)

    def write(self, name: str, value: dict[str, Any]) -> None:
        write_json(self.directory / name, value)

    replace = staticmethod(replace_bytes)

    def preferences(self) -> Preferences:
        try:
            return Preferences.parse(self.read("preferences.json"), get_version())
        except InvalidUpdateState:
            return Preferences(channel=default_channel(get_version()))

    def load_state(self, *, maximum_bytes: int | None = None) -> dict[str, Any]:
        state = (
            self.read("state.json") if maximum_bytes is None
            else read_json(self.directory / "state.json", maximum_bytes=maximum_bytes)
        )
        _validate_state(state)
        return state

    def recover_state(self) -> dict[str, Any]:
        """Repair an invalid journal while holding the admission gate."""
        try:
            state = self.load_state()
        except InvalidUpdateState:
            state = self.recovery()
            self._quarantine("state.json")
            state["unknown_leases"] = self._quarantine_record()
        try:
            self.live_leases()
        except InvalidUpdateState:
            self._quarantine("leases.json")
            state["unknown_leases"] = self._quarantine_record()
        return state

    @staticmethod
    def _quarantine_record() -> dict:
        return {"since": time.time(), "boot": boot_identity()}

    def gc_paused(self, state: dict, prefs: Preferences) -> bool:
        record = state.get("unknown_leases")
        if not record:
            return False
        if not isinstance(record, dict) or not _number(record.get("since")):
            record = state["unknown_leases"] = self._quarantine_record()
        boot = boot_identity()
        since = record.get("since", 0)
        rebooted = boot and record.get("boot") and boot != record["boot"]
        if rebooted or (_number(since) and time.time() - since >= prefs.lease_quarantine_max_seconds):
            state.pop("unknown_leases", None)
            return False
        return True

    def _quarantine(self, name: str) -> None:
        path = self.directory / name
        path.replace(path.with_name(f"{name}.corrupt-{time.time_ns()}"))

    def recovery(self) -> dict[str, Any]:
        try:
            state = self.read("routing.json")
            _validate_state(state)
            if state:
                return state
        except InvalidUpdateState:
            pass
        try:
            return _routing_snapshot(self.read("state.json"))
        except InvalidUpdateState:
            return {}

    def save_state(self, state: dict[str, Any]) -> None:
        self.write("state.json", state)
        if "current" not in state and "previous" not in state:
            return
        snapshot = _routing_snapshot(state)
        try:
            saved = self.read("routing.json")
        except InvalidUpdateState:
            saved = {}
        if snapshot != saved:
            self.write("routing.json", snapshot)

    def gate(self, *, timeout: float | None = None):
        return update_gate(self.directory, self.preferences().admission_timeout if timeout is None else timeout)

    def _leases(self) -> dict[str, Any]:
        leases = self.read("leases.json")
        if any(not key.isdecimal() or not isinstance(record, dict)
               or record.get("generation") is not None and not isinstance(record["generation"], str)
               or "id" in record and acknowledgement_path(self.directory, record["id"]) is None
               or "started" in record and type(record["started"]) is not bool
               or not _number(record.get("launched_at", 0))
               for key, record in leases.items()):
            raise InvalidUpdateState("Invalid updater leases")
        return leases

    def live_leases(self) -> dict[str, Any]:
        return {key: value for key, value in self._leases().items() if lease_is_live(key, value)}

    def launch_leases(self, window: float) -> dict[str, Any]:
        """Keep recent, unacknowledged starts even after their owners have exited."""
        rows = self._leases()
        # For an exited process, the marker is stable after the identity check.
        observed = [(pid, record, lease_is_live(pid, record), self.acknowledged_at(record))
                    for pid, record in rows.items()]
        now = time.time()
        latest_ack: dict[str | None, float] = {}
        for _pid, record, _live, acknowledged_at in observed:
            if acknowledged_at is not None and 0 <= now - acknowledged_at <= window:
                generation = record.get("generation")
                latest_ack[generation] = max(latest_ack.get(generation, 0), acknowledged_at)
        retained = {}
        for pid, record, live, acknowledged_at in observed:
            started = record.get("launched_at", 0)
            superseded = (record.get("superseded", False)
                          or started < latest_ack.get(record.get("generation"), 0))
            if live:
                retained[pid] = {**record, "superseded": True} if superseded else record
            elif (not superseded and acknowledged_at is None and 0 <= now - started <= window):
                retained[pid] = record
        return retained

    def register(self, role: str, leases: dict[str, Any],
                 generation: str, version: str) -> str:
        try:
            identity = birth(os.getpid())
        except OSError:
            identity = None
        lease_id = secrets.token_hex(16)
        leases[str(os.getpid())] = {
            "birth": identity, "role": role, "generation": generation, "version": version,
            "id": lease_id, "started": False, "launched_at": time.time(),
        }
        self.write_leases(leases)
        return lease_id

    def acknowledged(self, record: dict) -> bool:
        return self.acknowledged_at(record) is not None

    def acknowledged_at(self, record: dict) -> float | None:
        return lease_acknowledged_at(self.directory, record)

    def acknowledge(self, lease_id: str) -> None:
        """Publish startup success without waiting on the shared gate."""
        marker = acknowledgement_path(self.directory, lease_id)
        if marker is None:
            return
        marker.parent.mkdir(mode=0o700, exist_ok=True)
        try:
            descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return
        os.close(descriptor)

    def write_leases(self, leases: dict[str, Any]) -> None:
        previous = self._leases()
        if leases == previous:
            return
        retained = {record.get("id") for record in leases.values()}
        self.write("leases.json", leases)
        for record in previous.values():
            lease_id = record.get("id")
            if lease_id not in retained:
                marker = acknowledgement_path(self.directory, lease_id)
                if marker is not None:
                    try:
                        marker.unlink(missing_ok=True)
                    except OSError:
                        pass

    def discard_lease(self, lease_id: str, *, acknowledged_only: bool = False) -> None:
        if not lease_id:
            return
        leases = self.launch_leases(self.preferences().startup_attempt_window_seconds)
        for pid, record in tuple(leases.items()):
            if record.get("id") == lease_id and (not acknowledged_only or self.acknowledged(record)):
                leases.pop(pid)
        self.write_leases(leases)

    def unregister(self, lease_id: str, *, acknowledged_only: bool = False) -> None:
        if lease_id:
            with self.gate(timeout=1):
                self.discard_lease(lease_id, acknowledged_only=acknowledged_only)


def lease_is_live(key: str, entry: Any) -> bool:
    """Keep entries if the current owner cannot be safely ruled out."""
    try:
        actual = birth(int(key))
    except (OSError, ValueError):
        return True
    if actual is None:
        return False
    previous = entry.get("birth") if isinstance(entry, dict) else None
    return not previous or actual == previous


def _number(value: object) -> bool:
    return ((type(value) is int and value.bit_length() < 1024)
            or (type(value) is float and math.isfinite(value)))


def _routing_snapshot(state: dict[str, Any]) -> dict[str, Any]:
    records = state.get("generations", {})
    if not isinstance(records, dict):
        return {}
    snapshot: dict[str, Any] = {"generations": {}}
    for key in ("current", "previous"):
        identifier = state.get(key)
        row = records.get(identifier) if isinstance(identifier, str) else None
        if isinstance(row, dict) and isinstance(row.get("version"), str):
            snapshot[key] = identifier
            snapshot["generations"][identifier] = {
                key: row[key] for key in ("version", "health", "profile") if key in row
            }
    for key, kind in (("pin", dict), ("last_launcher_version", str), ("last_pipx_request", str)):
        if isinstance(state.get(key), kind):
            snapshot[key] = state[key]
    return snapshot


def _validate_state(state: dict[str, Any]) -> None:
    dictionaries = ("generations", "builder", "postponed", "failure", "pin", "check_failure")
    numbers = ("offered_at", "presented_at", "checked_at")
    if any(not isinstance(state.get(key, {}), dict) for key in dictionaries):
        raise InvalidUpdateState("Invalid updater journal mapping")
    if any(not _number(state.get(key, 0)) for key in numbers):
        raise InvalidUpdateState("Invalid updater timestamp")
    if any(state.get(key) is not None and not isinstance(state[key], str)
           for key in ("current", "previous", "ready", "offered", "last_launcher_version",
                       "launcher_version", "last_pipx_request")):
        raise InvalidUpdateState("Invalid updater pointer")
    for record in state.get("generations", {}).values():
        if (not isinstance(record, dict) or not isinstance(record.get("version"), str)
                or not all(_number(record.get(key, 0)) for key in (
                    "verified_at", "created_at", "last_validation_attempt_at",
                ))):
            raise InvalidUpdateState("Invalid updater generation")
    if any(not _number(value) for value in state.get("postponed", {}).values()):
        raise InvalidUpdateState("Invalid updater postponement")
    if any(not _number(state.get(name, {}).get(key, 0))
           for name in ("failure", "check_failure") for key in ("retry_at", "attempts")):
        raise InvalidUpdateState("Invalid updater backoff")
    pin = state.get("pin", {})
    if pin and not all(isinstance(pin.get(key), str) for key in ("version", "from")):
        raise InvalidUpdateState("Invalid updater version pin")
