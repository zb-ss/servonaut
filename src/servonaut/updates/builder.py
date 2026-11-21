"""Background work for a pipx launch, isolated from all live generations."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from threading import Thread

from servonaut.updates.generations import clear_offer, directory_for, evacuate_unused, healthy
from servonaut.updates.index import (
    ManualUpdateRequired, PackageIndex, UpdateUnavailable, Wheel, pinned_wheel, public_version,
)
from servonaut.updates.layout import console_for, python_for
from servonaut.updates.processes import birth
from servonaut.updates.profile import PipxUnavailable, Profile, load_profile
from servonaut.updates.state import InstallState, Preferences, lease_is_live
from servonaut.updates.status import MARKER_NAME, UpdateBusy, UpdateCheckOutcome


def _creation(pid: int) -> str | None:
    try:
        return birth(pid)
    except OSError:
        return None


def _active(record: object) -> bool:
    return isinstance(record, dict) and lease_is_live(str(record.get("pid")), record)


def schedule(store: InstallState, state: dict, prefs: Preferences,
             version: str, *, force: bool = False,
             interpreter: Path | None = None) -> subprocess.Popen[bytes] | None:
    """Schedule at most one detached worker. The caller holds the short gate."""
    builder = state.get("builder", {})
    if builder and (_active(builder) or _active(builder.get("writer"))):
        return
    now = time.time()
    ready = state.get("generations", {}).get(state.get("ready"), {})
    checked_at = state.get("checked_at", 0)
    verified_at = ready.get("verified_at", 0)
    stale = ready and not 0 <= now - verified_at <= prefs.validation_max_age_seconds
    first_refresh = stale and checked_at <= verified_at
    if builder:
        state.pop("builder")
        state["status"] = "failed"
        state.setdefault("failure", {}).setdefault("message", "The previous update build stopped unexpectedly.")
    recent = now - checked_at < prefs.check_interval_seconds
    same_launcher = state.get("launcher_version") == version
    failure = state.get("failure", {})
    check_failure = state.get("check_failure", {})
    if not force and same_launcher and now < max(failure.get("retry_at", 0), check_failure.get("retry_at", 0)):
        return
    if recent and not (force or first_refresh or not same_launcher):
        return
    token = secrets.token_hex(16)
    flags = ({"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
             if os.name == "nt" else {"start_new_session": True})
    descriptor = os.open(store.directory / "builder.log", os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as log:
        child = subprocess.Popen(
            [str(interpreter or sys.executable), "-m", "servonaut.updates.builder",
             str(store.root), token, version],
            cwd=store.directory, stdin=subprocess.DEVNULL, stdout=log, stderr=log, **flags,
        )
    state["builder"] = {"pid": child.pid, "birth": _creation(child.pid), "token": token}
    state["launcher_version"] = version
    state["checked_at"] = now
    return child


def queue_update_check(store: InstallState, installed_version: str) -> UpdateCheckOutcome:
    """Queue one manually requested check using the pipx launcher environment."""
    if os.environ.get("SERVONAUT_SKIP_AUTO_APPLY") == "1":
        return "skipped"
    try:
        with store.gate(timeout=0):
            state = store.recover_state()
            version = state.get("last_launcher_version") or state.get("launcher_version") or installed_version
            child = schedule(store, state, store.preferences(), version,
                             force=True, interpreter=python_for(store.root))
            if child is None:
                return "busy"
            try:
                store.save_state(state)
            finally:
                Thread(target=child.wait, daemon=True, name="servonaut-update-reaper").start()
    except UpdateBusy:
        return "busy"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        return "failed"
    return "queued"


def _target(index: PackageIndex, document: dict, current: dict, profile: Profile,
            launcher_version: str, prefs: Preferences, pin: dict) -> str | None:
    installed = current.get("version", launcher_version)
    target = index.target(document, installed, prefs.channel)
    if pin:
        return index.target(document, pin["from"], prefs.channel)
    floor, launcher = public_version(installed), public_version(launcher_version)
    retained_target = None
    if floor is not None and launcher is not None and (not launcher.is_prerelease or prefs.channel == "rc"):
        if (not current or launcher > floor) and index.wheel(document, launcher_version):
            retained_target = launcher_version
        elif current.get("profile") != profile.fingerprint and index.wheel(document, installed):
            retained_target = installed
    if target and retained_target and public_version(retained_target) > public_version(target):
        return retained_target
    return target or retained_target


def _retire(store: InstallState, state: dict, prefs: Preferences) -> list[Path]:
    paths = evacuate_unused(store, state, prefs)
    store.save_state(state)
    return paths


def _remove_retired(store: InstallState, paths: list[Path]) -> None:
    for path in {*paths, *(store.directory / "generations").glob(".retired-*")}:
        if path.is_dir():
            try:
                shutil.rmtree(path)
            except OSError:
                # Windows may still have a file handle open. Retry at the next check.
                continue


def _run_command(store: InstallState, args: list[str], timeout: float, env: dict | None = None) -> None:
    """Record the writer so a killed builder cannot cause its files to be reaped early."""
    with store.gate():
        state = store.read("state.json")
        process = subprocess.Popen(args, cwd=store.directory, env=env, stdin=subprocess.DEVNULL)
        state["builder"]["writer"] = {"pid": process.pid, "birth": _creation(process.pid)}
        store.write("state.json", state)
    try:
        if process.wait(timeout=timeout) != 0:
            raise UpdateUnavailable("The update build command failed.")
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise UpdateUnavailable("The update build timed out.") from exc


def _remaining(deadline: float, maximum: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise UpdateUnavailable("The update build timed out.")
    return min(remaining, maximum)


def _build(store: InstallState, path: Path, identifier: str, target: str, wheel: Wheel,
           profile: Profile, index: PackageIndex, prefs: Preferences, deadline: float) -> None:
    if shutil.disk_usage(store.directory).free < prefs.minimum_free_bytes:
        raise UpdateUnavailable("There is not enough disk space to prepare this update.")
    path.parent.mkdir(mode=0o700, exist_ok=True)
    _run_command(
        store, [profile.interpreter, "-m", "venv", "--copies", "--without-pip", str(path)],
        _remaining(deadline, prefs.upgrade_timeout),
    )
    python = str(python_for(path))
    _run_command(store, [python, "-m", "ensurepip", "--upgrade"],
                 _remaining(deadline, prefs.upgrade_timeout))
    with pinned_wheel(index, target, wheel, path,
                      lambda: _remaining(deadline, prefs.discovery_timeout)) as (url, environment):
        _run_command(
            store, [python, "-m", "pip", "install", "--only-binary=:all:",
                    f"{profile.requirement} @ {url}", *profile.injections],
            _remaining(deadline, prefs.upgrade_timeout), environment,
        )
    store.replace(
        path / MARKER_NAME,
        (json.dumps({"anchor": str(store.root), "generation": identifier}) + "\n").encode(),
    )
    _probe(store, path, target, min(deadline, time.monotonic() + prefs.health_timeout))


def _probe(store: InstallState, path: Path, target: str, deadline: float) -> None:
    commands = (
        [str(python_for(path)), "-c", "import servonaut.app, servonaut.mcp.server"],
        [str(console_for(path)), "--version"],
    )
    for command in commands:
        result = subprocess.run(
            command, cwd=store.directory, stdin=subprocess.DEVNULL, capture_output=True,
            text=True, timeout=_remaining(deadline, float("inf")),
        )
        if result.returncode:
            raise UpdateUnavailable("The new copy did not pass its startup check.")
    if result.stdout.strip() != f"servonaut {target}":
        raise UpdateUnavailable("The new copy did not pass its startup check.")


def _refresh_policy(launcher_version: str, prefs: Preferences) -> None:
    from servonaut.services.client_identity import configure_client_identity
    from servonaut.services.version_policy import VersionPolicyClient

    configure_client_identity(kind="cli", version=launcher_version, channel=prefs.channel)
    asyncio.run(VersionPolicyClient(timeout=prefs.discovery_timeout).fetch())


def _record_offer(state: dict, target: str) -> None:
    if state.get("offered") != target or "offered_at" not in state:
        clear_offer(state)
        state.update(offered=target, offered_at=time.time())


def _failed(store: InstallState, token: str, target: str | None, error: Exception) -> None:
    with store.gate():
        state = store.read("state.json")
        owner = state.get("builder", {})
        if owner.get("token") != token:
            return
        record = state.get("generations", {}).get(owner.get("generation"))
        if record is not None:
            record["health"] = "failed"
        prefs = store.preferences()
        manual = isinstance(error, ManualUpdateRequired)
        missing_pipx = isinstance(error, PipxUnavailable)
        checking = target is None
        history = "check_failure" if checking else "failure"
        previous = state.get(history, {})
        attempts = min(20, previous.get("attempts", 0) + 1) if previous.get("version") == target else 1
        cap = prefs.check_retry_max_seconds if checking else prefs.retry_max_seconds
        failure = {"version": target, "attempts": attempts, "retry_at": time.time() + min(
            cap, prefs.retry_base_seconds * 2 ** (attempts - 1),
        )}
        if missing_pipx:
            state["check_failure"] = failure
        else:
            message = str(error) if isinstance(error, UpdateUnavailable) else (
                "The update build failed." if target else "Could not check for updates. Try again later."
            )
            state.update(status="managed_elsewhere" if manual else "failed",
                         failure={**failure, "message": message})
            if checking:
                state["check_failure"] = failure
        state.pop("builder")
        retired = _retire(store, state, prefs)
    _remove_retired(store, retired)


def _stage(store: InstallState, token: str, launcher_version: str) -> None:
    prefs = store.preferences()
    index = PackageIndex()
    recorded = store.load_state().get("pipx_command")
    profile = load_profile(store.root, prefs.discovery_timeout, recorded)
    _refresh_policy(launcher_version, prefs)
    document = index.document(prefs.discovery_timeout)
    identifier = None
    target = None
    with store.gate():
        state = store.read("state.json")
        if state.get("builder", {}).get("token") != token:
            return
        old_check = state.pop("check_failure", None)
        if old_check and state.get("failure", {}).get("version") is None:
            state.pop("failure", None)
        if profile.pipx_command:
            state["pipx_command"] = list(profile.pipx_command)
        records = state.setdefault("generations", {})
        current = records.get(state.get("current"), {})
        target = _target(index, document, current, profile, launcher_version, prefs, state.get("pin", {}))
        announce = target is not None and target not in (launcher_version, current.get("version"))
        previous_offer = state.get("offered")
        ready = state.get("ready")
        candidate = records.get(ready, {})
        wheel = index.wheel(document, target) if target else None
        if (wheel is not None and healthy(store, state, ready) and candidate.get("version") == target
                and candidate.get("digest") == wheel.digest and candidate.get("profile") == profile.fingerprint):
            candidate["verified_at"] = time.time()
            if announce:
                _record_offer(state, target)
            else:
                clear_offer(state)
            state["status"] = "ready" if announce else "up_to_date"
            state.pop("failure", None)
        elif wheel is None:
            if previous_offer and previous_offer != current.get("version"):
                state["failure"] = {"version": previous_offer, "message": "The offered update is unavailable."}
                state["status"] = "failed"
            else:
                state["status"] = "up_to_date"
            state.pop("ready", None)
            clear_offer(state)
        elif state.get("failure", {}).get("version") == target and time.time() < state["failure"].get("retry_at", 0):
            state.pop("ready", None)
        else:
            state.pop("ready", None)
            identifier = secrets.token_hex(16)
            if announce:
                _record_offer(state, target)
            else:
                clear_offer(state)
            state["status"] = "building" if announce else "up_to_date"
            state["builder"]["generation"] = identifier
            records[identifier] = {
                "version": target, "profile": profile.fingerprint, "health": "building",
                "digest": wheel.digest, "created_at": time.time(),
            }
        if identifier is None:
            state.pop("builder")
        retired = _retire(store, state, prefs)
    _remove_retired(store, retired)
    if identifier is None or target is None or wheel is None:
        return
    try:
        deadline = time.monotonic() + prefs.build_timeout
        _build(store, directory_for(store, identifier), identifier, target, wheel,
               profile, index, prefs, deadline)
        if index.wheel(index.document(_remaining(deadline, prefs.discovery_timeout)), target) != wheel:
            raise UpdateUnavailable("The staged update was withdrawn.")
    except Exception as error:
        _failed(store, token, target, error)
        return
    with store.gate():
        state = store.read("state.json")
        if state.get("builder", {}).get("token") != token:
            return
        record = state["generations"][identifier]
        record.update(health="healthy", verified_at=time.time())
        state.update(ready=identifier, status="ready" if announce else "up_to_date")
        state.pop("failure", None)
        state.pop("builder")
        store.save_state(state)


def _claim(store: InstallState, token: str) -> bool:
    with store.gate():
        state = store.load_state()
        owner = state.get("builder", {})
        if owner.get("token") != token:
            return False
        owner.update(pid=os.getpid(), birth=_creation(os.getpid()))
        store.write("state.json", state)
        return True


def main() -> None:
    anchor, token, launcher_version = sys.argv[1:]
    store = InstallState(Path(anchor))
    try:
        if _claim(store, token):
            _stage(store, token, launcher_version)
    except Exception as error:
        _failed(store, token, None, error)


if __name__ == "__main__":
    main()
