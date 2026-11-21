"""Admission, recovery and staged-release checks used by the stdlib entry point."""

from __future__ import annotations

import errno
import os
import time
from queue import SimpleQueue
from threading import Thread

from servonaut.updates.builder import schedule
from servonaut.updates.generations import (
    clear_offer, demote_generation, eligible_generation, healthy, select_generation,
)
from servonaut.updates.index import PackageIndex
from servonaut.updates.profile import exact_pipx_request
from servonaut.updates.state import InstallState, Preferences, lease_is_live
from servonaut.updates.status import public_version

_PERSISTENT_EXEC_ERRORS = {errno.ENOENT, errno.EACCES, errno.ENOEXEC, errno.ELOOP, errno.ENOTDIR}


def log_error(store: InstallState, error: Exception) -> None:
    """Record the failure class without paths, network contents or console output."""
    try:
        path = store.directory / "launcher.log"
        flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND
        with os.fdopen(os.open(path, flags, 0o600), "a", encoding="utf-8") as log:
            log.write(f"{time.time():.0f} updater launch: {type(error).__name__}\n")
    except OSError:
        pass


def _routes(store: InstallState, state: dict, first: str | None, version: str) -> list[str]:
    active = state.get("generations", {}).get(first, {})
    launcher, running = public_version(version), public_version(active.get("version"))
    if state.get("pin") or (launcher and running and launcher > running):
        return []
    return [identifier for identifier in (first, state.get("previous"))
            if healthy(store, state, identifier)]


def fallback_routes(store: InstallState, version: str) -> list[str]:
    """Resolve the current and previous healthy copies without making writes."""
    for read in (store.load_state, store.recovery):
        try:
            state = read()
            if state:
                _observe_launcher(store, state, version)
                return _routes(store, state, state.get("current"), version)
        except Exception:
            continue
    return []


def _observe_launcher(store: InstallState, state: dict, version: str) -> None:
    prior = state.get("last_launcher_version", state.get("launcher_version"))
    state["last_launcher_version"] = version
    launcher, previous = public_version(version), public_version(prior)
    if launcher is None:
        return
    records = state.get("generations", {})
    running = public_version(records.get(state.get("current"), {}).get("version"))
    request = exact_pipx_request(store.root)
    prior_request = state.get("last_pipx_request")
    token = f"{request[1]}:{version}" if request is not None and request[0] == launcher else None
    exact = token is not None and token != prior_request
    if token is None:
        state.pop("last_pipx_request", None)
    else:
        state["last_pipx_request"] = token
    decreased = previous is not None and launcher < previous
    if decreased or (exact and (running is None or launcher < running)):
        staged = public_version(records.get(state.get("ready"), {}).get("version"))
        existing = public_version(state.get("pin", {}).get("from"))
        floor = running or previous or staged or launcher
        if running is None:
            floor = max(item for item in (previous, staged, existing, launcher) if item is not None)
        elif decreased:
            floor = max(item for item in (running, previous, existing) if item is not None)
        pin = {"version": version, "from": floor.text}
        if state.get("pin") != pin:
            state["pin"] = pin
            offer = public_version(state.get("offered"))
            if offer is not None and offer <= floor:
                clear_offer(state)
    elif prior is not None and version != prior:
        state.pop("pin", None)


def _pending(state: dict) -> tuple[str, str, str, float] | None:
    identifier = state.get("ready")
    row = state.get("generations", {}).get(identifier, {})
    digest = row.get("digest")
    if identifier and digest:
        return identifier, row["version"], digest, row.get("verified_at", 0)
    return None


def _reserve_validation(store: InstallState, state: dict, prefs: Preferences,
                        version: str) -> tuple[str, str, str, float] | None:
    if not eligible_generation(store, state, prefs, version):
        return None
    candidate = _pending(state)
    if candidate is None:
        return None
    ready = state["generations"][candidate[0]]
    now = time.time()
    if any(0 <= now - timestamp < prefs.validation_max_age_seconds for timestamp in (
        candidate[3], ready.get("last_validation_attempt_at", 0),
    )):
        return None
    ready["last_validation_attempt_at"] = now
    return candidate


def _verify(version: str, digest: str, timeout: float) -> bool | None:
    """Run one exact candidate check with a wall-clock caller deadline."""
    result: SimpleQueue[bool | None] = SimpleQueue()

    def request() -> None:
        try:
            index = PackageIndex()
            wheel = index.wheel(index.document(timeout), version)
            result.put(wheel is not None and wheel.digest == digest)
        except Exception:  # A check failure defers admission and leaves readiness intact.
            result.put(None)

    worker = Thread(target=request, daemon=True, name="servonaut-validate-update")
    worker.start()
    worker.join(timeout)
    return None if worker.is_alive() else result.get_nowait()


def _apply_validation(state: dict, candidate: tuple | None, valid: bool | None) -> None:
    if candidate is None or valid is None:
        return
    identifier, version, digest, verified = candidate
    record = state.get("generations", {}).get(identifier, {})
    if (state.get("ready") != identifier or record.get("digest") != digest
            or record.get("verified_at") != verified):
        return
    if valid:
        record["verified_at"] = time.time()
    else:
        state.pop("ready", None)
        clear_offer(state)
        state.update(status="failed", failure={
            "version": version, "message": "The offered update is unavailable.",
        })


def refresh_ready(store: InstallState) -> None:
    """Refresh the pending file from a running TUI worker."""
    if os.environ.get("SERVONAUT_SKIP_AUTO_APPLY") == "1":
        return
    try:
        prefs = store.preferences()
        candidate = _pending(store.load_state())
        if candidate:
            valid = _verify(candidate[1], candidate[2], prefs.launch_validation_timeout)
            if valid is False:
                with store.gate():
                    state = store.load_state()
                    _apply_validation(state, candidate, valid)
                    store.save_state(state)
    except Exception as error:
        log_error(store, error)


def admit(store: InstallState, role: str, version: str):
    """Reserve at most one check under the gate, then verify outside it."""
    prefs = store.preferences()
    deadline = time.monotonic() + prefs.admission_timeout
    with store.gate(timeout=prefs.admission_timeout):
        state = store.recover_state()
        _observe_launcher(store, state, version)
        candidate = _reserve_validation(store, state, prefs, version)
        if candidate is None:
            return _admit(store, state, prefs, role, version)
        store.save_state(state)

    started = time.monotonic()
    valid = _verify(candidate[1], candidate[2], prefs.launch_validation_timeout)
    deadline += time.monotonic() - started
    with store.gate(timeout=max(0, deadline - time.monotonic())):
        state = store.recover_state()
        _observe_launcher(store, state, version)
        _apply_validation(state, candidate, valid)
        return _admit(store, state, prefs, role, version)


def _admit(store: InstallState, state: dict, prefs: Preferences, role: str, version: str):
    selected = select_generation(store, state, prefs, activate=True, launcher_version=version)
    routes = _routes(store, state, selected, version)
    leases = store.launch_leases(prefs.startup_attempt_window_seconds)
    if routes:
        routes = _guard_startup(store, state, routes, leases, prefs)
    worker = schedule(store, state, prefs, version)
    lease_id = ""
    try:
        store.save_state(state)
        if routes:
            record = state["generations"][routes[0]]
            lease_id = store.register(role, leases, routes[0], record["version"])
    except Exception:
        if worker is not None:
            Thread(target=worker.wait, daemon=True).start()
        raise
    return routes, worker, lease_id


def _guard_startup(store: InstallState, state: dict, routes: list[str],
                   leases: dict, prefs: Preferences) -> list[str]:
    target = routes[0]
    launches = [(record, lease_is_live(pid, record), store.acknowledged_at(record))
                for pid, record in leases.items() if record.get("generation") == target]
    if any(live and acknowledged_at is not None for _, live, acknowledged_at in launches):
        return routes
    now = time.time()
    latest_ack = max((at for _, _, at in launches
                      if at is not None and 0 <= now - at <= prefs.startup_attempt_window_seconds),
                     default=0)
    failures = sum(
        not live and at is None and not record.get("superseded")
        and record.get("launched_at", 0) >= latest_ack
        for record, live, at in launches
    )
    if failures < max(1, prefs.crash_loop_count - 1):
        return routes
    demote_generation(store, state, target)
    state["failure"] = {"message": "The active copy repeatedly failed to start."}
    return routes[1:]


def route_failed(store: InstallState, generation: str, error: Exception, lease_id: str,
                 fallback: str | None, role: str) -> str:
    log_error(store, error)
    try:
        with store.gate(timeout=0):
            state = store.load_state()
            store.discard_lease(lease_id)
            if isinstance(error, OSError) and error.errno in _PERSISTENT_EXEC_ERRORS:
                demote_generation(store, state, generation)
                store.save_state(state)
            if fallback and healthy(store, state, fallback):
                prefs = store.preferences()
                leases = store.launch_leases(prefs.startup_attempt_window_seconds)
                return store.register(role, leases, fallback, state["generations"][fallback]["version"])
    except Exception as failure:
        log_error(store, failure)
    return ""
