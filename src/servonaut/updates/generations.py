"""Select healthy generations and keep live sessions pinned to their venv."""

from __future__ import annotations

import os
import time
from pathlib import Path

from servonaut.updates.index import public_version
from servonaut.updates.layout import generation_id, python_for
from servonaut.updates.state import InstallState, Preferences
from servonaut.updates.status import locate_install


def directory_for(store: InstallState, identifier: str) -> Path:
    if not generation_id(identifier):
        raise ValueError("Invalid update generation")
    return store.directory / "generations" / identifier


def healthy(store: InstallState, state: dict, identifier: object) -> bool:
    if not generation_id(identifier):
        return False
    record = state.get("generations", {}).get(identifier, {})
    if record.get("health") != "healthy":
        return False
    directory = directory_for(store, identifier)
    python = python_for(directory)
    return (python.is_file() and os.access(python, os.X_OK)
            and locate_install(directory) == (store.root, identifier))


def _ready_allowed(state: dict, identifier: str, prefs: Preferences,
                   launcher_version: str) -> bool:
    record = state["generations"][identifier]
    version = public_version(record.get("version"))
    if version is None or (version.is_prerelease and prefs.channel != "rc"):
        return False
    launcher = public_version(launcher_version)
    pinned_from = public_version(state.get("pin", {}).get("from"))
    if pinned_from is not None and version <= pinned_from:
        return False
    if launcher is not None and version < launcher:
        return False
    now = time.time()
    # Initial enrollment and a user's manual pipx upgrade are explicit choices.
    if version == launcher:
        return True
    active = state["generations"].get(state.get("current"), {})
    if record["version"] == active.get("version"):
        return True
    if state.get("postponed", {}).get(record["version"], 0) > now:
        return False
    if state.get("offered") != record["version"]:
        return False
    offered_at = state.get("offered_at", now)
    presented_at = state.get("presented_at", 0)
    return (0 < offered_at <= presented_at <= now
            or now - offered_at >= prefs.postpone_max_seconds)


def clear_offer(state: dict) -> None:
    for key in ("offered", "offered_at", "presented_at"):
        state.pop(key, None)


def eligible_generation(store: InstallState, state: dict, prefs: Preferences,
                        launcher_version: str) -> str | None:
    ready = state.get("ready")
    if healthy(store, state, ready) and _ready_allowed(state, ready, prefs, launcher_version):
        return ready
    return None


def select_generation(store: InstallState, state: dict, prefs: Preferences,
                      *, activate: bool, launcher_version: str) -> str | None:
    """Choose and, when appropriate, atomically change the current pointer."""
    current = state.get("current")
    if current and not healthy(store, state, current):
        current = demote_generation(store, state, current)
    ready = eligible_generation(store, state, prefs, launcher_version) if activate else None
    if ready and 0 <= time.time() - state["generations"][ready].get(
        "verified_at", 0,
    ) <= prefs.validation_max_age_seconds:
        state.update(current=ready, previous=current, status="up_to_date")
        state.pop("ready", None)
        clear_offer(state)
        state.pop("failure", None)
        state.pop("pin", None)
        current = ready
    return current


def demote_generation(store: InstallState, state: dict, identifier: str) -> str | None:
    record = state.get("generations", {}).get(identifier)
    if record is not None:
        record["health"] = "failed"
    if state.get("current") == identifier:
        previous = state.pop("previous", None)
        current = previous if healthy(store, state, previous) else None
        state.update(current=current, status="rolled_back" if current else "failed",
                     failure={"message": "The active copy could not be started."})
    return state.get("current")


def evacuate_unused(store: InstallState, state: dict, prefs: Preferences) -> list[Path]:
    """Retire unused directories under the gate, returning paths to remove outside it."""
    if store.gc_paused(state, prefs):
        return []
    store.write_leases(store.launch_leases(prefs.startup_attempt_window_seconds))
    generations = state.get("generations", {})
    retained = {state.get(key) for key in ("current", "previous", "ready")}
    retained.add(state.get("builder", {}).get("generation"))
    for value in store.live_leases().values():
        if not isinstance(value, dict):
            return []  # A damaged lease cannot safely identify its environment.
        retained.add(value.get("generation"))
    eligible = sorted(
        (identifier for identifier, record in generations.items()
         if generation_id(identifier) and record.get("health") == "healthy"),
        key=lambda identifier: generations[identifier].get("created_at", 0), reverse=True,
    )
    retained.update(eligible[:prefs.retain_healthy])
    paths = []
    for identifier in tuple(generations):
        if not generation_id(identifier) or identifier in retained:
            continue
        path = directory_for(store, identifier)
        retired = path.with_name(f".retired-{identifier}")
        if path.exists():
            os.replace(path, retired)
        del generations[identifier]
        paths.append(retired)
    return paths
