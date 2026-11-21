from __future__ import annotations

import os
import shutil
import sys
import types
from pathlib import Path

import pytest

fcntl = pytest.importorskip("fcntl")

from scripts.distribution import apt_generations as generations
from scripts.distribution.package_deb import generation_source
from servonaut.debian_layout import LEASE, MARKER, RESTART_GENERATION_ENV, ROLES, STATUS


@pytest.fixture(autouse=True)
def owned_files(monkeypatch):
    # These fixtures model a root-owned store and run in the regular unit suite.
    monkeypatch.setattr(generations, "secure", lambda path: path.lstat())
    monkeypatch.setattr(generations, "open_lease", lambda path: (path / LEASE).open("rb"))


def make_generation(store: Path, label: str) -> Path:
    temporary = store / f"build-{label}"
    temporary.mkdir()
    for role in ROLES:
        executable = temporary / role
        executable.write_text(f"{role} {label}", encoding="utf-8")
        executable.chmod(0o755)
    (temporary / MARKER).write_text(label, encoding="utf-8")
    name = generations.generation_id(list(generations.walk(temporary)))
    (temporary / LEASE).touch()
    return temporary.rename(store / name)


def test_packaged_helper_contains_shared_roles_without_application_imports(monkeypatch):
    source = generation_source()
    assert "from servonaut." not in source
    module = types.ModuleType("packaged_generation_helper")
    monkeypatch.setitem(sys.modules, module.__name__, module)
    exec(compile(source, "<Debian helper>", "exec"), module.__dict__)
    assert module.ROLES == ROLES


def test_prune_retains_both_configured_generations_without_leases(tmp_path):
    store = tmp_path / "generations"
    store.mkdir()
    proc = tmp_path / "proc"
    proc.mkdir()
    current, previous, unused = [make_generation(store, label) for label in ("current", "previous", "unused")]
    generations.prune(store, current.name, previous.name, proc)
    assert current.is_dir() and previous.is_dir() and not unused.exists()


@pytest.mark.parametrize("source", ["exe", "maps"])
def test_prune_preserves_mapped_generation_and_checks_complete_path(tmp_path, source):
    store = tmp_path / "generations"
    store.mkdir()
    running = make_generation(store, "running")
    unused = make_generation(store, "unused")
    process = tmp_path / "proc" / "105"
    process.mkdir(parents=True)
    if source == "exe":
        (process / "exe").symlink_to(running / ROLES[0])
    else:
        (process / "maps").write_text(
            f"1-2 r-xp 0 00:00 1 {running / ROLES[0]}\n"
            f"2-3 r-xp 0 00:00 1 /other{unused / ROLES[0]}\n",
            encoding="utf-8",
        )
    generations.prune(store, "", "", process.parent)
    assert running.is_dir() and not unused.exists()


def test_prune_skips_lease_less_generation_and_still_cleans_valid_siblings(tmp_path):
    store = tmp_path / "generations"
    store.mkdir()
    proc = tmp_path / "proc"
    proc.mkdir()
    invalid = store / ("0" * 64)
    invalid.mkdir()
    unused = make_generation(store, "unused")
    generations.prune(store, "", "", proc)
    assert invalid.is_dir() and not unused.exists()


@pytest.mark.parametrize("stage", ["before_rename", "before_delete", "during_delete", "after_delete"])
def test_retirement_recovers_at_each_interruption_point(tmp_path, monkeypatch, stage):
    store = tmp_path / "generations"
    store.mkdir()
    original = make_generation(store, "original")
    rename = Path.rename
    delete = shutil.rmtree

    def interrupt_rename(source, target):
        if source == original and stage == "before_rename":
            raise OSError("interrupted collection")
        return rename(source, target)

    def interrupt_delete(retired):
        if stage == "during_delete":
            (retired / original.name / LEASE).unlink()
        elif stage == "after_delete":
            delete(retired)
        raise OSError("interrupted collection")

    with monkeypatch.context() as patched:
        patched.setattr(Path, "rename", interrupt_rename)
        patched.setattr(generations.shutil, "rmtree", interrupt_delete)
        with pytest.raises(OSError, match="interrupted collection"):
            generations.retire(original)
    if stage == "before_rename":
        assert generations.valid_generation(original)
    else:
        assert not original.exists()
        assert list(generations.generations(store)) == []
    generations.remove_interrupted_files(store)
    assert list(store.glob(".retired-*")) == []


def test_invalid_status_recovers_newest_complete_generation(tmp_path):
    store = tmp_path / "generations"
    store.mkdir()
    older = make_generation(store, "older")
    newer = make_generation(store, "newer")
    damaged = make_generation(store, "damaged")
    (damaged / ROLES[0]).unlink()
    os.utime(older, ns=(1, 1))
    os.utime(newer, ns=(2, 2))
    (store / STATUS).write_text('{"current":"../../elsewhere"}', encoding="utf-8")
    status = generations.recover_status(store)
    assert (status["current"], status["previous"]) == (newer.name, older.name)


def test_reactivated_marker_is_preferred_over_newer_directory(tmp_path):
    store = tmp_path / "generations"
    store.mkdir()
    reactivated = make_generation(store, "reactivated")
    newer = make_generation(store, "newer")
    os.utime(reactivated, ns=(1, 1))
    os.utime(newer, ns=(2, 2))
    os.link(reactivated / MARKER, tmp_path / MARKER)
    (store / STATUS).write_text("interrupted status", encoding="utf-8")

    status = generations.recover_status(store)
    assert (status["current"], status["previous"]) == (reactivated.name, newer.name)


def test_existing_incomplete_target_is_retired_and_rebuilt(tmp_path, monkeypatch):
    store = tmp_path / "generations"
    store.mkdir()
    original = make_generation(store, "original")
    source = tmp_path / "payload"
    shutil.copytree(original, source, ignore=shutil.ignore_patterns(LEASE))
    (original / LEASE).unlink()
    (original / ROLES[0]).unlink()
    monkeypatch.setattr(generations, "mapped_by_process", lambda *args: False)
    generations.materialize(store, original.name, list(generations.walk(source)))
    assert generations.valid_generation(original)


def test_busy_lease_does_not_prevent_a_launch(tmp_path, monkeypatch):
    store = tmp_path / "generations"
    store.mkdir()
    active = make_generation(store, "active")
    monkeypatch.setattr(generations, "parent_generation", lambda _: "")
    monkeypatch.setattr(generations, "configured_status", lambda _: {"current": active.name})

    def execv(path, argv):
        assert path == active / ROLES[0]
        assert argv == [str(path), "--version"]
        raise SystemExit(0)

    monkeypatch.setattr(generations.os, "execv", execv)
    lock = fcntl.flock
    attempts = []

    def track(fd, operation):
        attempts.append(operation)
        return lock(fd, operation)

    with (active / LEASE).open("rb") as locked:
        lock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
        monkeypatch.setattr(fcntl, "flock", track)
        with pytest.raises(SystemExit) as result:
            generations.launch(store, ROLES[0], ["--version"])
    assert result.value.code == 0
    assert len(attempts) >= 2 and set(attempts) == {fcntl.LOCK_SH | fcntl.LOCK_NB}


def test_unpinned_launch_rechecks_after_activation(tmp_path, monkeypatch):
    store = tmp_path / "generations"
    store.mkdir()
    old = make_generation(store, "old")
    new = make_generation(store, "new")
    observed = iter([old.name, new.name, new.name, new.name])
    monkeypatch.setattr(generations, "parent_generation", lambda _: "")
    monkeypatch.setattr(generations, "configured_status", lambda _: {"current": next(observed)})

    def execv(path, argv):
        assert path == new / ROLES[0]
        raise SystemExit(0)

    monkeypatch.setattr(generations.os, "execv", execv)
    with pytest.raises(SystemExit) as result:
        generations.launch(store, ROLES[0], [])
    assert result.value.code == 0


def test_degraded_pointer_verifies_only_the_selected_build_once(tmp_path, monkeypatch):
    store = tmp_path / "generations"
    store.mkdir()
    selected = make_generation(store, "selected")
    make_generation(store, "other")
    os.link(selected / MARKER, tmp_path / MARKER)
    monkeypatch.setattr(generations, "parent_generation", lambda _: "")
    validate = generations.valid_generation
    checked = []

    def record(path):
        checked.append(path)
        return validate(path)

    def execv(path, _argv):
        assert path == selected / ROLES[0]
        raise SystemExit(0)

    monkeypatch.setattr(generations, "valid_generation", record)
    monkeypatch.setattr(generations.os, "execv", execv)
    with pytest.raises(SystemExit):
        generations.launch(store, ROLES[0], [])
    assert checked == [selected]


@pytest.mark.parametrize("restart", [False, True], ids=["normal-spawn", "deliberate-restart"])
def test_stable_launcher_uses_its_store_resident_parent_after_upgrade(tmp_path, monkeypatch, restart):
    store = tmp_path / "generations"
    store.mkdir()
    running = make_generation(store, "running")
    installed = make_generation(store, "installed")
    if restart:
        monkeypatch.setenv(RESTART_GENERATION_ENV, "1")
    generations.write_status(store, {
        "schema_version": 1, "current": installed.name, "previous": running.name, "copied_bytes": 0,
    })
    readlink = os.readlink

    def read_parent_executable(path):
        if path == Path("/proc") / str(os.getppid()) / "exe":
            return str(running / ROLES[0])
        return readlink(path)

    def execv(path, _argv):
        assert path == (installed if restart else running) / ROLES[1]
        assert RESTART_GENERATION_ENV not in os.environ
        raise SystemExit(0)

    monkeypatch.setattr(generations.os, "readlink", read_parent_executable)
    monkeypatch.setattr(generations.os, "execv", execv)
    with pytest.raises(SystemExit):
        generations.launch(store, ROLES[1], [])
