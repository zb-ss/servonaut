"""Regression coverage for launcher availability, user intent and builder isolation."""

import errno
import http.client
import importlib.util
import json
import os
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from servonaut import entry
from servonaut.updates import builder, index, state
from servonaut.updates.generations import directory_for, healthy
from servonaut.updates.layout import python_for
from servonaut.updates.profile import Profile, load_profile
from servonaut.updates.status import MARKER_NAME, UpdateBusy, read_update_status, storage_for

OLD, CURRENT, READY = ("1" * 32, "2" * 32, "3" * 32)
VERSION, ACTIVE_VERSION, TARGET = "2.34.0", "2.35.0", "2.36.0"
DIGEST = "1" * 64
_SCHEDULE = builder.schedule


def _initialize(store, journal, identifier, version):
    directory = directory_for(store, identifier)
    executable = python_for(directory)
    executable.parent.mkdir(parents=True)
    executable.touch()
    executable.chmod(0o700)
    (directory / MARKER_NAME).write_text(json.dumps({
        "anchor": str(store.root), "generation": identifier,
    }))
    journal["generations"][identifier] = {
        "version": version, "health": "healthy", "verified_at": time.time(),
        "digest": DIGEST, "profile": "profile",
    }


@pytest.fixture
def install(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path))
    monkeypatch.setenv("SERVONAUT_SKIP_AUTO_APPLY", "0")
    monkeypatch.setattr("servonaut.get_version", lambda: VERSION)
    store = state.InstallState(tmp_path / "pipx" / "servonaut")
    store.root.mkdir(parents=True)
    (store.root / "pipx_metadata.json").write_text("{}")
    monkeypatch.setattr(sys, "prefix", str(store.root))
    store.directory.mkdir(parents=True)
    journal = {"current": CURRENT, "previous": OLD, "generations": {},
               "launcher_version": VERSION, "last_launcher_version": VERSION}
    _initialize(store, journal, OLD, VERSION)
    _initialize(store, journal, CURRENT, ACTIVE_VERSION)
    for name in ("state.json", "routing.json"):
        store.write(name, journal)
    store.write("leases.json", {})
    monkeypatch.setattr(builder, "schedule", lambda *_args: None)
    # Keep this fixture runnable on the earlier launcher for the negative controls.
    if importlib.util.find_spec("servonaut.updates.launch") is not None:
        monkeypatch.setattr("servonaut.updates.launch.schedule", lambda *_args: None)
    return store, journal


@pytest.fixture
def route(monkeypatch):
    attempts = []
    monkeypatch.setattr(entry, "_dispatch", lambda: attempts.append("launcher"))

    def exec_generation(executable, *_arguments):
        attempts.append(Path(executable).parent.parent.name)
        raise SystemExit(0)

    monkeypatch.setattr(entry, "_run_generation", exec_generation)

    def run(*arguments):
        try:
            entry._route(list(arguments))
        except SystemExit as error:
            assert error.code == 0
        return attempts[-1]

    return run


@pytest.mark.parametrize(("file", "damage"), [
    ("state.json", "{"),
    ("state.json", "[]"),
    ("state.json", '{"generations": 5}'),
    ("state.json", '{"offered_at": "invalid"}'),
    ("leases.json", "{"),
    ("leases.json", "[]"),
    ("leases.json", '{"25": 5}'),
])
def test_corrupt_journal_launches_healthy_and_quarantines(install, route, file, damage, capsys):
    store, _ = install
    (store.directory / file).write_text(damage)
    assert route("--mcp") == CURRENT
    assert list(store.directory.glob(f"{file}.corrupt-*"))
    assert isinstance(store.read(file), dict)
    assert capsys.readouterr() == ("", "")


def test_bad_generation_timestamp_is_recovered(install, route):
    store, journal = install
    journal["generations"][CURRENT]["verified_at"] = "invalid"
    store.write("state.json", journal)
    assert route("--mcp") == CURRENT
    assert list(store.directory.glob("state.json.corrupt-*"))


@pytest.mark.parametrize("failure", [
    OSError(errno.ENOSPC, "full"),
    OSError(errno.EROFS, "read-only"),
    OSError(errno.EACCES, "sandbox"),
    OSError(errno.ENOLCK, "NFS"),
    UpdateBusy("lock wait expired"),
])
def test_launch_with_unavailable_updater_lock(install, route, monkeypatch, failure, capsys):
    @contextmanager
    def refused(*_args, **_kwargs):
        raise failure
        yield

    monkeypatch.setattr(state.InstallState, "gate", refused)
    assert route("--mcp") == ("launcher" if isinstance(failure, UpdateBusy) else CURRENT)
    assert capsys.readouterr() == ("", "")


def test_real_lock_timeout_recovers_without_console_output(install, route, capsys):
    store, _ = install
    store.write("preferences.json", {"admission_timeout": 0.01})
    with store.gate():
        assert route("--mcp") == "launcher"
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("operation", ["mkdir", "write"])
def test_launch_with_denied_storage(install, route, monkeypatch, operation):
    store, _ = install
    if operation == "mkdir":
        original = Path.mkdir

        def denied(path, *args, **kwargs):
            if path == store.directory:
                raise PermissionError(errno.EROFS, "read-only")
            return original(path, *args, **kwargs)

        monkeypatch.setattr(Path, "mkdir", denied)
    else:
        def full(*_args):
            raise OSError(errno.ENOSPC, "disk full")

        monkeypatch.setattr(state.InstallState, "write", full)
    assert route("--mcp") == CURRENT


def test_unreadable_install_uses_launcher_without_printing(install, route, capsys):
    store, _ = install
    for name in ("state.json", "routing.json"):
        (store.directory / name).write_text("[")
    assert route("--mcp") == "launcher"
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("argument", ["--version", "--help"])
def test_diagnostic_flags_leave_update_files_untouched(install, route, argument, monkeypatch):
    store, _ = install
    def forbidden(*_args):
        pytest.fail("Diagnostic flags acquired a writable updater gate")

    monkeypatch.setattr(state.InstallState, "gate", forbidden)
    before = _files(store)
    assert route(argument) == CURRENT
    assert _files(store) == before


def _files(store):
    return {path.name: path.read_bytes() for path in store.directory.iterdir() if path.is_file()}


@pytest.mark.parametrize("component", ["home", "data"])
def test_symlinked_storage_resolves_the_same_generation(tmp_path, monkeypatch, component):
    home = tmp_path / "real-home"
    home.mkdir()
    link = tmp_path / "home"
    data = tmp_path / "data"
    data.mkdir()
    if component == "home":
        link.symlink_to(home, target_is_directory=True)
        home = link
    else:
        (home / ".servonaut").symlink_to(data, target_is_directory=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))
    store = state.InstallState(tmp_path / "pipx" / "servonaut")
    journal = {"generations": {}}
    _initialize(store, journal, CURRENT, VERSION)
    assert storage_for(store.root) == directory_for(store, CURRENT).parent.parent.resolve()
    assert healthy(store, journal, CURRENT)


def test_automation_escape_hatch_bypasses_active_generation(install, route, monkeypatch):
    store, _ = install
    monkeypatch.setenv("SERVONAUT_SKIP_AUTO_APPLY", "1")
    before = _files(store)
    assert route("--mcp") == "launcher"
    assert _files(store) == before


def test_update_subcommand_operand_is_not_a_launcher_flag(install, route):
    assert route("--update") == "launcher"
    assert route("team", "rules", "--update") == CURRENT


def test_missing_console_falls_back_and_marks_current_failed(install, monkeypatch):
    store, _ = install
    called = []
    def execute(path, *_arguments):
        called.append(Path(path).parent.parent.name)
        if len(called) == 1:
            raise OSError(errno.ENOEXEC, "bad executable")
        raise SystemExit(0)

    monkeypatch.setattr(entry, "_run_generation", execute)
    with pytest.raises(SystemExit) as exit_info:
        entry._route(["--mcp"])
    assert exit_info.value.code == 0
    assert called == [CURRENT, OLD]
    journal = store.read("state.json")
    assert journal["current"] == OLD
    assert journal["generations"][CURRENT]["health"] == "failed"


def test_nonzero_application_exits_leave_current_healthy(install, monkeypatch):
    store, _ = install
    monkeypatch.setattr(sys, "prefix", str(directory_for(store, CURRENT)))
    store.write("preferences.json", {"crash_loop_count": 2})
    def exit_bad():
        raise SystemExit(9)

    monkeypatch.setattr(entry, "_dispatch", exit_bad)
    for _attempt in range(3):
        with pytest.raises(SystemExit, match="9"):
            entry._route(["--mcp"])
        assert store.read("state.json")["current"] == CURRENT


def test_manual_downgrade_is_pinned_until_a_new_release(install, route, monkeypatch):
    store, journal = install
    journal["last_launcher_version"] = ACTIVE_VERSION
    store.write("state.json", journal)
    assert route("--version") == "launcher"
    assert "pin" not in store.read("state.json")
    assert route("--mcp") == "launcher"
    snapshot = read_update_status()
    assert snapshot.pinned_version == VERSION
    assert snapshot.pinned_until_newer_than == ACTIVE_VERSION
    assert snapshot.last_failure is None
    journal = store.read("state.json")
    _initialize(store, journal, READY, TARGET)
    journal.update(ready=READY, offered=TARGET, offered_at=time.time() - 1, presented_at=time.time())
    store.write("state.json", journal)
    assert route("--mcp") == READY
    assert "pin" not in store.read("state.json")


def test_stale_stage_gets_one_bounded_check_and_promotes(install, route, monkeypatch):
    store, journal = install
    _initialize(store, journal, READY, TARGET)
    journal["generations"][READY]["verified_at"] = 0
    journal.update(ready=READY, offered=TARGET, offered_at=time.time() - 1, presented_at=time.time())
    store.write("state.json", journal)
    store.write("preferences.json", {"launch_validation_timeout": 0.5})
    calls = []

    class ExactIndex:
        def document(self, timeout):
            calls.append(timeout)
            return {}

        def wheel(self, _document, version):
            calls.append(version)
            return SimpleNamespace(digest=DIGEST)

    monkeypatch.setattr(index, "PackageIndex", ExactIndex)
    if importlib.util.find_spec("servonaut.updates.launch") is not None:
        monkeypatch.setattr("servonaut.updates.launch.PackageIndex", ExactIndex)
    assert route("--mcp") == READY
    assert calls == [0.5, TARGET]
    assert route("--mcp") == READY
    assert calls == [0.5, TARGET]


def test_poll_preserves_launch_freshness_after_a_positive_check(install, monkeypatch):
    store, journal = install
    _initialize(store, journal, READY, TARGET)
    journal["generations"][READY]["verified_at"] = 100
    journal["ready"] = READY
    store.write("state.json", journal)
    from servonaut.updates import launch
    monkeypatch.setattr(launch, "_verify", lambda *_args: True)
    launch.refresh_ready(store)
    updated = store.read("state.json")
    assert updated["current"] == CURRENT
    assert updated["generations"][READY]["verified_at"] == 100


def test_token_transfers_ownership_across_windows_redirector(install, monkeypatch):
    store, journal = install
    journal["builder"] = {"token": "claim", "pid": os.getpid() + 1}
    store.write("state.json", journal)
    monkeypatch.setattr(sys, "argv", ["builder", str(store.root), "claim", VERSION])
    called = []
    monkeypatch.setattr(builder, "_stage", lambda *_args: called.append(store.read("state.json")["builder"]))
    builder.main()
    assert called and called[0]["pid"] == os.getpid()
    assert called[0]["birth"] == builder._creation(os.getpid())


@pytest.mark.parametrize("error", [http.client.HTTPException, AttributeError, KeyError])
def test_builder_clears_owner_and_backs_off_on_check_errors(install, monkeypatch, error):
    store, journal = install
    journal["builder"] = {"token": "claim", "pid": os.getpid()}
    store.write("state.json", journal)
    monkeypatch.setattr(sys, "argv", ["builder", str(store.root), "claim", VERSION])
    def fail(*_args):
        raise error("test failure")

    monkeypatch.setattr(builder, "_stage", fail)
    builder.main()
    updated = store.read("state.json")
    assert "builder" not in updated
    assert updated["status"] == "failed"
    assert updated["failure"]["retry_at"] > time.time()


def test_dead_record_respects_retry_and_check_interval(install, monkeypatch):
    store, journal = install
    monkeypatch.setattr(builder, "_active", lambda _record: False)
    monkeypatch.setattr(builder.subprocess, "Popen", lambda *_args, **_kwargs: SimpleNamespace(pid=123))
    journal.update(checked_at=time.time(), builder={"pid": 99},
                   failure={"retry_at": time.time() + 100})
    assert _SCHEDULE(store, journal, state.Preferences(), VERSION) is None
    assert "builder" not in journal
    assert journal["failure"]["retry_at"] > time.time()


def test_rejects_option_shaped_injected_spec(install, monkeypatch):
    store, _ = install
    profile = store.root / "pipx_metadata.json"
    profile.write_text(json.dumps({
        "main_package": {"package_or_url": "servonaut"},
        "injected_packages": {"option": {"package_or_url": "--pre"}},
    }))
    monkeypatch.setattr("shutil.which", lambda _name: str(store.root.parent.parent / "pipx"))
    monkeypatch.setattr("subprocess.check_output", lambda *_args, **_kwargs: str(store.root.parent))
    with pytest.raises(index.UpdateUnavailable, match="custom package settings"):
        load_profile(store.root, 1)


def test_pip_environment_ignores_unapproved_package_knobs(tmp_path, monkeypatch):
    monkeypatch.setenv("PIP_NO_DEPS", "1")
    monkeypatch.setenv("PIP_PRE", "1")
    wheel = index.Wheel("servonaut-2.36.0-py3-none-any.whl", "https://example.org/wheel", DIGEST, 1)
    fake = SimpleNamespace(index_url=index.DEFAULT_INDEX_URL, document=lambda _timeout: {},
                           wheel=lambda *_args: wheel)
    monkeypatch.setattr(index, "_copy_wheel", lambda *_args: None)
    with index.pinned_wheel(fake, TARGET, wheel, tmp_path, lambda: 1) as (_url, environment):
        assert set(key for key in environment if key.startswith("PIP_")) <= {
            "PIP_INDEX_URL", "PIP_CONSTRAINT", "PIP_CONFIG_FILE", "PIP_NO_INPUT",
            "PIP_DISABLE_PIP_VERSION_CHECK",
        }


def test_release_candidate_defaults_to_rc():
    assert state.Preferences.parse({}, "2.36.0rc1").channel == "rc"
    assert state.Preferences.parse({"channel": "stable"}, "2.36.0rc1").channel == "stable"


def test_none_stdio_is_a_noninteractive_launch(monkeypatch):
    monkeypatch.setattr(sys, "stdin", None)
    monkeypatch.setattr(sys, "stdout", None)
    assert not entry._interactive([])


def test_windows_wait_preserves_signals_and_forwards_status(monkeypatch):
    import signal

    trace = {}
    monkeypatch.setattr(signal, "SIGBREAK", -99, raising=False)
    def install(sig, handler):
        previous = trace.get(sig, "app handler")
        trace[sig] = handler
        return previous

    def child(_command, **_kwargs):
        assert trace == {signal.SIGINT: signal.SIG_IGN, signal.SIGBREAK: signal.SIG_IGN}
        return 7

    monkeypatch.setattr(signal, "signal", install)
    monkeypatch.setattr(entry, "os", SimpleNamespace(name="nt", environ={}, getpid=os.getpid))
    monkeypatch.setattr(entry.subprocess, "call", child)
    with pytest.raises(SystemExit) as error:
        entry._run_generation("servonaut.exe", [], None)
    assert error.value.code == 7
    assert trace == {signal.SIGINT: "app handler", signal.SIGBREAK: "app handler"}


@pytest.mark.asyncio
async def test_ui_reads_and_presents_generation_status_off_main_thread(monkeypatch):
    from servonaut.app import ServonautApp
    from servonaut.updates import status

    main = threading.get_ident()
    calls = []
    def read(_runtime):
        calls.append(("read", threading.get_ident()))
        return status.UpdateStatus("ready", VERSION, "pipx", "stable", TARGET)

    def present(_version):
        calls.append(("present", threading.get_ident()))
        return True

    monkeypatch.setattr(status, "read_update_status", read)
    monkeypatch.setattr(status, "mark_update_presented", present)
    app = SimpleNamespace(runtime_layout=None, notify=lambda *_args, **_kwargs: None,
                          _show_update_button=lambda _version: None)
    await ServonautApp._show_generation_update(app)
    assert [name for name, _ in calls] == ["read", "present"]
    assert all(thread != main for _name, thread in calls)


def test_validation_timeout_keeps_current_and_queues_worker(install, route, monkeypatch):
    store, journal = install
    _initialize(store, journal, READY, TARGET)
    journal["generations"][READY]["verified_at"] = 0
    journal.update(ready=READY, offered=TARGET, offered_at=time.time() - 1, presented_at=time.time())
    store.write("state.json", journal)
    store.write("preferences.json", {"launch_validation_timeout": 0.03})
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    queued = []

    class WaitForIndex:
        def document(self, _timeout):
            entered.set()
            release.wait(5)
            finished.set()
            raise TimeoutError

        def wheel(self, _document, _version):
            pytest.fail("A timed-out request provided wheel metadata")

    has_launch = importlib.util.find_spec("servonaut.updates.launch") is not None
    if has_launch:
        monkeypatch.setattr("servonaut.updates.launch.PackageIndex", WaitForIndex)
        monkeypatch.setattr("servonaut.updates.launch.schedule", lambda *_args: queued.append(True))
    try:
        started = time.monotonic()
        assert route("--mcp") == CURRENT
        assert time.monotonic() - started < 1
        assert entered.is_set()
        assert queued == [True]
        assert store.read("state.json")["ready"] == READY
    finally:
        release.set()
        if entered.is_set():
            assert finished.wait(1)


def _builder_owner(store, journal, monkeypatch):
    journal["builder"] = {"token": "claim", "pid": os.getpid(), "previous_check": 12}
    journal["checked_at"] = time.time()
    store.write("state.json", journal)
    monkeypatch.setattr(sys, "argv", ["builder", str(store.root), "claim", VERSION])


@pytest.mark.parametrize("unsupported", ["index", "denylist", "global", "suffix"])
def test_unsupported_auto_setup_keeps_legacy_notice_available(install, monkeypatch, unsupported):
    store, journal = install
    _builder_owner(store, journal, monkeypatch)
    profile = Profile(sys.executable, "servonaut", ())
    monkeypatch.setenv("PIP_INDEX_URL", index.DEFAULT_INDEX_URL)
    monkeypatch.setattr(builder, "_refresh_policy", lambda *_args: None)

    if unsupported == "suffix":
        monkeypatch.setattr("shutil.which", lambda _name: str(store.root.parent.parent / "pipx"))
        monkeypatch.setattr("subprocess.check_output", lambda *_args, **_kwargs: str(store.root.parent))
        (store.root / "pipx_metadata.json").write_text(json.dumps({
            "main_package": {"package_or_url": "servonaut", "suffix": "-alternate"},
        }))
    else:
        monkeypatch.setattr(builder, "load_profile", lambda *_args: profile)
        if unsupported == "index":
            monkeypatch.setenv("PIP_INDEX_URL", "https://example.org/simple/")
        elif unsupported == "denylist":
            monkeypatch.setenv("PIP_TARGET", str(store.root))
        else:
            monkeypatch.setenv("PIPX_GLOBAL", "1")

    builder.main()
    updated = store.read("state.json")
    assert updated["status"] == "managed_elsewhere"
    assert read_update_status().state == "managed_elsewhere"


def _fake_build_index(monkeypatch, wheel, desired):
    class FakeIndex:
        def document(self, _timeout):
            return {}

        def target(self, *_args):
            return desired

        def wheel(self, _document, version):
            return wheel if version == desired else None

    monkeypatch.setattr(builder, "PackageIndex", FakeIndex)
    monkeypatch.setattr(builder, "load_profile", lambda *_args: Profile(sys.executable, "servonaut", ()))
    monkeypatch.setattr(builder, "_refresh_policy", lambda *_args: None)


def test_same_version_profile_rebuild_has_no_offer(install, monkeypatch):
    store, journal = install
    _builder_owner(store, journal, monkeypatch)
    wheel = index.Wheel("name", "url", DIGEST, 10)
    _fake_build_index(monkeypatch, wheel, ACTIVE_VERSION)
    monkeypatch.setattr(builder, "_build", lambda *_args: None)
    builder._stage(store, "claim", VERSION)
    updated = store.read("state.json")
    assert updated["ready"] in updated["generations"]
    assert "offered" not in updated
    assert updated["status"] == "up_to_date"


def test_builder_does_not_publish_after_losing_ownership(install, monkeypatch):
    store, journal = install
    _builder_owner(store, journal, monkeypatch)
    wheel = index.Wheel("name", "url", DIGEST, 10)
    _fake_build_index(monkeypatch, wheel, TARGET)

    def supersede(*_args):
        changed = store.read("state.json")
        changed["builder"]["token"] = "replacement"
        store.write("state.json", changed)

    monkeypatch.setattr(builder, "_build", supersede)
    builder._stage(store, "claim", VERSION)
    updated = store.read("state.json")
    assert updated["builder"]["token"] == "replacement"
    assert "ready" not in updated


@pytest.mark.asyncio
async def test_tui_keeps_legacy_notice_for_managed_elsewhere(monkeypatch):
    from servonaut.app import ServonautApp
    from servonaut.updates import status

    snapshot = status.UpdateStatus("managed_elsewhere", VERSION, "pipx", "stable")
    monkeypatch.setattr(status, "read_update_status", lambda _runtime: snapshot)
    calls = []

    async def check():
        calls.append("legacy notice")

    app = SimpleNamespace(runtime_layout=None, _check_legacy_update=check)
    await ServonautApp._show_generation_update(app)
    await ServonautApp._show_generation_update(app)
    assert calls == ["legacy notice"]
    assert app._legacy_generation_update


def test_startup_help_proclaims_servonaut(monkeypatch, capsys):
    from servonaut import main
    monkeypatch.setattr(sys, "argv", ["entry.py", "--help"])
    with pytest.raises(SystemExit) as error:
        main.main()
    assert error.value.code == 0
    assert capsys.readouterr().out.startswith("usage: servonaut ")


def test_generation_exec_uses_its_console_and_original_arguments(monkeypatch):
    launched = []
    os_interface = SimpleNamespace(
        name="posix", environ={}, getpid=os.getpid,
        execve=lambda executable, argv, _env: launched.append((executable, argv)),
    )
    monkeypatch.setattr(entry, "os", os_interface)
    entry._run_generation("/generation/bin/servonaut", ["--mcp"], None)
    assert launched == [("/generation/bin/servonaut", ["/generation/bin/servonaut", "--mcp"])]


def test_builder_probe_imports_app_and_mcp_from_neutral_directory(install, monkeypatch):
    store, _ = install
    destination = directory_for(store, READY)
    destination.mkdir()
    commands = []

    @contextmanager
    def wheel_file(*_args):
        yield "file:///wheel.whl", {}

    def run(command, **kwargs):
        commands.append((command, kwargs.get("cwd")))
        return SimpleNamespace(returncode=0, stdout=f"servonaut {TARGET}\n")

    monkeypatch.setattr(builder, "pinned_wheel", wheel_file)
    monkeypatch.setattr(builder, "_run_command", lambda *_args: None)
    monkeypatch.setattr(builder.subprocess, "run", run)
    wheel = index.Wheel("name", "url", DIGEST, 10)
    profile = Profile(sys.executable, "servonaut", ())
    builder._build(store, destination, READY, TARGET, wheel, profile, None, state.Preferences(),
                   time.monotonic() + 30)
    assert [command[1:] for command, _cwd in commands] == [
        ["-c", "import servonaut.app, servonaut.mcp.server"], ["--version"],
    ]
    assert all(cwd == store.directory for _command, cwd in commands)


def test_package_writer_runs_from_neutral_directory(install, monkeypatch):
    store, journal = install
    _builder_owner(store, journal, monkeypatch)
    working_directories = []

    def launch(_command, **kwargs):
        working_directories.append(kwargs.get("cwd"))
        return SimpleNamespace(pid=os.getpid(), wait=lambda **_kwargs: 0)

    monkeypatch.setattr(builder.subprocess, "Popen", launch)
    builder._run_command(store, ["python", "-m", "venv"], 1)
    assert working_directories == [store.directory]


def _pending_starts(store, rows):
    store.write("leases.json", {
        str(pid): {"birth": "native-identity", "role": "cli", "generation": CURRENT,
                   "version": ACTIVE_VERSION, "started": False, "launched_at": launched}
        for pid, launched in rows
    })


def test_third_launch_avoids_repeatedly_unavailable_interpreter(install, route, monkeypatch):
    store, _ = install
    monkeypatch.setattr(state, "birth", lambda _pid: None)
    now = time.time()
    _pending_starts(store, [(123, now - 2), (456, now - 1)])
    assert route("--mcp") == OLD
    updated = store.read("state.json")
    assert updated["generations"][CURRENT]["health"] == "failed"
    assert updated["failure"]["message"] == "The active copy repeatedly failed to start."


def test_expired_and_live_starts_do_not_count_toward_rollback(install, route, monkeypatch):
    store, _ = install
    store.write("preferences.json", {"startup_attempt_window_seconds": 10})
    monkeypatch.setattr(state, "birth", lambda pid: "native-identity" if pid == 456 else None)
    now = time.time()
    _pending_starts(store, [(123, now - 20), (456, now - 1)])
    assert route("--mcp") == CURRENT
    leases = store.read("leases.json")
    assert "123" not in leases
    assert "456" in leases
    assert leases[str(os.getpid())]["started"] is False


def test_entry_acknowledges_start_and_clears_old_attempts(install, monkeypatch):
    store, _ = install
    monkeypatch.setattr(sys, "prefix", str(directory_for(store, CURRENT)))
    pid = os.getpid()
    monkeypatch.setattr(state, "birth", lambda owner: "native-identity" if owner == pid else None)
    _pending_starts(store, [(123, time.time() - 1)])
    lease_id = store.register("mcp", store.read("leases.json"), CURRENT, ACTIVE_VERSION)
    monkeypatch.setenv(entry._LEASE_ID, lease_id)
    seen = []
    monkeypatch.setattr(entry, "_dispatch", lambda: seen.append((store.directory / "acks" / lease_id).exists()))
    entry._route(["--mcp"])
    assert seen == [True]
    assert store.read("leases.json") == {}
    assert not (store.directory / "acks" / lease_id).exists()
