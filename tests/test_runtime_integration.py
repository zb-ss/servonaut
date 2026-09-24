"""Runtime-layout integration seams for the TUI and relay CLI."""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from servonaut import main
from servonaut.app import ServonautApp
from servonaut.runtime import DistributionKind, RuntimeEvidence, resolve_runtime
from servonaut.services.process_control import wait_for_process_exit
from servonaut.services.relay_lock import RelayLock


def _source_layout(tmp_path: Path):
    executable = Path(sys.executable)
    evidence = RuntimeEvidence(
        executable=executable,
        executable_root=executable.parent,
        resource_root=tmp_path / "resources",
        home=tmp_path,
        is_frozen=False,
        package_version="2.27.0",
        package_is_installed=False,
        source_install_path=None,
        path_console=None,
        pipx_executable=None,
        pipx_contains_servonaut=False,
        marker=None,
    )
    return resolve_runtime(evidence)


class _BenignRuntime:
    def __init__(self, data_root: Path) -> None:
        self.data_root = data_root
        self.kind = DistributionKind.SOURCE
        self.executable = Path(sys.executable).resolve()
        self.executable_root = self.executable.parent
        self.is_frozen = False
        self.desktop_child = None
        self.calls: list[tuple[str, ...]] = []

    def current_app_argv(self, *args: str) -> list[str]:
        self.calls.append(args)
        return [str(self.executable), "-c", "import time; time.sleep(0.05)"]


def _desktop_runtime(argv: list[str]) -> SimpleNamespace:
    executable = Path(sys.executable).resolve()
    return SimpleNamespace(
        kind=DistributionKind.SOURCE,
        executable=executable,
        executable_root=executable.parent,
        is_frozen=False,
        desktop_child=None,
        current_app_argv=lambda: list(argv),
    )


def _write_argv_capture_script(path: Path) -> None:
    path.write_text(
        "import json\n"
        "import sys\n"
        "from pathlib import Path\n"
        "Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]), encoding='utf-8')\n",
        encoding="utf-8",
    )


def _packaged_runtime_with_command(tmp_path: Path, command_kind: str) -> SimpleNamespace:
    executable_root = tmp_path / "bundle"
    executable_root.mkdir()
    suffix = ".exe" if os.name == "nt" else ""
    gui = executable_root / f"Servonaut{suffix}"
    desktop_child = executable_root / f"desktop-child{suffix}"
    outside = tmp_path / f"outside-helper{suffix}"
    for helper in (gui, desktop_child, outside):
        helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        helper.chmod(0o755)
    commands = {
        "missing": executable_root / f"missing-helper{suffix}",
        "outside": outside,
        "gui": gui,
        "desktop_child": desktop_child,
    }
    command = commands[command_kind]
    return SimpleNamespace(
        kind=DistributionKind.PACKAGED_DESKTOP,
        executable=gui,
        executable_root=executable_root,
        is_frozen=True,
        desktop_child=desktop_child,
        console_helper=executable_root / f"servonaut{suffix}",
        data_root=tmp_path / "data",
        current_app_argv=lambda *args: [str(command), *args],
    )


def test_app_uses_one_injected_runtime_layout(tmp_path: Path) -> None:
    layout = _source_layout(tmp_path)

    app = ServonautApp(runtime_layout=layout)

    assert app.runtime_layout is layout


def _isolated_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ServonautApp:
    """Build the real app over temp storage with every outbound call stubbed."""
    from servonaut.services.cache_service import CacheService

    runtime = _source_layout(tmp_path)
    runtime_root = runtime.data_root
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "version": 6,
                "memory": {"enabled": False},
                "relay": {
                    "base_url": "https://loopback.invalid",
                    "mercure_url": "https://loopback.invalid/.well-known/mercure",
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr("servonaut.config.manager.CONFIG_DIR", runtime_root)
    monkeypatch.setattr("servonaut.config.manager.CONFIG_PATH", config_path)
    monkeypatch.setattr("servonaut.config.manager.BACKUP_DIR", runtime_root / "backups")
    monkeypatch.setattr("servonaut.config.manager._LEGACY_CONFIG", tmp_path / "legacy.json")
    monkeypatch.setattr("servonaut.config.manager._LEGACY_EC2SSH_DIR", tmp_path / "legacy-dir")
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr("servonaut.services.auth_service.AUTH_FILE", runtime_root / "auth.json")
    monkeypatch.setattr("servonaut.services.memory.store.MEMORY_ROOT", runtime_root / "memory")
    monkeypatch.setattr(CacheService, "CACHE_PATH", runtime_root / "cache.json")
    monkeypatch.setattr(
        "servonaut.utils.ephemeral_key.cleanup_stale_bw_keys", lambda: None
    )
    monkeypatch.setattr(
        "servonaut.services.update_service.UpdateService.check_for_update", lambda _self: None
    )

    async def no_instances(_self, *, force_refresh: bool = False) -> list[dict]:
        del force_refresh
        return []

    monkeypatch.setattr(
        "servonaut.services.aws_service.AWSService.fetch_instances_cached", no_instances
    )

    return ServonautApp(config_path=config_path, runtime_layout=runtime)


@pytest.mark.asyncio
async def test_servonaut_app_starts_with_an_injected_runtime_and_temp_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise the real app mount path without user data or outbound I/O."""
    from servonaut.screens.instance_list import InstanceListScreen

    app = _isolated_app(tmp_path, monkeypatch)
    runtime = app.runtime_layout
    async with app.run_test(headless=True, size=(120, 40)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, InstanceListScreen)
        assert app.update_service.runtime is runtime
        assert app.terminal_service._wrapper_dir == runtime.data_root / "logs"
        assert app.voice_setup_service.runtime is runtime


@pytest.mark.asyncio
async def test_a_failing_update_check_leaves_the_app_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checks: list[None] = []

    def malformed_release_data(_self):
        checks.append(None)
        raise TypeError("unexpected release data")

    app = _isolated_app(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "servonaut.services.update_service.UpdateService.check_for_update",
        malformed_release_data,
    )
    async with app.run_test(headless=True, size=(120, 40)) as pilot:
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert checks == [None]
        assert app.is_running
        assert app.return_code is None


@pytest.mark.asyncio
async def test_update_runs_alone_without_cancelling_other_workers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    from textual.widgets import Button
    from textual.worker import WorkerState

    finish_upgrade = asyncio.Event()
    upgrades: list[None] = []

    async def slow_upgrade(_self):
        upgrades.append(None)
        await finish_upgrade.wait()
        return True, "Updated [1/1] packages."

    monkeypatch.setattr(
        "servonaut.services.update_service.UpdateService.run_upgrade", slow_upgrade
    )
    app = _isolated_app(tmp_path, monkeypatch)
    async with app.run_test(headless=True, size=(120, 40)) as pilot:
        await pilot.pause()
        unrelated = app.run_worker(asyncio.sleep(30), name="unrelated")
        app._latest_version = "99.0.0"
        app._show_update_button("99.0.0")
        button = app.screen.query_one("#nav_update", Button)

        app._run_update()
        app._run_update()
        await pilot.pause()

        assert unrelated.state is WorkerState.RUNNING
        assert button.disabled
        assert len(upgrades) == 1
        finish_upgrade.set()
        update = next(worker for worker in app.workers if worker.name == "update")
        await app.workers.wait_for_complete([update])
        await pilot.pause()
        assert not button.disabled
        assert app._update_in_progress is False
        unrelated.cancel()


def test_background_launch_uses_runtime_argv_and_a_real_benign_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _BenignRuntime(tmp_path)
    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: runtime)

    main._relay_start_background()

    pid_path = tmp_path / "relay.pid"
    pid = int(pid_path.read_text(encoding="utf-8"))
    assert runtime.calls == [("connect",)]
    assert wait_for_process_exit(pid, 1.0)
    pid_path.unlink(missing_ok=True)


def test_background_launch_runs_the_listener_from_the_data_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A detached listener must not pin the directory it was launched from."""
    runtime = _BenignRuntime(tmp_path / "data")
    spawn = MagicMock(return_value=SimpleNamespace(pid=4321))
    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: runtime)
    monkeypatch.setattr("servonaut.services.process_control.spawn_detached", spawn)

    main._relay_start_background()

    assert spawn.call_args.kwargs == {"cwd": runtime.data_root}


@pytest.mark.parametrize("compound", [main._relay_force_bg, main._relay_reconnect])
def test_compound_relay_commands_collect_one_runtime_and_share_its_paths_and_argv(
    compound, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _BenignRuntime(tmp_path)
    detect = MagicMock(return_value=runtime)
    monkeypatch.setattr("servonaut.runtime.detect_runtime", detect)

    compound()

    pid_path = tmp_path / "relay.pid"
    pid = int(pid_path.read_text(encoding="utf-8"))
    assert runtime.calls == [("connect",)]
    detect.assert_called_once_with()
    assert wait_for_process_exit(pid, 1.0)
    pid_path.unlink(missing_ok=True)


def test_background_launch_reaps_its_child_when_pid_recording_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _BenignRuntime(tmp_path)
    child: subprocess.Popen[bytes] | None = None
    original_write_text = Path.write_text

    def spawn(_argv: list[str], **_kwargs: object) -> subprocess.Popen[bytes]:
        nonlocal child
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return child

    def fail_pid_record(path: Path, data: str, *args, **kwargs) -> int:
        if path == tmp_path / "relay.pid":
            raise OSError("temporary PID record failure")
        return original_write_text(path, data, *args, **kwargs)

    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: runtime)
    monkeypatch.setattr("servonaut.services.process_control.spawn_detached", spawn)
    monkeypatch.setattr(Path, "write_text", fail_pid_record)

    with pytest.raises(SystemExit) as exit_code:
        main._relay_start_background()

    assert exit_code.value.code == 1
    assert child is not None
    assert child.poll() is not None
    assert not (tmp_path / "relay.pid").exists()


def test_background_launch_kills_its_owned_child_after_terminate_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _BenignRuntime(tmp_path)
    original_write_text = Path.write_text

    class _OwnedChild:
        pid = 12345

        def __init__(self) -> None:
            self.terminated = False
            self.killed = False
            self.wait_calls = 0

        def terminate(self) -> None:
            self.terminated = True

        def kill(self) -> None:
            self.killed = True

        def wait(self, timeout: float) -> int:
            del timeout
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise subprocess.TimeoutExpired("benign-child", 0)
            return 0

    child = _OwnedChild()

    def fail_pid_record(path: Path, data: str, *args, **kwargs) -> int:
        if path == tmp_path / "relay.pid":
            raise OSError("temporary PID record failure")
        return original_write_text(path, data, *args, **kwargs)

    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: runtime)
    monkeypatch.setattr(
        "servonaut.services.process_control.spawn_detached", lambda _argv, **_kwargs: child
    )
    monkeypatch.setattr(Path, "write_text", fail_pid_record)

    with pytest.raises(SystemExit) as exit_code:
        main._relay_start_background()

    assert exit_code.value.code == 1
    assert child.terminated
    assert child.killed
    assert child.wait_calls == 2


def test_background_launch_refuses_a_held_relay_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _BenignRuntime(tmp_path)
    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: runtime)
    lock = RelayLock(mode="tui", path=tmp_path / "relay.lock").acquire()
    spawn = MagicMock()
    monkeypatch.setattr("servonaut.services.process_control.spawn_detached", spawn)

    try:
        main._relay_start_background()
    finally:
        lock.release()

    spawn.assert_not_called()
    assert not (tmp_path / "relay.pid").exists()


@pytest.mark.parametrize("command_kind", ["missing", "outside", "gui", "desktop_child"])
def test_background_launch_rejects_invalid_packaged_command_before_spawning(
    command_kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = _packaged_runtime_with_command(tmp_path, command_kind)
    spawn = MagicMock()
    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: runtime)
    monkeypatch.setattr("servonaut.services.process_control.spawn_detached", spawn)

    with pytest.raises(SystemExit) as exit_code:
        main._relay_start_background()

    assert exit_code.value.code == 1
    spawn.assert_not_called()
    assert not (runtime.data_root / "relay.pid").exists()


def test_desktop_exec_uses_desktop_entry_escaping_not_shell_quoting() -> None:
    rendered = main._desktop_exec(
        ["/tmp/runner with space", "München % $ ' \" ` \\ value"]
    )

    assert rendered.startswith('"/tmp/runner with space" ')
    assert "München" in rendered
    assert "%%" in rendered
    assert "\\\\$" in rendered
    assert "\\\"" in rendered
    assert "\\`" in rendered
    assert "'" in rendered
    assert rendered.endswith('\\\\\\\\ value"')


# Each terminal's flag must take the application argv as separate arguments;
# xfce4-terminal's ``-e`` takes one command string, so it needs ``-x``.
_DESKTOP_TERMINAL_PREFIXES = {
    "kitty": '"kitty" "-e"',
    "alacritty": '"alacritty" "-e"',
    "gnome-terminal": '"gnome-terminal" "--"',
    "konsole": '"konsole" "-e"',
    "xfce4-terminal": '"xfce4-terminal" "-x"',
    "xterm": '"xterm" "-e"',
}


@pytest.mark.parametrize(("terminal", "prefix"), sorted(_DESKTOP_TERMINAL_PREFIXES.items()))
def test_linux_shortcut_writes_a_desktop_entry_exec_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, terminal: str, prefix: str
) -> None:
    app_argv = [str(Path(sys.executable).resolve()), "-c", "print('benign')"]
    desktop_file = tmp_path / ".local" / "share" / "applications" / "servonaut.desktop"
    written_encodings: list[str | None] = []
    original_write_text = Path.write_text

    def record_desktop_encoding(path: Path, *args: object, **kwargs: object) -> int:
        if path == desktop_file:
            written_encodings.append(kwargs.get("encoding"))
        return original_write_text(path, *args, **kwargs)

    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: _desktop_runtime(app_argv))
    monkeypatch.setattr("servonaut.utils.platform_utils.get_os", lambda: "linux")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(
        shutil, "which", lambda name: f"/usr/bin/{terminal}" if name == terminal else None
    )
    monkeypatch.setattr(Path, "write_text", record_desktop_encoding)

    main._install_desktop()

    content = desktop_file.read_text(encoding="utf-8")
    assert f"Exec={prefix} {main._desktop_exec(app_argv)}\n" in content
    assert written_encodings == ["utf-8"]


@pytest.mark.skipif(sys.platform != "linux", reason="Desktop entry validation is Linux-only")
def test_desktop_exec_is_accepted_by_desktop_file_validator(tmp_path: Path) -> None:
    desktop_validate = shutil.which("desktop-file-validate")
    if desktop_validate is None:
        pytest.skip("desktop-file-validate is unavailable")

    command = [
        str(Path(sys.executable).resolve()),
        "-c",
        "import sys; raise SystemExit(0)",
        "space value",
        "naïve",
        "50%",
        "$money",
        "say \"hello\"",
        "single'quote",
    ]
    desktop_file = tmp_path / "org.servonaut.ExecValidation.desktop"
    desktop_file.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Servonaut Exec Validation\n"
        f"Exec={main._desktop_exec(command)}\n"
        "Terminal=false\n",
        encoding="utf-8",
    )

    validation = subprocess.run(
        [desktop_validate, str(desktop_file)], capture_output=True, text=True, check=False
    )

    assert validation.returncode == 0, validation.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="GTK desktop launching is Linux-only")
def test_desktop_exec_round_trips_through_gtk_launcher_when_available(tmp_path: Path) -> None:
    gtk_launch = shutil.which("gtk-launch")
    desktop_validate = shutil.which("desktop-file-validate")
    desktop_database = shutil.which("update-desktop-database")
    x_display_info = shutil.which("xdpyinfo")
    xvfb_run = shutil.which("xvfb-run")
    if (
        gtk_launch is None
        or desktop_validate is None
        or desktop_database is None
        or x_display_info is None
        or xvfb_run is None
    ):
        pytest.skip("desktop launch tooling is unavailable")
    display_check = subprocess.run(
        [xvfb_run, "-a", x_display_info], capture_output=True, text=True, check=False
    )
    if display_check.returncode != 0:
        pytest.skip("a usable X display is unavailable")

    capture_script = tmp_path / "capture.py"
    output_path = tmp_path / "observed.json"
    _write_argv_capture_script(capture_script)
    expected = [
        "space value",
        "naïve",
        "50%",
        "$money",
        "say \"hello\"",
        "single'quote",
        "back\\slash",
        "back`tick",
    ]
    command = [str(Path(sys.executable).resolve()), str(capture_script), str(output_path), *expected]
    home = tmp_path / "home"
    data_home = home / ".local" / "share"
    application_dir = data_home / "applications"
    application_dir.mkdir(parents=True)
    desktop_file = application_dir / "org.servonaut.exec-fixture.desktop"
    desktop_file.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Servonaut Exec Fixture\n"
        f"Exec={main._desktop_exec(command)}\n"
        "Terminal=false\n",
        encoding="utf-8",
    )
    desktop_file.chmod(0o755)

    validation = subprocess.run(
        [desktop_validate, str(desktop_file)], capture_output=True, text=True, check=False
    )
    assert validation.returncode == 0, validation.stderr
    database_update = subprocess.run(
        [desktop_database, str(application_dir)], capture_output=True, text=True, check=False
    )
    assert database_update.returncode == 0, database_update.stderr
    environment = {
        **os.environ,
        "HOME": str(home),
        "XDG_DATA_HOME": str(data_home),
        "XDG_DATA_DIRS": "/usr/local/share:/usr/share",
    }
    launch = subprocess.run(
        [xvfb_run, "-a", gtk_launch, desktop_file.name],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    assert launch.returncode == 0, launch.stderr

    deadline = time.monotonic() + 2
    while not output_path.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert output_path.exists(), launch.stderr
    assert json.loads(output_path.read_text(encoding="utf-8")) == expected


@pytest.mark.skipif(os.name == "nt", reason="macOS command helpers require a POSIX shell")
def test_macos_command_helper_executes_a_benign_quoted_argv(tmp_path: Path) -> None:
    capture_script = tmp_path / "capture argv.py"
    output_path = tmp_path / "observed.json"
    helper = tmp_path / "Servonaut.command"
    _write_argv_capture_script(capture_script)
    expected = ["space value", "naïve", "$money", "say \"hello\"", "single'quote"]
    main._write_macos_command_helper(
        helper,
        [sys.executable, str(capture_script), str(output_path), *expected],
    )

    execution = subprocess.run([str(helper)], capture_output=True, text=True, check=False)

    assert execution.returncode == 0, execution.stderr
    assert json.loads(output_path.read_text(encoding="utf-8")) == expected


def test_macos_shortcut_uses_a_bundle_relative_command_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app_argv = [str(Path(sys.executable).resolve()), "-c", "print('benign')"]
    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: _desktop_runtime(app_argv))
    monkeypatch.setattr("servonaut.utils.platform_utils.get_os", lambda: "darwin")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    main._install_desktop()

    app_dir = tmp_path / "Applications" / "Servonaut.app" / "Contents" / "MacOS"
    helper = app_dir / "Servonaut.command"
    launcher = app_dir / "Servonaut"
    assert f"exec {shlex.join(app_argv)}" in helper.read_text(encoding="utf-8")
    launcher_content = launcher.read_text(encoding="utf-8")
    assert 'exec open -a Terminal "$script_dir/Servonaut.command"' in launcher_content
    assert sys.executable not in launcher_content


def test_cli_update_prints_unavailable_runtime_guidance_without_running_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class _Updater:
        current_version = "2.27.0"
        update_status = "Install a newer packaged build."
        update_guidance = update_status

        def __init__(self, runtime) -> None:
            self.runtime = runtime

        def check_for_update(self):
            return None

    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: SimpleNamespace())
    monkeypatch.setattr("servonaut.services.update_service.UpdateService", _Updater)

    main._run_update()

    assert "newer packaged build" in capsys.readouterr().out


def test_cli_update_exits_nonzero_when_a_source_runtime_has_no_update_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from servonaut.services.update_service import UpdateService

    runtime = _source_layout(tmp_path)
    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: runtime)
    monkeypatch.setattr(UpdateService, "check_for_update", lambda _self: "9.9.9")

    with pytest.raises(SystemExit) as exit_code:
        main._run_update()

    assert exit_code.value.code == 1
    assert "source" in capsys.readouterr().out.lower()


@pytest.mark.asyncio
async def test_secrets_worker_uses_the_app_runtime_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    from textual.app import App

    from servonaut.screens.secrets import SecretsScreen

    class _SecretsApp(App):
        def __init__(self, runtime: object) -> None:
            super().__init__()
            self.runtime_layout = runtime
            self.auth_service = MagicMock(is_authenticated=False)
            self.auth_service.has_feature.return_value = False
            self.entitlement_guard = MagicMock()
            self.entitlement_guard.check.return_value = (False, "")
            self.api_client = MagicMock()
            self.ssh_service = MagicMock()

        def on_mount(self) -> None:
            self.push_screen(SecretsScreen())

    class _Process:
        returncode = 0

        async def communicate(self) -> tuple[bytes, None]:
            return b"", None

    async def create_subprocess_exec(*argv: str, **kwargs: object) -> _Process:
        return _Process()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_subprocess_exec)
    app = _SecretsApp(_BenignRuntime(tmp_path))
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SecretsScreen)
        monkeypatch.setattr(screen, "_render_state", MagicMock())
        monkeypatch.setattr(screen, "notify", MagicMock())

        await screen._install_bws_worker()

    assert app.runtime_layout.calls == [("secrets", "install", "bws", "--yes")]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "command_kind", ["missing", "outside", "gui", "desktop_child"]
)
async def test_secrets_worker_rejects_invalid_packaged_commands_before_spawning(
    command_kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    from textual.app import App

    from servonaut.screens.secrets import SecretsScreen

    runtime = _packaged_runtime_with_command(tmp_path, command_kind)

    class _SecretsApp(App):
        def __init__(self) -> None:
            super().__init__()
            self.runtime_layout = runtime
            self.auth_service = MagicMock(is_authenticated=False)
            self.auth_service.has_feature.return_value = False
            self.entitlement_guard = MagicMock()
            self.entitlement_guard.check.return_value = (False, "")
            self.api_client = MagicMock()
            self.ssh_service = MagicMock()

        def on_mount(self) -> None:
            self.push_screen(SecretsScreen())

    create_subprocess = MagicMock()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_subprocess)
    app = _SecretsApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SecretsScreen)
        monkeypatch.setattr(screen, "_render_state", MagicMock())
        notify = MagicMock()
        monkeypatch.setattr(screen, "notify", notify)

        await screen._install_bws_worker()

    create_subprocess.assert_not_called()
    notify.assert_called_once()
    assert "command helper could not be launched" in notify.call_args.args[0]
