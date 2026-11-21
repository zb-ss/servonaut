from __future__ import annotations

import asyncio
import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import MethodType, SimpleNamespace
from unittest.mock import Mock

import pytest

from servonaut.debian_layout import GENERATIONS, LEASE, MARKER, PAYLOAD, RESTART_GENERATION_ENV, STATUS
from servonaut.services import apt_runtime as apt

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Debian runtime uses Linux paths and leases")


@pytest.fixture
def install(tmp_path, monkeypatch):
    actual = tmp_path / "mounted-apps"
    actual.mkdir()
    opt = tmp_path / "opt"
    opt.symlink_to(actual)
    helpers = tmp_path / "libexec"
    root = actual / "servonaut"
    stage = root / PAYLOAD
    stage.mkdir(parents=True)
    generation = root / GENERATIONS / ("a" * 64)
    generation.mkdir(parents=True)
    helper = helpers / "servonaut" / "apt-generation"
    helper.parent.mkdir(parents=True)
    helper.write_text("helper\n")
    helper.chmod(0o755)
    (root / "servonaut").symlink_to(helper)
    image = generation / "servonaut"
    image.write_text("binary\n")
    image.chmod(0o755)
    os.link(image, stage / "servonaut")
    (generation / LEASE).touch()
    marker = {
        "schema_version": 1, "distribution": "packaged-desktop", "product_version": "1.0.0rc3",
        "build_revision": "fixture-revision", "packaging_revision": 4, "channel": "preview",
        "console_helper": "servonaut", "desktop_child": "servonaut-desktop-child",
    }
    (root / MARKER).write_text(json.dumps(marker))
    os.link(root / MARKER, generation / MARKER)
    (root / GENERATIONS / STATUS).write_text(json.dumps({
        "schema_version": 1, "current": generation.name, "allocated_bytes": 1000,
        "unconsolidated_bytes": 0,
    }))
    monkeypatch.setattr(apt, "INSTALL_ROOT", opt)
    monkeypatch.setattr(apt, "HELPER_ROOT", helpers)
    monkeypatch.setattr(apt, "_root_regular", lambda path: path.lstat())
    monkeypatch.setattr(apt, "_root_directory", lambda path: path.lstat())
    monkeypatch.setattr(apt, "validate_stable_apt_launcher", lambda _: helper)
    return root, image, opt / "servonaut" / "servonaut"


def installed(package):
    assert package == "servonaut"
    return apt.DpkgPackageState("installed", "1.0.0~rc3-4")


def test_real_and_logical_paths_share_one_generation_and_pinned_child(install, monkeypatch):
    root, image, stable = install
    logical_image = stable.parent / GENERATIONS / image.parent.name / image.name
    assert apt.generation_directory(logical_image) == apt.generation_directory(image) == image.parent
    assert apt.stable_apt_launcher(image, "servonaut") == stable
    monkeypatch.setattr(sys, "executable", str(image))
    assert apt.pin_apt_command(str(stable)) == str(image)
    alias = stable.parent.parent / "alias"
    (root.parent / "alias").symlink_to(stable)
    assert apt.pin_apt_command(str(alias)) == str(image)
    other = Path("/usr/bin/ssh")
    assert apt.pin_apt_command(str(other)) == str(other)


def test_build_revision_and_executable_identity_require_restart(install):
    _, image, _ = install
    stat = image.stat()
    running = apt.AptBuildIdentity("1.0.0rc3", "old-fixture", 4, (stat.st_dev, stat.st_ino + 1))
    result = apt.inspect_apt_upgrade(image, running, installed)
    assert result.change is apt.AptChange.RESTART_REQUIRED
    assert result.installed == apt.AptBuildIdentity(
        "1.0.0rc3", "fixture-revision", 4, (stat.st_dev, stat.st_ino),
    )
    observed = apt.inspect_apt_upgrade(image, result.installed, installed)
    assert observed.change is apt.AptChange.UNCHANGED and observed.allocated_bytes == 1000


def test_unpacked_mismatched_and_changed_dpkg_states_defer(install):
    _, image, _ = install
    current = apt.AptBuildIdentity("1.0.0rc3", "fixture-revision", 4, (0, 0))
    unpacked = apt.DpkgPackageState("unpacked", "1.0.0~rc3-4")
    mixed = apt.DpkgPackageState("installed", "1.0.0~rc3-3")
    changing = iter([installed("servonaut"), unpacked])
    for reader in (lambda _: unpacked, lambda _: mixed, lambda _: next(changing)):
        assert apt.inspect_apt_upgrade(image, current, reader).change is apt.AptChange.DEFERRED


def test_missing_marker_reports_removal_only_after_confirmed_dpkg_state(install):
    root, image, _ = install
    (root / MARKER).unlink()
    current = apt.AptBuildIdentity("1.0.0rc3", "fixture-revision", 4, (0, 0))
    removed = apt.DpkgPackageState("config-files")
    assert apt.inspect_apt_upgrade(image, current, installed).change is apt.AptChange.DEFERRED
    assert apt.inspect_apt_upgrade(image, current, lambda _: removed).change is apt.AptChange.REMOVED


def test_generation_ownership_uses_dpkg_paths_through_symlinked_opt(install):
    _, image, stable = install
    assert apt.dpkg_generation_paths(image) == (
        stable.parent / PAYLOAD / stable.name, stable.parent / MARKER,
    )


def test_monitor_checks_ownership_once_and_detects_later_removal(install, monkeypatch):
    root, image, _ = install
    from servonaut.updates import apt as apt_detection

    running = apt.AptBuildIdentity("1.0.0rc3", "older-fixture", 4, (0, 0))
    runtime = SimpleNamespace(executable=image)
    monitor = apt.AptRuntimeMonitor(runtime, running)
    flags = []

    def package_state(layout, name, *, verify_ownership):
        assert layout is runtime and name == "servonaut"
        flags.append(verify_ownership)
        if (root / MARKER).exists():
            return installed(name)
        return apt.DpkgPackageState("config-files")

    monkeypatch.setattr(apt_detection, "read_apt_runtime_package", package_state)
    assert monitor.check().change is apt.AptChange.RESTART_REQUIRED
    assert monitor.check().change is apt.AptChange.RESTART_REQUIRED
    assert flags == [True, False]
    assert monitor.check(force=True).change is apt.AptChange.RESTART_REQUIRED
    (root / MARKER).unlink()
    assert monitor.check().change is apt.AptChange.REMOVED
    assert monitor.check().change is apt.AptChange.REMOVED
    assert flags == [True, False, False, False, False, False]


def test_restart_exec_uses_stable_role_and_drops_old_lease(install, monkeypatch):
    root, image, stable = install
    monkeypatch.chdir(image.parent)
    monkeypatch.setenv("LD_LIBRARY_PATH", str(image.parent / "_internal"))
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/usr/lib")
    monkeypatch.setattr(apt.logging, "shutdown", lambda: None)
    replaced = []

    with (image.parent / LEASE).open("rb") as lease:
        os.set_inheritable(lease.fileno(), True)

        def execve(command, argv, environment):
            replaced.append(command)
            assert argv == [str(stable), "--demo"]
            assert environment[RESTART_GENERATION_ENV] == "1"
            assert environment["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
            assert environment["LD_LIBRARY_PATH"] == "/usr/lib"
            assert "LD_LIBRARY_PATH_ORIG" not in environment
            assert Path.cwd() == root
            assert not os.get_inheritable(lease.fileno())

        monkeypatch.setattr(apt.os, "execve", execve)
        apt.exec_apt_restart(image, ["--demo"])
    assert replaced == [stable]


@pytest.mark.skipif(shutil.which("ssh-agent") is None, reason="OpenSSH agent is required")
def test_exec_waits_for_cleanup_of_keys_agents_and_background_children(install, monkeypatch, tmp_path):
    from servonaut.services.vault.ssh_agent import PrivateSshAgent
    from servonaut.utils.ephemeral_key import persistent_bw_ssh_key
    from servonaut.utils.process_cleanup import cleanup_process_resources
    from servonaut.utils.ssh_utils import track_background_process

    _, image, stable = install
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(apt.logging, "shutdown", lambda: None)
    key = Path(persistent_bw_ssh_key("synthetic key data"))
    with tempfile.TemporaryDirectory(prefix="restart-agent-") as socket_root:
        with PrivateSshAgent.start(Path(socket_root)) as agent:
            command = [sys.executable, "-c", "import time; time.sleep(30)"]
            tracked = subprocess.Popen(command)
            other = subprocess.Popen(command)
            track_background_process(tracked)
            pidfd = os.dup(agent._pidfd) if agent._pidfd is not None else None
            called = []
            try:
                def execve(executable, _argv, _env):
                    assert executable == stable
                    assert not key.exists()
                    assert agent._closed and not agent.socket_path.exists()
                    if pidfd is not None:
                        assert select.select([pidfd], [], [], 1)[0]
                    assert tracked.wait(timeout=1) is not None
                    assert other.poll() is None
                    cleanup_process_resources()
                    called.append(executable)

                monkeypatch.setattr(apt.os, "execve", execve)
                apt.exec_apt_restart(image, [])
                assert called == [stable]
            finally:
                for child in (tracked, other):
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=5)
                if pidfd is not None:
                    os.close(pidfd)


def test_restart_argument_allowlist_keeps_only_interactive_session_options(tmp_path, monkeypatch):
    from servonaut.main import _restart_tui_arguments

    monkeypatch.chdir(tmp_path)
    args = SimpleNamespace(
        config="fixture.json", demo=True, debug=True, install_desktop=True,
        restore_backup=1, update=True, mcp_install="claude",
    )
    assert _restart_tui_arguments(args) == ["--config", str(tmp_path / "fixture.json"), "--demo", "--debug"]


def test_tui_restart_call_site_drops_already_consumed_arguments(tmp_path, monkeypatch):
    from servonaut import app as application, main, runtime

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", [
        "servonaut", "--demo", "--debug", "--config=fixture.json",
        "--ai-provider", "ollama", "--no-tools",
    ])
    monkeypatch.setenv("SERVONAUT_AI_PROVIDER", "fixture")
    monkeypatch.setenv("SERVONAUT_AI_NO_TOOLS", "1")
    monkeypatch.setattr(main, "_setup_logging", Mock())
    layout = SimpleNamespace(executable=tmp_path / "servonaut")
    monkeypatch.setattr(runtime, "detect_runtime", lambda: layout)
    app = Mock(return_code=apt.APT_RESTART_EXIT_CODE)
    monkeypatch.setattr(application, "ServonautApp", Mock(return_value=app))
    restart = Mock()
    monkeypatch.setattr(apt, "exec_apt_restart", restart)

    main._main()

    app.run.assert_called_once()
    restart.assert_called_once_with(
        layout.executable, ["--config", str(tmp_path / "fixture.json"), "--demo", "--debug"],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("managed", [True, False])
async def test_update_notice_waits_for_completed_apt_source_evidence(managed, monkeypatch):
    from servonaut.app import ServonautApp
    from servonaut.updates import apt as detection

    tasks = []
    app = SimpleNamespace(
        runtime_layout=SimpleNamespace(product_version="2.34.0"),
        apt_upgrade_state=None, _apt_notices=set(), _apt_notices_pending=set(),
        run_worker=lambda job, **_kwargs: tasks.append(asyncio.create_task(job)),
        notify=Mock(),
    )
    app._show_apt_upgrade = MethodType(ServonautApp._show_apt_upgrade, app)
    app._notify_apt_upgrade = MethodType(ServonautApp._notify_apt_upgrade, app)
    entered = asyncio.Event()
    release = asyncio.Event()
    uncached = True

    async def probe(function, runtime):
        assert function is detection.refresh_apt_status
        assert runtime is app.runtime_layout
        entered.set()
        await asyncio.wait_for(release.wait(), 3)
        return detection.AptInstallStatus(managed=managed and not uncached, checked=not uncached)

    monkeypatch.setattr(asyncio, "to_thread", probe)
    installed = apt.AptBuildIdentity("99.0.0", "fixture", 1, (1, 2))
    state = apt.AptUpgradeState(apt.AptChange.RESTART_REQUIRED, installed)
    try:
        app._show_apt_upgrade(state)
        await asyncio.wait_for(entered.wait(), 3)
        assert app.apt_upgrade_state == state
        app.notify.assert_not_called()
        app._show_apt_upgrade(state)
        assert len(tasks) == 1
    finally:
        release.set()
    await asyncio.wait_for(tasks[0], 3)
    app.notify.assert_not_called()
    assert installed not in app._apt_notices

    uncached = False
    app._show_apt_upgrade(state)
    await asyncio.wait_for(tasks[1], 3)
    app.notify.assert_called_once()
    expected = "Servonaut was updated by apt." if managed else "Servonaut was updated."
    assert app.notify.call_args.args[0].startswith(expected)
    app._show_apt_upgrade(state)
    assert len(tasks) == 2


@pytest.mark.parametrize(("setting", "expected_wait"), [("", 0.5), ("0.2", 0.2), ("inf", 0.5)])
def test_busy_lease_wait_is_configurable_and_bounded(setting, expected_wait, monkeypatch):
    import fcntl
    import time

    from servonaut.debian_layout import APT_LEASE_WAIT_ENV, acquire_shared_lease

    clock = [0.0]
    monkeypatch.setenv(APT_LEASE_WAIT_ENV, setting)
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))

    def busy(_descriptor, flags):
        assert flags == fcntl.LOCK_SH | fcntl.LOCK_NB
        raise BlockingIOError

    monkeypatch.setattr(fcntl, "flock", busy)
    assert not acquire_shared_lease(10)
    assert clock[0] == pytest.approx(expected_wait)
