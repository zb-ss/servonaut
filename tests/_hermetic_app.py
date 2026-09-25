"""Run the real :class:`ServonautApp` in a child process with a throwaway HOME.

About twenty modules bind ``Path.home()`` when they are imported (the config
directory, the instance cache, the auth file, the memory store, …), and the
test suite imports ``servonaut`` while it collects tests. An in-process test
therefore cannot move the data root any more: patching ``HOME`` afterwards
misses every path that is already bound. A child process can set ``HOME``
before its first ``servonaut`` import, so every one of those paths lands in
the throwaway directory instead of the developer's real one.

The child also watches itself through a :func:`sys.addaudithook` hook:

- every file it opens, lists or changes under the *real* home directory is
  recorded, except for the interpreter, its import paths and the source
  checkout (those legitimately live under ``$HOME`` on many machines);
- every outbound connection and name lookup is recorded, and anything that is
  not loopback is refused, so a test can never reach a real service.

The update check and the AWS instance fetch are stubbed as well, so the boot
path needs no network at all.

A test calls :func:`run_hermetic_app` with a scenario name; the child writes a
JSON report that the test asserts on. This module is not collected by pytest
(no ``test_`` prefix) and must not import ``servonaut`` at module level: the
child imports this file before it is allowed to resolve any home paths.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"

# Written into the throwaway HOME's config by the ``boot`` scenario. The app
# reporting it back proves it read the throwaway config, not a real one.
SENTINEL_USERNAME = "hermetic-sentinel-user"

_ENV_GUARDED_HOME = "SERVONAUT_TEST_GUARDED_HOME"
_ENV_WORKDIR = "SERVONAUT_TEST_WORKDIR"

# Must stay below the per-test ``timeout`` in pyproject.toml
# ([tool.pytest.ini_options], 60 s) so a hung child is reported as a child
# failure with its output, not as a bare pytest-timeout. The harness self-test
# checks the two against each other.
_CHILD_TIMEOUT_SECONDS = 50.0

# Poll interval while waiting for a screen. Short enough to land well inside
# the timing windows the scenarios probe, long enough not to spin a core.
_POLL_SECONDS = 0.005

# Variables Python or the OS loader needs on some platforms. Everything else
# (XDG dirs, SSH/AWS/DBus sockets, SERVONAUT_* overrides) is deliberately not
# inherited: any of them could point the child back at the real machine.
_PASSTHROUGH_ENV = ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT")


# ---------------------------------------------------------------------------
# Parent side
# ---------------------------------------------------------------------------


def run_hermetic_app(
    tmp_path: Path,
    scenario: str,
    *args: str,
    guarded_home: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run *scenario* in a child process and return its JSON report.

    Args:
        tmp_path: Per-test directory; the throwaway HOME, the child's working
            directory and the report live under it.
        scenario: A key of :data:`SCENARIOS`.
        *args: String arguments passed to the scenario.
        guarded_home: Directory the child must not touch. Defaults to the real
            home directory of the process running the tests.

    Returns:
        The report: ``result`` (scenario output), ``error`` (``None`` or the
        exception that escaped the scenario), ``home_accesses`` and
        ``network_attempts`` (lists recorded by the audit hook), ``home`` (the
        throwaway HOME used) and ``stderr`` (tail of the child's stderr).
    """
    home = tmp_path / "home"
    workdir = tmp_path / "work"
    home.mkdir(exist_ok=True)
    workdir.mkdir(exist_ok=True)
    report_path = workdir / f"report-{scenario}.json"
    guarded = guarded_home if guarded_home is not None else Path.home()

    command = [sys.executable, "-m", "tests._hermetic_app", scenario, str(report_path), *args]
    completed = _run_child(command, _child_env(home, workdir, guarded), scenario)
    report = _read_report(report_path, completed, scenario)
    report["home"] = str(home)
    return report


def _child_env(home: Path, workdir: Path, guarded: Path) -> Dict[str, str]:
    """Minimal environment: a throwaway HOME and nothing that points back out."""
    env = {name: os.environ[name] for name in _PASSTHROUGH_ENV if name in os.environ}
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "PATH": os.defpath,
            "PYTHONPATH": os.pathsep.join([str(SRC_DIR), str(REPO_ROOT)]),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
            "LANG": "C.UTF-8",
            "TMPDIR": str(workdir),
            "TEMP": str(workdir),
            "TMP": str(workdir),
            _ENV_GUARDED_HOME: str(guarded),
            _ENV_WORKDIR: str(workdir),
        }
    )
    return env


def _run_child(
    command: List[str], env: Dict[str, str], scenario: str
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_CHILD_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(
            f"hermetic child timed out running {scenario!r}:\n"
            f"{_tail(exc.stdout)}\n{_tail(exc.stderr)}"
        ) from exc


def _read_report(
    report_path: Path, completed: subprocess.CompletedProcess, scenario: str
) -> Dict[str, Any]:
    if not report_path.exists():
        raise AssertionError(
            f"hermetic child wrote no report for {scenario!r} "
            f"(exit {completed.returncode}):\n"
            f"{_tail(completed.stdout)}\n{_tail(completed.stderr)}"
        )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["stderr"] = _tail(completed.stderr)
    return report


def _tail(text: Optional[str | bytes], limit: int = 4000) -> str:
    if not text:
        return ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    return text[-limit:]


# ---------------------------------------------------------------------------
# Child side: audit guard
# ---------------------------------------------------------------------------

# Audit events whose first one or two arguments are filesystem paths.
_FS_EVENTS = frozenset(
    {
        "open",
        "os.listdir",
        "os.scandir",
        "os.mkdir",
        "os.rename",
        "os.remove",
        "os.rmdir",
        "os.chmod",
        "os.utime",
        "os.truncate",
        "os.symlink",
        "os.link",
        "shutil.copyfile",
        "shutil.copytree",
        "shutil.move",
        "shutil.rmtree",
    }
)
_TWO_PATH_FS_EVENTS = frozenset(
    {"os.rename", "os.symlink", "os.link", "shutil.copyfile", "shutil.copytree", "shutil.move"}
)
_NET_EVENTS = frozenset(
    {
        "socket.connect",
        "socket.sendto",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyaddr",
    }
)
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_MAX_RECORDS = 50


class NetworkBlockedError(ConnectionRefusedError):
    """Raised inside the child for any non-loopback network operation."""


def _within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # different drives on Windows
        return False


class _Guard:
    """Audit hook that records home access and refuses remote network use."""

    def __init__(self, guarded_home: str, allowed_roots: List[str]) -> None:
        self._home = os.path.normpath(os.path.abspath(guarded_home))
        self._fixed_roots = [os.path.normpath(os.path.abspath(r)) for r in allowed_roots if r]
        self._roots_key: tuple = ()
        self._roots: List[str] = []
        self.home_accesses: List[List[str]] = []
        self.network_attempts: List[List[str]] = []

    def __call__(self, event: str, args: tuple) -> None:
        if event in _FS_EVENTS:
            self._check_paths(event, args)
        elif event in _NET_EVENTS:
            self._check_network(event, args)

    # -- filesystem --------------------------------------------------------

    def _allowed_roots(self) -> List[str]:
        key = tuple(sys.path)
        if key != self._roots_key:
            roots = list(self._fixed_roots)
            for entry in (sys.prefix, sys.base_prefix, sys.exec_prefix, *sys.path):
                if not entry:
                    continue
                root = os.path.normpath(os.path.abspath(entry))
                if root != self._home:
                    roots.append(root)
            self._roots_key, self._roots = key, roots
        return self._roots

    def _check_paths(self, event: str, args: tuple) -> None:
        count = 2 if event in _TWO_PATH_FS_EVENTS else 1
        for raw in args[:count]:
            if isinstance(raw, int) or raw is None:
                continue
            try:
                path = os.path.normpath(os.path.abspath(os.fsdecode(raw)))
            except TypeError:
                continue
            if not _within(path, self._home):
                continue
            if any(_within(path, root) for root in self._allowed_roots()):
                continue
            record = [event, path]
            if record not in self.home_accesses and len(self.home_accesses) < _MAX_RECORDS:
                self.home_accesses.append(record)

    # -- network -----------------------------------------------------------

    def _check_network(self, event: str, args: tuple) -> None:
        host: Any
        if event in ("socket.connect", "socket.sendto"):
            address = args[1] if len(args) > 1 else None
            if not isinstance(address, tuple):
                return  # AF_UNIX path or similar local IPC
            host = address[0]
        else:
            host = args[0] if args else None
        if isinstance(host, bytes):
            host = host.decode("ascii", "replace")
        if len(self.network_attempts) < _MAX_RECORDS:
            self.network_attempts.append([event, repr(host)])
        if host not in _LOOPBACK_HOSTS:
            raise NetworkBlockedError(f"network disabled in hermetic child ({event} {host!r})")


# ---------------------------------------------------------------------------
# Child side: stubs and scenarios
# ---------------------------------------------------------------------------


def _install_stubs() -> Dict[str, int]:
    """Stub the update check and the AWS fetch; return their call counters."""
    from servonaut.services.aws_service import AWSService
    from servonaut.services.update_service import UpdateService

    calls = {"update_check": 0, "aws_fetch": 0}

    def no_update(_self: Any) -> None:
        calls["update_check"] += 1
        return None

    async def no_instances(_self: Any, *, force_refresh: bool = False) -> list:
        del force_refresh
        calls["aws_fetch"] += 1
        return []

    UpdateService.check_for_update = no_update  # type: ignore[method-assign]
    AWSService.fetch_instances_cached = no_instances  # type: ignore[method-assign]
    return calls


async def _wait_until(app: Any, predicate: Callable[[], bool], what: str) -> None:
    """Poll *predicate* without letting Pilot settle the app in between.

    ``Pilot.pause()`` waits until the screen has processed every pending
    message, which would close exactly the timing windows these scenarios
    probe. A short ``asyncio.sleep`` yields to the app without that.
    """
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if app.return_code is not None:
            return  # the app exited (crashed); run_test re-raises on exit
        try:
            if predicate():
                return
        except Exception:  # noqa: BLE001 - screen stack is mid-switch
            pass
        await asyncio.sleep(_POLL_SECONDS)
    raise TimeoutError(f"timed out waiting for {what}")


async def _scenario_boot() -> Dict[str, Any]:
    """Seed a sentinel config in the throwaway HOME, then boot the app."""
    from servonaut.config.manager import ConfigManager
    from servonaut.config.schema import AppConfig

    ConfigManager().save(AppConfig(default_username=SENTINEL_USERNAME))

    from servonaut.app import ServonautApp

    calls = _install_stubs()
    app = ServonautApp()
    async with app.run_test(headless=True, size=(120, 40)) as pilot:
        await pilot.pause()
        # Long-lived loops (fleet auto-scan) never finish; wait for the
        # one-shot startup check only.
        startup = [w for w in app.workers if w.name == "version_check"]
        await app.workers.wait_for_complete(startup)
        await pilot.pause()
        return {
            "screen": type(app.screen).__name__,
            "default_username": app.config_manager.get().default_username,
            "config_path": str(app.config_manager._config_path),
            "data_root": str(app.runtime_layout.data_root),
            "stub_calls": calls,
        }


async def _settings_round_trip(dwell: float) -> Dict[str, Any]:
    """Open Settings from the sidebar, leave for Instances after *dwell* s."""
    from textual.widgets import Button

    from servonaut.app import ServonautApp
    from servonaut.screens.instance_list import InstanceListScreen
    from servonaut.screens.settings import SettingsScreen

    outcome: Dict[str, Any] = {"dwell": dwell, "error": None, "final_screen": None}
    app = ServonautApp()
    try:
        async with app.run_test(headless=True, size=(140, 45)) as pilot:
            await pilot.pause()
            # Expand the sidebar group that holds Settings, as a user would.
            await pilot.click("#section_tools > Button.section-header")
            instances = app.screen
            # Button.press() rather than pilot.click(): a Pilot click settles
            # the new screen before returning, hiding the window under test.
            instances.query_one("#nav_settings", Button).press()
            await _wait_until(
                app,
                lambda: isinstance(app.screen, SettingsScreen) and app.screen.is_mounted,
                "the Settings screen",
            )
            await asyncio.sleep(dwell)
            app.screen.query_one("#nav_list", Button).press()
            await _wait_until(
                app,
                lambda: isinstance(app.screen, InstanceListScreen)
                and app.screen is not instances
                and app.screen.is_mounted,
                "the Instances screen",
            )
            await pilot.pause()
            await pilot.pause()
            outcome["final_screen"] = type(app.screen).__name__
    except Exception as exc:  # noqa: BLE001 - reported to the parent test
        outcome["error"] = f"{type(exc).__name__}: {exc}"
    return outcome


async def _scenario_leave_before_rebaseline() -> Dict[str, Any]:
    """Leave Settings while its first panel's deferred re-baseline is pending.

    The panel re-baselines its unsaved-changes snapshot from
    ``call_after_refresh`` callbacks. How many frames pass before those run
    depends on machine speed, so a plain timing test is flaky. This scenario
    holds the callbacks instead of scheduling them, switches to Instances, and
    releases them on the app's queue only once the Settings screen has been
    torn down: the state a quick click away from Settings reaches, made
    deterministic.
    """
    from textual.widgets import Button

    from servonaut.app import ServonautApp
    from servonaut.screens.instance_list import InstanceListScreen
    from servonaut.screens.settings import SettingsScreen
    from servonaut.screens.settings.base import SettingsPanel

    _install_stubs()
    held: List[Any] = []

    def hold(panel: Any, frames_left: int) -> None:
        held.append((panel, frames_left))

    SettingsPanel._schedule_rebaseline = hold  # type: ignore[method-assign]

    outcome: Dict[str, Any] = {"released": 0, "error": None, "final_screen": None}
    app = ServonautApp()
    try:
        async with app.run_test(headless=True, size=(140, 45)) as pilot:
            await pilot.pause()
            await pilot.click("#section_tools > Button.section-header")
            instances = app.screen
            instances.query_one("#nav_settings", Button).press()
            await _wait_until(
                app,
                lambda: isinstance(app.screen, SettingsScreen) and bool(held),
                "a pending re-baseline on the Settings screen",
            )
            app.screen.query_one("#nav_list", Button).press()
            await _wait_until(
                app,
                lambda: isinstance(app.screen, InstanceListScreen)
                and app.screen is not instances
                and app.screen.is_mounted
                and not any(panel.is_attached for panel, _ in held),
                "the Instances screen with Settings torn down",
            )
            for panel, frames_left in held:
                app.call_later(panel._rebaseline_after_refresh, frames_left)
            outcome["released"] = len(held)
            await pilot.pause()
            await pilot.pause()
            outcome["final_screen"] = type(app.screen).__name__
    except Exception as exc:  # noqa: BLE001 - reported to the parent test
        outcome["error"] = f"{type(exc).__name__}: {exc}"
    return outcome


async def _scenario_settings_round_trips(*dwells: str) -> List[Dict[str, Any]]:
    """Run one fresh app per dwell (seconds) and report each outcome."""
    _install_stubs()
    return [await _settings_round_trip(float(dwell)) for dwell in dwells]


async def _scenario_signed_in_with_api_override(api_url: str) -> Dict[str, Any]:
    """Boot signed in, with ``SERVONAUT_API_URL`` set to *api_url* in the secrets env file.

    The value is read from that file, as it is for a user, so the report also
    shows the startup check runs after the file has been loaded.
    """
    from servonaut.config.secrets import DEFAULT_SECRETS_PATH
    from servonaut.services.auth_service import AuthService, AuthToken

    DEFAULT_SECRETS_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    DEFAULT_SECRETS_PATH.write_text(f"SERVONAUT_API_URL={api_url}\n", encoding="utf-8")
    auth = AuthService()
    auth._token = AuthToken(
        access_token="hermetic-access-token",
        refresh_token="hermetic-refresh-token",
        expires_at=time.time() + 3600,
        plan="solo",
        user_id=7,
    )
    auth._save_token()

    from servonaut.app import ServonautApp

    _install_stubs()
    app = ServonautApp()
    async with app.run_test(headless=True, size=(120, 40)) as pilot:
        await pilot.pause()
        startup_workers = ("version_check", "relay_autostart", "ssh_verify_sidecar")
        startup = [w for w in app.workers if w.name in startup_workers]
        await app.workers.wait_for_complete(startup)
        await pilot.pause()
        return {
            "screen": type(app.screen).__name__,
            "signed_in": bool(app.auth_service and app.auth_service.is_authenticated),
            "notifications": [
                {"message": note.message, "severity": note.severity}
                for note in app._notifications
            ],
        }


async def _scenario_probe_guard(target: str) -> Dict[str, Any]:
    """Exercise the guard itself: read *target* and resolve a remote host."""
    try:
        with open(target, encoding="utf-8") as handle:
            handle.read()
    except OSError:
        pass
    import socket

    try:
        socket.getaddrinfo("example.com", 443)
        blocked = False
    except NetworkBlockedError:
        blocked = True
    return {"network_blocked": blocked}


SCENARIOS: Dict[str, Callable[..., Awaitable[Any]]] = {
    "boot": _scenario_boot,
    "settings-round-trips": _scenario_settings_round_trips,
    "leave-settings-before-rebaseline": _scenario_leave_before_rebaseline,
    "probe-guard": _scenario_probe_guard,
    "signed-in-with-api-override": _scenario_signed_in_with_api_override,
}


def _child_main(argv: List[str]) -> int:
    scenario, report_path, *scenario_args = argv
    workdir = os.environ[_ENV_WORKDIR]
    guard = _Guard(
        os.environ[_ENV_GUARDED_HOME],
        [str(REPO_ROOT), os.environ["HOME"], workdir],
    )
    sys.addaudithook(guard)
    # Relative paths must resolve inside the throwaway tree, not the checkout.
    os.chdir(workdir)

    result: Any = None
    error: Optional[str] = None
    try:
        result = asyncio.run(SCENARIOS[scenario](*scenario_args))
    except BaseException:  # noqa: BLE001 - everything is reported
        error = traceback.format_exc(limit=12)
    report = {
        "result": result,
        "error": error,
        "home_accesses": guard.home_accesses,
        "network_attempts": guard.network_attempts,
    }
    Path(report_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(_child_main(sys.argv[1:]))
