"""Hermetic bootstrap and shared fixtures for the end-to-end suite.

The first statement below replaces the process environment and installs the
guards. It must run before anything imports ``servonaut``, because several
Servonaut modules bind paths under the home directory at import time. See
``e2e/harness/bootstrap.py``.
"""

from e2e.harness import bootstrap as _bootstrap

CTX = _bootstrap.bootstrap()

# Everything below may import servonaut: the sandbox is in place.
import importlib.util  # noqa: E402
import itertools  # noqa: E402
import json  # noqa: E402
import logging  # noqa: E402
import os  # noqa: E402
import shlex  # noqa: E402
import sys  # noqa: E402
from dataclasses import dataclass, field  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any, Callable, Optional  # noqa: E402

import pytest  # noqa: E402

from e2e.harness import artifacts, canary, lifecycle  # noqa: E402
from e2e.harness.bootstrap import E2EContext, Sandbox, build_env  # noqa: E402
from e2e.harness.processes import ChildLog  # noqa: E402
from e2e.harness.shims import ShimSet  # noqa: E402
from e2e.harness.relay_fixtures import (  # noqa: E402,F401 (fixtures)
    _stop_leftover_listeners,
    account_home,
    relay,
)

GUARD = _bootstrap.load_guard()
# Fixtures for journeys against the loopback SSH servers.
pytest_plugins = ("e2e.harness.sshd_plugin",)
JOURNEY_TIMEOUT_SECONDS = 90
# Every journey declares which run it belongs to.
TIER_MARKERS = ("e2e_pr", "e2e_quarantine")
# Journeys that drive a headless browser (the desktop frontend).
BROWSER_MARKER = "needs_browser"
_REQUIRED_MODULES = ("moto", "aiohttp", "mcp", "textual_serve", "playwright")
# Read by child_site/sitecustomize.py (module constants pointed at the fakes).
REDIRECTS_ENV = "SERVONAUT_E2E_REDIRECTS"
_SEQUENCE = itertools.count(1)
# Escape reports name the offending command; a long ``python -c`` script is cut.
_MAX_COMMAND_CHARS = 300


# ---------------------------------------------------------------------------
# Session plumbing
# ---------------------------------------------------------------------------


def pytest_configure(config: pytest.Config) -> None:
    lifecycle.interrupt_on_sigterm()
    missing = [name for name in _REQUIRED_MODULES if importlib.util.find_spec(name) is None]
    if missing:
        raise pytest.UsageError(
            f"the end-to-end suite needs the e2e extra ({', '.join(missing)} not installed): "
            "pip install -e '.[e2e]'"
        )


def pytest_sessionstart(session: pytest.Session) -> None:
    # Failure artifacts describe this run only. xdist workers leave the
    # folder to the controller, which starts before any of them.
    if CTX.worker != "main":
        return
    try:
        artifacts.prepare_artifacts_dir(CTX)
    except RuntimeError as exc:
        raise pytest.UsageError(str(exc)) from exc
    # The packaged journeys' wheels, built once instead of once per worker.
    from e2e.harness.installs import prebuild_for_workers

    prebuild_for_workers(session.config, CTX)


def pytest_unconfigure(config: pytest.Config) -> None:
    _bootstrap.teardown()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    untiered = []
    unmarked_browser = []
    for item in items:
        lifecycle.use_signal_timeout(item, JOURNEY_TIMEOUT_SECONDS)
        if not any(item.get_closest_marker(name) for name in TIER_MARKERS):
            untiered.append(item.nodeid)
        # CI runs browser journeys in their own job, selected by this marker.
        uses_browser = "desktop" in getattr(item, "fixturenames", ())
        if uses_browser and item.get_closest_marker(BROWSER_MARKER) is None:
            unmarked_browser.append(item.nodeid)
    if untiered:
        raise pytest.UsageError(
            f"every journey needs one of the markers {', '.join(TIER_MARKERS)}; missing on: "
            + ", ".join(untiered)
        )
    if unmarked_browser:
        raise pytest.UsageError(
            f"journeys using the desktop fixture need the {BROWSER_MARKER} marker; missing on: "
            + ", ".join(unmarked_browser)
        )


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> Any:
    report = yield
    setattr(item, f"rep_{report.when}", report)
    return report


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Any:
    """Fail the journey itself when it tried to leave the sandbox."""
    result = yield
    journey = getattr(item, "funcargs", {}).get("journey")
    if isinstance(journey, Journey):
        escapes = journey.take_escapes()
        if escapes:
            raise AssertionError(_describe_escapes(escapes))
    return result


def _describe_escapes(escapes: list[dict]) -> str:
    """One block per process: which command it was, then what it tried."""
    by_pid: dict[Any, list[dict]] = {}
    for escape in escapes:
        by_pid.setdefault(escape.get("pid"), []).append(escape)
    lines = ["the journey tried to leave the e2e sandbox:"]
    for pid, attempts in by_pid.items():
        lines.append(f"  pid {pid}: {attempts[0].get('command', 'command unknown')}")
        lines.extend(f"    {e['kind']}: {e['target']}" for e in attempts)
    return "\n".join(lines)


def _name_processes(escapes: list[dict], armed: list[dict]) -> None:
    """Add the command line of the process behind each escape.

    A pid alone does not say which of a journey's many children escaped;
    every guarded child records its command line in the armed log when its
    guard is installed.
    """
    commands = {record["pid"]: record.get("cmdline", []) for record in armed if "pid" in record}
    for escape in escapes:
        pid = escape.get("pid")
        if pid == os.getpid():
            command = "this test process"
        elif pid in commands:
            command = shlex.join(commands[pid])
            if len(command) > _MAX_COMMAND_CHARS:
                command = command[:_MAX_COMMAND_CHARS] + "..."
        else:
            command = "command unknown (it never reported an armed guard)"
        escape["command"] = command


@pytest.fixture(scope="session")
def e2e_ctx() -> E2EContext:
    return CTX


@pytest.fixture(scope="session", autouse=True)
def _sandbox_is_hermetic(e2e_ctx: E2EContext) -> None:
    """Abort the whole run if import-time data paths escaped the sandbox."""
    problems = canary.critical_path_problems(e2e_ctx)
    if problems:
        pytest.exit("e2e sandbox is not hermetic: " + "; ".join(problems), returncode=3)


# ---------------------------------------------------------------------------
# Per-journey workspace
# ---------------------------------------------------------------------------


@dataclass
class Journey:
    """One test's workspace: fake tools, child sandboxes, logs, artifacts."""

    ctx: E2EContext
    nodeid: str
    directory: Path
    shims: ShimSet
    staging: Path
    children: ChildLog
    homes: list[Path] = field(default_factory=list)
    fake_cloud: Any = None
    env_overrides: dict[str, str] = field(default_factory=dict)

    @property
    def guard_log(self) -> Path:
        return self.directory / "guard.jsonl"

    @property
    def armed_log(self) -> Path:
        return self.directory / "armed.jsonl"

    def new_sandbox(self, name: str = "child") -> Sandbox:
        """A fresh home for a child process."""
        sandbox = Sandbox(self.directory / name).create()
        self.homes.append(sandbox.home)
        return sandbox

    def child_env(self, sandbox: Sandbox, **extra: str) -> dict[str, str]:
        """The complete environment for a child living in *sandbox*."""
        return build_env(
            sandbox,
            shim_dir=self.shims.directory,
            guard_log=self.guard_log,
            armed_log=self.armed_log,
            extra={**self.env_overrides, **extra},
        )

    def take_escapes(self) -> list[dict]:
        """Sandbox escapes recorded so far (this process and children)."""
        escapes = GUARD.violations() + GUARD.read_log(self.guard_log)
        GUARD.clear()
        if escapes:
            _name_processes(escapes, GUARD.read_log(self.armed_log))
            self.staging.mkdir(parents=True, exist_ok=True)
            with (self.staging / "escapes.txt").open("a", encoding="utf-8") as handle:
                handle.write(_describe_escapes(escapes) + "\n")
            self.guard_log.unlink(missing_ok=True)
        return escapes


def _attach_servonaut_log(path: Path) -> Callable[[], None]:
    """Send Servonaut's own logging to *path* for the duration of a journey."""
    root = logging.getLogger()
    root_handlers = list(root.handlers)
    logger = logging.getLogger("servonaut")
    previous_level = logger.level
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    def detach() -> None:
        logger.removeHandler(handler)
        handler.close()
        logger.setLevel(previous_level)
        for extra in [h for h in root.handlers if h not in root_handlers]:
            root.removeHandler(extra)

    return detach


def _reset_browser_registry() -> None:
    """Forget the browser Python's ``webbrowser`` cached from an earlier journey.

    The registry is module state keyed on ``$BROWSER``, which changes with
    every journey's fake tools; the attributes are private, so the reset is
    confined to this function.
    """
    import webbrowser

    with webbrowser._lock:
        webbrowser._browsers.clear()
        webbrowser._tryorder = None


def _open_journey(request: pytest.FixtureRequest, ctx: E2EContext) -> Journey:
    name = artifacts.sanitize(request.node.name)[:60]
    directory = ctx.tests_dir / f"{next(_SEQUENCE):04d}-{name}"
    directory.mkdir(parents=True)
    staging = directory / "artifacts"
    return Journey(
        ctx=ctx,
        nodeid=request.node.nodeid,
        directory=directory,
        shims=ShimSet(directory / "shims"),
        staging=staging,
        children=ChildLog(staging / "children.log"),
        homes=[ctx.sandbox.home],
    )


def _enter_journey(journey: Journey, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point this process at the journey's fake tools and a wiped home."""
    from e2e.harness.pilot import reset_app_class_state

    artifacts.forget_secrets()
    journey.ctx.sandbox.reset_home()
    for key, value in {
        "PATH": str(journey.shims.directory),
        "BROWSER": str(journey.shims.path_of("browser")),
        "EDITOR": str(journey.shims.path_of("editor")),
        "VISUAL": str(journey.shims.path_of("editor")),
        "SERVONAUT_E2E_GUARD_LOG": str(journey.guard_log),
        "SERVONAUT_E2E_ARMED_LOG": str(journey.armed_log),
        "SERVONAUT_E2E_SPAWN_DIRS": str(journey.shims.directory),
    }.items():
        monkeypatch.setenv(key, value)
    GUARD.set_spawn_dirs([str(journey.shims.directory)])
    GUARD.clear()
    reset_app_class_state()
    _reset_browser_registry()


def _close_journey(request: pytest.FixtureRequest, journey: Journey) -> list[dict]:
    """Collect artifacts for a failed journey; return escapes not yet reported."""
    leftover = journey.take_escapes()
    GUARD.set_spawn_dirs([str(journey.ctx.default_shims)])
    node = request.node
    if artifacts.journey_failed(node) or leftover:
        journey.staging.mkdir(parents=True, exist_ok=True)
        log = journey.directory / "servonaut.log"
        if log.exists():
            (journey.staging / "servonaut-in-process.log").write_bytes(log.read_bytes()[-65536:])
        artifacts.collect(
            journey.ctx,
            node.nodeid,
            staging=journey.staging,
            shim_dir=journey.shims.directory,
            guard_logs=[journey.guard_log, journey.armed_log],
            homes=journey.homes,
            fake_cloud=journey.fake_cloud,
        )
    return leftover


@pytest.fixture(autouse=True)
def journey(
    request: pytest.FixtureRequest, e2e_ctx: E2EContext, monkeypatch: pytest.MonkeyPatch
) -> Any:
    """Fresh fake tools and a wiped in-process home for every test."""
    current = _open_journey(request, e2e_ctx)
    _enter_journey(current, monkeypatch)
    detach_log = _attach_servonaut_log(current.directory / "servonaut.log")
    yield current
    detach_log()
    leftover = _close_journey(request, current)
    if leftover:
        pytest.fail(_describe_escapes(leftover))


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def _fake_cloud_server(e2e_ctx: E2EContext) -> Any:
    from servonaut import get_version

    from e2e.harness.fake_cloud.app import FakeCloud
    from e2e.harness.fake_cloud.tls import TlsMaterial

    material = TlsMaterial(e2e_ctx.ca_cert, e2e_ctx.server_cert, e2e_ctx.server_key)
    server = FakeCloud(material, default_pypi_version=get_version()).start()
    yield server
    server.stop()


@pytest.fixture
def fake_cloud(_fake_cloud_server: Any, journey: Journey, monkeypatch: pytest.MonkeyPatch) -> Any:
    """FakeCloud, reset, with the Servonaut API and package index pointed at it."""
    from servonaut.services import update_service

    _fake_cloud_server.reset()
    journey.fake_cloud = _fake_cloud_server
    urls = {
        "SERVONAUT_API_URL": _fake_cloud_server.url,
        "SERVONAUT_MCP_URL": _fake_cloud_server.url,
        # The update check's package-index document.
        "SERVONAUT_PYPI_URL": _fake_cloud_server.pypi_json_url,
    }
    for key, value in urls.items():
        monkeypatch.setenv(key, value)
    journey.env_overrides.update(urls)
    # The update check reads the package index URL from a module constant:
    # patched here, and redirected in children by child_site/sitecustomize.py.
    monkeypatch.setattr(update_service, "PYPI_URL", _fake_cloud_server.pypi_json_url)
    redirects = json.dumps(
        {update_service.__name__: {"PYPI_URL": _fake_cloud_server.pypi_json_url}}
    )
    # Children started with this process's own environment get it too.
    monkeypatch.setenv(REDIRECTS_ENV, redirects)
    journey.env_overrides[REDIRECTS_ENV] = redirects
    return _fake_cloud_server


@pytest.fixture(scope="session")
def _moto_server() -> Any:
    from e2e.harness.aws import MotoAws

    server = MotoAws().start()
    yield server
    server.stop()


@pytest.fixture
def moto(_moto_server: Any, journey: Journey, monkeypatch: pytest.MonkeyPatch) -> Any:
    """The local AWS endpoint, emptied, with ``AWS_ENDPOINT_URL`` pointing at it.

    CloudWatch Logs filter patterns are evaluated as AWS documents them; a
    pattern the emulation cannot evaluate fails the journey that sent it.
    """
    from e2e.harness import aws_logs_filter

    _moto_server.reset()
    monkeypatch.setenv("AWS_ENDPOINT_URL", _moto_server.url)
    journey.env_overrides["AWS_ENDPOINT_URL"] = _moto_server.url
    aws_logs_filter.install(monkeypatch)
    yield _moto_server
    refused = aws_logs_filter.take_refused()
    if refused:
        pytest.fail("CloudWatch filter patterns the e2e emulation refused: " + "; ".join(refused))


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------


@pytest.fixture
def seed(e2e_ctx: E2EContext, fake_cloud: Any) -> Any:
    """Seeder for the in-process home (TUI journeys)."""
    from e2e.harness.seed import HomeSeeder

    return HomeSeeder(e2e_ctx.sandbox.home, api_url=fake_cloud.url)


@pytest.fixture
def tui(journey: Journey, fake_cloud: Any) -> Callable[..., Any]:
    """Factory: ``async with tui() as t:`` boots the real app in this process."""
    from e2e.harness.pilot import DEFAULT_SIZE, tui_session

    def open_session(size: tuple[int, int] = DEFAULT_SIZE, *, wait_for_fleet: bool = True) -> Any:
        return tui_session(journey.staging, size=size, wait_for_fleet=wait_for_fleet)

    return open_session


@pytest.fixture
def servonaut_cmd() -> list[str]:
    """How to start Servonaut as a child process (source checkout)."""
    return [sys.executable, "-m", "servonaut.main"]


@pytest.fixture
def cli(journey: Journey, servonaut_cmd: list[str]) -> Callable[..., Any]:
    """Factory: ``cli(sandbox, "login", "--no-browser")`` runs one command."""
    from e2e.harness.processes import run_cli

    def run(
        sandbox: Sandbox, *args: str, timeout: float = 60.0, stdin: Optional[str] = None
    ) -> Any:
        return run_cli(
            servonaut_cmd,
            *args,
            env=journey.child_env(sandbox),
            cwd=sandbox.base,
            armed_log=journey.armed_log,
            stdin=stdin,
            timeout=timeout,
            log=journey.children,
        )

    return run


@pytest.fixture
def mcp(journey: Journey, servonaut_cmd: list[str]) -> Callable[..., Any]:
    """Factory: ``async with mcp(sandbox) as session:`` runs ``servonaut --mcp``."""
    from e2e.harness.processes import mcp_session

    counter = itertools.count(1)

    def open_session(sandbox: Sandbox, *, stderr_path: Optional[Path] = None) -> Any:
        return mcp_session(
            servonaut_cmd,
            env=journey.child_env(sandbox),
            cwd=sandbox.base,
            stderr_path=stderr_path or journey.staging / f"mcp-{next(counter)}.stderr.log",
            armed_log=journey.armed_log,
        )

    return open_session


# ---------------------------------------------------------------------------
# Desktop
# ---------------------------------------------------------------------------


class DesktopJourney:
    """Factories for desktop journeys; each returns an async context manager.

    ``browser()`` is headless Chromium kept on loopback, ``in_process()`` the
    desktop host with the real app in this process, and ``child()`` the real
    desktop child process in its own seeded sandbox.
    """

    def __init__(self, journey: Journey, fake_cloud: Any) -> None:
        self.journey = journey
        self.fake_cloud = fake_cloud
        self._children = itertools.count(1)

    def browser(self, *, allow_csp_blocked: bool = False) -> Any:
        from e2e.harness.desktop import chromium

        return chromium(self.journey.staging / "browser", allow_csp_blocked=allow_csp_blocked)

    def in_process(self) -> Any:
        from e2e.harness.desktop import in_process_host

        return in_process_host(self.journey.staging)

    def child_sandbox(self) -> Sandbox:
        """A fresh home with the neutral fleet, as a returning user has it."""
        from e2e.harness import fleet
        from e2e.harness.seed import HomeSeeder

        sandbox = self.journey.new_sandbox(f"desktop-{next(self._children)}")
        seeder = HomeSeeder(sandbox.home, api_url=self.fake_cloud.url)
        seeder.config()
        seeder.cache(fleet.cache_rows(), fresh=True)
        return sandbox

    def child_env(self, sandbox: Sandbox) -> dict[str, str]:
        return self.journey.child_env(sandbox)

    def child(self, sandbox: Optional[Sandbox] = None) -> Any:
        from e2e.harness.desktop import desktop_child

        sandbox = sandbox or self.child_sandbox()
        return desktop_child(
            sandbox, env=self.child_env(sandbox), armed_log=self.journey.armed_log
        )


@pytest.fixture
def desktop(journey: Journey, fake_cloud: Any) -> Any:
    """Desktop journeys: ``async with desktop.browser() as browser:`` etc."""
    from e2e.harness.desktop import playwright_driver_dir

    # Playwright drives the browser through its own bundled program; that
    # program may start, nothing else new.
    GUARD.set_spawn_dirs([str(journey.shims.directory), playwright_driver_dir()])
    yield DesktopJourney(journey, fake_cloud)
    GUARD.set_spawn_dirs([str(journey.shims.directory)])
