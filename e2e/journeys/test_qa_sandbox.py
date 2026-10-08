"""Journeys: the local QA sandbox (``python -m e2e.sandbox``) from ``up`` to ``down``.

The sandbox runs as a child of the test with its root inside the journey's
folder, and a person's environment of its own (home, state directory with
the per-user pointer). The tests drive it as a person does: ``status``, the
CLI through ``run``, one MCP tool through ``mcp-call``, the desktop child in
headless Chromium with the printed start snippet, then ``down``. Afterwards
none of the sandbox's processes runs, its root is gone, and nothing was left
outside it: the pointer was the only file written there, and ``down``
removed it again.

The others cover what can go wrong around it: a pointer naming a process
that is no longer the owner (never signalled), a stop request during
start-up, and a long-lived host (the TUI inside an MCP server) that outlives
``down`` and must not bring the sandbox directory back.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import pytest

from e2e.harness.bootstrap import REPO_ROOT, Sandbox
from e2e.sandbox import client, state

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd]

READY_TIMEOUT = 90.0
COMMAND_TIMEOUT = 90.0
JOURNEY_TIMEOUT = 240


def _files(base: Path) -> set[str]:
    return {str(path.relative_to(base)) for path in base.rglob("*") if path.is_file()}


class QaSandbox:
    """One ``up`` child and the commands that drive it."""

    def __init__(self, journey, root: Path) -> None:
        self.person: Sandbox = journey.new_sandbox("person")
        self.env = journey.child_env(self.person)
        self.root = root
        self.stderr = journey.staging / "qa-sandbox-up.stderr.log"
        self.owner: Optional[subprocess.Popen] = None

    @property
    def pointer(self) -> Path:
        return state.pointer_path(self.env)

    def argv(self, *args: str) -> list[str]:
        return [sys.executable, "-m", "e2e.sandbox", *args]

    def start(self, *args: str) -> subprocess.Popen:
        """``up`` in the background, without waiting for it to be ready."""
        self.stderr.parent.mkdir(parents=True, exist_ok=True)
        with self.stderr.open("w", encoding="utf-8") as stderr:
            self.owner = subprocess.Popen(
                self.argv("up", "--root", str(self.root), *args),
                cwd=REPO_ROOT, env=self.env, stdout=subprocess.PIPE, stderr=stderr, text=True,
            )
        return self.owner

    async def up(self, *args: str) -> dict:
        self.start(*args)
        assert self.owner is not None and self.owner.stdout is not None
        line = await asyncio.wait_for(asyncio.to_thread(self.owner.stdout.readline), READY_TIMEOUT)
        assert line.startswith(f"SANDBOX READY {self.root / state.STATE_FILE}"), (
            line or self.stderr.read_text(encoding="utf-8")
        )
        return json.loads((self.root / state.STATE_FILE).read_text(encoding="utf-8"))

    async def command(self, *args: str) -> subprocess.CompletedProcess:
        return await asyncio.to_thread(
            subprocess.run, self.argv(*args), cwd=REPO_ROOT, env=self.env,
            capture_output=True, text=True, timeout=COMMAND_TIMEOUT,
        )

    async def down(self) -> None:
        stopped = await self.command("down")
        assert stopped.returncode == 0, stopped.stdout + stopped.stderr
        assert self.owner is not None
        # `down` returns only once the owner itself has exited.
        assert self.owner.poll() == 0, "the owner still ran when down returned"

    def close(self) -> None:
        """Stop an owner a failed journey left running."""
        if self.owner is None or self.owner.poll() is not None:
            return
        subprocess.run(self.argv("down"), cwd=REPO_ROOT, env=self.env, capture_output=True,
                       timeout=COMMAND_TIMEOUT)
        if self.owner.poll() is None:
            self.owner.kill()
        self.owner.wait()

    def assert_gone(self, files_before: set[str]) -> None:
        assert not self.root.exists()
        assert not self.pointer.exists()
        assert state.sandbox_pids(self.root) == []
        assert _files(self.person.base) - files_before == set()


@pytest.fixture
def qa_sandbox(journey):
    sandbox = QaSandbox(journey, journey.directory / "qa-root")
    yield sandbox
    sandbox.close()


async def _screen(page) -> str:
    """The visible terminal text, as the printed ``text()`` helper reads it."""
    return await page.page.evaluate("() => window.servonautQa.text()")


async def _screen_until(page, predicate, desc: str, timeout: float = 20.0) -> str:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        screen = await _screen(page)
        if predicate(screen):
            return screen
        assert loop.time() < deadline, f"timed out waiting for {desc}:\n{screen}"
        await asyncio.sleep(0.05)


def _references(current: dict) -> dict[str, dict]:
    return {entry["reference"]: entry for entry in current["fleet"]}


@pytest.mark.needs_browser
@pytest.mark.asyncio
@pytest.mark.timeout(JOURNEY_TIMEOUT)
async def test_every_surface_from_up_to_down(qa_sandbox, desktop):
    before = _files(qa_sandbox.person.base)
    current = await qa_sandbox.up()
    assert current["scenario"] == state.SINGLE
    assert state.read_json(qa_sandbox.pointer)["state"] == str(qa_sandbox.root / state.STATE_FILE)
    fleet = _references(current)
    assert fleet["custom/web-1"]["ssh"] and fleet["aws/app-1"]["ssh"]
    assert fleet["hetzner/cache-1"]["shown"] == "cache-1"

    status = await qa_sandbox.command("status")
    assert status.returncode == 0, status.stderr
    assert "QA sandbox: running" in status.stdout and "custom/web-1" in status.stdout

    # One sandbox per person: a second one is refused while the first runs.
    second = await qa_sandbox.command("up", "--root", str(qa_sandbox.root.with_name("other")))
    assert second.returncode == 2 and "already running" in second.stderr

    listed = await qa_sandbox.command("run", "--", "servonaut", "hetzner", "list")
    assert listed.returncode == 0, listed.stderr
    assert "cache-1" in listed.stdout and "build-1" in listed.stdout

    called = await qa_sandbox.command("mcp-call", "list_instances")
    assert called.returncode == 0, called.stderr
    for name in ("app-1", "cache-1", "mail-1", "web-1"):
        assert name in called.stdout

    # Two requests at once share one desktop child: one starts it, one reuses it.
    answers = await asyncio.gather(*(qa_sandbox.command("desktop", "--json") for _ in range(2)))
    assert [answer.returncode for answer in answers] == [0, 0], [a.stderr for a in answers]
    infos = [json.loads(answer.stdout) for answer in answers]
    assert infos[0]["pid"] == infos[1]["pid"]
    assert sorted(info["reused"] for info in infos) == [False, True]
    assert list((qa_sandbox.root / state.CONTROL_DIR).iterdir()) == []
    info = infos[0]
    async with desktop.browser() as browser:
        page = await browser.new_page()
        assert await page.open(info["origin"]) == 200
        # The printed start snippet returns once the terminal painted, focused.
        started = await page.page.evaluate(client.start_session_js(info["token"]))
        assert started == {
            "columns": page.dimensions["width"], "rows": page.dimensions["height"], "text": True,
        }
        assert await page.page.evaluate(
            "() => document.activeElement.classList.contains('xterm-helper-textarea')"
        )
        await page.page.evaluate("() => window.servonautQa.waitForText('app-1')")
        # The footer follows the terminal's focus, which the browser may still
        # give or take away while the page starts: Textual blurs the focused
        # widget while the terminal is unfocused, and the fleet table's Enter
        # shortcut then shows instead of `o`. Settle it, unfocused, first.
        await page.page.evaluate("() => document.activeElement.blur()")
        screen = await _screen_until(page, lambda text: "⏎ Actions" in text, "footer without focus")
        assert len(screen.splitlines()) == started["rows"] and "cache-1" in screen

        # Running the snippet again changes nothing and says why.
        rerun = await page.page.evaluate(
            f"async () => {{ try {{ await ({client.start_session_js(info['token'])})(); }}"
            " catch (error) { return error.message; } }"
        )
        assert rerun.startswith("this page already started its session")
        assert await _screen(page) == screen
        await page.page.evaluate("() => window.servonautQa.focus()")
        await _screen_until(page, lambda text: "o Actions" in text, "the fleet table focused again")
        # Without a captured terminal, waitForText says so at once.
        unavailable = await page.page.evaluate(
            """async () => {
              const qa = window.servonautQa, terminal = qa.terminal, started = Date.now();
              qa.terminal = null;
              try { await qa.waitForText('app-1'); return null; }
              catch (error) { return [error.message, Date.now() - started]; }
              finally { qa.terminal = terminal; }
            }"""
        )
        assert unavailable[0] == "screen text unavailable: judge from screenshots"
        assert unavailable[1] < 1000

        # Keys typed straight into the page reach the app: "/" focuses the fleet
        # search, typing narrows. The box takes "q" as text, so "Quit" leaving
        # the footer shows it has focus; the footer also changes without it
        # ("⏎" replaces "o" for Actions when nothing is focused), and typing
        # then would run the fleet's one-key shortcuts instead.
        assert "Quit" in screen.splitlines()[-1]
        await page.page.keyboard.press("/")
        await _screen_until(
            page, lambda text: "Quit" not in text.splitlines()[-1], "search box focus"
        )
        await page.page.keyboard.type("cache")
        narrowed = await _screen_until(page, lambda text: "app-1" not in text, "search applied")
        assert "cache-1" in narrowed

        # The printed click helper aims where the harness's own click_cell does.
        size = {"columns": started["columns"], "rows": started["rows"]}
        box = await page.page.locator(".xterm-screen").bounding_box()
        center = await page.page.evaluate(client.cell_center_js(3, 2))
        assert center["x"] == pytest.approx(box["x"] + 3.5 * box["width"] / size["columns"])
        assert center["y"] == pytest.approx(box["y"] + 2.5 * box["height"] / size["rows"])
        assert page.errors() == []

    guard_log = Path(current["logs"]["guard"])
    assert not guard_log.exists() or guard_log.read_text(encoding="utf-8") == ""
    await qa_sandbox.down()
    qa_sandbox.assert_gone(before)


@pytest.mark.asyncio
@pytest.mark.timeout(JOURNEY_TIMEOUT)
async def test_multi_account_scenario_names_every_account(qa_sandbox):
    before = _files(qa_sandbox.person.base)
    current = await qa_sandbox.up("--scenario", state.MULTI_ACCOUNT)
    fleet = _references(current)
    for reference in ("prod/web-1", "staging/web-1", "backup/web-1", "aws/web-1", "custom/web-1"):
        assert reference in fleet, reference
    assert fleet["staging/web-1"]["shown"] == "staging/web-1"
    assert fleet["custom/web-1"]["shown"] == "web-1"

    listed = await qa_sandbox.command("run", "--", "hetzner", "list")
    assert listed.returncode == 0, listed.stderr
    assert "staging/web-1" in listed.stdout and "hetzner/web-1" in listed.stdout

    # The shared name is refused with the references to use instead.
    ambiguous = await qa_sandbox.command("run", "--", "ssh", "web-1", "--", "true")
    assert ambiguous.returncode != 0 and "prod/web-1" in ambiguous.stdout + ambiguous.stderr
    reached = await qa_sandbox.command("run", "--", "ssh", "custom/web-1", "--", "hostname")
    assert reached.returncode == 0 and reached.stdout.strip() == "web-1", reached.stderr

    await qa_sandbox.down()
    qa_sandbox.assert_gone(before)


def _write_stale_sandbox(qa_sandbox: QaSandbox, root: Path, pid: int) -> None:
    """A pointer and root left by an owner that died, naming a pid now used by *pid*."""
    record = {
        "schema": state.SCHEMA, "root": str(root), "state": str(root / state.STATE_FILE),
        "repo_root": str(REPO_ROOT), "owner_pid": pid,
        "owner_identity": state.process_identity(pid), "started_at": "2026-01-01T00:00:00+00:00",
    }
    root.mkdir(parents=True)
    state.write_json(root / state.MARKER, {**record, "phase": state.RUNNING})
    state.write_json(root / state.STATE_FILE, {**record, "keep": False})
    state.write_json(qa_sandbox.pointer, record)


@pytest.mark.asyncio
@pytest.mark.timeout(JOURNEY_TIMEOUT)
async def test_a_stale_pointer_never_gets_its_pid_signalled(qa_sandbox, journey):
    # A live process that is not a sandbox owner, under the number a dead owner had.
    stranger = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.read()"],
        env=qa_sandbox.env, stdin=subprocess.PIPE,
    )
    try:
        stale = journey.directory / "stale-root"
        _write_stale_sandbox(qa_sandbox, stale, stranger.pid)

        status = await qa_sandbox.command("status")
        assert status.returncode == 1 and "no longer running" in status.stderr
        refused = await qa_sandbox.command("desktop")
        assert refused.returncode == 1 and "no longer running" in refused.stderr
        cleaned = await qa_sandbox.command("down")
        assert cleaned.returncode == 0, cleaned.stderr
        assert "had already stopped" in cleaned.stdout
        assert not stale.exists() and not qa_sandbox.pointer.exists()
        assert stranger.poll() is None

        # A directory without the marker is left alone, with advice.
        leftover = journey.directory / "leftover"
        (leftover / "user").mkdir(parents=True)
        blocked = await qa_sandbox.command("up", "--root", str(leftover))
        assert blocked.returncode == 2 and "no sandbox marker" in blocked.stderr
        assert f"rm -r {leftover}" in blocked.stderr and (leftover / "user").is_dir()

        # A new sandbox replaces a stale pointer and removes the root it named.
        _write_stale_sandbox(qa_sandbox, stale, stranger.pid)
        await qa_sandbox.up()
        assert not stale.exists()
        assert f"removed {stale}" in qa_sandbox.stderr.read_text(encoding="utf-8")
        await qa_sandbox.down()
        assert stranger.poll() is None
    finally:
        stranger.kill()
        stranger.wait()


async def _until(predicate, desc: str, timeout: float = READY_TIMEOUT) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        assert loop.time() < deadline, f"timed out waiting for {desc}"
        await asyncio.sleep(0.05)


@pytest.mark.asyncio
@pytest.mark.timeout(JOURNEY_TIMEOUT)
@pytest.mark.parametrize("keep", [False, True], ids=["removed", "kept"])
async def test_a_stop_during_start_up_cleans_up(qa_sandbox, keep):
    owner = qa_sandbox.start(*(["--keep"] if keep else []))
    # The pointer is written as soon as the sandbox is claimed, well before it is ready.
    await _until(qa_sandbox.pointer.exists, "the pointer")
    owner.terminate()
    assert await asyncio.to_thread(owner.wait, COMMAND_TIMEOUT) == 0
    log = qa_sandbox.stderr.read_text(encoding="utf-8")
    assert "Traceback" not in log and "could not" not in log, log
    assert not qa_sandbox.pointer.exists()
    assert not qa_sandbox.root.exists()
    assert state.sandbox_pids(qa_sandbox.root) == []
    kept = list(qa_sandbox.root.parent.glob(f"{qa_sandbox.root.name}.kept-*"))
    assert len(kept) == int(keep)
    # A kept root is set aside: the next sandbox here starts fresh and leaves it alone.
    if keep:
        await qa_sandbox.up()
        await qa_sandbox.down()
        assert kept[0].is_dir()


# Stands in for the TUI host inside an MCP server: it outlives `down`, with
# the sandbox's environment and guard but without the owner watchdog.
_HOST_STAND_IN = """
import os, sys
from pathlib import Path
from e2e.harness import child_guard
from e2e.sandbox import state

current = state.load_live_state()
os.environ.clear()
os.environ.update(current["env"])
child_guard.arm(watch_owner=False)
owner = {"owner_pid": current["owner_pid"], "started_at": current["started_at"]}
state.watch_owner(
    Path(current["root"]),
    lambda: (child_guard.guard_module().restrict_writes([sys.argv[1]]),
             print("confined", flush=True)),
    owner=owner, interval=float(sys.argv[2]),
)
print("armed", flush=True)
for line in sys.stdin:
    target = Path(line.strip())
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("written")
        print("wrote", flush=True)
    except PermissionError:
        print("refused", flush=True)
"""


class HostStandIn:
    """The stand-in above, as a child of the test."""

    def __init__(self, qa_sandbox: QaSandbox, captures: Path, interval: float) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-c", _HOST_STAND_IN, str(captures), str(interval)],
            cwd=REPO_ROOT, env=qa_sandbox.env, text=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )

    async def line(self, timeout: float = 30) -> str:
        assert self.process.stdout is not None
        return (await asyncio.wait_for(asyncio.to_thread(self.process.stdout.readline), timeout)).strip()

    async def write(self, path: Path) -> str:
        assert self.process.stdin is not None
        self.process.stdin.write(f"{path}\n")
        self.process.stdin.flush()
        return await self.line()

    def close(self) -> None:
        self.process.kill()
        self.process.wait()


@pytest.mark.asyncio
@pytest.mark.timeout(JOURNEY_TIMEOUT)
async def test_a_host_that_outlives_the_sandbox_cannot_bring_it_back(qa_sandbox, journey):
    current = await qa_sandbox.up()
    home = Path(current["sandbox"]["home"])
    captures = journey.directory / "captures"
    host = HostStandIn(qa_sandbox, captures, interval=0.5)
    try:
        assert await host.line() == "armed"
        assert await host.write(home / "early.txt") == "wrote"
        await qa_sandbox.down()
        assert await host.line() == "confined"
        assert await host.write(home / "late.txt") == "refused"
        assert not qa_sandbox.root.exists()
        assert await host.write(captures / "snapshot.svg") == "wrote"
    finally:
        host.close()


@pytest.mark.asyncio
@pytest.mark.timeout(JOURNEY_TIMEOUT)
async def test_a_host_notices_a_restart_at_the_same_root(qa_sandbox, journey):
    await qa_sandbox.up()
    # A long watch interval: the restart completes between two looks, so the
    # lock is held again when the host next checks, by a new owner.
    host = HostStandIn(qa_sandbox, journey.directory / "captures", interval=8.0)
    try:
        assert await host.line() == "armed"
        await qa_sandbox.down()
        restarted = await qa_sandbox.up()
        assert await host.line(timeout=20) == "confined"
        fresh_home = Path(restarted["sandbox"]["home"])
        assert await host.write(fresh_home / "late.txt") == "refused"
        assert not (fresh_home / "late.txt").exists()
        await qa_sandbox.down()
    finally:
        host.close()


@pytest.mark.asyncio
@pytest.mark.timeout(JOURNEY_TIMEOUT)
async def test_a_pointer_from_another_version_is_left_alone(qa_sandbox, journey):
    root = journey.directory / "other-version"
    root.mkdir()
    record = {"schema": 99, "root": str(root), "owner_pid": os.getpid(), "repo_root": "elsewhere"}
    state.write_json(qa_sandbox.pointer, record)
    for args, code in ((("status",), 1), (("down",), 1), (("up", "--root", str(root)), 2)):
        answer = await qa_sandbox.command(*args)
        assert answer.returncode == code, (args, answer.stdout, answer.stderr)
        assert "another version of this tool" in answer.stderr, (args, answer.stderr)
    assert state.read_json(qa_sandbox.pointer) == record and root.is_dir()


# What the textual-pilot-mcp specs run first (import_path.require_clean), in a
# process whose import path holds a directory inside src/servonaut.
_PATH_CHECK = """
import sys
from e2e.sandbox import import_path

if sys.argv[1] == "late":
    import secrets  # before the check: Servonaut's own secrets.py stands in
try:
    import_path.require_clean()
except ImportError as exc:
    print("refused:", exc)
    raise SystemExit(0)
import secrets
print("secrets:", secrets.__file__)
"""


@pytest.mark.parametrize("when", ["early", "late"])
def test_a_directory_inside_the_package_stays_off_the_import_path(journey, when):
    env = journey.child_env(journey.new_sandbox("path-check"))
    # An empty entry is the working directory, as for a shell whose
    # PYTHONPATH starts with ":".
    env["PYTHONPATH"] = os.pathsep.join([env["PYTHONPATH"], str(REPO_ROOT), ""])
    result = subprocess.run(
        [sys.executable, "-c", _PATH_CHECK, when],
        cwd=REPO_ROOT / "src" / "servonaut" / "config", env=env,
        capture_output=True, text=True, timeout=COMMAND_TIMEOUT,
    )
    assert result.returncode == 0, result.stderr
    if when == "early":
        assert result.stdout.startswith("secrets:") and "servonaut" not in result.stdout
    else:
        assert result.stdout.startswith("refused:") and "from the checkout root" in result.stdout


def test_only_the_package_itself_counts_as_inside_it(journey, monkeypatch):
    from e2e.sandbox import import_path

    def checkout(root: Path) -> Path:
        (root / "src" / "servonaut" / "config").mkdir(parents=True)
        (root / "src" / "servonaut" / "__init__.py").write_text("")
        return root

    # One checkout in an ordinary folder, one that lives at .../src/servonaut.
    plain = checkout(journey.directory / "work" / "servonaut-checkout")
    nested = checkout(journey.directory / "home" / "src" / "servonaut")
    for root in (plain, nested):
        assert not import_path.inside_package(str(root))
        assert not import_path.inside_package(str(root / "src"))
        assert import_path.inside_package(str(root / "src" / "servonaut"))
        assert import_path.inside_package(str(root / "src" / "servonaut" / "config"))
    kept = [str(nested), str(nested / "src"), str(plain / "src")]
    dropped = [str(nested / "src" / "servonaut" / "config"), str(plain / "src" / "servonaut")]
    monkeypatch.setattr(sys, "path", [*kept, *dropped])
    assert import_path.drop_package_dirs() == dropped
    assert sys.path == kept


# A sandbox process without /proc (as on macOS): its PATH holds only fake
# tools and its guard refuses other programs, yet `ps` must still answer.
_WITHOUT_PROC = """
import json, os, sys
from e2e.sandbox import state

state.can_list_processes = lambda: False
target = int(sys.argv[1])
identity = state.process_identity(target)
print(json.dumps({
    "identity": identity,
    "alive": state.process_alive(target, identity),
    "command": state.process_command(target),
}))
"""


def _without_proc(journey, pid: int, **env: str) -> dict:
    child_env = journey.child_env(journey.new_sandbox("no-proc"))
    child_env["PYTHONPATH"] = os.pathsep.join([child_env["PYTHONPATH"], str(REPO_ROOT)])
    result = subprocess.run(
        [sys.executable, "-c", _WITHOUT_PROC, str(pid)], cwd=REPO_ROOT,
        env={**child_env, **env}, capture_output=True, text=True, timeout=COMMAND_TIMEOUT,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_process_identity_without_proc_works_inside_a_sandbox(journey):
    if shutil.which("ps", path="/bin:/usr/bin") is None:
        pytest.skip("needs the system ps")
    subject = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.read()"], stdin=subprocess.PIPE,
        env=journey.child_env(journey.new_sandbox("subject")),
    )
    try:
        # Asked from two time zones, the same process has the same identity:
        # its start time. (The state beside it is read live, running or
        # sleeping, and only ever used to tell a zombie apart.)
        east = _without_proc(journey, subject.pid, TZ="Pacific/Auckland")
        west = _without_proc(journey, subject.pid, TZ="America/New_York")
        assert east["identity"] and west["identity"]
        assert east["identity"][1] == west["identity"][1]
        assert east["identity"][0] not in ("Z", "X")
        assert east["alive"] and west["alive"]
        assert "sys.stdin.read()" in east["command"]
    finally:
        subject.kill()
        subject.wait()
    # Once it is gone, it is gone.
    assert _without_proc(journey, subject.pid)["identity"] is None


@pytest.mark.asyncio
@pytest.mark.timeout(JOURNEY_TIMEOUT)
async def test_up_waits_for_a_down_that_holds_the_pointer(qa_sandbox):
    def said(text: str) -> bool:
        return text in qa_sandbox.stderr.read_text(encoding="utf-8")

    # The pointer lock, as a `down` holds it while it stops survivors.
    with state.pointer_lock(qa_sandbox.pointer):
        # A stop while waiting ends the wait at once.
        waiting = qa_sandbox.start()
        await _until(lambda: said("waiting for another QA sandbox command"), "the wait")
        waiting.terminate()
        assert await asyncio.to_thread(waiting.wait, COMMAND_TIMEOUT) == 2
        assert said("stopped while waiting")
        assert not qa_sandbox.root.exists() and not qa_sandbox.pointer.exists()

        owner = qa_sandbox.start()
        await _until(lambda: said("waiting for another QA sandbox command"), "the wait")
    assert owner.stdout is not None
    line = await asyncio.wait_for(asyncio.to_thread(owner.stdout.readline), READY_TIMEOUT)
    assert line.startswith("SANDBOX READY"), qa_sandbox.stderr.read_text(encoding="utf-8")
    await qa_sandbox.down()


@pytest.mark.asyncio
@pytest.mark.timeout(JOURNEY_TIMEOUT)
async def test_unusable_roots_are_refused_with_the_reason(qa_sandbox, journey):
    # A regular file where the root should be: its marker cannot even be opened.
    not_a_directory = journey.directory / "not-a-directory"
    not_a_directory.write_text("")
    refused = await qa_sandbox.command("up", "--root", str(not_a_directory))
    assert refused.returncode == 2 and "Not a directory" in refused.stderr, refused.stderr
    assert "flock" not in refused.stderr

    record = {"schema": state.SCHEMA, "root": str(not_a_directory), "owner_pid": os.getpid()}
    state.write_json(qa_sandbox.pointer, record)
    status = await qa_sandbox.command("status")
    assert status.returncode == 1 and "Cannot tell whether" in status.stderr, status.stderr
    assert "Not a directory" in status.stderr
    qa_sandbox.pointer.unlink()

    # Inside the checkout only the ignored top-level .qa-sandbox* names are allowed.
    for inside in (REPO_ROOT / "qa-root", REPO_ROOT / "e2e" / ".qa-sandbox"):
        refused = await qa_sandbox.command("up", "--root", str(inside))
        assert refused.returncode == 2 and "is inside the checkout" in refused.stderr
        assert not inside.exists()
