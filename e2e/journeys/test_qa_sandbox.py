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
        assert await asyncio.to_thread(self.owner.wait, COMMAND_TIMEOUT) == 0

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
        screen = await _screen(page)
        assert len(screen.splitlines()) == started["rows"] and "cache-1" in screen

        # Keys typed straight into the page reach the app: "/" focuses the fleet
        # search (the footer then lists the search box's keys), typing narrows.
        footer = screen.splitlines()[-1]
        await page.page.keyboard.press("/")
        await _screen_until(page, lambda text: text.splitlines()[-1] != footer, "search focused")
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
    assert qa_sandbox.root.exists() == keep
    assert state.sandbox_pids(qa_sandbox.root) == []
    # A kept root is provably the sandbox's own: the next start clears it.
    if keep:
        await qa_sandbox.up()
        await qa_sandbox.down()


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
state.confine_after(Path(current["root"]), [sys.argv[1]], lambda: print("confined", flush=True))
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


@pytest.mark.asyncio
@pytest.mark.timeout(JOURNEY_TIMEOUT)
async def test_a_host_that_outlives_the_sandbox_cannot_bring_it_back(qa_sandbox, journey):
    current = await qa_sandbox.up()
    home = Path(current["sandbox"]["home"])
    captures = journey.directory / "captures"
    host = subprocess.Popen(
        [sys.executable, "-c", _HOST_STAND_IN, str(captures)],
        cwd=REPO_ROOT, env=qa_sandbox.env, text=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    )
    assert host.stdin is not None and host.stdout is not None

    async def ask(path: Path) -> str:
        host.stdin.write(f"{path}\n")
        host.stdin.flush()
        return (await asyncio.wait_for(asyncio.to_thread(host.stdout.readline), 30)).strip()

    try:
        assert (await asyncio.wait_for(asyncio.to_thread(host.stdout.readline), 30)).strip() == "armed"
        assert await ask(home / "early.txt") == "wrote"
        await qa_sandbox.down()
        assert (await asyncio.wait_for(asyncio.to_thread(host.stdout.readline), 30)).strip() == "confined"
        assert await ask(home / "late.txt") == "refused"
        assert not qa_sandbox.root.exists()
        assert await ask(captures / "snapshot.svg") == "wrote"
    finally:
        host.kill()
        host.wait()
