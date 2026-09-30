"""Journeys: the local QA sandbox (``python -m e2e.sandbox``) from ``up`` to ``down``.

The sandbox runs as a child of the test with its root inside the journey's
folder, and a person's environment of its own (home, state directory with
the per-user pointer). The test drives it as a person does: ``status``, the
CLI through ``run``, one MCP tool through ``mcp-call``, the desktop child in
headless Chromium with the printed start snippet, then ``down``. Afterwards
none of the sandbox's processes runs, its root is gone, and nothing was left
outside it: the pointer was the only file written there, and ``down``
removed it again.
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
from e2e.harness.desktop import wait_until
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

    async def up(self, *args: str) -> dict:
        self.stderr.parent.mkdir(parents=True, exist_ok=True)
        with self.stderr.open("w", encoding="utf-8") as stderr:
            self.owner = subprocess.Popen(
                self.argv("up", "--root", str(self.root), *args),
                cwd=REPO_ROOT, env=self.env, stdout=subprocess.PIPE, stderr=stderr, text=True,
            )
        assert self.owner.stdout is not None
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

    started = await qa_sandbox.command("desktop", "--json")
    assert started.returncode == 0, started.stderr
    info = json.loads(started.stdout)
    async with desktop.browser() as browser:
        page = await browser.new_page()
        assert await page.open(info["origin"]) == 200
        await page.page.evaluate(client.start_session_js(info["token"]))
        await page.wait_for_first_output()
        await page.wait_for_text("app-1")
        # The printed click helper aims where the harness's own click_cell does.
        await wait_until(lambda: page.dimensions, desc="the terminal size")
        size = await page.page.evaluate("() => window.servonautQa")
        assert size == {"columns": page.dimensions["width"], "rows": page.dimensions["height"]}
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
