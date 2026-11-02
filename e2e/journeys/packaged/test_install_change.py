"""Journey: switch installs, remove the old one, and keep the coding agent working.

The user registers the MCP server from one installation, installs Servonaut
again elsewhere and deletes the first copy, so the agent config now names a
command that no longer exists. Starting the new installation's TUI repoints
the entry at itself and says so; the repaired command starts a working MCP
server, and ``--mcp-repair`` afterwards finds nothing left to fix.
"""

from __future__ import annotations

import json
import shutil

import pytest

from e2e.harness.processes import mcp_session, require_armed
from e2e.harness.terminal import run_in_terminal
from e2e.journeys.packaged import support

pytestmark = [pytest.mark.e2e_pr, pytest.mark.timeout(300)]


def _servonaut_entry(sandbox) -> dict:
    return json.loads((sandbox.home / ".claude.json").read_text())["mcpServers"]["servonaut"]


@pytest.mark.asyncio
async def test_the_new_install_repairs_the_agent_left_on_the_removed_one(
    journey, installs, current_wheel, build_version, fake_cloud
):
    sandbox = journey.new_sandbox()
    installs.offer(current_wheel, version=build_version)
    old = installs.venv(sandbox, "old-venv")
    support.ok(old.pip(sandbox, "install", "servonaut"))
    support.seed(installs, sandbox, old.python)
    support.ok(old.run(sandbox, "--mcp-install", "claude"))
    assert _servonaut_entry(sandbox)["command"] == str(old.console)

    new = installs.venv(sandbox, "new-venv")
    support.ok(new.pip(sandbox, "install", "servonaut"))
    shutil.rmtree(old.path)

    names = support.fleet_names()
    run = run_in_terminal(
        [str(new.console)],
        env=installs.env(sandbox),
        cwd=sandbox.base,
        until=lambda text: "repaired its" in text and all(name in text for name in names),
        description="the repair notification in the new install's TUI",
    )
    assert run.returncode == 0, run.text[-2000:]
    require_armed(installs.armed_log, pid=run.pid)
    assert "Claude Code" in run.text

    entry = _servonaut_entry(sandbox)
    assert (entry["command"], entry["args"]) == (str(new.console), ["--mcp"])
    async with mcp_session(
        [entry["command"]],
        env=installs.env(sandbox),
        cwd=sandbox.base,
        stderr_path=journey.staging / "mcp.stderr.log",
        armed_log=journey.armed_log,
    ) as session:
        assert "list_instances" in await session.tool_names()

    check = support.ok(new.run(sandbox, "--mcp-repair"))
    assert "Claude Code (~/.claude.json): ok" in check.stdout
