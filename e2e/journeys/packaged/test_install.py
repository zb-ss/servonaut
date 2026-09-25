"""Journey: install the built wheel the way users do and use it.

The wheel built from the checkout is installed by name from the local
package index, with pip into a fresh venv and with pipx. Every dependency is
already satisfied, so the index only ever serves Servonaut. The ``servonaut``
console script then works like a user's: version, help and a bad option, a
sign-in against FakeCloud, registering the MCP server with a coding agent
and starting it with exactly the command that was registered, and the TUI in
a real terminal showing the fleet before it quits.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness.processes import mcp_session
from e2e.journeys.packaged import support

pytestmark = [pytest.mark.e2e_pr, pytest.mark.timeout(300)]


def _index_traffic(fake_cloud) -> set[str]:
    return {
        entry["path"]
        for entry in fake_cloud.requests()
        if entry["path"].startswith(("/simple/", "/packages/"))
    }


def _assert_cli_basics(install, sandbox, version):
    assert support.reported_version(install, sandbox) == version
    usage = support.ok(install.run(sandbox, "--help")).stdout
    assert usage.startswith("usage: servonaut ")
    for option in ("--update", "--mcp", "--mcp-install", "--list-backups", "--restore-backup"):
        assert option in usage
    wrong = install.run(sandbox, "--no-such-option")
    assert wrong.returncode == 2, wrong.describe()
    assert "unrecognized arguments: --no-such-option" in wrong.stderr


@pytest.mark.asyncio
async def test_pip_install_into_a_fresh_venv(journey, installs, current_wheel, fake_cloud):
    from servonaut import __version__ as current

    sandbox = journey.new_sandbox()
    installs.offer(current_wheel, version=current)
    venv = installs.venv(sandbox)

    installed = support.ok(venv.pip(sandbox, "install", "servonaut"))
    assert f"Successfully installed servonaut-{current}" in installed.stdout
    assert _index_traffic(fake_cloud) == {"/simple/servonaut/", f"/packages/{current_wheel.name}"}

    _assert_cli_basics(venv, sandbox, current)
    login = support.ok(venv.run(sandbox, "login", "--no-browser"))
    assert "Signed in successfully (plan: solo)" in login.stdout
    support.seed(installs, sandbox, venv.python)

    # The agent config names the installed console script, and that exact
    # command starts a working MCP server.
    support.ok(venv.run(sandbox, "--mcp-install", "claude"))
    entry = json.loads((sandbox.home / ".claude.json").read_text())["mcpServers"]["servonaut"]
    assert (entry["command"], entry["args"]) == (str(venv.console), ["--mcp"])
    async with mcp_session(
        [entry["command"]],
        env=installs.env(sandbox),
        cwd=sandbox.base,
        stderr_path=journey.staging / "mcp.stderr.log",
        armed_log=journey.armed_log,
    ) as session:
        assert "list_instances" in await session.tool_names()
        listing = await session.call("list_instances")
    for name in support.fleet_names():
        assert name in listing

    support.boot_tui(installs, sandbox, venv.console, support.fleet_names())


def test_pipx_install_with_its_own_home(
    journey, installs, current_wheel, fake_cloud, pipx_available
):
    from servonaut import __version__ as current

    sandbox = journey.new_sandbox()
    installs.offer(current_wheel, version=current)
    pipx = installs.pipx(sandbox)

    support.ok(pipx.install(sandbox))
    assert _index_traffic(fake_cloud) == {"/simple/servonaut/", f"/packages/{current_wheel.name}"}
    listed = support.ok(pipx.pipx(sandbox, "list", "--short")).stdout
    assert f"servonaut {current}" in listed
    assert pipx.console.is_symlink()
    assert pipx.console.resolve().parent == (pipx.venv / "bin").resolve()

    _assert_cli_basics(pipx, sandbox, current)
    support.seed(installs, sandbox, pipx.python)
    support.boot_tui(installs, sandbox, pipx.console, support.fleet_names())
