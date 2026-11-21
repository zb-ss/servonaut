"""The installed MCP console works when its local logging storage is unwritable."""

import asyncio
import json
import os

import pytest

from e2e.harness.processes import mcp_session
from e2e.harness.waits import wait_for
from e2e.journeys.packaged import support

pytestmark = [pytest.mark.e2e_pr, pytest.mark.timeout(300)]


@pytest.mark.asyncio
@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0,
                    reason="requires POSIX permission enforcement for the child")
@pytest.mark.parametrize("blocked", ["home", "logs_and_audit"])
async def test_mcp_lists_tools_without_writable_logs(
    journey, installs, current_wheel, build_version, pipx_available, blocked,
):
    sandbox = journey.new_sandbox()
    installs.offer(current_wheel, version=build_version)
    pipx = installs.pipx(sandbox)
    support.ok(pipx.install(sandbox, "servonaut[mcp]"))
    installs.extra_env["SERVONAUT_SKIP_AUTO_APPLY"] = "0"
    root = sandbox.home / ".servonaut"
    if blocked == "home":
        assert not root.exists()
        restricted, mode = sandbox.home, 0o500
    else:
        root.mkdir()
        (root / "logs").touch()
        restricted, mode = root / "mcp_audit.jsonl", 0o400
        restricted.touch()
    original_mode = restricted.stat().st_mode & 0o777
    stderr = sandbox.base / "mcp-readonly.stderr.log"
    restricted.chmod(mode)
    try:
        async with mcp_session(
            [str(pipx.console)], env=installs.env(sandbox), cwd=sandbox.base,
            stderr_path=stderr, armed_log=journey.armed_log,
        ) as session:
            assert "list_instances" in await session.tool_names()
            assert not session.protocol_errors
            # Keep the console alive to reap the updater it started. Otherwise
            # the detached build can still be writing during sandbox teardown.
            states = root / "updates" / "installs"

            def builder_finished() -> bool:
                return all(
                    "builder" not in json.loads(path.read_text(encoding="utf-8"))
                    for path in states.glob("*/state.json")
                )

            await asyncio.to_thread(
                wait_for, builder_finished, timeout=90, desc="the MCP startup update builder",
            )
    finally:
        restricted.chmod(original_mode)

    warnings = stderr.read_text()
    assert warnings.count("MCP audit log is unavailable") == 1
    assert "Could not enable file logging" not in warnings
    assert "Traceback" not in warnings
    if blocked == "home":
        assert not root.exists()
