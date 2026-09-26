"""Journey: an MCP client runs the remote tools against a real SSH server.

``servonaut --mcp`` runs as a child process at the standard guard level and
reaches ``web-1`` (a custom server) with the real OpenSSH client. The agent
reads a log file, tails a log, collects server facts and builds the server's
memory; each answer comes from the server's own files and tools. A compound
command is refused before anything reaches the server, while the dangerous
level runs it as written.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import remote_fleet
from e2e.harness.seed import HomeSeeder

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd, pytest.mark.asyncio]

WEB_1 = remote_fleet.fleet.WEB_1.name
COMPOUND = "tail x; id"


def _mcp_home(journey, sshd, fake_cloud, level: str):
    from servonaut.config.schema import MCPConfig

    sandbox = journey.new_sandbox(f"mcp-{level}")
    seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
    remote_fleet.seed_web_1(sshd, seeder, sandbox.home, mcp=MCPConfig(guard_level=level))
    return sandbox


def _split(result: str) -> tuple[str, list[str]]:
    """(command output, stderr lines) of a run_command answer."""
    body = result.removesuffix("\n[transport_used: ssh]")
    stdout, _, stderr = body.partition("\nSTDERR:\n")
    return stdout, [line for line in stderr.splitlines() if line.strip()]


def _only_host_key_notices(stderr: list[str]) -> bool:
    # The app turns off known-hosts checking, so OpenSSH notes every new key.
    return all(line.startswith("Warning: Permanently added") for line in stderr)


def _audit(sandbox) -> list[dict]:
    path = sandbox.home / ".servonaut" / "mcp_audit.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


async def test_standard_level_reads_a_real_server(mcp, journey, fake_cloud, sshd):
    sandbox = _mcp_home(journey, sshd, fake_cloud, "standard")

    async with mcp(sandbox) as session:
        tail = await session.call(
            "run_command",
            {"instance_id": WEB_1, "command": "tail -n 2 /var/log/app/worker.log"},
        )
        logs = await session.call(
            "get_logs", {"instance_id": WEB_1, "log_path": "/var/log/syslog", "lines": 1}
        )
        info = await session.call("get_server_info", {"instance_id": WEB_1})
        built = json.loads(await session.call("build_server_memory", {"instance_id": WEB_1}))
        memory = await session.call("get_server_memory", {"instance_id": WEB_1})
        refused = await session.call("run_command", {"instance_id": WEB_1, "command": COMPOUND})

    assert tail.endswith("[transport_used: ssh]")
    stdout, stderr = _split(tail)
    assert stdout == "worker: job 1 done\nworker: job 2 done\n"
    assert _only_host_key_notices(stderr), stderr
    assert "CRON[901]" in logs and "Started Daily" not in logs
    assert info.splitlines()[0] == WEB_1
    assert "load average" in info and "/dev/vda1" in info and "Mem:" in info
    assert "os" in built["successes"], built
    assert "E2E Linux 12 (fixture)" in memory

    assert refused.startswith("Blocked:"), refused
    commands = sshd.target.commands()
    assert "tail -n 2 /var/log/app/worker.log" in commands
    assert "tail -n 1 -- /var/log/syslog" in commands
    assert "cat /etc/os-release" in commands
    assert COMPOUND not in commands
    assert {entry["user"] for entry in sshd.target.sessions("exec")} == {
        remote_fleet.fleet.WEB_1.username
    }
    denied = [r for r in _audit(sandbox) if r.get("args", {}).get("command") == COMPOUND]
    assert [r["allowed"] for r in denied] == [False]


async def test_dangerous_level_runs_a_compound_command(mcp, journey, fake_cloud, sshd):
    sandbox = _mcp_home(journey, sshd, fake_cloud, "dangerous")

    async with mcp(sandbox) as session:
        output = await session.call("run_command", {"instance_id": WEB_1, "command": COMPOUND})

    assert sshd.target.commands() == [COMPOUND]
    assert output.endswith("[transport_used: ssh]")
    stdout, stderr = _split(output)
    assert stdout.startswith("uid="), output
    assert any("tail: cannot open 'x'" in line for line in stderr), stderr
