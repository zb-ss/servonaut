"""Journey: ``servonaut memory build`` for a server behind a bastion.

The build shares ONE connection to the server instead of opening a new one per
probe command: the bastion sees a single login and a single forward however
many commands the probers run, and the shared connection is closed (and its
socket directory removed) when the build ends.
"""

from __future__ import annotations

import pytest

from servonaut.config.schema import MemoryConfig
from e2e.harness import fleet, remote_fleet
from e2e.harness.seed import HomeSeeder
from e2e.harness.shims import jump_host
from e2e.harness.sshd import BASTION_ALIAS

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd]

APP_1 = fleet.APP_1


def _option(argv: list[str], name: str) -> str | None:
    for flag, value in zip(argv, argv[1:]):
        if flag == "-o" and value.startswith(f"{name}="):
            return value.split("=", 1)[1]
    return None


def test_a_build_through_a_bastion_opens_one_shared_connection_and_closes_it(
    journey, fake_cloud, sshd, cli,
):
    sandbox = journey.new_sandbox()
    seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
    # A short folder inside the test root: the sandbox allows writes only there.
    mux_dir = journey.ctx.root / "mux"
    mux_dir.mkdir(exist_ok=True)
    remote_fleet.seed_app_1_behind_bastion(
        sshd, seeder, sandbox.home, memory=MemoryConfig(ssh_control_socket_dir=str(mux_dir)),
    )
    sshd.target.remote.write("/etc/hostname", f"{APP_1.name}\n")

    result = cli(sandbox, "memory", "build", APP_1.name)

    assert result.returncode == 0, result.describe()
    calls = [c.argv for c in journey.shims.calls("ssh")]
    masters = [a for a in calls if _option(a, "ControlMaster") == "yes"]
    commands = [a for a in calls if _option(a, "ControlMaster") == "no" and "-O" not in a]
    exits = [a for a in calls if "-O" in a and a[a.index("-O") + 1] == "exit"]
    assert len(masters) == 1, [c for c in calls if any("Control" in x for x in c)] or "no Control opts"
    assert jump_host(masters[0]) == f"{fleet.BASTION_USER}@{BASTION_ALIAS}"
    assert len(commands) >= 2, calls
    # Every command used the master's socket; the master was told to exit.
    socket_pattern = _option(masters[0], "ControlPath")
    assert socket_pattern and {_option(a, "ControlPath") for a in commands} == {socket_pattern}
    assert len(exits) == 1 and _option(exits[0], "ControlPath") == socket_pattern
    # The bastion saw the master's single hop, not one per probe command.
    assert [f["destination"] for f in sshd.bastion.sessions("forward")] == [f"{APP_1.private_ip}:22"]
