"""Journey: ``servonaut ssh <server>`` from the command line, without a terminal.

The CLI runs as a real child process and opens a real OpenSSH session to the
loopback target with the custom server's user, port and key. Commands piped
to it run on the server and their output comes back on stdout. Running a
single command given after ``--`` is how most SSH front ends are scripted.
"""

from __future__ import annotations

import pytest

from e2e.harness import remote_fleet
from e2e.harness.known_issues import known_issue
from e2e.harness.remote_root import OS_RELEASE
from e2e.harness.seed import HomeSeeder

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd]

WEB_1 = remote_fleet.fleet.WEB_1


def _home(journey, sshd, fake_cloud):
    sandbox = journey.new_sandbox()
    seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
    remote_fleet.seed_web_1(sshd, seeder, sandbox.home)
    return sandbox


def test_commands_piped_to_ssh_run_on_the_server(journey, fake_cloud, sshd, cli):
    sandbox = _home(journey, sshd, fake_cloud)

    result = cli(sandbox, "ssh", WEB_1.name, stdin="hostname\ncat /etc/os-release\n")

    assert result.returncode == 0, result.describe()
    assert result.stdout.splitlines()[0] == WEB_1.name
    assert OS_RELEASE.splitlines()[0] in result.stdout
    # One login, as the custom server's user, with the key from its entry.
    assert [s["user"] for s in sshd.target.sessions("shell")] == [WEB_1.username]
    logins = sshd.target.sessions("auth")
    assert logins and all(a["accepted"] and a["user"] == WEB_1.username for a in logins)
    argv = journey.shims.calls("ssh")[-1].argv
    assert argv[argv.index("-p") + 1] == str(sshd.target.port)
    assert argv[argv.index("-i") + 1] == str(sandbox.home / ".ssh" / remote_fleet.WEB_1_KEY)


def test_an_unknown_server_is_reported(journey, fake_cloud, sshd, cli):
    sandbox = _home(journey, sshd, fake_cloud)

    result = cli(sandbox, "ssh", "db-9")

    assert result.returncode == 1, result.describe()
    assert "No instance found matching 'db-9'" in result.stderr
    assert sshd.target.sessions() == []


def test_a_command_after_a_double_dash_runs_on_the_server(journey, fake_cloud, sshd, cli):
    sandbox = _home(journey, sshd, fake_cloud)

    result = cli(sandbox, "ssh", WEB_1.name, "--", "hostname")

    known_issue(
        result.returncode == 2 and "unrecognized arguments: hostname" in result.stderr,
        "the command after -- is rejected as an unrecognized argument",
    )
    assert result.returncode == 0, result.describe()
    assert result.stdout.strip() == WEB_1.name
    assert sshd.target.commands() == ["hostname"]
