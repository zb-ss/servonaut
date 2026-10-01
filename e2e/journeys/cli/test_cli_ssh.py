"""Journey: ``servonaut ssh <server>`` from the command line, without a terminal.

The CLI runs as a real child process and opens a real OpenSSH session to the
loopback target with the custom server's user, port and key. Commands piped
to it run on the server and their output comes back on stdout. Running a
single command given after ``--`` is how most SSH front ends are scripted.
A server that matches a connection rule is reached the way the TUI reaches
it: through the rule's bastion, at its private address. A provider account
that was never listed is read before a name counts as unique, but an API that
never answers holds the command up only for the time the config allows.
"""

from __future__ import annotations

import socket
import threading
import time
from contextlib import contextmanager

import pytest

from e2e.harness import fleet, remote_fleet
from e2e.harness.known_issues import known_issue
from e2e.harness.remote_root import OS_RELEASE
from e2e.harness.seed import HomeSeeder
from e2e.harness.shims import jump_host
from e2e.harness.sshd import BASTION_ALIAS

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd]

WEB_1 = remote_fleet.fleet.WEB_1
APP_1 = fleet.APP_1


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


def test_a_connection_rule_routes_ssh_through_its_bastion(journey, fake_cloud, sshd, cli):
    sandbox = journey.new_sandbox()
    seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
    remote_fleet.seed_app_1_behind_bastion(sshd, seeder, sandbox.home)
    sshd.target.remote.write("/etc/hostname", f"{APP_1.name}\n")

    result = cli(sandbox, "ssh", APP_1.name, "--", "hostname")

    assert result.returncode == 0, result.describe()
    assert result.stdout.strip() == APP_1.name
    # The private address, through the bastion the rule names.
    argv = journey.shims.calls("ssh")[0].argv
    assert jump_host(argv) == f"{fleet.BASTION_USER}@{BASTION_ALIAS}"
    assert argv[-2:] == [f"{fleet.BASTION_USER}@{APP_1.private_ip}", "hostname"]
    assert [f["destination"] for f in sshd.bastion.sessions("forward")] == [
        f"{APP_1.private_ip}:22"
    ]
    bastion_logins = sshd.bastion.sessions("auth")
    assert bastion_logins and all(a["accepted"] for a in bastion_logins)
    assert sshd.target.commands(user=fleet.BASTION_USER) == ["hostname"]


@contextmanager
def _unanswering_api():
    """A loopback HTTP endpoint that accepts connections and never answers."""
    listener = socket.create_server(("127.0.0.1", 0))
    held, stop = [], threading.Event()

    def accept():
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                held.append(listener.accept()[0])
            except OSError:
                continue

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}/v1"
    finally:
        stop.set()
        thread.join()
        for connection in held:
            connection.close()
        listener.close()


def test_an_api_that_never_answers_holds_ssh_up_only_briefly(journey, fake_cloud, sshd, cli):
    sandbox = journey.new_sandbox()
    seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
    # A Hetzner project never listed on this machine, and two seconds to list it.
    remote_fleet.seed_web_1(
        sshd, seeder, sandbox.home,
        hetzner=seeder.hetzner_config(), account_check_timeout_seconds=2,
    )
    seeder.cache()
    with _unanswering_api() as url:
        journey.env_overrides["SERVONAUT_HETZNER_API_URL"] = url

        begin = time.monotonic()
        result = cli(sandbox, "ssh", WEB_1.name, "--", "hostname")
        first = time.monotonic() - begin
        again = cli(sandbox, "ssh", WEB_1.name, "--", "hostname")

    assert result.returncode == 0, result.describe()
    assert result.stdout.strip() == WEB_1.name
    # The request gets half the budget to answer, then gives up.
    (note,) = [line for line in result.stderr.splitlines() if line.startswith("Note:")]
    assert note.startswith("Note: Hetzner project 'hetzner' could not be listed (")
    assert "timed out" in note
    assert note.endswith(f"its servers were not checked for '{WEB_1.name}'")
    # Two seconds at most for the lookup; nothing waits for the silent API
    # after that; the rest is start-up and the SSH session.
    assert first < 2 + 4, result.describe()
    # The failure is remembered: the next command does not wait for it again.
    assert again.returncode == 0, again.describe()
    assert "; at " in again.stderr and "tried again after" in again.stderr
    assert again.duration < first
