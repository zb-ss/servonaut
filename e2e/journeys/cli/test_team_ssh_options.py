"""Journey: an SSH option a team set runs a program here only after the member allows it.

A custom server (or a connection profile) carries ``ProxyCommand=touch <marker>``.
While the option is refused, ``servonaut ssh`` stops before any ssh process
starts and the marker is never created. After ``servonaut team options allow``,
ssh is started with the option on its command line (the sandbox's ssh stand-in
never runs a program a ProxyCommand names). A profile saved before
Servonaut recorded where options come from is refused the same way for a
member who has an account.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import remote_fleet
from e2e.harness.seed import HomeSeeder

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd]

WEB_1 = remote_fleet.fleet.WEB_1


def _config(sshd, seeder, home, marker, **extra):
    from servonaut.config.schema import SSHConfig

    server = remote_fleet.web_1(sshd)
    server.extra_ssh_options = [f"ProxyCommand=touch {marker}"]
    sshd.install_client_key(home, remote_fleet.WEB_1_KEY)
    return seeder.config(custom_servers=[server], **extra), SSHConfig


def test_a_team_proxy_command_is_refused_until_it_is_allowed(journey, fake_cloud, sshd, cli):
    sandbox = journey.new_sandbox()
    seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
    marker = sandbox.home / "proxy-ran"
    option = f"proxycommand=touch {marker}"
    from servonaut.config.schema import SSHConfig

    _config(
        sshd, seeder, sandbox.home, marker,
        ssh=SSHConfig(
            team_options_checked=True,
            team_options=[{"option": option, "team": "7", "team_name": "Acme", "allowed": False}],
        ),
    )

    refused = cli(sandbox, "ssh", WEB_1.name, stdin="hostname\n")

    assert refused.returncode == 4, refused.describe()
    assert (
        f"Not connecting: the custom server '{WEB_1.name}' came from team Acme and sets "
        "ProxyCommand, which runs a program on this computer."
    ) in refused.stderr
    assert not marker.exists()
    assert journey.shims.calls("ssh") == []
    assert sshd.target.sessions() == []

    listed = cli(sandbox, "team", "options")
    assert f"1  refused  Team Acme  {option}" in listed.stdout
    allowed = cli(sandbox, "team", "options", "allow", "1")
    assert allowed.returncode == 0, allowed.describe()

    cli(sandbox, "ssh", WEB_1.name, stdin="hostname\n")

    # The sandbox's ssh stand-in refuses to run any program a ProxyCommand names,
    # so the marker is never created here; what it records is the command line
    # the real client was handed, which now carries the option.
    [call] = journey.shims.calls("ssh")
    assert f"ProxyCommand=touch {marker}" in call.argv
    assert not marker.exists()


def test_a_profile_saved_before_options_were_recorded_is_refused_for_a_member(
    journey, fake_cloud, sshd, cli
):
    from servonaut.config.schema import ConnectionProfile, ConnectionRule

    sandbox = journey.new_sandbox()
    seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
    marker = sandbox.home / "old-proxy-ran"
    remote_fleet.seed_web_1(
        sshd, seeder, sandbox.home,
        connection_profiles=[ConnectionProfile(name="jump", proxy_command=f"touch {marker}")],
        connection_rules=[ConnectionRule(
            name="all", match_conditions={"name_contains": "web"}, profile_name="jump",
        )],
    )
    (sandbox.home / ".servonaut" / "auth.json").write_text(json.dumps({
        "teams_fetched_at": 1.0, "teams_cached": [{"slug": "acme", "name": "Acme"}],
    }))

    refused = cli(sandbox, "ssh", WEB_1.name, stdin="hostname\n")

    assert refused.returncode == 4, refused.describe()
    assert (
        "Not connecting: the connection profile 'jump' sets ProxyCommand, which runs a program on "
        "this computer. It was saved before Servonaut recorded where settings come from."
    ) in refused.stderr
    assert not marker.exists()
    assert journey.shims.calls("ssh") == []
    assert f"1  refused  Saved before 2.33.1  proxycommand=touch {marker}" in cli(
        sandbox, "team", "options"
    ).stdout
