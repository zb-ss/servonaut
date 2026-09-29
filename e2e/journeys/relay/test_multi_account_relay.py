"""Journey: ``servonaut connect`` with two Hetzner projects.

A signed-in home runs the real listener as a child process, configured with
the primary Hetzner project and a second one (``staging``); both have a
server named ``web-1``. The handshake tells the service which account
labels each provider has (labels only). Web-console commands reach the
server a ``<project>/<name>`` reference or a name only one project uses
points at, over (fake) ssh at that server's address; the bare shared name
is refused with the candidates and nothing runs. AI chat tool calls can
scope a listing to one account.

With two AWS accounts, each holding an IP-ban config, a ban remediation for
a server uses the config of that server's own account, and is refused when
that account has none rather than banning in another account's IP set.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import aws, fleet
from e2e.harness.fake_providers import hetzner as fake_hetzner
from e2e.harness.relay_events import (
    command_event,
    remediation_event,
    tool_call_event,
    wait_for_result,
    wait_for_tool_result,
    wait_until_connected,
)
from e2e.harness.seed import HomeSeeder

pytestmark = [pytest.mark.e2e_pr]

STAGING = fleet.HETZNER_SECOND_ACCOUNT
PRIMARY = fake_hetzner.PRIMARY_LABEL
SHARED = fleet.SHARED_NAME
STAGING_WEB_1 = fleet.HZ_SECOND_WEB_1
STAGING_LB_1 = fleet.HZ_SECOND_LB_1
PROD = fleet.AWS_SECOND_ACCOUNT
REGION = "us-east-1"


def _address(host) -> str:
    return host.public_ip.replace(".", r"\.")


def test_commands_reach_the_server_of_the_named_project(
    journey, fake_cloud, providers, account_home, relay
):
    fleet.seed_provider_fleet(providers, ovh=False)
    fleet.seed_second_accounts(providers, ovh=False)
    home = account_home(
        hetzner=HomeSeeder.hetzner_config(accounts=[HomeSeeder.hetzner_account(STAGING)]),
    )
    journey.shims.when("ssh", rf"root@{_address(STAGING_WEB_1)} .*uptime", stdout=" up 3 days\n")
    journey.shims.when("ssh", rf"root@{_address(STAGING_LB_1)} .*uptime", stdout=" up 9 days\n")
    listener = relay(home).start()
    user_id = wait_until_connected(fake_cloud, listener)

    handshake = fake_cloud.relay.heartbeats()[0]
    assert handshake["type"] == "cli.handshake"
    assert handshake["accounts"] == {"aws": ["aws"], "hetzner": [PRIMARY, STAGING], "ovh": []}

    publish = fake_cloud.relay.publish
    publish(command_event(
        "cmd-qualified", user_id, "run_command", f"{STAGING}/{SHARED}", {"command": "uptime"},
    ))
    qualified = wait_for_result(fake_cloud, "cmd-qualified", listener)
    assert qualified["status"] == "success", qualified
    assert "up 3 days" in qualified["output"]
    assert f"root@{STAGING_WEB_1.public_ip}" in journey.shims.calls("ssh")[-1].argv

    publish(command_event(
        "cmd-only-there", user_id, "run_command", STAGING_LB_1.name, {"command": "uptime"},
    ))
    only_there = wait_for_result(fake_cloud, "cmd-only-there", listener)
    assert only_there["status"] == "success", only_there
    assert "up 9 days" in only_there["output"]

    calls = len(journey.shims.calls("ssh"))
    publish(command_event("cmd-shared", user_id, "run_command", SHARED, {"command": "uptime"}))
    shared = wait_for_result(fake_cloud, "cmd-shared", listener)
    assert shared["status"] == "error"
    assert f"'{SHARED}' matches 2 servers" in shared["error_message"]
    for reference in (f"{PRIMARY}/{SHARED}", f"{STAGING}/{SHARED}"):
        assert reference in shared["error_message"]
    assert len(journey.shims.calls("ssh")) == calls

    publish(
        tool_call_event("tc-staging", user_id, "list_instances", {"account": STAGING}),
        topic="ai-tool-calls",
    )
    listing = json.dumps(wait_for_tool_result(fake_cloud, "tc-staging", listener)["result"])
    assert f"{STAGING}/{SHARED}" in listing and f"{STAGING}/{STAGING_LB_1.name}" in listing
    assert f"{PRIMARY}/{SHARED}" not in listing

    assert listener.interrupt() in (0, 130)
    assert "Traceback" not in listener.output()


def _ban(user_id, request_id, target):
    return remediation_event(
        request_id, user_id, "block_ip", target,
        {"finding_id": f"fnd-{request_id}", "action": "block_ip", "ip": "9.9.9.9",
         "method": "waf", "dry_run": True},
    )


def test_a_ban_uses_the_config_of_the_servers_account(
    journey, fake_cloud, moto, account_home, relay
):
    from servonaut.config.schema import IPBanConfig

    role_arn = moto.seed_role(aws.ACCOUNT_ROLE, aws.SECOND_ACCOUNT)
    moto.seed_fleet(fleet.AWS_SECOND_FLEET, role_arn=role_arn)
    home = account_home(
        aws=HomeSeeder.aws_config(
            regions=[REGION], accounts=[HomeSeeder.aws_account(PROD, regions=[REGION])],
        ),
        ip_ban_configs=[
            IPBanConfig(name="waf-default", method="waf", ip_set_name="edge", region=REGION),
            IPBanConfig(name="waf-prod", method="waf", ip_set_name="edge", region=REGION,
                        account=PROD),
            IPBanConfig(name="sg-default", method="security_group",
                        security_group_id="sg-0e2e", region=REGION),
        ],
    )
    seeder = HomeSeeder(home.home)
    seeder.aws_profile("base")
    seeder.aws_profile(PROD, role_arn=role_arn, source_profile="base")
    listener = relay(home).start()
    user_id = wait_until_connected(fake_cloud, listener)
    publish = fake_cloud.relay.publish

    # A server of the second account: its own account's config.
    publish(_ban(user_id, "ban-prod", f"{PROD}/{SHARED}"))
    prod = wait_for_result(fake_cloud, "ban-prod", listener)
    assert prod["status"] == "success", prod
    assert "via waf config 'waf-prod'" in json.loads(prod["output"])["stdout_tail"]

    # A server of the default account (from its cache): the default config.
    publish(_ban(user_id, "ban-default", fleet.APP_1.name))
    default = wait_for_result(fake_cloud, "ban-default", listener)
    assert default["status"] == "success", default
    assert "via waf config 'waf-default'" in json.loads(default["output"])["stdout_tail"]

    # The second account has no security-group config: refused, never the
    # default account's one.
    publish(remediation_event(
        "ban-prod-sg", user_id, "block_ip", f"{PROD}/{SHARED}",
        {"finding_id": "fnd-sg", "action": "block_ip", "ip": "9.9.9.9",
         "method": "security_group", "dry_run": True},
    ))
    refused = wait_for_result(fake_cloud, "ban-prod-sg", listener)
    assert refused["status"] == "error"
    assert refused["error_message"].startswith(
        "block_ip_config_missing: no IP-ban configuration with method "
        f"'security_group' acts in AWS account '{PROD}'"
    )

    assert listener.interrupt() in (0, 130)
    assert "Traceback" not in listener.output()
