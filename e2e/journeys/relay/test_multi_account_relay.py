"""Journey: ``servonaut connect`` with two Hetzner projects.

A signed-in home runs the real listener as a child process, configured with
the primary Hetzner project and a second one (``staging``); both have a
server named ``web-1``. The handshake tells the service which account
labels each provider has (labels only). Web-console commands reach the
server a ``<project>/<name>`` reference or a name only one project uses
points at, over (fake) ssh at that server's address; the bare shared name
is refused with the candidates and nothing runs. AI chat tool calls can
scope a listing to one account.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import fleet
from e2e.harness.fake_providers import hetzner as fake_hetzner
from e2e.harness.relay_events import (
    command_event,
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
