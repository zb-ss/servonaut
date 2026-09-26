"""Journey: ``servonaut connect`` in the foreground answers what the service sends.

A signed-in home runs the real listener as a child process. It subscribes
to its account's two topics on the (fake) Mercure hub, sends its handshake,
and then answers every kind of event the service publishes:

* web-console commands, run over (fake) ssh, with the blocklist applied;
* AI chat tool calls, answered on the chat tool-result route;
* monitoring probes and confirmed remediations, answered on the
  command-result route.

Events for another account are ignored, and an event the service publishes
on both topics runs once. Events are handled one at a time, so a final
sentinel event proves every earlier one has been dealt with.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import fleet
from e2e.harness.relay_events import (
    command_event,
    probe_event,
    remediation_event,
    tool_call_event,
    wait_for_result,
    wait_for_tool_result,
    wait_until_connected,
)

pytestmark = [pytest.mark.e2e_pr]

WEB_1 = fleet.WEB_1


def _web_1():
    from servonaut.config.schema import CustomServer

    return CustomServer(
        name=WEB_1.name,
        host=WEB_1.host,
        username=WEB_1.username,
        ssh_key=WEB_1.ssh_key,
        port=WEB_1.port,
        provider=WEB_1.provider,
        group=WEB_1.group,
    )


def test_listener_answers_every_event_kind(journey, fake_cloud, account_home, relay):
    home = account_home(custom_servers=[_web_1()])
    journey.shims.when("ssh", r"deploy@10\.0\.0\.11 .*uptime", stdout=" 10:00:00 up 3 days\n")
    journey.shims.when("ssh", r"tail -n 5 /var/log/syslog", stdout="line one\nline two\n")
    listener = relay(home).start()
    user_id = wait_until_connected(fake_cloud, listener)
    output = listener.output()

    assert f"Starting Servonaut relay listener (user: {user_id})" in output
    assert "AI chat tools: enabled" in output
    handshake = fake_cloud.relay.heartbeats()[0]
    assert handshake["type"] == "cli.handshake"
    assert handshake["capabilities"] == {"supports_dynamic_catalog": True}
    assert fake_cloud.requests("/api/cli/mercure-token")[0]["bearer_ok"]

    publish = fake_cloud.relay.publish

    # A web-console command runs over ssh with the server's user and port.
    publish(command_event("cmd-uptime", user_id, "run_command", WEB_1.name, {"command": "uptime"}))
    result = wait_for_result(fake_cloud, "cmd-uptime", listener)
    assert result["status"] == "success", result
    assert "up 3 days" in result["output"]
    ssh = journey.shims.calls("ssh")[-1].argv
    assert f"{WEB_1.username}@{WEB_1.host}" in ssh and str(WEB_1.port) in ssh

    # Log tailing becomes a validated tail command.
    publish(
        command_event(
            "cmd-logs", user_id, "get_logs", WEB_1.name,
            {"log_path": "/var/log/syslog", "lines": 5},
        )
    )
    assert "line two" in wait_for_result(fake_cloud, "cmd-logs", listener)["output"]

    # The blocklist applies to relayed commands; nothing reaches ssh.
    calls = len(journey.shims.calls("ssh"))
    publish(command_event("cmd-rm", user_id, "run_command", WEB_1.name, {"command": "rm -rf /"}))
    refused = wait_for_result(fake_cloud, "cmd-rm", listener)
    assert refused["status"] == "rejected"
    assert "blocklist" in refused["error_message"]
    assert len(journey.shims.calls("ssh")) == calls

    # An unknown server is an error, not a crash.
    publish(command_event("cmd-lost", user_id, "run_command", "no-such-host", {"command": "id"}))
    lost = wait_for_result(fake_cloud, "cmd-lost", listener)
    assert lost["status"] == "error" and "Instance not found" in lost["error_message"]

    # An AI chat tool call runs locally and answers on the chat route.
    publish(tool_call_event("tc-list", user_id, "list_instances", {}), topic="ai-tool-calls")
    tool = wait_for_tool_result(fake_cloud, "tc-list", listener)
    assert tool["status"] == "ok", tool
    assert tool["conversation_id"] == "conv-e2e-1"
    assert fleet.APP_1.name in json.dumps(tool["result"])

    # A monitoring probe answers on the command-result route with JSON output.
    publish(probe_event("probe-list", user_id, "list_instances"))
    probe = wait_for_result(fake_cloud, "probe-list", listener)
    assert probe["status"] == "success", probe
    assert isinstance(json.loads(probe["output"]), (dict, list))

    # Probes that are not read-only are refused with a slug-first error.
    publish(probe_event("probe-shell", user_id, "ssh_exec_readonly", WEB_1.name))
    denied = wait_for_result(fake_cloud, "probe-shell", listener)
    assert denied["status"] == "error"
    assert denied["error_message"].startswith("not_permitted:")

    # A confirmed remediation, as a dry run, reports what it would do.
    publish(
        remediation_event(
            "fix-ban", user_id, "block_ip", WEB_1.name,
            {"ip": "9.9.9.9", "method": "nftables", "dry_run": True},
        )
    )
    fix = wait_for_result(fake_cloud, "fix-ban", listener)
    assert fix["status"] == "success", fix
    outcome = json.loads(fix["output"])
    assert outcome["ok"] is True and outcome["dry_run"] is True
    assert "would ban 9.9.9.9" in outcome["stdout_tail"]

    # The client-side rails refuse a private address before anything runs.
    publish(
        remediation_event(
            "fix-private", user_id, "block_ip", WEB_1.name,
            {"ip": "10.0.0.99", "method": "nftables"},
        )
    )
    rail = wait_for_result(fake_cloud, "fix-private", listener)
    assert rail["status"] == "error"
    assert rail["error_message"].startswith("block_ip_address_not_public")

    output = listener.output()
    assert f"[run_command] {WEB_1.name}: v" in output
    assert "[ai:list_instances] ok v" in output
    assert "[probe:list_instances]" in output
    assert "[remediate:block_ip]" in output

    # Ctrl+C stops the listener cleanly (the exit status depends on the
    # Python version's asyncio signal handling) and frees the relay lock.
    assert listener.interrupt() in (0, 130)
    assert listener.lock_owner() is None
    assert "Traceback" not in listener.output()


def test_foreign_and_duplicate_events_are_not_executed(journey, fake_cloud, account_home, relay):
    home = account_home(custom_servers=[_web_1()])
    journey.shims.when("ssh", r"echo", stdout="ran\n")
    listener = relay(home).start()
    user_id = wait_until_connected(fake_cloud, listener)
    publish = fake_cloud.relay.publish

    # Published on this account's topic but addressed to another user.
    publish(command_event("cmd-foreign", user_id + 1, "run_command", WEB_1.name,
                          {"command": "echo foreign"}))
    # Another account's topic: the hub never delivers it to this listener.
    other = publish(
        command_event("cmd-other", user_id + 1, "run_command", WEB_1.name,
                      {"command": "echo other"}),
        user_id=user_id + 1,
    )
    # The service dual-publishes tool calls on both topics during a
    # migration window: two events, one logical call.
    dual = tool_call_event("tc-dual", user_id, "list_instances", {})
    publish(dual, topic="commands")
    publish(dual, topic="ai-tool-calls")
    # A retried command with the same id.
    twice = command_event("cmd-twice", user_id, "run_command", WEB_1.name, {"command": "echo 1"})
    publish(twice)
    publish(twice)
    # Something this CLI does not know how to run.
    publish({"id": "odd-1", "user_id": user_id, "note": "no type"})
    publish(command_event("cmd-sentinel", user_id, "run_command", WEB_1.name,
                          {"command": "echo sentinel"}))
    wait_for_result(fake_cloud, "cmd-sentinel", listener)

    relay_state = fake_cloud.relay
    # Every event on the account's topics reached the listener...
    sent = relay_state.subscriptions(live=True)[0]["sent"]
    assert len(sent) == 7 and other not in sent
    # ...but only the new, own-account ones ran.
    assert relay_state.command_results("cmd-foreign") == []
    assert relay_state.command_results("cmd-other") == []
    assert len(fake_cloud.ai.tool_results("tc-dual")) == 1
    assert len(relay_state.command_results("cmd-twice")) == 1
    assert relay_state.command_results("odd-1") == []
    ran = [call.argv[-1] for call in journey.shims.calls("ssh")]
    assert ran == ["echo 1", "echo sentinel"]
