"""Journey: add a custom server, then open SSH sessions from the fleet table.

The server is added through the Custom Servers form and must be saved to the
config file and appear in the fleet. Pressing ``s`` opens the (fake)
terminal emulator with Servonaut's wrapper script, which runs the (fake)
``ssh`` with the server's user, port and key. An AWS instance matched by a
bastion rule is reached with ProxyJump; instances that cannot be reached are
refused with a clear message instead of a terminal.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from e2e.harness import fleet
from e2e.harness.shims import jump_host

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

WEB_1 = fleet.WEB_1


def _names(t) -> list[str]:
    return [row[1] for row in t.table_rows("InstanceTable")]


def _pair(argv: list[str], flag: str) -> str:
    """The value following *flag* in an argv list."""
    assert flag in argv, f"{flag} not in {argv}"
    return argv[argv.index(flag) + 1]


async def _launch_ssh(t, journey, name: str):
    """Select *name*, press s, and return the ssh argv the terminal ran."""
    terminals = len(journey.shims.calls("xterm"))
    sessions = len(journey.shims.calls("ssh"))
    await t.select_instance(name)
    await t.press("s")
    await t.wait_for_toast(f"SSH session launched for {name}")
    await t.wait_until(
        lambda: len(journey.shims.calls("xterm")) > terminals, desc="terminal started"
    )
    terminal = journey.shims.calls("xterm")[-1]
    # Servonaut hands the terminal its wrapper script, stored in its logs folder.
    assert terminal.argv[:2] == ["-e", "bash"]
    wrapper = Path(terminal.argv[2])
    assert wrapper.parent == Path(os.environ["HOME"]) / ".servonaut" / "logs"
    await t.wait_until(lambda: len(journey.shims.calls("ssh")) > sessions, desc="ssh started")
    return journey.shims.calls("ssh")[-1].argv


async def test_add_a_custom_server_and_ssh_into_it(tui, seed, journey):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    key = seed.ssh_key("e2e_web1")
    journey.shims.when("ssh", f"{WEB_1.username}@{WEB_1.host}", rc=0)

    async with tui() as t:
        await t.nav("nav_custom_servers")
        await t.wait_for_screen("CustomServersScreen")
        await t.click("#btn_add_server")
        await t.fill("#input_name", WEB_1.name)
        await t.fill("#input_host", WEB_1.host)
        await t.fill("#input_username", WEB_1.username)
        await t.fill("#input_ssh_key", WEB_1.ssh_key)
        await t.fill("#input_port", str(WEB_1.port))
        await t.fill("#input_provider", WEB_1.provider)
        await t.fill("#input_group", WEB_1.group)
        await t.click("#btn_save_server")
        await t.wait_for_toast(f"Saved server: {WEB_1.name}")

        assert t.table_rows("#custom_servers_table") == [
            [WEB_1.name, WEB_1.host, str(WEB_1.port), WEB_1.username, WEB_1.ssh_key,
             WEB_1.provider, WEB_1.group]
        ]
        saved = seed.read_config()["custom_servers"]
        assert [(s["name"], s["host"], s["port"], s["username"], s["ssh_key"]) for s in saved] == [
            (WEB_1.name, WEB_1.host, WEB_1.port, WEB_1.username, WEB_1.ssh_key)
        ]

        await t.nav("nav_list")
        await t.wait_for_screen("InstanceListScreen")
        await t.wait_until(lambda: WEB_1.name in _names(t), desc="web-1 in the fleet")

        argv = await _launch_ssh(t, journey, WEB_1.name)
        assert argv[-1] == f"{WEB_1.username}@{WEB_1.host}"
        assert _pair(argv, "-p") == str(WEB_1.port)
        assert _pair(argv, "-i") == str(key)
        assert "IdentitiesOnly=yes" in argv
        assert jump_host(argv) is None


async def test_ssh_through_a_bastion_and_refusals(tui, seed, journey):
    from servonaut.config.schema import ConnectionProfile, ConnectionRule

    seed.config(
        connection_profiles=[
            ConnectionProfile(
                name=fleet.BASTION_PROFILE,
                bastion_host=fleet.BASTION_1.public_ip,
                bastion_user=fleet.BASTION_USER,
            )
        ],
        connection_rules=[
            ConnectionRule(
                name="private apps",
                match_conditions={"name_contains": "app-"},
                profile_name=fleet.BASTION_PROFILE,
            )
        ],
    )
    seed.cache(fleet.cache_rows(*fleet.AWS_FLEET, fleet.QUEUE_1), fresh=True)
    key = seed.ssh_key(f"{fleet.APP_1.key_name}.pem")
    journey.shims.when("ssh", fleet.APP_1.private_ip, rc=0)

    async with tui() as t:
        await t.wait_until(lambda: fleet.APP_1.name in _names(t), desc="fleet rows")

        argv = await _launch_ssh(t, journey, fleet.APP_1.name)
        # A private-only instance is reached through the bastion by its
        # private address, with the key found for its AWS key pair.
        assert jump_host(argv) == f"{fleet.BASTION_USER}@{fleet.BASTION_1.public_ip}"
        assert argv[-1] == f"ec2-user@{fleet.APP_1.private_ip}"
        assert _pair(argv, "-i") == str(key)
        assert any(
            message.endswith(f"via {fleet.BASTION_1.public_ip}")
            for _, message in t.toasts()
        )

        started = len(journey.shims.calls("xterm"))
        await t.select_instance(fleet.QUEUE_1.name)
        await t.press("s")
        await t.wait_for_toast("No IP address available for this instance", severity="error")

        await t.select_instance(fleet.DB_1.name)
        await t.press("s")
        await t.wait_for_toast("Only running instances can connect", severity="warning")
        await t.settle()
        assert len(journey.shims.calls("xterm")) == started
