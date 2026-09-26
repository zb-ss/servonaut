"""Journey: reach a private instance through a bastion (ProxyJump).

``app-1`` has only a private address and matches a connection rule that
sends it through ``bastion-1``. Running a command from the overlay, and
opening an SSH session with ``s``, both travel the real OpenSSH ProxyJump
path: the bastion accepts its own key and forwards the private address to
the instance, which answers as ``app-1``.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet, remote_fleet
from e2e.harness.shims import jump_host
from e2e.harness.sshd import BASTION_ALIAS

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd, pytest.mark.asyncio]

APP_1 = fleet.APP_1
JUMP = f"{fleet.BASTION_USER}@{BASTION_ALIAS}"


def _forwards(sshd) -> list[dict]:
    return sshd.bastion.sessions("forward")


async def test_command_and_session_through_the_bastion(tui, seed, journey, sshd):
    remote_fleet.seed_app_1_behind_bastion(sshd, seed, seed.home)
    sshd.target.remote.write("/etc/hostname", f"{APP_1.name}\n")

    async with tui() as t:
        await t.wait_and_select_instance(APP_1.name)
        await t.press("c")
        await t.wait_for_screen("CommandOverlay")
        await t.wait_until(lambda: t.focused_id() == "command_input", desc="command input")
        output = t.on_screen("#command_output")
        await t.type("hostname")
        await t.press("enter")
        await t.wait_until(
            lambda: APP_1.name in t.log_text(output).splitlines(), desc="hostname output"
        )

        argv = journey.shims.calls("ssh")[0].argv
        assert jump_host(argv) == JUMP
        assert argv[-2:] == [f"{fleet.BASTION_USER}@{APP_1.private_ip}", "bash -ic hostname"]
        assert [f["destination"] for f in _forwards(sshd)] == [f"{APP_1.private_ip}:22"]
        assert sshd.target.commands(user=fleet.BASTION_USER) == ["bash -ic hostname"]

        await t.press("escape")
        await t.wait_for_screen("InstanceListScreen")
        await t.select_instance(APP_1.name)
        await t.press("s")
        await t.wait_for_toast(f"SSH session launched for {APP_1.name}")
        # The (fake) terminal runs the wrapper script, whose ssh logs in and
        # ends when its input does.
        shells = await t.wait_until(
            lambda: [e for e in sshd.target.sessions("exit") if e["command"] is None],
            desc="interactive session ended",
        )
    assert [s["status"] for s in shells] == [0]
    assert [s["user"] for s in sshd.target.sessions("shell")] == [fleet.BASTION_USER]
    assert len(_forwards(sshd)) == 2
    bastion_logins = sshd.bastion.sessions("auth")
    assert bastion_logins and all(a["accepted"] for a in bastion_logins)
    transcript = (journey.shims.directory.glob("terminal-*.log"))
    text = "".join(path.read_text() for path in transcript)
    assert "Connecting:" in text and "SSH exited with code" not in text


async def test_an_unrouted_private_address_is_refused_by_the_bastion(tui, seed, journey, sshd):
    remote_fleet.seed_app_1_behind_bastion(sshd, seed, seed.home)
    sshd.bastion.routes.clear()

    async with tui() as t:
        await t.wait_and_select_instance(APP_1.name)
        await t.press("c")
        await t.wait_for_screen("CommandOverlay")
        await t.wait_until(lambda: t.focused_id() == "command_input", desc="command input")
        output = t.on_screen("#command_output")
        await t.type("hostname")
        await t.press("enter")
        await t.wait_until(
            lambda: "Command exited with code 255" in t.log_text(output), desc="ssh failure"
        )
    assert [f["to"] for f in _forwards(sshd)] == [None]
    assert sshd.target.sessions() == []
