"""Journey: run commands on a server from the command overlay.

``c`` on a fleet row opens the overlay. A command runs over (fake) SSH and
its output streams into the log; it is remembered in the command history on
disk, ``ctrl+r`` brings it back from the picker, and ``ctrl+s`` saves a
command under a name. Interactive programs are refused, and a failing
command shows its exit status.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import fleet

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

WEB_1 = fleet.WEB_1
UPTIME = " 10:00:00 up 3 days,  2 users,  load average: 0.10, 0.05, 0.01\n"


def _seed_web_1(seed) -> None:
    from servonaut.config.schema import CustomServer

    seed.config(
        custom_servers=[
            CustomServer(
                name=WEB_1.name,
                host=WEB_1.host,
                username=WEB_1.username,
                port=WEB_1.port,
                ssh_key=WEB_1.ssh_key,
            )
        ]
    )
    seed.cache(fleet.cache_rows(), fresh=True)


async def _open_overlay(t):
    await t.wait_until(lambda: any(r[1] == WEB_1.name for r in t.table_rows("InstanceTable")))
    await t.select_instance(WEB_1.name)
    await t.press("c")
    await t.wait_for_screen("CommandOverlay")
    await t.wait_until(lambda: t.focused_id() == "command_input", desc="command input focus")
    return t.on_screen("#command_output")


async def _run(t, command: str) -> None:
    await t.type(command)
    await t.press("enter")


def _picker_entries(t) -> list[str]:
    options = t.on_screen("#picker_list")
    return [str(options.get_option_at_index(i).prompt) for i in range(options.option_count)]


def _history(seed) -> dict:
    """The command history file, or {} while it does not exist or is mid-write."""
    try:
        return json.loads((seed.data_dir / "command_history.json").read_text())
    except (FileNotFoundError, ValueError):
        return {}


async def test_run_recall_and_save_commands(tui, seed, journey):
    _seed_web_1(seed)
    journey.shims.when("ssh", r"uptime", stdout=UPTIME)
    journey.shims.when(
        "ssh", r"failing-check", stderr="bash: failing-check: command not found\n", rc=127
    )

    async with tui() as t:
        output = await _open_overlay(t)

        await _run(t, "uptime")
        await t.wait_until(lambda: "up 3 days" in t.log_text(output), desc="uptime output")
        call = journey.shims.calls("ssh")[-1]
        assert f"{WEB_1.username}@{WEB_1.host}" in call.argv
        assert call.argv[-1] == "bash -ic uptime"
        history = await t.wait_until(
            lambda: _history(seed).get("history"), desc="command history written"
        )
        assert history[f"custom-{WEB_1.name}"] == ["uptime"]
        assert history["_global"] == ["uptime"]

        # ctrl+r: pick the command from recent history and run it again.
        await t.press("ctrl+r")
        await t.wait_for_screen("CommandPickerModal")
        await t.wait_until(
            lambda: any("uptime" in entry for entry in _picker_entries(t)),
            desc="uptime listed under recent commands",
        )
        await t.press("enter")
        await t.wait_for_screen("CommandOverlay")
        field = t.on_screen("#command_input")
        await t.wait_until(lambda: field.value == "uptime", desc="picked command in the input")
        await t.press("enter")
        await t.wait_until(lambda: len(journey.shims.calls("ssh")) == 2, desc="second run")
        await t.wait_until(lambda: t.log_text(output).count("up 3 days") == 2, desc="output twice")

        # ctrl+s: save the typed command under a name.
        await t.type("df -h")
        await t.press("ctrl+s")
        await t.wait_for_screen("SaveCommandModal")
        await t.type("disk usage")
        await t.press("enter")
        await t.wait_for_toast("Saved: disk usage")
        saved = await t.wait_until(
            lambda: _history(seed).get("saved_commands"), desc="saved command written"
        )
        assert saved == [{"name": "disk usage", "command": "df -h"}]
        await t.wait_for_screen("CommandOverlay")
        await t.press("ctrl+u")

        # Interactive programs need a real terminal and are refused.
        runs = len(journey.shims.calls("ssh"))
        await _run(t, "top")
        await t.wait_until(
            lambda: "requires an interactive terminal" in t.log_text(output), desc="refusal"
        )
        assert len(journey.shims.calls("ssh")) == runs

        # A failing command shows its error output and exit status.
        await _run(t, "failing-check")
        await t.wait_until(
            lambda: "Command exited with code 127" in t.log_text(output), desc="exit status"
        )
        assert "command not found" in t.log_text(output)

        await t.press("escape")
        await t.wait_for_screen("InstanceListScreen")


async def test_commands_use_the_custom_server_port(tui, seed, journey):
    _seed_web_1(seed)
    journey.shims.when("ssh", r"uptime", stdout=UPTIME)

    async with tui() as t:
        output = await _open_overlay(t)
        await _run(t, "uptime")
        await t.wait_until(lambda: "up 3 days" in t.log_text(output), desc="uptime output")
        argv = journey.shims.calls("ssh")[-1].argv
        assert "-p" in argv and argv[argv.index("-p") + 1] == str(WEB_1.port)
