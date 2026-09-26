"""Journey: change settings, keep them across a restart, and upgrade a config.

Edits in the General panel are saved to the config file and shown again
after the app restarts. Leaving with unsaved edits asks first, and both
answers do what they say. A config written by the previous release is
upgraded on start-up: a backup is kept and nothing the user set is lost.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import fleet

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


async def _open_general_settings(t):
    await t.nav("nav_settings")
    await t.wait_for_screen("SettingsScreen")
    field = t.on_screen("#general_username")
    await t.wait_until(lambda: field.value != "", desc="General panel loaded")
    return field


def _dirty_marker(t) -> str:
    return str(t.on_screen("#dirty_general").render())


async def test_saved_settings_survive_a_restart(tui, seed):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)

    async with tui() as t:
        username = await _open_general_settings(t)
        assert username.value == "ec2-user"
        await t.fill("#general_username", "ops")
        await t.fill("#general_cache_ttl", "600")
        await t.wait_until(lambda: "unsaved" in _dirty_marker(t), desc="unsaved marker")
        await t.click("#save_general")
        await t.wait_for_toast(r"^Saved$")
        await t.wait_until(lambda: "unsaved" not in _dirty_marker(t), desc="marker cleared")

    saved = seed.read_config()
    assert saved["default_username"] == "ops"
    assert saved["cache_ttl_seconds"] == 600

    async with tui() as t:
        username = await _open_general_settings(t)
        assert username.value == "ops"
        assert t.on_screen("#general_cache_ttl").value == "600"


async def test_unsaved_edits_ask_before_they_are_dropped(tui, seed):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)

    async with tui() as t:
        await _open_general_settings(t)
        await t.fill("#general_username", "ops")

        # Leaving with unsaved edits asks first; "Keep editing" stays put.
        await t.press("escape")
        await t.wait_for_screen("DiscardChangesModal")
        await t.click("#discard-cancel")
        await t.wait_for_screen("SettingsScreen")
        assert t.on_screen("#general_username").value == "ops"

        # Moving to another panel asks too; "Discard" reverts the edit.
        await t.click("#navbtn_history_paths")
        await t.wait_for_screen("DiscardChangesModal")
        await t.click("#discard-confirm")
        await t.wait_for_screen("SettingsScreen")
        await t.wait_until(
            lambda: t.find_one("#general_username").value == "ec2-user", desc="edit reverted"
        )
        assert seed.read_config()["default_username"] == "ec2-user"

        # Back on General, nothing is unsaved any more, so leaving does not ask.
        await t.wait_until(
            lambda: t.on_screen("#hp_command_history_path").value != "",
            desc="History & Paths panel loaded",
        )
        await t.click("#navbtn_general")
        await t.wait_until(
            lambda: t.on_screen("#general_username").display
            and t.on_screen("#general_username").value == "ec2-user",
            desc="General panel shown again",
        )
        await t.press("escape")
        await t.wait_for_screen("InstanceListScreen")


async def test_config_from_the_previous_release_is_upgraded(tui, seed):
    from servonaut.config.schema import CONFIG_VERSION, CustomServer

    web_1 = fleet.WEB_1
    written = seed.previous_version_config(
        default_username="ops",
        custom_servers=[
            CustomServer(
                name=web_1.name,
                host=web_1.host,
                username=web_1.username,
                port=web_1.port,
                ssh_key=web_1.ssh_key,
            )
        ],
    )
    assert written["version"] == CONFIG_VERSION - 1

    async with tui() as t:
        await t.wait_until(
            lambda: web_1.name in [row[1] for row in t.table_rows("InstanceTable")],
            desc="custom server in the fleet",
        )
        username = await _open_general_settings(t)
        assert username.value == "ops"

    upgraded = seed.read_config()
    assert upgraded["version"] == CONFIG_VERSION
    assert upgraded["cloudtrail_max_events"] == 500  # the old default is raised
    assert [(s["name"], s["host"], s["port"]) for s in upgraded["custom_servers"]] == [
        (web_1.name, web_1.host, web_1.port)
    ]
    backups = sorted(seed.data_dir.glob("config*.bak*"))
    assert len(backups) == 1, backups
    assert json.loads(backups[0].read_text())["version"] == CONFIG_VERSION - 1
