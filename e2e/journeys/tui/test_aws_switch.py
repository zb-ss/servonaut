"""Journey: AWS switched off in Settings stays off.

With ``aws.enabled`` off and AWS servers still in the cache (the switch used
to change nothing, so someone may have turned it off long ago), the server
list holds only the other servers, the AWS sidebar section is gone, and the
app says once why the AWS servers are hidden. The next start says nothing.
An agent connected over MCP is offered no AWS tool, and one called anyway is
refused with the same reason. Switching AWS back on in Settings lists the
AWS servers again.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

NOTE = r"^AWS is switched off in Settings, so 4 AWS servers are hidden\."
AWS_NAMES = sorted(host.name for host in fleet.AWS_FLEET)


def _seed_switched_off(seed) -> None:
    from servonaut.config.schema import CustomServer

    web_1 = fleet.WEB_1
    seed.config(
        aws=seed.aws_config(enabled=False),
        custom_servers=[CustomServer(
            name=web_1.name, host=web_1.host, username=web_1.username,
            port=web_1.port, ssh_key=web_1.ssh_key,
        )],
    )
    seed.cache(fleet.cache_rows(), fresh=True)


def _names(t) -> list[str]:
    return sorted(row[1] for row in t.table_rows("InstanceTable"))


async def test_switched_off_aws_is_hidden_and_explained_once(tui, seed):
    _seed_switched_off(seed)
    async with tui() as t:
        await t.wait_for_toast(NOTE, severity="warning")
        await t.wait_until(lambda: _names(t) == [fleet.WEB_1.name], desc="only the custom server")
        assert t.on_screen("#section_aws").display is False

    # Said once: the next start lists the same servers without the note.
    async with tui() as t:
        await t.wait_until(lambda: _names(t) == [fleet.WEB_1.name], desc="only the custom server")
        await t.settle()
        assert not any("AWS is switched off" in text for _, text in t.toasts())


async def test_switching_aws_back_on_lists_its_servers(tui, seed, moto):
    _seed_switched_off(seed)
    moto.seed_fleet(list(fleet.AWS_FLEET))
    async with tui() as t:
        await t.wait_until(lambda: _names(t) == [fleet.WEB_1.name], desc="only the custom server")
        await t.nav("nav_settings")
        await t.wait_for_screen("SettingsScreen")
        # Provider panels sit in a collapsed "Cloud Providers" group.
        await t.nav("navbtn_aws")
        switch = await t.wait_for_widget("#aws_enabled")
        assert switch.value is False
        await t.click("#aws_enabled")
        await t.wait_until(lambda: switch.value is True, desc="switch on")
        await t.click("#save_aws")
        await t.wait_for_toast(r"^AWS settings saved")
        assert seed.read_config()["aws"]["enabled"] is True
        await t.press("escape")
        await t.wait_for_screen("InstanceListScreen")
        await t.wait_until(
            lambda: _names(t) == sorted([*AWS_NAMES, fleet.WEB_1.name]), desc="AWS servers back",
        )
        assert t.on_screen("#section_aws").display is True


async def test_an_agent_is_offered_no_aws_tool_and_told_why(mcp, journey):
    from e2e.harness.seed import HomeSeeder

    sandbox = journey.new_sandbox("mcp-aws-off")
    seeder = HomeSeeder(sandbox.home)
    seeder.config(aws=seeder.aws_config(enabled=False))
    seeder.cache(fleet.cache_rows(), fresh=True)
    async with mcp(sandbox) as session:
        names = await session.tool_names()
        refused = await session.call("aws_list_regions", {})
        listed = await session.call("list_instances", {})

    assert not [name for name in names if name.startswith(("aws_", "cloudwatch_", "cloudtrail_"))]
    assert "list_instances" in names
    assert refused == (
        "Error: AWS is switched off in Settings → AWS, so AWS servers and tools are not "
        "available. Switch it on there to use them."
    )
    for name in AWS_NAMES:
        assert name not in listed
