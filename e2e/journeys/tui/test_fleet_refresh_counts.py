"""Journey: the background refresh reports how the AWS fleet changed.

When the fleet table also holds servers from outside AWS (here a custom
server), a background refresh that finds exactly the AWS instances already
cached says the fleet is up to date, and every row stays on screen.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.known_bugs import ProductBug, known_bug

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


class RefreshCountsOtherProviders(ProductBug):
    """The refresh toast counts non-AWS rows as vanished AWS instances."""


def _names(t) -> list[str]:
    return sorted(row[1] for row in t.table_rows("InstanceTable"))


@known_bug(
    "The background-refresh toast compares the AWS-only count with the whole "
    "fleet (custom, OVH and Hetzner rows included), so an unchanged AWS fleet "
    "is reported as 'N fewer'",
    raises=RefreshCountsOtherProviders,
)
async def test_unchanged_aws_fleet_with_a_custom_server_is_up_to_date(tui, seed, moto):
    from servonaut.config.schema import CustomServer

    web_1 = fleet.WEB_1
    seed.config(
        custom_servers=[
            CustomServer(
                name=web_1.name,
                host=web_1.host,
                username=web_1.username,
                port=web_1.port,
                ssh_key=web_1.ssh_key,
            )
        ]
    )
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=False)
    moto.seed_fleet([fleet.APP_1])

    async with tui() as t:
        await t.wait_for_toast("Refreshing instances in background")
        message = await t.wait_for_toast(r"^Refreshed: ", timeout=30)
        # Nothing was lost: both rows are still in the table.
        assert _names(t) == sorted([fleet.APP_1.name, web_1.name])
        if "fewer" in message:
            raise RefreshCountsOtherProviders(message)
        assert message == "Refreshed: 1 instances (up to date)", message
