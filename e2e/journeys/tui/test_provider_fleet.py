"""Journey: servers from Hetzner Cloud and OVHcloud join the fleet table.

With both providers configured, the fleet table lists AWS instances, Hetzner
servers, and OVH VPS, dedicated and Public Cloud instances side by side, with
their state and public address, and the provider sections appear in the
sidebar. A provider that refuses the credentials is reported without
emptying the rest of the table.
"""

from __future__ import annotations

import json
import re

import pytest

from e2e.harness import fleet
from e2e.harness.known_bugs import ProductBug
from e2e.harness.pilot import JourneyTimeout

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

PROVIDER_NAV = (
    "nav_ovh_manage",
    "nav_ovh_dns",
    "nav_ovh_ips",
    "nav_ovh_storage",
    "nav_ovh_billing",
    "nav_ovh_ssh_keys",
    "nav_hetzner_manage",
    "nav_hetzner_ssh_keys",
)
PROVIDER_NAMES = {
    *(host.name for host in fleet.HETZNER_FLEET),
    *(vps.display_name for vps in fleet.OVH_VPS_FLEET),
    *(server.reverse for server in fleet.OVH_DEDICATED_FLEET),
    *(host.name for host in fleet.OVH_CLOUD_FLEET),
}


class HetznerNotFetchedAtLaunch(ProductBug):
    """The Hetzner servers never load while the AWS cache is fresh."""


class OvhRefusalWipesTheFleet(ProductBug):
    """A refused OVH refresh empties the OVH rows and their cache, silently."""


def _rows_by_name(t) -> dict[str, list[str]]:
    return {row[1]: row for row in t.table_rows("InstanceTable")}


def _state(row: list[str]) -> str:
    """The state cell of a fleet row, without its colour markup."""
    states = [
        cell for cell in row
        if re.sub(r"\[/?[a-z ]+\]", "", cell) in ("running", "stopped", "pending", "error")
    ]
    assert len(states) == 1, row
    return re.sub(r"\[/?[a-z ]+\]", "", states[0])


def _seed_all_providers(seed, providers, *, fresh_aws_cache: bool) -> None:
    seed.config(hetzner=seed.hetzner_config(), ovh=seed.ovh_config())
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=fresh_aws_cache)
    fleet.seed_provider_fleet(providers)


async def test_every_provider_shows_up_in_the_fleet(tui, seed, moto, providers):
    _seed_all_providers(seed, providers, fresh_aws_cache=False)
    moto.seed_fleet([fleet.APP_1])
    expected = {fleet.APP_1.name, *PROVIDER_NAMES}

    async with tui() as t:
        await t.wait_for_toast(r"Hetzner refreshed: 2 instances")
        await t.wait_for_toast(r"OVH refreshed: 5 instances")
        rows = await t.wait_until(
            lambda: (r := _rows_by_name(t)) and set(r) == expected and r,
            desc="every provider's servers in the fleet table",
        )
        screen = t.rendered_text()
        for name in expected:
            assert name in screen, name
        for address in (fleet.HZ_CACHE_1.public_ip, fleet.OVH_VPS_MAIL_1.ips[0],
                        fleet.OVH_BATCH_1.public_ip):
            assert address in screen, address
        assert _state(rows[fleet.HZ_BUILD_1.name]) == "stopped"
        assert _state(rows[fleet.OVH_VPS_PROXY_1.display_name]) == "stopped"
        assert _state(rows[fleet.OVH_BATCH_1.name]) == "running"

        for nav_id in PROVIDER_NAV:
            assert t.nav_reachable(nav_id), f"{nav_id} should be shown for a configured provider"

    # Listing only reads: nothing was changed at either provider.
    assert providers.mutations() == []
    assert providers.requests("hetzner", method="GET", path="/servers")
    assert providers.requests("ovh", method="GET", path="/vps")


async def test_hetzner_servers_load_with_a_fresh_aws_cache(tui, seed, providers):
    _seed_all_providers(seed, providers, fresh_aws_cache=True)

    async with tui() as t:
        # The start-up refresh has run: OVH, which had no cache either, loaded.
        await t.wait_for_toast(r"OVH refreshed: 5 instances")
        # A manual refresh is what a user tries next.
        await t.focus_instance_table()
        await t.press("r")
        await t.wait_until(
            lambda: len(providers.requests("ovh", path="/vps")) >= 2, desc="second OVH refresh"
        )
        try:
            await t.wait_until(
                lambda: fleet.HZ_CACHE_1.name in _rows_by_name(t),
                timeout=5,
                desc="Hetzner rows",
            )
        except JourneyTimeout as exc:
            assert not providers.requests("hetzner"), "Hetzner was asked but not shown"
            raise HetznerNotFetchedAtLaunch("Hetzner was never asked for its servers") from exc


async def test_a_refused_ovh_refresh_keeps_the_cached_ovh_rows(tui, seed, moto, providers):
    _seed_all_providers(seed, providers, fresh_aws_cache=False)
    moto.seed_fleet([fleet.APP_1])
    ovh_names = {vps.display_name for vps in fleet.OVH_VPS_FLEET}
    ovh_cache = seed.data_dir / "ovh_cache.json"

    async with tui() as t:
        await t.wait_for_toast(r"OVH refreshed: 5 instances")
        await t.wait_until(lambda: ovh_names <= set(_rows_by_name(t)), desc="OVH rows")
        assert len(json.loads(ovh_cache.read_text())["instances"]) == 5

        # The credentials are revoked, then the user refreshes.
        providers.ovh.fail_with = "INVALID_CREDENTIAL"
        await t.focus_instance_table()
        await t.press("r")

        def settled() -> bool:
            warned = any("OVH refresh failed" in m for _, m in t.toasts())
            vanished = not ovh_names & set(_rows_by_name(t))
            return warned or vanished

        await t.wait_until(settled, desc="the refused OVH refresh to finish")
        await t.settle()
        cached = json.loads(ovh_cache.read_text())["instances"]
        if not ovh_names & set(_rows_by_name(t)) or not cached:
            raise OvhRefusalWipesTheFleet(
                f"OVH rows left: {sorted(ovh_names & set(_rows_by_name(t)))}, "
                f"cached instances: {len(cached)}"
            )
        assert any("OVH refresh failed" in m for _, m in t.toasts())
