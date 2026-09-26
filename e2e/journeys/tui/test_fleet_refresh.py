"""Journey: the fleet table refreshes from AWS and survives a failed refresh.

A stale cache is shown at once and refreshed in the background from the
local AWS endpoint; ``r`` forces a refresh and ``/`` filters the table. When
AWS cannot be reached, or the AWS profile setting is empty, the cached fleet
stays on screen, a warning says so, and the cache file is left untouched.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import fleet

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


def _names(t) -> list[str]:
    return sorted(row[1] for row in t.table_rows("InstanceTable"))


async def test_stale_cache_refreshes_from_aws(tui, seed, moto):
    seed.config()
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=False)
    moto.seed_fleet([fleet.APP_1, fleet.DB_1, fleet.API_1])

    async with tui() as t:
        await t.wait_for_toast("Refreshing instances in background")
        await t.wait_for_toast(r"Refreshed: 3 instances \(2 more\)", timeout=30)
        assert _names(t) == ["api-1", "app-1", "db-1"]

        cache = json.loads(seed.cache_path.read_text())
        cached = {row["name"]: row for row in cache["instances"]}
        assert sorted(cached) == ["api-1", "app-1", "db-1"]
        assert cached["db-1"]["state"] == "stopped"
        assert cached["api-1"]["private_ip"] == fleet.API_1.private_ip
        assert all(row["public_ip"] is None for row in cached.values())

        # "/" jumps to the search box; typing narrows the table.
        await t.focus_instance_table()
        await t.press("slash")
        await t.wait_until(lambda: t.focused_id() == "search_input", desc="search focus")
        await t.type("db-1")
        await t.wait_until(lambda: _names(t) == ["db-1"], desc="filtered to db-1")
        await t.press("ctrl+u")
        await t.wait_until(lambda: len(_names(t)) == 3, desc="filter cleared")

        # "r" fetches again right away and picks up a new instance.
        moto.seed_fleet([fleet.WORKER_1])
        await t.focus_instance_table()
        await t.press("r")
        await t.wait_until(lambda: "worker-1" in _names(t), timeout=30, desc="worker-1 row")
        assert _names(t) == ["api-1", "app-1", "db-1", "worker-1"]


@pytest.mark.parametrize("failure", ["unreachable", "empty_profile"])
async def test_failed_refresh_keeps_the_cached_fleet(tui, seed, moto, monkeypatch, failure):
    seed.config()
    cache_file = seed.cache(fleet.cache_rows(), fresh=False)
    before = cache_file.read_bytes()
    moto.seed_fleet([fleet.API_1])  # what a working refresh would have found
    if failure == "unreachable":
        monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9")
    else:
        # An empty AWS_PROFILE (for example left by a shell default) must
        # not be mistaken for "no instances".
        monkeypatch.setenv("AWS_PROFILE", "")

    expected = sorted(host.name for host in fleet.AWS_FLEET)
    async with tui() as t:
        await t.wait_for_toast(
            r"AWS refresh failed: .*Showing cached instances", severity="warning"
        )
        assert _names(t) == expected
        assert cache_file.read_bytes() == before

        # Forcing a refresh fails the same way and still keeps everything.
        warnings_before = len([m for s, m in t.toasts() if "AWS refresh failed" in m])
        await t.focus_instance_table()
        await t.press("r")
        await t.wait_until(
            lambda: len([m for s, m in t.toasts() if "AWS refresh failed" in m]) > warnings_before,
            desc="second refresh warning",
        )
        assert _names(t) == expected
        assert cache_file.read_bytes() == before
