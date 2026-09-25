"""Journey: scan a server for keywords and read the results.

A scan rule adds paths and commands for matching servers. From a server's
actions (Enter, then ``5``), "Scan Now" lists each path and runs each
command over real SSH, shows one result row per source and stores the
results for next time. Both a private AWS instance (through the bastion)
and a reachable custom server are scanned.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import fleet, remote_fleet

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd, pytest.mark.asyncio]

SOURCES = ["path:~/", "path:/var/www/", "command:cat /etc/os-release"]


def _rule(name_contains: str):
    from servonaut.config.schema import ScanRule

    return ScanRule(
        name="web content",
        match_conditions={"name_contains": name_contains},
        scan_paths=["/var/www/"],
        scan_commands=["cat /etc/os-release"],
    )


async def _scan(t, name: str) -> None:
    await t.wait_until(lambda: name in [r[1] for r in t.table_rows("InstanceTable")])
    await t.select_instance(name)
    await t.press("enter")
    await t.wait_for_screen("ServerActionsScreen")
    await t.press("5")
    await t.wait_for_screen("ScanResultsScreen")
    await t.press("s")
    await t.wait_for_toast("^Scan completed")


def _stored(seed) -> dict:
    return json.loads((seed.data_dir / "keywords.json").read_text(encoding="utf-8"))


async def test_scan_a_private_instance_through_the_bastion(tui, seed, journey, sshd):
    remote_fleet.seed_app_1_behind_bastion(sshd, seed, seed.home, scan_rules=[_rule("app-")])

    async with tui() as t:
        await _scan(t, fleet.APP_1.name)
        assert t.toasts()[-1] == ("information", f"Scan completed: {len(SOURCES)} results")
        rows = t.table_rows("#results_table")
        assert [row[0] for row in rows] == SOURCES
        assert 'PRETTY_NAME="E2E Linux 12 (fixture)"' in rows[2][1]

    # The full output is stored per instance for later keyword searches.
    stored = {r["source"]: r["content"] for r in _stored(seed)[fleet.APP_1.instance_id]}
    assert list(stored) == SOURCES
    assert stored["path:/var/www/"].splitlines()[-1].split()[-1] == "html"
    assert stored["command:cat /etc/os-release"].splitlines()[0] == (
        'PRETTY_NAME="E2E Linux 12 (fixture)"'
    )
    assert sshd.target.commands(user=fleet.BASTION_USER) == [
        'ls -la "$HOME/" 2>/dev/null',
        'ls -la "/var/www/" 2>/dev/null',
        "cat /etc/os-release",
    ]


@pytest.mark.xfail(
    strict=True,
    reason="scanning a custom server finds nothing: it is skipped as not running",
)
async def test_scan_a_reachable_custom_server(tui, seed, journey, sshd):
    remote_fleet.seed_web_1(sshd, seed, seed.home, scan_rules=[_rule("web-")])
    seed.cache([], fresh=True)

    async with tui() as t:
        await _scan(t, fleet.WEB_1.name)
        assert t.toasts()[-1] == ("information", f"Scan completed: {len(SOURCES)} results")
        assert [row[0] for row in t.table_rows("#results_table")] == SOURCES
