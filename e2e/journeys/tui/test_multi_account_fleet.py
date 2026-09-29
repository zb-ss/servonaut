"""Journey: the fleet table with several Hetzner projects and OVH accounts.

Each provider has a second account, and both accounts of a provider hold a
server named web-1. The fleet table lists every account's servers and names
each one ``account/name``, so the two web-1 servers are told apart; AWS, with
a single account, keeps plain names. The search box narrows the table to one
account with ``staging/``. A project whose token is refused is reported by
name while the other project's servers stay listed. Demo mode shows a
stand-in for an account label that could identify someone, in the table and
in notifications. On a 100x30 terminal the qualified names and the public
addresses stay readable.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.fake_providers import hetzner as fake_hetzner
from e2e.harness.fake_providers import ovh as fake_ovh

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

HETZNER = fake_hetzner.PRIMARY_LABEL
OVH = fake_ovh.PRIMARY_LABEL
STAGING = fleet.HETZNER_SECOND_ACCOUNT
BACKUP = fleet.OVH_SECOND_ACCOUNT
WEB_1 = fleet.SHARED_NAME

HETZNER_ROWS = {
    *(f"{HETZNER}/{host.name}" for host in (*fleet.HETZNER_FLEET, fleet.HZ_WEB_1)),
    *(f"{STAGING}/{host.name}" for host in fleet.HETZNER_SECOND_FLEET),
}
OVH_ROWS = {
    *(f"{OVH}/{vps.display_name}" for vps in (*fleet.OVH_VPS_FLEET, fleet.OVH_VPS_WEB_1)),
    *(f"{OVH}/{server.reverse}" for server in fleet.OVH_DEDICATED_FLEET),
    *(f"{OVH}/{host.name}" for host in fleet.OVH_CLOUD_FLEET),
    *(f"{BACKUP}/{vps.display_name}" for vps in fleet.OVH_SECOND_VPS_FLEET),
    *(f"{BACKUP}/{host.name}" for host in fleet.OVH_SECOND_CLOUD_FLEET),
}

# Not a generic word such as "staging", so demo mode swaps it for a stand-in.
NAMED_PROJECT = "north"


def _rows(t) -> dict[str, list[str]]:
    """Fleet rows by the name the table shows."""
    return {row[1]: row for row in t.table_rows("InstanceTable")}


async def _select_shown(t, shown: str) -> None:
    """Move the fleet table's cursor to the row showing *shown*, by keyboard.

    The row scrolls into view on the way, as it does for a user.
    """
    table = await t.focus_instance_table()
    names = list(_rows(t))
    target = names.index(shown)
    for _ in range(len(names) + 1):
        if table.cursor_row == target:
            break
        await t.press("down" if table.cursor_row < target else "up")
    await t.wait_until(lambda: table.cursor_row == target, desc=f"cursor on {shown}")


def _by_label(t) -> dict[str, list[str]]:
    """The qualified names of the fleet table, by the account label they show."""
    groups: dict[str, list[str]] = {}
    for name in _rows(t):
        label, slash, _ = name.partition("/")
        if slash:
            groups.setdefault(label, []).append(name)
    return groups


def _seed(seed, providers, moto, *, ovh: bool = True) -> None:
    """Both accounts of Hetzner (and OVH), and one AWS instance to refresh."""
    fleet.seed_provider_fleet(providers, ovh=ovh)
    fleet.seed_second_accounts(providers, ovh=ovh)
    moto.seed_fleet([fleet.APP_1])
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=False)
    overrides = {
        "hetzner": seed.hetzner_config(accounts=[seed.hetzner_account(STAGING)]),
    }
    if ovh:
        overrides["ovh"] = seed.ovh_config(accounts=[seed.ovh_account(BACKUP)])
    seed.config(**overrides)


async def test_every_account_is_listed_under_its_label(tui, seed, moto, providers):
    _seed(seed, providers, moto)
    expected = {fleet.APP_1.name, *HETZNER_ROWS, *OVH_ROWS}

    async with tui() as t:
        rows = await t.wait_until(
            lambda: (r := _rows(t)) and set(r) == expected and r,
            desc="every account's servers in the fleet table",
        )
        # The two web-1 servers of each provider are different servers.
        assert rows[f"{HETZNER}/{WEB_1}"][4] == fleet.HZ_WEB_1.public_ip
        assert rows[f"{STAGING}/{WEB_1}"][4] == fleet.HZ_SECOND_WEB_1.public_ip
        assert rows[f"{OVH}/{WEB_1}"][4] == fleet.OVH_VPS_WEB_1.ips[0]
        assert rows[f"{BACKUP}/{WEB_1}"][4] == fleet.OVH_SECOND_VPS_WEB_1.ips[0]
        await t.wait_for_text(f"{STAGING}/{WEB_1}", fleet.HZ_SECOND_WEB_1.public_ip)

        # "/" jumps to the search box; an account label narrows to its servers.
        await t.focus_instance_table()
        await t.press("slash")
        await t.wait_until(lambda: t.focused_id() == "search_input", desc="search focus")
        await t.type(f"{STAGING}/")
        await t.wait_until(
            lambda: set(_rows(t)) == {f"{STAGING}/{h.name}" for h in fleet.HETZNER_SECOND_FLEET},
            desc="only the staging project's servers",
        )
        await t.press("ctrl+u")
        await t.wait_until(lambda: set(_rows(t)) == expected, desc="filter cleared")

    # Each account was listed with its own credentials; nothing was changed.
    for provider, account, path in (
        ("hetzner", HETZNER, "/servers"),
        ("hetzner", STAGING, "/servers"),
        ("ovh", OVH, "/vps"),
        ("ovh", BACKUP, "/vps"),
    ):
        assert providers.requests(provider, method="GET", path=path, account=account), account
    assert providers.mutations() == []


async def test_a_refused_project_keeps_the_other_projects_servers(tui, seed, moto, providers):
    _seed(seed, providers, moto, ovh=False)
    providers.hetzner_projects.get(STAGING).fail_with = "unauthorized"
    primary = {f"{HETZNER}/{host.name}" for host in (*fleet.HETZNER_FLEET, fleet.HZ_WEB_1)}

    async with tui() as t:
        message = await t.wait_for_toast(
            rf"^Hetzner refresh incomplete\. {STAGING}: ", severity="warning"
        )
        await t.wait_until(lambda: primary <= set(_rows(t)), desc="the primary project's servers")
        await t.settle()
        assert not [name for name in _rows(t) if name.startswith(f"{STAGING}/")]
        assert fleet.APP_1.name in _rows(t)

    assert "unable to authenticate" in message or "unauthorized" in message.lower(), message
    refused = providers.requests("hetzner", method="GET", path="/servers", account=STAGING)
    assert refused and {entry["status"] for entry in refused} == {401}
    assert providers.requests("hetzner", method="GET", path="/servers", account=HETZNER)


async def test_demo_mode_shows_stand_ins_for_account_labels(
    tui, seed, moto, providers, monkeypatch
):
    from servonaut.app import ServonautApp

    fleet.seed_provider_fleet(providers, ovh=False)
    providers.hetzner.seed_servers([fleet.HZ_WEB_1])
    project = providers.add_hetzner_project(NAMED_PROJECT)
    project.seed_servers(fleet.HETZNER_SECOND_FLEET)
    moto.seed_fleet([fleet.APP_1])
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=False)
    seed.config(hetzner=seed.hetzner_config(accounts=[seed.hetzner_account(NAMED_PROJECT)]))
    # What `--demo` sets before the app starts.
    monkeypatch.setattr(ServonautApp, "demo_mode", True)
    hetzner_count = len(fleet.HETZNER_FLEET) + 1 + len(fleet.HETZNER_SECOND_FLEET)

    async with tui() as t:
        await t.wait_for_text("DEMO")
        labels = await t.wait_until(
            lambda: (q := _by_label(t)) and sum(map(len, q.values())) == hetzner_count and q,
            desc="both projects' servers, qualified",
        )
        # The provider's default label is public; the other one gets a stand-in.
        stand_ins = set(labels) - {HETZNER}
        assert len(stand_ins) == 1, labels
        stand_in = stand_ins.pop()
        assert stand_in != NAMED_PROJECT
        assert len(labels[stand_in]) == len(fleet.HETZNER_SECOND_FLEET)
        assert NAMED_PROJECT not in t.rendered_text()

        # A refused refresh names the project by its stand-in too.
        project.fail_with = "unauthorized"
        await t.focus_instance_table()
        await t.press("r")
        message = await t.wait_for_toast(r"^Hetzner refresh incomplete\. ", severity="warning")
        assert message.startswith(f"Hetzner refresh incomplete. {stand_in}: "), message
        assert not [text for _, text in t.toasts() if NAMED_PROJECT in text]
        # The project's cached servers stay listed.
        assert len(_by_label(t).get(stand_in, [])) == len(fleet.HETZNER_SECOND_FLEET)

    assert providers.requests("hetzner", method="GET", path="/servers", account=NAMED_PROJECT)


async def test_qualified_names_stay_readable_at_100x30(tui, seed, moto, providers):
    _seed(seed, providers, moto, ovh=False)

    async with tui(size=(100, 30)) as t:
        await t.wait_until(lambda: HETZNER_ROWS <= set(_rows(t)), desc="both projects listed")
        # Only a few rows fit: each web-1 is scrolled to, then read across
        # one drawn line, its qualified name and public address in view.
        for shown, address in (
            (f"{HETZNER}/{WEB_1}", fleet.HZ_WEB_1.public_ip),
            (f"{STAGING}/{WEB_1}", fleet.HZ_SECOND_WEB_1.public_ip),
        ):
            await _select_shown(t, shown)
            text = await t.wait_for_text(shown, address)
            line = next(line for line in text.splitlines() if shown in line)
            assert address in line, line
