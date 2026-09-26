"""Journey: audit AWS activity in the CloudTrail screen.

The user fetches a day of management events for the configured region. The
first page holds the configured maximum and says more is waiting; Next reads
the rest of the window and Prev goes back. The Event and User pickers offer
exactly the values in the loaded events, with counts, and combine: the API
honours one filter per call, so the second one is applied locally. A value
the loaded events do not contain can be typed, and is then searched for
across the whole window.

Events made by an instance role name the instance id as the user; the screen
shows the fleet name instead. Some events carry a resource without a type,
which used to crash the screen. Selecting a row shows that event's details.

The local CloudTrail endpoint refuses what AWS refuses, including a page
token reused with a different time range or filter, so paging only passes
when the screen asks for the same window each time.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from e2e.harness import fleet
from e2e.harness.cloudtrail_stub import cloudtrail_event
from e2e.harness.controls import choose, clear, select_row, table_text

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

PAGE_CAP = 100  # cloudtrail_max_events: events per fetch
REGULAR_EVENTS = 160
NAMES = ("DescribeInstances", "StopInstances", "StartInstances", "AuthorizeSecurityGroupIngress")
INSTANCE_ROLE = fleet.APP_1.instance_id
USERS = ("e2e-operator", INSTANCE_ROLE, "e2e-deployer")
SOURCE_IPS = {"e2e-operator": "9.9.9.9", INSTANCE_ROLE: fleet.APP_1.private_ip, "e2e-deployer": "8.8.8.8"}
RESOURCES = {
    "DescribeInstances": [],
    "StopInstances": [{"ResourceType": "AWS::EC2::Instance", "ResourceName": INSTANCE_ROLE}],
    "StartInstances": [{"ResourceType": "AWS::EC2::Instance", "ResourceName": INSTANCE_ROLE}],
    # No ResourceType: CloudTrail does not promise one.
    "AuthorizeSecurityGroupIngress": [{"ResourceName": "sg-0e2e0000000000001"}],
}
# Older than every regular event, so absent from the first page.
RARE_EVENT = "RebootInstances"


def _events() -> list[dict]:
    now = datetime.now(timezone.utc)
    events = []
    for index in range(REGULAR_EVENTS):
        name, user = NAMES[index % len(NAMES)], USERS[index % len(USERS)]
        events.append(
            cloudtrail_event(
                name,
                now - timedelta(seconds=30 + 40 * index),
                username=user,
                source_ip=SOURCE_IPS[user],
                resources=RESOURCES[name],
                identity_type="AssumedRole" if user == INSTANCE_ROLE else "IAMUser",
            )
        )
    for hours in (3, 4):
        events.append(
            cloudtrail_event(RARE_EVENT, now - timedelta(hours=hours), username="e2e-operator")
        )
    return events


def _rows(t) -> list[tuple[str, ...]]:
    return table_text(t, "#cloudtrail_table")


def _page_info(t) -> str:
    visual = t.on_screen("#ct_page_info").visual
    return getattr(visual, "plain", str(visual))


async def _fetch(t, expected_toast: str) -> None:
    await t.click("#ct_btn_fetch")
    await t.wait_for_toast(expected_toast)


def _seed(seed, cloudtrail) -> list[dict]:
    seed.config(cloudtrail_default_region="us-east-1", cloudtrail_max_events=PAGE_CAP)
    seed.cache(fleet.cache_rows(), fresh=True)
    events = _events()
    cloudtrail.seed(events, region="us-east-1")
    return events


async def _open_and_fetch(t) -> None:
    await t.nav("nav_cloudtrail")
    await t.wait_for_screen("CloudTrailBrowserScreen")
    await _fetch(t, rf"^Loaded {PAGE_CAP} CloudTrail events\.$")
    assert len(_rows(t)) == PAGE_CAP


async def test_pickers_offer_loaded_values_and_combine(tui, seed, cloudtrail):
    first_page = _seed(seed, cloudtrail)[:PAGE_CAP]
    stops = [e for e in first_page if e["EventName"] == "StopInstances"]
    by_role = [e for e in first_page if e["Username"] == INSTANCE_ROLE]
    stops_by_role = [e for e in stops if e["Username"] == INSTANCE_ROLE]
    assert 0 < len(stops_by_role) < len(stops)  # the fixture makes the filters meaningful

    async with tui() as t:
        await _open_and_fetch(t)
        assert "more in this window, press Next" in _page_info(t)
        # Instance-role sessions show the fleet name, never the raw id.
        users = {row[2] for row in _rows(t)}
        assert users == {"e2e-operator", fleet.APP_1.name, "e2e-deployer"}

        # The pickers offer the loaded values with counts, and combine.
        await choose(t, "#ct_select_event_name", f"StopInstances  ({len(stops)})")
        await t.wait_until(
            lambda: _page_info(t).startswith(f"{len(stops)} of {PAGE_CAP} loaded events"),
            desc="narrowed to StopInstances",
        )
        await choose(t, "#ct_select_username", f"{fleet.APP_1.name}  ({len(by_role)})")
        await t.wait_until(
            lambda: _page_info(t).startswith(f"{len(stops_by_role)} of {PAGE_CAP} loaded"),
            desc="narrowed by both pickers",
        )
        assert {(row[1], row[2]) for row in _rows(t)} == {("StopInstances", fleet.APP_1.name)}

        # Clearing one picker widens the list again.
        await clear(t, "#ct_select_username")
        await t.wait_until(lambda: len(_rows(t)) == len(stops), desc="user filter cleared")


async def test_typed_value_is_searched_across_the_window(tui, seed, cloudtrail):
    _seed(seed, cloudtrail)
    async with tui() as t:
        await _open_and_fetch(t)
        assert RARE_EVENT not in {row[1] for row in _rows(t)}

        # A value beyond the loaded page is typed and searched for server-side.
        await choose(t, "#ct_select_event_name", "Type a value...")
        await t.wait_for_screen("FilterValueModal")
        await t.type(RARE_EVENT)
        await t.press("enter")
        await t.wait_for_screen("CloudTrailBrowserScreen")
        await t.wait_for_toast(r"^Loaded 2 CloudTrail events\.$")
        assert {row[1] for row in _rows(t)} == {RARE_EVENT}
        searched = cloudtrail.lookups()[-1]["LookupAttributes"]
        assert searched == [{"AttributeKey": "EventName", "AttributeValue": RARE_EVENT}]


async def test_next_reads_the_rest_of_the_window(tui, seed, cloudtrail):
    events = _seed(seed, cloudtrail)
    rest = len(events) - PAGE_CAP
    async with tui() as t:
        await _open_and_fetch(t)
        assert "more in this window, press Next" in _page_info(t)

        await t.click("#ct_btn_next")
        await t.wait_for_toast(rf"^Loaded {rest} more events \({len(events)} total\)\.$")
        await t.wait_until(lambda: _page_info(t).startswith("Page 2 of 2"), desc="page 2")
        assert f"{len(events)} events" in _page_info(t)
        assert len(_rows(t)) == rest
        assert RARE_EVENT in {row[1] for row in _rows(t)}
        assert t.on_screen("#ct_btn_next").disabled  # nothing further in the window

        await t.click("#ct_btn_prev")
        await t.wait_until(lambda: _page_info(t).startswith("Page 1 of 2"), desc="page 1")
        assert len(_rows(t)) == PAGE_CAP

        # A resource without a type opens in the detail pane; the last such
        # event on the page sits below the fold, so the table scrolls to it.
        rows = _rows(t)
        target = max(i for i, row in enumerate(rows) if row[1] == NAMES[3])
        assert target > 50
        await select_row(t, t.on_screen("#cloudtrail_table"), target)
        await t.wait_for_text(
            f"Time: {rows[target][0]}",
            f"Event: {NAMES[3]}",
            "Resource Name: sg-0e2e0000000000001",
        )


async def test_selected_row_details_match_while_filtered(tui, seed, cloudtrail):
    first_page = _seed(seed, cloudtrail)[:PAGE_CAP]
    stops = [e for e in first_page if e["EventName"] == "StopInstances"]
    async with tui() as t:
        await _open_and_fetch(t)
        await choose(t, "#ct_select_event_name", f"StopInstances  ({len(stops)})")
        await t.wait_until(lambda: len(_rows(t)) == len(stops), desc="narrowed to StopInstances")
        first = _rows(t)[0]
        assert first[1] == "StopInstances", first
        await select_row(t, t.on_screen("#cloudtrail_table"), 0)
        # The details of the row now selected, not of an earlier selection.
        await t.wait_for_text(f"Event: {first[1]}", f"Time: {first[0]}")
