"""Journey: browse WAF logs in the CloudWatch screen and rank client IPs.

The user opens CloudWatch from the sidebar, the configured region lists its
log groups, and fetching a WAF log group fills the events table and the Top
IPs panel. Top IPs splits each address into allowed and blocked requests,
and the action filter (a click on the toggle, or ``f``) cycles through All,
Allowed and Blocked. A filter pattern narrows the fetch; one that matches
nothing says so.

CloudWatch filter patterns are evaluated as AWS documents them (see
``e2e/harness/aws_logs_filter.py``), not as moto's substring match.
"""

from __future__ import annotations

import os
import re
import time

import pytest
from rich.text import Text
from textual.widgets import DataTable

from e2e.harness import fleet
from e2e.harness.aws import waf_log_record
from e2e.harness.controls import choose

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

WAF_GROUP = "aws-waf-logs-e2e"
APP_GROUP = "/e2e/app/access"
# 13 requests: one public client mixing allowed and blocked requests, one
# always blocked, one always allowed, and an internal health check that Top
# IPs leaves out because its address is private.
WAF_TRAFFIC = (
    [waf_log_record("9.9.9.9", "ALLOW", uri=f"/page/{n}") for n in range(5)]
    + [waf_log_record("9.9.9.9", "BLOCK", uri="/wp-login.php", status=403) for _ in range(2)]
    + [waf_log_record("1.1.1.1", "BLOCK", uri="/wp-login.php", status=403) for _ in range(3)]
    + [waf_log_record("8.8.8.8", "ALLOW", uri="/") for _ in range(2)]
    + [waf_log_record(fleet.APP_1.private_ip, "ALLOW", uri="/health")]
)
ALL_IPS = [("9.9.9.9", "7", "MIXED"), ("1.1.1.1", "3", "BLOCKED"), ("8.8.8.8", "2", "ALLOWED")]
ALLOWED_IPS = [("9.9.9.9", "5", "ALLOWED"), ("8.8.8.8", "2", "ALLOWED")]
BLOCKED_IPS = [("1.1.1.1", "3", "BLOCKED"), ("9.9.9.9", "2", "BLOCKED")]


def _plain(cell) -> str:
    return cell.plain if isinstance(cell, Text) else Text.from_markup(str(cell)).plain


def _rows(t, selector: str) -> list[tuple[str, ...]]:
    table = t.on_screen(selector, DataTable)
    return [tuple(_plain(cell) for cell in table.get_row(key)) for key in table.rows]


def _top_ips(t) -> list[tuple[str, ...]]:
    return _rows(t, "#cloudwatch_ips_table")


def _seed(seed, cloudwatch) -> None:
    seed.config(cloudwatch_default_region="us-east-1")
    seed.cache(fleet.cache_rows(), fresh=True)
    cloudwatch.seed_log_events(WAF_GROUP, WAF_TRAFFIC)
    cloudwatch.seed_log_events(APP_GROUP, ["GET /health 200", "GET / 200"])


async def _open_waf_group(t) -> None:
    await t.nav("nav_cloudwatch")
    await t.wait_for_screen("CloudWatchBrowserScreen")
    # The configured default region is preselected and its groups load.
    await t.wait_for_toast(r"Found 2 log group\(s\)\.")
    await choose(t, "#cw_select_log_group", WAF_GROUP)


async def _fetch(t, *, before: int) -> str:
    """Press Fetch and return the outcome toast that follows it."""
    await t.click("#cw_btn_fetch")
    outcome = re.compile(r"^(Loaded \d+ events|No events found|CloudWatch fetch failed)")

    def arrived():
        fresh = [message for _, message in t.toasts()[before:] if outcome.search(message)]
        return fresh[-1] if fresh else None

    return await t.wait_until(arrived, desc="fetch outcome toast")


async def test_top_ips_split_and_action_filter(tui, seed, cloudwatch):
    _seed(seed, cloudwatch)
    async with tui() as t:
        await _open_waf_group(t)

        message = await _fetch(t, before=len(t.toasts()))
        assert message == "Loaded 13 events (60min window), 3 unique IPs."
        assert len(_rows(t, "#cloudwatch_events_table")) == 13
        assert _top_ips(t) == ALL_IPS

        # The toggle next to "Top IPs" cycles the action filter on click...
        await t.click("#cw_btn_ip_filter")
        await t.wait_until(lambda: _top_ips(t) == ALLOWED_IPS, desc="allowed-only ranking")
        assert "[Allowed]" in t.rendered_text()
        # ...and so does the f key.
        await t.press("f")
        await t.wait_until(lambda: _top_ips(t) == BLOCKED_IPS, desc="blocked-only ranking")
        assert "[Blocked]" in t.rendered_text()
        await t.press("f")
        await t.wait_until(lambda: _top_ips(t) == ALL_IPS, desc="full ranking again")


async def test_filter_pattern_narrows_the_fetch(tui, seed, cloudwatch):
    _seed(seed, cloudwatch)
    async with tui() as t:
        await _open_waf_group(t)

        # A quoted term narrows the fetch to the requests that contain it.
        await t.fill("#cw_input_filter_pattern", '"wp-login"')
        message = await _fetch(t, before=len(t.toasts()))
        assert message == "Loaded 5 events (60min window), 2 unique IPs."
        assert len(_rows(t, "#cloudwatch_events_table")) == 5
        assert _top_ips(t) == BLOCKED_IPS

        # A filter nothing matches empties both tables and says so.
        await t.fill("#cw_input_filter_pattern", "NOMATCH")
        message = await _fetch(t, before=len(t.toasts()))
        assert message == "No events found for the given filters."
        assert _rows(t, "#cloudwatch_events_table") == []
        assert _top_ips(t) == []


async def test_bare_address_filter_finds_that_clients_requests(tui, seed, cloudwatch):
    _seed(seed, cloudwatch)
    async with tui() as t:
        await _open_waf_group(t)
        await t.fill("#cw_input_filter_pattern", "1.1.1.1")
        message = await _fetch(t, before=len(t.toasts()))
        assert message == "Loaded 3 events (60min window), 1 unique IPs."


@pytest.fixture
def clock_three_hours_east_of_utc():
    """This process's local time zone set to UTC+3 for one journey."""
    if not hasattr(time, "tzset"):
        pytest.skip("changing the local time zone needs time.tzset (POSIX)")
    previous = os.environ.get("TZ", "UTC")
    os.environ["TZ"] = "<+03>-3"  # POSIX notation: three hours east of UTC
    time.tzset()
    yield
    os.environ["TZ"] = previous
    time.tzset()


async def test_newest_events_show_when_local_time_is_not_utc(
    tui, seed, cloudwatch, clock_three_hours_east_of_utc
):
    _seed(seed, cloudwatch)
    async with tui() as t:
        await _open_waf_group(t)
        message = await _fetch(t, before=len(t.toasts()))
        assert message == "Loaded 13 events (60min window), 3 unique IPs."
