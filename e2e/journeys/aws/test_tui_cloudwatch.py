"""Journey: browse WAF logs in the CloudWatch screen and rank client IPs.

The user opens CloudWatch from the sidebar, the configured region lists its
log groups, and fetching a WAF log group fills the events table and the Top
IPs panel. Top IPs splits each address into allowed and blocked requests,
and the action filter (a click on the toggle, or ``f``) cycles through All,
Allowed and Blocked. A filter pattern narrows the fetch; one that matches
nothing says so.

The ``moto`` fixture evaluates CloudWatch filter patterns as AWS documents
them (see ``e2e/harness/aws_logs_filter.py``), not as moto's substring match.
"""

from __future__ import annotations

import os
import re
import time

import pytest

from e2e.harness import fleet
from e2e.harness.controls import choose, table_text
from e2e.journeys.aws.support import WAF_GROUP, waf_traffic

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

APP_GROUP = "/e2e/app/access"
ALL_IPS = [("9.9.9.9", "7", "MIXED"), ("1.1.1.1", "3", "BLOCKED"), ("8.8.8.8", "2", "ALLOWED")]
ALLOWED_IPS = [("9.9.9.9", "5", "ALLOWED"), ("8.8.8.8", "2", "ALLOWED")]
BLOCKED_IPS = [("1.1.1.1", "3", "BLOCKED"), ("9.9.9.9", "2", "BLOCKED")]


def _events(t) -> list[tuple[str, ...]]:
    return table_text(t, "#cloudwatch_events_table")


def _top_ips(t) -> list[tuple[str, ...]]:
    return table_text(t, "#cloudwatch_ips_table")


def _seed(seed, moto) -> None:
    seed.config(cloudwatch_default_region="us-east-1")
    seed.cache(fleet.cache_rows(), fresh=True)
    moto.seed_log_events(WAF_GROUP, waf_traffic())
    moto.seed_log_events(APP_GROUP, ["GET /health 200", "GET / 200"])


async def _open_waf_group(t) -> None:
    await t.nav("nav_cloudwatch")
    await t.wait_for_screen("CloudWatchBrowserScreen")
    # The configured default region is preselected and its groups load.
    await t.wait_for_toast(r"Found 2 log group\(s\)\.")
    await choose(t, "#cw_select_log_group", WAF_GROUP)


async def _fetch(t, *, before: int) -> str:
    """Press Fetch and return the outcome toast that follows it."""
    await t.click("#cw_btn_fetch")
    outcome = re.compile(r"^(Loaded \d+ events|No events |CloudWatch fetch failed)")

    def arrived():
        fresh = [message for _, message in t.toasts()[before:] if outcome.search(message)]
        return fresh[-1] if fresh else None

    return await t.wait_until(arrived, desc="fetch outcome toast")


async def test_top_ips_split_and_action_filter(tui, seed, moto):
    _seed(seed, moto)
    async with tui() as t:
        await _open_waf_group(t)

        message = await _fetch(t, before=len(t.toasts()))
        assert message == "Loaded 13 events (60min window), 3 unique IPs."
        assert len(_events(t)) == 13
        assert _top_ips(t) == ALL_IPS

        # The toggle next to "Top IPs" cycles the action filter on click...
        await t.click("#cw_btn_ip_filter")
        await t.wait_until(lambda: _top_ips(t) == ALLOWED_IPS, desc="allowed-only ranking")
        await t.wait_until(lambda: "[Allowed]" in t.rendered_text(), desc="toggle shows Allowed")
        # ...and so does the f key.
        await t.press("f")
        await t.wait_until(lambda: _top_ips(t) == BLOCKED_IPS, desc="blocked-only ranking")
        await t.wait_until(lambda: "[Blocked]" in t.rendered_text(), desc="toggle shows Blocked")
        await t.press("f")
        await t.wait_until(lambda: _top_ips(t) == ALL_IPS, desc="full ranking again")


async def test_filter_pattern_narrows_the_fetch(tui, seed, moto):
    _seed(seed, moto)
    async with tui() as t:
        await _open_waf_group(t)

        # A quoted term narrows the fetch to the requests that contain it.
        await t.fill("#cw_input_filter_pattern", '"wp-login"')
        message = await _fetch(t, before=len(t.toasts()))
        assert message == "Loaded 5 events (60min window), 2 unique IPs."
        assert len(_events(t)) == 5
        assert _top_ips(t) == BLOCKED_IPS

        # A filter nothing matches empties both tables and says so.
        await t.fill("#cw_input_filter_pattern", "NOMATCH")
        message = await _fetch(t, before=len(t.toasts()))
        assert message == "No events matched filter NOMATCH (60min window)."
        assert _events(t) == []
        assert _top_ips(t) == []


async def test_bare_address_filter_finds_that_clients_requests(tui, seed, moto):
    _seed(seed, moto)
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
    tui, seed, moto, clock_three_hours_east_of_utc
):
    _seed(seed, moto)
    async with tui() as t:
        await _open_waf_group(t)
        message = await _fetch(t, before=len(t.toasts()))
        assert message == "Loaded 13 events (60min window), 3 unique IPs."
