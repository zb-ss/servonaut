"""Journey: two AWS accounts in the desktop window.

The desktop app draws the same TUI in a web page. With a second AWS account
(``prod``, a named profile that assumes a role in another moto account) the
fleet lists each server under its account, ``aws/web-1`` beside
``prod/web-1``, and an account picker is used with the mouse and keyboard
through the browser: picking the other account in CloudWatch lists that
account's log groups.
"""

from __future__ import annotations

import pytest

from e2e.harness import aws, fleet
from e2e.journeys.desktop.test_desktop_ui import _click_widget, _nav, _open_session

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_browser, pytest.mark.asyncio]

SECOND = fleet.AWS_SECOND_ACCOUNT
REGION = "us-east-1"
PRIMARY_HOSTS = (fleet.APP_1, fleet.AWS_WEB_1)
PRIMARY_GROUP = "/e2e/primary/app"
SECOND_GROUP = "/e2e/second/app"


def _seed_accounts(seed, moto) -> str:
    """Both accounts, their servers, caches and one log group each."""
    moto.seed_fleet(PRIMARY_HOSTS)
    role = moto.seed_account(aws.SECOND_ACCOUNT, fleet.AWS_SECOND_FLEET)
    seed.aws_profile("base")
    seed.aws_profile(SECOND, role_arn=role, source_profile="base")
    seed.config(
        aws=seed.aws_config(regions=[REGION], accounts=[seed.aws_account(SECOND, regions=[REGION])]),
        cloudwatch_default_region=REGION,
    )
    seed.cache(fleet.cache_rows(*PRIMARY_HOSTS), fresh=True)
    seed.cache(fleet.cache_rows(*fleet.AWS_SECOND_FLEET), fresh=True, account=SECOND)

    moto.seed_log_events(PRIMARY_GROUP, ["GET /primary 200"])
    moto.seed_log_events(SECOND_GROUP, ["GET /second 200"], role_arn=role)
    return role


def _group_options(tui) -> list[str]:
    select = tui.on_screen("#cw_select_log_group")
    return [str(label) for label, _value in select._options]


async def test_desktop_fleet_and_account_picker(desktop, seed, moto):
    _seed_accounts(seed, moto)
    async with desktop.in_process() as app, desktop.browser() as browser:
        page = await _open_session(browser, app)
        tui = app.tui

        # The fleet names each server after its account.
        await page.wait_for_text(f"{SECOND}/web-1")
        rows = {row[1] for row in tui.table_rows("InstanceTable")}
        assert {"aws/app-1", "aws/web-1", f"{SECOND}/web-1", f"{SECOND}/jobs-1"} <= rows

        # CloudWatch opens on the default account's log groups...
        await _nav(page, app, "nav_cloudwatch")
        await tui.wait_for_screen("CloudWatchBrowserScreen")
        await tui.wait_until(lambda: PRIMARY_GROUP in _group_options(tui), desc="primary groups")
        picker = tui.on_screen("#cw_filter_account")
        assert picker.display and picker.account == "aws"

        # ...and picking the other account with the mouse and keyboard lists its own.
        select = tui.on_screen("#cw_filter_account_select")
        await _click_widget(page, app, select)
        await tui.wait_until(lambda: select.expanded, desc="the account list open")
        # One key at a time: the menu must have moved before Enter picks.
        menu = select.query_one("SelectOverlay")
        await page.press("ArrowDown")
        await tui.wait_until(lambda: menu.highlighted == 1, desc="the second account highlighted")
        await page.press("Enter")
        await tui.wait_until(lambda: picker.account == SECOND, desc="the second account picked")
        await tui.wait_until(lambda: SECOND_GROUP in _group_options(tui), desc="second groups")
        assert PRIMARY_GROUP not in _group_options(tui)
        assert page.errors() == []
