"""Self-test: a click in the desktop window lands on the widget it names.

A widget's region is where the screen last laid it out, which trails a
scroll until the screen's next update. A click measured in between lands
where the widget was, on whatever took its place. ``click_widget`` must
wait for the layout, whatever the machine's load.
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.desktop import click_widget, open_session

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_browser, pytest.mark.asyncio]


async def test_a_click_waits_for_the_layout_to_catch_up(desktop, seed):
    from textual.widgets import Button

    from servonaut.widgets.sidebar_section import SidebarSection

    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    async with desktop.in_process() as app, desktop.browser() as browser:
        page = await open_session(browser, app)
        tui = app.tui
        cloudwatch = tui.nav_button("nav_cloudwatch")
        section = next(n for n in cloudwatch.ancestors if isinstance(n, SidebarSection))
        await click_widget(page, app, section.query_one("Button.section-header", Button))
        await tui.wait_until(lambda: not section.collapsed, desc="the AWS section open")
        sidebar = tui.on_screen("#sidebar-scroll")
        await tui.wait_until(lambda: sidebar.max_scroll_y >= 2, desc="a sidebar that can scroll")

        # Scroll by less than an entry: the entry below now covers the middle
        # of the region the screen still reports for CloudWatch.
        before = cloudwatch.region
        sidebar.scroll_relative(y=2, animate=False, immediate=True)
        assert sidebar.scroll_y > 0
        assert cloudwatch.region == before, "the layout already caught up; nothing to test"
        await click_widget(page, app, cloudwatch)

        await tui.wait_for_screen("CloudWatchBrowserScreen")
