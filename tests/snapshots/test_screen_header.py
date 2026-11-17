"""The shared screen header: bold title, muted description, no bar, one look on every screen."""

from __future__ import annotations

from typing import Any

import pytest
from textual.css.query import NoMatches
from textual.widgets import Button

from . import _harness

pytestmark = pytest.mark.asyncio

SIZES = [(160, 50), (100, 30)]
# (navigation id, title id, description id or None)
SCREENS = [
    ("nav_keys", "keys_header", "keys_intro"),
    ("nav_secrets", "secrets_title", "secrets_subtitle"),
    ("nav_vault", "vault_title", None),
    ("nav_ca", "ca_title", "ca_description"),
    ("nav_cloudwatch", "cloudwatch_title", None),
    ("nav_cloudtrail", "cloudtrail_title", None),
    ("nav_bw_vault", "bw_vault_mgr_header", "bw_vault_mgr_hint"),
    ("nav_aws_manage", "aws_mgr_header", None),
    ("nav_hetzner_manage", "hetzner_mgr_header", None),
    ("nav_ovh_manage", "ovh_mgr_header", None),
    ("nav_ovh_dns", "dns_title", None),
    ("nav_ovh_ips", "ip_mgmt_title", None),
    ("nav_ovh_storage", "storage_title", None),
    ("nav_hetzner_ssh_keys", "hetzner_ssh_keys_header", None),
]
# One empty row between the top of the screen's content row and the title.
TITLE_OFFSET = 1


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("nav_id,title_id,description_id", SCREENS)
async def test_screen_header_is_the_shared_look(nav_id, title_id, description_id, size) -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=size) as pilot:
        await _harness.wait_for_fleet(pilot)
        app.vault_available = True
        app.screen.query_one(f"#{nav_id}", Button).press()

        def title_ready() -> bool:
            try:
                return app.screen.query_one(f"#{title_id}").region.height > 0
            except NoMatches:
                return False

        await _harness.wait_until(pilot, title_ready, f"the {title_id} header")
        await pilot.pause()
        screen = app.screen
        title = screen.query_one(f"#{title_id}")
        row_top = screen.query_one("#main-layout").region.y
        assert title.has_class("screen-title")
        assert title.region.y - row_top == TITLE_OFFSET
        _assert_no_bar(title, screen.query_one("#main-layout"))
        if description_id:
            description = screen.query_one(f"#{description_id}")
            assert description.has_class("screen-description")
            assert description.region.x == title.region.x
            assert description.region.y >= title.region.bottom


BAR_EDGES = {"thick", "heavy", "wide", "tall", "inner", "outer", "block", "blank"}


def _assert_no_bar(title: Any, stop: Any) -> None:
    """No accent bar: the title has no edge, and nothing around it up to the
    content row draws a bar-style left edge (a rounded card border is allowed)."""
    assert all(edge[0] in ("", "none") for edge in title.styles.border)
    for widget in title.ancestors:
        if widget is stop:
            return
        left = widget.styles.border.left[0]
        assert left not in BAR_EDGES, (widget, left)
