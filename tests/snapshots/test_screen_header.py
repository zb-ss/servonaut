"""The shared screen header: bold title, muted description, no bar, never on the first row."""

from __future__ import annotations

from typing import Any

import pytest
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
]


def _content_top(widget: Any) -> int:
    for ancestor in widget.ancestors:
        if ancestor.has_class("workspace-content") or ancestor.id in {"keys_container", "ca_content"}:
            return ancestor.region.y
    raise AssertionError("no content container above the title")


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("nav_id,title_id,description_id", SCREENS)
async def test_screen_header_is_the_shared_look(nav_id, title_id, description_id, size) -> None:
    app = _harness.SnapshotApp()
    async with app.run_test(size=size) as pilot:
        await _harness.wait_for_fleet(pilot)
        app.vault_available = True
        app.screen.query_one(f"#{nav_id}", Button).press()
        await pilot.pause()
        await pilot.pause(0.6)
        title = app.screen.query_one(f"#{title_id}")
        assert title.has_class("screen-title")
        assert title.region.y > _content_top(title)  # one empty row above it
        assert title.styles.text_style.bold or "[bold]" in str(getattr(title, "renderable", ""))
        assert all(edge[0] in ("", "none") for edge in title.styles.border)
        if description_id:
            description = app.screen.query_one(f"#{description_id}")
            assert description.has_class("screen-description")
            assert description.region.y >= title.region.bottom
