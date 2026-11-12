"""Auto-bind frames keep native records, full fingerprints and explicit trust."""
from __future__ import annotations

import pytest
from textual.widgets import Button, Checkbox, DataTable

from servonaut.services.vault import crypto
from tests._shown_label import shown_label
from tests._async_bounds import wait_until
from tests._native_actions import click_action
from tests._workspace_reflow_conformance import tab_to
from tests.test_workspace_reflow import _painted
from tests.test_workspace_vault_reflow import (
    HOST_KEY, _VaultHost, inert_services as _inert_services, stable_open,
)

pytestmark = pytest.mark.usefixtures("navigation_open")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation", [False, True])
async def test_auto_bind_review_and_actions_stay_painted_without_losing_rows(
    size: tuple[int, int], navigation: bool,
) -> None:
    app = _VaultHost(navigation_visible=navigation)
    async with app.run_test(size=size, notifications=True) as pilot:
        screen = await stable_open(app, "auto")
        await pilot.pause()
        content = screen.query_one("#auto_bind_content")
        table = screen.query_one("#auto_bind_table", DataTable)
        before = (tuple(screen._rows), set(screen._selected), table.cursor_row)
        for selector in (
            "#auto_bind_scope", "#auto_bind_vault_select", "#auto_bind_records",
            "#auto_bind_table", "#auto_bind_review", "#auto_bind_trust",
            "#auto_bind_actions",
        ):
            widget = screen.query_one(selector)
            assert content.can_view_entire(widget), (selector, widget.region, content.region)
        assert table.region.height >= (3 if size[1] <= 32 else 5)
        actions = screen.query_one("#auto_bind_actions")
        assert [button.id for button in actions.query(Button)] == [
            "auto_bind_apply", "auto_bind_fetch_keys", "auto_bind_all",
            "auto_bind_none", "auto_bind_back",
        ]
        for button in actions.query(Button):
            assert shown_label(button) in _painted(app, button)
            assert app.get_widget_at(*button.content_region.center)[0] is button
        trust = screen.query_one("#auto_bind_trust", Checkbox)
        assert trust.label.plain in _painted(app, trust)
        assert trust.value is False
        assert (tuple(screen._rows), set(screen._selected), table.cursor_row) == before
        assert not app.vault_command_service.operations
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_full_fingerprint_is_reachable_and_binding_still_requires_trust(
    size: tuple[int, int],
) -> None:
    app = _VaultHost(navigation_visible=True)
    async with app.run_test(size=size, notifications=True) as pilot:
        screen = await stable_open(app, "auto")
        table = screen.query_one("#auto_bind_table", DataTable)
        cursor = table.cursor_row
        selected = set(screen._selected)
        detail = screen.query_one("#auto_bind_detail_scroll")
        await tab_to(pilot, detail)
        await pilot.press("end")
        await pilot.wait_for_scheduled_animations()
        assert crypto.ssh_public_fingerprint(HOST_KEY) in _painted(app, detail)
        assert table.cursor_row == cursor and screen._selected == selected
        await click_action(pilot, "#auto_bind_apply")
        await wait_until(lambda: "tick the box" in screen._status_raw)
        assert not screen.query_one("#auto_bind_trust", Checkbox).value
        assert not app.vault_command_service.operations
        assert screen._selected == selected
        assert app.screen is screen and app._exception is None
