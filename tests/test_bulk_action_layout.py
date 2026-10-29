"""The batch picker's record list uses the room a short terminal leaves it."""
from __future__ import annotations

import pytest
from textual.app import App
from textual.widgets import Button, Input, SelectionList

from servonaut.screens.bulk_action import BulkActionModal


class _Host(App):
    def on_mount(self) -> None:
        self.push_screen(BulkActionModal(
            "Delete vault keys", "Delete selected keys from this vault only.",
            [(f"k{n}", f"key-{n}") for n in range(1, 6)],
            action_label="Delete", confirm_text="DELETE",
        ))


@pytest.mark.asyncio
@pytest.mark.parametrize(("size", "rows"), [((100, 30), 4), ((160, 50), 5)])
async def test_the_list_shows_several_records_and_keeps_the_confirmation_in_view(size, rows) -> None:
    # Regression: below 40 rows the list was capped at two visible records
    # while the dialog had empty lines to spare.
    app = _Host()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        modal = app.screen
        listing = modal.query_one("#bulk_action_list", SelectionList)
        body = modal.query_one("#bulk_action_body")
        assert listing.content_region.height >= rows
        for widget in (modal.query_one("#bulk_action_confirm_input", Input), modal.query_one("#bulk_action_submit", Button)):
            assert modal.query_one("#bulk_action_modal").region.contains_region(widget.region)
        assert body.region.contains_region(modal.query_one("#bulk_action_confirm_input", Input).region)
