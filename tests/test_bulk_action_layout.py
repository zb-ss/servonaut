"""The batch picker's record list uses the room a short terminal leaves it."""
from __future__ import annotations

import pytest
from textual.app import App
from textual.widgets import Button, Input, SelectionList

from servonaut.screens.bulk_action import BulkActionModal
from servonaut.widgets.dialogs import DialogActions, DialogContent, DialogFrame
from servonaut.widgets.filterable_selection import FilterableSelection
from tests._async_bounds import wait_until


async def _laid_out(app, records: int) -> BulkActionModal:
    """Wait for the dialog with every record listed and the list drawn."""
    await wait_until(lambda: isinstance(app.screen, BulkActionModal))
    modal = app.screen
    picker = modal.query_one(FilterableSelection)
    await wait_until(
        lambda: picker.total == records
        and modal.query_one("#bulk_action_list", SelectionList).content_region.height > 0
    )
    return modal


class _Host(App):
    records = 5

    def on_mount(self) -> None:
        self.push_screen(BulkActionModal(
            "Delete vault keys", "Delete selected keys from this vault only.",
            [(f"k{n}", f"key-{n}") for n in range(1, self.records + 1)],
            action_label="Delete", confirm_text="DELETE",
        ))


@pytest.mark.asyncio
@pytest.mark.parametrize(("size", "rows"), [((100, 30), 4), ((160, 50), 5)])
@pytest.mark.parametrize("records", [5, 40])
async def test_the_list_shows_several_records_and_keeps_the_confirmation_in_view(
    size, rows, records,
) -> None:
    # Regression: below 40 rows the list was capped at two visible records
    # while the dialog had empty lines to spare.
    if records == 40:
        rows = 12 if size == (160, 50) else 6
    app = _Host()
    app.records = records
    async with app.run_test(size=size):
        modal = await _laid_out(app, records)
        listing = modal.query_one("#bulk_action_list", SelectionList)
        body = modal.query_one("#bulk_action_body", DialogContent)
        frame = modal.query_one("#bulk_action_modal", DialogFrame)
        status = modal.query_one(".dialog-status")
        actions = modal.query_one(DialogActions)
        confirmation = modal.query_one("#bulk_action_confirm_input", Input)
        submit = modal.query_one("#bulk_action_submit", Button)
        assert listing.content_region.height >= rows
        for widget in (confirmation, submit):
            assert frame.content_region.contains_region(widget.region)
            assert modal.region.contains_region(widget.region)
            assert app.get_widget_at(*widget.region.center)[0] is widget
        assert status.region.contains_region(confirmation.region)
        assert actions.region.contains_region(submit.region)
        assert body.region.bottom <= status.region.y
        assert status.region.bottom <= actions.region.y


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_a_long_note_leaves_the_search_box_and_list_in_the_body(size) -> None:
    from servonaut.screens.bulk_action import BulkPreset

    note = "\n".join(
        f"key-{n}: 2 copies of the same key are in use, so all of them stay. "
        "Give their servers one copy before deleting the others."
        for n in range(8)
    )

    class _NoteHost(App):
        def on_mount(self) -> None:
            self.push_screen(BulkActionModal(
                "Delete vault keys", "Delete selected keys from this vault only.",
                [(f"k{n}", f"key-{n}") for n in range(1, 41)],
                action_label="Delete", confirm_text="DELETE",
                preset=BulkPreset("Select duplicate copies", lambda: ([], note)),
            ))

    app = _NoteHost()
    async with app.run_test(size=size) as pilot:
        modal = await _laid_out(app, 40)
        await pilot.click("#bulk_action_preset")
        await wait_until(lambda: modal.query_one("#bulk_action_note_box").display)
        body = modal.query_one("#bulk_action_body", DialogContent)
        listing = modal.query_one("#bulk_action_list", SelectionList)
        assert body.region.contains_region(listing.region)
        assert listing.content_region.height >= 3


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(100, 30), (160, 50)])
async def test_a_capped_note_is_scrollable_to_its_last_line(size) -> None:
    from servonaut.screens.bulk_action import BulkPreset

    note = "\n".join(f"line {n} of the note" for n in range(8))

    class _NoteHost(App):
        def on_mount(self) -> None:
            self.push_screen(BulkActionModal(
                "Delete vault keys", "Delete selected keys from this vault only.",
                [(f"k{n}", f"key-{n}") for n in range(1, 41)],
                action_label="Delete", confirm_text="DELETE",
                preset=BulkPreset("Select duplicate copies", lambda: ([], note)),
            ))

    app = _NoteHost()
    async with app.run_test(size=size) as pilot:
        modal = await _laid_out(app, 40)
        await pilot.click("#bulk_action_preset")
        box = modal.query_one("#bulk_action_note_box")
        await wait_until(lambda: box.display and box.max_scroll_y > 0)
        box.scroll_end(animate=False)
        await wait_until(lambda: box.scroll_y == box.max_scroll_y)


def _painted(app, widget) -> str:
    rows = app.screen._compositor.render_strips()
    region = widget.region.intersection(app.screen.region)
    return "\n".join(rows[y].crop(region.x, region.right).text for y in range(region.y, region.bottom))


@pytest.mark.asyncio
async def test_the_action_button_grows_with_its_count() -> None:
    # Regression: a label change alone kept the button's old width, so going
    # from "(9)" to "(10)" drew "Delete (10" with the last character cut off.
    app = _Host()
    app.records = 12
    async with app.run_test(size=(160, 50)) as pilot:
        modal = await _laid_out(app, 12)
        picker = modal.query_one(FilterableSelection)
        submit = modal.query_one("#bulk_action_submit", Button)
        picker.select_values([f"k{n}" for n in range(1, 10)])
        modal._update_submit()
        await wait_until(lambda: "Delete (9)" in _painted(app, submit))
        picker.select_values([f"k{n}" for n in range(1, 11)])
        modal._update_submit()
        await pilot.pause()
        await wait_until(lambda: "Delete (10)" in _painted(app, submit))
