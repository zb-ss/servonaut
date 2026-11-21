"""The shared filterable selection list: filtering, selecting shown rows, keys."""
from __future__ import annotations

from typing import List, Sequence

import pytest
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widgets import Button, Input

from servonaut.widgets.filterable_selection import (
    LISTED,
    PICKER_BINDINGS,
    FilterableSelection,
    PickerActions,
    SelectionRow,
    SortOrder,
    count_text,
    filter_rows,
    without_digest_prefix,
    sort_rows,
)
from tests._async_bounds import wait_until


def _row(name: str, *, fingerprint: str = "", **kwargs) -> SelectionRow:
    return SelectionRow(
        value=name, label=name, search_text=f"{name} {fingerprint}".strip(), **kwargs,
    )


# -- pure functions -------------------------------------------------------

def test_filter_is_a_case_insensitive_trimmed_substring_match() -> None:
    rows = [_row("Key-1"), _row("site-2", fingerprint="SHA256:AbC")]
    assert [r.value for r in filter_rows(rows, "  KEY ")] == ["Key-1"]
    assert [r.value for r in filter_rows(rows, "sha256:abc")] == ["site-2"]
    assert [r.value for r in filter_rows(rows, "")] == ["Key-1", "site-2"]
    assert [r.value for r in filter_rows(rows, "   ")] == ["Key-1", "site-2"]
    assert filter_rows(rows, "zzz") == []


def test_sort_is_stable_and_puts_rows_without_the_key_last() -> None:
    rows = [
        SelectionRow("a", "a", "a", sort_keys={"n": 2}),
        SelectionRow("b", "b", "b"),
        SelectionRow("c", "c", "c", sort_keys={"n": 1}),
        SelectionRow("d", "d", "d", sort_keys={"n": 2}),
    ]
    assert [r.value for r in sort_rows(rows, "n")] == ["c", "a", "d", "b"]
    assert [r.value for r in sort_rows(rows, "")] == ["a", "b", "c", "d"]


def test_count_text_is_exact() -> None:
    assert count_text(3, 40, 12) == "3 selected of 40 (12 shown)"


# -- host -----------------------------------------------------------------

class _Screen(PickerActions, ModalScreen):
    BINDINGS = [*PICKER_BINDINGS]

    def __init__(self, rows: Sequence[SelectionRow], orders: Sequence[SortOrder]) -> None:
        super().__init__()
        self._rows = rows
        self._orders = orders
        self.changes = 0

    def compose(self) -> ComposeResult:
        yield FilterableSelection(prefix="t", sort_orders=self._orders)

    def on_mount(self) -> None:
        self.query_one(FilterableSelection).set_rows(self._rows)

    def on_filterable_selection_changed(self, event: FilterableSelection.Changed) -> None:
        self.changes += 1


class _Host(App):
    def __init__(self, rows: Sequence[SelectionRow], orders: Sequence[SortOrder] = ()) -> None:
        super().__init__()
        self._rows = rows
        self._orders = orders

    def on_mount(self) -> None:
        self.push_screen(_Screen(self._rows, self._orders))


def _rows(count: int = 12) -> List[SelectionRow]:
    return [_row(f"key-{n}", fingerprint=f"SHA256:fp{n}") for n in range(1, count + 1)]


async def _ready(app: App, pilot) -> FilterableSelection:
    await wait_until(lambda: isinstance(app.screen, _Screen)
                     and bool(app.screen.query(FilterableSelection))
                     and app.screen.query_one(FilterableSelection).listing.option_count > 0)
    return app.screen.query_one(FilterableSelection)


async def _type(pilot, widget: FilterableSelection, text: str) -> None:
    widget.focus_search()
    await wait_until(lambda: widget.query_one("#t_search").has_focus)
    await pilot.press(*text)


async def _click(pilot, widget: FilterableSelection, button_id: str) -> None:
    # A pressed button ignores clicks until its brief "active" effect ends.
    button = widget.query_one(f"#{button_id}", Button)
    await wait_until(lambda: not button.has_class("-active"))
    await pilot.click(f"#{button_id}")


def _count(widget: FilterableSelection) -> str:
    return str(widget.query_one("#t_count").render())


async def _filtered(widget: FilterableSelection, pilot, text: str, shown: int) -> None:
    await _type(pilot, widget, text)
    await wait_until(lambda: widget.shown == shown
                     and widget.listing.option_count == shown)


# -- behaviour -------------------------------------------------------------

@pytest.mark.asyncio
async def test_typing_a_filter_hides_rows_but_keeps_their_selection() -> None:
    app = _Host([*_rows()[:-1], _row("key-12", fingerprint="x", selected=True)])
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        assert widget.selected == ["key-12"]
        await _filtered(widget, pilot, "key-2", 1)
        assert widget.selected == ["key-12"]
        assert _count(widget) == "1 selected of 12 (1 shown)"
        widget.query_one("#t_search", Input).value = ""
        await wait_until(lambda: widget.listing.option_count == 12)
        assert _count(widget) == "1 selected of 12 (12 shown)"


@pytest.mark.asyncio
async def test_select_all_and_none_change_only_the_shown_rows() -> None:
    app = _Host(_rows())
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        await _filtered(widget, pilot, "key-1", 4)  # key-1, key-10..12
        await _click(pilot, widget, "t_all")
        await wait_until(lambda: len(widget.selected) == 4)
        assert widget.selected == ["key-1", "key-10", "key-11", "key-12"]
        assert _count(widget) == "4 selected of 12 (4 shown)"
        widget.query_one("#t_search", Input).value = "key-2"
        await wait_until(lambda: widget.shown == 1)
        await _click(pilot, widget, "t_none")
        await wait_until(lambda: _count(widget).endswith("(1 shown)"))
        assert len(widget.selected) == 4  # hidden rows untouched
        widget.query_one("#t_search", Input).value = "key-1"
        await wait_until(lambda: widget.shown == 4)
        await _click(pilot, widget, "t_none")
        await wait_until(lambda: widget.selected == [])
        assert _count(widget) == "0 selected of 12 (4 shown)"


@pytest.mark.asyncio
async def test_disabled_rows_are_never_selected() -> None:
    rows = [_row("key-1"), _row("key-2", disabled=True, selected=True), _row("key-3")]
    app = _Host(rows)
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        assert widget.selected == []
        widget.select_visible()
        assert widget.selected == ["key-1", "key-3"]
        widget.listing.select_all()
        await wait_until(lambda: "key-2" not in widget.listing.selected)
        assert widget.selected == ["key-1", "key-3"]
        widget.select_values(["key-2", "missing"], replace=False)
        assert widget.selected == ["key-1", "key-3"]


@pytest.mark.asyncio
async def test_set_rows_keeps_selection_query_and_sort() -> None:
    orders = [SortOrder("name", "Name")]
    rows = [_row(f"key-{n}", sort_keys={"name": -n}) for n in range(1, 5)]
    app = _Host(rows, orders)
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        widget.select_values(["key-1", "key-2", "key-3"])
        await _click(pilot, widget, "t_sort")
        await wait_until(lambda: "Name" in str(widget.query_one("#t_sort", Button).label))
        await _filtered(widget, pilot, "key", 4)
        new_rows = [
            _row("key-1", sort_keys={"name": -1}),
            _row("key-2", disabled=True, sort_keys={"name": -2}),
            _row("key-4", sort_keys={"name": -4}, selected=True),
            _row("other", sort_keys={"name": 0}),
        ]
        widget.set_rows(new_rows, keep_selection=True)
        assert widget.selected == ["key-1"]  # key-2 disabled, key-3 gone, row.selected ignored
        assert widget.query_text == "key"
        assert widget.shown == 3
        values = [widget.listing.get_option_at_index(i).value for i in range(3)]
        assert values == ["key-4", "key-2", "key-1"]
        widget.set_rows(new_rows)
        assert widget.selected == ["key-4"]


@pytest.mark.asyncio
async def test_changed_is_posted_for_user_actions_not_for_filtering_or_set_rows() -> None:
    app = _Host(_rows(4))
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        screen = app.screen
        await _filtered(widget, pilot, "key-1", 1)
        widget.set_rows(_rows(4))
        await _click(pilot, widget, "t_all")
        # Only the click counts: neither filtering nor set_rows posted one.
        await wait_until(lambda: screen.changes == 1)
        widget.focus_list()
        await wait_until(lambda: widget.listing.has_focus)
        await pilot.press("down", "space")
        await wait_until(lambda: screen.changes == 2)
        assert widget.selected == []


@pytest.mark.asyncio
async def test_sort_button_cycles_orders_and_keeps_selection() -> None:
    orders = [SortOrder("name", "Name"), SortOrder("fp", "Fingerprint")]
    rows = [
        _row("b", sort_keys={"name": "b", "fp": "3"}),
        _row("a", sort_keys={"name": "a"}),
        _row("c", sort_keys={"name": "c", "fp": "1"}),
    ]
    app = _Host(rows, orders)
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        button = widget.query_one("#t_sort", Button)
        widget.select_values(["a"])

        def listed() -> List[str]:
            return [widget.listing.get_option_at_index(i).value
                    for i in range(widget.listing.option_count)]

        assert str(button.label) == "Sort: Listed order"
        assert listed() == ["b", "a", "c"]
        await _click(pilot, widget, "t_sort")
        await wait_until(lambda: str(button.label) == "Sort: Name")
        assert listed() == ["a", "b", "c"]
        await _click(pilot, widget, "t_sort")
        await wait_until(lambda: str(button.label) == "Sort: Fingerprint")
        assert listed() == ["c", "b", "a"]  # "a" has no fingerprint: last
        await _click(pilot, widget, "t_sort")
        await wait_until(lambda: str(button.label) == f"Sort: {LISTED.label}")
        assert listed() == ["b", "a", "c"]
        assert widget.selected == ["a"]


@pytest.mark.asyncio
async def test_sort_button_is_hidden_without_orders() -> None:
    app = _Host(_rows(3))
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        assert widget.query_one("#t_sort", Button).display is False


@pytest.mark.asyncio
async def test_ctrl_f_and_slash_focus_the_search_from_the_list() -> None:
    app = _Host(_rows())
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        search = widget.query_one("#t_search", Input)
        for key in ("ctrl+f", "slash"):
            widget.focus_list()
            await wait_until(lambda: widget.listing.has_focus)
            await pilot.press(key)
            await wait_until(lambda: search.has_focus)
        assert search.value == ""


@pytest.mark.asyncio
async def test_printable_keys_only_type_in_the_search_box() -> None:
    app = _Host(_rows())
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        await _type(pilot, widget, "an/")
        search = widget.query_one("#t_search", Input)
        await wait_until(lambda: search.value == "an/")
        assert widget.selected == []
        assert search.has_focus


@pytest.mark.asyncio
async def test_ctrl_a_in_the_search_box_selects_rows_and_home_moves_the_cursor() -> None:
    app = _Host(_rows())
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        await _filtered(widget, pilot, "key-2", 1)
        search = widget.query_one("#t_search", Input)
        await pilot.press("ctrl+a")
        await wait_until(lambda: widget.selected == ["key-2"])
        assert search.value == "key-2"
        assert search.cursor_position == 5
        await pilot.press("home")
        await wait_until(lambda: search.cursor_position == 0)
        await pilot.press("ctrl+n")
        await wait_until(lambda: widget.selected == [])


@pytest.mark.asyncio
async def test_typing_and_ctrl_a_in_one_batch_selects_the_matching_rows() -> None:
    app = _Host(_rows())
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        widget.focus_search()
        await wait_until(lambda: widget.query_one("#t_search").has_focus)
        await pilot.press(*"key-1", "ctrl+a")
        await wait_until(lambda: len(widget.selected) == 4)
        assert widget.selected == ["key-1", "key-10", "key-11", "key-12"]


@pytest.mark.asyncio
async def test_enter_in_the_search_box_moves_to_the_list() -> None:
    app = _Host(_rows())
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        await _filtered(widget, pilot, "key-3", 1)
        await pilot.press("enter")
        await wait_until(lambda: widget.listing.has_focus)


@pytest.mark.asyncio
async def test_a_label_with_markup_is_shown_literally() -> None:
    row = SelectionRow("k", Text("[bold]site-1"), "site-1")
    app = _Host([row])
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        prompt = widget.listing.get_option_at_index(0).prompt
        assert getattr(prompt, "plain", str(prompt)) == "[bold]site-1"


# -- Escape: clear a non-empty filter before cancelling ---------------------

class _CancelScreen(_Screen):
    BINDINGS = [Binding("escape", "cancel", show=False), *PICKER_BINDINGS]

    def action_cancel(self) -> None:
        self.dismiss(None)


class _CancelHost(App):
    def __init__(self, rows: Sequence[SelectionRow]) -> None:
        super().__init__()
        self._rows = rows
        self._orders: Sequence[SortOrder] = ()

    def on_mount(self) -> None:
        self.push_screen(_CancelScreen(self._rows, self._orders))


async def _cancel_ready(app: App) -> FilterableSelection:
    await wait_until(lambda: isinstance(app.screen, _CancelScreen)
                     and app.screen.query_one(FilterableSelection).listing.option_count > 0)
    return app.screen.query_one(FilterableSelection)


@pytest.mark.asyncio
async def test_escape_clears_a_filter_first_then_cancels() -> None:
    app = _CancelHost([*_rows()[:-1], _row("key-12", fingerprint="x", selected=True)])
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _cancel_ready(app)
        await _filtered(widget, pilot, "key-1", 4)
        await pilot.press("escape")
        await wait_until(lambda: widget.shown == 12)
        assert widget.query_text == ""
        assert widget.selected == ["key-12"]
        assert isinstance(app.screen, _CancelScreen)
        await pilot.press("escape")
        await wait_until(lambda: not isinstance(app.screen, _CancelScreen))


@pytest.mark.asyncio
async def test_escape_with_an_empty_box_cancels_at_once() -> None:
    app = _CancelHost(_rows())
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _cancel_ready(app)
        widget.focus_search()
        await wait_until(lambda: widget.query_one("#t_search").has_focus)
        await pilot.press("escape")
        await wait_until(lambda: not isinstance(app.screen, _CancelScreen))


@pytest.mark.asyncio
async def test_escape_from_the_list_cancels_even_while_filtered() -> None:
    app = _CancelHost(_rows())
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _cancel_ready(app)
        await _filtered(widget, pilot, "key-1", 4)
        widget.focus_list()
        await wait_until(lambda: widget.listing.has_focus)
        await pilot.press("escape")
        await wait_until(lambda: not isinstance(app.screen, _CancelScreen))


@pytest.mark.asyncio
async def test_enter_then_space_toggles_the_one_filtered_row() -> None:
    app = _Host(_rows())
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        await _filtered(widget, pilot, "key-7", 1)
        await pilot.press("enter")
        await wait_until(lambda: widget.listing.has_focus and widget.listing.highlighted == 0)
        await pilot.press("space")
        await wait_until(lambda: widget.selected == ["key-7"])
        await pilot.press("space")
        await wait_until(lambda: widget.selected == [])


@pytest.mark.asyncio
async def test_the_first_enabled_row_is_highlighted_when_none_can_be_restored() -> None:
    rows = [_row("key-1", disabled=True), _row("key-2"), _row("key-3")]
    app = _Host(rows)
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        await wait_until(lambda: widget.listing.highlighted == 1)


@pytest.mark.asyncio
async def test_set_rows_keeping_the_selection_first_takes_in_toggles_not_yet_synced() -> None:
    app = _Host(_rows(4))
    async with app.run_test(size=(120, 40)) as pilot:
        widget = await _ready(app, pilot)
        # A toggle made inside the list whose SelectedChanged has not been handled yet.
        widget.listing.select("key-2")
        assert widget.selected == []
        widget.set_rows(_rows(4), keep_selection=True)
        assert widget.selected == ["key-2"]
        await wait_until(lambda: "key-2" in widget.listing.selected)


def test_a_fingerprint_algorithm_prefix_is_not_searchable() -> None:
    rows = [_row(f"key-{n}", fingerprint=f"SHA256:fp{n}") for n in range(1, 41)]
    rows = [SelectionRow(r.value, r.label, without_digest_prefix(r.search_text)) for r in rows]
    assert [r.value for r in filter_rows(rows, "25")] == ["key-25"]
    assert filter_rows(rows, "sha") == []
    # A pasted full fingerprint still finds its row.
    assert [r.value for r in filter_rows(rows, "SHA256:fp7")] == ["key-7"]
