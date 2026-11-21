"""A filterable, sortable multi-selection list.

Composes Textual's ``SelectionList`` with a search box, a count line and
Select all / Select none / Sort controls. ``SelectionList`` cannot filter in
place and forgets its selection when its options are replaced, so this widget
owns the selected set and rebuilds the shown rows from it. Select all and
Select none act on the rows currently shown, and rows hidden by the filter keep
their selection.

Hosting screens splice :data:`PICKER_BINDINGS` into their own ``BINDINGS``
(Textual only merges the bindings of DOM classes) and mix in
:class:`PickerActions` for the matching actions. The bindings are deliberately
not priority bindings: a priority binding would run before text typed just
ahead of it has reached the search box.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Hashable, Iterable, List, Mapping, Optional, Sequence, Set

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Button, Input, SelectionList, Static
from textual.widgets.selection_list import Selection


@dataclass(frozen=True)
class SelectionRow:
    """One row of the list.

    ``label`` is handed to ``Selection`` unchanged (markup string, rich ``Text``
    or ``Content``): the caller escapes user data. ``search_text`` is the plain
    text the filter matches.
    """

    value: Hashable
    label: Any
    search_text: str
    selected: bool = False
    disabled: bool = False
    sort_keys: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SortOrder:
    """A named order; ``key`` indexes ``SelectionRow.sort_keys``."""

    key: str
    label: str


LISTED = SortOrder("", "Listed order")


_DIGEST_PREFIX = re.compile(r"\b(?:SHA\d+|MD5):", re.IGNORECASE)


def without_digest_prefix(text: str) -> str:
    """*text* without the constant algorithm prefix of a fingerprint ("SHA256:").

    Search text is built with it so typing "sha" or "25" does not match every
    row; the digest itself stays matchable.
    """
    return _DIGEST_PREFIX.sub("", text)


def filter_rows(rows: Iterable[SelectionRow], query: str) -> List[SelectionRow]:
    """Rows whose search text contains *query* (case-insensitive, trimmed)."""
    needle = without_digest_prefix(query.strip()).casefold()
    if not needle:
        return list(rows)
    return [row for row in rows if needle in row.search_text.casefold()]


def sort_rows(rows: Sequence[SelectionRow], key: str) -> List[SelectionRow]:
    """The given order for an empty *key*, else a stable sort, missing keys last."""
    if not key:
        return list(rows)
    have = [row for row in rows if row.sort_keys.get(key) is not None]
    missing = [row for row in rows if row.sort_keys.get(key) is None]
    have.sort(key=lambda row: row.sort_keys[key])
    return have + missing


def count_text(selected: int, total: int, shown: int) -> str:
    return f"{selected} selected of {total} ({shown} shown)"


PICKER_BINDINGS = (
    Binding("ctrl+f,slash", "picker_focus_filter", "Filter", show=False),
    Binding("ctrl+a", "picker_select_shown", "Select all", show=False),
    Binding("ctrl+n", "picker_clear_shown", "Select none", show=False),
)


class PickerActions:
    """Mixin for the hosting screen: actions behind :data:`PICKER_BINDINGS`."""

    def _picker(self) -> "FilterableSelection":
        return self.query_one(FilterableSelection)  # type: ignore[attr-defined]

    def action_picker_focus_filter(self) -> None:
        self._picker().focus_search()

    def action_picker_select_shown(self) -> None:
        self._picker().select_visible()

    def action_picker_clear_shown(self) -> None:
        self._picker().deselect_visible()


class _FilterInput(Input):
    """Search box where Ctrl+A selects the shown rows (Home still goes home)."""

    BINDINGS = [
        Binding("ctrl+a", "select_shown", show=False),
        Binding("escape", "clear_filter", show=False),
    ]

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        # With an empty box Escape falls through to the dialog's cancel.
        if action == "clear_filter" and not self.value:
            return False
        return super().check_action(action, parameters)

    def action_clear_filter(self) -> None:
        self.value = ""

    def action_select_shown(self) -> None:
        for ancestor in self.ancestors:
            if isinstance(ancestor, FilterableSelection):
                ancestor.select_visible()
                return


class FilterableSelection(Vertical):
    """Search box + selection list with a count line and bulk controls."""

    DEFAULT_CSS = """
    FilterableSelection {
        height: 1fr;
        width: 100%;
    }
    FilterableSelection > .fs-search-row,
    FilterableSelection > .fs-toolbar {
        height: 1;
        width: 100%;
    }
    FilterableSelection .fs-search {
        width: 1fr;
    }
    FilterableSelection .fs-count {
        width: auto;
        height: 1;
        margin-left: 1;
    }
    FilterableSelection .fs-toolbar Button {
        width: auto;
        margin-right: 1;
    }
    FilterableSelection Button:focus {
        text-style: bold underline reverse;
    }
    FilterableSelection > SelectionList {
        height: 1fr;
        min-height: 3;
    }
    """

    class Changed(Message):
        """The selected set changed through the user or a bulk control."""

        def __init__(self, selection: "FilterableSelection") -> None:
            super().__init__()
            self.selection = selection

        @property
        def control(self) -> "FilterableSelection":
            return self.selection

    def __init__(
        self,
        *,
        prefix: str,
        sort_orders: Sequence[SortOrder] = (),
        tools: Sequence[Widget] = (),
        id: Optional[str] = None,  # noqa: A002 - Textual's widget id
        classes: Optional[str] = None,
    ) -> None:
        super().__init__(id=id, classes=classes)
        self._prefix = prefix
        self._orders: List[SortOrder] = [LISTED, *sort_orders]
        self._order_index = 0
        self._tools: List[Widget] = list(tools)
        self._rows: List[SelectionRow] = []
        self._selected: Set[Hashable] = set()
        self._visible: List[SelectionRow] = []
        self._query = ""
        self._ready = False

    # -- composition -----------------------------------------------------

    def compose(self) -> ComposeResult:
        prefix = self._prefix
        with Horizontal(classes="fs-search-row"):
            yield _FilterInput(
                placeholder="Type to filter  (Ctrl+F or /)",
                compact=True,
                id=f"{prefix}_search",
                classes="fs-search",
            )
            yield Static("", id=f"{prefix}_count", classes="fs-count", markup=False)
        with Horizontal(classes="fs-toolbar"):
            all_button = Button(
                "Select all", compact=True, id=f"{prefix}_all",
            )
            all_button.tooltip = "Select every row shown (Ctrl+A)"
            yield all_button
            none_button = Button(
                "Select none", compact=True, id=f"{prefix}_none",
            )
            none_button.tooltip = "Clear every row shown (Ctrl+N)"
            yield none_button
            has_orders = len(self._orders) > 1
            sort_button = Button(
                self._sort_label(), compact=True, id=f"{prefix}_sort",
                disabled=not has_orders,
            )
            sort_button.display = has_orders
            yield sort_button
            for tool in self._tools:
                yield tool
        yield SelectionList(id=f"{prefix}_list")

    def on_mount(self) -> None:
        self._ready = True
        self._rebuild()

    # -- public API ------------------------------------------------------

    @property
    def listing(self) -> SelectionList:
        return self.query_one(f"#{self._prefix}_list", SelectionList)

    @property
    def query_text(self) -> str:
        return self._query

    @property
    def total(self) -> int:
        return len(self._rows)

    @property
    def shown(self) -> int:
        return len(self._visible)

    @property
    def selected(self) -> List[Hashable]:
        """Selected values in the given row order, never a disabled row."""
        return [
            row.value for row in self._rows
            if row.value in self._selected and not row.disabled
        ]

    def set_rows(
        self, rows: Sequence[SelectionRow], *, keep_selection: bool = False,
    ) -> None:
        """Replace the rows.

        With *keep_selection* the previously selected values that still exist
        and are selectable stay selected and ``row.selected`` is ignored.
        Query, sort order and the highlighted value are always kept.
        """
        if keep_selection and self._ready and self._sync_from_listing():
            self.post_message(self.Changed(self))
        new_rows = list(rows)
        selectable = {row.value for row in new_rows if not row.disabled}
        if keep_selection:
            self._selected = {v for v in self._selected if v in selectable}
        else:
            self._selected = {
                row.value for row in new_rows if row.selected and not row.disabled
            }
        self._rows = new_rows
        self._rebuild()

    def select_values(self, values: Iterable[Hashable], *, replace: bool = True) -> None:
        """Select *values*; unknown and disabled values are ignored."""
        selectable = {row.value for row in self._rows if not row.disabled}
        wanted = {v for v in values if v in selectable}
        self._selected = wanted if replace else self._selected | wanted
        self._rebuild()

    def select_visible(self) -> None:
        self._change_visible(select=True)

    def deselect_visible(self) -> None:
        self._change_visible(select=False)

    def clear_search(self) -> None:
        """Empty the search box and show every row again."""
        self._query = ""
        if not self._ready:
            return
        self.query_one(f"#{self._prefix}_search", _FilterInput).value = ""
        self._rebuild()

    def focus_search(self) -> None:
        self.query_one(f"#{self._prefix}_search", _FilterInput).focus()

    def focus_list(self) -> None:
        self.listing.focus()

    # -- rendering -------------------------------------------------------

    def _sort_label(self) -> str:
        return f"Sort: {self._orders[self._order_index].label}"

    def _update_count(self) -> None:
        if not self._ready:
            return
        self.query_one(f"#{self._prefix}_count", Static).update(
            count_text(len(self.selected), len(self._rows), len(self._visible))
        )

    def _highlighted_value(self, listing: SelectionList) -> Any:
        index = listing.highlighted
        if index is None or index >= listing.option_count:
            return None
        return listing.get_option_at_index(index).value

    def _rebuild(self) -> None:
        if not self._ready:
            return
        order = self._orders[self._order_index]
        self._visible = sort_rows(filter_rows(self._rows, self._query), order.key)
        listing = self.listing
        highlighted = self._highlighted_value(listing)
        with listing.prevent(SelectionList.SelectedChanged):
            listing.clear_options()
            listing.add_options([
                Selection(row.label, row.value, row.value in self._selected,
                          disabled=row.disabled)
                for row in self._visible
            ])
        restored = False
        if highlighted is not None:
            for index, row in enumerate(self._visible):
                if row.value == highlighted:
                    listing.highlighted = index
                    restored = True
                    break
        if not restored:
            # Without a highlight Space has no row to act on, e.g. after Enter
            # moved focus from the search box to a freshly filtered list.
            for index, row in enumerate(self._visible):
                if not row.disabled:
                    listing.highlighted = index
                    break
        self._update_count()

    def _sync_from_listing(self) -> bool:
        """Copy the shown rows' state from the list; True when the set changed."""
        listing = self.listing
        current = set(listing.selected)
        changed = False
        stray: List[Hashable] = []
        for row in self._visible:
            inside = row.value in current
            if row.disabled:
                if inside:
                    stray.append(row.value)
                continue
            if inside and row.value not in self._selected:
                self._selected.add(row.value)
                changed = True
            elif not inside and row.value in self._selected:
                self._selected.discard(row.value)
                changed = True
        if stray:
            with listing.prevent(SelectionList.SelectedChanged):
                for value in stray:
                    listing.deselect(value)
        return changed

    def _apply_pending_query(self) -> None:
        """A key pressed right after typing must act on what the box says."""
        box = self.query_one(f"#{self._prefix}_search", _FilterInput)
        if box.value != self._query:
            self._query = box.value
            self._rebuild()

    def _change_visible(self, *, select: bool) -> None:
        if not self._ready:
            return
        self._apply_pending_query()
        changed = False
        listing = self.listing
        with listing.prevent(SelectionList.SelectedChanged):
            for row in self._visible:
                if row.disabled:
                    continue
                if select and row.value not in self._selected:
                    self._selected.add(row.value)
                    listing.select(row.value)
                    changed = True
                elif not select and row.value in self._selected:
                    self._selected.discard(row.value)
                    listing.deselect(row.value)
                    changed = True
        self._update_count()
        if changed:
            self.post_message(self.Changed(self))

    # -- events ----------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != f"{self._prefix}_search":
            return
        event.stop()
        if self._ready and self._sync_from_listing():
            self.post_message(self.Changed(self))
        self._query = event.value
        self._rebuild()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != f"{self._prefix}_search":
            return
        event.stop()
        self.focus_list()

    def on_selection_list_selected_changed(
        self, event: SelectionList.SelectedChanged,
    ) -> None:
        event.stop()
        if self._sync_from_listing():
            self.post_message(self.Changed(self))
        self._update_count()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        prefix = self._prefix
        button_id = event.button.id
        if button_id == f"{prefix}_all":
            event.stop()
            self.select_visible()
        elif button_id == f"{prefix}_none":
            event.stop()
            self.deselect_visible()
        elif button_id == f"{prefix}_sort":
            event.stop()
            if self._ready and self._sync_from_listing():
                self.post_message(self.Changed(self))
            self._order_index = (self._order_index + 1) % len(self._orders)
            event.button.label = self._sort_label()
            self._rebuild()
