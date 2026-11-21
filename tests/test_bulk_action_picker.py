"""BulkActionModal on the shared filterable list."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from textual.app import App
from textual.widgets import Button, Checkbox, Input, Static

from servonaut.screens.bulk_action import BulkActionModal, BulkPreset
from servonaut.widgets.filterable_selection import FilterableSelection
from tests._async_bounds import wait_until

CHOICES = [("k1", "zeta-1"), ("k2", "alpha-2"), ("k3", "mid-3"), ("k4", "beta-4"), ("k5", "gamma-5")]


class _Host(App):
    def __init__(self, modal: BulkActionModal) -> None:
        super().__init__()
        self.modal = modal
        self.results: list[object] = []

    def on_mount(self) -> None:
        self.push_screen(self.modal, self.results.append)


def _modal(choices=CHOICES, **kwargs) -> BulkActionModal:
    kwargs.setdefault("action_label", "Delete")
    kwargs.setdefault("confirm_text", "DELETE")
    return BulkActionModal("Delete records", "Review the records.", choices, **kwargs)


async def _ready(app: App, pilot) -> FilterableSelection:
    await wait_until(lambda: isinstance(app.screen, BulkActionModal) and bool(app.screen.query(FilterableSelection)))
    picker = app.screen.query_one(FilterableSelection)
    await wait_until(lambda: picker.total > 0)
    return picker


def _count(app: App) -> str:
    return str(app.screen.query_one("#bulk_action_count", Static).render())


async def _type(pilot, text: str) -> None:
    await pilot.press(*list(text))


@pytest.mark.asyncio
async def test_filter_then_select_all_selects_only_shown_and_clearing_keeps_it() -> None:
    app = _Host(_modal())
    async with app.run_test(size=(160, 50)) as pilot:
        picker = await _ready(app, pilot)
        app.screen.query_one("#bulk_action_search", Input).value = "alpha"
        await wait_until(lambda: picker.shown == 1)
        await pilot.click("#bulk_action_all")
        await wait_until(lambda: picker.selected == ["k2"])
        assert _count(app) == "1 selected of 5 (1 shown)"
        app.screen.query_one("#bulk_action_search", Input).value = ""
        await wait_until(lambda: picker.shown == 5)
        assert picker.selected == ["k2"]
        assert _count(app) == "1 selected of 5 (5 shown)"


@pytest.mark.asyncio
async def test_submit_returns_ids_in_choices_order_after_name_sort() -> None:
    app = _Host(_modal())
    async with app.run_test(size=(160, 50)) as pilot:
        picker = await _ready(app, pilot)
        await pilot.click("#bulk_action_sort")
        await wait_until(lambda: "Name" in str(app.screen.query_one("#bulk_action_sort", Button).label))
        names = [picker.listing.get_option_at_index(i).value for i in range(picker.shown)]
        assert names == ["k2", "k4", "k5", "k3", "k1"]
        await pilot.click("#bulk_action_all")
        await wait_until(lambda: len(picker.selected) == 5)
        app.screen.query_one("#bulk_action_confirm_input", Input).value = "DELETE"
        await wait_until(lambda: not app.screen.query_one("#bulk_action_submit", Button).disabled)
        await pilot.click("#bulk_action_submit")
        await wait_until(lambda: bool(app.results))
        assert app.results == [["k1", "k2", "k3", "k4", "k5"]]


@pytest.mark.asyncio
async def test_team_shaped_call_still_works() -> None:
    choices = [(str(n), f"server-{n}") for n in range(3)]
    modal = BulkActionModal(
        "Remove servers", "Remove them.", choices, action_label="Remove",
        confirm_text="REMOVE", label_builder=lambda key: f"server-{key}",
    )
    app = _Host(modal)
    async with app.run_test(size=(160, 50)) as pilot:
        picker = await _ready(app, pilot)
        app.screen.query_one("#bulk_action_search", Input).value = "server-1"
        await wait_until(lambda: picker.shown == 1)
        app.screen.query_one("#bulk_action_search", Input).value = ""
        await wait_until(lambda: picker.shown == 3)
        await pilot.click("#bulk_action_all")
        await wait_until(lambda: len(picker.selected) == 3)
        app.screen.query_one("#bulk_action_confirm_input", Input).value = "REMOVE"
        await wait_until(lambda: not app.screen.query_one("#bulk_action_submit", Button).disabled)
        await pilot.click("#bulk_action_submit")
        await wait_until(lambda: bool(app.results))
        assert app.results == [["0", "1", "2"]]


@pytest.mark.asyncio
async def test_preset_replaces_selection_and_shows_note_literally() -> None:
    preset = BulkPreset("Select copies", lambda: (["k3", "k4"], "Kept [bold]one[/bold] copy."))
    app = _Host(_modal(selected=["k1"], preset=preset))
    async with app.run_test(size=(160, 50)) as pilot:
        picker = await _ready(app, pilot)
        assert picker.selected == ["k1"]
        await pilot.click("#bulk_action_preset")
        await wait_until(lambda: picker.selected == ["k3", "k4"])
        note = app.screen.query_one("#bulk_action_note", Static)
        assert app.screen.query_one("#bulk_action_note_box").display
        assert "[bold]" in str(note.render())
        assert app.screen.query_one("#bulk_action_submit", Button).label.plain == "Delete (2)"


@pytest.mark.asyncio
async def test_demo_toggle_redacts_labels_keeps_state_and_hides_real_names() -> None:
    modal = _modal(selected=["k2"])
    app = _Host(modal)
    async with app.run_test(size=(160, 50)) as pilot:
        picker = await _ready(app, pilot)
        app.screen.query_one("#bulk_action_search", Input).value = "alpha"
        await wait_until(lambda: picker.shown == 1)
        await pilot.click("#bulk_action_sort")
        app.demo_mode = True
        app.redaction_service = SimpleNamespace(redact_name=lambda name: "hidden-" + str(len(name)))
        modal.refresh_after_demo_toggle()
        await wait_until(lambda: picker.shown == 0)
        assert picker.selected == ["k2"]
        assert picker.query_text == "alpha"
        assert "Name" in str(app.screen.query_one("#bulk_action_sort", Button).label)
        app.screen.query_one("#bulk_action_search", Input).value = "hidden"
        await wait_until(lambda: picker.shown == 5)
        assert all("alpha" not in str(picker.listing.get_option_at_index(i).prompt)
                   for i in range(picker.shown))


@pytest.mark.asyncio
async def test_acknowledgement_follows_selected_and_keys() -> None:
    modal = _modal(
        acknowledgement=("Include unchecked", "DELETE UNCHECKED"),
        acknowledgement_hint="Careful.", acknowledgement_keys=["k3"],
    )
    app = _Host(modal)
    async with app.run_test(size=(160, 50)) as pilot:
        picker = await _ready(app, pilot)
        box = app.screen.query_one("#bulk_action_acknowledge", Checkbox)
        assert box.disabled
        picker.select_values(["k3"])
        modal._update_submit()
        await wait_until(lambda: not box.disabled)
        picker.select_values(["k1"])
        modal._update_submit()
        await wait_until(lambda: box.disabled)


@pytest.mark.asyncio
async def test_escape_dismisses_none() -> None:
    app = _Host(_modal())
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        await pilot.press("escape")
        await wait_until(lambda: app.results == [None])


@pytest.mark.asyncio
async def test_ctrl_f_focuses_search_from_cancel_button() -> None:
    app = _Host(_modal())
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        await wait_until(lambda: app.focused is not None and app.focused.id == "bulk_action_cancel")
        await pilot.press("ctrl+f")
        await wait_until(lambda: app.focused is not None and app.focused.id == "bulk_action_search")


@pytest.mark.asyncio
async def test_control_characters_in_labels_are_neutralised() -> None:
    app = _Host(_modal([("k1", "evil\x1b]0;title\x07name")]))
    async with app.run_test(size=(160, 50)) as pilot:
        picker = await _ready(app, pilot)
        text = str(picker.listing.get_option_at_index(0).prompt)
        assert "\x1b" not in text and "\x07" not in text


@pytest.mark.asyncio
async def test_a_fingerprint_algorithm_prefix_does_not_match_every_row() -> None:
    choices = [(f"k{n}", f"key-{n}  SHA256:fp{n}") for n in range(1, 41)]
    app = _Host(_modal(choices))
    async with app.run_test(size=(160, 50)) as pilot:
        picker = await _ready(app, pilot)
        search = app.screen.query_one("#bulk_action_search", Input)
        search.value = "25"
        await wait_until(lambda: picker.shown == 1)
        assert picker.listing.get_option_at_index(0).value == "k25"
        search.value = "sha"
        await wait_until(lambda: picker.shown == 0)
