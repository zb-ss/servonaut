"""An ActionRow keeps every button inside its container when its content is rebuilt."""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.containers import Vertical

from servonaut.styles import CSS_FILES
from servonaut.widgets.action_button import ActionButton, ActionRow

LABELS = (
    ("Switch on SSH certificates", "s"),
    ("Refresh status", "r"),
    ("Audit issuance chain", "a"),
    ("Enroll server", "e"),
)


def _row(suffix: int) -> Vertical:
    return Vertical(
        ActionRow(
            *(ActionButton(text, key, id=f"b{suffix}_{i}") for i, (text, key) in enumerate(LABELS))
        ),
        id=f"box{suffix}",
    )


class _RowApp(App):
    CSS_PATH = CSS_FILES
    CSS = "#host { width: 30; height: auto; }"

    def compose(self) -> ComposeResult:
        yield Vertical(_row(0), id="host")


def _assert_inside(app: App, box_id: str) -> None:
    box = app.query_one(box_id)
    for button in box.query(ActionButton):
        assert button.region.width > 0
        assert box.region.contains_region(button.region), (button.id, button.region, box.region)


@pytest.mark.asyncio
async def test_remounted_rows_keep_every_button_inside_the_container() -> None:
    app = _RowApp()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        _assert_inside(app, "#box0")
        host = app.query_one("#host")
        for round_number in range(1, 6):
            await host.remove_children()
            await host.mount(_row(round_number))
            await pilot.pause()
            _assert_inside(app, f"#box{round_number}")


class _RecomposeApp(App):
    CSS_PATH = CSS_FILES
    CSS = "#panel { width: 30; height: auto; }"

    def compose(self) -> ComposeResult:
        yield _Panel(id="panel")


class _Panel(Vertical):
    def compose(self) -> ComposeResult:
        yield _row(0)


@pytest.mark.asyncio
async def test_recomposed_rows_keep_every_button_inside_the_container() -> None:
    app = _RecomposeApp()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        panel = app.query_one("#panel")
        for _ in range(6):
            await panel.recompose()
            await pilot.pause()
            _assert_inside(app, "#box0")


@pytest.mark.asyncio
async def test_buttons_added_to_a_row_are_fitted_without_a_resize() -> None:
    app = _RowApp()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        host = app.query_one("#host")
        await host.remove_children()
        await host.mount(Vertical(ActionRow(ActionButton("Go", "g", id="first")), id="box9"))
        await pilot.pause()
        row = app.query_one("#box9 ActionRow")
        width_before = row.size.width
        await row.mount(*(ActionButton(text, key, id=f"late{i}") for i, (text, key) in enumerate(LABELS)))
        await pilot.pause()
        await pilot.pause()
        assert row.size.width == width_before
        _assert_inside(app, "#box9")


FIVE = (
    ("Refresh memory", "r"), ("Scan server", "s"), ("Edit notes", "n"),
    ("Share memory", "m"), ("Show findings", "f"),
)


class _WrapApp(App):
    CSS_PATH = CSS_FILES
    CSS = "#host { width: 80; height: auto; } #host ActionRow { width: auto; }"

    def compose(self) -> ComposeResult:
        yield Vertical(
            ActionRow(*(ActionButton(t, k, id=f"five{i}") for i, (t, k) in enumerate(FIVE))),
            id="host",
        )


@pytest.mark.asyncio
async def test_five_actions_wrap_into_two_lines_that_keep_their_hints() -> None:
    app = _WrapApp()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.pause()
        row = app.query_one(ActionRow)
        buttons = list(row.query(ActionButton))
        assert row.has_class("-wrap")
        assert all(b.label.plain.endswith(k) for b, (_, k) in zip(buttons, FIVE))
        assert len({b.region.y for b in buttons}) == 2
        host = app.query_one("#host")
        assert all(host.region.contains_region(b.region) for b in buttons)
