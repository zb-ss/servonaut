"""An ActionRow keeps every button inside its container when its content is rebuilt."""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult
from textual.containers import Vertical

from servonaut.styles import CSS_FILES
from servonaut.widgets.action_button import ActionButton, ActionRow
from tests._async_bounds import wait_until

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


class _WideApp(App):
    CSS_PATH = CSS_FILES
    CSS = "#host { width: 72; height: auto; }"

    def compose(self) -> ComposeResult:
        yield Vertical(id="host")


class _BalanceApp(App):
    CSS_PATH = CSS_FILES
    CSS = "#host { width: 60; height: auto; }"

    def compose(self) -> ComposeResult:
        yield Vertical(
            ActionRow(
                ActionButton("Browse files", "1", short="Browse", compact=True, id="a0"),
                ActionButton("SCP transfer", "4", short="SCP", compact=True, id="a1"),
                ActionButton("Run command", "2", short="Command", compact=True, id="a2"),
                ActionButton("Diagnostics now", "5", short="Diagnose", compact=True, id="a3"),
                ActionButton("SSH connect", "3", short="SSH", compact=True, id="a4"),
            ),
            id="host",
        )


@pytest.mark.asyncio
async def test_a_wrapped_row_balances_its_lines_on_one_grid() -> None:
    app = _BalanceApp()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.pause()
        buttons = list(app.query(ActionButton))
        lines: dict[int, list[ActionButton]] = {}
        for button in buttons:
            lines.setdefault(button.region.y, []).append(button)
        assert sorted(len(line) for line in lines.values()) == [2, 3]
        first, second = (sorted(line, key=lambda b: b.region.x) for _, line in sorted(lines.items()))
        assert [b.region.x for b in second] == [b.region.x for b in first[: len(second)]]


@pytest.mark.asyncio
async def test_wrapped_columns_follow_their_own_content() -> None:
    app = _WideApp()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        host = app.query_one("#host")
        await host.remove_children()
        await host.mount(Vertical(ActionRow(
            ActionButton("Switch on SSH certificates", "s"),
            ActionButton("Refresh status", "r"),
            ActionButton("Audit issuance chain", "a"),
        ), id="box7"))
        await pilot.pause()
        await pilot.pause()
        buttons = {b.label.plain.split("  ")[0]: b for b in app.query("#box7 ActionButton")}
        assert len({b.region.y for b in buttons.values()}) <= 2
        assert buttons["Refresh status"].region.width < buttons["Switch on SSH certificates"].region.width


class _BorderedApp(App):
    CSS_PATH = CSS_FILES
    CSS = "#host { width: 52; height: auto; }"

    def compose(self) -> ComposeResult:
        yield Vertical(
            ActionRow(
                ActionButton("Browse files", "1", short="Browse", id="r0"),
                ActionButton("SCP transfer", "4", short="SCP", id="r1"),
                ActionButton("Run command", "2", short="Command", id="r2"),
                ActionButton("SSH connect", "3", short="SSH", id="r3"),
            ),
            id="host",
        )


@pytest.mark.asyncio
async def test_bordered_buttons_drop_hints_before_wrapping_into_a_second_line() -> None:
    app = _BorderedApp()
    async with app.run_test(size=(100, 30)) as pilot:
        row = app.query_one(ActionRow)
        buttons = list(app.query(ActionButton))
        await wait_until(
            lambda: row.size.width > 0
            and all(b.region.width > 0 for b in buttons)
        )
        # Hinted short words need 59 cells; the bare short words fit in 52.
        assert not row.has_class("-wrap")
        assert len({b.region.y for b in buttons}) == 1
        assert [b.label.plain for b in buttons] == ["Browse", "SCP", "Command", "SSH"]


def _uniform_buttons(count: int) -> list[ActionButton]:
    # Each button needs 14 cells (label 9, chrome 4, margin 1).
    return [ActionButton(f"Item {chr(65 + i)}", str(i), compact=True, id=f"u{i}") for i in range(count)]


class _UniformApp(App):
    CSS_PATH = CSS_FILES

    def __init__(self, width: int, **row_options) -> None:
        super().__init__()
        self._width = width
        self._row_options = row_options

    def compose(self) -> ComposeResult:
        host = Vertical(
            ActionRow(*_uniform_buttons(5), **self._row_options), id="host",
        )
        host.styles.width = self._width
        yield host


def _lines(app: App) -> list[int]:
    rows: dict[int, int] = {}
    for button in app.query(ActionButton):
        rows[button.region.y] = rows.get(button.region.y, 0) + 1
    return [rows[y] for y in sorted(rows)]


@pytest.mark.asyncio
async def test_five_buttons_that_fit_four_across_wrap_three_and_two() -> None:
    # 66 cells hold four 14-cell columns but not five, so an unbalanced wrap
    # would put four on the first line and one alone on the second.
    app = _UniformApp(66)
    async with app.run_test(size=(100, 30)) as pilot:
        row = app.query_one(ActionRow)
        await wait_until(lambda: row.size.width > 0 and all(b.region.width > 0 for b in app.query(ActionButton)))
        await pilot.pause()
        assert row.has_class("-wrap")
        assert _lines(app) == [3, 2]


@pytest.mark.asyncio
async def test_prefer_one_line_drops_hints_instead_of_wrapping() -> None:
    app = _UniformApp(66, prefer_one_line=True)
    async with app.run_test(size=(100, 30)) as pilot:
        row = app.query_one(ActionRow)
        await wait_until(lambda: row.size.width > 0 and all(b.region.width > 0 for b in app.query(ActionButton)))
        await pilot.pause()
        assert not row.has_class("-wrap")
        assert _lines(app) == [5]
        assert all(b.label.plain.startswith("Item") and not b.label.plain.rstrip().endswith(str(i))
                   for i, b in enumerate(app.query(ActionButton)))


@pytest.mark.asyncio
async def test_keep_hints_wins_over_prefer_one_line() -> None:
    app = _UniformApp(66, prefer_one_line=True, keep_hints=True)
    async with app.run_test(size=(100, 30)) as pilot:
        row = app.query_one(ActionRow)
        await wait_until(lambda: row.size.width > 0 and all(b.region.width > 0 for b in app.query(ActionButton)))
        await pilot.pause()
        assert row.has_class("-wrap")
        assert all(b.label.plain.rstrip().endswith(str(i)) for i, b in enumerate(app.query(ActionButton)))


class _CompactWrapApp(App):
    CSS_PATH = CSS_FILES
    CSS = "#host { width: 40; height: auto; }"

    def compose(self) -> ComposeResult:
        labels = [("Scan all (2)", "s"), ("Stale", "f"), ("Auto: off", "a"), ("Refresh", "r"), ("Share", "S")]
        yield Vertical(
            ActionRow(*(ActionButton(t, k, compact=True, id=f"c{i}") for i, (t, k) in enumerate(labels))),
            id="host",
        )


@pytest.mark.asyncio
async def test_a_wrapped_row_of_compact_buttons_never_folds_a_label() -> None:
    app = _CompactWrapApp()
    async with app.run_test(size=(80, 20)) as pilot:
        row = app.query_one(ActionRow)
        buttons = list(app.query(ActionButton))
        await wait_until(lambda: row.size.width > 0 and all(b.region.width > 0 for b in buttons))
        await pilot.pause()
        assert row.has_class("-wrap")
        for button in buttons:
            # Button pads its label by one cell on each side.
            assert button.content_size.width >= button.label.cell_length + 2 * button.styles.line_pad, button.id
            assert button.region.height == 1
