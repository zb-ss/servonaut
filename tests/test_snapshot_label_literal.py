"""Snapshot labels remain literal through the native table and success toast."""

from __future__ import annotations

from dataclasses import replace

import pytest
from textual.coordinate import Coordinate
from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import DataTable, Input
from textual.widgets._toast import Toast

from servonaut.config.schema import AppConfig
from servonaut.screens.snapshot_manager import LabelInputModal, SnapshotManagerScreen
from servonaut.services.redaction_service import RedactionService
from tests._async_bounds import wait_until
from tests.test_workspace_pilot import _Host

pytestmark = pytest.mark.usefixtures("navigation_open")


# The neutral public address exercises demo scrubbing before literal rendering.
LABEL = "daily [red] café Ω 8.8.8.8"


class _Config:
    def __init__(self) -> None:
        self.value = AppConfig()

    def get(self) -> AppConfig:
        return self.value

    def update(self, **changes: object) -> None:
        self.value = replace(self.value, **changes)


class _Sync:
    """Only in-memory list/push/rename; no encryption, API client or config IO."""

    _cached_passphrase = "fixture cached passphrase"

    def __init__(self, rows: list[dict]) -> None:
        self.rows = [dict(row) for row in rows]
        self.calls: list[tuple] = []

    async def list_snapshots(self, limit: int = 30) -> list[dict]:
        assert limit == 100
        return [dict(row) for row in self.rows]

    async def push(
        self, passphrase: str | None = None, label: str | None = None,
    ) -> dict:
        self.calls.append(("push", passphrase, label))
        self.rows.append({"id": "snapshot-new", "label": label, "version": 1})
        return dict(self.rows[-1])

    async def rename_snapshot(self, snapshot_id: str, label: str) -> dict:
        self.calls.append(("rename", snapshot_id, label))
        row = next(row for row in self.rows if row["id"] == snapshot_id)
        row["label"] = label
        return dict(row)

    async def restore_by_id(self, *args: object, **kwargs: object) -> dict:
        raise AssertionError("Unexpected snapshot restore")

    async def delete_snapshot(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("Unexpected snapshot deletion")

    def apply_remote_config(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("Unexpected local config mutation")

    def has_probe(self) -> bool:
        raise AssertionError("Cached fixture passphrase must avoid probe IO")


def _painted(app: _Host, widget: Widget) -> str:
    box = widget.content_region.intersection(app.screen.region)
    assert box.width > 0 and box.height > 0
    strips = app.screen._compositor.render_strips()
    return "\n".join(
        strips[y].crop(box.x, box.right).text
        for y in range(box.y, box.bottom)
    )


def _compact(text: str) -> str:
    return "".join(text.split())


def _host(sync: _Sync) -> _Host:
    app = _Host(navigation_visible=False)
    app.config_manager = _Config()
    app.config_sync_service = sync
    return app


async def _open(app: _Host, pilot: Pilot) -> SnapshotManagerScreen:
    await app.push_screen(SnapshotManagerScreen())
    screen = app.screen
    await wait_until(lambda: not screen._loading)
    await pilot.pause()
    return screen


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("demo", [False, True])
@pytest.mark.parametrize("field", ["label", "name"])
async def test_snapshot_table_paints_literal_label_or_name_after_demo_scrub(
    monkeypatch: pytest.MonkeyPatch, size: tuple[int, int], demo: bool, field: str,
) -> None:
    monkeypatch.delenv("SERVONAUT_DEMO_DISABLE_STREAM", raising=False)
    row = {"id": "snapshot-one", "version": 1, field: LABEL}
    sync = _Sync([row])
    app = _host(sync)
    redactor = RedactionService()
    app.demo_mode = demo
    app.redaction_service = redactor if demo else None
    expected = redactor.scrub_stream(LABEL) if demo else LABEL
    if demo:
        assert expected != LABEL and "8.8.8.8" not in expected

    async with app.run_test(size=size, notifications=True) as pilot:
        screen = await _open(app, pilot)
        table = screen.query_one("#snapshots_table", DataTable)
        await wait_until(lambda: table.row_count == 1)
        await pilot.pause()
        cell = table.get_cell_at(Coordinate(0, 1))
        assert (cell.plain if hasattr(cell, "plain") else cell) == expected
        assert expected in _painted(app, table)
        x = table.content_region.x + 1
        y = table.content_region.y + table.header_height
        assert app.get_widget_at(x, y)[0] is table
        assert screen._snapshots == [row]
        assert sync.rows == [row] and sync.calls == []
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("action", ["push", "rename"])
async def test_snapshot_native_label_save_keeps_success_toast_literal(
    monkeypatch: pytest.MonkeyPatch, size: tuple[int, int], action: str,
) -> None:
    # Avoid using the machine's hostname as the push modal's initial label.
    monkeypatch.setattr("socket.gethostname", lambda: "fixture-machine")
    sync = _Sync([{"id": "snapshot-one", "label": "before", "version": 1}])
    app = _host(sync)
    async with app.run_test(size=size, notifications=True) as pilot:
        screen = await _open(app, pilot)
        table = screen.query_one("#snapshots_table", DataTable)
        await wait_until(lambda: table.row_count == 1)
        assert await pilot.click(table, offset=(
            table.content_region.x - table.region.x + 1,
            table.content_region.y - table.region.y + table.header_height,
        ))
        await pilot.press("p" if action == "push" else "n")
        await wait_until(lambda: isinstance(app.screen, LabelInputModal))
        modal = app.screen
        await wait_until(lambda: modal.is_mounted and app.focused is modal.query_one(
            "#label_input", Input,
        ))
        await pilot.press("ctrl+shift+a", "backspace", *f"  {LABEL}  ")
        assert modal.query_one("#label_input", Input).value == f"  {LABEL}  "
        await pilot.press("enter")
        await wait_until(lambda: app.screen is screen and len(sync.calls) == 1)
        await wait_until(lambda: not screen._loading)
        expected = f"Pushed snapshot: {LABEL}" if action == "push" else f"Renamed to {LABEL}"
        await wait_until(lambda: any(
            toast._notification.message == expected for toast in screen.query(Toast)
        ))
        toast = next(t for t in screen.query(Toast) if t._notification.message == expected)
        await wait_until(
            lambda: toast.is_mounted
            and toast.content_region.width > 0
            and toast.content_region.height > 0
        )
        await pilot.pause()
        assert toast.render().plain == expected
        assert _compact(expected) in _compact(_painted(app, toast))
        assert toast._notification.severity == "information"
        assert toast._notification.markup is False
        if action == "push":
            assert sync.calls == [("push", sync._cached_passphrase, LABEL)]
            assert sync.rows[0]["label"] == "before"
            assert sync.rows[-1]["label"] == LABEL
        else:
            assert sync.calls == [("rename", "snapshot-one", LABEL)]
            assert sync.rows == [{"id": "snapshot-one", "label": LABEL, "version": 1}]
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("label", [
    "QA [red] Ω snapshot",
    "QA [red] Ω snapshot " + "segment-" * 9,
], ids=["literal", "long-literal"])
async def test_narrow_snapshot_metadata_keeps_a_data_row_above_horizontal_scrollbar(
    label: str,
) -> None:
    from servonaut.widgets.sidebar import Sidebar

    row = {
        "id": "snapshot-full-metadata", "label": label, "version": 1,
        "created_at": "2026-01-01T12:34:56+00:00",
        "hash": "0123456789abcdef" * 4,
    }
    sync = _Sync([row])
    app = _host(sync)
    app.workspace_state.navigation_visible = True
    async with app.run_test(size=(96, 30)) as pilot:
        screen = await _open(app, pilot)
        table = screen.query_one("#snapshots_table", DataTable)
        await wait_until(lambda: table.row_count == 1)
        for _ in range(len(screen.focus_chain) + 1):
            if app.focused is table:
                break
            await pilot.press("tab")
        assert app.focused is table and screen.query_one(Sidebar).display
        await pilot.press("home")  # DataTable row cursor: native horizontal home.
        await pilot.wait_for_scheduled_animations()
        assert table.show_horizontal_scrollbar and table.max_scroll_x > 0
        assert table.scrollable_content_region.height >= table.header_height + 1
        assert screen.can_view_entire(table) and "Label" in _painted(app, table)
        assert table.cursor_row == 0
        for column, expected in enumerate((
            "1", label, "1", "2026-01-01 12:34", row["hash"][:16],
        )):
            cell = table.get_cell_at(Coordinate(0, column))
            assert (cell.plain if hasattr(cell, "plain") else cell) == expected
        actions = tuple((button.id, button.label.plain, button.disabled)
                        for button in screen.query("#snapshots_actions Button"))
        assert tuple(action[0] for action in actions) == (
            "btn_pull_latest", "btn_push_new", "btn_refresh", "btn_restore",
            "btn_rename", "btn_delete",
        )
        seen: set[int] = set()

        def collect_visible_label() -> None:
            cell = table._get_cell_region(Coordinate(0, 1))
            viewport = table.scrollable_content_region.intersection(
                screen._compositor.find_widget(table).clip,
            )
            y = table.content_region.y + cell.y - int(table.scroll_y)
            left = table.content_region.x + cell.x + table.cell_padding - int(table.scroll_x)
            start, stop = max(0, viewport.x - left), min(len(label), viewport.right - left)
            assert viewport.y + table.header_height <= y < viewport.bottom
            if start < stop:
                strips = screen._compositor.render_strips()
                assert strips[y].crop(left + start, left + stop).text == label[start:stop]
                assert app.get_widget_at(left + start, y)[0] is table
                assert app.get_widget_at(left + stop - 1, y)[0] is table
                seen.update(range(start, stop))

        # Literal labels use single-cell glyphs; observe each substring at its
        # actual native position while Right scrolls the real table viewport.
        for _ in range(int(table.max_scroll_x) + 1):
            collect_visible_label()
            if len(seen) == len(label):
                break
            previous = table.scroll_x
            await pilot.press("right")
            await pilot.wait_for_scheduled_animations()
            assert table.scroll_x > previous
        assert seen == set(range(len(label)))
        await pilot.press("end")
        await pilot.wait_for_scheduled_animations()
        assert table.scroll_x == table.max_scroll_x
        assert "2026-01-01 12:34" in _painted(app, table)
        assert row["hash"][:16] in _painted(app, table)
        # A modal round trip must preserve this same real row and viewport.
        scroll = table.scroll_x
        await pilot.press("n")
        await wait_until(lambda: isinstance(app.screen, LabelInputModal))
        await wait_until(lambda: bool(app.screen.query("#label_input")) and (
            app.focused is app.screen.query_one("#label_input", Input)
        ))
        assert app.screen.query_one("#label_input", Input).value == label
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen and app.focused is table)
        await pilot.wait_for_scheduled_animations()
        assert screen.query_one(Sidebar).display and table.row_count == 1
        assert table.scroll_x == scroll and table.cursor_row == 0
        assert table.scrollable_content_region.height >= table.header_height + 1
        assert row["hash"][:16] in _painted(app, table)
        assert tuple((button.id, button.label.plain, button.disabled)
                     for button in screen.query("#snapshots_actions Button")) == actions
        assert screen._snapshots == [row] and sync.rows == [row] and sync.calls == []
        assert app._exception is None
