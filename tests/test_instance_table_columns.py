"""How the fleet table sizes, orders and fills its columns.

Every column is as wide as its longest value up to a maximum, so short
values leave room for the rest and a long one ends in an ellipsis. The
most important columns come first. The SSH verify column only appears once
some server has a result. Cells are plain text, never Rich markup, and the
bottom border says so while columns are scrolled out of view.
"""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult

from servonaut.widgets.instance_table import COLUMNS, SCROLL_HINT, InstanceTable

OVH_VPS_ID = "vps-00000001.example.test"
OVH_TYPE = "vps-value-1-2-40"


def _server(name: str, **fields) -> dict:
    row = {
        "id": f"i-{name}",
        "name": name,
        "type": "t3.micro",
        "state": "running",
        "public_ip": "9.9.9.9",
        "private_ip": "10.0.0.1",
        "region": "us-east-1",
        "key_name": "deploy-key",
    }
    row.update(fields)
    return row


class _Host(App):
    CSS = "InstanceTable { height: 12; border: round $primary; }"

    def compose(self) -> ComposeResult:
        yield InstanceTable()


async def _settle(pilot) -> None:
    for _ in range(3):
        await pilot.pause()


def _column_keys(table: InstanceTable) -> list:
    return [str(key.value) for key in table.columns]


def _cells(table: InstanceTable, column: str) -> list:
    index = table.get_column_index(column)
    return [str(table.get_row_at(row)[index]) for row in range(table.row_count)]


def test_the_most_important_columns_come_first() -> None:
    keys = [column.key for column in COLUMNS]
    assert keys[:6] == ["index", "name", "state", "provider", "public_ip", "type"]


@pytest.mark.asyncio
async def test_columns_fit_their_values_up_to_a_maximum() -> None:
    app = _Host()
    async with app.run_test(size=(220, 16)) as pilot:
        table = app.query_one(InstanceTable)
        long_id = "0e0e0000000000000000000000000001/batch-0001"
        table.populate([
            _server("app-1"),
            _server("mail-1", id=OVH_VPS_ID, type=OVH_TYPE, provider="OVH"),
            _server("batch-1", id=long_id, provider="OVH"),
        ])
        await _settle(pilot)

        ids = _cells(table, "id")
        assert OVH_VPS_ID in ids, "a typical OVH service name is shown in full"
        assert OVH_TYPE in _cells(table, "type")
        cut = next(cell for cell in ids if cell.startswith("0e0e"))
        assert cut.endswith("…") and len(cut) == 25
        # State holds a short word: its column stays narrow.
        state = next(c for c in table.columns.values() if str(c.key.value) == "state")
        assert state.get_render_width(table) == len("running") + 2 * table.cell_padding


@pytest.mark.asyncio
async def test_cells_are_plain_text_not_markup() -> None:
    app = _Host()
    async with app.run_test(size=(220, 16)) as pilot:
        table = app.query_one(InstanceTable)
        table.populate([_server("web[bold]-1", state="[red]odd[/red]")])
        await _settle(pilot)
        assert _cells(table, "name") == ["web[bold]-1"]
        assert _cells(table, "state") == ["[red]odd[/red]"]


@pytest.mark.asyncio
async def test_a_key_file_is_listed_by_its_file_name() -> None:
    app = _Host()
    async with app.run_test(size=(220, 16)) as pilot:
        table = app.query_one(InstanceTable)
        table.populate([
            _server("web-1", key_name="~/.ssh/web1_ed25519"),
            _server("app-1"),
            _server("db-1", key_name=""),
        ])
        await _settle(pilot)
        assert _cells(table, "key") == ["web1_ed25519", "deploy-key", "-"]


@pytest.mark.asyncio
async def test_the_ssh_column_appears_once_a_server_has_a_result() -> None:
    app = _Host()
    async with app.run_test(size=(220, 16)) as pilot:
        table = app.query_one(InstanceTable)
        table.populate([_server("app-1"), _server("db-1")])
        await _settle(pilot)
        assert "ssh" not in _column_keys(table)

        verified = _server("db-1", ssh_verify_status="auth_failed")
        table.populate([_server("app-1"), verified])
        await _settle(pilot)
        keys = _column_keys(table)
        assert keys.index("key") < keys.index("ssh") < keys.index("memory")

        # Filtering to servers without a result keeps the column in place.
        table.filter("app-1")
        await _settle(pilot)
        assert "ssh" in _column_keys(table)


@pytest.mark.asyncio
async def test_the_border_says_when_columns_are_out_of_view() -> None:
    app = _Host()
    async with app.run_test(size=(60, 16)) as pilot:
        table = app.query_one(InstanceTable)
        table.populate([_server("app-1")])
        await _settle(pilot)
        assert table.border_subtitle == SCROLL_HINT

        await pilot.resize_terminal(220, 16)
        await _settle(pilot)
        assert table.border_subtitle == ""
