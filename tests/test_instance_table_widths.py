"""The fleet table redraws its rows once their column widths are known.

A DataTable measures new rows for its auto-width columns on its next idle
pass, not when they are added. A frame drawn in between (a busy event loop,
a slow terminal) renders the rows with the old widths, and DataTable keeps
those lines cached after the widths change, so a long server name stayed cut
short until the next repopulate.
"""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult

from servonaut.widgets.instance_table import InstanceTable

LONG_NAME = "storage-1.example.test"


def _instance(name: str) -> dict:
    return {
        "name": name,
        "id": f"id-{name}",
        "type": "t3.micro",
        "state": "running",
        "public_ip": "",
        "private_ip": "10.0.0.1",
        "region": "us-east-1",
        "provider": "AWS",
    }


class _Host(App):
    # A fixed height: a table that grows with its rows is resized, and a
    # resize drops the stale lines, which would hide the problem.
    CSS = "InstanceTable { height: 8; }"

    def compose(self) -> ComposeResult:
        yield InstanceTable()


def _drawn_text(table: InstanceTable) -> str:
    return "\n".join(table.render_line(y).text for y in range(table.size.height))


@pytest.mark.asyncio
async def test_rows_drawn_before_the_width_pass_are_redrawn_at_full_width() -> None:
    app = _Host()
    async with app.run_test(size=(220, 12)) as pilot:
        table = app.query_one(InstanceTable)
        table.populate([_instance("app-1"), _instance("cache-1")])
        await pilot.pause()

        table.populate([_instance("app-1"), _instance(LONG_NAME)])
        # A frame drawn before the table's idle pass has measured the new row.
        assert LONG_NAME not in _drawn_text(table), (
            "DataTable now sizes rows as they are added; "
            "InstanceTable._update_dimensions is no longer needed"
        )
        for _ in range(3):
            await pilot.pause()

        assert LONG_NAME in _drawn_text(table)


@pytest.mark.asyncio
async def test_rows_drawn_after_the_width_pass_show_the_full_name() -> None:
    app = _Host()
    async with app.run_test(size=(220, 12)) as pilot:
        table = app.query_one(InstanceTable)
        table.populate([_instance("app-1"), _instance(LONG_NAME)])
        for _ in range(3):
            await pilot.pause()

        assert LONG_NAME in _drawn_text(table)
