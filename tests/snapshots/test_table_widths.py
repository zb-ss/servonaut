"""Tables that used to scroll sideways now fit their panel."""

from __future__ import annotations

from typing import Any

import pytest
from textual.widgets import DataTable

from . import _geometry, _harness, test_memory_family as family, test_screens as screens

sizes = pytest.mark.parametrize("size", ["160x50", "100x30"])


@sizes
def test_the_ovh_inventory_does_not_scroll_sideways(size: str) -> None:
    scenario = screens._manager_of(
        "nav_ovh_manage", "OVHManagerScreen", "ovh_mgr_table", len(_harness.OVH_ROWS), 0,
    )

    def check(pilot: Any) -> None:
        table = pilot.app.screen.query_one("#ovh_mgr_table", DataTable)
        assert table.max_scroll_x == 0, f"the OVH inventory scrolls sideways ({table.size.width} wide, {table.virtual_size.width} needed)"

    _geometry.run(scenario, size, check, name="table-ovh-inventory")


@sizes
def test_the_findings_inbox_does_not_scroll_sideways(size: str) -> None:
    def check(pilot: Any) -> None:
        table = pilot.app.screen.query_one("#findings_table", DataTable)
        assert table.max_scroll_x == 0, "the findings inbox scrolls sideways"
        titles = [str(table.get_row_at(i)[table.get_column_index("title")]) for i in range(table.row_count)]
        assert all(titles)

    _geometry.run(family._findings, size, check, name="table-findings")
