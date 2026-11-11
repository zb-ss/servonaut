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


@sizes
def test_the_ovh_inventory_shows_a_whole_address_and_marks_what_it_shortens(size: str) -> None:
    long_type = "vps-value-1-2-40-extended-plan"
    rows = [
        dict(_harness.OVH_ROWS[0], public_ip="141.123.123.123", type=long_type),
        dict(_harness.OVH_ROWS[1], public_ip="2001:db8:85a3:8d3:1319:8a2e:370:7344"),
    ]

    async def scenario(pilot: Any) -> None:
        await screens._navigate(pilot, "nav_ovh_manage", "OVHManagerScreen")
        screen = pilot.app.screen
        await _harness.wait_until(
            pilot, lambda: screen.query_one("#ovh_mgr_table", DataTable).row_count == len(_harness.OVH_ROWS),
            "the server table",
        )
        screen._instances = rows
        screen._render_table()
        await pilot.pause()

    def check(pilot: Any) -> None:
        table = pilot.app.screen.query_one("#ovh_mgr_table", DataTable)
        assert table.max_scroll_x == 0
        labels = [str(column.label) for column in table.ordered_columns]
        assert "Public IP" in labels
        address = labels.index("Public IP")
        shown = [str(table.get_row_at(i)[address]) for i in range(table.row_count)]
        assert shown[0] == "141.123.123.123", "an address was cropped without a mark"
        assert shown[1].endswith("…"), "an IPv6 address is cut without an ellipsis"
        kind = str(table.get_row_at(0)[labels.index("Type")])
        assert kind.endswith("…"), "a shortened type is not marked"

    _geometry.run(scenario, size, check, name="table-ovh-whole-address")


@sizes
def test_the_findings_instance_column_marks_a_cut_id(size: str) -> None:
    long_id = "i-0123456789abcdef01"

    async def scenario(pilot: Any) -> None:
        await family._findings(pilot)
        screen = pilot.app.screen
        screen._rows[0] = dict(screen._rows[0], instance_id=long_id)
        screen._populate_table()
        await pilot.pause()

    def check(pilot: Any) -> None:
        table = pilot.app.screen.query_one("#findings_table", DataTable)
        shown = str(table.get_row_at(0)[table.get_column_index("instance")])
        assert shown == long_id if size == "160x50" else shown.endswith("…")

    _geometry.run(scenario, size, check, name="table-findings-instance")
