"""Tables that used to scroll sideways now fit their panel."""

from __future__ import annotations

from typing import Any

import pytest
from textual.widgets import DataTable

from servonaut.widgets.planned_table import plannable_width

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


# --- a table plans for the room it has now, however it got there -----------------


def _signature(open_scenario: Any, table_id: str, size: tuple, steps: list) -> tuple:
    """Columns, widths and sideways scroll of the table after *steps*, from a fresh start at *size*."""
    found: dict = {}

    async def scenario(pilot: Any) -> None:
        await open_scenario(pilot)
        for step in steps:
            await step(pilot)
            await _geometry.settle(pilot, pilot.app)

    def check(pilot: Any) -> None:
        table = pilot.app.screen.query_one(f"#{table_id}", DataTable)
        found["signature"] = (
            tuple((str(c.label), c.width) for c in table.ordered_columns), table.max_scroll_x,
            plannable_width(table),
        )

    _geometry.run(scenario, size, check, name=f"plan-{table_id}")
    return found["signature"]


def _resize(width: int, height: int):
    async def step(pilot: Any) -> None:
        await pilot.resize_terminal(width, height)

    return step


async def _toggle_navigation(pilot: Any) -> None:
    state = pilot.app.workspace_state
    state.navigation_visible = not state.navigation_visible
    state.navigation_choice_class = pilot.app.screen.navigation_width_class()
    pilot.app.screen.apply_workspace_state()


async def _toggle_chat(pilot: Any) -> None:
    await pilot.press("f2")


_OVH_OPEN_PLAIN = screens._manager_of(
    "nav_ovh_manage", "OVHManagerScreen", "ovh_mgr_table", len(_harness.OVH_ROWS), 0,
)


async def _OVH_OPEN(pilot: Any) -> None:
    """The OVH manager with values long enough that the columns depend on the room."""
    await _OVH_OPEN_PLAIN(pilot)
    screen = pilot.app.screen
    screen._instances = [
        dict(_harness.OVH_ROWS[0], name="a-server-with-a-rather-long-name-1", type="vps-value-1-2-40-extended-plan-x"),
        dict(_harness.OVH_ROWS[1], public_ip="2001:db8:85a3:8d3:1319:8a2e:370:7344", region="os-gra-long"),
    ]
    screen._render_table()
    await pilot.pause()

_TABLES = pytest.mark.parametrize("open_scenario,table_id", [
    (_OVH_OPEN, "ovh_mgr_table"),
    (family._findings, "findings_table"),
], ids=["ovh-inventory", "findings-inbox"])


def _assert_same_plan(actual: tuple, expected: tuple) -> None:
    """Same columns as a fresh open, for the same room.

    The side panel next to the table can come out a cell wider or narrower
    after a resize; the plan then follows the room the table really has, so
    only the columns planned for an equal room are compared, and neither may
    scroll sideways.
    """
    assert actual[1] == 0 and expected[1] == 0, "a table scrolls sideways"
    if actual[2] == expected[2]:
        assert actual[0] == expected[0]


def _hidden_navigation(open_scenario: Any):
    async def scenario(pilot: Any) -> None:
        state = pilot.app.workspace_state
        state.navigation_visible = False
        state.navigation_choice_class = pilot.app.screen.navigation_width_class()
        pilot.app.screen.apply_workspace_state()
        await pilot.pause()
        await open_scenario(pilot)

    return scenario


@_TABLES
def test_a_table_resized_there_and_back_matches_a_fresh_open(open_scenario: Any, table_id: str) -> None:
    fresh_narrow = _signature(open_scenario, table_id, (100, 30), [])
    churned = _signature(open_scenario, table_id, (100, 30), [_resize(160, 50), _resize(100, 30)])
    _assert_same_plan(churned, fresh_narrow)
    fresh_wide = _signature(open_scenario, table_id, (160, 50), [])
    grown = _signature(open_scenario, table_id, (100, 30), [_resize(160, 50)])
    _assert_same_plan(grown, fresh_wide)
    assert grown[1] == 0 and churned[1] == 0, "the table scrolls sideways"
    # ... and the OVH columns are exactly the plan for the room the table has.
    if table_id == "ovh_mgr_table":
        assert [label for label, _ in churned[0]][:2] == ["#", "Name"]


@_TABLES
def test_a_table_follows_the_navigation_and_the_chat(open_scenario: Any, table_id: str) -> None:
    fresh = _signature(open_scenario, table_id, (160, 50), [])
    after_navigation = _signature(open_scenario, table_id, (160, 50), [_toggle_navigation, _toggle_navigation])
    _assert_same_plan(after_navigation, fresh)
    after_chat = _signature(open_scenario, table_id, (160, 50), [_toggle_chat, _toggle_chat])
    _assert_same_plan(after_chat, fresh)
    hidden = _signature(open_scenario, table_id, (160, 50), [_toggle_navigation])
    assert hidden[1] == 0, "the table scrolls sideways with the navigation hidden"
    # The same room reached by hiding the navigation at the start.
    fresh_hidden = _signature(_hidden_navigation(open_scenario), table_id, (160, 50), [])
    _assert_same_plan(hidden, fresh_hidden)


def test_a_wide_character_name_is_cut_by_cells_and_marked() -> None:
    from servonaut.screens._ovh_columns import plan_columns
    from servonaut.utils.text_fit import cut

    name = "サーバー名" * 6
    widths = plan_columns([("1", name, "vps", "vps", "running", "9.9.9.9", "gra")], 30)
    assert widths["Name"] <= 28
    shown = cut(name, widths["Name"])
    assert shown.endswith("…")


def test_the_ovh_inventory_fits_beside_the_open_navigation_at_130x40() -> None:
    async def scenario(pilot: Any) -> None:
        await _OVH_OPEN_PLAIN(pilot)
        screen = pilot.app.screen
        screen._instances = [dict(_harness.OVH_ROWS[0], public_ip="141.123.123.123"), *_harness.OVH_ROWS[1:]]
        screen._render_table()
        await pilot.pause()

    def check(pilot: Any) -> None:
        table = pilot.app.screen.query_one("#ovh_mgr_table", DataTable)
        assert table.max_scroll_x == 0, f"the inventory scrolls sideways ({table.max_scroll_x})"
        labels = [str(column.label) for column in table.ordered_columns]
        shown = str(table.get_row_at(0)[labels.index("Public IP")])
        assert shown == "141.123.123.123"

    _geometry.run(scenario, (130, 40), check, name="table-ovh-130x40")


def test_the_ovh_inventory_keeps_its_title_and_panel_top_in_view_at_100x30() -> None:
    async def scenario(pilot: Any) -> None:
        await _OVH_OPEN(pilot)
        pilot.app.screen.query_one("#ovh_mgr_table").focus()
        await pilot.pause()

    def check(pilot: Any) -> None:
        screen = pilot.app.screen
        container = screen.query_one("#ovh_mgr_container")
        assert screen.region.contains_region(screen.query_one("#ovh_mgr_header").region)
        panel = screen.query_one(".provider-manager-inventory")
        assert panel.region.y >= container.region.y, "the inventory's top border is scrolled out"
        assert container.region.contains_region(screen.query_one("#ovh_mgr_table").region)

    _geometry.run(scenario, (100, 30), check, name="panel-ovh-inventory-100x30")


def test_the_findings_inbox_keeps_its_title_and_panel_top_in_view_at_100x30() -> None:
    async def scenario(pilot: Any) -> None:
        await family._findings(pilot)
        pilot.app.screen.query_one("#findings_table").focus()
        await pilot.pause()

    def check(pilot: Any) -> None:
        screen = pilot.app.screen
        assert screen.region.contains_region(screen.query_one("#findings_title").region)
        card = screen.query_one("#findings_table_card")
        container = screen.query_one("#findings_container")
        assert card.region.y >= container.region.y, "the inbox's top border is scrolled out"
        assert screen.region.contains_region(card.region)

    _geometry.run(scenario, (100, 30), check, name="panel-findings-100x30")


@sizes
def test_a_long_memory_value_is_cut_with_an_ellipsis_and_kept_whole_in_the_detail(size: str) -> None:
    long_value = "['cron.service', 'nginx.service', 'php8.2-fpm.service', 'ssh.service', 'unattended-upgrades.service']"

    async def scenario(pilot: Any) -> None:
        await screens._memory(pilot)
        screen = pilot.app.screen
        service = pilot.app.memory_service
        original = service.get_all_modules

        def with_long_value(instance_id: str, provider: str) -> dict:
            modules = original(instance_id, provider)
            return {
                name: {**data, "observed": {**data.get("observed", {}), "units": long_value}}
                for name, data in modules.items()
            }

        service.get_all_modules = with_long_value
        screen._render_table()
        await pilot.pause()

    def check(pilot: Any) -> None:
        screen = pilot.app.screen
        table = screen.query_one("#memory-table", DataTable)
        column = table.get_column_index("observed")
        keys = [str(table.get_row_at(i)[table.get_column_index("key")]) for i in range(table.row_count)]
        cell = str(table.get_row_at(keys.index("units"))[column])
        assert cell.endswith("…") and len(cell) <= 48
        assert any(long_value in detail for detail in screen._record_details.values())

    _geometry.run(scenario, size, check, name="table-memory-values")
