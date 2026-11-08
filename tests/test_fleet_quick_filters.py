"""Filter logic and load reporting of the fleet list, without a screen."""

from __future__ import annotations

import pytest
from textual.app import App, ComposeResult

from servonaut.screens._fleet_filter import (
    ALL, PROVIDERS, STATES, FleetFilter, facets, next_choice, row_provider, row_state, summary,
)
from servonaut.screens._fleet_load import FleetLoad, Phase, format_ago, render_load
from servonaut.utils.instance_resolver import row_identity
from servonaut.widgets.instance_table import InstanceTable

ROWS = [
    {"id": "1", "name": "app-1", "state": "running"},
    {"id": "2", "name": "db-1", "state": "stopped"},
    {"id": "3", "name": "web-1", "is_custom": True, "provider": "colo"},
    {"id": "4", "name": "mail-1", "is_ovh": True, "state": "running"},
    {"id": "5", "name": "cache-1", "is_hetzner": True, "state": "pending"},
    {"id": "6", "name": "shared-1", "is_shared": True, "state": "Running "},
]


@pytest.mark.parametrize(
    "state, expected",
    [("running", "running"), ("Running ", "running"), ("stopped", "stopped"),
     ("pending", "other"), ("terminated", "other"), ("", "other"), (None, "other")],
)
def test_row_state_groups_every_state(state, expected) -> None:
    assert row_state({"state": state}) == expected


def test_a_row_without_a_state_key_is_other() -> None:
    assert row_state({}) == "other"


def test_row_provider_uses_the_row_source_not_its_label() -> None:
    assert [row_provider(row) for row in ROWS] == [
        "aws", "aws", "custom", "ovh", "hetzner", "shared",
    ]


def test_filters_combine_with_and() -> None:
    both = FleetFilter(state="running", provider="aws")
    assert [r["name"] for r in ROWS if both.matches(r)] == ["app-1"]
    assert [r["name"] for r in ROWS if FleetFilter().matches(r)] == [r["name"] for r in ROWS]
    assert not FleetFilter().is_active and both.is_active


def test_unknown_choices_fall_back_to_all() -> None:
    assert FleetFilter().with_state("nonsense").state == ALL
    assert FleetFilter().with_provider("nonsense").provider == ALL


def test_facets_count_each_group_with_the_other_applied() -> None:
    counts = facets(ROWS, FleetFilter(provider="aws"))
    assert counts.total == 6
    assert counts.states == {"running": 1, "stopped": 1, "other": 0}
    counts = facets(ROWS, FleetFilter(state="running"))
    assert counts.providers == {"aws": 1, "ovh": 1, "hetzner": 0, "custom": 0, "shared": 1}


def test_facets_of_nothing_are_zero() -> None:
    counts = facets([], FleetFilter())
    assert counts.total == 0 and not any(counts.states.values()) and not any(counts.providers.values())


def test_next_choice_cycles_through_the_present_choices_and_all() -> None:
    present = {"running", "stopped"}.__contains__
    order = []
    current = ALL
    for _ in range(4):
        current = next_choice(current, STATES, present)
        order.append(current)
    assert order == ["running", "stopped", ALL, "running"]


def test_next_choice_with_nothing_present_stays_on_all() -> None:
    assert next_choice(ALL, PROVIDERS, lambda _value: False) == ALL
    assert next_choice("aws", PROVIDERS, lambda _value: False) == ALL


def test_next_choice_leaves_a_choice_that_is_no_longer_present() -> None:
    assert next_choice("ovh", PROVIDERS, {"aws"}.__contains__) == ALL


def test_summary_says_only_fixed_words() -> None:
    assert summary(9, 12, FleetFilter(state="running", provider="aws")) == (
        "Showing 9 of 12 · Running · AWS"
    )
    assert summary(12, 12, FleetFilter()) == "Showing 12 of 12"
    assert summary(2, 12, FleetFilter(), "secret-name") == "Showing 2 of 12 · search"


# ---- load reporting ------------------------------------------------------


def _load(*keys: str, has_rows: bool = False, accounts: int = 1) -> FleetLoad:
    load = FleetLoad()
    for key in keys:
        load.start(key, accounts=accounts, has_rows=has_rows, cached_age="6 min ago")
    return load


def test_a_cycle_ends_when_the_last_provider_answers() -> None:
    load = _load("aws", "ovh")
    assert load.active
    load.finish("aws", count=3)
    assert load.active
    load.finish("ovh", count=2)
    assert not load.active and not load.problems


def test_a_new_cycle_forgets_the_previous_one() -> None:
    load = _load("aws")
    load.finish("aws", count=1, error="boom")
    assert load.problems
    load.start("ovh", has_rows=True)
    assert list(load.providers) == ["ovh"] and not load.first_run


def test_an_error_with_rows_is_stale_and_without_rows_failed() -> None:
    load = _load("aws", "ovh")
    load.finish("aws", count=3, error="timeout")
    load.finish("ovh", count=0, error="denied")
    assert load.providers["aws"].phase is Phase.STALE
    assert load.providers["ovh"].phase is Phase.FAILED


def test_first_run_block_lists_every_provider() -> None:
    load = _load("aws", "ovh", "hetzner", accounts=2)
    load.finish("hetzner", count=2)
    text = render_load(load).plain
    assert text.splitlines() == [
        "Loading servers from 3 providers…",
        "◐ AWS · 2 accounts",
        "◐ OVH · 2 accounts",
        "✓ Hetzner · 2 servers",
    ]


def test_a_single_server_is_not_plural() -> None:
    load = _load("hetzner")
    load.finish("hetzner", count=1)
    load.start("aws", has_rows=False)
    assert "✓ Hetzner" not in render_load(load).plain  # a new cycle began


def test_refresh_shows_one_line_with_the_cache_age() -> None:
    load = _load("aws", "ovh", "hetzner", has_rows=True)
    load.finish("aws", count=3)
    assert render_load(load).plain == "◐ Refreshing · AWS ✓ · OVH … · Hetzner …  cached 6 min ago"


def test_failure_reasons_are_literal_clipped_and_redacted() -> None:
    load = _load("ovh", has_rows=True)
    load.finish("ovh", count=2, error="[bold]x[/bold] 1.2.3.4 " + "y" * 200)
    content = render_load(load, lambda text: text.replace("1.2.3.4", "stand-in"))
    line = content.plain
    assert line.startswith("⚠ OVH · stale: [bold]x[/bold] stand-in")
    assert "1.2.3.4" not in line and line.endswith("…")
    assert len(line) < 120


def test_nothing_to_report_after_a_clean_cycle_or_before_one() -> None:
    assert render_load(FleetLoad()) is None
    load = _load("aws")
    load.finish("aws", count=3)
    assert render_load(load) is None


def test_a_cycle_delivers_only_when_a_provider_answers_cleanly() -> None:
    load = _load("aws", "ovh")
    load.finish("aws", count=3, error="offline")
    load.finish("ovh", count=2, error="offline")
    assert not load.delivered
    load.start("hetzner", has_rows=True)
    load.finish("hetzner", count=1)
    assert load.delivered
    load.start("aws", has_rows=True)  # the previous cycle ended: a new one begins
    assert not load.delivered


def test_a_provider_can_be_dropped() -> None:
    load = _load("aws", "shared")
    load.drop("shared")
    load.drop("missing")
    assert list(load.providers) == ["aws"]


@pytest.mark.parametrize(
    "seconds, text",
    [(0, "just now"), (9, "just now"), (12, "12 s ago"), (59, "59 s ago"),
     (60, "1 min ago"), (400, "6 min ago"), (7200, "2 h ago"), (-5, "just now")],
)
def test_format_ago(seconds, text) -> None:
    assert format_ago(seconds) == text


# ---- the table keeps its place --------------------------------------------


def _is_bold(text) -> bool:
    return "bold" in str(text.style) or any("bold" in str(span.style) for span in text.spans)


class _Host(App):
    def compose(self) -> ComposeResult:
        yield InstanceTable()


@pytest.mark.asyncio
async def test_filter_predicate_and_search_both_apply() -> None:
    async with _Host().run_test() as pilot:
        table = pilot.app.query_one(InstanceTable)
        table.configure_filters("1", lambda row: row.get("state") == "running")
        table.populate([dict(row) for row in ROWS])
        assert [r["name"] for r in table._filtered_instances] == ["app-1", "mail-1"]
        assert {r["name"] for r in table.searched_rows()} == {
            "app-1", "db-1", "web-1", "mail-1", "cache-1", "shared-1",
        }


@pytest.mark.asyncio
async def test_the_cursor_stays_on_its_server_when_rows_are_added_above_it() -> None:
    async with _Host().run_test() as pilot:
        table = pilot.app.query_one(InstanceTable)
        table.populate([dict(row) for row in ROWS])
        table.move_cursor(row=3)
        assert table.get_selected_instance()["name"] == "mail-1"
        table.populate([{"id": "0", "name": "api-1"}, *(dict(row) for row in ROWS)])
        assert table.get_selected_instance()["name"] == "mail-1"


@pytest.mark.asyncio
async def test_the_cursor_moves_to_the_nearest_row_when_its_server_is_gone() -> None:
    async with _Host().run_test() as pilot:
        table = pilot.app.query_one(InstanceTable)
        table.populate([dict(row) for row in ROWS])
        table.move_cursor(row=4)
        table.populate([dict(row) for row in ROWS[:3]])
        assert table.cursor_row == 2
        table.populate([])
        assert table.get_selected_instance() is None


@pytest.mark.asyncio
async def test_marks_decorate_the_name_and_state_cells() -> None:
    async with _Host().run_test() as pilot:
        table = pilot.app.query_one(InstanceTable)
        table.set_marks({row_identity(ROWS[1]): "was running"}, redraw=False)
        cells = table._row_cells(0, ROWS[1], None)
        assert cells["state"].plain.endswith("was running") and _is_bold(cells["name"])
        plain_cells = table._row_cells(0, ROWS[2], None)
        assert "was" not in str(plain_cells["state"]) and not _is_bold(plain_cells["name"])


# ---- row identity: ids repeat across sources and may be missing ------------

DUPLICATES = [
    {"id": "7", "name": "db-1", "state": "stopped"},
    {"id": "7", "name": "dup-hz", "state": "running", "is_hetzner": True},
    {"name": "no-id-a", "state": "running", "is_custom": True},
    {"name": "no-id-b", "state": "stopped", "is_custom": True},
]


@pytest.mark.asyncio
async def test_the_cursor_follows_a_server_whose_id_another_source_shares() -> None:
    async with _Host().run_test() as pilot:
        table = pilot.app.query_one(InstanceTable)
        table.populate([dict(row) for row in DUPLICATES])
        table.move_cursor(row=1)
        table.populate([dict(row) for row in DUPLICATES])
        assert table.get_selected_instance()["name"] == "dup-hz"


@pytest.mark.asyncio
async def test_rows_without_an_id_do_not_anchor_the_cursor() -> None:
    async with _Host().run_test() as pilot:
        table = pilot.app.query_one(InstanceTable)
        table.populate([dict(row) for row in DUPLICATES])
        table.move_cursor(row=3)
        table.populate([{"id": "9", "name": "new-1"}, *(dict(row) for row in DUPLICATES)])
        # No identity to follow: the cursor keeps its row number.
        assert table.cursor_row == 3


@pytest.mark.asyncio
async def test_an_unchanged_refresh_marks_nothing_even_with_shared_or_missing_ids() -> None:
    from types import SimpleNamespace

    from servonaut.screens.instance_list import InstanceListScreen

    screen = InstanceListScreen()
    screen.set_timer = lambda *args, **kwargs: None
    screen._instances = [dict(row) for row in DUPLICATES]
    screen._replace_fleet = InstanceListScreen._replace_fleet.__get__(screen)
    app = SimpleNamespace(instances=[], _instances_pristine=[], demo_mode=False)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(InstanceListScreen, "app", property(lambda _self: app))
        screen._replace_fleet(None, DUPLICATES)
        screen._replace_fleet(None, DUPLICATES)
    assert screen._marks == {}


def test_row_identity_separates_sources_accounts_and_teams_and_skips_missing_ids() -> None:
    aws = {"id": "7"}
    assert row_identity(aws) != row_identity({"id": "7", "is_hetzner": True})
    assert row_identity(aws) != row_identity({"id": "7", "account": "prod"})
    shared = {"id": "7", "is_shared": True}
    assert row_identity({**shared, "team_slug": "a"}) != row_identity({**shared, "team_slug": "b"})
    assert row_identity({"id": ""}) is None and row_identity({"name": "x"}) is None
