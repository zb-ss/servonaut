"""The fleet list's quick filters and loading reports, driven like a user.

Runs the real application with its real stylesheets (see ``_harness``), so
geometry and visibility assertions describe what is on screen.
"""

from __future__ import annotations

import asyncio
import copy
from types import SimpleNamespace
from typing import Any, Awaitable, Callable, List

import pytest
from textual.widgets import Button, Input, Static
from textual.worker import WorkerState

from servonaut.screens._demo_resolve import replace_instances
from servonaut.screens.instance_list import FleetChip, InstanceListScreen
from servonaut.utils.instance_resolver import row_identity
from servonaut.widgets.instance_table import InstanceTable

from . import _harness

# The seeded fleet: AWS app-1 (running), db-1 (stopped), bastion-1 (running);
# custom web-1 (no state); OVH mail-1 (running), batch-1 (stopped);
# Hetzner cache-1 (running).
RUNNING = {"app-1", "bastion-1", "mail-1", "cache-1"}
STOPPED = {"db-1", "batch-1"}
AWS = {"app-1", "db-1", "bastion-1"}


def _run(
    scenario: Callable[[Any], Awaitable[None]], size: str = "160x50", *, demo: bool = False,
) -> None:
    async def main() -> None:
        app = _harness.SnapshotApp(demo=demo)
        async with app.run_test(size=_harness.SIZES[size]) as pilot:
            await _harness.wait_for_fleet(pilot)
            await scenario(pilot)

    asyncio.run(main())


def _screen(pilot: Any) -> InstanceListScreen:
    return pilot.app.screen


def _names(pilot: Any) -> List[str]:
    table = _screen(pilot).query_one(InstanceTable)
    return [str(row["name"]) for row in table._filtered_instances]


def _chip(pilot: Any, group: str, value: str) -> FleetChip:
    return _screen(pilot).query_one(f"#chip_{group}_{value}", FleetChip)


def _chip_text(pilot: Any, group: str, value: str) -> str:
    return _chip(pilot, group, value).label.plain


def _summary(pilot: Any) -> str:
    return _screen(pilot).query_one("#fleet_summary", Static).visual.plain


async def _click(pilot: Any, group: str, value: str) -> None:
    await pilot.click(_chip(pilot, group, value))
    await pilot.pause()


async def _search(pilot: Any, text: str) -> None:
    _screen(pilot).query_one("#search_input", Input).value = text
    await pilot.pause(InstanceListScreen._SEARCH_DEBOUNCE + 0.2)


def test_chips_count_the_fleet_and_show_only_what_is_present() -> None:
    async def scenario(pilot: Any) -> None:
        assert _chip_text(pilot, "state", "all") == "All 7"
        assert _chip_text(pilot, "state", "running").endswith("Running 4")
        assert _chip_text(pilot, "state", "stopped").endswith("Stopped 2")
        assert _chip_text(pilot, "state", "other").endswith("Other 1")
        for provider, count in (("aws", 3), ("ovh", 2), ("hetzner", 1), ("custom", 1)):
            assert _chip(pilot, "provider", provider).display
            assert _chip_text(pilot, "provider", provider).endswith(str(count))
        # No team servers: no Team chip.
        assert not _chip(pilot, "provider", "shared").display
        assert _summary(pilot) == "7 servers"

    _run(scenario)


def test_other_chip_is_hidden_when_every_server_has_a_state() -> None:
    async def scenario(pilot: Any) -> None:
        rows = [dict(row, state="running") for row in _screen(pilot)._instances]
        _screen(pilot)._instances = rows
        _screen(pilot)._update_table()
        _screen(pilot)._update_status_bar()
        await pilot.pause()
        assert not _chip(pilot, "state", "other").display

    _run(scenario)


def test_clicking_a_state_chip_filters_and_all_clears() -> None:
    async def scenario(pilot: Any) -> None:
        await _click(pilot, "state", "running")
        assert set(_names(pilot)) == RUNNING
        assert _chip(pilot, "state", "running").has_class("--chosen")
        assert not _chip(pilot, "state", "all").has_class("--chosen")
        assert _summary(pilot) == "Showing 4 of 7 · Running"
        await _click(pilot, "state", "all")
        assert len(_names(pilot)) == 7
        assert _chip(pilot, "state", "all").has_class("--chosen")

    _run(scenario)


def test_state_and_provider_combine_and_all_clears_both() -> None:
    async def scenario(pilot: Any) -> None:
        await _click(pilot, "state", "stopped")
        await _click(pilot, "provider", "aws")
        assert _names(pilot) == ["db-1"]
        assert _summary(pilot) == "Showing 1 of 7 · Stopped · AWS"
        # Each group is single-select: a second provider replaces the first.
        await _click(pilot, "provider", "ovh")
        assert _names(pilot) == ["batch-1"]
        await _click(pilot, "state", "running")
        assert _names(pilot) == ["mail-1"]
        # Choosing the active chip again keeps it; All is how a filter ends.
        await _click(pilot, "provider", "ovh")
        assert _names(pilot) == ["mail-1"]

    _run(scenario)


def test_the_all_chip_clears_state_and_provider_together() -> None:
    async def scenario(pilot: Any) -> None:
        await _click(pilot, "state", "running")
        await _click(pilot, "provider", "aws")
        assert set(_names(pilot)) == {"app-1", "bastion-1"}
        await _click(pilot, "state", "all")
        assert len(_names(pilot)) == 7
        assert _summary(pilot) == "7 servers"

    _run(scenario)


def test_chip_counts_show_what_selecting_the_chip_would_list() -> None:
    async def scenario(pilot: Any) -> None:
        await _click(pilot, "provider", "aws")
        # State chips count AWS servers only; provider chips ignore the provider filter.
        assert _chip_text(pilot, "state", "running").endswith("Running 2")
        assert _chip_text(pilot, "state", "stopped").endswith("Stopped 1")
        assert _chip_text(pilot, "state", "other").endswith("Other 0")
        assert _chip_text(pilot, "provider", "ovh").endswith("OVH 2")
        assert _chip_text(pilot, "state", "all") == "All 7"

    _run(scenario)


def test_the_search_narrows_the_counts_and_combines_with_the_chips() -> None:
    async def scenario(pilot: Any) -> None:
        await _search(pilot, "-1")
        assert _chip_text(pilot, "state", "all") == "All 7"
        await _search(pilot, "mail")
        assert _chip_text(pilot, "state", "all") == "All 1"
        assert _chip_text(pilot, "provider", "ovh").endswith("OVH 1")
        assert _chip_text(pilot, "provider", "aws").endswith("AWS 0")
        await _click(pilot, "provider", "aws")
        assert _names(pilot) == []
        assert _summary(pilot) == "Showing 0 of 7 · AWS · search"
        await _click(pilot, "provider", "ovh")
        assert _names(pilot) == ["mail-1"]

    _run(scenario)


def test_an_empty_result_clears_the_inspector() -> None:
    async def scenario(pilot: Any) -> None:
        await _click(pilot, "state", "stopped")
        await _click(pilot, "provider", "hetzner")
        screen = _screen(pilot)
        assert screen.query_one(InstanceTable).row_count == 0
        assert _summary(pilot) == "Showing 0 of 7 · Stopped · Hetzner"
        header = screen.query_one("#fleet_inspector_header", Static).visual.plain
        assert "No server selected" in header
        assert all(b.disabled for b in screen.query("#fleet_inspector Button"))

    _run(scenario)


def test_the_inspector_follows_the_filtered_selection() -> None:
    async def scenario(pilot: Any) -> None:
        await _click(pilot, "provider", "ovh")
        screen = _screen(pilot)
        header = screen.query_one("#fleet_inspector_header", Static).visual.plain
        assert "mail-1" in header and "app-1" not in header
        screen.query_one(InstanceTable).focus()
        await pilot.press("down")
        header = screen.query_one("#fleet_inspector_header", Static).visual.plain
        assert "batch-1" in header

    _run(scenario)


def test_f_cycles_the_state_filter_and_p_the_provider_filter() -> None:
    async def scenario(pilot: Any) -> None:
        seen = []
        for _ in range(5):
            await pilot.press("f")
            await pilot.pause()
            seen.append(_screen(pilot)._filter.state)
        assert seen == ["running", "stopped", "other", "all", "running"]
        # The state filter ended on "running"; the provider cycle starts from "all".
        assert _screen(pilot)._filter.state == "running"
        seen = []
        for _ in range(6):
            await pilot.press("p")
            await pilot.pause()
            seen.append(_screen(pilot)._filter.provider)
        assert seen == ["aws", "ovh", "hetzner", "custom", "all", "aws"]
        assert set(_names(pilot)) == AWS & RUNNING

    _run(scenario)


def test_the_keys_skip_a_provider_the_fleet_does_not_list() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        replace_instances(pilot.app, "custom", [])
        screen._instances = list(pilot.app.instances)
        screen._update_table()
        screen._update_status_bar()
        await pilot.pause()
        seen = []
        for _ in range(5):
            await pilot.press("p")
            await pilot.pause()
            seen.append(screen._filter.provider)
        assert seen == ["aws", "ovh", "hetzner", "all", "aws"]
        assert not _chip(pilot, "provider", "custom").display

    _run(scenario)


def test_the_keys_work_while_a_chip_has_focus_but_are_text_in_the_search_box() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        _chip(pilot, "state", "stopped").focus()
        await pilot.pause()
        await pilot.press("f")
        assert screen._filter.state == "running"
        await pilot.press("slash", "f", "p")
        await pilot.pause()
        assert screen.query_one("#search_input", Input).value == "fp"
        assert screen._filter.state == "running"
        assert screen._filter.provider == "all"

    _run(scenario)


def test_inactive_chips_have_a_visible_pill_background_in_one_row() -> None:
    async def scenario(pilot: Any) -> None:
        for chip in _screen(pilot).query(FleetChip):
            if not chip.display or chip.has_class("--chosen"):
                continue
            assert chip.styles.background.a > 0, chip.id
            assert chip.region.height == 1

    _run(scenario)


def test_chips_take_keyboard_focus_and_enter_presses_them() -> None:
    async def scenario(pilot: Any) -> None:
        chip = _chip(pilot, "state", "stopped")
        assert chip.can_focus
        chip.focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert set(_names(pilot)) == STOPPED

    _run(scenario)


def test_the_filters_survive_leaving_the_list_and_coming_back() -> None:
    async def scenario(pilot: Any) -> None:
        await _click(pilot, "state", "running")
        await _click(pilot, "provider", "ovh")
        state = pilot.app.workspace_state
        assert (state.fleet_state_filter, state.fleet_provider_filter) == ("running", "ovh")
        screen = _screen(pilot)
        await pilot.app.push_screen(InstanceListScreen())
        await _harness.wait_until(
            pilot, lambda: pilot.app.screen is not screen and pilot.app.screen.query(InstanceTable),
            "a second fleet screen",
        )
        await _harness.wait_until(
            pilot, lambda: pilot.app.screen.query_one(InstanceTable).row_count == 1, "the filtered list",
        )
        assert _chip(pilot, "state", "running").has_class("--chosen")
        assert _chip(pilot, "provider", "ovh").has_class("--chosen")

    _run(scenario)


def test_a_refresh_keeps_the_cursor_the_search_and_the_filters() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        await _click(pilot, "state", "running")
        await _search(pilot, "1")
        table = screen.query_one(InstanceTable)
        table.focus()
        await _harness.wait_until(pilot, lambda: len(_names(pilot)) == 4, "running servers matching 1")
        names = _names(pilot)
        target = names.index("mail-1")
        table.move_cursor(row=target)
        await pilot.pause()
        gates = _harness.gate_providers(pilot.app)
        screen.action_refresh()
        # A new server appears above the selected one while it refreshes.
        extra = copy.deepcopy(_harness.AWS_ROWS)
        extra.insert(0, {**extra[0], "id": "i-00000000000000009", "name": "api-1"})
        gates["aws"].release(extra)
        gates["ovh"].release()
        gates["hetzner"].release()
        await _harness.wait_until(pilot, lambda: not screen._load.active, "the refresh to end")
        await pilot.pause()
        assert screen.query_one("#search_input", Input).value == "1"
        assert screen._filter.state == "running"
        selected = table.get_selected_instance()
        assert selected is not None and selected["name"] == "mail-1"
        assert "api-1" in _names(pilot)

    _run(scenario)


def test_first_run_lists_rows_as_providers_answer() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        await _harness.empty_fleet(pilot)
        gates = _harness.gate_providers(pilot.app, cached=False)
        screen.action_refresh()
        await pilot.pause()
        status = screen.query_one("#fleet_load_status", Static)
        assert status.display
        text = status.visual.plain
        assert "Loading servers from 3 providers" in text
        assert "AWS · 2 accounts" in text and "OVH" in text and "Hetzner" in text
        gates["hetzner"].release()
        await _harness.wait_until(pilot, lambda: _names(pilot) == ["cache-1"], "Hetzner's rows")
        text = status.visual.plain
        assert "✓ Hetzner · 1 server" in text and "AWS" in text
        gates["ovh"].release()
        await _harness.wait_until(
            pilot, lambda: {"mail-1", "cache-1"} <= set(_names(pilot)), "OVH's rows",
        )
        assert len(_names(pilot)) == 3
        # Rows that arrive on a first run are not marked as new.
        assert not screen._marks
        gates["aws"].release()
        await _harness.wait_until(pilot, lambda: not screen._load.active, "the load to end")
        await pilot.pause()
        assert not status.display
        assert screen._updated_text() == "Updated just now"

    _run(scenario)


def test_a_refresh_marks_changed_and_new_rows_for_a_few_seconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(InstanceListScreen, "_MARK_SECONDS", 0.6)

    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        gates = _harness.gate_providers(pilot.app)
        screen.action_refresh()
        await pilot.pause()
        status = screen.query_one("#fleet_load_status", Static)
        assert status.display and "Refreshing" in status.visual.plain
        assert "cached" in status.visual.plain
        changed = copy.deepcopy(_harness.AWS_ROWS)
        changed[1]["state"] = "running"
        changed.append({**changed[0], "id": "i-00000000000000009", "name": "worker-3"})
        gates["aws"].release(changed)
        await _harness.wait_until(pilot, lambda: "worker-3" in _names(pilot), "the new row")
        table = screen.query_one(InstanceTable)
        identity = {row["name"]: row_identity(row) for row in table._all_instances}
        assert table._marks == {identity["db-1"]: "was stopped", identity["worker-3"]: "new"}
        assert "AWS ✓" in status.visual.plain and "OVH …" in status.visual.plain
        gates["ovh"].release()
        gates["hetzner"].release()
        await _harness.wait_until(pilot, lambda: not table._marks, "the marks to expire")
        assert not screen._marks

    _run(scenario)


def test_a_failing_provider_keeps_its_cached_rows_and_says_they_are_stale() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        gates = _harness.gate_providers(pilot.app)
        screen.action_refresh()
        gates["aws"].release()
        gates["hetzner"].release()
        gates["ovh"].release(error="request timed out [ @click=app.quit]")
        await _harness.wait_until(pilot, lambda: not screen._load.active, "the refresh to end")
        await pilot.pause()
        assert len(_names(pilot)) == 7
        status = screen.query_one("#fleet_load_status", Static)
        assert status.display
        text = status.visual.plain
        assert "OVH · stale: request timed out [ @click=app.quit]" in text
        assert "✓" not in text

    _run(scenario)


def test_a_provider_that_fails_with_no_rows_reads_failed() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        await _harness.empty_fleet(pilot)
        gates = _harness.gate_providers(pilot.app, cached=False)
        screen.action_refresh()
        gates["aws"].release()
        gates["hetzner"].release()
        gates["ovh"].fail(RuntimeError("token refused"))
        await _harness.wait_until(pilot, lambda: not screen._load.active, "the load to end")
        text = screen.query_one("#fleet_load_status", Static).visual.plain
        assert "✗ OVH · failed: token refused" in text

    _run(scenario)


def test_demo_mode_redacts_a_provider_failure_reason() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        gates = _harness.gate_providers(pilot.app)
        redacted = []
        real = pilot.app.redact_display_text
        pilot.app.redact_display_text = lambda text: (redacted.append(text) or real(text))
        screen.action_refresh()
        gates["aws"].release()
        gates["ovh"].release()
        gates["hetzner"].release(error="cannot reach vps-00000001.example.test")
        await _harness.wait_until(pilot, lambda: not screen._load.active, "the refresh to end")
        await pilot.pause()
        text = screen.query_one("#fleet_load_status", Static).visual.plain
        assert any("vps-00000001.example.test" in item for item in redacted)
        assert "vps-00000001.example.test" not in text

    _run(scenario, demo=True)


def test_demo_mode_hides_ovh_failure_details_that_name_a_project() -> None:
    project = "7f3a9c2b1d4e5f60718293a4b5c6d7e8"

    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        gates = _harness.gate_providers(pilot.app)
        screen.action_refresh()
        gates["aws"].release()
        gates["hetzner"].release()
        gates["ovh"].release(
            error=f"Could not list OVH Public Cloud project {project} (HTTP 403); none cached."
        )
        await _harness.wait_until(pilot, lambda: not screen._load.active, "the refresh to end")
        await pilot.pause()
        text = screen.query_one("#fleet_load_status", Static).visual.plain
        assert project not in text
        assert "OVH · stale: could not refresh" in text

    _run(scenario, demo=True)


@pytest.mark.parametrize("size", ["160x50", "100x30"])
def test_the_chips_never_push_the_table_off_screen(size: str) -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        table = screen.query_one(InstanceTable)
        height = pilot.app.size.height
        assert table.region.height >= 8
        assert table.region.y + table.region.height <= height
        content = screen.query_one("#instance_list_container")
        for chip in screen.query(FleetChip):
            if not chip.display:
                continue
            assert chip.region.width > 0 and chip.region.height == 1
            assert chip.region.right <= content.region.right
            assert chip.region.bottom <= table.region.y
        refresh = screen.query_one("#fleet_refresh", Button)
        assert refresh.region.right <= content.region.right
        assert refresh.region.bottom <= table.region.y

    _run(scenario, size)


def test_narrow_terminals_stack_the_chip_groups_and_wide_ones_use_one_row() -> None:
    async def wide(pilot: Any) -> None:
        assert (
            _chip(pilot, "state", "all").region.y == _chip(pilot, "provider", "aws").region.y
        )

    async def narrow(pilot: Any) -> None:
        assert (
            _chip(pilot, "provider", "aws").region.y > _chip(pilot, "state", "all").region.y
        )

    _run(wide, "160x50")
    _run(narrow, "100x30")


def test_the_refresh_button_refreshes(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: List[str] = []
    monkeypatch.setattr(InstanceListScreen, "action_refresh", lambda self: calls.append("r"))

    async def scenario(pilot: Any) -> None:
        await pilot.click("#fleet_refresh")
        await pilot.pause()
        assert calls == ["r"]

    _run(scenario)


def test_a_team_only_load_does_not_claim_the_list_was_updated() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        before = screen._updated_text()
        assert before.startswith("Cached")
        screen._begin_load("shared")
        worker = SimpleNamespace(name="shared_refresh", error=None, result=None, is_finished=True)
        screen._record_load_outcome(SimpleNamespace(worker=worker, state=WorkerState.SUCCESS))
        assert screen._updated_text() == before
        assert pilot.app.workspace_state.fleet_updated_at is None

    _run(scenario)


def test_a_refresh_where_every_provider_fails_says_so() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        gates = _harness.gate_providers(pilot.app)
        screen.action_refresh()
        for gate in gates.values():
            gate.release(error="offline")
        await _harness.wait_until(pilot, lambda: not screen._load.active, "the refresh to end")
        await pilot.pause()
        text = screen.query_one("#fleet_updated", Static).visual.plain
        assert text.startswith("Refresh failed") and "cached" in text
        assert pilot.app.workspace_state.fleet_updated_at is None

    _run(scenario)


def test_one_provider_answering_is_an_update_even_if_another_failed() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        gates = _harness.gate_providers(pilot.app)
        screen.action_refresh()
        gates["aws"].release()
        gates["hetzner"].release()
        gates["ovh"].release(error="offline")
        await _harness.wait_until(pilot, lambda: not screen._load.active, "the refresh to end")
        await pilot.pause()
        assert screen._updated_text() == "Updated just now"

    _run(scenario)


def test_the_cache_age_is_shown_in_one_place_at_a_time() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        updated = screen.query_one("#fleet_updated", Static)
        assert updated.visual.plain == "Cached 5 min ago"
        assert "Cache:" not in screen.query_one("StatusBar").render().plain
        gates = _harness.gate_providers(pilot.app)
        screen.action_refresh()
        await pilot.pause()
        pill = screen.query_one("#fleet_load_status", Static).visual.plain
        assert "cached 5 min ago" in pill
        assert updated.visual.plain == ""
        for gate in gates.values():
            gate.release()
        await _harness.wait_until(pilot, lambda: not screen._load.active, "the refresh to end")
        await pilot.pause()
        assert updated.visual.plain == "Updated just now"

    _run(scenario)


def test_the_updated_ticker_does_not_read_the_cache_file(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        reads: List[int] = []
        original = pilot.app.cache_service.get_age
        monkeypatch.setattr(
            pilot.app.cache_service, "get_age", lambda: reads.append(1) or original(),
        )
        for _ in range(5):
            screen._sync_updated()
        assert reads == []

    _run(scenario)


def test_updated_label_counts_up(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario(pilot: Any) -> None:
        import time

        screen = _screen(pilot)
        screen._last_updated = time.time() - 12
        assert screen._updated_text() == "Updated 12 s ago"
        screen._last_updated = time.time() - 400
        assert screen._updated_text() == "Updated 6 min ago"

    _run(scenario)
