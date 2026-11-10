"""The fleet list while providers answer, driven like a user.

Real application and stylesheets (see ``_harness``); the providers are gates
the test opens, so every assertion lands in a known state and nothing sleeps.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Dict

from textual.widgets import Static
from textual.worker import WorkerState

from servonaut.screens._fleet_load import SPINNER_FRAMES, Phase
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.services.load_progress import LoadProgress
from servonaut.widgets.fleet_skeleton import FleetSkeleton
from servonaut.widgets.instance_table import InstanceTable

from . import _harness


def _run(
    scenario: Callable[[Any], Awaitable[None]], size: str = "160x50", animation: str = "none",
) -> None:
    async def main() -> None:
        app = _harness.SnapshotApp()
        app.animation_level = animation
        async with app.run_test(size=_harness.SIZES[size]) as pilot:
            await _harness.wait_for_fleet(pilot)
            await scenario(pilot)

    asyncio.run(main())


def _screen(pilot: Any) -> InstanceListScreen:
    return pilot.app.screen


def _status(pilot: Any) -> str:
    return _screen(pilot).query_one("#fleet_load_status", Static).visual.plain


def _skeleton(pilot: Any) -> FleetSkeleton:
    return _screen(pilot).query_one(FleetSkeleton)


async def _first_run(pilot: Any) -> Dict[str, Any]:
    """Nothing cached, a refresh started, no provider has answered."""
    await _harness.empty_fleet(pilot)
    gates = _harness.gate_providers(pilot.app, cached=False)
    _screen(pilot).action_refresh()
    await _harness.wait_until(pilot, lambda: _screen(pilot)._load.active, "the load to start")
    await pilot.pause()
    return gates


def _phase(pilot: Any, key: str) -> Phase:
    return _screen(pilot)._load.providers[key].phase


def test_first_run_names_each_provider_and_shows_placeholder_rows() -> None:
    async def scenario(pilot: Any) -> None:
        gates = await _first_run(pilot)
        lines = _status(pilot).splitlines()
        assert lines[0] == "Loading servers from 3 providers…  esc stop"
        assert any(line.endswith("AWS · 2 accounts") for line in lines)
        assert _skeleton(pilot).display
        gates["hetzner"].release()
        await _harness.wait_until(pilot, lambda: _phase(pilot, "hetzner") is Phase.DONE, "Hetzner")
        assert "✓ Hetzner · 1 server" in _status(pilot)
        assert _skeleton(pilot).display  # AWS and OVH are still answering

    _run(scenario)


def test_the_loading_line_names_the_account_and_region() -> None:
    async def scenario(pilot: Any) -> None:
        gates = await _first_run(pilot)
        gates["aws"].load_progress = LoadProgress(1, 2, "us-east-1")
        _screen(pilot)._tick_load()
        assert "AWS · account 1 of 2 · us-east-1" in _status(pilot)
        gates["aws"].load_progress = LoadProgress(2, 2, "eu-west-1")
        _screen(pilot)._tick_load()
        assert "AWS · account 2 of 2 · eu-west-1" in _status(pilot)

    _run(scenario)


def test_the_spinner_turns_while_a_provider_answers() -> None:
    async def scenario(pilot: Any) -> None:
        await _first_run(pilot)
        seen = set()

        def turned() -> bool:
            seen.add(_status(pilot).splitlines()[1][0])
            return len(seen) >= 3

        await _harness.wait_until(pilot, turned, "the spinner to turn")
        assert seen <= set(SPINNER_FRAMES)

    _run(scenario, animation="full")


def test_the_spinner_stays_still_when_animation_is_off() -> None:
    async def scenario(pilot: Any) -> None:
        await _first_run(pilot)
        screen = _screen(pilot)
        screen._tick_load()
        screen._tick_load()
        assert screen._load.frame == 0

    _run(scenario)


def test_the_timer_runs_only_while_a_provider_answers() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        gates = await _first_run(pilot)
        assert screen._load_timer is not None
        for gate in gates.values():
            gate.release()
        await _harness.wait_until(pilot, lambda: not screen._load.active, "the load to end")
        assert screen._load_timer is None
        assert screen._load_workers == {}  # finished workers are not kept

    _run(scenario)


def _table(pilot: Any) -> InstanceTable:
    return _screen(pilot).query_one(InstanceTable)


def test_placeholder_rows_are_not_servers() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        gates = await _first_run(pilot)
        gates["hetzner"].release()
        await _harness.wait_until(pilot, lambda: _table(pilot).row_count == 1, "Hetzner's row")
        table = _table(pilot)
        skeleton = _skeleton(pilot)
        assert skeleton.display and not skeleton.can_focus
        # Nothing counts them: table, summary, chips and the status bar.
        assert table.row_count == 1 and len(table._all_instances) == 1
        assert screen.query_one("#fleet_summary", Static).visual.plain.startswith("Showing 1 of 1")
        # The cursor cannot leave the listed servers.
        table.focus()
        await pilot.press("down", "down", "end")
        assert table.cursor_row == 0
        assert table.get_selected_instance()["name"] == "cache-1"
        # A search that matches nothing lists nothing; the placeholders stay out of it.
        screen.query_one("#search_input").value = "mail"
        await _harness.wait_until(pilot, lambda: table.row_count == 0, "the empty search result")
        assert table.get_selected_instance() is None

    _run(scenario)


def test_the_placeholder_rows_go_when_the_last_provider_answers() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        gates = await _first_run(pilot)
        for gate in gates.values():
            gate.release()
        await _harness.wait_until(pilot, lambda: not screen._load.active, "the load to end")
        assert not _skeleton(pilot).display
        assert not _table(pilot).has_class("--loading")

    _run(scenario)


def test_a_listed_server_opens_while_other_providers_still_load() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        gates = await _first_run(pilot)
        gates["hetzner"].release()
        await _harness.wait_until(pilot, lambda: _table(pilot).row_count == 1, "Hetzner's row")
        _table(pilot).focus()
        await pilot.press("enter")
        await _harness.wait_until(
            pilot, lambda: type(pilot.app.screen).__name__ == "ServerActionsScreen",
            "the server's actions",
        )
        assert screen._load.active  # AWS and OVH never stopped loading

    _run(scenario)


def test_escape_cancels_the_slow_providers_and_keeps_the_others() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        gates = await _first_run(pilot)
        gates["hetzner"].release()
        await _harness.wait_until(pilot, lambda: _phase(pilot, "hetzner") is Phase.DONE, "Hetzner")
        await pilot.press("escape")
        await _harness.wait_until(pilot, lambda: not screen._load.active, "the load to end")
        assert _phase(pilot, "hetzner") is Phase.DONE
        assert _phase(pilot, "aws") is Phase.CANCELLED
        assert _phase(pilot, "ovh") is Phase.CANCELLED
        assert [row["name"] for row in _table(pilot)._all_instances] == ["cache-1"]
        assert not _skeleton(pilot).display
        text = _status(pilot)
        assert "AWS · cancelled" in text and "OVH · cancelled" in text

    _run(scenario)


def test_escape_leaves_a_provider_that_already_answered_alone() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        gates = await _first_run(pilot)
        gates["ovh"].release()
        await _harness.wait_until(pilot, lambda: _phase(pilot, "ovh") is Phase.DONE, "OVH")
        await pilot.press("escape")
        await _harness.wait_until(pilot, lambda: not screen._load.active, "the load to end")
        assert _phase(pilot, "ovh") is Phase.DONE
        assert {row["name"] for row in _table(pilot)._all_instances} == {"mail-1", "batch-1"}

    _run(scenario)


def test_a_cancelled_provider_keeps_its_cached_rows_and_says_stale() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        gates = _harness.gate_providers(pilot.app)  # cached rows to fall back on
        screen.action_refresh()
        await _harness.wait_until(pilot, lambda: screen._load.active, "the refresh to start")
        gates["aws"].release()
        gates["hetzner"].release()
        await _harness.wait_until(pilot, lambda: _phase(pilot, "hetzner") is Phase.DONE, "Hetzner")
        before = {row["name"] for row in _table(pilot)._all_instances}
        await pilot.press("escape")
        await _harness.wait_until(pilot, lambda: not screen._load.active, "the refresh to end")
        assert {row["name"] for row in _table(pilot)._all_instances} == before
        assert "OVH · stale: cancelled" in _status(pilot)
        assert not screen._refresh_failed  # the user's choice is not a failure

    _run(scenario)


def test_escape_without_a_load_does_nothing() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        assert not screen._load.active
        assert screen.check_action("cancel_slow_providers", ()) is False
        await pilot.press("escape")
        assert pilot.app.screen is screen

    _run(scenario)


def test_the_cancelled_worker_state_ends_the_cycle() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        await _first_run(pilot)
        workers = [w for w in screen.workers if w.name in ("fetch_instances", "ovh_refresh")]
        for worker in workers:
            worker.cancel()
        await _harness.wait_until(
            pilot,
            lambda: all(w.state is WorkerState.CANCELLED for w in workers),
            "the workers to be cancelled",
        )
        assert _phase(pilot, "aws") is Phase.CANCELLED
        assert _phase(pilot, "ovh") is Phase.CANCELLED

    _run(scenario)


def test_marks_survive_a_filter_and_clear_when_their_timer_fires() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        gates = _harness.gate_providers(pilot.app)
        screen.action_refresh()
        await _harness.wait_until(pilot, lambda: screen._load.active, "the refresh to start")
        changed = [dict(row) for row in _harness.AWS_ROWS]
        changed[1]["state"] = "running"
        gates["aws"].release(changed)
        await _harness.wait_until(pilot, lambda: _phase(pilot, "aws") is Phase.DONE, "AWS")
        marked = dict(screen._marks)
        assert marked and screen._marks_timer is not None
        # Re-sorting or filtering redraws the rows; the marks stay on them.
        screen.query_one("#chip_provider_aws").press()
        await pilot.pause()
        assert _table(pilot)._marks == marked
        assert [name for name in marked.values()] == ["was stopped"]
        # The timer, not the user, takes them away.
        screen._clear_marks()
        assert screen._marks == {} and _table(pilot)._marks == {}
        assert screen._marks_timer is None

    _run(scenario)


def test_pressing_r_again_mid_load_keeps_every_provider_loading() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        await _first_run(pilot)
        screen.action_refresh()  # replaces the workers still running
        await _harness.wait_until(
            pilot,
            lambda: all(w.state is not WorkerState.PENDING for w in screen.workers),
            "the new workers to start",
        )
        await pilot.pause()
        assert {key: load.phase for key, load in screen._load.providers.items()} == {
            "aws": Phase.LOADING, "ovh": Phase.LOADING, "hetzner": Phase.LOADING,
        }
        assert screen._load.active and screen._load_timer is not None
        assert _skeleton(pilot).display
        assert screen.check_action("cancel_slow_providers", ()) is True

    _run(scenario)


def test_escape_while_typing_in_the_search_box_does_not_cancel_the_load() -> None:
    async def scenario(pilot: Any) -> None:
        screen = _screen(pilot)
        await _first_run(pilot)
        await pilot.press("slash", *"app")
        assert screen.check_action("cancel_slow_providers", ()) is False
        await pilot.press("escape")
        assert screen._load.active
        assert {load.phase for load in screen._load.providers.values()} == {Phase.LOADING}

    _run(scenario)
