"""Tests for FleetMemoryScreen live per-row update and summary helper.

Unit-tests for:
- ``_summary_line_from_rows`` — static helper that builds the fleet status footer.
- ``_update_row_for_instance`` — live cell updater fired from _on_scan_progress.

These tests construct ``FleetMemoryScreen`` via ``object.__new__`` (skipping
the full Textual init) and patch ``app`` using the same harness pattern as
``test_demo_mode_coverage.py``.  The DataTable is mocked so ``update_cell_at``
assertions run without a running Textual event loop.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, call, patch

import pytest

from servonaut.screens.fleet_memory import (
    FleetMemoryScreen,
    STATUS_FRESH,
    STATUS_STALE,
    STATUS_NONE,
    STATUS_OPT_OUT,
    _STATUS_CELL,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_screen() -> FleetMemoryScreen:
    """Return a FleetMemoryScreen skipping the Textual widget init."""
    screen = object.__new__(FleetMemoryScreen)
    screen._rows = []
    screen._scanning = False
    return screen


def _make_app(
    *,
    memory_service: Any = None,
    demo_mode: bool = False,
) -> MagicMock:
    """Return a minimal mock ServonautApp."""
    app = MagicMock()
    app.demo_mode = demo_mode
    app.redaction_service = None
    app.memory_service = memory_service
    app.instances = []
    return app


def _set_app(screen: Any, app: Any) -> None:
    """Patch the ``app`` property on the screen's class shadow (read-only bypass)."""
    type(screen).app = property(lambda self: app)


def _fresh_modules(age_seconds: float = 60.0) -> Dict[str, Any]:
    ts = (datetime.now(tz=timezone.utc) - timedelta(seconds=age_seconds)).isoformat()
    return {"os": {"probed_at": ts}}


def _stale_modules(threshold: float = 7 * 86400) -> Dict[str, Any]:
    ts = (
        datetime.now(tz=timezone.utc) - timedelta(seconds=threshold + 3600)
    ).isoformat()
    return {"os": {"probed_at": ts}}


def _make_memory_service(
    *,
    module_map: Optional[Dict[str, Dict[str, Any]]] = None,
    disabled_ids: Optional[List[str]] = None,
    stale_seconds: float = 7 * 86400,
) -> MagicMock:
    """Return a memory service mock.

    ``module_map`` maps raw_id → modules dict returned by ``get_all_modules``.
    ``disabled_ids`` lists ids for which ``is_memory_disabled`` returns True.
    """
    ms = MagicMock()
    ms.snapshot_stale_seconds = stale_seconds
    disabled = set(disabled_ids or [])

    def _is_disabled(iid: str, name: str) -> bool:
        return iid in disabled or name in disabled

    def _get_all_modules(iid: str, provider: str) -> Dict[str, Any]:
        return (module_map or {}).get(iid, {})

    ms.is_memory_disabled = MagicMock(side_effect=_is_disabled)
    ms.get_all_modules = MagicMock(side_effect=_get_all_modules)
    return ms


def _row(
    raw_id: str,
    raw_provider: str = "aws",
    status: str = STATUS_STALE,
    modules: int = 0,
    age: str = "—",
    name: str = "",
) -> Dict[str, Any]:
    """Build a minimal _rows entry."""
    return {
        "instance": {"id": raw_id, "name": name or raw_id, "provider": raw_provider},
        "id": raw_id,
        "raw_id": raw_id,
        "name": name or raw_id,
        "provider": raw_provider,
        "raw_provider": raw_provider,
        "source": "local",
        "status": status,
        "modules": modules,
        "drift_7d": 0,
        "age": age,
    }


# ---------------------------------------------------------------------------
# _summary_line_from_rows
# ---------------------------------------------------------------------------


class TestSummaryLineFromRows:
    def test_empty_rows(self) -> None:
        line = FleetMemoryScreen._summary_line_from_rows([])
        assert "0 instances" in line
        assert "0 not probed" in line

    def test_single_fresh_row(self) -> None:
        rows = [_row("web-1", status=STATUS_FRESH)]
        line = FleetMemoryScreen._summary_line_from_rows(rows)
        assert "1 instances" in line
        assert "1 fresh" in line
        assert "0 stale" in line

    def test_mixed_statuses(self) -> None:
        rows = [
            _row("web-1", status=STATUS_FRESH),
            _row("web-2", status=STATUS_STALE),
            _row("web-3", status=STATUS_NONE),
            _row("web-4", status=STATUS_OPT_OUT),
        ]
        line = FleetMemoryScreen._summary_line_from_rows(rows)
        assert "4 instances" in line
        assert "1 fresh" in line
        assert "1 stale" in line
        assert "1 not probed" in line
        assert "1 opted-out" in line

    def test_all_opted_out(self) -> None:
        rows = [_row(f"web-{i}", status=STATUS_OPT_OUT) for i in range(3)]
        line = FleetMemoryScreen._summary_line_from_rows(rows)
        assert "3 opted-out" in line
        assert "0 fresh" in line

    def test_summary_reflects_updated_row_dict(self) -> None:
        """After mutating a row's status the helper reads the new value."""
        row = _row("web-1", status=STATUS_STALE)
        rows = [row]
        before = FleetMemoryScreen._summary_line_from_rows(rows)
        assert "1 stale" in before

        row["status"] = STATUS_FRESH
        after = FleetMemoryScreen._summary_line_from_rows(rows)
        assert "0 stale" in after
        assert "1 fresh" in after


# ---------------------------------------------------------------------------
# _update_row_for_instance — no-op guard cases
# ---------------------------------------------------------------------------


class TestUpdateRowForInstanceNoOp:
    def test_empty_instance_id_is_noop(self) -> None:
        screen = _make_screen()
        screen._rows = [_row("web-1")]
        _set_app(screen, _make_app())
        # Must not raise; returns immediately.
        screen._update_row_for_instance("")

    def test_empty_rows_is_noop(self) -> None:
        screen = _make_screen()
        screen._rows = []
        _set_app(screen, _make_app())
        screen._update_row_for_instance("web-1")

    def test_unknown_id_is_noop(self) -> None:
        """When no row has raw_id == instance_id, nothing is updated."""
        screen = _make_screen()
        screen._rows = [_row("web-1")]
        mock_app = _make_app()
        _set_app(screen, mock_app)
        mock_table = MagicMock()
        with patch.object(screen, "query_one", return_value=mock_table):
            screen._update_row_for_instance("unknown-id")
        mock_table.update_cell_at.assert_not_called()


# ---------------------------------------------------------------------------
# _update_row_for_instance — cell update on STALE → FRESH flip
# ---------------------------------------------------------------------------


class TestUpdateRowForInstanceCellUpdate:
    def test_stale_becomes_fresh_updates_cells(self) -> None:
        """When a probe makes an instance fresh the status/modules/age cells update."""
        from textual.coordinate import Coordinate

        fresh_mods = _fresh_modules(age_seconds=30)
        ms = _make_memory_service(module_map={"i-abc123": fresh_mods})
        mock_app = _make_app(memory_service=ms)

        screen = _make_screen()
        screen._rows = [_row("i-abc123", raw_provider="aws", status=STATUS_STALE)]
        _set_app(screen, mock_app)

        mock_table = MagicMock()
        mock_status_widget = MagicMock()

        def _query_one(selector, *args):
            if "table" in selector:
                return mock_table
            return mock_status_widget

        with patch.object(screen, "query_one", side_effect=_query_one):
            screen._update_row_for_instance("i-abc123")

        # Column 4 = status
        update_calls = mock_table.update_cell_at.call_args_list
        coords = [c[0][0] for c in update_calls]
        values = [c[0][1] for c in update_calls]

        col_indices = [coord.column for coord in coords]
        assert 4 in col_indices, "Status cell (col 4) must be updated"
        # Find what was set for col 4
        status_value = values[col_indices.index(4)]
        assert status_value == _STATUS_CELL[STATUS_FRESH]

    def test_row_dict_status_updated_in_place(self) -> None:
        """After _update_row_for_instance the _rows entry must reflect new status."""
        fresh_mods = _fresh_modules(age_seconds=30)
        ms = _make_memory_service(module_map={"i-abc123": fresh_mods})
        mock_app = _make_app(memory_service=ms)

        screen = _make_screen()
        screen._rows = [_row("i-abc123", status=STATUS_STALE)]
        _set_app(screen, mock_app)

        mock_widget = MagicMock()
        with patch.object(screen, "query_one", return_value=mock_widget):
            screen._update_row_for_instance("i-abc123")

        assert screen._rows[0]["status"] == STATUS_FRESH

    def test_modules_count_updated(self) -> None:
        """Module count cell reflects the number of modules returned by the service."""
        from textual.coordinate import Coordinate

        fresh_mods = _fresh_modules(age_seconds=30)
        # Add a second module so count = 2.
        fresh_ts = next(iter(fresh_mods.values()))["probed_at"]
        fresh_mods_2 = {"os": {"probed_at": fresh_ts}, "disk": {"probed_at": fresh_ts}}
        ms = _make_memory_service(module_map={"i-xyz": fresh_mods_2})
        mock_app = _make_app(memory_service=ms)

        screen = _make_screen()
        screen._rows = [_row("i-xyz", status=STATUS_STALE, modules=0)]
        _set_app(screen, mock_app)

        mock_widget = MagicMock()
        with patch.object(screen, "query_one", return_value=mock_widget):
            screen._update_row_for_instance("i-xyz")

        # Col 5 = modules
        update_calls = mock_widget.update_cell_at.call_args_list
        coords = [c[0][0] for c in update_calls]
        values = [c[0][1] for c in update_calls]
        col_indices = [coord.column for coord in coords]
        assert 5 in col_indices
        modules_value = values[col_indices.index(5)]
        assert modules_value == "2"

    def test_age_cell_updated(self) -> None:
        """Age cell (col 7) must be updated after a successful probe."""
        from textual.coordinate import Coordinate

        fresh_mods = _fresh_modules(age_seconds=90)  # 1m 30s ago
        ms = _make_memory_service(module_map={"i-xyz": fresh_mods})
        mock_app = _make_app(memory_service=ms)

        screen = _make_screen()
        screen._rows = [_row("i-xyz", status=STATUS_STALE, age="—")]
        _set_app(screen, mock_app)

        mock_widget = MagicMock()
        with patch.object(screen, "query_one", return_value=mock_widget):
            screen._update_row_for_instance("i-xyz")

        update_calls = mock_widget.update_cell_at.call_args_list
        coords = [c[0][0] for c in update_calls]
        values = [c[0][1] for c in update_calls]
        col_indices = [coord.column for coord in coords]
        assert 7 in col_indices
        age_value = values[col_indices.index(7)]
        # Age text should not be the placeholder "—" any more.
        assert age_value != "—"

    def test_widget_missing_does_not_raise(self) -> None:
        """If query_one raises (screen navigated away), _update_row_for_instance is silent."""
        fresh_mods = _fresh_modules()
        ms = _make_memory_service(module_map={"i-abc": fresh_mods})
        mock_app = _make_app(memory_service=ms)

        screen = _make_screen()
        screen._rows = [_row("i-abc", status=STATUS_STALE)]
        _set_app(screen, mock_app)

        with patch.object(screen, "query_one", side_effect=Exception("no widget")):
            # Must not raise.
            screen._update_row_for_instance("i-abc")


# ---------------------------------------------------------------------------
# _update_row_for_instance — summary line recomputed live
# ---------------------------------------------------------------------------


class TestUpdateRowSummaryRecomputed:
    def test_summary_updates_after_flip(self) -> None:
        """The #fleet-memory-status widget must be updated after a row flips."""
        fresh_mods = _fresh_modules(age_seconds=30)
        ms = _make_memory_service(module_map={"web-1": fresh_mods})
        mock_app = _make_app(memory_service=ms)

        screen = _make_screen()
        screen._rows = [
            _row("web-1", status=STATUS_STALE),
            _row("web-2", status=STATUS_STALE),
        ]
        _set_app(screen, mock_app)

        mock_table = MagicMock()
        mock_status = MagicMock()

        def _query_one(selector, *args):
            if "table" in selector:
                return mock_table
            return mock_status

        with patch.object(screen, "query_one", side_effect=_query_one):
            screen._update_row_for_instance("web-1")

        # The status Static must have been updated.
        mock_status.update.assert_called()
        summary_arg = mock_status.update.call_args[0][0]
        # After web-1 flips to fresh: 1 fresh, 1 stale.
        assert "1 fresh" in summary_arg
        assert "1 stale" in summary_arg


# ---------------------------------------------------------------------------
# _update_row_for_instance — raw_id / raw_provider used for memory lookup
# ---------------------------------------------------------------------------


class TestUpdateRowRawIdLookup:
    def test_memory_service_called_with_raw_id_not_display_id(self) -> None:
        """When demo-mode redacts the display id, memory lookup still uses raw_id."""
        fresh_mods = _fresh_modules(age_seconds=30)
        # Memory is keyed by raw_id "i-realid"
        ms = _make_memory_service(module_map={"i-realid": fresh_mods})
        mock_app = _make_app(memory_service=ms)

        screen = _make_screen()
        # Simulate a demo-redacted row: display id differs from raw_id.
        row = _row("i-realid", raw_provider="aws", status=STATUS_STALE)
        row["id"] = "i-REDACTED"  # what the display shows
        screen._rows = [row]
        _set_app(screen, mock_app)

        mock_widget = MagicMock()
        with patch.object(screen, "query_one", return_value=mock_widget):
            # Progress event always carries the real instance_id.
            screen._update_row_for_instance("i-realid")

        # Memory service must have been called with the raw (un-redacted) id.
        ms.get_all_modules.assert_called_with("i-realid", "aws")
        # Row should have been updated to fresh.
        assert screen._rows[0]["status"] == STATUS_FRESH


# ---------------------------------------------------------------------------
# _update_row_for_instance — opted-out instance stays opted-out
# ---------------------------------------------------------------------------


class TestUpdateRowOptedOut:
    def test_opted_out_status_not_overridden(self) -> None:
        """An opted-out instance must not flip to fresh even if modules appear."""
        fresh_mods = _fresh_modules(age_seconds=30)
        ms = _make_memory_service(
            module_map={"web-1": fresh_mods},
            disabled_ids=["web-1"],
        )
        mock_app = _make_app(memory_service=ms)

        screen = _make_screen()
        screen._rows = [_row("web-1", status=STATUS_OPT_OUT)]
        _set_app(screen, mock_app)

        mock_widget = MagicMock()
        with patch.object(screen, "query_one", return_value=mock_widget):
            screen._update_row_for_instance("web-1")

        assert screen._rows[0]["status"] == STATUS_OPT_OUT
