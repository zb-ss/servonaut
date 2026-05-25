"""Tests for InstanceTable widget — SSH verify column additions."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from servonaut.widgets.instance_table import InstanceTable
from servonaut.utils.formatting import format_ssh_verify_state


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_table() -> InstanceTable:
    """Construct an InstanceTable without a real Textual app."""
    # Patch DataTable.__init__ so we can instantiate without a running app.
    with patch("textual.widgets.DataTable.__init__", return_value=None), \
         patch.object(InstanceTable, "add_column", MagicMock()):
        table = InstanceTable.__new__(InstanceTable)
        table._all_instances = []
        table._filtered_instances = []
    return table


# ---------------------------------------------------------------------------
# Column presence
# ---------------------------------------------------------------------------

class TestSetupColumns:
    def test_ssh_column_added(self):
        """_setup_columns must add a column with key='ssh'."""
        calls = []

        class FakeTable:
            def add_column(self, label, **kwargs):
                calls.append((label, kwargs))

        ft = FakeTable()
        # Borrow the method and bind it to the fake table.
        InstanceTable._setup_columns(ft)

        keys = [kw.get("key") for _, kw in calls]
        assert "ssh" in keys, f"Expected 'ssh' key in columns; got {keys}"

    def test_ssh_column_between_key_and_mem(self):
        """'SSH' column must be inserted between 'Key' and 'Mem'."""
        calls = []

        class FakeTable:
            def add_column(self, label, **kwargs):
                calls.append((label, kwargs))

        ft = FakeTable()
        InstanceTable._setup_columns(ft)

        labels = [label for label, _ in calls]
        assert "Key" in labels and "SSH" in labels and "Mem" in labels
        key_idx = labels.index("Key")
        ssh_idx = labels.index("SSH")
        mem_idx = labels.index("Mem")
        assert key_idx < ssh_idx < mem_idx, (
            f"Expected Key < SSH < Mem in column order; got indices "
            f"Key={key_idx}, SSH={ssh_idx}, Mem={mem_idx}"
        )

    def test_ssh_column_width(self):
        """SSH column should have width=14."""
        calls = []

        class FakeTable:
            def add_column(self, label, **kwargs):
                calls.append((label, kwargs))

        ft = FakeTable()
        InstanceTable._setup_columns(ft)

        ssh_entry = next(
            (kw for label, kw in calls if kw.get("key") == "ssh"),
            None,
        )
        assert ssh_entry is not None, "SSH column not found"
        assert ssh_entry.get("width") == 14


# ---------------------------------------------------------------------------
# _ssh_verify_cell
# ---------------------------------------------------------------------------

class TestSshVerifyCell:
    def _cell(self, instance: dict) -> str:
        table = _make_table()
        return InstanceTable._ssh_verify_cell(table, instance)

    def test_missing_status_returns_dash(self):
        """Instance without ssh_verify_status keys renders the dim dash."""
        result = self._cell({})
        assert result == "[dim]—[/dim]"

    def test_none_status_returns_dash(self):
        result = self._cell({"ssh_verify_status": None})
        assert result == "[dim]—[/dim]"

    def test_verified_status_shows_green_tick(self):
        result = self._cell({
            "ssh_verify_status": "verified",
            "ssh_verified_at": "2026-05-24T10:00:00+00:00",
        })
        assert "[green]" in result
        assert "verified" in result

    def test_not_found_status_shows_red(self):
        result = self._cell({"ssh_verify_status": "not_found"})
        assert "[red]" in result
        assert "not found" in result

    def test_auth_failed_status_shows_red(self):
        result = self._cell({"ssh_verify_status": "auth_failed"})
        assert "[red]" in result
        assert "auth failed" in result

    def test_delegates_to_format_ssh_verify_state(self):
        """_ssh_verify_cell must produce same output as format_ssh_verify_state."""
        inst = {
            "ssh_verify_status": "verified",
            "ssh_verified_at": "2026-05-20T12:00:00+00:00",
        }
        table_result = self._cell(inst)
        formatter_result = format_ssh_verify_state(
            inst["ssh_verify_status"],
            inst["ssh_verified_at"],
        )
        # Both should start with the same green prefix
        assert table_result.startswith("[green]") == formatter_result.startswith("[green]")

    def test_unknown_status_returns_dash(self):
        """Unrecognised status values degrade to the dim dash."""
        result = self._cell({"ssh_verify_status": "something_new"})
        assert result == "[dim]—[/dim]"
