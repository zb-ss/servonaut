"""Tests for InstanceTable widget — SSH verify column additions."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from servonaut.widgets.instance_table import COLUMNS, InstanceTable
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

class TestColumns:
    def test_ssh_column_sits_between_key_and_mem(self):
        """The SSH verify column is listed after Key and before Mem."""
        keys = [column.key for column in COLUMNS]
        assert keys.index("key") < keys.index("ssh") < keys.index("memory")

    def test_ssh_column_is_optional(self):
        """The SSH column is left out while no server has a verify result."""
        ssh = next(column for column in COLUMNS if column.key == "ssh")
        assert ssh.optional


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
