"""Smoke tests for the fleet DB-credential scan TUI (Layer B3).

Mounts :class:`DbFleetScanScreen` on a host app with mocked
``servonaut_tools`` + ``config_manager`` and drives a scan + commit-all,
asserting the review table populates and bulk commit runs.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App
from textual.widgets import DataTable, Static

from servonaut.config.schema import AppConfig, DBProfile
from servonaut.screens.db_fleet_scan import DbFleetScanScreen


def _candidate(token="dbstg_x"):
    return {
        "token": token, "engine": "mysql", "user": "app", "host": "127.0.0.1",
        "port": 3306, "database": "appdb", "password_preview": "****xyz",
        "source": "/var/www/.env",
    }


class _WrapperApp(App):
    def __init__(self, *, tools, config_manager, instances, **kwargs):
        super().__init__(**kwargs)
        self.demo_mode = False
        self.redaction_service = None
        self.servonaut_tools = tools
        self.config_manager = config_manager
        self._instances = instances

    def on_mount(self) -> None:
        self.push_screen(DbFleetScanScreen(self._instances))


def _cm(vaulted=()):
    cfg = AppConfig()
    cfg.db_profiles = [DBProfile(instance=i, password_secret=f"db/{i}") for i in vaulted]
    cm = MagicMock()
    cm.get.return_value = cfg
    return cm


def _rendered(app):
    out = []
    for s in app.screen.query(Static):
        try:
            r = s.render()
            if r is not None:
                out.append(str(r))
        except Exception:  # noqa: BLE001
            continue
    return "\n".join(out)


@pytest.mark.asyncio
async def test_scan_populates_table_with_vaulted_column():
    tools = MagicMock()
    tools.db_scan_stage = AsyncMock(
        return_value={"error": None, "candidates": [_candidate()]}
    )
    instances = [{"id": "a", "name": "a"}, {"id": "b", "name": "b"}]
    app = _WrapperApp(tools=tools, config_manager=_cm(vaulted=["b"]), instances=instances)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.pause(0.05)
        table = app.screen.query_one("#fleet_db_table", DataTable)
        assert table.row_count == 2
        text = _rendered(app)
    # 'b' was already vaulted → never probed.
    probed = {c.args[0] for c in tools.db_scan_stage.call_args_list}
    assert probed == {"a"}
    assert "already vaulted" in text


@pytest.mark.asyncio
async def test_commit_all_runs_bulk_save():
    tools = MagicMock()
    tools.db_scan_stage = AsyncMock(
        return_value={"error": None, "candidates": [_candidate("t1")]}
    )
    tools.db_setup_save = AsyncMock(return_value="Saved db_profile for a")
    instances = [{"id": "a", "name": "a"}, {"id": "c", "name": "c"}]
    app = _WrapperApp(tools=tools, config_manager=_cm(), instances=instances)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.pause(0.05)
        await pilot.click("#fleet_commit_all")
        await pilot.pause(0.05)
        text = _rendered(app)
    assert tools.db_setup_save.await_count == 2
    assert "Committed 2" in text
