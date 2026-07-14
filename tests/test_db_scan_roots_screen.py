"""Tests for the DB scan-roots editor and its wiring into the scan screen.

Covers: adding roots (typed + browsed), absolute-path validation, removal,
persistence to config on save, and that the scan screen passes saved roots to
db_scan_stage as a space-separated search_path.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
from textual.app import App
from textual.widgets import Input, OptionList

from servonaut.config.schema import AppConfig
from servonaut.screens.db_scan_roots import DbScanRootsScreen
from servonaut.screens.db_credential_scan import DbCredentialScanScreen


_INSTANCE = {"id": "custom-ovh-web", "name": "ovh-web", "is_custom": True,
             "username": "ubuntu"}


class _RootsApp(App):
    def __init__(self, *, config: AppConfig, initial=None, **kwargs):
        super().__init__(**kwargs)
        self._config = config
        self._initial = initial or []
        self.connection_service = MagicMock()
        self.ssh_service = MagicMock()
        self.config_manager = MagicMock()
        self.config_manager.get.return_value = config
        self.config_manager.save = MagicMock()

    def on_mount(self) -> None:
        self.push_screen(DbScanRootsScreen(_INSTANCE, roots=self._initial))


# ---------------------------------------------------------------------------
# Config field
# ---------------------------------------------------------------------------


def test_config_has_db_scan_roots_default_empty():
    cfg = AppConfig()
    assert cfg.db_scan_roots == {}


# ---------------------------------------------------------------------------
# Editor behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_typed_absolute_path():
    app = _RootsApp(config=AppConfig())
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        scr = app.screen
        scr.query_one("#db_roots_input", Input).value = "/opt/app3"
        scr.action_add_typed()
        await pilot.pause()
        assert scr._roots == ["/opt/app3"]
        assert scr.query_one("#db_roots_list", OptionList).option_count == 1


@pytest.mark.asyncio
async def test_relative_path_rejected():
    app = _RootsApp(config=AppConfig())
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        scr = app.screen
        scr.query_one("#db_roots_input", Input).value = "relative/path"
        scr.action_add_typed()
        await pilot.pause()
        assert scr._roots == []


@pytest.mark.asyncio
async def test_duplicate_not_added():
    app = _RootsApp(config=AppConfig(), initial=["/opt/app3"])
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        scr = app.screen
        scr.query_one("#db_roots_input", Input).value = "/opt/app3"
        scr.action_add_typed()
        await pilot.pause()
        assert scr._roots == ["/opt/app3"]


@pytest.mark.asyncio
async def test_add_browsed_requires_directory():
    app = _RootsApp(config=AppConfig())
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        scr = app.screen
        tree = scr.query_one("#db_roots_tree")
        # cursor_node is a read-only Tree property — patch it at class level.
        with patch.object(type(tree), "cursor_node", new_callable=PropertyMock) as cn:
            # A highlighted FILE node must be refused.
            cn.return_value = MagicMock(data={"path": "/x/f.txt", "type": "file"})
            scr.action_add_browsed()
            assert scr._roots == []
            # A directory node is accepted.
            cn.return_value = MagicMock(data={"path": "/opt/app3", "type": "directory"})
            scr.action_add_browsed()
            assert scr._roots == ["/opt/app3"]


@pytest.mark.asyncio
async def test_remove_selected():
    app = _RootsApp(config=AppConfig(), initial=["/a", "/b"])
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        scr = app.screen
        scr.query_one("#db_roots_list", OptionList).highlighted = 0
        scr.action_remove_selected()
        await pilot.pause()
        assert scr._roots == ["/b"]


@pytest.mark.asyncio
async def test_save_persists_to_config():
    config = AppConfig()
    app = _RootsApp(config=config, initial=["/opt/app3", "/srv/app4"])
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        scr = app.screen
        scr.action_save()
        await pilot.pause()
    assert config.db_scan_roots["custom-ovh-web"] == ["/opt/app3", "/srv/app4"]
    app.config_manager.save.assert_called_once()


@pytest.mark.asyncio
async def test_save_empty_drops_key():
    config = AppConfig(db_scan_roots={"custom-ovh-web": ["/old"]})
    app = _RootsApp(config=config, initial=[])
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        scr = app.screen
        scr.action_save()
        await pilot.pause()
    # Emptying the list removes the override → fall back to built-in defaults.
    assert "custom-ovh-web" not in config.db_scan_roots


# ---------------------------------------------------------------------------
# Scan screen passes custom roots into the scan
# ---------------------------------------------------------------------------


class _ScanApp(App):
    def __init__(self, *, config: AppConfig, tools, **kwargs):
        super().__init__(**kwargs)
        self.demo_mode = False
        self.redaction_service = None
        self.servonaut_tools = tools
        self.config_manager = MagicMock()
        self.config_manager.get.return_value = config

    def on_mount(self) -> None:
        self.push_screen(DbCredentialScanScreen(_INSTANCE))


def _empty_tools():
    tools = MagicMock()
    tools.db_scan_stage = AsyncMock(return_value={"error": None, "candidates": []})
    return tools


@pytest.mark.asyncio
async def test_scan_passes_custom_roots_as_search_path():
    config = AppConfig(db_scan_roots={"custom-ovh-web": ["/opt/app3", "/srv/app4"]})
    tools = _empty_tools()
    app = _ScanApp(config=config, tools=tools)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.pause(0.05)
    tools.db_scan_stage.assert_awaited_once()
    _, kwargs = tools.db_scan_stage.call_args
    assert kwargs.get("search_path") == "/opt/app3 /srv/app4"


@pytest.mark.asyncio
async def test_scan_no_roots_passes_empty_search_path():
    tools = _empty_tools()
    app = _ScanApp(config=AppConfig(), tools=tools)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.pause(0.05)
    _, kwargs = tools.db_scan_stage.call_args
    assert kwargs.get("search_path") == ""
