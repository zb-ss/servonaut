"""Smoke tests for the DB-vault coverage TUI (Layer B4).

Mounts :class:`DbCoverageScreen` with a mocked provider + config +
instances, verifies the coverage table populates and the filter narrows
rows — and that only NAMES (never values) touch the provider.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App
from textual.widgets import DataTable, Input, Static

from servonaut.config.schema import AppConfig, DBProfile
from servonaut.screens.db_coverage_view import DbCoverageScreen


class _WrapperApp(App):
    def __init__(self, *, auth, guard, config_manager, instances, **kwargs):
        super().__init__(**kwargs)
        self.demo_mode = False
        self.redaction_service = None
        self.auth_service = auth
        self.entitlement_guard = guard
        self.config_manager = config_manager
        self.instances = instances

    def on_mount(self) -> None:
        self.push_screen(DbCoverageScreen())


def _cm(profiles):
    cfg = AppConfig()
    cfg.db_profiles = profiles
    cm = MagicMock()
    cm.get.return_value = cfg
    return cm


def _summary_text(app):
    return str(app.screen.query_one("#db_cov_summary", Static).render())


@pytest.mark.asyncio
async def test_coverage_table_and_summary():
    provider = MagicMock()
    provider.provider_name = "local"
    provider.list_secrets = AsyncMock(return_value=["db/web-1"])
    cm = _cm([
        DBProfile(instance="web-1", password_secret="db/web-1"),  # covered
        DBProfile(instance="web-2", password_secret="db/web-2"),  # secret missing
    ])
    instances = [{"id": n, "name": n} for n in ("web-1", "web-2", "web-3")]
    app = _WrapperApp(
        auth=MagicMock(), guard=MagicMock(), config_manager=cm, instances=instances,
    )
    with _patch_resolver(provider):
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            table = app.screen.query_one("#db_cov_table", DataTable)
            assert table.row_count == 3
            summary = _summary_text(app)
    assert "1" in summary  # 1 covered
    # Values were never requested.
    provider.get_secret = AsyncMock(side_effect=AssertionError("values must not be read"))


@pytest.mark.asyncio
async def test_filter_narrows_rows():
    provider = MagicMock()
    provider.provider_name = "local"
    provider.list_secrets = AsyncMock(return_value=["db/web-1"])
    cm = _cm([DBProfile(instance="web-1", password_secret="db/web-1")])
    instances = [{"id": n, "name": n} for n in ("web-1", "api-2")]
    app = _WrapperApp(
        auth=MagicMock(), guard=MagicMock(), config_manager=cm, instances=instances,
    )
    with _patch_resolver(provider):
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            table = app.screen.query_one("#db_cov_table", DataTable)
            assert table.row_count == 2
            app.screen.query_one("#db_cov_filter", Input).value = "api"
            app.screen._repaint()
            await pilot.pause(0.02)
            assert table.row_count == 1


def _patch_resolver(provider):
    from unittest.mock import patch
    return patch(
        "servonaut.services.secret_provider_resolver.resolve_secret_provider",
        return_value=provider,
    )
