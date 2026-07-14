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
    def __init__(self, *, auth, guard, config_manager, instances, tools=None,
                 **kwargs):
        super().__init__(**kwargs)
        self.demo_mode = False
        self.redaction_service = None
        self.auth_service = auth
        self.entitlement_guard = guard
        self.config_manager = config_manager
        self.instances = instances
        self.servonaut_tools = tools

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
            # New per-site "Site" column is present.
            assert [str(c.label) for c in table.columns.values()] == [
                "Server", "Site", "Profile", "Secret", "In store", "Status",
            ]
            summary = _summary_text(app)
    assert "1" in summary  # 1 covered
    # Values were never requested.
    provider.get_secret = AsyncMock(side_effect=AssertionError("values must not be read"))


@pytest.mark.asyncio
async def test_multi_site_instance_yields_row_per_label():
    provider = MagicMock()
    provider.provider_name = "local"
    provider.list_secrets = AsyncMock(return_value=["db/shop", "db/blog"])
    cm = _cm([
        DBProfile(instance="web-1", label="shop.example.com", password_secret="db/shop"),
        DBProfile(instance="web-1", label="blog.example.com", password_secret="db/blog"),
    ])
    instances = [{"id": "web-1", "name": "web-1"}]
    app = _WrapperApp(
        auth=MagicMock(), guard=MagicMock(), config_manager=cm, instances=instances,
    )
    with _patch_resolver(provider):
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            table = app.screen.query_one("#db_cov_table", DataTable)
            # One instance, two labelled sites → two distinct rows.
            assert table.row_count == 2
            labels = {r.label for r in app.screen._rows}
            assert labels == {"shop.example.com", "blog.example.com"}


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


# ---------------------------------------------------------------------------
# Remove a stored credential (d)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_remove_covered_row_pushes_confirm_modal():
    from servonaut.screens.db_coverage_view import ConfirmDbRemoveModal
    provider = MagicMock()
    provider.provider_name = "local"
    provider.list_secrets = AsyncMock(return_value=["db/shop"])
    cm = _cm([DBProfile(
        instance="web-1", label="shop.example.com", password_secret="db/shop")])
    app = _WrapperApp(
        auth=MagicMock(), guard=MagicMock(), config_manager=cm,
        instances=[{"id": "web-1", "name": "web-1"}], tools=MagicMock(),
    )
    with _patch_resolver(provider):
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            app.screen.action_remove()
            await pilot.pause()
            # The confirm modal is now the active screen.
            assert isinstance(app.screen, ConfirmDbRemoveModal)


@pytest.mark.asyncio
async def test_remove_gap_row_shows_no_modal():
    provider = MagicMock()
    provider.provider_name = "local"
    provider.list_secrets = AsyncMock(return_value=[])
    cm = _cm([])  # no profiles → the single instance is a gap row
    app = _WrapperApp(
        auth=MagicMock(), guard=MagicMock(), config_manager=cm,
        instances=[{"id": "web-1", "name": "web-1"}], tools=MagicMock(),
    )
    with _patch_resolver(provider):
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            app.screen.action_remove()
            await pilot.pause()
            # Nothing to remove on a gap row → no modal pushed.
            assert isinstance(app.screen, DbCoverageScreen)


@pytest.mark.asyncio
async def test_do_remove_calls_tool_with_label_and_delete_flag():
    provider = MagicMock()
    provider.provider_name = "local"
    provider.list_secrets = AsyncMock(return_value=["db/shop"])
    tools = MagicMock()
    tools.db_setup_remove = AsyncMock(
        return_value="Removed db_profile for web-1 [shop.example.com].")
    cm = _cm([DBProfile(
        instance="web-1", label="shop.example.com", password_secret="db/shop")])
    app = _WrapperApp(
        auth=MagicMock(), guard=MagicMock(), config_manager=cm,
        instances=[{"id": "web-1", "name": "web-1"}], tools=tools,
    )
    with _patch_resolver(provider):
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            await app.screen._do_remove("web-1", "shop.example.com", True)
    tools.db_setup_remove.assert_awaited_once_with(
        "web-1", app="shop.example.com", delete_secret=True)


@pytest.mark.asyncio
async def test_remove_unlabelled_row_round_trips_empty_app_to_tool():
    # Full path: select an unlabelled (empty-label) covered row → confirm →
    # the empty label must round-trip through the composite key into app="".
    from servonaut.screens.db_coverage_view import ConfirmDbRemoveModal
    provider = MagicMock()
    provider.provider_name = "local"
    provider.list_secrets = AsyncMock(return_value=["db/web-1"])
    tools = MagicMock()
    tools.db_setup_remove = AsyncMock(return_value="Removed db_profile for web-1.")
    cm = _cm([DBProfile(instance="web-1", label="", password_secret="db/web-1")])
    app = _WrapperApp(
        auth=MagicMock(), guard=MagicMock(), config_manager=cm,
        instances=[{"id": "web-1", "name": "web-1"}], tools=tools,
    )
    with _patch_resolver(provider):
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            app.screen.action_remove()
            await pilot.pause()
            assert isinstance(app.screen, ConfirmDbRemoveModal)
            await pilot.click("#btn_db_remove_confirm")
            await pilot.pause(0.05)
    tools.db_setup_remove.assert_awaited_once()
    assert tools.db_setup_remove.call_args.kwargs["app"] == ""
    assert tools.db_setup_remove.call_args.kwargs["delete_secret"] is True
