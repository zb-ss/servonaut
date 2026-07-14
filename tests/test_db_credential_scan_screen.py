"""Smoke tests for the DB-credential scan→store TUI screen (Layer B2).

Mounts :class:`DbCredentialScanScreen` on a host app whose
``servonaut_tools`` is mocked. Verifies the scan populates the review
list from ``db_scan_stage`` (masked previews only — no plaintext) and
that "Store in vault" drives ``db_setup_save`` with the selected token.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App
from textual.widgets import OptionList, Static

from servonaut.screens.db_credential_scan import DbCredentialScanScreen

_SECRET_PW = "s3cr3t-passw0rd-xyz"


class _WrapperApp(App):
    def __init__(self, *, tools, config=None, **kwargs):
        super().__init__(**kwargs)
        self.demo_mode = False
        self.redaction_service = None
        self.servonaut_tools = tools
        if config is not None:
            self.config_manager = MagicMock()
            self.config_manager.get.return_value = config

    def on_mount(self) -> None:
        self.push_screen(DbCredentialScanScreen({"id": "i-1", "name": "web"}))


def _rendered(app: App) -> str:
    out = []
    for s in app.screen.query(Static):
        try:
            r = s.render()
            if r is not None:
                out.append(str(r))
        except Exception:  # noqa: BLE001
            continue
    return "\n".join(out)


def _tools_with_candidates():
    tools = MagicMock()
    tools.db_scan_stage = AsyncMock(return_value={
        "error": None,
        "instance": "web",
        "candidates": [{
            "token": "dbstg_abc123",
            "engine": "mysql",
            "user": "app",
            "host": "127.0.0.1",
            "port": 3306,
            "database": "appdb",
            "password_preview": "****xyz",
            "source": "/var/www/app/.env",
        }],
    })
    tools.db_setup_save = AsyncMock(
        return_value="Saved db_profile for web: mysql app@127.0.0.1:3306/appdb"
    )
    return tools


@pytest.mark.asyncio
async def test_scan_populates_list_without_plaintext():
    tools = _tools_with_candidates()
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.pause(0.05)
        option_list = app.screen.query_one("#db_scan_candidates", OptionList)
        assert option_list.option_count == 1
        option_text = str(option_list.get_option_at_index(0).prompt)
        text = _rendered(app)
    assert "Found 1 candidate" in text
    # Masked preview is shown in the review row; plaintext never is.
    assert "****xyz" in option_text
    assert _SECRET_PW not in option_text
    assert _SECRET_PW not in text
    tools.db_scan_stage.assert_awaited_once()


@pytest.mark.asyncio
async def test_store_calls_db_setup_save_with_token():
    from servonaut.screens.db_credential_scan import _DbLabelPromptModal
    tools = _tools_with_candidates()
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.pause(0.05)
        # Simulate the operator selecting the sole candidate.
        app.screen._selected_token = "dbstg_abc123"
        await pilot.click("#db_scan_store")
        await pilot.pause(0.05)
        # Store now prompts for a label first; confirm the derived default.
        assert isinstance(app.screen, _DbLabelPromptModal)
        await pilot.click("#btn_db_label_store")
        await pilot.pause(0.05)
        text = _rendered(app)
    tools.db_setup_save.assert_awaited_once()
    assert tools.db_setup_save.call_args.args[0] == "dbstg_abc123"
    assert tools.db_setup_save.call_args.kwargs["instance_id"] == "i-1"
    # Bare web-root source (/var/www/app/.env) → no derivable label → "".
    assert tools.db_setup_save.call_args.kwargs["label"] == ""
    assert "resolve it by site name" in text


@pytest.mark.asyncio
async def test_store_label_override_passed_to_save():
    from servonaut.screens.db_credential_scan import _DbLabelPromptModal
    from textual.widgets import Input
    tools = _tools_with_candidates()
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.pause(0.05)
        app.screen._selected_token = "dbstg_abc123"
        await pilot.click("#db_scan_store")
        await pilot.pause(0.05)
        assert isinstance(app.screen, _DbLabelPromptModal)
        # Operator types a custom label (e.g. to separate prod vs staging).
        app.screen.query_one("#db_label_input", Input).value = "storefront-prod"
        await pilot.click("#btn_db_label_store")
        await pilot.pause(0.05)
    tools.db_setup_save.assert_awaited_once()
    assert tools.db_setup_save.call_args.kwargs["label"] == "storefront-prod"


@pytest.mark.asyncio
async def test_store_cancel_label_modal_skips_save():
    from servonaut.screens.db_credential_scan import _DbLabelPromptModal
    tools = _tools_with_candidates()
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.pause(0.05)
        app.screen._selected_token = "dbstg_abc123"
        await pilot.click("#db_scan_store")
        await pilot.pause(0.05)
        assert isinstance(app.screen, _DbLabelPromptModal)
        await pilot.click("#btn_db_label_cancel")
        await pilot.pause(0.05)
    tools.db_setup_save.assert_not_awaited()


def _tools_with_two_labeled_candidates():
    tools = MagicMock()
    tools.db_scan_stage = AsyncMock(return_value={
        "error": None,
        "instance": "web",
        "candidates": [
            {
                "token": "dbstg_shop",
                "engine": "mysql",
                "user": "app",
                "host": "127.0.0.1",
                "port": 3306,
                "database": "shopdb",
                "label": "shop",
                "password_preview": "****abc",
                "source": "/var/www/shop/.env",
            },
            {
                "token": "dbstg_blog",
                "engine": "mysql",
                "user": "app",
                "host": "127.0.0.1",
                "port": 3306,
                "database": "blogdb",
                "label": "blog",
                "password_preview": "****def",
                "source": "/var/www/blog/.env",
            },
        ],
    })
    return tools


@pytest.mark.asyncio
async def test_already_vaulted_candidate_carries_stored_badge():
    """A candidate whose label matches a config DBProfile is flagged."""
    from servonaut.config.schema import AppConfig, DBProfile

    config = AppConfig(db_profiles=[DBProfile(instance="i-1", label="shop")])
    tools = _tools_with_two_labeled_candidates()
    app = _WrapperApp(tools=tools, config=config)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.pause(0.05)
        option_list = app.screen.query_one("#db_scan_candidates", OptionList)
        assert option_list.option_count == 2
        rows = {
            str(option_list.get_option_at_index(i).id): str(
                option_list.get_option_at_index(i).prompt
            )
            for i in range(option_list.option_count)
        }
        text = _rendered(app)
    # The vaulted site (shop) carries the badge; the fresh one (blog) does not.
    assert "✓ stored" in rows["dbstg_shop"]
    assert "✓ stored" not in rows["dbstg_blog"]
    assert "1 already vaulted" in text


@pytest.mark.asyncio
async def test_scan_error_surfaces():
    tools = MagicMock()
    tools.db_scan_stage = AsyncMock(return_value={
        "error": "ssh_error: connection refused", "candidates": [],
    })
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause()
        await pilot.pause(0.05)
        text = _rendered(app)
    assert "connection refused" in text
