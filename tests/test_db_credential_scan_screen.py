"""Pilot tests for the DB-credential scan→store TUI screen.

Mounts :class:`DbCredentialScanScreen` on a host app whose
``servonaut_tools`` is mocked. Verifies the scan populates the review
list from ``db_scan_stage`` (masked previews only — no plaintext), that the
highlighted row is what "Store" acts on, and that a stored row is marked
straight away.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App
from textual.widgets import Input, OptionList, Static

from servonaut.screens.db_credential_scan import (
    DbCredentialScanScreen,
    _DbLabelPromptModal,
)

_SECRET_PW = "s3cr3t-passw0rd-xyz"
_STORE = "the local secret store (~/.servonaut/secrets.json)"


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


def _rendered(screen) -> str:
    out = []
    for s in screen.query(Static):
        try:
            r = s.render()
            if r is not None:
                out.append(str(r))
        except Exception:  # noqa: BLE001
            continue
    return "\n".join(out)


def _saved(message: str = "Saved db_profile for web") -> AsyncMock:
    return AsyncMock(return_value=message)


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
    tools.db_setup_save = _saved()
    tools.describe_secret_store = MagicMock(return_value=_STORE)
    return tools


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
                "engine": "postgres",
                "user": "app",
                "host": "127.0.0.1",
                "port": 5432,
                "database": "blogdb",
                "label": "blog",
                "password_preview": "****def",
                "source": "/var/www/blog/.env",
            },
        ],
    })
    tools.db_setup_save = _saved()
    tools.describe_secret_store = MagicMock(return_value=_STORE)
    return tools


def _rows(screen) -> dict:
    option_list = screen.query_one("#db_scan_candidates", OptionList)
    return {
        str(option_list.get_option_at_index(i).id):
            str(option_list.get_option_at_index(i).prompt)
        for i in range(option_list.option_count)
    }


async def _settle(pilot) -> None:
    await pilot.pause()
    await pilot.pause(0.05)


@pytest.mark.asyncio
async def test_scan_populates_list_without_plaintext():
    tools = _tools_with_candidates()
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await _settle(pilot)
        option_list = app.screen.query_one("#db_scan_candidates", OptionList)
        assert option_list.option_count == 1
        option_text = str(option_list.get_option_at_index(0).prompt)
        text = _rendered(app.screen)
    assert "Found 1 database. Press Enter to store it." in text
    # Masked preview is shown in the review row; plaintext never is.
    assert "password ****xyz" in option_text
    assert _SECRET_PW not in option_text
    assert _SECRET_PW not in text
    tools.db_scan_stage.assert_awaited_once()


@pytest.mark.asyncio
async def test_copy_is_plain_and_engines_are_named_like_the_cli():
    tools = _tools_with_two_labeled_candidates()
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await _settle(pilot)
        text = _rendered(app.screen)
        rows = _rows(app.screen)
    assert "Finds the database settings of the apps on web" in text
    assert "without changing anything" in text
    assert "Looks in the usual web folders." in text
    assert (
        "Found 2 databases. Pick one and press Enter to store it; "
        "each is saved under its own name." in text
    )
    for jargon in ("db_processlist", "DATABASE_URL", "candidate", "vault", "server-side"):
        assert jargon not in text
    assert rows["dbstg_shop"].startswith("shop  MySQL  ")
    assert rows["dbstg_blog"].startswith("blog  PostgreSQL  ")
    assert rows["dbstg_blog"].endswith("password ****def  from /var/www/blog/.env")


@pytest.mark.asyncio
async def test_scan_highlights_the_first_unstored_row_and_focuses_the_list():
    from servonaut.config.schema import AppConfig, DBProfile

    config = AppConfig(db_profiles=[DBProfile(instance="i-1", label="shop")])
    tools = _tools_with_two_labeled_candidates()
    app = _WrapperApp(tools=tools, config=config)
    async with app.run_test(headless=True) as pilot:
        await _settle(pilot)
        option_list = app.screen.query_one("#db_scan_candidates", OptionList)
        assert option_list.highlighted == 1  # shop is stored, blog is not
        assert app.focused is option_list
        assert app.screen._selected_token == "dbstg_blog"


@pytest.mark.asyncio
async def test_highlighted_row_is_what_the_store_button_stores():
    """Arrow to a row, Tab to Store, Enter: the highlighted row is stored."""
    tools = _tools_with_two_labeled_candidates()
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await _settle(pilot)
        await pilot.press("down")
        await pilot.press("tab")
        assert app.focused is app.screen.query_one("#db_scan_store")
        await pilot.press("enter")
        await pilot.pause(0.05)
        assert isinstance(app.screen, _DbLabelPromptModal)
        assert app.screen.query_one("#db_label_input", Input).value == "blog"
        await pilot.press("enter")
        await _settle(pilot)
        text = _rendered(app.screen)
    tools.db_setup_save.assert_awaited_once()
    assert tools.db_setup_save.call_args.args[0] == "dbstg_blog"
    assert tools.db_setup_save.call_args.kwargs == {"instance_id": "i-1", "label": "blog"}
    assert "Pick a database first" not in text


@pytest.mark.asyncio
async def test_enter_on_a_row_opens_the_store_prompt():
    tools = _tools_with_two_labeled_candidates()
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await _settle(pilot)
        await pilot.press("enter")
        await pilot.pause(0.05)
        assert isinstance(app.screen, _DbLabelPromptModal)
        await pilot.press("enter")
        await _settle(pilot)
    tools.db_setup_save.assert_awaited_once()
    assert tools.db_setup_save.call_args.args[0] == "dbstg_shop"
    assert tools.db_setup_save.call_args.kwargs["label"] == "shop"


@pytest.mark.asyncio
async def test_stored_row_is_marked_right_after_storing():
    tools = _tools_with_two_labeled_candidates()
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await _settle(pilot)
        await pilot.press("enter")
        await pilot.pause(0.05)
        await pilot.press("enter")
        await _settle(pilot)
        screen = app.screen
        rows = _rows(screen)
        text = _rendered(screen)
        highlighted = screen.query_one("#db_scan_candidates", OptionList).highlighted
        notes = [n.message for n in app._notifications]
    assert rows["dbstg_shop"].startswith("✓ stored  shop  MySQL")
    assert "✓ stored" not in rows["dbstg_blog"]
    assert "Stored shop. Agents and the TUI can now use it. 1 more to store." in text
    assert f"Stored shop in {_STORE}." in notes
    # The next database not stored yet is ready for the next Enter.
    assert highlighted == 1
    assert screen._selected_token == "dbstg_blog"


@pytest.mark.asyncio
async def test_storing_under_a_used_name_unmarks_the_replaced_row():
    tools = _tools_with_two_labeled_candidates()
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await _settle(pilot)
        await pilot.press("enter")  # shop, stored as "shop"
        await pilot.pause(0.05)
        await pilot.press("enter")
        await _settle(pilot)
        await pilot.press("enter")  # blog is highlighted now
        await pilot.pause(0.05)
        app.screen.query_one("#db_label_input", Input).value = "Shop"
        await pilot.press("enter")
        await _settle(pilot)
        rows = _rows(app.screen)
        text = _rendered(app.screen)
    # One database per name: blog replaced shop's.
    assert "✓ stored" in rows["dbstg_blog"]
    assert "✓ stored" not in rows["dbstg_shop"]
    assert "Stored Shop. Agents and the TUI can now use it. 1 more to store." in text


@pytest.mark.asyncio
async def test_store_without_label_names_the_connection():
    tools = _tools_with_candidates()
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await _settle(pilot)
        await pilot.click("#db_scan_store")
        await pilot.pause(0.05)
        # Store prompts for a name first; confirm the derived (empty) default.
        assert isinstance(app.screen, _DbLabelPromptModal)
        await pilot.click("#btn_db_label_store")
        await _settle(pilot)
        text = _rendered(app.screen)
        prompt = _rows(app.screen)["dbstg_abc123"]
    tools.db_setup_save.assert_awaited_once()
    assert tools.db_setup_save.call_args.args[0] == "dbstg_abc123"
    assert tools.db_setup_save.call_args.kwargs["instance_id"] == "i-1"
    # Bare web-root source (/var/www/app/.env) → no derivable label → "".
    assert tools.db_setup_save.call_args.kwargs["label"] == ""
    assert "Agents and the TUI can now use it." in text
    assert "more to store" not in text
    assert prompt.startswith("✓ stored  MySQL")


@pytest.mark.asyncio
async def test_store_label_override_passed_to_save():
    tools = _tools_with_candidates()
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await _settle(pilot)
        await pilot.click("#db_scan_store")
        await pilot.pause(0.05)
        assert isinstance(app.screen, _DbLabelPromptModal)
        # Operator types a custom name (e.g. to separate prod vs staging).
        app.screen.query_one("#db_label_input", Input).value = "storefront-prod"
        await pilot.click("#btn_db_label_store")
        await pilot.pause(0.05)
    tools.db_setup_save.assert_awaited_once()
    assert tools.db_setup_save.call_args.kwargs["label"] == "storefront-prod"


@pytest.mark.asyncio
async def test_label_prompt_is_plain():
    tools = _tools_with_candidates()
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await _settle(pilot)
        await pilot.click("#db_scan_store")
        await pilot.pause(0.05)
        text = _rendered(app.screen)
    assert "Name this database" in text
    assert "Leave it blank if this server has only one database." in text
    assert "single/default" not in text


@pytest.mark.asyncio
async def test_store_cancel_label_modal_skips_save():
    tools = _tools_with_candidates()
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await _settle(pilot)
        await pilot.click("#db_scan_store")
        await pilot.pause(0.05)
        assert isinstance(app.screen, _DbLabelPromptModal)
        await pilot.click("#btn_db_label_cancel")
        await pilot.pause(0.05)
        prompt = _rows(app.screen)["dbstg_abc123"]
    tools.db_setup_save.assert_not_awaited()
    assert "✓ stored" not in prompt


@pytest.mark.asyncio
async def test_expired_scan_result_says_to_scan_again():
    tools = _tools_with_candidates()
    tools.db_setup_save = _saved(
        "Error: unknown or expired staging token 'dbstg_abc123'. Run "
        "db_setup_scan again to re-stage."
    )
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await _settle(pilot)
        await pilot.press("enter")
        await pilot.pause(0.05)
        await pilot.press("enter")
        await _settle(pilot)
        text = _rendered(app.screen)
        prompt = _rows(app.screen)["dbstg_abc123"]
    assert "Could not store" in text
    assert "the scan result expired before it was stored. Press s to scan again." in text
    assert "dbstg_abc123" not in text
    assert "✓ stored" not in prompt


@pytest.mark.asyncio
async def test_already_vaulted_candidate_carries_stored_badge():
    """A candidate whose label matches a config DBProfile is flagged."""
    from servonaut.config.schema import AppConfig, DBProfile

    config = AppConfig(db_profiles=[DBProfile(instance="i-1", label="shop")])
    tools = _tools_with_two_labeled_candidates()
    app = _WrapperApp(tools=tools, config=config)
    async with app.run_test(headless=True) as pilot:
        await _settle(pilot)
        rows = _rows(app.screen)
        text = _rendered(app.screen)
    # The vaulted site (shop) carries the badge; the fresh one (blog) does not.
    assert "✓ stored" in rows["dbstg_shop"]
    assert "✓ stored" not in rows["dbstg_blog"]
    assert "Found 2 databases, 1 already stored." in text


@pytest.mark.asyncio
async def test_scan_error_surfaces():
    tools = MagicMock()
    tools.db_scan_stage = AsyncMock(return_value={
        "error": "ssh_error: connection refused", "candidates": [],
    })
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await _settle(pilot)
        text = _rendered(app.screen)
    assert "Could not scan web over SSH: connection refused" in text


@pytest.mark.asyncio
async def test_nothing_found_says_where_to_point_the_scan():
    tools = MagicMock()
    tools.db_scan_stage = AsyncMock(return_value={"error": None, "candidates": []})
    app = _WrapperApp(tools=tools)
    async with app.run_test(headless=True) as pilot:
        await _settle(pilot)
        text = _rendered(app.screen)
    assert "No database settings found on web." in text
    assert "add its folder with p (Scan roots)" in text
