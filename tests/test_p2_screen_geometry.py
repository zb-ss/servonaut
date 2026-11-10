"""Header and form geometry of the Vault and SSH Keys screens, with the real stylesheet."""
from __future__ import annotations

import pytest
from textual.widgets import Button, DataTable

from tests.test_vault_screen import _StyledVaultHost
from tests.test_vault_workspace_views import _Service
from tests.test_workspace_account_leaf import (
    _AccountHost, _inert_boundaries as _inert_boundaries, _opener, _ready,
)

SIZES = [(160, 50), (100, 30)]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES, ids=["160x50", "100x30"])
async def test_add_mapping_sits_level_with_the_inputs_like_set_default(size) -> None:
    app = _AccountHost()
    async with app.run_test(size=size) as pilot:
        screen = await _opener("keys")(app, pilot)
        await _ready(screen)
        await pilot.pause()
        region = {
            name: screen.query_one(f"#{name}").region
            for name in (
                "input_default_key", "btn_set_default",
                "input_mapping_key", "btn_add_mapping",
            )
        }
        # Wide: the button shares the input row. Narrow: both buttons stack
        # directly under their inputs, with the same left edge and width.
        gaps = []
        for button, field in (("btn_set_default", "input_default_key"),
                              ("btn_add_mapping", "input_mapping_key")):
            if region[button].y == region[field].y:
                continue
            assert region[button].x == region[field].x
            assert region[button].width == region[field].width
            gaps.append(region[button].y - region[field].bottom)
        assert len(set(gaps)) <= 1
        assert (region["btn_set_default"].y == region["input_default_key"].y) == (
            region["btn_add_mapping"].y == region["input_mapping_key"].y
        )
        if size[0] >= 160:
            assert region["btn_add_mapping"].y == region["input_mapping_key"].y


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES, ids=["160x50", "100x30"])
async def test_key_cards_share_one_border_until_one_is_focused(size) -> None:
    app = _AccountHost()
    async with app.run_test(size=size) as pilot:
        screen = await _opener("keys")(app, pilot)
        await _ready(screen)
        screen.set_focus(screen.query_one("#available_keys_table"))
        await pilot.pause()
        default, overrides = list(screen.query("#key_connection_column .key-section"))
        assert default.styles.border_top == overrides.styles.border_top


@pytest.mark.asyncio
@pytest.mark.parametrize("size", SIZES, ids=["160x50", "100x30"])
async def test_vault_title_shares_its_row_with_the_refresh_label(size) -> None:
    app = _StyledVaultHost(_Service(local=True))
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        await pilot.pause()
        screen = app.screen
        title = screen.query_one("#vault_title").region
        state = screen.query_one("#vault_identity_state").region
        refresh = screen.query_one("#vault_refresh", Button).region
        label_row = refresh.y + (refresh.height - 1) // 2
        assert title.y == label_row
        assert state.y == label_row


@pytest.mark.asyncio
async def test_remove_override_works_by_button_and_by_key() -> None:
    app = _AccountHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _opener("keys")(app, pilot)
        await _ready(screen)
        config = app.config_manager.get()
        table = screen.query_one("#instance_keys_table", DataTable)
        assert [str(c.label) for c in table.columns.values()] == ["Instance ID", "Key path"]
        assert config.instance_keys == {"id-web-1": "~/.ssh/web_key"}

        screen.query_one("#btn_remove_mapping").press()
        await pilot.pause()
        assert config.instance_keys == {}

        config.instance_keys["id-web-1"] = "~/.ssh/web_key"
        screen._load_instance_mappings()
        await pilot.pause()
        screen.set_focus(table)
        await pilot.press("delete")
        await pilot.pause()
        assert config.instance_keys == {}
