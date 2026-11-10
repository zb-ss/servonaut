"""Header and form geometry of the Vault and SSH Keys screens, with the real stylesheet."""
from __future__ import annotations

import pytest
from textual.widgets import Button

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
        default = screen.query_one("#default_key_section").styles.border_top
        overrides = screen.query_one("#instance_key_section").styles.border_top
        assert default == overrides


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
