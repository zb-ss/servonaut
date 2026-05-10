"""Tests for the Hetzner setup wizard's dropdown-population logic.

We don't drive the full Textual screen lifecycle here — that path is
exercised by hand under tpmcp. What we DO test is the pure logic that
shapes API responses into ``Select`` option lists, since a buggy
``_refresh_select`` could quietly drop the user's saved value off the
list and surprise them on save.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from servonaut.screens.hetzner_setup import HetznerSetupScreen


pytestmark = pytest.mark.asyncio


def _make_screen_with_app() -> HetznerSetupScreen:
    """Construct a screen instance bypassing the Textual mount cycle."""
    return HetznerSetupScreen()


async def _harness(screen: HetznerSetupScreen):
    """Mount the screen via ``Pilot.run_test`` so query_one works.

    The screen's ``on_mount`` reads ``self.app.config_manager`` to seed
    its form, so the harness has to expose a stub manager returning a
    default :class:`HetznerConfig`. We use the real :class:`AppConfig`
    so the dataclass shape stays in lockstep with production.
    """
    from textual.app import App, ComposeResult

    from servonaut.config.schema import AppConfig, HetznerConfig

    fake_config = AppConfig(hetzner=HetznerConfig())
    fake_manager = MagicMock()
    fake_manager.get.return_value = fake_config

    class _Harness(App):
        def __init__(self) -> None:
            super().__init__()
            self.config_manager = fake_manager  # noqa: ANN001

        def compose(self) -> ComposeResult:
            yield screen

    return _Harness()


class TestSeedSelect:
    async def test_seed_with_value_pre_selects_it(self) -> None:
        from textual.widgets import Select

        screen = HetznerSetupScreen()
        app = await _harness(screen)
        async with app.run_test() as pilot:
            screen._seed_select("#hetzner_select_image", "ubuntu-22.04")
            await pilot.pause()
            sel = screen.query_one("#hetzner_select_image", Select)
            assert sel.value == "ubuntu-22.04"
            # _select_value reads back the same string.
            assert screen._select_value("#hetzner_select_image") == "ubuntu-22.04"

    async def test_seed_with_empty_value_collapses_to_blank(self) -> None:
        from textual.widgets import Select

        screen = HetznerSetupScreen()
        app = await _harness(screen)
        async with app.run_test() as pilot:
            screen._seed_select("#hetzner_select_image", "")
            await pilot.pause()
            sel = screen.query_one("#hetzner_select_image", Select)
            assert sel.value is Select.NULL
            assert screen._select_value("#hetzner_select_image") == ""


class TestRefreshSelect:
    async def test_preserves_current_value_when_present_in_new_list(self) -> None:
        from textual.widgets import Select

        screen = HetznerSetupScreen()
        app = await _harness(screen)
        async with app.run_test() as pilot:
            screen._seed_select("#hetzner_select_server_type", "cx22")
            await pilot.pause()
            screen._refresh_select(
                "#hetzner_select_server_type",
                [("cx22 — cheap", "cx22"), ("cx32 — bigger", "cx32")],
            )
            await pilot.pause()
            sel = screen.query_one("#hetzner_select_server_type", Select)
            assert sel.value == "cx22"

    async def test_keeps_saved_value_as_special_option_when_missing(
        self,
    ) -> None:
        """User has ``cx99`` saved (deprecated/unknown). New API list
        doesn't include it. The refresh must keep ``cx99`` selectable
        with a ``(saved)`` suffix so the user notices it's stale but
        doesn't lose it on save."""
        from textual.widgets import Select

        screen = HetznerSetupScreen()
        app = await _harness(screen)
        async with app.run_test() as pilot:
            screen._seed_select("#hetzner_select_server_type", "cx99")
            await pilot.pause()
            screen._refresh_select(
                "#hetzner_select_server_type",
                [("cx22", "cx22"), ("cx32", "cx32")],
            )
            await pilot.pause()
            sel = screen.query_one("#hetzner_select_server_type", Select)
            # Saved value is preserved as the selected option.
            assert sel.value == "cx99"
            # And it's labelled so the user can spot it.
            labels = [label for label, _ in sel._options]  # type: ignore[attr-defined]
            assert any("cx99 (saved)" in str(l) for l in labels)

    async def test_falls_back_to_first_option_when_no_saved(self) -> None:
        from textual.widgets import Select

        screen = HetznerSetupScreen()
        app = await _harness(screen)
        async with app.run_test() as pilot:
            screen._seed_select("#hetzner_select_server_type", "")
            await pilot.pause()
            screen._refresh_select(
                "#hetzner_select_server_type",
                [("cx22", "cx22"), ("cx32", "cx32")],
            )
            await pilot.pause()
            sel = screen.query_one("#hetzner_select_server_type", Select)
            assert sel.value == "cx22"

    async def test_empty_options_collapse_to_blank(self) -> None:
        from textual.widgets import Select

        screen = HetznerSetupScreen()
        app = await _harness(screen)
        async with app.run_test() as pilot:
            screen._seed_select("#hetzner_select_server_type", "")
            await pilot.pause()
            screen._refresh_select("#hetzner_select_server_type", [])
            await pilot.pause()
            sel = screen.query_one("#hetzner_select_server_type", Select)
            assert sel.value is Select.NULL
