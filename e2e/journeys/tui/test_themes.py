"""Journeys: colour themes.

The app opens in the Servonaut theme. A config saved by a release whose Theme
setting offered only Dark and Light opens in the matching Servonaut theme,
and opening the app does not rewrite it. A theme chosen in Settings → General
is applied at once and again after a restart. A theme chosen with Ctrl+P →
Theme is saved too, and the open Settings picker follows it, so saving
another General field afterwards keeps it.
"""

from __future__ import annotations

import pytest
from textual.command import CommandList
from textual.widgets import Select

from e2e.harness import fleet

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


@pytest.fixture(autouse=True)
def _no_theme_override(monkeypatch: pytest.MonkeyPatch) -> None:
    # TEXTUAL_THEME picks a theme for one run and would hide the saved one.
    monkeypatch.delenv("TEXTUAL_THEME", raising=False)


async def _open_general(t) -> Select:
    await t.nav("nav_settings")
    await t.wait_for_screen("SettingsScreen")
    select = t.on_screen("#general_theme", Select)
    await t.wait_until(lambda: t.is_reachable(select), desc="General panel shown")
    return select


async def _choose_from_palette(t, query: str, wanted: str) -> None:
    """Pick the highlighted palette entry once it starts with *wanted*."""
    await t.type(query)
    command_list = t.on_screen(CommandList)

    def highlighted() -> bool:
        index = command_list.highlighted
        if index is None:
            return False
        prompt = command_list.get_option_at_index(index).prompt
        return getattr(prompt, "plain", str(prompt)).startswith(wanted)

    await t.wait_until(highlighted, desc=f"palette entry {wanted!r}")
    await t.press("enter")


@pytest.mark.parametrize(
    ("saved", "shown"),
    [("servonaut", "servonaut"), ("dark", "servonaut"), ("light", "servonaut-light")],
)
async def test_app_opens_in_the_saved_theme(tui, seed, saved, shown):
    seed.config(theme=saved)
    seed.cache(fleet.cache_rows(), fresh=True)

    async with tui() as t:
        assert t.app.theme == shown

    assert seed.read_config()["theme"] == saved


async def test_theme_chosen_in_settings_applies_and_survives_a_restart(tui, seed):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)

    async with tui() as t:
        select = await _open_general(t)
        assert select.value == "servonaut"
        for _ in range(12):
            if select.has_focus:
                break
            await t.press("tab")
        assert select.has_focus, t.focused_id()
        await t.press("enter")
        await t.wait_until(lambda: select.expanded, desc="theme list open")
        await t.press("down", "enter")
        await t.wait_until(lambda: select.value == "servonaut-light", desc="Servonaut Light chosen")
        assert t.app.theme == "servonaut"  # nothing changes before Save
        await t.click("#save_general")
        await t.wait_for_toast(r"^Saved$")
        await t.wait_until(lambda: t.app.theme == "servonaut-light", desc="theme applied")

    assert seed.read_config()["theme"] == "servonaut-light"

    async with tui() as t:
        assert t.app.theme == "servonaut-light"


async def test_theme_chosen_in_the_palette_is_saved_and_kept_by_settings(tui, seed):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)

    async with tui() as t:
        select = await _open_general(t)
        await t.press("ctrl+p")
        await t.wait_for_screen("CommandPalette")
        await _choose_from_palette(t, "Theme", "Theme")
        await t.wait_until(
            lambda: t.screen_name() == "CommandPalette"
            and "theme" in t.app.screen.query_one("Input").placeholder.lower(),
            desc="theme search open",
        )
        await _choose_from_palette(t, "nord", "nord")
        await t.wait_until(lambda: t.app.theme == "nord", desc="nord applied")
        await t.wait_until(lambda: seed.read_config()["theme"] == "nord", desc="nord saved")
        await t.wait_until(lambda: select.value == "nord", desc="Settings picker follows")

        await t.fill("#general_username", "deploy")
        await t.click("#save_general")
        await t.wait_for_toast(r"^Saved$")
        assert t.app.theme == "nord"

    saved = seed.read_config()
    assert saved["default_username"] == "deploy"
    assert saved["theme"] == "nord"
