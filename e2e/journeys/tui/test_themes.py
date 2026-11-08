"""Journeys: colour themes.

The app opens in the Servonaut theme. A config saved by a release whose Theme
setting offered only Dark and Light opens in the matching Servonaut theme,
and opening the app does not rewrite it. A theme chosen in Settings → Appearance
is applied at once and again after a restart. A theme chosen with Ctrl+P →
Theme is saved too, and the open Settings cards follow it, so saving another
General field afterwards keeps it. A theme file in the themes folder shows
up as a card, applies, and survives a restart; a broken file is listed with
its problem and never stops the app.
"""

from __future__ import annotations

import pytest
from textual.command import CommandList

from e2e.harness import fleet
from servonaut.screens.settings.panels.appearance import ThemeCard, ThemeErrorCard

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]


@pytest.fixture(autouse=True)
def _no_theme_override(monkeypatch: pytest.MonkeyPatch) -> None:
    # TEXTUAL_THEME picks a theme for one run and would hide the saved one.
    monkeypatch.delenv("TEXTUAL_THEME", raising=False)


async def _open_appearance(t) -> None:
    await t.nav("nav_settings")
    await t.wait_for_screen("SettingsScreen")
    await t.click("#navbtn_appearance")
    card = t.on_screen("#theme_card_servonaut-light", ThemeCard)
    await t.wait_until(lambda: t.is_reachable(card), desc="Appearance cards shown")


def _active_cards(t) -> list[str]:
    return [card.theme_name for card in t.screen.query(ThemeCard) if card.has_class("-active")]


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
        await _open_appearance(t)
        assert _active_cards(t) == ["servonaut"]
        card = t.on_screen("#theme_card_servonaut-light", ThemeCard)
        assert card in t.screen.focus_chain, "Theme cards must remain keyboard reachable"
        await t.click(card)
        await t.wait_until(lambda: t.app.theme == "servonaut-light", desc="theme applied")
        await t.wait_until(lambda: seed.read_config()["theme"] == "servonaut-light", desc="theme saved")
        assert _active_cards(t) == ["servonaut-light"]

    async with tui() as t:
        assert t.app.theme == "servonaut-light"


async def test_theme_chosen_in_the_palette_is_saved_and_kept_by_settings(tui, seed):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)

    async with tui() as t:
        await _open_appearance(t)
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
        await t.wait_until(lambda: _active_cards(t) == ["nord"], desc="Appearance cards follow")

        await t.click("#navbtn_general")
        await t.fill("#general_username", "deploy")
        await t.click("#save_general")
        await t.wait_for_toast(r"^Saved$")
        assert t.app.theme == "nord"

    saved = seed.read_config()
    assert saved["default_username"] == "deploy"
    assert saved["theme"] == "nord"


OCEAN = 'primary = "#5EB1FF"\naccent = "#7DD3FC"\nbackground = "#0B1622"\nsurface = "#10233A"\n'


async def test_a_theme_file_shows_applies_and_survives_a_restart(tui, seed):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)
    folder = seed.home / ".servonaut" / "themes"
    folder.mkdir(parents=True)
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    (folder / "broken.toml").write_text('primary = "nope"\n', encoding="utf-8")

    async with tui() as t:
        await _open_appearance(t)
        card = t.on_screen("#theme_card_ocean", ThemeCard)
        assert len(t.screen.query(ThemeErrorCard)) == 1
        await t.click(card)
        await t.wait_until(lambda: t.app.theme == "ocean", desc="user theme applied")
        await t.wait_until(lambda: seed.read_config()["theme"] == "ocean", desc="user theme saved")

    async with tui() as t:
        assert t.app.theme == "ocean"

    (folder / "ocean.toml").unlink()

    async with tui() as t:
        assert t.app.theme == "servonaut", "a vanished theme file falls back to the default"
    assert seed.read_config()["theme"] == "ocean", "and the saved name is kept for when it returns"


async def test_new_theme_from_current_creates_a_file_that_loads(tui, seed):
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)

    async with tui() as t:
        await _open_appearance(t)
        await t.click("#appearance_new")
        await t.wait_for_screen("ThemeNamePromptScreen")
        await t.fill("#theme_name_input", "mine")
        await t.click("#theme_name_save")
        await t.wait_until(lambda: (seed.home / ".servonaut" / "themes" / "mine.toml").exists(), desc="theme file written")
        card = t.on_screen("#theme_card_mine", ThemeCard)
        await t.click(card)
        await t.wait_until(lambda: t.app.theme == "mine", desc="the new theme applied")
