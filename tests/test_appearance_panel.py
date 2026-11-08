"""Settings › Appearance: theme cards, applying, making and reloading theme files."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import pytest
from textual import events
from textual.pilot import Pilot
from textual.widgets import Button, Input, Static

from servonaut.app import ServonautApp
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.screens.settings.panels.appearance import (
    AppearancePanel,
    EditFileButton,
    ThemeCard,
    ThemeErrorCard,
)
from servonaut.screens.settings.shell import SettingsScreen
from servonaut.screens.theme_name_prompt import ThemeNamePromptScreen
from servonaut.styles.user_themes import check_theme_file, themes_dir
from tests._async_bounds import wait_until

OCEAN = 'primary = "#5EB1FF"\naccent = "#7DD3FC"\nbackground = "#0B1622"\nsurface = "#10233A"\n'
PALE = (
    'primary = "#C0C0C0"\nforeground = "#B0B0B0"\nbackground = "#FFFFFF"\n'
    'surface = "#F4F4F4"\ndark = false\n'
)


@pytest.fixture
def folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("TEXTUAL_THEME", raising=False)
    path = themes_dir()
    path.mkdir(parents=True)
    return path


@pytest.fixture
def manager(tmp_path: Path, folder: Path) -> ConfigManager:
    config = ConfigManager(config_path=tmp_path / "config.json")
    config.save(AppConfig())
    config.load()
    return config


class _Host(ServonautApp):
    def __init__(self, manager: ConfigManager, panel_id: str = "appearance") -> None:
        super().__init__()
        self.config_manager = manager
        self.workspace_state.navigation_visible = False
        self.theme = manager.get().theme
        self.panel_id = panel_id

    def on_mount(self, event: events.Mount) -> None:
        event.prevent_default()
        self.push_screen(SettingsScreen(self.panel_id))

    async def on_unmount(self, event: events.Unmount) -> None:
        event.prevent_default()


async def _ready(app: _Host, pilot: Pilot) -> AppearancePanel:
    await pilot.pause()
    await wait_until(lambda: isinstance(app.screen, SettingsScreen))
    await wait_until(lambda: app.screen._current_panel() is not None)
    panel = app.screen._current_panel()
    assert isinstance(panel, AppearancePanel)
    await wait_until(lambda: panel._loaded and not panel._settling)
    await wait_until(lambda: bool(panel.query(ThemeCard)))
    await pilot.pause()
    return panel


def _card(panel: AppearancePanel, name: str) -> ThemeCard:
    return next(card for card in panel.query(ThemeCard) if card.theme_name == name)


def _text(widget: Static) -> str:
    return str(widget.render())


def _card_text(card: ThemeCard) -> str:
    return " ".join(_text(part) for part in card.query(Static))


def _active(panel: AppearancePanel) -> list[str]:
    return [card.theme_name for card in panel.query(ThemeCard) if card.has_class("-active")]


async def _until(predicate: Callable[[], bool]) -> None:
    await wait_until(predicate)


@pytest.mark.asyncio
async def test_cards_show_built_in_and_user_themes_with_the_active_marker(
    manager: ConfigManager, folder: Path,
) -> None:
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        names = [card.theme_name for card in panel.query(ThemeCard)]
        assert names[:3] == ["servonaut", "servonaut-light", "ocean"]
        assert "nord" in names
        assert _active(panel) == ["servonaut"]
        assert "✓ active" in _card_text(_card(panel, "servonaut"))
        ocean = _card_text(_card(panel, "ocean"))
        assert "yours" in ocean and "~/.servonaut/themes/ocean.toml" in ocean
        assert str(folder.parent.parent) not in ocean  # the home directory is never shown


@pytest.mark.asyncio
async def test_a_file_that_did_not_load_shows_file_line_and_message_literally(
    manager: ConfigManager, folder: Path,
) -> None:
    (folder / "[bold]odd.toml").write_text(
        'name = "odd"\nprimary = "#5EB1FF"\naccent = "#ff88"\n', encoding="utf-8",
    )
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        await _until(lambda: bool(panel.query(ThemeErrorCard)))
        (error_card,) = panel.query(ThemeErrorCard)
        text = " ".join(_text(part) for part in error_card.query(Static))
        assert "[bold]odd.toml" in text and "not loaded" in text
        assert "Line 3" in text and "not a colour" in text and "#ff88" in text
        assert error_card.query(EditFileButton)


@pytest.mark.asyncio
async def test_choosing_a_card_applies_and_saves_the_theme(manager: ConfigManager, folder: Path) -> None:
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        await pilot.click(_card(panel, "ocean"))
        await _until(lambda: app.theme == "ocean")
        await _until(lambda: _active(panel) == ["ocean"])
        assert manager.get().theme == "ocean"
        assert app.ansi_theme_dark is app.user_themes["ocean"].ansi


@pytest.mark.asyncio
async def test_a_card_is_reachable_and_chosen_from_the_keyboard(manager: ConfigManager) -> None:
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        target = _card(panel, "servonaut-light")
        assert target in app.screen.focus_chain
        target.focus()
        await pilot.press("enter")
        await _until(lambda: app.theme == "servonaut-light")
        assert manager.get().theme == "servonaut-light"


@pytest.mark.asyncio
async def test_a_theme_picked_elsewhere_moves_the_active_marker(manager: ConfigManager) -> None:
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        app.theme = "nord"
        await _until(lambda: _active(panel) == ["nord"])


@pytest.mark.asyncio
async def test_general_no_longer_has_a_theme_picker(manager: ConfigManager) -> None:
    app = _Host(manager, "general")
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        await wait_until(lambda: isinstance(app.screen, SettingsScreen))
        assert not list(app.screen.query("#general_theme"))


@pytest.mark.asyncio
async def test_readability_shows_marks_for_the_previewed_theme(manager: ConfigManager, folder: Path) -> None:
    (folder / "pale.toml").write_text(PALE, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        readability = panel.query_one("#appearance_readability", Static)
        assert _text(readability).count("✓") == 5 and "⚠" not in _text(readability)
        _card(panel, "pale").focus()
        await _until(lambda: "⚠" in _text(readability))
        assert "Readability · Pale" in _text(panel.query_one("#appearance_readability_title", Static))
        assert "4.5:1" in _card_text(_card(panel, "pale"))
        assert app.theme == "servonaut", "focus previews; it does not apply"


@pytest.mark.asyncio
async def test_a_terminal_colour_theme_explains_why_it_has_no_preview(manager: ConfigManager) -> None:
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        _card(panel, "ansi-dark").focus()
        await _until(lambda: "terminal's own colours" in _text(panel.query_one("#appearance_preview", Static)))


# ---------------------------------------------------------------------- new from current


async def _open_prompt(app: _Host, pilot: Pilot) -> ThemeNamePromptScreen:
    await pilot.click("#appearance_new")
    await _until(lambda: isinstance(app.screen, ThemeNamePromptScreen))
    return app.screen  # type: ignore[return-value]


async def _enter_name(pilot: Pilot, prompt: ThemeNamePromptScreen, name: str) -> None:
    field = prompt.query_one("#theme_name_input", Input)
    field.value = name
    await pilot.pause()
    await pilot.click("#theme_name_save")


@pytest.mark.asyncio
async def test_new_theme_from_current_writes_a_valid_file_and_lists_it(
    manager: ConfigManager, folder: Path,
) -> None:
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        prompt = await _open_prompt(app, pilot)
        assert prompt.query_one("#theme_name_input", Input).value == "servonaut-copy"
        await _enter_name(pilot, prompt, "mine")
        await _until(lambda: (folder / "mine.toml").exists())
        text = (folder / "mine.toml").read_text(encoding="utf-8")
        assert "docs/themes.md" in text and 'name = "mine"' in text
        assert check_theme_file(folder / "mine.toml") == []
        await _until(lambda: any(card.theme_name == "mine" for card in panel.query(ThemeCard)))
        assert "mine" in app.available_themes
        assert app.theme == "servonaut", "making a theme does not switch to it"
        assert [p.name for p in folder.iterdir()] == ["mine.toml"]


@pytest.mark.asyncio
async def test_new_theme_refuses_to_overwrite_without_a_second_confirmation(
    manager: ConfigManager, folder: Path,
) -> None:
    (folder / "mine.toml").write_text(OCEAN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        prompt = await _open_prompt(app, pilot)
        await _enter_name(pilot, prompt, "mine")
        await _until(lambda: "already exists" in _text(prompt.query_one("#theme_name_error", Static)))
        assert isinstance(app.screen, ThemeNamePromptScreen)
        assert (folder / "mine.toml").read_text(encoding="utf-8") == OCEAN
        assert str(prompt.query_one("#theme_name_save", Button).label) == "Replace"

        # A button ignores clicks while its press animation is still showing.
        await _until(lambda: not prompt.query_one("#theme_name_save", Button).has_class("-active"))
        await pilot.click("#theme_name_save")
        await _until(lambda: not isinstance(app.screen, ThemeNamePromptScreen))
        await _until(lambda: (folder / "mine.toml").read_text(encoding="utf-8") != OCEAN)


@pytest.mark.asyncio
async def test_editing_the_name_cancels_a_pending_replace(manager: ConfigManager, folder: Path) -> None:
    (folder / "mine.toml").write_text(OCEAN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        prompt = await _open_prompt(app, pilot)
        await _enter_name(pilot, prompt, "mine")
        await _until(lambda: str(prompt.query_one("#theme_name_save", Button).label) == "Replace")
        prompt.query_one("#theme_name_input", Input).value = "mine2"
        await _until(lambda: str(prompt.query_one("#theme_name_save", Button).label) == "Create")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "message"),
    [("Bad Name", "lowercase"), ("../escape", "lowercase"), ("nord", "already exists"), ("", "Enter a name")],
)
async def test_new_theme_validates_the_name(
    manager: ConfigManager, folder: Path, name: str, message: str,
) -> None:
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        prompt = await _open_prompt(app, pilot)
        await _enter_name(pilot, prompt, name)
        await _until(lambda: message in _text(prompt.query_one("#theme_name_error", Static)))
        assert isinstance(app.screen, ThemeNamePromptScreen)
        assert list(folder.iterdir()) == []


@pytest.mark.asyncio
async def test_new_theme_can_be_cancelled(manager: ConfigManager, folder: Path) -> None:
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        await _open_prompt(app, pilot)
        await pilot.press("escape")
        await _until(lambda: isinstance(app.screen, SettingsScreen))
        assert list(folder.iterdir()) == []


@pytest.mark.asyncio
async def test_new_theme_key_opens_the_prompt(manager: ConfigManager) -> None:
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        _card(panel, "servonaut").focus()
        await pilot.press("n")
        await _until(lambda: isinstance(app.screen, ThemeNamePromptScreen))


@pytest.mark.asyncio
async def test_a_terminal_colour_theme_cannot_be_copied(manager: ConfigManager, folder: Path) -> None:
    manager.update(theme="ansi-dark")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        prompt = await _open_prompt(app, pilot)
        await _enter_name(pilot, prompt, "mine")
        await _until(lambda: isinstance(app.screen, SettingsScreen))
        assert list(folder.iterdir()) == []


# ---------------------------------------------------------------------- folder and reload


@pytest.mark.asyncio
async def test_open_themes_folder_creates_it_and_opens_it(
    manager: ConfigManager, folder: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[str] = []
    monkeypatch.setattr(
        "servonaut.screens.settings.panels.appearance.webbrowser.open", lambda url: opened.append(url) or True,
    )
    folder.rmdir()
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        await pilot.click("#appearance_open")
        await _until(lambda: bool(opened))
        assert folder.is_dir() and opened == [folder.as_uri()]


@pytest.mark.asyncio
async def test_open_folder_falls_back_to_telling_the_path(
    manager: ConfigManager, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("servonaut.screens.settings.panels.appearance.webbrowser.open", lambda url: False)
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        await pilot.click("#appearance_open")
        await _until(lambda: any("Open it yourself" in n.message for n in app._notifications))


@pytest.mark.asyncio
async def test_reload_picks_up_new_files_and_fixed_ones(manager: ConfigManager, folder: Path) -> None:
    (folder / "ocean.toml").write_text('primary = "nope"\n', encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        await _until(lambda: bool(panel.query(ThemeErrorCard)))
        (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
        (folder / "river.toml").write_text(OCEAN, encoding="utf-8")
        await pilot.click("#appearance_reload")
        await _until(lambda: not panel.query(ThemeErrorCard) and any(c.theme_name == "ocean" for c in panel.query(ThemeCard)))
        assert any(card.theme_name == "river" for card in panel.query(ThemeCard))


@pytest.mark.asyncio
async def test_reload_when_the_active_themes_file_vanishes_falls_back(
    manager: ConfigManager, folder: Path,
) -> None:
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        await pilot.click(_card(panel, "ocean"))
        await _until(lambda: _active(panel) == ["ocean"])
        (folder / "ocean.toml").unlink()
        await pilot.click("#appearance_reload")
        await _until(lambda: app.theme == "servonaut")
        await _until(lambda: _active(panel) == ["servonaut"] and not any(c.theme_name == "ocean" for c in panel.query(ThemeCard)))


@pytest.mark.asyncio
async def test_edit_file_opens_the_theme_file(
    manager: ConfigManager, folder: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[str] = []
    monkeypatch.setattr(
        "servonaut.screens.settings.panels.appearance.webbrowser.open", lambda url: opened.append(url) or True,
    )
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        button = _card(panel, "ocean").query_one(EditFileButton)
        await pilot.click(button)
        await _until(lambda: bool(opened))
        assert opened == [(folder / "ocean.toml").as_uri()]
        assert app.theme == "servonaut", "pressing Edit file does not also apply the theme"


@pytest.mark.asyncio
async def test_a_broken_theme_file_never_stops_the_settings_screen(manager: ConfigManager, folder: Path) -> None:
    (folder / "broken.toml").write_text("primary = [[[", encoding="utf-8")
    (folder / "binary.toml").write_bytes(b"\xff\xfe\x00")
    app = _Host(manager)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        await _until(lambda: len(panel.query(ThemeErrorCard)) == 2)
        assert app._exception is None
