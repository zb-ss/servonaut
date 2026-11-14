"""Settings › Appearance: theme cards, applying, making and reloading theme files."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import pytest
from textual import events
from textual.color import Color
from textual.pilot import Pilot
from textual.widget import Widget
from textual.widgets import Button, Input, Static

from servonaut.app import ServonautApp
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AppConfig
from servonaut.screens.settings.panels.appearance import (
    AppearancePanel,
    EditFileButton,
    SwatchStrip,
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


from tests.conftest import _ChoiceInEveryWidthClass


class _Host(ServonautApp):
    def __init__(self, manager: ConfigManager, panel_id: str = "appearance") -> None:
        super().__init__()
        self.config_manager = manager
        self.workspace_state.navigation_visible = False
        # An explicit choice, held in every width class, as the toggle makes it.
        self.workspace_state.navigation_choice_class = _ChoiceInEveryWidthClass("any")
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
        assert names[:3] == ["servonaut", "ocean", "servonaut-light"]
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
    (folder / "mine.toml").write_text(OCEAN.replace("#5EB1FF", "nope"), encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        prompt = await _open_prompt(app, pilot)
        await _enter_name(pilot, prompt, "mine")
        await _until(lambda: "already exists" in _text(prompt.query_one("#theme_name_error", Static)))
        assert isinstance(app.screen, ThemeNamePromptScreen)
        assert "nope" in (folder / "mine.toml").read_text(encoding="utf-8")
        assert str(prompt.query_one("#theme_name_save", Button).label) == "Replace"

        # A button ignores clicks while its press animation is still showing.
        await _until(lambda: not prompt.query_one("#theme_name_save", Button).has_class("-active"))
        await pilot.click("#theme_name_save")
        await _until(lambda: not isinstance(app.screen, ThemeNamePromptScreen))
        await _until(lambda: "nope" not in (folder / "mine.toml").read_text(encoding="utf-8"))


@pytest.mark.asyncio
async def test_editing_the_name_cancels_a_pending_replace(manager: ConfigManager, folder: Path) -> None:
    (folder / "mine.toml").write_text('primary = "nope"\n', encoding="utf-8")
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
    [("Bad Name", "lowercase"), ("../escape", "lowercase"), ("nord", "already exists"), ("", "Enter a name"),
     ("servonaut-light", "already exists")],
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
    opened: list[Path] = []
    monkeypatch.setattr(
        "servonaut.screens.settings.panels.appearance.open_path", lambda path: opened.append(path) or True,
    )
    folder.rmdir()
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        await pilot.click("#appearance_open")
        await _until(lambda: bool(opened))
        assert folder.is_dir() and opened == [folder]


@pytest.mark.asyncio
async def test_open_folder_falls_back_to_telling_the_path(
    manager: ConfigManager, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("servonaut.screens.settings.panels.appearance.open_path", lambda path: False)
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
        await _until(lambda: any(card.theme_name == "river" for card in panel.query(ThemeCard)))
        await app.workers.wait_for_complete()  # the reload ends before the screen is torn down


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
    opened: list[Path] = []
    monkeypatch.setattr(
        "servonaut.screens.settings.panels.appearance.open_path", lambda path: opened.append(path) or True,
    )
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        button = _card(panel, "ocean").query_one(EditFileButton)
        await pilot.click(button)
        await _until(lambda: bool(opened))
        assert opened == [folder / "ocean.toml"]
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


@pytest.mark.asyncio
async def test_a_file_with_many_faults_gets_one_card_that_lists_a_few(manager: ConfigManager, folder: Path) -> None:
    (folder / "noisy.toml").write_text('primary = "#5EB1FF"\n' + "".join(f"k{i}=1\n" for i in range(400)), encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        await _until(lambda: bool(panel.query(ThemeErrorCard)))
        (card,) = panel.query(ThemeErrorCard)
        text = " ".join(_text(part) for part in card.query(Static))
        assert text.count("Unknown key") <= 3
        assert "more problem" in text


@pytest.mark.asyncio
async def test_reload_reads_the_folder_in_a_worker_and_shows_it_is_busy(
    manager: ConfigManager, folder: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading
    import time

    from servonaut.screens.settings.panels import appearance
    from servonaut.styles.user_themes import load_user_themes as real_load

    main_thread = threading.current_thread()
    seen: list[bool] = []

    def slow_load(*args, **kwargs):
        seen.append(threading.current_thread() is not main_thread)
        time.sleep(0.4)
        return real_load(*args, **kwargs)

    monkeypatch.setattr(appearance, "load_user_themes", slow_load)
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        busy = panel.query_one("#appearance_busy")
        await pilot.click("#appearance_reload")
        await _until(lambda: busy.is_active)
        await _until(lambda: not busy.is_active)
        assert seen == [True]


@pytest.mark.asyncio
async def test_a_name_that_is_registered_is_refused_even_when_a_file_has_that_stem(
    manager: ConfigManager, folder: Path,
) -> None:
    (folder / "nord.toml").write_text('primary = "#5EB1FF"\n', encoding="utf-8")  # clashes, so it is not loaded
    (folder / "mine.toml").write_text(OCEAN, encoding="utf-8")  # loaded as "mine"
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        for name in ("nord", "mine"):
            prompt = await _open_prompt(app, pilot)
            await _enter_name(pilot, prompt, name)
            await _until(lambda: "already exists" in _text(prompt.query_one("#theme_name_error", Static)))
            assert str(prompt.query_one("#theme_name_save", Button).label) == "Create"
            await pilot.press("escape")
            await _until(lambda: isinstance(app.screen, SettingsScreen))


@pytest.mark.asyncio
async def test_new_theme_from_an_unregistered_current_theme_is_handled(
    manager: ConfigManager, folder: Path,
) -> None:
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        app.set_reactive(ServonautApp.theme, "bogus")  # what TEXTUAL_THEME=bogus leaves behind
        prompt = await _open_prompt(app, pilot)
        await _enter_name(pilot, prompt, "mine")
        await _until(lambda: isinstance(app.screen, SettingsScreen))
        await _until(lambda: any("cannot be copied" in n.message for n in app._notifications))
        assert list(folder.iterdir()) == [] and app._exception is None


@pytest.mark.asyncio
async def test_edit_file_is_offered_only_for_a_regular_toml_file_in_the_folder(
    manager: ConfigManager, folder: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[Path] = []
    monkeypatch.setattr(
        "servonaut.screens.settings.panels.appearance.open_path", lambda path: opened.append(path) or True,
    )
    target = folder.parent / "run-me.desktop"
    target.write_text("[Desktop Entry]\nExec=true\n", encoding="utf-8")
    (folder / "handy.toml").symlink_to(target)
    (folder / "plain.toml").write_text('primary = "nope"\n', encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        await _until(lambda: len(panel.query(ThemeErrorCard)) == 2)
        cards = {card._errors[0].file: card for card in panel.query(ThemeErrorCard)}
        assert not cards["handy.toml"].query(EditFileButton)
        assert "link" in " ".join(_text(part) for part in cards["handy.toml"].query(Static)).lower()
        (button,) = cards["plain.toml"].query(EditFileButton)

        # The file is swapped for a link after the card was drawn: pressing refuses.
        (folder / "plain.toml").unlink()
        (folder / "plain.toml").symlink_to(target)
        button.press()
        await _until(lambda: any("regular" in n.message for n in app._notifications))
        assert opened == []


@pytest.mark.asyncio
async def test_arrow_keys_move_between_cards_following_the_grid(manager: ConfigManager) -> None:
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        names = [card.theme_name for card in panel.query(ThemeCard)]
        columns = panel.card_columns
        assert columns >= 2
        _card(panel, names[0]).focus()
        await pilot.pause()

        def focused() -> str:
            return app.focused.theme_name

        await pilot.press("right")
        assert focused() == names[1]
        await pilot.press("down")
        assert focused() == names[1 + columns]
        await pilot.press("up")
        assert focused() == names[1]
        await pilot.press("left")
        assert focused() == names[0]
        await pilot.press("left", "up")
        assert focused() == names[0], "the first card stays put"
        await pilot.press("end")
        assert focused() == names[-1]
        await pilot.press("right", "down")
        assert focused() == names[-1], "the last card stays put"
        await pilot.press("home")
        assert focused() == names[0]


@pytest.mark.asyncio
async def test_a_card_can_be_reached_with_tab_too(manager: ConfigManager) -> None:
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        reached = set()
        for _ in range(len(app.screen.focus_chain) + 1):
            await pilot.press("tab")
            if isinstance(app.focused, ThemeCard):
                reached.add(app.focused.theme_name)
        assert {"servonaut", "servonaut-light"} <= reached


BROKEN = 'primary = "#5EB1FF"\naccent = "#ff88"\n'


def _visible(panel: AppearancePanel, widget: Widget) -> bool:
    """Whether *widget* is laid out inside the scrolling cards area without scrolling."""
    area = panel.query_one("#appearance_layout").region
    return widget.region.height > 0 and area.contains_region(widget.region)


@pytest.mark.asyncio
async def test_cards_are_ordered_active_yours_broken_then_built_in(manager: ConfigManager, folder: Path) -> None:
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    (folder / "broken.toml").write_text(BROKEN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        await _until(lambda: bool(panel.query(ThemeErrorCard)))
        slots = list(panel.query_one("#appearance_cards").children)
        kinds = ["error" if isinstance(slot, ThemeErrorCard) else slot.theme_name for slot in slots]
        assert kinds[:4] == ["servonaut", "ocean", "error", "servonaut-light"]


@pytest.mark.asyncio
async def test_a_broken_file_and_a_warning_card_are_visible_without_scrolling_at_160x50(
    manager: ConfigManager, folder: Path,
) -> None:
    (folder / "pale.toml").write_text(PALE, encoding="utf-8")
    (folder / "broken.toml").write_text(BROKEN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        await _until(lambda: bool(panel.query(ThemeErrorCard)))
        assert _visible(panel, _card(panel, "pale"))
        assert _visible(panel, next(iter(panel.query(ThemeErrorCard))))


@pytest.mark.asyncio
async def test_only_a_theme_with_a_contrast_warning_gets_the_warning_border(
    manager: ConfigManager, folder: Path,
) -> None:
    (folder / "pale.toml").write_text(PALE, encoding="utf-8")
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        pale, ocean = _card(panel, "pale"), _card(panel, "ocean")
        assert pale.has_class("-warning") and not ocean.has_class("-warning")
        assert pale.styles.border_top[0] == "round"
        assert pale.styles.border_top[1].hex == Color.parse(app.get_css_variables()["warning"]).hex
        assert pale.styles.border_top != ocean.styles.border_top


@pytest.mark.asyncio
async def test_a_user_card_is_as_tall_as_a_built_in_card_and_edit_file_shares_the_path_row(
    manager: ConfigManager, folder: Path,
) -> None:
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        ocean, built_in = _card(panel, "ocean"), _card(panel, "servonaut-light")
        assert ocean.region.height == built_in.region.height
        edit = ocean.query_one(EditFileButton)
        path = ocean.query_one(".theme-card-path .theme-card-detail")
        assert edit.region.height == 1 and edit.region.y == path.region.y


@pytest.mark.asyncio
async def test_the_header_is_one_row_when_wide_and_two_rows_of_cards_show_at_100x30(
    manager: ConfigManager, folder: Path,
) -> None:
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        title = panel.query_one("#appearance_heading .panel-title")
        buttons = panel.query_one("#appearance_actions")
        assert buttons.region.y < title.region.y + 3 and buttons.region.x >= title.region.right
        assert not panel.query("#appearance_verdict") and not panel.query("#appearance_folder")
    narrow = _Host(manager)
    async with narrow.run_test(size=(100, 30)) as pilot:
        panel = await _ready(narrow, pilot)
        shown = {card.region.y for card in panel.query(ThemeCard) if _visible(panel, card)}
        assert len(shown) >= 2


@pytest.mark.asyncio
async def test_swatches_span_the_card_width(manager: ConfigManager, folder: Path) -> None:
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        strip = _card(panel, "servonaut").query_one(SwatchStrip)
        assert strip.content_size.width > 24
        assert len(strip.render().plain) == strip.content_size.width


@pytest.mark.asyncio
async def test_the_preview_draws_outlined_buttons_with_the_apps_labels(manager: ConfigManager, folder: Path) -> None:
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        preview = _text(panel.query_one("#appearance_preview", Static))
        for label in ("SSH connect", "Browse files", "Ban IP…", "Terminate…"):
            assert f"│ {label} │" in preview
        assert preview.count("╭") == 4 and preview.count("╰") == 4


@pytest.mark.asyncio
async def test_the_readability_note_explains_what_a_theme_sets(manager: ConfigManager, folder: Path) -> None:
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        note = _text(panel.query_one("#appearance_hint", Static))
        assert "optional extras" in note and "servonaut theme check <file>" in note


@pytest.mark.asyncio
async def test_the_screen_context_names_the_panel(manager: ConfigManager, folder: Path) -> None:
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        await _ready(app, pilot)
        context = app.screen.query_one("#workspace_context", Static)
        assert _text(context) == "Settings › Appearance"


def _rows_fully_visible(panel: AppearancePanel) -> int:
    area = panel.query_one("#appearance_layout").region
    return len({c.region.y for c in panel.query(".theme-card") if c.region.height and area.contains_region(c.region)})


def _title_cells(card: Widget) -> tuple:
    """The card's title text style: the focus cue, which must not depend on the state border."""
    return card.query_one(".theme-card-title").styles.text_style


@pytest.mark.asyncio
async def test_every_kind_of_card_shows_when_it_has_focus(manager: ConfigManager, folder: Path) -> None:
    (folder / "pale.toml").write_text(PALE, encoding="utf-8")
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        kinds = {"built-in": "servonaut-light", "active": "servonaut", "user": "ocean", "warning": "pale"}
        for kind, name in kinds.items():
            card = _card(panel, name)
            blurred = _title_cells(card)
            card.focus()
            await pilot.pause()
            assert _title_cells(card) != blurred, f"a focused {kind} card looks the same"
            assert _title_cells(card).underline, f"a focused {kind} card's title is not underlined"


@pytest.mark.asyncio
async def test_two_rows_of_cards_show_at_100x30_with_user_themes_and_a_broken_file(
    manager: ConfigManager, folder: Path,
) -> None:
    (folder / "pale.toml").write_text(PALE, encoding="utf-8")
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    (folder / "broken.toml").write_text(BROKEN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        await _until(lambda: bool(panel.query(ThemeErrorCard)))
        await pilot.pause()
        assert _rows_fully_visible(panel) >= 2
        assert panel.query_one("#appearance_new", Button).compact, "a stacked header uses one-row buttons"
        assert _card(panel, "ocean").query_one(".theme-card-path .theme-card-detail").region.height == 1


@pytest.mark.asyncio
async def test_a_narrow_card_shows_the_file_name_and_keeps_the_full_path_in_its_tooltip(
    manager: ConfigManager, folder: Path,
) -> None:
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(100, 30)) as pilot:
        panel = await _ready(app, pilot)
        card = _card(panel, "ocean")
        assert "ocean.toml" in _card_text(card) and ".servonaut" not in _card_text(card)
        assert "~/.servonaut/themes/ocean.toml" in str(card.tooltip)


@pytest.mark.asyncio
async def test_default_layout_with_navigation_open_keeps_special_cards_visible_and_user_cards_short(
    manager: ConfigManager, folder: Path,
) -> None:
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    (folder / "pale.toml").write_text(PALE, encoding="utf-8")
    (folder / "broken.toml").write_text(BROKEN, encoding="utf-8")
    app = _Host(manager)
    app.workspace_state.navigation_visible = True
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        await _until(lambda: bool(panel.query(ThemeErrorCard)))
        await pilot.pause()
        assert _visible(panel, _card(panel, "pale"))
        assert _visible(panel, next(iter(panel.query(ThemeErrorCard))))
        assert _card(panel, "ocean").region.height == _card(panel, "servonaut-light").region.height


@pytest.mark.asyncio
async def test_arrow_keys_step_over_the_broken_files_card(manager: ConfigManager, folder: Path) -> None:
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    (folder / "broken.toml").write_text(BROKEN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        await _until(lambda: bool(panel.query(ThemeErrorCard)))
        assert panel.card_columns == 2
        # Slots: servonaut, ocean / error, servonaut-light / atom-one-dark, ...
        _card(panel, "servonaut").focus()
        await pilot.press("down")
        assert app.focused.theme_name == "atom-one-dark", "down from the first column steps over the error card"
        await pilot.press("up")
        assert app.focused.theme_name == "servonaut", "up steps back over it"
        _card(panel, "ocean").focus()
        await pilot.press("right")
        assert app.focused.theme_name == "servonaut-light", "right from the last card of a row steps over it"
        await pilot.press("left")
        assert app.focused.theme_name == "ocean"


@pytest.mark.asyncio
async def test_every_card_with_a_file_shows_its_full_path_when_it_fits(manager: ConfigManager, folder: Path) -> None:
    # Slots: servonaut, ocean / pale, sunset (broken): the broken file sits in the right-hand column.
    (folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    (folder / "pale.toml").write_text(PALE, encoding="utf-8")
    (folder / "sunset.toml").write_text(BROKEN, encoding="utf-8")
    app = _Host(manager)
    async with app.run_test(size=(160, 50)) as pilot:
        panel = await _ready(app, pilot)
        await _until(lambda: bool(panel.query(ThemeErrorCard)))
        error_card = next(iter(panel.query(ThemeErrorCard)))
        await _until(lambda: "~/.servonaut/themes/sunset.toml" in _card_text(error_card))
        assert "~/.servonaut/themes/ocean.toml" in _card_text(_card(panel, "ocean"))
