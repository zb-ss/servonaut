"""Appearance settings: pick a colour theme, and make your own from a file.

Every theme shows as a card. Choosing one applies and saves it at once (the
app remembers any theme picked anywhere), so this panel has no Save button.
"""

from __future__ import annotations

import logging
import webbrowser
from pathlib import Path
from typing import Dict, List, Optional

from rich.markup import escape
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.color import Color
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.content import Content
from textual.message import Message
from textual.theme import Theme
from textual.widgets import Button, Static

from servonaut.config.paths import tildify
from servonaut.screens.settings.base import SettingsPanel
from servonaut.screens.theme_name_prompt import ThemeNamePromptScreen
from servonaut.styles.readability import MIN_CONTRAST, Reading, readings_for, token_colour, worst_reading
from servonaut.styles.theme_files import (
    SOURCE_USER,
    ThemeFileError,
    ThemeInfo,
    describe_themes,
    render_theme_file,
    write_theme_file,
)
from servonaut.styles.user_themes import (
    THEME_FILE_SUFFIX,
    ThemeError,
    resolved_colours,
    themes_dir,
)
from servonaut.utils.markup import literal

logger = logging.getLogger(__name__)

# A card needs about this many cells to show a swatch strip and a file path.
CARD_MIN_WIDTH = 34
MAX_CARD_COLUMNS = 3
SWATCH_CELLS = 3
_SWATCH_ROLES = ("background", "surface", "panel", "primary", "accent", "warning", "error", "success")
_ANSI_SWATCHES = ("black", "red", "green", "yellow", "blue", "magenta", "cyan", "white")


def _swatch_fills(theme: Theme) -> List[str]:
    """One fill per swatch: the theme's colours, or the terminal's own for an ANSI theme."""
    if theme.ansi:
        return [f"ansi_{name}" for name in _ANSI_SWATCHES]
    colours = resolved_colours(theme)
    return [colours[role].hex for role in _SWATCH_ROLES]


def swatch_strip(theme: Theme) -> Content:
    """The theme's main colours side by side."""
    return Content.assemble(*[(" " * SWATCH_CELLS, f"on {fill}") for fill in _swatch_fills(theme)])


def _suggest_name(active: str, taken: frozenset[str]) -> str:
    base = active[:30].strip("-") or "theme"
    candidate, number = f"{base}-copy", 2
    while candidate in taken:
        candidate = f"{base}-copy-{number}"
        number += 1
    return candidate


def _readings_content(readings: List[Reading]) -> Content:
    lines: List[Content] = []
    for reading in readings:
        mark, style = ("✓", "$text-success") if reading.is_readable else ("⚠", "$text-warning")
        lines.append(Content.assemble((mark, style), f" {reading.label} {reading.ratio:.1f}:1"))
    return Content("\n").join(lines)


class ThemeCard(Vertical):
    """One selectable theme; Enter or a click applies it, focus previews it."""

    can_focus = True
    BINDINGS = [Binding("enter", "choose", "Apply", show=True)]

    class Chosen(Message):
        def __init__(self, name: str) -> None:
            super().__init__()
            self.name = name

    class Previewed(Message):
        def __init__(self, name: str) -> None:
            super().__init__()
            self.name = name

    def __init__(self, info: ThemeInfo, is_active: bool, warning: Optional[Reading]) -> None:
        super().__init__(classes="theme-card -active" if is_active else "theme-card")
        self.theme_name = info.name
        self._info = info
        self._warning = warning

    def compose(self) -> ComposeResult:
        yield Static(self._title(), classes="theme-card-title")
        yield Static(swatch_strip(self._info.theme), classes="theme-card-swatches")
        yield Static(self._detail(), classes="theme-card-detail")
        if self._info.path is not None:
            yield EditFileButton(self._info.path)

    def set_active(self, is_active: bool) -> None:
        self.set_class(is_active, "-active")
        self.query_one(".theme-card-title", Static).update(self._title())

    def _title(self) -> Content:
        parts: List[object] = [(self._info.label, "bold")]
        if self._info.source == SOURCE_USER:
            parts.append((" · yours", "$text-muted"))
        if self.has_class("-active"):
            parts.append((" ✓ active", "$text-accent"))
        return Content.assemble(*parts)

    def _detail(self) -> Content:
        info = self._info
        if info.source == SOURCE_USER and info.path is not None:
            location = Content(tildify(str(info.path)))
            if self._warning is None:
                return location
            return Content.assemble(location, "\n", (_warning_text(self._warning), "$text-warning"))
        kind = "follows your terminal" if info.theme.ansi else ("dark" if info.theme.dark else "light")
        return Content(f"Built in · {kind}")

    def action_choose(self) -> None:
        self.post_message(self.Chosen(self.theme_name))

    def on_click(self, event: events.Click) -> None:
        if isinstance(event.widget, Button):
            return
        self.focus()
        self.action_choose()

    def on_focus(self) -> None:
        self.post_message(self.Previewed(self.theme_name))


def _warning_text(reading: Reading) -> str:
    return f"⚠ {reading.label} is {reading.ratio:.1f}:1 (needs {MIN_CONTRAST}:1)"


class EditFileButton(Button):
    """Opens the theme file for editing."""

    def __init__(self, path: Path) -> None:
        super().__init__("Edit file", classes="theme-edit-file")
        self.path = path


class ThemeErrorCard(Vertical):
    """A theme file that could not be loaded, and why."""

    def __init__(self, error: ThemeError, path: Path) -> None:
        super().__init__(classes="theme-card -error")
        self._error = error
        self._path = path

    def compose(self) -> ComposeResult:
        yield Static(
            Content.assemble((self._error.file, "bold"), (" · not loaded", "$text-error")),
            classes="theme-card-title",
        )
        where = f"Line {self._error.line}: " if self._error.line else ""
        yield Static(
            Content(f"{where}{self._error.message}. Fix the file, then Reload themes."),
            classes="theme-card-detail",
        )
        if self._path.is_file():
            yield EditFileButton(self._path)


class AppearancePanel(SettingsPanel):
    """Colour themes: built-in, yours, and the files that did not load."""

    PANEL_ID = "appearance"
    TITLE = "Appearance"
    DESCRIPTION = "Applies at once and is saved to your config."

    BINDINGS = [
        Binding("n", "new_theme", "New from current", show=True),
        Binding("o", "open_folder", "Open folder", show=True),
        Binding("ctrl+r", "reload_themes", "Reload", show=True),
    ]

    DEFAULT_CSS = """
    AppearancePanel #appearance_actions {
        height: auto;
        margin-bottom: 1;
    }
    AppearancePanel #appearance_actions Button {
        width: auto;
        min-width: 10;
        margin: 0 1 0 0;
    }
    AppearancePanel #appearance_folder {
        height: auto;
        color: $text-muted;
        margin-bottom: 1;
    }
    AppearancePanel #appearance_cards {
        height: auto;
        grid-size: 1;
        grid-gutter: 1 1;
        grid-rows: auto;
        margin-bottom: 1;
    }
    AppearancePanel #appearance_cards.-cols-2 { grid-size: 2; }
    AppearancePanel #appearance_cards.-cols-3 { grid-size: 3; }
    AppearancePanel .theme-card {
        height: auto;
        padding: 0 1;
        border: round $border-blurred;
        background: transparent;
    }
    AppearancePanel .theme-card:focus {
        border: round $text-accent;
    }
    AppearancePanel .theme-card.-active {
        border: round $accent;
    }
    AppearancePanel .theme-card.-error {
        border: round $error;
    }
    AppearancePanel .theme-card-title {
        height: auto;
    }
    AppearancePanel .theme-card-swatches {
        height: 1;
        margin: 1 0;
    }
    AppearancePanel .theme-card-detail {
        height: auto;
        color: $text-muted;
    }
    AppearancePanel .theme-edit-file {
        width: auto;
        min-width: 10;
        margin: 1 0 0 0;
    }
    AppearancePanel #appearance_details {
        height: auto;
    }
    AppearancePanel .appearance-section {
        height: auto;
        width: 1fr;
        padding: 0 1;
        border: round $border-blurred;
        background: transparent;
        margin-right: 1;
    }
    AppearancePanel .appearance-section-title {
        height: auto;
        color: $text-muted;
        text-style: bold;
    }
    AppearancePanel #appearance_preview {
        height: auto;
        padding: 1;
    }
    AppearancePanel #appearance_readability {
        height: auto;
    }
    AppearancePanel #appearance_hint {
        height: auto;
        color: $text-muted;
        margin-top: 1;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._previewed: str = ""

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        """The title, then the cards and the preview; there is nothing to save."""
        with Vertical(classes="panel-context"):
            yield Static(escape(self.TITLE), classes="panel-title")
            yield Static(self.DESCRIPTION, classes="panel-description", markup=False)
        with VerticalScroll(classes="panel-body"):
            yield from self.form_rows()
        yield Static("", id=f"status_{self.PANEL_ID}", classes="panel-status")

    def form_rows(self) -> ComposeResult:
        with Horizontal(id="appearance_actions"):
            yield Button("New theme from current…", id="appearance_new", variant="primary")
            yield Button("Open themes folder", id="appearance_open")
            yield Button("Reload themes", id="appearance_reload")
        yield Static("", id="appearance_folder", markup=False)
        yield Grid(id="appearance_cards", classes="-cols-1")
        with Horizontal(id="appearance_details"):
            with Vertical(classes="appearance-section"):
                yield Static("", id="appearance_preview_title", classes="appearance-section-title", markup=False)
                yield Static("", id="appearance_preview")
            with Vertical(classes="appearance-section"):
                yield Static("", id="appearance_readability_title", classes="appearance-section-title", markup=False)
                yield Static("", id="appearance_readability")
                yield Static(
                    "Themes set the core colours plus optional extras (borders, cursor, "
                    "terminal palette for command output). Check a file from the shell "
                    "with: servonaut theme check <file>",
                    id="appearance_hint",
                    markup=False,
                )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self.app.theme_changed_signal.subscribe(self, self._follow_app_theme)
        super().on_mount()

    def load(self) -> None:
        self._previewed = self.app.theme
        self.run_worker(self._rebuild_cards(), exclusive=True, group="appearance_cards")
        self._snapshot_now()

    def collect(self) -> Dict[str, object]:
        return {}

    def persist(self) -> None:
        """Nothing to save: choosing a theme applies and saves it."""

    def on_resize(self, event: events.Resize) -> None:
        columns = max(1, min(MAX_CARD_COLUMNS, event.size.width // CARD_MIN_WIDTH))
        grid = self.query_one("#appearance_cards", Grid)
        for count in range(1, MAX_CARD_COLUMNS + 1):
            grid.set_class(count == columns, f"-cols-{count}")

    # ------------------------------------------------------------------
    # Cards
    # ------------------------------------------------------------------

    async def _rebuild_cards(self) -> None:
        app = self.app
        infos = describe_themes(app.available_themes, app.user_themes)
        cards: List[object] = [
            ThemeCard(
                info,
                is_active=info.name == app.theme,
                warning=worst_reading(info.theme) if info.source == SOURCE_USER else None,
            )
            for info in infos
        ]
        folder = themes_dir()
        cards += [ThemeErrorCard(error, folder / error.file) for error in app.user_theme_errors if _is_file_error(error)]
        grid = self.query_one("#appearance_cards", Grid)
        await grid.remove_children()
        await grid.mount_all(cards)
        self._show_folder_note()
        self._show_details(self._previewed or app.theme)

    def _show_folder_note(self) -> None:
        """Where themes live, plus any problem with the folder itself."""
        notes = [f"Your themes live in {tildify(str(themes_dir()))}"]
        notes += [e.message for e in self.app.user_theme_errors if not _is_file_error(e)]
        self.query_one("#appearance_folder", Static).update(Content("\n".join(notes)))

    def _follow_app_theme(self, theme: Theme) -> None:
        """Show a theme picked elsewhere (Ctrl+P) as the active one."""
        self._previewed = theme.name
        for card in self.query(ThemeCard):
            card.set_active(card.theme_name == theme.name)
        self._show_details(theme.name)

    @on(ThemeCard.Chosen)
    def _apply_theme(self, event: ThemeCard.Chosen) -> None:
        event.stop()
        self.app.theme = event.name

    @on(ThemeCard.Previewed)
    def _preview_theme(self, event: ThemeCard.Previewed) -> None:
        event.stop()
        self._previewed = event.name
        self._show_details(event.name)

    # ------------------------------------------------------------------
    # Preview and readability
    # ------------------------------------------------------------------

    def _show_details(self, name: str) -> None:
        theme = self.app.available_themes.get(name)
        if theme is None:
            return
        info = next((i for i in describe_themes({name: theme}, self.app.user_themes)), None)
        label = info.label if info else name
        self.query_one("#appearance_preview_title", Static).update(literal(f"Preview · {label}"))
        self.query_one("#appearance_readability_title", Static).update(literal(f"Readability · {label}"))
        preview = self.query_one("#appearance_preview", Static)
        readability = self.query_one("#appearance_readability", Static)
        if theme.ansi:
            preview.styles.background = None
            preview.update("This theme uses your terminal's own colours, so it has no fixed preview.")
            readability.update("Contrast depends on your terminal's colour scheme.")
            return
        preview.styles.background = resolved_colours(theme)["background"]
        preview.update(_preview_content(theme))
        readability.update(_readings_content(list(readings_for(theme))))

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    @on(Button.Pressed, "#appearance_new")
    def _on_new_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_new_theme()

    @on(Button.Pressed, "#appearance_open")
    def _on_open_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_open_folder()

    @on(Button.Pressed, "#appearance_reload")
    def _on_reload_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_reload_themes()

    @on(Button.Pressed, ".theme-edit-file")
    def _on_edit_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if isinstance(event.button, EditFileButton):
            self._open_path(event.button.path)

    def action_new_theme(self) -> None:
        app = self.app
        taken = frozenset(app.available_themes)
        prompt = ThemeNamePromptScreen(_suggest_name(app.theme, taken), taken, self._existing_theme_files())
        app.push_screen(prompt, self._create_theme_file)

    def _existing_theme_files(self) -> frozenset[str]:
        try:
            return frozenset(p.stem for p in themes_dir().glob(f"*{THEME_FILE_SUFFIX}"))
        except OSError:
            return frozenset()

    def _create_theme_file(self, result: object) -> None:
        if not result:
            return
        name, replace = result  # type: ignore[misc]
        app = self.app
        infos = describe_themes(app.available_themes, app.user_themes)
        active = next(info for info in infos if info.name == app.theme)
        try:
            path = write_theme_file(name, render_theme_file(active, name=name), overwrite=replace)
        except (ThemeFileError, ValueError) as exc:
            app.notify(str(exc), severity="error", markup=False)
            return
        self.action_reload_themes(announce=False)
        app.notify(f"Saved {tildify(str(path))}. Edit it, then Reload themes.", markup=False)

    def action_open_folder(self) -> None:
        folder = themes_dir()
        try:
            folder.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.app.notify(f"Could not create {tildify(str(folder))}: {exc.strerror or exc}", severity="error", markup=False)
            return
        self._open_path(folder)

    def _open_path(self, path: Path) -> None:
        try:
            opened = webbrowser.open(path.as_uri())
        except webbrowser.Error:
            opened = False
        if not opened:
            self.app.notify(f"Open it yourself: {tildify(str(path))}", severity="warning", markup=False)

    def action_reload_themes(self, announce: bool = True) -> None:
        result = self.app.reload_user_themes()
        self.run_worker(self._rebuild_cards(), exclusive=True, group="appearance_cards")
        if announce:
            problems = len(result.errors)
            message = f"Loaded {len(result.themes)} of your themes"
            self.app.notify(
                message if not problems else f"{message}; {problems} file problem(s) shown below",
                severity="information" if not problems else "warning",
                markup=False,
            )


def _is_file_error(error: ThemeError) -> bool:
    """Whether the error belongs to one file (not the folder as a whole)."""
    return error.file.endswith(THEME_FILE_SUFFIX)


def _preview_content(theme: Theme) -> Content:
    """A few sample controls drawn in the theme's own colours."""
    colours = resolved_colours(theme)
    background, surface, panel = colours["background"], colours["surface"], colours["panel"]
    muted = token_colour(theme, "foreground-muted", surface) or colours["foreground"]
    on_primary = token_colour(theme, "button-color-foreground", colours["primary"]) or background
    text = colours["foreground"]

    def paint(value: str, foreground: Color, fill: Color, bold: bool = False) -> tuple:
        return (value, f"{'bold ' if bold else ''}{foreground.hex} on {fill.hex}")

    return Content("\n").join([
        Content.assemble(
            paint(" SSH connect ", on_primary, colours["primary"], True), " ",
            paint(" Browse files ", text, panel), " ",
            paint(" Ban IP… ", colours["warning"], surface), " ",
            paint(" Terminate… ", colours["error"], surface),
        ),
        Content(""),
        Content.assemble(paint(" Name        State     Provider ", on_primary, colours["primary"], True)),
        Content.assemble(
            paint(" app-1       ", text, surface), paint("running", colours["success"], surface),
            paint("   AWS      ", text, surface),
        ),
        Content.assemble(
            paint(" db-1        ", text, panel), paint("stopped", colours["error"], panel),
            paint("   AWS      ", text, panel),
        ),
        Content(""),
        Content.assemble(paint(" Search servers…              ", muted, surface)),
    ])
