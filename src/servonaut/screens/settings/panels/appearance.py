"""Appearance settings: pick a colour theme, and make your own from a file.

Every theme shows as a card. Choosing one applies and saves it at once (the
app remembers any theme picked anywhere), so this panel has no Save button.
"""

from __future__ import annotations

import asyncio
import logging
import re
from functools import partial
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from rich.markup import escape
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.color import Color
from textual.containers import Container, Grid, Horizontal, Vertical
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
    errors_by_file,
    is_more_problems_note,
    load_user_themes,
    problem_count,
    resolved_colours,
    themes_dir,
)
from servonaut.utils.markup import literal
from servonaut.widgets.busy_indicator import BusyIndicator
from servonaut.utils.platform_utils import open_path

logger = logging.getLogger(__name__)

# A card needs about this many cells to show a swatch strip and a file path.
CARD_MIN_WIDTH = 34
MAX_CARD_COLUMNS = 3
# At this panel width the preview sits beside the cards instead of below them.
SIDE_DETAILS_MIN_WIDTH = 110
# Below this panel width the three action buttons drop their borders to fit one row.
COMPACT_ACTIONS_MAX_WIDTH = 64
DETAILS_WIDTH = 44
SWATCH_CELLS = 3
_SWATCH_ROLES = ("background", "surface", "panel", "primary", "accent", "warning", "error", "success")
_ANSI_SWATCHES = ("black", "red", "green", "yellow", "blue", "magenta", "cyan", "white")


# Button id -> (label, short label for a narrow panel).
_ACTION_LABELS = {
    "appearance_new": ("New theme from current…", "New theme…"),
    "appearance_open": ("Open themes folder", "Folder"),
    "appearance_reload": ("Reload themes", "Reload"),
}


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
    base = re.sub(r"[^a-z0-9-]+", "-", active.lower())[:30].strip("-") or "theme"
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
        super().__init__(id=f"theme_card_{info.name}", classes="theme-card -active" if is_active else "theme-card")
        self.theme_name = info.name
        self._info = info
        self._warning = warning

    def compose(self) -> ComposeResult:
        yield Static(self._title(), classes="theme-card-title")
        yield Static(swatch_strip(self._info.theme), classes="theme-card-swatches")
        yield Static(self._detail(), classes="theme-card-detail")
        if self._info.path is not None and _can_edit(self._info.path):
            yield EditFileButton(self._info.path)

    def set_active(self, is_active: bool) -> None:
        self.set_class(is_active, "-active")
        for title in self.query(".theme-card-title"):  # none while the card is being redrawn
            title.update(self._title())

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


def _can_edit(path: Path) -> bool:
    """Whether *path* is a regular .toml file directly inside the themes folder, not a link."""
    return (
        path.suffix == THEME_FILE_SUFFIX
        and path.parent == themes_dir()
        and not path.is_symlink()
        and path.is_file()
    )


class EditFileButton(Button):
    """Opens the theme file for editing."""

    def __init__(self, path: Path) -> None:
        super().__init__("Edit file", classes="theme-edit-file", compact=True)
        self.path = path


# How many of a file's problems its card lists; the rest are counted.
CARD_PROBLEMS_SHOWN = 3


def _problem_lines(errors: List[ThemeError]) -> List[str]:
    """The first few problems of one file as lines, then a count of the others."""
    real = [e for e in errors if not is_more_problems_note(e)]
    lines = [f"Line {e.line}: {e.message}" if e.line else e.message for e in real[:CARD_PROBLEMS_SHOWN]]
    more = problem_count(errors) - len(lines)
    if more > 0:
        lines.append(f"…and {more} more problems")
    return lines


class ThemeErrorCard(Vertical):
    """A theme file that could not be loaded: one card per file, with its first problems."""

    def __init__(self, errors: List[ThemeError], path: Path) -> None:
        super().__init__(classes="theme-card -error")
        self._errors = errors
        self._path = path

    def compose(self) -> ComposeResult:
        yield Static(
            Content.assemble((self._errors[0].file, "bold"), (" · not loaded", "$text-error")),
            classes="theme-card-title",
        )
        yield Static(
            Content("\n".join(_problem_lines(self._errors) + ["Fix the file, then choose Reload themes."])),
            classes="theme-card-detail",
        )
        if _can_edit(self._path):
            yield EditFileButton(self._path)
        elif self._path.is_symlink():
            yield Static("This file is a link, so it cannot be opened from here.", classes="theme-card-detail")


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
        yield from self.form_rows()
        yield Static("", id=f"status_{self.PANEL_ID}", classes="panel-status")

    def form_rows(self) -> ComposeResult:
        with Horizontal(id="appearance_actions"):
            for button_id, (label, _short) in _ACTION_LABELS.items():
                yield Button(
                    label, id=button_id, tooltip=label,
                    variant="primary" if button_id == "appearance_new" else "default",
                )
        yield Static("", id="appearance_folder", markup=False)
        yield BusyIndicator(id="appearance_busy")
        with Container(id="appearance_layout", classes="-stacked"):
            yield Grid(id="appearance_cards", classes="-cols-1")
            with Vertical(id="appearance_details"):
                with Vertical(classes="appearance-section"):
                    yield Static("", id="appearance_preview_title", classes="appearance-section-title", markup=False)
                    yield Static("", id="appearance_preview")
                with Vertical(classes="appearance-section"):
                    yield Static("", id="appearance_readability_title", classes="appearance-section-title", markup=False)
                    yield Static("", id="appearance_readability")
                    yield Static(
                        "Check a theme file from the shell with: servonaut theme check <file>",
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
        self.run_worker(self._rebuild_cards, exclusive=True, group="appearance_cards")
        self._snapshot_now()

    def collect(self) -> Dict[str, object]:
        return {}

    def persist(self) -> None:
        """Nothing to save: choosing a theme applies and saves it."""

    def on_resize(self, event: events.Resize) -> None:
        """Put the preview beside the cards when there is room, below them otherwise."""
        wide = event.size.width >= SIDE_DETAILS_MIN_WIDTH
        layout = self.query_one("#appearance_layout", Container)
        layout.set_class(wide, "-side")
        layout.set_class(not wide, "-stacked")
        self._fit_actions(event.size.width < COMPACT_ACTIONS_MAX_WIDTH)
        cards_width = event.size.width - (DETAILS_WIDTH + 2 if wide else 0)
        columns = max(1, min(MAX_CARD_COLUMNS, cards_width // CARD_MIN_WIDTH))
        grid = self.query_one("#appearance_cards", Grid)
        for count in range(1, MAX_CARD_COLUMNS + 1):
            grid.set_class(count == columns, f"-cols-{count}")

    def _fit_actions(self, compact: bool) -> None:
        """Borderless buttons with short labels when the panel is too narrow for three."""
        for button_id, (full, short) in _ACTION_LABELS.items():
            button = self.query_one(f"#{button_id}", Button)
            button.compact = compact
            button.label = short if compact else full

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
        cards += [ThemeErrorCard(errors, folder / errors[0].file) for errors in errors_by_file(app.user_theme_errors).values()]
        grid = self.query_one("#appearance_cards", Grid)
        await grid.remove_children()
        await grid.mount_all(cards)
        self._show_folder_note()
        self._show_details(self._previewed or app.theme)

    def _show_folder_note(self) -> None:
        """Where themes live, plus any problem with the folder itself."""
        notes = [f"Your themes live in {tildify(str(themes_dir()))}"]
        notes += [e.message for e in self.app.user_theme_errors if not e.file.endswith(THEME_FILE_SUFFIX)]
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
        if not isinstance(event.button, EditFileButton):
            return
        if not _can_edit(event.button.path):  # it may have changed since the card was drawn
            self.app.notify(
                "Only a regular .toml file inside the themes folder can be opened from here.",
                severity="warning", markup=False,
            )
            return
        self._open_path(event.button.path)

    def action_new_theme(self) -> None:
        app = self.app
        taken = frozenset(app.available_themes)
        prompt = ThemeNamePromptScreen(_suggest_name(app.theme, taken), taken, self._replaceable_theme_files())
        app.push_screen(prompt, self._create_theme_file)

    def _replaceable_theme_files(self) -> frozenset[str]:
        """Names of theme files that are not themes (they failed to load), so no theme owns the name."""
        try:
            stems = frozenset(p.stem for p in themes_dir().glob(f"*{THEME_FILE_SUFFIX}"))
        except OSError:
            return frozenset()
        return stems - frozenset(self.app.available_themes)

    def _create_theme_file(self, result: object) -> None:
        if not result:
            return
        name, replace = result  # type: ignore[misc]
        app = self.app
        infos = describe_themes(app.available_themes, app.user_themes)
        active = next((info for info in infos if info.name == app.theme), None)
        if active is None:
            app.notify("The current theme is not a registered one and cannot be copied.", severity="error", markup=False)
            return
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
        if not open_path(path):
            self.app.notify(f"Open it yourself: {tildify(str(path))}", severity="warning", markup=False)

    def action_reload_themes(self, announce: bool = True) -> None:
        self.run_worker(partial(self._reload, announce), exclusive=True, group="appearance_cards")

    async def _reload(self, announce: bool) -> None:
        """Read the folder off the main thread, then register it and redraw the cards."""
        app = self.app
        busy = self.query_one("#appearance_busy", BusyIndicator)
        busy.start("Reading theme files…")
        try:
            previous = set(app.user_themes)
            result = await asyncio.to_thread(load_user_themes, reserved=app.reserved_theme_names())
            app.apply_user_themes(result)
            app.finish_theme_reload(previous)
            await self._rebuild_cards()
        finally:
            busy.stop()
        if announce:
            problems = len(errors_by_file(result.errors))
            message = f"Loaded {len(result.themes)} of your themes"
            app.notify(
                message if not problems else f"{message}; {problems} file(s) had problems, shown below",
                severity="information" if not problems else "warning",
                markup=False,
            )


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
            paint(" Connect ", on_primary, colours["primary"], True), " ",
            paint(" Files ", text, panel), " ",
            paint(" Ban IP… ", colours["warning"], surface), " ",
            paint(" Stop… ", colours["error"], surface),
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
