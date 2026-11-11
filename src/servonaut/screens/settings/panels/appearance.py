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
from textual.widget import Widget
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
SIDE_DETAILS_MIN_WIDTH = 104
# Below this panel width the three action buttons drop their borders to fit one row.
COMPACT_ACTIONS_MAX_WIDTH = 64
DETAILS_WIDTH = 36
# At this panel width the title, hint and the three buttons share one row.
HEADER_ROW_MIN_WIDTH = 120
SWATCH_MIN_CELLS = 2
# The room the "Edit file" link and its gap need beside a path.
EDIT_LINK_CELLS = 11


def _path_for_row(path: Path, room: int) -> str:
    """The whole path when it fits beside the Edit link, otherwise just the file name."""
    full = tildify(str(path))
    return full if room <= 0 or len(full) + EDIT_LINK_CELLS <= room else path.name
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


def swatch_strip(theme: Theme, width: int) -> Content:
    """The theme's main colours side by side, spread over *width* cells."""
    fills = _swatch_fills(theme)
    base, extra = divmod(max(width, SWATCH_MIN_CELLS * len(fills)), len(fills))
    return Content.assemble(*[
        (" " * (base + (1 if index < extra else 0)), f"on {fill}") for index, fill in enumerate(fills)
    ])


class SwatchStrip(Static):
    """The swatches, redrawn to span whatever width the card has."""

    def __init__(self, theme: Theme) -> None:
        super().__init__(classes="theme-card-swatches")
        self._theme = theme

    def render(self) -> Content:
        return swatch_strip(self._theme, self.content_size.width)


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
    BINDINGS = [
        Binding("enter", "choose", "Apply", show=True),
        Binding("left", "move('left')", "Previous", show=False),
        Binding("right", "move('right')", "Next", show=False),
        Binding("up", "move('up')", "Row up", show=False),
        Binding("down", "move('down')", "Row down", show=False),
        Binding("home", "move('first')", "First", show=False),
        Binding("end", "move('last')", "Last", show=False),
    ]

    class Chosen(Message):
        def __init__(self, name: str) -> None:
            super().__init__()
            self.name = name

    class Previewed(Message):
        def __init__(self, name: str) -> None:
            super().__init__()
            self.name = name

    def __init__(self, info: ThemeInfo, is_active: bool, warning: Optional[Reading]) -> None:
        classes = ["theme-card"]
        if is_active:
            classes.append("-active")
        if warning is not None:
            classes.append("-warning")
        super().__init__(id=f"theme_card_{info.name}", classes=" ".join(classes))
        self.theme_name = info.name
        self._info = info
        self._warning = warning
        self._room = 0

    def compose(self) -> ComposeResult:
        yield Static(self._title(), classes="theme-card-title")
        yield SwatchStrip(self._info.theme)
        editable = self._info.path is not None and _can_edit(self._info.path)
        with Horizontal(classes="theme-card-path"):
            yield Static(self._detail(), classes="theme-card-detail")
            if editable:
                yield EditFileButton(self._info.path)
        if self._warning is not None:
            yield Static(Content.assemble((_warning_text(self._warning), "$text-warning")), classes="theme-card-warning")

    def fit_path(self, room: int) -> None:
        """Show the file name alone when the card is too narrow for the path and Edit link."""
        self._room = room
        if self._info.path is None:
            return
        self.tooltip = tildify(str(self._info.path))
        for detail in self.query(".theme-card-path .theme-card-detail"):
            detail.update(self._detail())

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
            return Content(_path_for_row(info.path, self._room))
        kind = "follows your terminal" if info.theme.ansi else ("dark" if info.theme.dark else "light")
        return Content(f"Built in · {kind}")

    def action_choose(self) -> None:
        self.post_message(self.Chosen(self.theme_name))

    def action_move(self, direction: str) -> None:
        """Move focus to a neighbouring card, following the grid's rows and columns."""
        panel = next((a for a in self.ancestors if isinstance(a, AppearancePanel)), None)
        if panel is not None:
            panel.move_card_focus(self, direction)

    def on_click(self, event: events.Click) -> None:
        if isinstance(event.widget, Button):
            return
        self.focus()
        self.action_choose()

    def on_focus(self) -> None:
        self.post_message(self.Previewed(self.theme_name))


def _shortfall(reading: Reading) -> str:
    return f"{reading.label} is {reading.ratio:.1f}:1 (needs {MIN_CONTRAST}:1)"


def _warning_text(reading: Reading) -> str:
    return f"⚠ {_shortfall(reading)}"


def _can_edit(path: Path) -> bool:
    """Whether *path* is a regular .toml file directly inside the themes folder, not a link."""
    return (
        path.suffix == THEME_FILE_SUFFIX
        and path.parent == themes_dir()
        and not path.is_symlink()
        and path.is_file()
    )


class EditFileButton(Button):
    """Opens the theme file for editing; one row, so it sits on the path line."""

    def __init__(self, path: Path) -> None:
        super().__init__("Edit file", classes="theme-edit-file", compact=True)
        self.path = path
        self.styles.line_pad = 0

    def get_content_width(self, container, viewport) -> int:
        """Just the words: the stock button adds a cell each side, which a link does not want."""
        return self.label.cell_length


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
        self._room = 0

    def fit_path(self, room: int) -> None:
        """Show the file name alone when the card is too narrow for the path and Edit link."""
        self._room = room
        self.tooltip = tildify(str(self._path))
        for detail in self.query(".theme-card-path .theme-card-detail"):
            detail.update(Content(_path_for_row(self._path, room)))

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
            with Horizontal(classes="theme-card-path"):
                yield Static(Content(_path_for_row(self._path, self._room)), classes="theme-card-detail")
                yield EditFileButton(self._path)
        elif self._path.is_symlink():
            yield Static("This file is a link, so it cannot be opened from here.", classes="theme-card-detail")


class AppearancePanel(SettingsPanel):
    """Colour themes: built-in, yours, and the files that did not load."""

    PANEL_ID = "appearance"
    TITLE = "Appearance"
    DESCRIPTION = "Applies at once and is saved to your config."
    READABILITY_NOTE = (
        "Themes set the core colours plus optional extras (borders, cursor, terminal palette for "
        "command output). Check a theme file from the shell with: servonaut theme check <file>"
    )

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
        """The title row, then the cards and the preview; there is nothing to save."""
        yield from self.form_rows()
        yield Static("", id=f"status_{self.PANEL_ID}", classes="panel-status")

    def form_rows(self) -> ComposeResult:
        with Horizontal(id="appearance_header", classes="-wide"):
            with Vertical(id="appearance_heading"):
                yield Static(escape(self.TITLE), classes="panel-title screen-title")
                yield Static(self._hint(), id="appearance_description", classes="panel-description screen-description", markup=False)
            with Horizontal(id="appearance_actions"):
                for button_id, (label, _short) in _ACTION_LABELS.items():
                    yield Button(
                        label, id=button_id, tooltip=label,
                        variant="primary" if button_id == "appearance_new" else "default",
                    )
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
                    yield Static(self.READABILITY_NOTE, id="appearance_hint", markup=False)

    def _hint(self) -> str:
        """What the panel does and where themes live, plus any problem with the folder itself."""
        notes = [f"{self.DESCRIPTION} Your themes live in {tildify(str(themes_dir()))}."]
        errors = getattr(self.app, "user_theme_errors", [])
        notes += [e.message for e in errors if not e.file.endswith(THEME_FILE_SUFFIX)]
        return "\n".join(notes)

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
        header_wide = event.size.width >= HEADER_ROW_MIN_WIDTH
        self._fit_actions(event.size.width < COMPACT_ACTIONS_MAX_WIDTH, one_row=not header_wide)
        self.query_one("#appearance_header", Horizontal).set_class(header_wide, "-wide")
        cards_width = event.size.width - (DETAILS_WIDTH + 2 if wide else 0)
        columns = max(1, min(MAX_CARD_COLUMNS, cards_width // CARD_MIN_WIDTH))
        grid = self.query_one("#appearance_cards", Grid)
        for count in range(1, MAX_CARD_COLUMNS + 1):
            grid.set_class(count == columns, f"-cols-{count}")
        self._fit_card_paths()

    def _fit_card_paths(self) -> None:
        """Once the cards are laid out, give each the width it really has for its path row."""
        self.call_after_refresh(self._measure_card_paths)

    def _measure_card_paths(self) -> None:
        for card in self.query(".theme-card"):
            if isinstance(card, (ThemeCard, ThemeErrorCard)) and card.content_size.width > 0:
                card.fit_path(card.content_size.width)

    @property
    def card_columns(self) -> int:
        grid = self.query_one("#appearance_cards", Grid)
        return next((n for n in range(MAX_CARD_COLUMNS, 0, -1) if grid.has_class(f"-cols-{n}")), 1)

    def move_card_focus(self, current: "ThemeCard", direction: str) -> None:
        """Focus the card *direction* of *current*, following the grid's rows and columns.

        Cards that cannot take focus (a file that failed to load) keep their place in the
        grid, so a move steps over them.
        """
        slots = list(self.query_one("#appearance_cards", Grid).children)
        focusable = [i for i, slot in enumerate(slots) if isinstance(slot, ThemeCard)]
        if current not in slots or not focusable:
            return
        index, columns = slots.index(current), self.card_columns
        if direction in ("first", "last"):
            target = focusable[0] if direction == "first" else focusable[-1]
        else:
            step = {"left": -1, "right": 1, "up": -columns, "down": columns}[direction]
            target = index + step
            while 0 <= target < len(slots) and not isinstance(slots[target], ThemeCard):
                target += step
        if 0 <= target < len(slots) and target != index:
            slots[target].focus()
            slots[target].scroll_visible()

    def _fit_actions(self, short_labels: bool, one_row: bool) -> None:
        """Short labels when the panel is too narrow for three buttons; one-row buttons when stacked."""
        for button_id, (full, short) in _ACTION_LABELS.items():
            button = self.query_one(f"#{button_id}", Button)
            button.compact = short_labels or one_row
            button.label = short if short_labels else full

    # ------------------------------------------------------------------
    # Cards
    # ------------------------------------------------------------------

    async def _rebuild_cards(self) -> None:
        app = self.app
        cards = self._ordered_cards(describe_themes(app.available_themes, app.user_themes))
        grid = self.query_one("#appearance_cards", Grid)
        await grid.remove_children()
        await grid.mount_all(cards)
        self._fit_card_paths()
        for description in self.query("#appearance_description"):  # none once the panel is closing
            description.update(self._hint())
        self._show_details(self._previewed or app.theme)

    def _ordered_cards(self, infos: List[ThemeInfo]) -> List[Widget]:
        """The active theme, yours, the files that did not load, then the built-in themes."""
        app = self.app
        cards = {
            info.name: ThemeCard(
                info,
                is_active=info.name == app.theme,
                warning=worst_reading(info.theme) if info.source == SOURCE_USER else None,
            )
            for info in infos
        }
        active = [cards[name] for name in cards if name == app.theme]
        yours = [cards[i.name] for i in infos if i.source == SOURCE_USER and i.name != app.theme]
        broken = [
            ThemeErrorCard(errors, themes_dir() / errors[0].file) for errors in errors_by_file(app.user_theme_errors).values()
        ]
        built_in = [cards[i.name] for i in infos if i.source != SOURCE_USER and i.name != app.theme]
        return [*active, *yours, *broken, *built_in]

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


def _outlined_button(label: str, colour: Color, fill: Color, bold: bool) -> List[tuple]:
    """A rounded outline around *label*, as three (text, style) lines."""
    style = f"{'bold ' if bold else ''}{colour.hex} on {fill.hex}"
    width = len(label) + 2
    return [
        ("╭" + "─" * width + "╮", style),
        (f"│ {label} │", style),
        ("╰" + "─" * width + "╯", style),
    ]


def _join_with_gap(parts: tuple) -> List[object]:
    """One line of each button, one cell apart."""
    joined: List[object] = []
    for index, part in enumerate(parts):
        if index:
            joined.append(" ")
        joined.append(part)
    return joined


def _preview_content(theme: Theme) -> Content:
    """A few sample controls drawn in the theme's own colours."""
    colours = resolved_colours(theme)
    background, surface, panel = colours["background"], colours["surface"], colours["panel"]
    muted = token_colour(theme, "foreground-muted", surface) or colours["foreground"]
    on_primary = token_colour(theme, "button-color-foreground", colours["primary"]) or background
    text = colours["foreground"]

    def paint(value: str, foreground: Color, fill: Color, bold: bool = False) -> tuple:
        return (value, f"{'bold ' if bold else ''}{foreground.hex} on {fill.hex}")

    def table_row(name: str, state: str, state_colour: Color, fill: Color) -> Content:
        return Content.assemble(
            paint(f" {name:<9} ", text, fill), paint(f"{state:<8} ", state_colour, fill), paint(f"{'AWS':<9}", text, fill),
        )

    def button_row(*buttons: tuple) -> List[Content]:
        """Outlined buttons side by side: three lines, each button's outline in its role colour."""
        boxes = [_outlined_button(label, colour, background, bold) for label, colour, bold in buttons]
        return [Content.assemble(*_join_with_gap(line_parts)) for line_parts in zip(*boxes)]

    return Content("\n").join([
        *button_row(("SSH connect", colours["primary"], True), ("Browse files", muted, False)),
        *button_row(("Ban IP…", colours["warning"], False), ("Terminate…", colours["error"], False)),
        Content(""),
        Content.assemble(paint(f" {'Name':<9} {'State':<8} {'Provider':<9}", on_primary, colours["primary"], True)),
        table_row("app-1", "running", colours["success"], surface),
        table_row("db-1", "stopped", colours["error"], panel),
        Content(""),
        Content.assemble(paint(f" {'Search servers…':<28}", muted, surface)),
    ])
