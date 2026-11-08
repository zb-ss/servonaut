"""Describing, exporting and writing themes, and the contrast readings."""

from __future__ import annotations

from pathlib import Path

import pytest
from textual.theme import BUILTIN_THEMES, Theme

from servonaut.styles.readability import MIN_CONTRAST, readings_for, worst_reading
from servonaut.styles.theme_files import (
    SOURCE_BUILT_IN,
    SOURCE_USER,
    ThemeFileError,
    describe_themes,
    render_theme_file,
    write_theme_file,
)
from servonaut.styles.themes import SERVONAUT_DARK, SERVONAUT_LIGHT, SERVONAUT_THEMES
from servonaut.styles.user_themes import check_theme_file, load_user_themes


def _available() -> dict[str, Theme]:
    available = dict(BUILTIN_THEMES)
    available.update({theme.name: theme for theme in SERVONAUT_THEMES})
    return available


def test_describe_lists_servonaut_then_user_then_textual_themes(tmp_path: Path) -> None:
    (tmp_path / "ocean.toml").write_text('primary = "#5EB1FF"\n', encoding="utf-8")
    users = {t.theme.name: t for t in load_user_themes((), tmp_path).themes}
    available = _available() | {name: user.theme for name, user in users.items()}

    infos = describe_themes(available, users)

    names = [info.name for info in infos]
    assert names[:3] == ["servonaut", "servonaut-light", "ocean"]
    assert names[3:] == sorted(names[3:], key=lambda name: next(i.label for i in infos if i.name == name))
    assert {info.name: info.source for info in infos}["ocean"] == SOURCE_USER
    assert {info.name: info.source for info in infos}["nord"] == SOURCE_BUILT_IN
    assert next(i for i in infos if i.name == "ocean").path == tmp_path / "ocean.toml"


@pytest.mark.parametrize("theme", [SERVONAUT_DARK, SERVONAUT_LIGHT, BUILTIN_THEMES["nord"], BUILTIN_THEMES["textual-light"]],
                         ids=lambda t: t.name)
def test_every_exported_theme_is_a_valid_theme_file_with_the_same_colours(theme: Theme, tmp_path: Path) -> None:
    info = describe_themes({theme.name: theme}, {})[0]
    path = tmp_path / "copy.toml"
    path.write_text(render_theme_file(info, name="copy"), encoding="utf-8")

    assert check_theme_file(path) == []
    (loaded,) = load_user_themes((), tmp_path).themes
    assert loaded.theme.name == "copy"
    assert loaded.theme.dark is theme.dark
    assert loaded.theme.primary.upper() == theme.primary.upper()


def test_export_of_a_servonaut_theme_keeps_its_variables_and_palette() -> None:
    info = describe_themes({SERVONAUT_DARK.name: SERVONAUT_DARK}, {})[0]
    text = render_theme_file(info)
    assert 'text-accent = "#00F2FE"' in text
    assert "[ansi]" in text and "docs/themes.md" in text


def test_a_terminal_colour_theme_cannot_be_exported() -> None:
    info = describe_themes({"ansi-dark": BUILTIN_THEMES["ansi-dark"]}, {})[0]
    with pytest.raises(ValueError, match="terminal colours"):
        render_theme_file(info)


def test_write_creates_the_folder_and_the_file(tmp_path: Path) -> None:
    folder = tmp_path / "themes"
    path = write_theme_file("ocean", "primary = 1\n", folder=folder)
    assert path == folder / "ocean.toml" and path.read_text(encoding="utf-8") == "primary = 1\n"
    assert [p.name for p in folder.iterdir()] == ["ocean.toml"]


def test_write_refuses_to_overwrite_unless_told(tmp_path: Path) -> None:
    write_theme_file("ocean", "old", folder=tmp_path)
    with pytest.raises(ThemeFileError, match="already exists"):
        write_theme_file("ocean", "new", folder=tmp_path)
    assert (tmp_path / "ocean.toml").read_text(encoding="utf-8") == "old"
    write_theme_file("ocean", "new", overwrite=True, folder=tmp_path)
    assert (tmp_path / "ocean.toml").read_text(encoding="utf-8") == "new"


@pytest.mark.parametrize("name", ["../escape", "a/b", "a\\b", "", "Upper", ".hidden", "x" * 41, "name.toml"])
def test_write_refuses_names_that_could_leave_the_folder(tmp_path: Path, name: str) -> None:
    folder = tmp_path / "themes"
    with pytest.raises(ThemeFileError):
        write_theme_file(name, "x", folder=folder)
    assert not folder.exists() and list(tmp_path.iterdir()) == []


def test_a_failed_write_leaves_no_temporary_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr("servonaut.styles.theme_files.os.replace", refuse)
    with pytest.raises(ThemeFileError, match="Permission denied"):
        write_theme_file("ocean", "x", folder=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_servonaut_themes_read_well_on_every_pair() -> None:
    for theme in SERVONAUT_THEMES:
        assert worst_reading(theme) is None, theme.name
        assert [r.label for r in readings_for(theme)] == [
            "Text on background", "Text on cards", "Muted text on cards",
            "Accent text on cards", "Error text on cards",
        ]


def test_low_contrast_is_reported_with_the_failing_pair() -> None:
    pale = Theme(name="pale", primary="#C0C0C0", foreground="#B0B0B0", background="#FFFFFF",
                 surface="#F4F4F4", dark=False)
    worst = worst_reading(pale)
    assert worst is not None and worst.ratio < MIN_CONTRAST and not worst.is_readable


def test_a_terminal_colour_theme_has_nothing_to_measure() -> None:
    assert readings_for(BUILTIN_THEMES["ansi-dark"]) == ()
    assert worst_reading(BUILTIN_THEMES["ansi-dark"]) is None
