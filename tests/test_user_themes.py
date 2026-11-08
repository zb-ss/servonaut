"""Loading colour themes from TOML files: valid files and every way they can be wrong."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from servonaut.styles.user_themes import (
    MAX_THEME_FILE_BYTES,
    MAX_THEME_FILES,
    ThemeError,
    check_theme_file,
    derive_ansi_palette,
    is_valid_theme_name,
    load_user_themes,
    themes_dir,
)

VALID = """\
name = "ocean"
dark = true
primary = "#5EB1FF"
accent = "#7DD3FC"
background = "#0B1622"
surface = "#10233A"
"""


def _write(folder: Path, filename: str, text: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / filename
    path.write_text(text, encoding="utf-8")
    return path


def _errors(folder: Path, reserved=("servonaut",)) -> list[ThemeError]:
    return list(load_user_themes(reserved, folder).errors)


def test_themes_dir_follows_home(tmp_path: Path) -> None:
    assert themes_dir(tmp_path) == tmp_path / ".servonaut" / "themes"


def test_missing_folder_is_no_themes_and_no_errors(tmp_path: Path) -> None:
    result = load_user_themes((), tmp_path / "absent")
    assert result.themes == () and result.errors == ()


def test_valid_file_loads(tmp_path: Path) -> None:
    _write(tmp_path, "ocean.toml", VALID)
    result = load_user_themes((), tmp_path)
    assert result.errors == ()
    (loaded,) = result.themes
    assert loaded.theme.name == "ocean"
    assert loaded.theme.primary == "#5EB1FF"
    assert loaded.theme.dark is True
    assert loaded.path == tmp_path / "ocean.toml"


def test_name_defaults_to_the_file_stem(tmp_path: Path) -> None:
    _write(tmp_path, "paper.toml", VALID.replace('name = "ocean"\n', ""))
    (loaded,) = load_user_themes((), tmp_path).themes
    assert loaded.theme.name == "paper"


def test_variables_are_loaded_and_normalised(tmp_path: Path) -> None:
    _write(
        tmp_path, "ocean.toml",
        VALID + '[variables]\ntext-muted = "#9fb3c8"\ninput-selection-background = "#5eb1ff 35%"\n'
        'block-cursor-text-style = "bold underline"\n',
    )
    (loaded,) = load_user_themes((), tmp_path).themes
    assert loaded.theme.variables == {
        "text-muted": "#9FB3C8",
        "input-selection-background": "#5EB1FF 35%",
        "block-cursor-text-style": "bold underline",
    }


def test_ansi_table_is_used_when_present(tmp_path: Path) -> None:
    normal = ", ".join(f'"#0{i}0{i}0{i}"' for i in range(8))
    bright = ", ".join(f'"#1{i}1{i}1{i}"' for i in range(8))
    _write(tmp_path, "ocean.toml", VALID + f"[ansi]\nnormal = [{normal}]\nbright = [{bright}]\n")
    (loaded,) = load_user_themes((), tmp_path).themes
    assert tuple(loaded.ansi.ansi_colors[3]) == (3, 3, 3)
    assert tuple(loaded.ansi.ansi_colors[8 + 5]) == (0x15, 0x15, 0x15)
    assert loaded.ansi.background_color == (0x0B, 0x16, 0x22)


def test_ansi_palette_is_derived_when_absent(tmp_path: Path) -> None:
    _write(tmp_path, "ocean.toml", VALID + 'error = "#FF8A8A"\nsuccess = "#4ADE80"\n')
    (loaded,) = load_user_themes((), tmp_path).themes
    expected = derive_ansi_palette(loaded.theme)
    assert [tuple(c) for c in loaded.ansi.ansi_colors] == [tuple(c) for c in expected.ansi_colors]
    # Meaning-bearing colours keep their slot: red is the error colour.
    assert loaded.ansi.ansi_colors[1] == (0xFF, 0x8A, 0x8A)
    assert loaded.ansi.ansi_colors[2] == (0x4A, 0xDE, 0x80)


def test_light_theme_palette_puts_dark_text_in_black(tmp_path: Path) -> None:
    _write(tmp_path, "paper.toml", 'primary = "#2B6CB0"\ndark = false\nforeground = "#1A202C"\nbackground = "#FFFDF7"\n')
    (loaded,) = load_user_themes((), tmp_path).themes
    assert loaded.ansi.ansi_colors[0] == (0x1A, 0x20, 0x2C)


@pytest.mark.parametrize(
    ("text", "line", "fragment"),
    [
        ('primary = "#5EB1FF"\naccent = "#ff88"\n', 2, '"accent" is not a colour'),
        ('primary = "nonsense"\n', 1, '"primary" is not a colour'),
        ('primary = 12\n', 1, '"primary" is not a colour'),
        ('primary = "ansi_red"\n', 1, "is not a colour"),
        ('accent = "#7DD3FC"\n', None, 'Missing the required colour "primary"'),
        ('primary = "#5EB1FF"\nbogus = 1\n', 2, 'Unknown key "bogus"'),
        ('primary = "#5EB1FF"\ndark = "yes"\n', 2, '"dark" must be true or false'),
        ('primary = "#5EB1FF"\n[variables]\nnope = "#fff"\n', 3, "unknown key"),
        ('primary = "#5EB1FF"\n[variables]\ntext-muted = "blue-ish"\n', 3, "is not a colour"),
        ('primary = "#5EB1FF"\n[variables]\ntext-muted = "#fff 250%"\n', 3, "is not a colour"),
        ('primary = "#5EB1FF"\n[variables]\nblock-cursor-text-style = "blink"\n', 3, "must use only"),
        ('primary = "#5EB1FF"\n[ansi]\nnormal = ["#000000"]\n', 2, "list of 8 colours"),
        ('primary = "#5EB1FF"\n[ansi]\nextra = 1\n', 2, "unknown key"),
        ('primary = "#5EB1FF"\nname = "Bad Name"\n', 2, "theme name"),
        ('primary = "#5EB1FF"\nname = "../escape"\n', 2, "theme name"),
        ('primary = "#5EB1FF"\nname = "' + "a" * 41 + '"\n', 2, "theme name"),
        ('primary = "#5EB1FF"\nprimary = "#000000"\n', 2, "TOML"),
        ('primary = "#5EB1FF\n', 1, "TOML"),
    ],
)
def test_each_validation_error_names_the_file_line_and_problem(
    tmp_path: Path, text: str, line: int | None, fragment: str,
) -> None:
    _write(tmp_path, "broken.toml", text)
    result = load_user_themes((), tmp_path)
    assert result.themes == ()
    (error,) = [e for e in result.errors if fragment in e.message][:1] or [None]
    assert error is not None, result.errors
    assert error.file == "broken.toml"
    if line is not None:
        assert error.line == line


def test_good_files_load_even_when_others_fail(tmp_path: Path) -> None:
    _write(tmp_path, "a-good.toml", VALID)
    _write(tmp_path, "b-bad.toml", 'primary = "nope"\n')
    result = load_user_themes((), tmp_path)
    assert [t.theme.name for t in result.themes] == ["ocean"]
    assert [e.file for e in result.errors] == ["b-bad.toml"]


def test_name_clashing_with_a_reserved_theme_is_refused(tmp_path: Path) -> None:
    _write(tmp_path, "nord.toml", 'primary = "#5EB1FF"\n')
    (error,) = _errors(tmp_path, reserved=("nord",))
    assert "already used" in error.message


def test_duplicate_names_keep_the_first_file(tmp_path: Path) -> None:
    _write(tmp_path, "one.toml", VALID)
    _write(tmp_path, "two.toml", VALID)
    result = load_user_themes((), tmp_path)
    assert [t.path.name for t in result.themes] == ["one.toml"]
    assert [e.file for e in result.errors] == ["two.toml"]


def test_oversized_file_is_an_error_not_read(tmp_path: Path) -> None:
    _write(tmp_path, "big.toml", VALID + "# " + "x" * MAX_THEME_FILE_BYTES + "\n")
    (error,) = _errors(tmp_path)
    assert error.file == "big.toml" and "larger than" in error.message


def test_only_the_first_files_are_read(tmp_path: Path) -> None:
    for index in range(MAX_THEME_FILES + 3):
        _write(tmp_path, f"t{index:03d}.toml", 'primary = "#5EB1FF"\n')
    result = load_user_themes((), tmp_path)
    assert len(result.themes) == MAX_THEME_FILES
    assert any("skipped" in e.message for e in result.errors)


def test_undecodable_file_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "binary.toml").write_bytes(b"\xff\xfe\x00primary")
    (error,) = _errors(tmp_path)
    assert "UTF-8" in error.message


def test_unreadable_file_is_an_error(tmp_path: Path) -> None:
    locked = _write(tmp_path, "locked.toml", VALID)
    locked.chmod(0)
    _write(tmp_path, "open.toml", VALID.replace("ocean", "river"))
    try:
        if os.access(locked, os.R_OK):
            pytest.skip("permissions are not enforced for this user")
        result = load_user_themes((), tmp_path)
    finally:
        locked.chmod(0o600)
    assert [t.theme.name for t in result.themes] == ["river"]
    (error,) = result.errors
    assert error.file == "locked.toml" and "could not be read" in error.message.lower()


def test_a_directory_named_like_a_theme_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "folder.toml").mkdir()
    result = load_user_themes((), tmp_path)
    assert result.themes == () and result.errors == ()


def test_other_file_types_are_ignored(tmp_path: Path) -> None:
    _write(tmp_path, "notes.txt", "primary = nonsense")
    result = load_user_themes((), tmp_path)
    assert result.themes == () and result.errors == ()


def test_check_reports_every_fault_in_one_file(tmp_path: Path) -> None:
    path = _write(tmp_path, "x.toml", 'primary = "nope"\nbogus = 1\naccent = "#ff88"\n')
    messages = [e.message for e in check_theme_file(path)]
    assert len(messages) == 3


def test_check_of_a_valid_file_is_empty(tmp_path: Path) -> None:
    assert check_theme_file(_write(tmp_path, "ocean.toml", VALID)) == []


@pytest.mark.parametrize("name", ["ocean", "a", "my-theme-2", "0day"])
def test_valid_names(name: str) -> None:
    assert is_valid_theme_name(name)


@pytest.mark.parametrize("name", ["", "-lead", "Upper", "has space", "a/b", "a\\b", "x" * 41, "dot.dot", None, 5])
def test_invalid_names(name: object) -> None:
    assert not is_valid_theme_name(name)
