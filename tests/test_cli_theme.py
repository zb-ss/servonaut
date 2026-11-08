"""``servonaut theme list | export | check``."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from servonaut.cli.theme import add_theme_parser, handle_theme_command, is_theme_command
from servonaut.styles.user_themes import check_theme_file, themes_dir

VALID = 'primary = "#5EB1FF"\naccent = "#7DD3FC"\nbackground = "#0B1622"\nsurface = "#10233A"\n'


@pytest.fixture
def folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    path = themes_dir()
    path.mkdir(parents=True)
    return path


def _run(*argv: str) -> int:
    parser = argparse.ArgumentParser()
    add_theme_parser(parser.add_subparsers(dest="subcommand"))
    args = parser.parse_args(["theme", *argv])
    assert is_theme_command(args)
    return handle_theme_command(args)


def test_list_shows_built_in_and_user_themes_and_errors(folder: Path, capsys) -> None:
    (folder / "ocean.toml").write_text(VALID, encoding="utf-8")
    (folder / "sunset.toml").write_text('primary = "#5EB1FF"\naccent = "#ff88"\n', encoding="utf-8")

    assert _run("list") == 0

    out = capsys.readouterr().out
    assert "servonaut" in out and "nord" in out
    assert any(line.startswith("ocean") and "user" in line for line in out.splitlines())
    assert any("sunset.toml" in line and "line 2" in line and "not a colour" in line for line in out.splitlines())
    assert str(folder) in out


def test_list_warns_about_low_contrast(folder: Path, capsys) -> None:
    (folder / "pale.toml").write_text(
        'primary = "#C0C0C0"\nforeground = "#B0B0B0"\nbackground = "#FFFFFF"\nsurface = "#F4F4F4"\ndark = false\n',
        encoding="utf-8",
    )
    _run("list")
    line = next(l for l in capsys.readouterr().out.splitlines() if l.startswith("pale"))
    assert "warning" in line and "4.5:1" in line


def test_list_does_not_print_control_characters_from_a_file(folder: Path, capsys) -> None:
    (folder / "evil\x1b[31m.toml").write_text('primary = "nope"\n', encoding="utf-8")
    _run("list")
    assert "\x1b" not in capsys.readouterr().out


def test_export_prints_a_valid_theme_file(folder: Path, capsys, tmp_path: Path) -> None:
    assert _run("export", "servonaut") == 0
    text = capsys.readouterr().out
    path = tmp_path / "servonaut-copy.toml"
    path.write_text(text.replace('name = "servonaut"', 'name = "servonaut-copy"'), encoding="utf-8")
    assert check_theme_file(path) == []


def test_export_can_start_from_a_user_theme(folder: Path, capsys) -> None:
    (folder / "ocean.toml").write_text(VALID, encoding="utf-8")
    assert _run("export", "ocean") == 0
    assert 'primary = "#5EB1FF"' in capsys.readouterr().out


def test_export_to_a_file_refuses_to_replace_without_force(folder: Path, tmp_path: Path, capsys) -> None:
    target = tmp_path / "mine.toml"
    assert _run("export", "nord", "--output", str(target)) == 0
    first = target.read_text(encoding="utf-8")
    assert _run("export", "dracula", "--output", str(target)) == 2
    assert target.read_text(encoding="utf-8") == first
    assert "already exists" in capsys.readouterr().err
    assert _run("export", "dracula", "--output", str(target), "--force") == 0
    assert target.read_text(encoding="utf-8") != first


def test_export_of_an_unknown_theme_is_a_usage_error(folder: Path, capsys) -> None:
    assert _run("export", "no-such-theme") == 2
    assert "No theme named" in capsys.readouterr().err


def test_export_of_a_terminal_colour_theme_explains_itself(folder: Path, capsys) -> None:
    assert _run("export", "ansi-dark") == 2
    assert "terminal colours" in capsys.readouterr().err


def test_check_accepts_a_valid_file(folder: Path, tmp_path: Path, capsys) -> None:
    path = tmp_path / "mine.toml"
    path.write_text(VALID, encoding="utf-8")
    assert _run("check", str(path)) == 0
    assert "ok" in capsys.readouterr().out


def test_check_lists_every_problem_and_exits_one(folder: Path, tmp_path: Path, capsys) -> None:
    path = tmp_path / "bad.toml"
    path.write_text('primary = "nope"\nbogus = 1\n', encoding="utf-8")
    assert _run("check", str(path)) == 1
    err = capsys.readouterr().err
    assert f"{path}:1:" in err and f"{path}:2:" in err


def test_check_of_a_missing_file_fails_cleanly(folder: Path, tmp_path: Path, capsys) -> None:
    assert _run("check", str(tmp_path / "absent.toml")) == 1
    assert "could not be read" in capsys.readouterr().err.lower()


def test_check_refuses_a_name_a_built_in_theme_already_has(folder: Path, tmp_path: Path, capsys) -> None:
    path = tmp_path / "nord.toml"
    path.write_text(VALID, encoding="utf-8")
    assert _run("check", str(path)) == 1
    assert "already used" in capsys.readouterr().err


def test_checking_a_file_in_the_folder_does_not_clash_with_itself(folder: Path) -> None:
    path = folder / "ocean.toml"
    path.write_text(VALID, encoding="utf-8")
    assert _run("check", str(path)) == 0


def test_the_main_entry_point_dispatches_theme_commands(folder: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    from servonaut import main as entry

    monkeypatch.setattr("sys.argv", ["servonaut", "theme", "list"])
    with pytest.raises(SystemExit) as stopped:
        entry.main()
    assert stopped.value.code == 0
    assert "servonaut-light" in capsys.readouterr().out


def test_list_shows_one_row_per_broken_file(folder: Path, capsys) -> None:
    (folder / "bad.toml").write_text('primary = "nope"\nbogus = 1\nmore = 2\n', encoding="utf-8")
    _run("list")
    rows = [line for line in capsys.readouterr().out.splitlines() if line.startswith("bad.toml")]
    assert len(rows) == 1 and "2 more problems" in rows[0] and "line 2" in rows[0]
