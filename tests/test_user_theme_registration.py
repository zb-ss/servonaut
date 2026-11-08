"""User theme files reach the app: registered, applied, and never able to stop startup."""

from __future__ import annotations

from pathlib import Path

import pytest

from servonaut.app import ServonautApp
from servonaut.config.manager import ConfigManager
from servonaut.styles.themes import SERVONAUT_ANSI_DARK, SERVONAUT_DARK
from servonaut.styles.user_themes import derive_ansi_palette, themes_dir

OCEAN = 'primary = "#5EB1FF"\naccent = "#7DD3FC"\nbackground = "#0B1622"\nsurface = "#10233A"\n'


@pytest.fixture
def themes_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The themes folder of a throwaway home."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("TEXTUAL_THEME", raising=False)
    folder = themes_dir()
    folder.mkdir(parents=True)
    return folder


def _app(tmp_path: Path, saved_theme: str = "servonaut") -> ServonautApp:
    manager = ConfigManager(config_path=tmp_path / "config.json")
    manager.update(theme=saved_theme)
    app = ServonautApp(config_path=tmp_path / "config.json")
    app.config_manager = manager
    return app


def test_valid_theme_files_are_registered_after_the_built_ins(themes_folder: Path, tmp_path: Path) -> None:
    (themes_folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    app = _app(tmp_path)
    assert "ocean" in app.available_themes
    assert SERVONAUT_DARK.name in app.available_themes
    assert set(app.user_themes) == {"ocean"}
    assert app.user_theme_errors == ()


def test_a_user_theme_applies_and_brings_its_own_ansi_palette(themes_folder: Path, tmp_path: Path) -> None:
    (themes_folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    app = _app(tmp_path)

    app.theme = "ocean"

    expected = app.user_themes["ocean"].ansi
    assert app.ansi_theme_dark is expected and app.ansi_theme_light is expected
    assert app.ansi_theme_dark is not SERVONAUT_ANSI_DARK
    assert [tuple(c) for c in expected.ansi_colors] == [
        tuple(c) for c in derive_ansi_palette(app.user_themes["ocean"].theme).ansi_colors
    ]
    app.theme = "servonaut"
    assert app.ansi_theme_dark is SERVONAUT_ANSI_DARK


def test_a_saved_user_theme_is_applied_at_start(themes_folder: Path, tmp_path: Path) -> None:
    (themes_folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    app = _app(tmp_path, "ocean")
    app._apply_configured_theme("ocean")
    assert app.theme == "ocean"


def test_a_saved_theme_whose_file_vanished_falls_back_without_rewriting_the_config(
    themes_folder: Path, tmp_path: Path,
) -> None:
    app = _app(tmp_path, "ocean")
    before = (tmp_path / "config.json").read_bytes()

    app._apply_configured_theme("ocean")

    assert app.theme == "servonaut"
    assert (tmp_path / "config.json").read_bytes() == before


def test_a_broken_file_never_stops_startup(themes_folder: Path, tmp_path: Path) -> None:
    (themes_folder / "broken.toml").write_text("primary = [[[", encoding="utf-8")
    (themes_folder / "binary.toml").write_bytes(b"\xff\xfe\x00")
    (themes_folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")

    app = _app(tmp_path)

    assert "ocean" in app.available_themes
    assert sorted(error.file for error in app.user_theme_errors) == ["binary.toml", "broken.toml"]


def test_a_scan_that_raises_is_contained(
    themes_folder: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(**_kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr("servonaut.app.load_user_themes", explode)

    app = _app(tmp_path)

    assert app.user_themes == {} and app.user_theme_errors == ()


def test_a_theme_cannot_take_a_built_in_name(themes_folder: Path, tmp_path: Path) -> None:
    (themes_folder / "nord.toml").write_text(OCEAN, encoding="utf-8")
    app = _app(tmp_path)
    assert app.user_themes == {}
    assert "already used" in app.user_theme_errors[0].message
    assert app.available_themes["nord"].primary != "#5EB1FF"


@pytest.mark.asyncio
async def test_reload_picks_up_new_edited_and_deleted_files(themes_folder: Path, tmp_path: Path) -> None:
    (themes_folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    app = _app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        app.theme = "ocean"
        await pilot.pause()

        (themes_folder / "ocean.toml").write_text(OCEAN.replace("#5EB1FF", "#112233"), encoding="utf-8")
        (themes_folder / "river.toml").write_text(OCEAN, encoding="utf-8")
        result = app.reload_user_themes()
        await pilot.pause()

        assert {t.theme.name for t in result.themes} == {"ocean", "river"}
        assert app.theme == "ocean"
        assert app.current_theme.primary == "#112233"

        (themes_folder / "ocean.toml").unlink()
        app.reload_user_themes()
        await pilot.pause()

        assert "ocean" not in app.available_themes
        assert app.theme == "servonaut"
        # The saved name stays, so the theme returns if the file does.
        assert ConfigManager(config_path=tmp_path / "config.json").load().theme == "ocean"
