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


def test_fifty_hostile_files_still_start_the_app_in_bounded_time(themes_folder: Path, tmp_path: Path) -> None:
    import time

    flood = 'primary = "#5EB1FF"\n' + "".join(f"k{i}=1\n" for i in range(8000))[: 64 * 1024 - 64]
    for index in range(50):
        (themes_folder / f"f{index:02d}.toml").write_text(flood, encoding="utf-8")

    started = time.perf_counter()
    app = _app(tmp_path)

    assert time.perf_counter() - started < 10
    assert len({error.file for error in app.user_theme_errors}) == 50


# ------------------------------------------------------------------ Textual's own theme watcher


# Servonaut re-applies the active theme after a reload by calling App._watch_theme,
# which Textual does not offer publicly. The hash pins the version reviewed.
_UPSTREAM_WATCH_THEME_SHA256 = "585f469c9ae8ca2d1aa23f4366c795e3b42db42fe79e51b401bf41ae0dc85f9e"


def test_upstream_theme_watcher_is_the_one_a_reload_relies_on() -> None:
    """A reload calls App._watch_theme to refresh the dark/light classes and notify listeners.

    If a Textual release changes it, re-check ServonautApp._reapply_theme_after_reload.
    """
    import hashlib
    import inspect
    import textwrap

    from textual.app import App

    assert list(inspect.signature(App._watch_theme).parameters) == ["self", "theme_name"]
    source = textwrap.dedent(inspect.getsource(App._watch_theme))
    assert hashlib.sha256(source.encode("utf-8")).hexdigest() == _UPSTREAM_WATCH_THEME_SHA256, (
        "Textual's App._watch_theme has changed. ServonautApp._reapply_theme_after_reload calls it "
        "to re-apply a theme after its file was edited: check that it still does, then update "
        "_UPSTREAM_WATCH_THEME_SHA256 in this file."
    )


@pytest.mark.asyncio
async def test_editing_the_active_theme_from_dark_to_light_flips_the_mode_and_tells_listeners(
    themes_folder: Path, tmp_path: Path,
) -> None:
    (themes_folder / "ocean.toml").write_text(OCEAN, encoding="utf-8")
    app = _app(tmp_path)
    heard: list[str] = []
    async with app.run_test(size=(120, 40)) as pilot:
        app.theme = "ocean"
        await pilot.pause()
        assert app.has_class("-dark-mode")
        app.theme_changed_signal.subscribe(app, lambda theme: heard.append(theme.name))

        (themes_folder / "ocean.toml").write_text(OCEAN + "dark = false\n", encoding="utf-8")
        app.reload_user_themes()
        await pilot.pause()
        await pilot.pause()

        assert app.has_class("-light-mode") and not app.has_class("-dark-mode")
        assert heard == ["ocean"]
