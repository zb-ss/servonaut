"""The fast and release theme selections preserve their promised coverage."""

from __future__ import annotations

import pytest
from textual.app import App
from textual.theme import BUILTIN_THEMES

from tests._theme_sets import (
    COLOUR_THEMES,
    REGISTERED_THEMES,
    REPRESENTATIVE_THEMES,
    all_themes_enabled,
    theme_chunks,
    theme_names,
)
from tests.test_dialog_frame import DialogHost


def test_representatives_cover_custom_ansi_and_third_party_dark_and_light(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SERVONAUT_TEST_ALL_THEMES", raising=False)
    names = theme_names()
    assert len(names) == len(set(names)) == 6
    assert set(COLOUR_THEMES) <= set(names) <= set(DialogHost().available_themes)
    assert BUILTIN_THEMES["gruvbox"].dark
    assert not BUILTIN_THEMES["solarized-light"].dark
    assert names == REPRESENTATIVE_THEMES


def test_release_selection_covers_the_actual_registered_themes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SERVONAUT_TEST_ALL_THEMES", "1")
    assert all_themes_enabled()
    assert set(theme_names()) == set(DialogHost().available_themes)
    assert theme_names() == REGISTERED_THEMES


@pytest.mark.parametrize("release", [False, True])
def test_bare_app_selection_uses_only_its_registered_themes(
    monkeypatch: pytest.MonkeyPatch, release: bool,
) -> None:
    monkeypatch.setenv("SERVONAUT_TEST_ALL_THEMES", "1" if release else "0")
    available = App().available_themes
    names = theme_names(available)
    expected = set(available) if release else set(REPRESENTATIVE_THEMES) & set(available)
    assert set(names) == expected
    assert {"ansi-dark", "ansi-light", "gruvbox", "solarized-light"} <= set(names)


@pytest.mark.parametrize("available", [(), ("gruvbox",), ("solarized-light",)])
def test_empty_or_single_polarity_registry_is_rejected(
    monkeypatch: pytest.MonkeyPatch, available: tuple[str, ...],
) -> None:
    monkeypatch.delenv("SERVONAUT_TEST_ALL_THEMES", raising=False)
    with pytest.raises(AssertionError):
        theme_names(available)


@pytest.mark.parametrize("value", ["", "0", "true"])
def test_full_registry_requires_explicit_opt_in(
    monkeypatch: pytest.MonkeyPatch, value: str,
) -> None:
    monkeypatch.setenv("SERVONAUT_TEST_ALL_THEMES", value)
    assert not all_themes_enabled()
    assert theme_names() == REPRESENTATIVE_THEMES


@pytest.mark.parametrize("release", [False, True])
@pytest.mark.parametrize("count", [1, 2, 4, 100])
def test_chunks_cover_the_selected_registry_once_and_remain_balanced(
    monkeypatch: pytest.MonkeyPatch, release: bool, count: int,
) -> None:
    monkeypatch.setenv("SERVONAUT_TEST_ALL_THEMES", "1" if release else "0")
    chunks = theme_chunks(count=count)
    flattened = tuple(name for chunk in chunks for name in chunk)
    assert len(flattened) == len(set(flattened)) == len(theme_names())
    assert set(flattened) == set(theme_names())
    assert all(chunks)
    assert max(map(len, chunks)) - min(map(len, chunks)) <= 1


@pytest.mark.parametrize("count", [0, -1])
def test_invalid_chunk_count_fails_explicitly(count: int) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        theme_chunks(count=count)
