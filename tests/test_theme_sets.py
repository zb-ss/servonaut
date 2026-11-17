"""The fast and release theme selections preserve their promised coverage."""

from __future__ import annotations

import importlib.util
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

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
@pytest.mark.parametrize("max_size", [1, 2, 3, 100])
def test_chunks_cover_the_selected_registry_once_and_remain_balanced(
    monkeypatch: pytest.MonkeyPatch, release: bool, max_size: int,
) -> None:
    monkeypatch.setenv("SERVONAUT_TEST_ALL_THEMES", "1" if release else "0")
    chunks = theme_chunks(max_size=max_size)
    flattened = tuple(name for chunk in chunks for name in chunk)
    assert len(flattened) == len(set(flattened)) == len(theme_names())
    assert set(flattened) == set(theme_names())
    assert all(chunks)
    assert max(map(len, chunks)) <= max_size
    assert max(map(len, chunks)) - min(map(len, chunks)) <= 1


@pytest.mark.parametrize("max_size", [0, -1])
def test_invalid_chunk_size_fails_explicitly(max_size: int) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        theme_chunks(max_size=max_size)


@pytest.mark.parametrize("release,expected", [(False, 5), (True, 20)])
def test_appearance_soak_survives_snapshot_environment_cleanup(
    monkeypatch: pytest.MonkeyPatch, release: bool, expected: int,
) -> None:
    monkeypatch.setenv("SERVONAUT_TEST_ALL_THEMES", "1" if release else "0")
    path = Path(__file__).parent / "snapshots" / "test_appearance_layout.py"
    spec = importlib.util.spec_from_file_location("tests.snapshots._soak_probe", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Snapshot fixtures clear SERVONAUT_* after collection, before execution.
    monkeypatch.delenv("SERVONAUT_TEST_ALL_THEMES")
    app = SimpleNamespace(workspace_state=SimpleNamespace(navigation_visible=True))
    pilot = SimpleNamespace(app=app, press=AsyncMock(), pause=AsyncMock())

    @asynccontextmanager
    async def run_test(*, size: tuple[int, int]) -> AsyncIterator[SimpleNamespace]:
        yield pilot

    app.run_test = run_test
    monkeypatch.setattr(module._harness, "SnapshotApp", lambda: app)
    monkeypatch.setattr(module._harness, "wait_for_fleet", AsyncMock())
    layout = SimpleNamespace(classes={"-side"}, has_class=lambda name: name == "-side")
    screen = SimpleNamespace(query_one=lambda *args: layout)
    opened = AsyncMock(return_value=screen)
    monkeypatch.setattr(module, "_open_appearance_at_once", opened)
    module.test_appearance_chosen_at_once_takes_the_layout_its_width_calls_for(
        (160, 50), "-side",
    )
    assert opened.await_count == expected


@pytest.mark.parametrize("release", [False, True])
def test_default_chunks_bound_release_and_normal_work_equally(
    monkeypatch: pytest.MonkeyPatch, release: bool,
) -> None:
    monkeypatch.setenv("SERVONAUT_TEST_ALL_THEMES", "1" if release else "0")
    assert all(len(chunk) <= 3 for chunk in theme_chunks())
