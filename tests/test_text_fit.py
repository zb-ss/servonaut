"""Cutting text by terminal cells, with a mark where it was cut."""

from __future__ import annotations

from rich.cells import cell_len

from servonaut.utils.text_fit import cut


def test_text_that_fits_is_unchanged() -> None:
    assert cut("short", 5) == "short"


def test_a_cut_ends_with_an_ellipsis_within_the_width() -> None:
    assert cut("141.123.123.1234", 15) == "141.123.123.12…"
    assert cell_len(cut("abcdefghij", 6)) <= 6


def test_wide_characters_count_two_cells() -> None:
    name = "サーバー名サーバー"
    shown = cut(name, 8)
    assert shown.endswith("…") and cell_len(shown) <= 8
    assert cut("日本", 4) == "日本"


def test_no_room_leaves_nothing() -> None:
    assert cut("anything", 0) == ""
    assert cut("anything", -3) == ""
