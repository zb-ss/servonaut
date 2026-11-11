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


# --- the OVH inventory's column planner ------------------------------------------------


def _row(name: str, address: str, kind: str = "vps", state: str = "running") -> tuple:
    return ("1", name, "vps-value-1-2-40", kind, state, address, "os-gra7")


def test_the_planner_never_overflows_and_keeps_the_address_whole() -> None:
    from servonaut.screens._ovh_columns import CELL_PADDING, IP_WIDTH, plan_columns

    cases = {
        "short": [_row("web", "141.123.123.123")],
        "long": [_row("a-server-with-a-rather-long-name-1", "141.123.123.123")],
        "mixed": [_row("a", "9.9.9.9"), _row("another-quite-long-server-name", "141.123.123.123")],
    }
    for label, rows in cases.items():
        for available in range(30, 121):
            widths = plan_columns(rows, available)
            total = sum(widths.values()) + CELL_PADDING * len(widths)
            smallest = 4 + 7 + IP_WIDTH + 3 * CELL_PADDING  # Name, State, Public IP
            if available >= smallest:
                assert total <= available, (label, available, widths)
            assert widths["Public IP"] == IP_WIDTH, (label, available)
            assert "State" in widths and widths["Name"] >= 3


def test_the_planner_never_widens_a_short_column() -> None:
    from servonaut.screens._ovh_columns import plan_columns

    # A 3-cell name stays 4 (the header) however tight the room: it is not widened to the floor.
    widths = plan_columns([_row("web", "9.9.9.9")], 50)
    assert widths["Name"] == 4
