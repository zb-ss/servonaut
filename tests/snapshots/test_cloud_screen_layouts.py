"""Layout defects on the multi-account cloud screens, as geometry checks."""

from __future__ import annotations

from typing import Any

import pytest

from . import _geometry
from .test_multi_account_cloud_screens import (  # noqa: F401  (the fixture is autouse)
    CloudAccountsSnapshotApp,
    _hetzner_manager,
    _ovh_ssh_keys,
    _run,
    two_accounts_each,
)

sizes = pytest.mark.parametrize("size", ["160x50", "100x30"])


def run(scenario: Any, size: str, check: Any, name: str) -> None:
    _geometry.run(
        _run(scenario), size, check, name=name, wait_for_fleet=False,
        app=CloudAccountsSnapshotApp(),
    )


@sizes
def test_ovh_ssh_keys_title_is_shared(size: str) -> None:
    def check(pilot: Any) -> None:
        title = pilot.app.screen.query_one("#ovh_ssh_keys_header")
        assert title.has_class("screen-title")
        assert not [s for s in title.visual.spans if "accent" in str(s.style)]

    run(_ovh_ssh_keys, size, check, "title-ovh-ssh-keys")


def test_hetzner_manager_keeps_its_title_in_view_at_100x30() -> None:
    def check(pilot: Any) -> None:
        screen = pilot.app.screen
        title = screen.query_one("#hetzner_mgr_header")
        assert screen.region.contains_region(title.region), "the title is scrolled out of view"
        table = screen.query_one("#hetzner_mgr_table")
        assert screen.query_one("#hetzner_mgr_container").region.contains_region(table.region)

    run(_hetzner_manager, "100x30", check, "hetzner-manager")


@sizes
def test_the_ovh_key_table_does_not_scroll_sideways(size: str) -> None:
    from textual.widgets import DataTable

    def check(pilot: Any) -> None:
        assert pilot.app.screen.query_one("#ssh_keys_table", DataTable).max_scroll_x == 0

    run(_ovh_ssh_keys, size, check, "table-ovh-keys")


def test_the_ovh_key_table_fits_beside_the_open_navigation_at_130x40() -> None:
    from textual.widgets import DataTable as Table

    def check(pilot: Any) -> None:
        table = pilot.app.screen.query_one("#ssh_keys_table", Table)
        assert table.max_scroll_x == 0, f"the key table scrolls sideways ({table.max_scroll_x})"

    _geometry.run(
        _run(_ovh_ssh_keys), (130, 40), check, name="table-ovh-keys-130",
        wait_for_fleet=False, app=CloudAccountsSnapshotApp(),
    )


