"""Every cell of the six Vault tables is drawn as typed, whatever the service sends.

A DataTable parses a plain ``str`` cell as markup when it paints, so an action
payload (``[@click=...]``), a closing tag a backslash defeats and a control
sequence must each arrive as a ``Text`` cell and leave the screen without a
click action, an exception or a raw escape sequence.
"""

from __future__ import annotations

from typing import Any, Callable

import pytest
from rich.text import Text
from textual.widgets import DataTable

from tests._literal_probe import BACKSLASH_CRASH, CLICK, SPACED_CLICK, clickable_cells, no_backstop  # noqa: F401
from tests._vault_target_harness import FakeVaultService, VaultHost, ready, vault_screen

CONTROL = "ctl\x1b]52;c;ZWNobw==\x07tail"
HOSTILE = [CLICK, SPACED_CLICK, BACKSLASH_CRASH, CONTROL]


def _vaults(value: str) -> dict:
    return {
        "_vaults": [{"vault_id": value, "name": value, "kind": value,
                     "counts": {"items": value, "open_exposures": value}}],
    }


def _items(value: str) -> dict:
    return {"_items": [{"item_id": value, "type": value, "revision": value, "public_fingerprint": value}]}


def _exposures(value: str) -> dict:
    return {"_exposures": [{"subject": value, "reason": value, "item_id": value, "exposure_id": value}]}


def _rotation(value: str) -> dict:
    return {"_rotation_hosts": [{"server_id": value, "status": value, "error": value}]}


def _devices(value: str) -> dict:
    return {"_devices": [{"name": value, "platform": value, "status": value, "device_id": value}]}


def _roster(value: str) -> dict:
    return {"_roster": [{"display_name": value, "user_id": value, "role": value, "status": value,
                         "identity": {"fingerprint": value}}]}


TABLES: dict[str, tuple[Callable[[str], dict], str]] = {
    "vaults": (_vaults, "_render_vaults"),
    "items": (_items, "_render_items"),
    "exposures": (_exposures, "_render_exposures"),
    "rotation": (_rotation, "_render_rotation"),
    "devices": (_devices, "_render_devices"),
    "roster": (_roster, "_render_roster"),
}


@pytest.mark.asyncio
@pytest.mark.timeout(400)
@pytest.mark.parametrize("value", HOSTILE, ids=["click", "spaced_click", "backslash_crash", "control"])
@pytest.mark.parametrize("table_name", list(TABLES))
async def test_vault_table_cells_are_drawn_as_typed(no_backstop, table_name: str, value: str) -> None:  # noqa: F811
    build, render = TABLES[table_name]
    app = VaultHost(FakeVaultService())
    async with app.run_test(size=(120, 36)) as pilot:
        await ready(app, pilot)
        screen = vault_screen(app)
        for name, rows in build(value).items():
            setattr(screen, name, rows)
        getattr(screen, render)()
        for _ in range(3):
            await pilot.pause()
        table = screen.query_one("#vault_table", DataTable)
        assert table.row_count == 1
        cells = table.get_row_at(0)
        assert all(isinstance(cell, Text) or cell == "" for cell in cells), [type(cell) for cell in cells]
        assert app._exception is None
        assert clickable_cells(app) == []
        out = app.screen._compositor.render_update(full=True).render_segments(app.console)
        assert "\x1b]52" not in out and "\x07" not in out
