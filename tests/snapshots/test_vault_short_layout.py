"""Vault layout defects at the short size, as geometry checks."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Callable

import pytest

from servonaut.screens.vault import VaultScreen
from tests._async_bounds import wait_until
from tests.test_vault_screen import _StyledVaultHost
from tests.test_vault_workspace_views import _Service

from . import _harness
from ._geometry import settle


def _ready(screen: VaultScreen) -> bool:
    return screen._identity_state != "loading" and not screen._busy_work


def run_vault(view: str, size: str, check: Callable[[Any], None], name: str) -> None:
    app = _StyledVaultHost(_Service(local=True))

    async def main() -> None:
        async with app.run_test(size=_harness.SIZES[size]) as pilot:
            screen = app.screen
            await wait_until(lambda: isinstance(screen, VaultScreen) and _ready(screen))
            loader = {"items": screen.action_items, "devices": screen.action_devices}.get(view)
            if loader is not None:
                loader()
                await wait_until(lambda: screen._table_mode == view and not screen._busy_work)
            await settle(pilot, app)
            target = os.environ.get("GEOMETRY_SVG_DIR")
            if target:
                Path(target).mkdir(parents=True, exist_ok=True)
                (Path(target) / f"{name}-{size}.svg").write_text(
                    app.export_screenshot(simplify=True), encoding="utf-8"
                )
            check(screen)

    asyncio.run(main())


@pytest.mark.parametrize("view", ["devices", "items", "vaults"])
def test_vault_header_stays_in_view_at_100x30(view: str) -> None:
    def check(screen: VaultScreen) -> None:
        for widget_id in ("vault_title", "vault_identity_state", "vault_refresh", "vault_status"):
            widget = screen.query_one(f"#{widget_id}")
            assert widget.region.height > 0, f"{widget_id} is scrolled out of view"
            assert screen.region.contains_region(widget.region), widget_id

    run_vault(view, "100x30", check, f"vault-{view}")
