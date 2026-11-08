"""The Vault screen: each view, the inspector and the identity steps at both sizes."""
from __future__ import annotations

import pytest

from servonaut.screens.vault import VaultScreen
from tests._async_bounds import wait_until
from tests.test_vault_screen import _StyledVaultHost
from tests.test_vault_workspace_views import _Service

def _ready(screen: VaultScreen) -> bool:
    return screen._identity_state != "loading" and not screen._busy_work


@pytest.mark.parametrize("size", [(160, 50), (100, 30)], ids=["160x50", "100x30"])
@pytest.mark.parametrize("view", ["vaults", "items", "devices", "roster", "exposures", "setup"])
def test_vault_views(screen_snapshot, size, view) -> None:
    app = _StyledVaultHost(_Service(local=view != "setup"))

    async def scene(pilot) -> None:
        screen = app.screen
        await wait_until(lambda: isinstance(screen, VaultScreen) and _ready(screen))
        loader = {
            "items": screen.action_items, "devices": screen.action_devices,
            "roster": screen.action_roster, "exposures": screen.action_exposures,
        }.get(view)
        if loader is not None:
            if view == "exposures":
                screen.action_items()
                await wait_until(lambda: screen._table_mode == "items" and not screen._busy_work)
            loader()
            await wait_until(lambda: screen._table_mode == view and not screen._busy_work)
        await pilot.pause()

    screen_snapshot(app, size, scene)
