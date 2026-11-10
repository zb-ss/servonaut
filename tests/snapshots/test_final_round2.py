"""Second pass over the sentence-case sweep: SCP roles, Appearance header, fleet columns."""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

from textual.widgets import RadioSet, Static

from servonaut.screens.scp_transfer import SCPTransferScreen, path_roles

from . import _harness


def _on(factory: Callable[[], Any], check: Callable[[Any, Any], Awaitable[None]], size=(160, 50)) -> None:
    async def main() -> None:
        app = _harness.SnapshotApp()
        async with app.run_test(size=size) as pilot:
            await _harness.wait_for_fleet(pilot)
            await app.push_screen(factory())
            await pilot.pause()
            await pilot.pause()
            await check(pilot, app.screen)

    asyncio.run(main())


def test_the_transfer_roles_read_the_same_after_toggling_both_ways() -> None:
    async def check(pilot: Any, screen: Any) -> None:
        local = screen.query_one("#local_path_role", Static)
        remote = screen.query_one("#remote_path_role", Static)
        opened = (local.visual.plain, remote.visual.plain)
        assert opened == path_roles(True)
        buttons = screen.query_one("#direction_selector", RadioSet)
        buttons.query_one("#radio_download").value = True
        await pilot.pause()
        assert (local.visual.plain, remote.visual.plain) == path_roles(False)
        buttons.query_one("#radio_upload").value = True
        await pilot.pause()
        assert (local.visual.plain, remote.visual.plain) == opened

    _on(lambda: SCPTransferScreen({"id": "web-1", "name": "web-1"}), check)
