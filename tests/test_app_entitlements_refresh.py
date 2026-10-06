"""The TUI refreshes entitlements once per launch so the AI footer is current."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.app import ServonautApp


@pytest.mark.asyncio
async def test_startup_refresh_fetches_entitlements_then_redraws_open_chat_footers() -> None:
    panel = MagicMock()
    screen = MagicMock()
    screen.query.return_value = [panel]
    app = SimpleNamespace(
        auth_service=SimpleNamespace(fetch_entitlements=AsyncMock(return_value={})),
        screen_stack=[screen],
    )

    await ServonautApp._refresh_entitlements_on_start(app)  # type: ignore[arg-type]

    app.auth_service.fetch_entitlements.assert_awaited_once()
    panel._update_quota_footer.assert_called_once_with()


@pytest.mark.asyncio
async def test_startup_refresh_failure_is_quiet_and_leaves_the_footer_alone() -> None:
    screen = MagicMock()
    app = SimpleNamespace(
        auth_service=SimpleNamespace(fetch_entitlements=AsyncMock(side_effect=OSError("offline"))),
        screen_stack=[screen],
    )

    await ServonautApp._refresh_entitlements_on_start(app)  # type: ignore[arg-type]

    screen.query.assert_not_called()
