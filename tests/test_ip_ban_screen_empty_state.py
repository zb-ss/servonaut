"""IP Ban screen: a hint points to Settings while no ban method is set up."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from servonaut.screens.ip_ban import IPBanScreen


def _mount_with_configs(configs: list) -> MagicMock:
    """Run ``on_mount`` against stand-in widgets; return the hint widget."""
    app = MagicMock()
    app.demo_mode = False
    app.redaction_service = None
    app.ip_ban_service.get_configs.return_value = configs
    app.config_manager.get.return_value.ip_ban_audit_path = "/nonexistent/audit.json"
    hint = MagicMock(display=True)
    widgets = {"#ip_ban_empty_hint": hint}
    screen = IPBanScreen()
    with (
        patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app),
        patch.object(
            screen,
            "query_one",
            side_effect=lambda selector, *args: widgets.get(selector, MagicMock()),
        ),
    ):
        screen.on_mount()
    return hint


@pytest.mark.parametrize(
    ("configs", "shown"),
    [
        ([], True),
        ([SimpleNamespace(name="edge-waf", method="waf")], False),
    ],
)
def test_the_hint_shows_only_without_a_ban_configuration(configs, shown) -> None:
    assert _mount_with_configs(configs).display is shown

