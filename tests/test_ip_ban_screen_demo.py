"""IP Ban screen: operator-named ban configurations are redacted in demo mode."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock, patch

from servonaut.screens.ip_ban import IPBanScreen
from servonaut.services.redaction_service import RedactionService


def _app(demo: bool):
    app = MagicMock()
    app.demo_mode = demo
    app.redaction_service = RedactionService() if demo else None
    app.ip_ban_service.get_configs.return_value = [
        SimpleNamespace(name="customer-shop-waf", method="waf"),
        SimpleNamespace(name="ops-nacl", method="nacl"),
    ]
    return app


def test_config_options_show_pool_names_but_keep_real_values_in_demo_mode():
    app = _app(demo=True)
    screen = IPBanScreen()
    with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
        options = screen._get_config_options()

    labels = [label for label, _ in options]
    values = [value for _, value in options]
    assert values == ["customer-shop-waf", "ops-nacl"]
    assert all("customer-shop-waf" not in label for label in labels)
    assert labels[0] == f"{app.redaction_service.redact_name('customer-shop-waf')} (waf)"


def test_config_options_are_raw_outside_demo_mode():
    app = _app(demo=False)
    screen = IPBanScreen()
    with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
        options = screen._get_config_options()

    assert options[0] == ("customer-shop-waf (waf)", "customer-shop-waf")
