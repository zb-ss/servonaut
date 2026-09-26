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


# ---------------------------------------------------------------------------
# Addresses picked from the screen are acted on for real; toasts stay redacted
# ---------------------------------------------------------------------------

REAL_BANNED = "9.9.9.9"


def _ban_screen(demo: bool):
    from unittest.mock import AsyncMock

    app = _app(demo)
    app.ip_ban_service.list_banned = AsyncMock(return_value=[f"{REAL_BANNED}/32"])
    app.ip_ban_service.unban_ip = AsyncMock(return_value={
        "success": True, "message": f"Unbanned {REAL_BANNED}/32 from WAF IP set",
    })
    app.ip_ban_service.ban_ip = AsyncMock(return_value={
        "success": False, "message": f"{REAL_BANNED} already banned in WAF",
    })
    app.config_manager.get.return_value.ip_ban_audit_path = "/nonexistent/audit.json"
    screen = IPBanScreen()
    widgets = {"#banned_table": MagicMock(), "#ip_input": MagicMock(value="")}
    return app, screen, widgets


def _query(widgets):
    return lambda selector, *args: widgets.get(selector, MagicMock())


def test_an_address_picked_from_the_table_is_unbanned_for_real() -> None:
    import asyncio

    app, screen, widgets = _ban_screen(demo=True)
    with (
        patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", side_effect=_query(widgets)),
    ):
        asyncio.run(screen._load_banned_ips("customer-shop-waf"))
        shown = widgets["#banned_table"].add_row.call_args.args[0]
        assert REAL_BANNED not in shown
        # "Use selected IP" puts the address as shown, without its prefix.
        widgets["#ip_input"].value = shown.split("/")[0]
        asyncio.run(screen._unban_ip(screen._input_ip(), "customer-shop-waf"))
        asyncio.run(screen._ban_ip(screen._input_ip(), "customer-shop-waf"))

    assert app.ip_ban_service.unban_ip.await_args.args[0] == REAL_BANNED
    assert app.ip_ban_service.ban_ip.await_args.args[0] == REAL_BANNED
    for call in app.notify.call_args_list:
        assert REAL_BANNED not in call.args[0]
        assert "customer-shop-waf" not in call.args[0]
        assert call.kwargs.get("markup") is False


def test_a_typed_address_is_used_as_typed() -> None:
    app, screen, widgets = _ban_screen(demo=True)
    widgets["#ip_input"].value = "8.8.8.8"
    with (
        patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", side_effect=_query(widgets)),
    ):
        assert screen._input_ip() == "8.8.8.8"


def test_toasts_are_unchanged_outside_demo_mode() -> None:
    import asyncio

    app, screen, widgets = _ban_screen(demo=False)
    with (
        patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", side_effect=_query(widgets)),
    ):
        asyncio.run(screen._unban_ip(f"{REAL_BANNED}/32", "customer-shop-waf"))
    assert app.notify.call_args_list[0].args[0] == f"Unbanned {REAL_BANNED}/32 from WAF IP set"


def test_toggle_redraws_config_labels_and_the_address_field() -> None:
    app, screen, widgets = _ban_screen(demo=True)
    selector = MagicMock(value="customer-shop-waf")
    widgets["#ban_config_selector"] = selector
    widgets["#ip_input"].value = REAL_BANNED  # typed while demo mode was off
    with (
        patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", side_effect=_query(widgets)),
        patch.object(screen, "run_worker", side_effect=lambda coro, **kw: coro.close()),
    ):
        screen.refresh_after_demo_toggle()
        labels = [label for label, _ in selector.set_options.call_args.args[0]]
        assert all("customer-shop-waf" not in label for label in labels)
        assert selector.value == "customer-shop-waf"
        assert widgets["#ip_input"].value != REAL_BANNED
        assert screen._input_ip() == REAL_BANNED


# Two real addresses that share one stand-in (the stand-in range is small).
TWIN_A, TWIN_B = "9.9.1.46", "9.9.1.47"


def _twin_screen(prefill: str = "", prefill_real: str = ""):
    from unittest.mock import AsyncMock

    app = _app(demo=True)
    assert app.redaction_service.redact_ip(TWIN_A) == app.redaction_service.redact_ip(TWIN_B)
    app.ip_ban_service.list_banned = AsyncMock(return_value=[f"{TWIN_A}/32", f"{TWIN_B}/32"])
    app.ip_ban_service.ban_ip = AsyncMock(return_value={"success": True, "message": "ok"})
    app.ip_ban_service.unban_ip = AsyncMock(return_value={"success": True, "message": "ok"})
    app.config_manager.get.return_value.ip_ban_audit_path = "/nonexistent/audit.json"
    screen = IPBanScreen(prefill_ip=prefill, prefill_real_ip=prefill_real)
    table = MagicMock(cursor_row=0)
    table.row_count = 2
    widgets = {
        "#banned_table": table,
        "#ip_input": MagicMock(value=prefill),
        "#ban_config_selector": MagicMock(value="customer-shop-waf"),
    }
    return app, screen, widgets


def _run_with(app, screen, widgets, *steps):
    import asyncio

    with (
        patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", side_effect=_query(widgets)),
        patch.object(screen, "notify"),
        patch.object(screen, "run_worker", side_effect=lambda coro, **kw: asyncio.run(coro)),
    ):
        asyncio.run(screen._load_banned_ips("customer-shop-waf"))
        for step in steps:
            step()


def test_a_picked_row_is_acted_on_by_position_not_by_stand_in() -> None:
    app, screen, widgets = _twin_screen()
    widgets["#banned_table"].cursor_row = 0
    _run_with(app, screen, widgets, screen.action_use_selected_ip, screen._do_unban)
    app.ip_ban_service.unban_ip.assert_awaited_once()
    assert app.ip_ban_service.unban_ip.await_args.args[0] == TWIN_A

    app, screen, widgets = _twin_screen()
    widgets["#banned_table"].cursor_row = 1
    _run_with(app, screen, widgets, screen.action_use_selected_ip, screen._do_unban)
    assert app.ip_ban_service.unban_ip.await_args.args[0] == TWIN_B


def test_a_prefill_keeps_its_real_address_when_the_table_loads() -> None:
    shown = RedactionService().redact_ip(TWIN_B)
    app, screen, widgets = _twin_screen(prefill=shown, prefill_real=TWIN_B)
    _run_with(app, screen, widgets, screen._do_ban)
    assert app.ip_ban_service.ban_ip.await_args.args[0] == TWIN_B


def test_a_typed_stand_in_shared_by_two_addresses_is_refused() -> None:
    app, screen, widgets = _twin_screen()
    shown = app.redaction_service.redact_ip(TWIN_A)

    def type_it() -> None:
        widgets["#ip_input"].value = shown

    _run_with(app, screen, widgets, type_it, screen._do_ban, screen._do_unban)
    app.ip_ban_service.ban_ip.assert_not_awaited()
    app.ip_ban_service.unban_ip.assert_not_awaited()
    refusal = app.notify.call_args.args[0]
    assert "ctrl+shift+d" in refusal and TWIN_A not in refusal
