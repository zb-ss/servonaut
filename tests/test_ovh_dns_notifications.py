"""DNS notifications hide account identifiers without changing API targets."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from servonaut.screens.ovh_dns import OVHDNSScreen
from servonaut.services.redaction_service import RedactionService


@pytest.mark.parametrize("is_demo", [False, True])
@pytest.mark.parametrize("method,args,service_method", [
    ("_create_record", ("TXT", "demo", '"example"', 300), "create_record"),
    ("_update_record", (89123, "demo", '"updated"', 300), "update_record"),
    ("_delete_record", (89123,), "delete_record"),
    ("_do_refresh_zone", (), "refresh_zone"),
])
def test_dns_notice_preserves_raw_service_target(
    is_demo: bool, method: str, args: tuple, service_method: str,
) -> None:
    screen = OVHDNSScreen()
    service = SimpleNamespace(**{name: AsyncMock() for name in (
        "create_record", "update_record", "delete_record", "refresh_zone",
    )})
    app = SimpleNamespace(demo_mode=is_demo, redaction_service=RedactionService())
    zone = "private-zone.example"
    with (
        patch.object(OVHDNSScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "_get_dns_service", return_value=service),
        patch.object(screen, "_load_records", new_callable=AsyncMock),
        patch.object(screen, "notify") as notify,
    ):
        asyncio.run(getattr(screen, method)(zone, *args))
    assert getattr(service, service_method).await_args.args[0] == zone
    message = notify.call_args.args[0]
    assert (zone not in message) is is_demo
    if method == "_update_record":
        assert ("89123" not in message) is is_demo


@pytest.mark.parametrize("is_demo", [False, True])
def test_dns_provider_error_hides_unmapped_identifiers(is_demo: bool) -> None:
    screen = OVHDNSScreen()
    service = SimpleNamespace(create_record=AsyncMock(side_effect=RuntimeError("private-zone.example")))
    app = SimpleNamespace(demo_mode=is_demo, redaction_service=RedactionService())
    with (
        patch.object(OVHDNSScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "_get_dns_service", return_value=service),
        patch.object(screen, "notify") as notify,
    ):
        asyncio.run(screen._create_record("private-zone.example", "TXT", "demo", '"example"', 300))
    assert ("private-zone.example" not in notify.call_args.args[0]) is is_demo


@pytest.mark.parametrize("is_demo", [False, True])
@pytest.mark.parametrize("field_type,target", [
    ("TXT", '"verification=private-zone.example"'),
    ("MX", "10 mail.private-zone.example"),
    ("CNAME", "mail.private-zone.example."),
])
def test_record_edit_keeps_masked_values_out_of_api(
    is_demo: bool, field_type: str, target: str,
) -> None:
    screen = OVHDNSScreen()
    screen._selected_zone = "private-zone.example"
    record = {"id": 89123, "fieldType": field_type, "subDomain": "private-label",
              "target": target, "ttl": 300}
    inputs = {key: MagicMock() for key in ("#input_type", "#input_subdomain", "#input_target",
                                          "#input_ttl", "#record_form")}
    app = SimpleNamespace(demo_mode=is_demo, redaction_service=RedactionService())
    with (
        patch.object(OVHDNSScreen, "app", new_callable=PropertyMock, return_value=app),
        patch.object(screen, "query_one", side_effect=lambda key, *args: inputs[key]),
        patch.object(screen, "_hide_form"),
        patch.object(screen, "_update_record", new_callable=AsyncMock) as update,
        patch.object(screen, "run_worker", side_effect=lambda coro, **kwargs: coro.close()),
    ):
        screen._show_edit_form(record)
        assert ("private-zone.example" not in inputs["#input_target"].value) is is_demo
        screen._action_save()
        assert update.call_args.args == ("private-zone.example", 89123, "private-label", target, 300)
        inputs["#input_target"].value = '"new value"'
        screen._action_save()
        assert update.call_args.args[3] == '"new value"'
