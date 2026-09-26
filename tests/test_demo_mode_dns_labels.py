"""DNS record names are redacted in demo mode, including one-label names."""
from __future__ import annotations

import re
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from textual.app import App
from textual.widgets import DataTable, Input, Static

from servonaut.screens.ovh_dns import OVHDNSScreen
from servonaut.services.redaction_service import RedactionService
from servonaut.styles import CSS_FILES

ZONE = "acme-corp.example"
RECORDS = [
    {"id": 1, "fieldType": "A", "subDomain": "shop", "target": "10.20.30.40", "ttl": 3600},
    {"id": 2, "fieldType": "CNAME", "subDomain": "api", "target": "origin.acme-corp.example.",
     "ttl": 60},
    {"id": 3, "fieldType": "A", "subDomain": "portal.eu", "target": "10.20.30.41", "ttl": 60},
    {"id": 4, "fieldType": "TXT", "subDomain": "_dmarc", "target": "v=DMARC1", "ttl": 60},
    {"id": 5, "fieldType": "MX", "subDomain": "", "target": "10 mx.acme-corp.example.",
     "ttl": 60},
]
NAMES = ("shop", "api", "portal", "acme-corp")


def _shows(text: str, label: str) -> bool:
    """*label* as a whole DNS label (the stand-ins reuse words like "api")."""
    return re.search(rf"(?<![\w-]){re.escape(label)}(?![\w-])", text) is not None


class TestRedactDnsLabel:
    def test_every_name_label_is_replaced(self) -> None:
        redaction = RedactionService()
        for name in ("shop", "api", "portal.eu", "e2e-portal"):
            fake = redaction.redact_dns_label(name)
            assert fake != name
            assert fake.count(".") == name.count(".")
            for label in name.split("."):
                assert label not in fake.split(".")

    def test_dns_syntax_is_kept(self) -> None:
        redaction = RedactionService()
        for name in ("@", "*", "_dmarc", "_acme-challenge", ""):
            assert redaction.redact_dns_label(name) == name
        assert redaction.redact_dns_label("*.shop").startswith("*.")

    def test_deterministic_and_idempotent(self) -> None:
        first, second = RedactionService(), RedactionService()
        fake = first.redact_dns_label("shop")
        assert second.redact_dns_label("shop") == fake
        assert first.redact_dns_label(fake) == fake


class DNSApp(App):
    CSS_PATH = CSS_FILES

    def __init__(self, demo: bool) -> None:
        super().__init__()
        self.demo_mode = demo
        self.redaction_service = RedactionService() if demo else None
        self.ovh_dns_service = SimpleNamespace(
            list_domains=AsyncMock(return_value=[ZONE]),
            list_records=AsyncMock(return_value=[dict(r) for r in RECORDS]),
            update_record=AsyncMock(),
            refresh_zone=AsyncMock(),
        )
        self.ovh_ip_service = SimpleNamespace(list_ips=AsyncMock(return_value=[]))
        self.ovh_service = None

    def on_mount(self) -> None:
        self.push_screen(OVHDNSScreen())


def _cells(screen, table_id: str) -> str:
    table = screen.query_one(table_id, DataTable)
    return "\n".join(
        str(cell) for key in table.rows for cell in table.get_row(key)
    )


async def _open_zone(pilot) -> OVHDNSScreen:
    screen = pilot.app.screen
    await pilot.app.workers.wait_for_complete()
    await pilot.pause()
    screen._selected_zone = ZONE
    await screen._load_records(ZONE)
    await pilot.pause()
    return screen


def _visible(screen) -> str:
    return "\n".join([
        _cells(screen, "#domains_table"),
        _cells(screen, "#records_table"),
        str(screen.query_one("#selected_zone", Static).render()),
    ])


@pytest.mark.asyncio
async def test_records_hide_their_names_in_demo_mode() -> None:
    app = DNSApp(demo=True)
    with patch("servonaut.screens.ovh_dns.Sidebar", side_effect=lambda: Static(id="sidebar")):
        async with app.run_test(size=(160, 50)) as pilot:
            screen = await _open_zone(pilot)
            shown = _visible(screen)
            assert screen.query_one("#records_table", DataTable).row_count == len(RECORDS)
            for name in NAMES:
                assert not _shows(shown, name), name
            assert "_dmarc" in shown and "@" in shown


@pytest.mark.asyncio
async def test_records_show_their_names_outside_demo_mode() -> None:
    app = DNSApp(demo=False)
    with patch("servonaut.screens.ovh_dns.Sidebar", side_effect=lambda: Static(id="sidebar")):
        async with app.run_test(size=(160, 50)) as pilot:
            shown = _visible(await _open_zone(pilot))
            for name in ("shop", "api", "portal.eu", ZONE):
                assert name in shown, name


@pytest.mark.asyncio
async def test_editing_a_record_in_demo_mode_keeps_its_real_name() -> None:
    app = DNSApp(demo=True)
    with patch("servonaut.screens.ovh_dns.Sidebar", side_effect=lambda: Static(id="sidebar")):
        async with app.run_test(size=(160, 50)) as pilot:
            screen = await _open_zone(pilot)
            screen._show_edit_form(RECORDS[0])
            field = screen.query_one("#input_subdomain", Input)
            assert field.value != "shop"
            screen._action_save()
            await app.workers.wait_for_complete()
            call = app.ovh_dns_service.update_record.await_args
            assert call.kwargs["sub_domain"] == "shop"
            assert call.kwargs["target"] == "10.20.30.40"


@pytest.mark.asyncio
async def test_toggle_redraws_zones_and_records() -> None:
    app = DNSApp(demo=False)
    with patch("servonaut.screens.ovh_dns.Sidebar", side_effect=lambda: Static(id="sidebar")):
        async with app.run_test(size=(160, 50)) as pilot:
            screen = await _open_zone(pilot)
            assert "shop" in _visible(screen)

            records = screen.query_one("#records_table", DataTable)
            records.move_cursor(row=2)
            app.demo_mode, app.redaction_service = True, RedactionService()
            screen.refresh_after_demo_toggle()
            await pilot.pause()
            assert records.cursor_row == 2, "the cursor stays on the same record"
            shown = _visible(screen)
            for name in NAMES:
                assert not _shows(shown, name), name

            app.demo_mode, app.redaction_service = False, None
            screen.refresh_after_demo_toggle()
            await pilot.pause()
            assert "shop" in _visible(screen)
