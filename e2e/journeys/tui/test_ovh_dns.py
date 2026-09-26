"""Journey: edit OVH DNS zones and reverse DNS from the DNS Zones screen.

A wrong DNS record can take a site offline, so every change is checked
against the requests OVH received. Choosing a zone lists its records.
Adding or editing a record sends one create or update request followed by
one zone refresh (the step that publishes the change). Deleting a record
asks the user to type the record's target first; backing out sends
nothing. Incomplete input is refused before anything is sent. The reverse
DNS section below edits and removes PTR records the same way.
"""

from __future__ import annotations

import re

import pytest

from e2e.harness import fleet
from e2e.harness.fake_providers.ovh import SeedDnsRecord
from e2e.journeys.tui.ovh_ui import mutations, ovh_audit, plain, press, select_row

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

ZONE = "e2e.test"
EMPTY_ZONE = "lab.e2e.test"
MAIL = fleet.OVH_VPS_MAIL_1
MAIL_IP = MAIL.ips[0]
MAIL_BLOCK = f"{MAIL_IP}/32"
RECORDS = (
    SeedDnsRecord("A", "", MAIL_IP),
    SeedDnsRecord("A", "www", MAIL_IP),
    SeedDnsRecord("CNAME", "mail", "mail-1.e2e.test."),
    SeedDnsRecord("TXT", "", '"v=spf1 -all"'),
)


def _records(t) -> list[tuple[str, str, str, str]]:
    return [tuple(plain(c) for c in row) for row in t.table_rows("#records_table")]


def _actions(seed) -> list[str]:
    return [row["action"] for row in ovh_audit(seed)]


def _seed(seed, providers) -> list[int]:
    seed.config(ovh=seed.ovh_config())
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=True)
    fleet.seed_provider_fleet(providers, hetzner=False)
    providers.ovh.seed_dns_zone(EMPTY_ZONE)
    providers.ovh.seed_ip_block(
        MAIL_BLOCK, ip_type="vps", routed_to=MAIL.service_name,
        reverse={MAIL_IP: "mail-1.e2e.test"},
    )
    return providers.ovh.seed_dns_zone(ZONE, RECORDS)


async def _open_zone(t, providers) -> None:
    await t.nav("nav_ovh_dns")
    await t.wait_for_screen("OVHDNSScreen")
    await t.wait_until(
        lambda: [r[0] for r in t.table_rows("#domains_table")] == [ZONE, EMPTY_ZONE],
        desc="zones listed",
    )
    await select_row(t, "#domains_table", 0, ZONE)
    await t.press("enter")
    await t.wait_until(lambda: len(_records(t)) == len(RECORDS), desc="records of the zone")


async def test_create_edit_and_delete_a_record(tui, seed, providers):
    record_ids = _seed(seed, providers)
    zone_path = f"/domain/zone/{ZONE}"

    async with tui() as t:
        await _open_zone(t, providers)
        assert ("A", "www", MAIL_IP, "3600") in _records(t)
        assert ("CNAME", "mail", "mail-1.e2e.test.", "3600") in _records(t)
        assert mutations(providers) == []

        # Add: a missing target is refused before anything is sent.
        await press(t, "#btn_add")
        await t.fill("#input_type", "A")
        await t.fill("#input_subdomain", "api")
        await press(t, "#btn_save")
        await t.wait_for_toast("Target is required", severity="error")
        assert mutations(providers) == []
        await t.fill("#input_target", "9.9.9.9")
        await t.fill("#input_ttl", "600")
        await press(t, "#btn_save")
        await t.wait_for_toast(rf"Record created in {re.escape(ZONE)}")
        await t.wait_until(lambda: ("A", "api", "9.9.9.9", "600") in _records(t), desc="new row")
        assert mutations(providers) == [
            ("POST", f"{zone_path}/record"), ("POST", f"{zone_path}/refresh"),
        ]
        created = providers.mutations("ovh")[0]["body"]
        assert created == {"fieldType": "A", "subDomain": "api", "target": "9.9.9.9", "ttl": 600}

        # Edit: the form opens with the record's values; only the change is new.
        await select_row(t, "#records_table", 1, "www")
        await press(t, "#btn_edit")
        await t.wait_until(lambda: t.on_screen("#input_target").value == MAIL_IP, desc="form")
        await t.fill("#input_target", "8.8.4.4")
        await press(t, "#btn_save")
        await t.wait_for_toast(rf"Record {record_ids[1]} updated in {re.escape(ZONE)}")
        await t.wait_until(lambda: ("A", "www", "8.8.4.4", "3600") in _records(t), desc="edit")
        assert mutations(providers)[2:] == [
            ("PUT", f"{zone_path}/record/{record_ids[1]}"), ("POST", f"{zone_path}/refresh"),
        ]
        assert providers.mutations("ovh")[2]["body"] == {
            "subDomain": "www", "target": "8.8.4.4", "ttl": 3600,
        }

        # Delete: backing out sends nothing; the exact target confirms.
        await select_row(t, "#records_table", 1, "api")
        await press(t, "#btn_delete")
        await t.wait_for_screen("ConfirmActionScreen")
        await t.press("escape")
        await t.wait_for_screen("OVHDNSScreen")
        assert len(mutations(providers)) == 4

        await press(t, "#btn_delete")
        await t.wait_for_screen("ConfirmActionScreen")
        confirm = t.on_screen("#btn_confirm")
        await t.fill("#confirm_input", "9.9.9")
        await t.settle()
        assert confirm.disabled
        await t.fill("#confirm_input", "9.9.9.9")
        await t.wait_until(lambda: not confirm.disabled, desc="confirm enabled")
        await press(t, confirm)
        await t.wait_for_toast(rf"Record deleted from {re.escape(ZONE)}")
        await t.wait_until(
            lambda: not any(row[1] == "api" for row in _records(t)), desc="api row gone"
        )

    # The fake numbers records in order, so the added one follows the seeded ones.
    added_id = max(record_ids) + 1
    assert mutations(providers)[4:] == [
        ("DELETE", f"{zone_path}/record/{added_id}"), ("POST", f"{zone_path}/refresh"),
    ]
    remaining = {
        (r["fieldType"], r["subDomain"], r["target"]) for r in providers.ovh.dns_records(ZONE)
    }
    assert remaining == {
        ("A", "", MAIL_IP), ("A", "www", "8.8.4.4"),
        ("CNAME", "mail", "mail-1.e2e.test."), ("TXT", "", '"v=spf1 -all"'),
    }
    assert _actions(seed) == ["dns_create_record", "dns_update_record", "dns_delete_record"]


async def test_edit_and_remove_reverse_dns(tui, seed, providers):
    _seed(seed, providers)
    reverse_path = f"/ip/{MAIL_BLOCK}/reverse"

    async with tui() as t:
        await t.nav("nav_ovh_dns")
        await t.wait_for_screen("OVHDNSScreen")
        await t.wait_until(
            lambda: [tuple(r) for r in t.table_rows("#rdns_table")]
            == [(MAIL_IP, "mail-1.e2e.test", MAIL_BLOCK)],
            desc="reverse DNS listed",
        )

        await select_row(t, "#rdns_table", 0, MAIL_IP)
        await press(t, "#btn_rdns_edit")
        field = t.on_screen("#input_rdns_hostname")
        await t.wait_until(lambda: field.value == "mail-1.e2e.test", desc="rDNS form")
        await t.fill("#input_rdns_hostname", "smtp-1.e2e.test")
        await press(t, "#btn_rdns_save")
        await t.wait_for_toast(rf"Reverse DNS set for {re.escape(MAIL_IP)}")
        await t.wait_until(
            lambda: [r[1] for r in t.table_rows("#rdns_table")] == ["smtp-1.e2e.test"],
            desc="new PTR shown",
        )
        assert providers.ovh.reverse_of(MAIL_BLOCK, MAIL_IP) == "smtp-1.e2e.test"

        await select_row(t, "#rdns_table", 0, MAIL_IP)
        await press(t, "#btn_rdns_delete")
        await t.wait_for_screen("ConfirmActionScreen")
        await t.fill("#confirm_input", MAIL_IP)
        await press(t, "#btn_confirm")
        await t.wait_for_toast(rf"Reverse DNS deleted for {re.escape(MAIL_IP)}")

    assert mutations(providers) == [
        ("POST", reverse_path), ("DELETE", f"{reverse_path}/{MAIL_IP}"),
    ]
    assert providers.mutations("ovh")[0]["body"] == {"ipReverse": MAIL_IP, "reverse": "smtp-1.e2e.test"}
    assert providers.ovh.reverse_of(MAIL_BLOCK, MAIL_IP) is None
    assert _actions(seed) == ["rdns_set", "rdns_delete"]
