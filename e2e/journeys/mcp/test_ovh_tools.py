"""Journey: an MCP client works with OVHcloud through ``servonaut --mcp``.

The real server runs as a child process against the local OVH stand-in.
The read tools list IPs, DNS records, firewall rules, SSH keys, snapshots,
the billing summary and invoices, and change nothing. The lifecycle tools
follow the guard levels: start, stop and reboot need the standard level,
create and delete the dangerous one. A refused call sends nothing to OVH
and leaves one audit entry; an allowed call sends exactly one request and
is audited too.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from e2e.harness import fleet
from e2e.harness.fake_providers.ovh import (
    SeedBill,
    SeedDnsRecord,
    SeedFirewallRule,
    flavor_id,
    image_id,
)
from e2e.harness.known_bugs import ProductBug
from e2e.harness.seed import HomeSeeder

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

PROJECT = fleet.OVH_PROJECT_ID
MAIL = fleet.OVH_VPS_MAIL_1
PROXY = fleet.OVH_VPS_PROXY_1
STORAGE = fleet.OVH_DEDICATED_STORAGE_1
BATCH_1 = fleet.OVH_BATCH_1
BATCH_2 = fleet.OVH_BATCH_2
MAIL_IP = MAIL.ips[0]
ZONE = "e2e.test"
READ_TOOLS = (
    "ovh_list_ips", "ovh_firewall_rules", "ovh_ssh_keys", "ovh_snapshots",
    "ovh_dns_records", "ovh_billing", "ovh_invoices",
)


class OvhReadToolsLeaveNoAudit(ProductBug):
    """The OVH read tools answer without writing an audit entry."""


class CloudSnapshotsUnreachable(ProductBug):
    """ovh_snapshots cannot list snapshots for a Public Cloud instance."""


def _seed_account(providers) -> dict[str, str]:
    fleet.seed_provider_fleet(providers, hetzner=False)
    ovh = providers.ovh
    ovh.seed_ip_block(f"{MAIL_IP}/32", ip_type="vps", routed_to=MAIL.service_name)
    ovh.seed_firewall(MAIL_IP, rules=[SeedFirewallRule(0, "permit", "tcp", "22", "10.0.0.0/8")])
    ovh.seed_dns_zone(ZONE, [
        SeedDnsRecord("A", "www", MAIL_IP),
        SeedDnsRecord("CNAME", "mail", "mail-1.e2e.test."),
    ])
    ovh.seed_account_ssh_key("deploy-key", "ssh-ed25519 AAAAE2EDEPLOY e2e", default=True)
    ovh.seed_bills([
        SeedBill("FR00000001", "2026-07-01", 18.5),
        SeedBill("FR00000002", "2026-08-01", 21.0),
    ])
    ovh.set_usage(current=12.0, forecast=20.0)
    return {
        "vps_snapshot": ovh.seed_vps_snapshot(MAIL.service_name, "before-upgrade"),
        "cloud_snapshot": ovh.seed_cloud_snapshot(PROJECT, "batch-1-snapshot"),
    }


def _mcp_home(journey, level: str):
    from servonaut.config.schema import MCPConfig

    sandbox = journey.new_sandbox(f"mcp-ovh-{level}")
    seeder = HomeSeeder(sandbox.home, api_url=journey.fake_cloud.url)
    seeder.config(mcp=MCPConfig(guard_level=level), ovh=HomeSeeder.ovh_config())
    seeder.cache(fleet.cache_rows(fleet.APP_1), fresh=True)
    return sandbox


def _audit(sandbox) -> list[dict]:
    path: Path = sandbox.home / ".servonaut" / "mcp_audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _mutations(providers) -> list[tuple[str, str]]:
    return [(r["method"], r["api_path"]) for r in providers.mutations("ovh")]


async def test_read_tools_report_the_account_and_change_nothing(
    mcp, journey, fake_cloud, providers
):
    ids = _seed_account(providers)
    sandbox = _mcp_home(journey, "readonly")

    async with mcp(sandbox) as session:
        assert set(READ_TOOLS) <= set(await session.tool_names())
        ips = await session.call("ovh_list_ips")
        rules = await session.call("ovh_firewall_rules", {"ip": MAIL_IP})
        keys = await session.call("ovh_ssh_keys")
        snapshots = await session.call("ovh_snapshots", {"instance_id": MAIL.display_name})
        records = await session.call("ovh_dns_records", {"zone": ZONE, "record_type": "A"})
        billing = await session.call("ovh_billing")
        invoices = await session.call("ovh_invoices", {"limit": 1})

    assert f"{MAIL_IP}/32" in ips and MAIL.service_name in ips and "vps" in ips
    assert "permit" in rules and "tcp" in rules and "10.0.0.0/8" in rules
    assert "deploy-key [default]" in keys and "type=ssh-ed25519" in keys
    assert ids["vps_snapshot"] in snapshots and "before-upgrade" in snapshots
    assert f"DNS records for {ZONE} [A] (1 found)" in records and "www" in records
    assert "mail-1.e2e.test." not in records  # the CNAME is filtered out
    assert "OVH Billing Summary" in billing and "12.0" in billing and "20.0" in billing
    assert "FR00000002" in invoices and "FR00000001" not in invoices  # newest, limit 1
    # The type filter is sent to OVH, and nothing was changed.
    assert providers.requests("ovh", method="GET", path=f"/domain/zone/{ZONE}/record")[0][
        "query"
    ] == {"fieldType": "A"}
    assert providers.mutations("ovh") == []


async def test_read_tools_are_audited(mcp, journey, fake_cloud, providers):
    _seed_account(providers)
    sandbox = _mcp_home(journey, "readonly")

    async with mcp(sandbox) as session:
        await session.call("ovh_list_ips")
        await session.call("ovh_dns_records", {"zone": ZONE})

    audited = [row["tool"] for row in _audit(sandbox)]
    if not {"ovh_list_ips", "ovh_dns_records"} & set(audited):
        raise OvhReadToolsLeaveNoAudit(f"audit tools: {audited}")
    assert {"ovh_list_ips", "ovh_dns_records"} <= set(audited)


async def test_snapshots_of_a_cloud_instance(mcp, journey, fake_cloud, providers):
    ids = _seed_account(providers)
    sandbox = _mcp_home(journey, "readonly")

    async with mcp(sandbox) as session:
        text = await session.call("ovh_snapshots", {"instance_id": BATCH_1.name})

    if "Cannot determine project_id" in text:
        raise CloudSnapshotsUnreachable(text)
    assert ids["cloud_snapshot"] in text


# What each lifecycle tool sends, and the lowest guard level that allows it.
def _lifecycle_calls() -> list[dict[str, Any]]:
    cloud = f"/cloud/project/{PROJECT}/instance"
    return [
        {"tool": "ovh_reboot_instance", "level": "standard",
         "args": {"instance_id": STORAGE.service_name, "provider_type": "dedicated"},
         "request": ("POST", f"/dedicated/server/{STORAGE.service_name}/reboot")},
        {"tool": "ovh_start_instance", "level": "standard",
         "args": {"instance_id": PROXY.service_name, "provider_type": "vps"},
         "request": ("POST", f"/vps/{PROXY.service_name}/start")},
        {"tool": "ovh_stop_instance", "level": "standard",
         "args": {"instance_id": fleet.ovh_cloud_id(BATCH_1), "provider_type": "cloud"},
         "request": ("POST", f"{cloud}/{BATCH_1.instance_id}/stop")},
        {"tool": "ovh_create_instance", "level": "dangerous",
         "args": {"project_id": PROJECT, "name": "batch-3", "flavor_id": flavor_id("d2-2"),
                  "image_id": image_id("Debian 12"), "region": "GRA7"},
         "request": ("POST", cloud)},
        {"tool": "ovh_delete_instance", "level": "dangerous",
         "args": {"project_id": PROJECT, "instance_id": BATCH_2.instance_id},
         "request": ("DELETE", f"{cloud}/{BATCH_2.instance_id}")},
    ]


_ORDER = ("readonly", "standard", "dangerous")


@pytest.mark.parametrize("level", _ORDER)
async def test_lifecycle_tools_follow_the_guard_level(level, mcp, journey, fake_cloud, providers):
    _seed_account(providers)
    sandbox = _mcp_home(journey, level)
    calls = _lifecycle_calls()

    async with mcp(sandbox) as session:
        answers = []
        for call in calls:
            seen = len(_audit(sandbox))
            text = await session.call(call["tool"], call["args"])
            answers.append((call, text, _audit(sandbox)[seen:]))

    expected_requests = []
    for call, text, audit in answers:
        allowed = _ORDER.index(level) >= _ORDER.index(call["level"])
        detail = f"{call['tool']} at {level}: {text!r} {audit}"
        assert len(audit) == 1, detail
        assert audit[0]["tool"] == call["tool"], detail
        if allowed:
            assert not text.startswith(("Blocked", "Error")), detail
            assert audit[0]["allowed"] is True, detail
            expected_requests.append(call["request"])
        else:
            assert text == f"Blocked: Tool '{call['tool']}' not available in {level} mode", detail
            assert audit[0]["allowed"] is False and audit[0]["reason"], detail
    assert _mutations(providers) == expected_requests
    if level == "dangerous":
        create = providers.mutations("ovh")[3]["body"]
        assert create == {"name": "batch-3", "flavorId": flavor_id("d2-2"),
                          "imageId": image_id("Debian 12"), "region": "GRA7"}
        assert providers.ovh.cloud_instance(PROJECT, BATCH_2.instance_id) is None
    if level != "readonly":
        assert providers.ovh.vps_state(PROXY.service_name) == "running"
