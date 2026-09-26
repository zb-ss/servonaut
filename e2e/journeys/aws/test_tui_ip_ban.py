"""Journey: ban and unban an address with each of the three ban methods.

The user opens the IP Ban Manager, picks a ban configuration (a WAF IP set,
a security group or a network ACL), bans an address, sees it listed with its
ban count, and unbans it. A second ban of a listed address is refused. Each
attempt, refused or not, lands in the audit trail on disk and in the audit
panel, and the AWS resource itself changes accordingly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

import pytest
from textual.widgets import RichLog

from e2e.harness import fleet
from e2e.harness.controls import choose, table_text

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

ADDRESS = "9.9.9.9"
CIDR = f"{ADDRESS}/32"


@dataclass(frozen=True)
class BanMethod:
    config_name: str
    method: str
    banned: str  # toasts, after the address
    unbanned: str
    already: str


METHODS = {
    "waf": BanMethod(
        "edge-waf", "waf", "via WAF IP set", "from WAF IP set", "already banned in WAF"
    ),
    "security_group": BanMethod(
        "web-sg",
        "security_group",
        "via security group",
        "from security group",
        "already banned in security group",
    ),
    "nacl": BanMethod(
        "subnet-nacl", "nacl", "via NACL rule 100", "from NACL", "already banned in NACL"
    ),
}


def _seed_targets(moto) -> tuple[list, dict[str, Callable[[], list[str]]]]:
    """One ban target per method; returns the configs and readers of AWS state."""
    from servonaut.config.schema import IPBanConfig

    ip_set = moto.seed_waf_ip_set("e2e-blocklist")
    group_id = moto.seed_security_group("e2e-web")
    nacl_id = moto.seed_network_acl()
    configs = [
        IPBanConfig(
            name="edge-waf",
            method="waf",
            region="us-east-1",
            ip_set_id=ip_set["Id"],
            ip_set_name=ip_set["Name"],
        ),
        IPBanConfig(
            name="web-sg", method="security_group", region="us-east-1", security_group_id=group_id
        ),
        IPBanConfig(name="subnet-nacl", method="nacl", region="us-east-1", nacl_id=nacl_id),
    ]
    in_aws = {
        "edge-waf": lambda: moto.waf_addresses(ip_set),
        "web-sg": lambda: [
            r["CidrIp"] for r in moto.ingress_ranges(group_id) if r["Description"] == "servonaut-ban"
        ],
        "subnet-nacl": lambda: sorted(moto.nacl_denies(nacl_id).values()),
    }
    return configs, in_aws


def _banned_rows(t) -> list[tuple[str, ...]]:
    return table_text(t, "#banned_table")


def _audit_panel(t) -> str:
    return t.log_text(t.on_screen("#audit_log", RichLog))


@pytest.mark.parametrize("kind", list(METHODS))
async def test_ban_and_unban_with_audit_trail(tui, seed, moto, kind):
    chosen = METHODS[kind]
    configs, in_aws = _seed_targets(moto)
    seed.config(ip_ban_configs=configs)
    seed.cache(fleet.cache_rows(), fresh=True)
    audit_file = seed.data_dir / "ip_ban_audit.json"

    async with tui() as t:
        await t.nav("nav_ip_ban")
        await t.wait_for_screen("IPBanScreen")
        assert "No audit log entries yet." in _audit_panel(t)
        await choose(t, "#ban_config_selector", f"{chosen.config_name} ({chosen.method})")
        await t.wait_for_toast(f"No IPs currently banned in '{chosen.config_name}'")

        await t.fill("#ip_input", ADDRESS)
        await t.click("#btn_ban")
        await t.wait_for_toast(f"^Banned {ADDRESS} {chosen.banned}$", severity="information")
        await t.wait_until(
            lambda: _banned_rows(t) == [(CIDR, "1", chosen.config_name, chosen.method)],
            desc="banned address listed",
        )
        assert in_aws[chosen.config_name]() == [CIDR]
        await t.wait_until(
            lambda: f"BAN {ADDRESS} via {chosen.config_name}" in _audit_panel(t),
            desc="audit panel shows the ban",
        )

        # Banning it again is refused, and the refusal is audited too.
        await t.click("#btn_ban")
        await t.wait_for_toast(f"^{ADDRESS} {chosen.already}$", severity="error")
        assert in_aws[chosen.config_name]() == [CIDR]

        await t.click("#btn_unban")
        await t.wait_for_toast(f"^Unbanned {ADDRESS} {chosen.unbanned}$", severity="information")
        await t.wait_until(lambda: _banned_rows(t) == [], desc="banned list emptied")
        assert in_aws[chosen.config_name]() == []

    trail = json.loads(audit_file.read_text())
    assert [(e["action"], e["ip_address"], e["config"], e["success"]) for e in trail] == [
        ("ban", ADDRESS, chosen.config_name, True),
        ("ban", ADDRESS, chosen.config_name, False),
        ("unban", ADDRESS, chosen.config_name, True),
    ]
    # The other targets were never touched.
    for name, reader in in_aws.items():
        if name != chosen.config_name:
            assert reader() == [], name
