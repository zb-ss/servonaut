"""Journey: an MCP client manages Hetzner Cloud through ``servonaut --mcp``.

The server runs as a child process against the local Hetzner stand-in. At the
readonly level the inventory tools answer and every tool that changes
something is refused before any request reaches Hetzner. The standard level
adds power management and key registration; creating and deleting servers
(and deleting keys) needs the dangerous level. Each allowed call sends
exactly one change to Hetzner, and every call, allowed or refused, leaves
one audit entry.

A last journey checks the product's own switch for the Hetzner API address.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from e2e.harness import fleet
from e2e.harness import provider_redirects as redirects
from e2e.harness.known_bugs import ProductBug
from e2e.harness.seed import HomeSeeder

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

DEPLOY_KEY = ("e2e-deploy", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2Edeploykeyonly00000000000000000 deploy")
CI_KEY = ("e2e-ci", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2Ecikeyonly0000000000000000000000 ci")
# Mutating tools with arguments that would succeed at a permissive level.
MUTATIONS = {
    "hetzner_power_on": {"identifier": str(fleet.HZ_BUILD_1.server_id)},
    "hetzner_power_off": {"identifier": str(fleet.HZ_CACHE_1.server_id)},
    "hetzner_shutdown": {"identifier": str(fleet.HZ_CACHE_1.server_id)},
    "hetzner_reboot": {"identifier": str(fleet.HZ_CACHE_1.server_id)},
    "hetzner_create_ssh_key": {"name": CI_KEY[0], "public_key": CI_KEY[1]},
    "hetzner_delete_ssh_key": {"identifier": DEPLOY_KEY[0]},
    "hetzner_create_server": {
        "name": "web-2", "server_type": "cx32", "image": "debian-12",
        "location": "nbg1", "ssh_keys": [DEPLOY_KEY[0]],
    },
    "hetzner_delete_server": {"identifier": fleet.HZ_CACHE_1.name},
}
STANDARD = {
    "hetzner_power_on", "hetzner_power_off", "hetzner_shutdown",
    "hetzner_reboot", "hetzner_create_ssh_key",
}


class HetznerEndpointOverrideIgnored(ProductBug):
    """The Hetzner client still targets the public API despite the override."""


def _home(journey, level: str) -> tuple:
    from servonaut.config.schema import MCPConfig

    sandbox = journey.new_sandbox(f"mcp-hetzner-{level}")
    seeder = HomeSeeder(sandbox.home, api_url=journey.fake_cloud.url)
    seeder.config(hetzner=seeder.hetzner_config(), mcp=MCPConfig(guard_level=level))
    seeder.cache(fleet.cache_rows(fleet.APP_1), fresh=True)
    return sandbox, sandbox.home / ".servonaut" / "mcp_audit.jsonl"


def _audit(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _seed_project(providers) -> None:
    providers.hetzner.seed_servers(fleet.HETZNER_FLEET)
    providers.hetzner.seed_ssh_key(*DEPLOY_KEY)


async def test_readonly_lists_and_refuses_every_change(mcp, journey, fake_cloud, providers):
    _seed_project(providers)
    sandbox, audit = _home(journey, "readonly")

    async with mcp(sandbox) as session:
        listed = await session.call("hetzner_list_servers")
        types = await session.call("hetzner_list_server_types")
        keys = await session.call("hetzner_list_ssh_keys")
        refused = {tool: await session.call(tool, args) for tool, args in MUTATIONS.items()}

    assert "Hetzner Cloud servers (2 total):" in listed
    for host in fleet.HETZNER_FLEET:
        assert host.name in listed and str(host.server_id) in listed
    assert fleet.HZ_CACHE_1.public_ip in listed
    assert "cx23" in types and "cax11" in types
    assert DEPLOY_KEY[0] in keys
    for tool, text in refused.items():
        assert text == f"Blocked: Tool '{tool}' not available in readonly mode", (tool, text)
    assert providers.mutations("hetzner") == []

    rows = _audit(audit)
    assert [(r["tool"], r["allowed"]) for r in rows] == [
        ("hetzner_list_servers", True),
        ("hetzner_list_server_types", True),
        ("hetzner_list_ssh_keys", True),
        *((tool, False) for tool in MUTATIONS),
    ]
    # The public key never lands in the audit trail.
    assert all("public_key" not in r["args"] for r in rows)


async def test_standard_allows_power_but_not_create_or_delete(mcp, journey, fake_cloud, providers):
    _seed_project(providers)
    sandbox, audit = _home(journey, "standard")

    async with mcp(sandbox) as session:
        answers = {tool: await session.call(tool, args) for tool, args in MUTATIONS.items()}

    build, cache = fleet.HZ_BUILD_1.server_id, fleet.HZ_CACHE_1.server_id
    assert answers["hetzner_power_on"] == f"Hetzner server '{build}': started."
    assert answers["hetzner_reboot"] == f"Hetzner server '{cache}': reboot sent."
    assert answers["hetzner_create_ssh_key"].startswith(f"Registered SSH key '{CI_KEY[0]}'")
    for tool in set(MUTATIONS) - STANDARD:
        assert answers[tool] == f"Blocked: Tool '{tool}' not available in standard mode"

    # One request per allowed tool, in call order; nothing created or deleted.
    assert [(e["method"], e["api_path"]) for e in providers.mutations("hetzner")] == [
        ("POST", f"/servers/{build}/actions/poweron"),
        ("POST", f"/servers/{cache}/actions/poweroff"),
        ("POST", f"/servers/{cache}/actions/shutdown"),
        ("POST", f"/servers/{cache}/actions/reboot"),
        ("POST", "/ssh_keys"),
    ]
    assert providers.hetzner.key_named(DEPLOY_KEY[0]) is not None
    assert [(r["tool"], r["allowed"]) for r in _audit(audit)] == [
        (tool, tool in STANDARD) for tool in MUTATIONS
    ]


async def test_dangerous_creates_and_deletes_once(mcp, journey, fake_cloud, providers):
    _seed_project(providers)
    sandbox, audit = _home(journey, "dangerous")
    key_id = providers.hetzner.key_named(DEPLOY_KEY[0])["id"]

    async with mcp(sandbox) as session:
        created = await session.call("hetzner_create_server", MUTATIONS["hetzner_create_server"])
        deleted = await session.call("hetzner_delete_server", MUTATIONS["hetzner_delete_server"])
        key_gone = await session.call("hetzner_delete_ssh_key", MUTATIONS["hetzner_delete_ssh_key"])
        missing = await session.call("hetzner_delete_server", {"identifier": "no-such-server"})
        listed = await session.call("hetzner_list_servers")

    assert created.startswith("Created Hetzner server 'web-2'")
    assert deleted == f"Deleted Hetzner server '{fleet.HZ_CACHE_1.name}'."
    assert key_gone == f"Deleted Hetzner SSH key '{DEPLOY_KEY[0]}'."
    assert "Server not found: no-such-server" in missing
    assert "web-2" in listed and fleet.HZ_CACHE_1.name not in listed

    changes = [(e["method"], e["api_path"]) for e in providers.mutations("hetzner")]
    assert changes == [
        ("POST", "/servers"),
        ("DELETE", f"/servers/{fleet.HZ_CACHE_1.server_id}"),
        ("DELETE", f"/ssh_keys/{key_id}"),
    ]
    body = providers.requests("hetzner", method="POST", path="/servers")[0]["body"]
    assert (body["server_type"], body["image"], body["location"], body["ssh_keys"]) == (
        "cx32", "debian-12", "nbg1", [key_id],
    )
    rows = _audit(audit)
    assert [(r["tool"], r["allowed"]) for r in rows] == [
        ("hetzner_create_server", True),
        ("hetzner_delete_server", True),
        ("hetzner_delete_ssh_key", True),
        ("hetzner_delete_server", False),
        ("hetzner_list_servers", True),
    ]
    assert "Server not found: no-such-server" in rows[3]["reason"]


async def test_hetzner_api_address_can_be_overridden(mcp, journey, fake_cloud, providers):
    providers.hetzner.seed_servers(fleet.HETZNER_FLEET)
    # Only the product's own switch: no rewrite of the client library default.
    journey.env_overrides[redirects.ENV_REDIRECTS] = json.dumps({"ovh": providers.ovh_url})
    assert journey.env_overrides[redirects.HETZNER_URL_ENV] == providers.hetzner_url
    assert os.environ[redirects.HETZNER_URL_ENV] == providers.hetzner_url
    sandbox, _ = _home(journey, "readonly")

    async with mcp(sandbox) as session:
        listed = await session.call("hetzner_list_servers")

    escapes = journey.take_escapes()
    if escapes and not providers.requests("hetzner"):
        raise HetznerEndpointOverrideIgnored(
            f"requests went to {sorted({e['target'] for e in escapes})}: {listed[:120]!r}"
        )
    assert escapes == []
    assert providers.requests("hetzner", method="GET", path="/servers")
    assert fleet.HZ_CACHE_1.name in listed
