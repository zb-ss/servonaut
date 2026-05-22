"""Tests for service-gated tool exposure in ``mcp_tool_list``.

The MCP server drops tools from ``tools/list`` when their backing capability
isn't available, so agents querying the catalogue only see what's callable:

- OVH / Hetzner tools     — gated on the provider service being wired up.
- ``ip_ban_*`` tools      — gated on at least one ban target being configured.
- ``*_server_memory*``    — gated on the memory subsystem being enabled.
- CloudWatch / CloudTrail — never gated (AWS is the base provider).
- Session / relay tools   — never gated (login state changes mid-session).
"""

from __future__ import annotations

from servonaut.mcp.tool_schemas import TOOL_SCHEMAS, mcp_tool_list

MEMORY_TOOLS = {
    "get_server_memory", "build_server_memory",
    "refresh_server_memory", "list_server_memories",
}
ALWAYS_ON = {
    "list_instances", "run_command", "check_status",
    "cloudwatch_top_ips", "cloudtrail_lookup_events",
    "whoami", "api_request", "relay_status",
}


def _names(**gates) -> set:
    return {t.name for t in mcp_tool_list(**gates)}


def test_all_gates_open_exposes_everything():
    names = _names()
    assert names == set(TOOL_SCHEMAS.keys())


def test_memory_gate_drops_only_memory_tools():
    on = _names(have_memory=True)
    off = _names(have_memory=False)
    assert MEMORY_TOOLS <= on
    assert not (MEMORY_TOOLS & off)
    # Dropping the memory gate removes exactly the four memory tools.
    assert on - off == MEMORY_TOOLS


def test_ovh_gate_drops_only_ovh_tools():
    off = _names(have_ovh=False)
    assert not any(n.startswith("ovh_") for n in off)
    assert "list_instances" in off and "hetzner_list_servers" in off


def test_hetzner_gate_drops_only_hetzner_tools():
    off = _names(have_hetzner=False)
    assert not any(n.startswith("hetzner_") for n in off)
    assert "list_instances" in off and "ovh_billing" in off


def test_ip_ban_gate_drops_only_ip_ban_tools():
    off = _names(have_ip_ban=False)
    assert not any(n.startswith("ip_ban_") for n in off)
    # CloudWatch/CloudTrail share the security theme but are NOT gated.
    assert "cloudwatch_top_ips" in off and "cloudtrail_lookup_events" in off


def test_cloudwatch_cloudtrail_and_core_never_gated():
    # Close every optional gate at once; AWS-base + session tools survive.
    minimal = _names(
        have_ovh=False, have_hetzner=False,
        have_ip_ban=False, have_memory=False,
    )
    assert ALWAYS_ON <= minimal


def test_only_required_service_tools_are_gateable():
    # Any tool without a required_service must appear in every configuration.
    ungated = {
        name for name, spec in TOOL_SCHEMAS.items()
        if not spec.get("required_service")
    }
    minimal = _names(
        have_ovh=False, have_hetzner=False,
        have_ip_ban=False, have_memory=False,
    )
    assert ungated <= minimal
