"""Tests for PR5' _LOCAL_TOOL_HANDLERS dispatch routing.

Verifies that every tool added in PR5' resolves to the expected
ServonautTools method name and that the bridge's _execute_local path
invokes the right handler.
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.ai_tool_bridge import (
    AIToolBridge,
    ToolCall,
    _LOCAL_TOOL_HANDLERS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run(coro):
    return asyncio.run(coro)


def _make_bridge_with_tools(tool_methods: dict) -> tuple:
    """Return (bridge, servonaut_tools_mock) with all external deps mocked.

    ``tool_methods`` maps method_name -> return value (str).
    """
    api = MagicMock()
    api.post = AsyncMock(return_value={})

    relay = MagicMock()
    relay.execute = AsyncMock(return_value=MagicMock(status="success", output="ok"))

    audit = MagicMock()
    audit.log = MagicMock()

    confirm = AsyncMock(return_value=True)
    auth = MagicMock()
    auth.has_dangerous_ai_tools = True

    tools = MagicMock()
    for method_name, ret_val in tool_methods.items():
        setattr(tools, method_name, AsyncMock(return_value=ret_val))

    bridge = AIToolBridge(
        api_client=api,
        relay_executors=relay,
        mcp_audit=audit,
        confirm_callback=confirm,
        auth_service=auth,
        servonaut_tools=tools,
    )
    return bridge, tools


# ---------------------------------------------------------------------------
# Map-level assertion: every new tool in _LOCAL_TOOL_HANDLERS points to a
# real ServonautTools method.
# ---------------------------------------------------------------------------

_ORIGINAL_TOOLS = {"list_instances", "describe_instance"}


class TestLocalToolHandlerMapCompleteness:
    def test_all_new_handlers_have_servonaut_tools_method(self):
        """Every tool added in PR5' must have a matching ServonautTools method."""
        from servonaut.mcp.tools import ServonautTools

        st_methods = {
            m for m in dir(ServonautTools)
            if not m.startswith("_") and callable(getattr(ServonautTools, m))
        }
        missing = []
        for tool_name, method_name in _LOCAL_TOOL_HANDLERS.items():
            if tool_name in _ORIGINAL_TOOLS:
                continue
            if method_name not in st_methods:
                missing.append((tool_name, method_name))

        assert not missing, (
            f"Tools in _LOCAL_TOOL_HANDLERS whose target method is missing "
            f"from ServonautTools: {missing}"
        )

    def test_new_entries_count_is_83(self):
        """Local-handler entries beyond the 2 originals.

        PR5' seeded 57; incident-response tools added the rest:
        Group A (web_traffic_summary, fleet_health_snapshot, enrich_ips,
        db_processlist, db_top_queries) → 62; describe_ingress_path → 63;
        Group C waf_rate_rule_set + block_ip → 65; rds_metrics → 66;
        db_setup_scan + db_setup_save → 68; db_setup_remove → 69; agent
        findings (remember_server_finding, recall_server_findings) → 71;
        docker container probes (docker_ps, docker_stats, docker_logs,
        docker_events_summary) → 75; system-health probes (journal_errors,
        tls_cert_check, auth_log_summary) → 78; docker_log_summary → 79;
        breadth probes (disk_usage, pending_updates) → 81; security_audit
        → 82; service_state → 83. All dispatch locally (CLI's own SSH /
        boto3 / network / memory surface); the server catalog mirror is
        tracked separately (see test_catalog_drift::CATALOG_PENDING_SERVER).
        """
        new_entries = {k for k in _LOCAL_TOOL_HANDLERS if k not in _ORIGINAL_TOOLS}
        assert len(new_entries) == 83, (
            f"Expected 83 new entries, got {len(new_entries)}: {sorted(new_entries)}"
        )


# ---------------------------------------------------------------------------
# Parametrised dispatch tests -- sample across the full set
# ---------------------------------------------------------------------------

# fmt: off
_DISPATCH_CASES = [
    # (tool_name, expected_method, mock_return)
    # --- AWS describe ---
    ("aws_list_regions",           "aws_list_regions",           "us-east-1\nus-west-2"),
    ("aws_list_amis",              "aws_list_amis",              "ami-abc"),
    ("aws_list_instance_types",    "aws_list_instance_types",    "t3.micro"),
    ("aws_list_key_pairs",         "aws_list_key_pairs",         "mykey"),
    ("aws_list_subnets",           "aws_list_subnets",           "subnet-123"),
    ("aws_list_security_groups",   "aws_list_security_groups",   "sg-456"),
    # --- AWS lifecycle ---
    ("aws_start_instance",         "aws_start_instance",         "started"),
    ("aws_stop_instance",          "aws_stop_instance",          "stopped"),
    ("aws_reboot_instance",        "aws_reboot_instance",        "rebooted"),
    ("aws_run_instances",          "aws_run_instances",          "launched"),
    ("aws_terminate_instance",     "aws_terminate_instance",     "terminated"),
    # --- S3 read ---
    ("s3_list_buckets",            "s3_list_buckets",            "my-bucket"),
    ("s3_list_objects",            "s3_list_objects",            "object.txt"),
    # --- S3 mutations ---
    ("s3_create_bucket",           "s3_create_bucket",           "created"),
    ("s3_delete_bucket",           "s3_delete_bucket",           "deleted"),
    ("s3_upload_object",           "s3_upload_object",           "uploaded"),
    ("s3_delete_object",           "s3_delete_object",           "deleted"),
    ("s3_copy_object",             "s3_copy_object",             "copied"),
    ("s3_move_object",             "s3_move_object",             "moved"),
    ("s3_generate_presigned_url",  "s3_generate_presigned_url",  "https://example.com/presigned"),
    ("s3_download_object",         "s3_download_object",         "downloaded"),
    # --- AWS observability ---
    ("cloudwatch_list_log_groups", "cloudwatch_list_log_groups", "/aws/lambda/fn"),
    ("cloudwatch_get_log_events",  "cloudwatch_get_log_events",  "log event"),
    ("cloudwatch_top_ips",         "cloudwatch_top_ips",         "1.2.3.4"),
    ("cloudtrail_lookup_events",   "cloudtrail_lookup_events",   "event"),
    ("ip_ban_list_configs",        "ip_ban_list_configs",        "config"),
    ("ip_ban_list_banned",         "ip_ban_list_banned",         "banned ip"),
    ("ip_ban_set",                 "ip_ban_set",                 "banned"),
    # --- Log fetch ---
    ("get_logs",                   "get_logs",                   "log output"),
    # --- Hetzner read + power management ---
    ("hetzner_list_servers",       "hetzner_list_servers",       "server1"),
    ("hetzner_list_server_types",  "hetzner_list_server_types",  "cx11"),
    ("hetzner_list_ssh_keys",      "hetzner_list_ssh_keys",      "key1"),
    ("hetzner_power_on",           "hetzner_power_on",           "on"),
    ("hetzner_power_off",          "hetzner_power_off",          "off"),
    ("hetzner_shutdown",           "hetzner_shutdown",           "shutdown"),
    ("hetzner_reboot",             "hetzner_reboot",             "rebooted"),
    ("hetzner_create_ssh_key",     "hetzner_create_ssh_key",     "created"),
    # --- Hetzner lifecycle (dangerous) ---
    ("hetzner_create_server",      "hetzner_create_server",      "created"),
    ("hetzner_delete_server",      "hetzner_delete_server",      "deleted"),
    ("hetzner_delete_ssh_key",     "hetzner_delete_ssh_key",     "deleted"),
    # --- OVH read + lifecycle ---
    ("ovh_monitoring",             "ovh_monitoring",             "metrics"),
    ("ovh_list_ips",               "ovh_list_ips",               "1.2.3.4"),
    ("ovh_firewall_rules",         "ovh_firewall_rules",         "rules"),
    ("ovh_ssh_keys",               "ovh_ssh_keys",               "key"),
    ("ovh_snapshots",              "ovh_snapshots",              "snap"),
    ("ovh_dns_records",            "ovh_dns_records",            "records"),
    ("ovh_billing",                "ovh_billing",                "billing"),
    ("ovh_invoices",               "ovh_invoices",               "invoice"),
    ("ovh_start_instance",         "ovh_start_instance",         "started"),
    ("ovh_stop_instance",          "ovh_stop_instance",          "stopped"),
    ("ovh_reboot_instance",        "ovh_reboot_instance",        "rebooted"),
    # --- OVH lifecycle (dangerous) ---
    ("ovh_create_instance",        "ovh_create_instance",        "created"),
    ("ovh_delete_instance",        "ovh_delete_instance",        "deleted"),
    # --- Memory ---
    ("get_server_memory",          "get_server_memory",          "memory data"),
    ("list_server_memories",       "list_server_memories",       "memories"),
    ("build_server_memory",        "build_server_memory",        "built"),
    ("refresh_server_memory",      "refresh_server_memory",      "refreshed"),
]
# fmt: on


@pytest.mark.parametrize("tool_name,expected_method,mock_return", _DISPATCH_CASES)
def test_dispatch_routes_to_correct_method(tool_name, expected_method, mock_return):
    """Bridge dispatches each tool name to the right ServonautTools method."""
    bridge, tools_mock = _make_bridge_with_tools({expected_method: mock_return})
    call = ToolCall(
        tool_call_id="tc-1",
        tool=tool_name,
        args={},
        # Use dangerous for tests so entitlement gate does not block
        guard_level="dangerous",
        conversation_id="conv-1",
    )
    result = run(bridge.handle_tool_call(call))

    # Method was called
    getattr(tools_mock, expected_method).assert_called_once()
    # Result status is ok and content matches
    assert result.status == "ok"
    assert result.result == mock_return


def test_unknown_tool_returns_error():
    """A tool not in any dispatch map returns status='error' with skipped=True."""
    bridge, _ = _make_bridge_with_tools({})
    call = ToolCall(
        tool_call_id="tc-unknown",
        tool="completely_unknown_tool_xyz",
        args={},
        guard_level="readonly",
        conversation_id="conv-1",
    )
    result = run(bridge.handle_tool_call(call))
    assert result.status == "error"
    assert result.skipped is True
