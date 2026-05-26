"""Tests for dangerous_tool_floor: 18-pattern regex set and _floor_dangerous helper."""
from __future__ import annotations

import pytest

from servonaut.services.dangerous_tool_floor import (
    DANGEROUS_FLOOR_PATTERNS,
    is_dangerous_floor,
)
from servonaut.services.ai_tool_bridge import _FloorDangerousMixin


# ---------------------------------------------------------------------------
# Pattern compilation
# ---------------------------------------------------------------------------

def test_exactly_18_patterns():
    assert len(DANGEROUS_FLOOR_PATTERNS) == 18


def test_all_patterns_are_compiled_regexes():
    import re
    for pat in DANGEROUS_FLOOR_PATTERNS:
        assert isinstance(pat, re.Pattern), f"Not a compiled regex: {pat!r}"


# ---------------------------------------------------------------------------
# Dangerous tools — should match
# ---------------------------------------------------------------------------

DANGEROUS_TOOL_NAMES = [
    # AWS EC2 lifecycle
    "aws_run_instances",
    "aws_terminate_instance",
    # S3 mutations + presigned URL
    "s3_create_bucket",
    "s3_delete_bucket",
    "s3_delete_object",
    "s3_upload_object",
    "s3_copy_object",
    "s3_move_object",
    "s3_generate_presigned_url",
    # Hetzner lifecycle
    "hetzner_create_server",
    "hetzner_create_ssh_key",
    "hetzner_delete_server",
    "hetzner_delete_ssh_key",
    # OVH lifecycle
    "ovh_create_instance",
    "ovh_delete_instance",
    # Cross-provider destructive
    "deploy",
    "provision",
    "security_scan",
    "run_command",
    "transfer_file",
    "ip_ban_set",
]


@pytest.mark.parametrize("tool_name", DANGEROUS_TOOL_NAMES)
def test_dangerous_tools_match_floor(tool_name: str):
    assert is_dangerous_floor(tool_name), (
        f"Expected {tool_name!r} to match the dangerous-floor patterns"
    )


# ---------------------------------------------------------------------------
# Readonly/standard tools — must NOT match
# ---------------------------------------------------------------------------

SAFE_TOOL_NAMES = [
    "aws_list_regions",
    "aws_list_amis",
    "aws_list_instance_types",
    "aws_list_key_pairs",
    "aws_list_security_groups",
    "aws_list_subnets",
    "aws_start_instance",
    "aws_stop_instance",
    "aws_reboot_instance",
    "s3_list_buckets",
    "s3_list_objects",
    "s3_download_object",
    "hetzner_list_servers",
    "hetzner_list_server_types",
    "hetzner_list_ssh_keys",
    "hetzner_power_on",
    "hetzner_power_off",
    "hetzner_reboot",
    "hetzner_shutdown",
    "ovh_list_ips",
    "ovh_billing",
    "ovh_invoices",
    "ovh_dns_records",
    "ovh_monitoring",
    "ovh_snapshots",
    "ovh_ssh_keys",
    "ovh_firewall_rules",
    "ovh_start_instance",
    "ovh_stop_instance",
    "ovh_reboot_instance",
    "list_instances",
    "get_logs",
    "cloudwatch_top_ips",
    "cloudwatch_list_log_groups",
    "cloudwatch_get_log_events",
    "cloudtrail_lookup_events",
    "ip_ban_list_configs",
    "ip_ban_list_banned",
    "get_server_memory",
    "build_server_memory",
    "refresh_server_memory",
    "list_server_memories",
]


@pytest.mark.parametrize("tool_name", SAFE_TOOL_NAMES)
def test_safe_tools_do_not_match_floor(tool_name: str):
    assert not is_dangerous_floor(tool_name), (
        f"Expected {tool_name!r} NOT to match the dangerous-floor patterns"
    )


# ---------------------------------------------------------------------------
# _floor_dangerous helper on _FloorDangerousMixin
# ---------------------------------------------------------------------------

class _ConcreteFloor(_FloorDangerousMixin):
    """Minimal concrete subclass for testing the mixin."""


@pytest.fixture
def floor():
    return _ConcreteFloor()


def test_floor_dangerous_escalates_when_pattern_matches(floor):
    tier, escalated = floor._floor_dangerous("aws_run_instances", "standard")
    assert tier == "dangerous"
    assert escalated is True


def test_floor_dangerous_no_escalation_when_already_dangerous(floor):
    tier, escalated = floor._floor_dangerous("aws_run_instances", "dangerous")
    assert tier == "dangerous"
    assert escalated is False


def test_floor_dangerous_no_escalation_for_safe_tool(floor):
    tier, escalated = floor._floor_dangerous("aws_list_regions", "readonly")
    assert tier == "readonly"
    assert escalated is False


def test_floor_dangerous_unknown_tool_unchanged(floor):
    tier, escalated = floor._floor_dangerous("nonexistent_tool", "standard")
    assert tier == "standard"
    assert escalated is False


def test_floor_dangerous_run_command_readonly_escalates(floor):
    """run_command sent as readonly from a buggy catalog must escalate."""
    tier, escalated = floor._floor_dangerous("run_command", "readonly")
    assert tier == "dangerous"
    assert escalated is True


def test_floor_dangerous_transfer_file_standard_escalates(floor):
    tier, escalated = floor._floor_dangerous("transfer_file", "standard")
    assert tier == "dangerous"
    assert escalated is True


def test_aito_bridge_has_floor_dangerous_method():
    """AIToolBridge must inherit _floor_dangerous via _FloorDangerousMixin."""
    from servonaut.services.ai_tool_bridge import AIToolBridge
    assert hasattr(AIToolBridge, "_floor_dangerous"), (
        "AIToolBridge must expose _floor_dangerous (via _FloorDangerousMixin)"
    )
