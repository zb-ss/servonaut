"""Tests for MCP AWS EC2 tools — lifecycle (5) + describe helpers (6).

Covers the per-tool matrix from the workflow plan §5:
1. Happy path
2. Guard-tier enforcement (blocked below required tier)
3. Validator rejection (ValueError from service)
4. API error (generic Exception from service)
5. Audit-on-success (log called once with success=True)

Special tests:
- aws_run_instances: 8 validator-failure cases
- aws_list_regions: empty bootstrap_region falls back to "us-east-1"
- aws_terminate_instance: blocked at STANDARD tier
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, call

import pytest

from servonaut.config.schema import AppConfig, MCPConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tools import ServonautTools


# ---------------------------------------------------------------------------
# Shared factory — mirrors test_mcp_tools.make_tools, adds hetzner/ovh OS mocks
# ---------------------------------------------------------------------------

def make_tools(
    guard_level=GuardLevel.STANDARD,
    aws_service=None,
    hetzner_os_service=None,
    ovh_os_service=None,
    aws_os_service=None,
):
    config = AppConfig(mcp=MCPConfig(guard_level=guard_level))
    config_manager = MagicMock()
    config_manager.get.return_value = config

    if aws_service is None:
        aws_service = MagicMock()
        aws_service.fetch_instances_cached = AsyncMock(return_value=[])

    custom_server_service = MagicMock()
    custom_server_service.list_as_instances.return_value = []

    ssh_service = MagicMock()
    ssh_service.get_key_path.return_value = "~/.ssh/test.pem"
    ssh_service.discover_key.return_value = None
    ssh_service.build_ssh_command.return_value = ["ssh", "host"]

    connection_service = MagicMock()
    connection_service.resolve_profile.return_value = None
    connection_service.get_target_host.return_value = "1.2.3.4"
    connection_service.get_proxy_args.return_value = []
    connection_service.get_proxy_jump_string.return_value = None

    scp_service = MagicMock()
    scp_service.execute_transfer = AsyncMock(return_value=(0, "", ""))

    ovh_service = MagicMock()
    ovh_service.fetch_instances_cached = AsyncMock(return_value=[])

    guard = CommandGuard(config.mcp)
    audit = MagicMock()
    audit.log = MagicMock()

    tools = ServonautTools(
        config_manager, aws_service, custom_server_service, MagicMock(),
        ssh_service, connection_service, scp_service,
        guard, audit,
        ovh_service=ovh_service,
        aws_object_storage_service=aws_os_service,
        hetzner_object_storage_service=hetzner_os_service,
        ovh_object_storage_service=ovh_os_service,
    )
    return tools


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# aws_start_instance
# ---------------------------------------------------------------------------

class TestAwsStartInstance:
    def _make_aws(self):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        svc.start_instance = AsyncMock()
        return svc

    def test_happy_path(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_service=aws)
        result = run(tools.aws_start_instance("i-abc123", "us-east-1"))
        assert "start sent" in result
        assert "i-abc123" in result
        assert "us-east-1" in result

    def test_blocked_at_readonly(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_start_instance("i-abc123", "us-east-1"))
        assert result.startswith("Blocked:")
        tools._audit.log.assert_called_once()
        assert tools._audit.log.call_args[0][3] is False

    def test_validator_rejection(self):
        aws = self._make_aws()
        aws.start_instance = AsyncMock(side_effect=ValueError("Invalid instance ID"))
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_service=aws)
        result = run(tools.aws_start_instance("bad-id", "us-east-1"))
        assert result.startswith("Error:")
        tools._audit.log.assert_called_once()
        reason = tools._audit.log.call_args[0][4]
        assert reason.startswith("validation:")

    def test_api_error(self):
        aws = self._make_aws()
        aws.start_instance = AsyncMock(side_effect=Exception("ConnectionError"))
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_service=aws)
        result = run(tools.aws_start_instance("i-abc123", "us-east-1"))
        assert "Error" in result
        reason = tools._audit.log.call_args[0][4]
        assert reason.startswith("api_error:")

    def test_audit_on_success(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_service=aws)
        run(tools.aws_start_instance("i-abc123", "us-east-1"))
        tools._audit.log.assert_called_once()
        call_args = tools._audit.log.call_args[0]
        assert call_args[0] == "aws_start_instance"
        assert call_args[3] is True


# ---------------------------------------------------------------------------
# aws_stop_instance
# ---------------------------------------------------------------------------

class TestAwsStopInstance:
    def _make_aws(self):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        svc.stop_instance = AsyncMock()
        return svc

    def test_happy_path(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_service=aws)
        result = run(tools.aws_stop_instance("i-abc123", "us-east-1"))
        assert "stop sent" in result
        assert "i-abc123" in result

    def test_blocked_at_readonly(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_stop_instance("i-abc123", "us-east-1"))
        assert result.startswith("Blocked:")
        assert tools._audit.log.call_args[0][3] is False

    def test_validator_rejection(self):
        aws = self._make_aws()
        aws.stop_instance = AsyncMock(side_effect=ValueError("Invalid region"))
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_service=aws)
        result = run(tools.aws_stop_instance("i-abc123", "bad-region"))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        aws = self._make_aws()
        aws.stop_instance = AsyncMock(side_effect=Exception("Timeout"))
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_service=aws)
        result = run(tools.aws_stop_instance("i-abc123", "us-east-1"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_service=aws)
        run(tools.aws_stop_instance("i-abc123", "us-east-1"))
        assert tools._audit.log.call_args[0][0] == "aws_stop_instance"
        assert tools._audit.log.call_args[0][3] is True


# ---------------------------------------------------------------------------
# aws_reboot_instance
# ---------------------------------------------------------------------------

class TestAwsRebootInstance:
    def _make_aws(self):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        svc.reboot_instance = AsyncMock()
        return svc

    def test_happy_path(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_service=aws)
        result = run(tools.aws_reboot_instance("i-abc123", "us-east-1"))
        assert "reboot sent" in result

    def test_blocked_at_readonly(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_reboot_instance("i-abc123", "us-east-1"))
        assert result.startswith("Blocked:")

    def test_validator_rejection(self):
        aws = self._make_aws()
        aws.reboot_instance = AsyncMock(side_effect=ValueError("bad ID"))
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_service=aws)
        result = run(tools.aws_reboot_instance("bad", "us-east-1"))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        aws = self._make_aws()
        aws.reboot_instance = AsyncMock(side_effect=Exception("Network error"))
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_service=aws)
        result = run(tools.aws_reboot_instance("i-abc123", "us-east-1"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_service=aws)
        run(tools.aws_reboot_instance("i-abc123", "us-east-1"))
        assert tools._audit.log.call_args[0][0] == "aws_reboot_instance"
        assert tools._audit.log.call_args[0][3] is True


# ---------------------------------------------------------------------------
# aws_terminate_instance
# ---------------------------------------------------------------------------

class TestAwsTerminateInstance:
    def _make_aws(self):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        svc.terminate_instance = AsyncMock()
        return svc

    def test_happy_path(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, aws_service=aws)
        result = run(tools.aws_terminate_instance("i-abc123", "us-east-1"))
        assert "terminate" in result.lower()
        assert "i-abc123" in result

    def test_blocked_at_standard(self):
        """aws_terminate_instance is dangerous — must be blocked at STANDARD."""
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_service=aws)
        result = run(tools.aws_terminate_instance("i-abc123", "us-east-1"))
        assert result.startswith("Blocked:")
        assert tools._audit.log.call_args[0][3] is False
        reason = tools._audit.log.call_args[0][4]
        assert "standard" in reason.lower()

    def test_blocked_at_readonly(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_terminate_instance("i-abc123", "us-east-1"))
        assert result.startswith("Blocked:")

    def test_validator_rejection(self):
        aws = self._make_aws()
        aws.terminate_instance = AsyncMock(side_effect=ValueError("bad instance id"))
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, aws_service=aws)
        result = run(tools.aws_terminate_instance("bad", "us-east-1"))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        aws = self._make_aws()
        aws.terminate_instance = AsyncMock(side_effect=Exception("EC2 error"))
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, aws_service=aws)
        result = run(tools.aws_terminate_instance("i-abc123", "us-east-1"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, aws_service=aws)
        run(tools.aws_terminate_instance("i-abc123", "us-east-1"))
        assert tools._audit.log.call_args[0][0] == "aws_terminate_instance"
        assert tools._audit.log.call_args[0][3] is True


# ---------------------------------------------------------------------------
# aws_run_instances
# ---------------------------------------------------------------------------

VALID_RUN_KWARGS = dict(
    region="us-east-1",
    ami_id="ami-0abc1234",
    instance_type="t3.medium",
    key_name="prod-key",
    subnet_id="subnet-0abc1234",
    security_group_ids=["sg-0abc1234"],
    name_tag="test-instance",
    count=1,
)


class TestAwsRunInstances:
    def _make_aws(self, launched=None):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        if launched is None:
            launched = [{"id": "i-new001", "state": "pending", "type": "t3.medium", "region": "us-east-1"}]
        svc.run_instances = AsyncMock(return_value=launched)
        return svc

    def test_happy_path_returns_json(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, aws_service=aws)
        result = run(tools.aws_run_instances(**VALID_RUN_KWARGS))
        data = json.loads(result)
        assert data["count"] == 1
        assert data["region"] == "us-east-1"
        assert len(data["instances"]) == 1
        assert data["instances"][0]["id"] == "i-new001"

    def test_blocked_at_standard(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_service=aws)
        result = run(tools.aws_run_instances(**VALID_RUN_KWARGS))
        assert result.startswith("Blocked:")
        reason = tools._audit.log.call_args[0][4]
        assert "standard" in reason.lower()

    def test_blocked_at_readonly(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_run_instances(**VALID_RUN_KWARGS))
        assert result.startswith("Blocked:")

    def test_api_error(self):
        aws = MagicMock()
        aws.fetch_instances_cached = AsyncMock(return_value=[])
        aws.run_instances = AsyncMock(side_effect=Exception("InsufficientInstanceCapacity"))
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, aws_service=aws)
        result = run(tools.aws_run_instances(**VALID_RUN_KWARGS))
        assert "Error" in result
        assert "us-east-1" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, aws_service=aws)
        run(tools.aws_run_instances(**VALID_RUN_KWARGS))
        assert tools._audit.log.call_args[0][0] == "aws_run_instances"
        assert tools._audit.log.call_args[0][3] is True

    # --- Validation cascade — 8 validator-failure tests ---

    def test_validation_bad_region(self):
        aws = MagicMock()
        aws.fetch_instances_cached = AsyncMock(return_value=[])
        aws.run_instances = AsyncMock(side_effect=ValueError("Invalid region 'BADREGION'"))
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, aws_service=aws)
        kw = dict(VALID_RUN_KWARGS, region="BADREGION")
        result = run(tools.aws_run_instances(**kw))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_validation_bad_ami_id(self):
        aws = MagicMock()
        aws.fetch_instances_cached = AsyncMock(return_value=[])
        aws.run_instances = AsyncMock(side_effect=ValueError("Invalid AMI ID"))
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, aws_service=aws)
        kw = dict(VALID_RUN_KWARGS, ami_id="bad-ami")
        result = run(tools.aws_run_instances(**kw))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_validation_bad_instance_type(self):
        aws = MagicMock()
        aws.fetch_instances_cached = AsyncMock(return_value=[])
        aws.run_instances = AsyncMock(side_effect=ValueError("Invalid instance_type"))
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, aws_service=aws)
        kw = dict(VALID_RUN_KWARGS, instance_type="invalid")
        result = run(tools.aws_run_instances(**kw))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_validation_bad_key_name(self):
        aws = MagicMock()
        aws.fetch_instances_cached = AsyncMock(return_value=[])
        aws.run_instances = AsyncMock(side_effect=ValueError("Invalid key_name"))
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, aws_service=aws)
        kw = dict(VALID_RUN_KWARGS, key_name="")
        result = run(tools.aws_run_instances(**kw))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_validation_bad_subnet_id(self):
        aws = MagicMock()
        aws.fetch_instances_cached = AsyncMock(return_value=[])
        aws.run_instances = AsyncMock(side_effect=ValueError("Invalid subnet_id"))
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, aws_service=aws)
        kw = dict(VALID_RUN_KWARGS, subnet_id="bad-subnet")
        result = run(tools.aws_run_instances(**kw))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_validation_bad_security_group_ids(self):
        aws = MagicMock()
        aws.fetch_instances_cached = AsyncMock(return_value=[])
        aws.run_instances = AsyncMock(side_effect=ValueError("Invalid security_group_ids"))
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, aws_service=aws)
        kw = dict(VALID_RUN_KWARGS, security_group_ids=[])
        result = run(tools.aws_run_instances(**kw))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_validation_bad_name_tag(self):
        aws = MagicMock()
        aws.fetch_instances_cached = AsyncMock(return_value=[])
        aws.run_instances = AsyncMock(side_effect=ValueError("Invalid name_tag"))
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, aws_service=aws)
        kw = dict(VALID_RUN_KWARGS, name_tag="")
        result = run(tools.aws_run_instances(**kw))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_validation_bad_count(self):
        aws = MagicMock()
        aws.fetch_instances_cached = AsyncMock(return_value=[])
        aws.run_instances = AsyncMock(side_effect=ValueError("count must be between 1 and 10"))
        tools = make_tools(guard_level=GuardLevel.DANGEROUS, aws_service=aws)
        kw = dict(VALID_RUN_KWARGS, count=99)
        result = run(tools.aws_run_instances(**kw))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")


# ---------------------------------------------------------------------------
# aws_list_regions
# ---------------------------------------------------------------------------

class TestAwsListRegions:
    def _make_aws(self, regions=None):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        svc.list_regions = AsyncMock(return_value=regions or ["us-east-1", "eu-west-1"])
        return svc

    def test_happy_path(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_regions())
        assert "us-east-1" in result
        assert "eu-west-1" in result
        assert "2 total" in result

    def test_empty_bootstrap_region_falls_back_to_us_east_1(self):
        """An empty bootstrap_region must send 'us-east-1' to the service."""
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        run(tools.aws_list_regions(bootstrap_region=""))
        aws.list_regions.assert_called_once_with("us-east-1")

    def test_custom_bootstrap_region_passed_through(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        run(tools.aws_list_regions(bootstrap_region="eu-central-1"))
        aws.list_regions.assert_called_once_with("eu-central-1")

    def test_allowed_at_readonly(self):
        # aws_list_regions IS in readonly — it should be ALLOWED at all tiers
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_regions())
        assert "Blocked" not in result

    def test_api_error(self):
        aws = self._make_aws()
        aws.list_regions = AsyncMock(side_effect=Exception("NoCredentialsError"))
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_regions())
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        run(tools.aws_list_regions())
        assert tools._audit.log.call_args[0][0] == "aws_list_regions"
        assert tools._audit.log.call_args[0][3] is True


# ---------------------------------------------------------------------------
# aws_list_amis
# ---------------------------------------------------------------------------

class TestAwsListAmis:
    def _make_aws(self, amis=None):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        svc.list_amis = AsyncMock(return_value=amis or [
            {
                "image_id": "ami-0abc1234",
                "name": "amzn2-ami-kernel-5.10",
                "architecture": "x86_64",
                "creation_date": "2024-01-15",
            }
        ])
        return svc

    def test_happy_path_renders_all_fields(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_amis(region="us-east-1"))
        assert "ami-0abc1234" in result
        assert "amzn2-ami-kernel-5.10" in result
        assert "x86_64" in result
        assert "2024-01-15" in result

    def test_allowed_at_readonly(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_amis(region="us-east-1"))
        assert "Blocked" not in result

    def test_validator_rejection(self):
        aws = self._make_aws()
        aws.list_amis = AsyncMock(side_effect=ValueError("Invalid region"))
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_amis(region="bad!"))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        aws = self._make_aws()
        aws.list_amis = AsyncMock(side_effect=Exception("Access denied"))
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_amis(region="us-east-1"))
        assert "Error" in result
        assert "us-east-1" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        run(tools.aws_list_amis(region="us-east-1"))
        assert tools._audit.log.call_args[0][0] == "aws_list_amis"
        assert tools._audit.log.call_args[0][3] is True

    def test_owners_default_amazon(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        run(tools.aws_list_amis(region="us-east-1"))
        # The service should be called with ("amazon",) as default owners
        call_args = aws.list_amis.call_args
        owners_arg = call_args[0][2]  # positional arg 3
        assert "amazon" in owners_arg


# ---------------------------------------------------------------------------
# aws_list_instance_types
# ---------------------------------------------------------------------------

class TestAwsListInstanceTypes:
    def _make_aws(self, types=None):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        svc.list_instance_types = AsyncMock(return_value=types or [
            {"instance_type": "t3.medium", "vcpus": 2, "memory_mib": 4096}
        ])
        return svc

    def test_happy_path_renders_all_fields(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_instance_types(region="us-east-1"))
        assert "t3.medium" in result
        assert "2" in result
        assert "4096" in result

    def test_allowed_at_readonly(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_instance_types(region="us-east-1"))
        assert "Blocked" not in result

    def test_validator_rejection(self):
        aws = self._make_aws()
        aws.list_instance_types = AsyncMock(side_effect=ValueError("Invalid region"))
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_instance_types(region="!!"))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        aws = self._make_aws()
        aws.list_instance_types = AsyncMock(side_effect=Exception("Throttled"))
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_instance_types(region="us-east-1"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        run(tools.aws_list_instance_types(region="us-east-1"))
        assert tools._audit.log.call_args[0][0] == "aws_list_instance_types"
        assert tools._audit.log.call_args[0][3] is True


# ---------------------------------------------------------------------------
# aws_list_key_pairs
# ---------------------------------------------------------------------------

class TestAwsListKeyPairs:
    def _make_aws(self, keys=None):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        svc.list_key_pairs = AsyncMock(return_value=keys or [
            {"key_name": "prod-key", "key_pair_id": "key-0abc123", "fingerprint": "aa:bb:cc"}
        ])
        return svc

    def test_happy_path_renders_all_fields(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_key_pairs(region="us-east-1"))
        assert "prod-key" in result
        assert "key-0abc123" in result
        assert "aa:bb:cc" in result

    def test_allowed_at_readonly(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_key_pairs(region="us-east-1"))
        assert "Blocked" not in result

    def test_validator_rejection(self):
        aws = self._make_aws()
        aws.list_key_pairs = AsyncMock(side_effect=ValueError("Invalid region 'bad'"))
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_key_pairs(region="bad"))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        aws = self._make_aws()
        aws.list_key_pairs = AsyncMock(side_effect=Exception("Access denied"))
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_key_pairs(region="us-east-1"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        run(tools.aws_list_key_pairs(region="us-east-1"))
        assert tools._audit.log.call_args[0][0] == "aws_list_key_pairs"
        assert tools._audit.log.call_args[0][3] is True


# ---------------------------------------------------------------------------
# aws_list_subnets
# ---------------------------------------------------------------------------

class TestAwsListSubnets:
    def _make_aws(self, subnets=None):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        svc.list_subnets = AsyncMock(return_value=subnets or [
            {
                "subnet_id": "subnet-0abc1234",
                "vpc_id": "vpc-0def5678",
                "availability_zone": "us-east-1a",
                "cidr_block": "10.0.1.0/24",
                "available_ip_count": 251,
            }
        ])
        return svc

    def test_happy_path_renders_all_fields(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_subnets(region="us-east-1"))
        assert "subnet-0abc1234" in result
        assert "vpc-0def5678" in result
        assert "us-east-1a" in result
        assert "10.0.1.0/24" in result
        assert "251" in result

    def test_allowed_at_readonly(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_subnets(region="us-east-1"))
        assert "Blocked" not in result

    def test_validator_rejection(self):
        aws = self._make_aws()
        aws.list_subnets = AsyncMock(side_effect=ValueError("Invalid region"))
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_subnets(region="bad!"))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        aws = self._make_aws()
        aws.list_subnets = AsyncMock(side_effect=Exception("Timeout"))
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_subnets(region="us-east-1"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        run(tools.aws_list_subnets(region="us-east-1"))
        assert tools._audit.log.call_args[0][0] == "aws_list_subnets"
        assert tools._audit.log.call_args[0][3] is True


# ---------------------------------------------------------------------------
# aws_list_security_groups
# ---------------------------------------------------------------------------

class TestAwsListSecurityGroups:
    def _make_aws(self, groups=None):
        svc = MagicMock()
        svc.fetch_instances_cached = AsyncMock(return_value=[])
        svc.list_security_groups = AsyncMock(return_value=groups or [
            {
                "group_id": "sg-0abc1234",
                "group_name": "web-sg",
                "vpc_id": "vpc-0def5678",
                "description": "Web tier security group",
            }
        ])
        return svc

    def test_happy_path_renders_all_fields(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_security_groups(region="us-east-1"))
        assert "sg-0abc1234" in result
        assert "web-sg" in result
        assert "vpc-0def5678" in result
        assert "Web tier" in result

    def test_allowed_at_readonly(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_security_groups(region="us-east-1"))
        assert "Blocked" not in result

    def test_validator_rejection(self):
        aws = self._make_aws()
        aws.list_security_groups = AsyncMock(side_effect=ValueError("Invalid region"))
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_security_groups(region="bad!"))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        aws = self._make_aws()
        aws.list_security_groups = AsyncMock(side_effect=Exception("EC2 API error"))
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_security_groups(region="us-east-1"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        aws = self._make_aws()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        run(tools.aws_list_security_groups(region="us-east-1"))
        assert tools._audit.log.call_args[0][0] == "aws_list_security_groups"
        assert tools._audit.log.call_args[0][3] is True

    def test_description_truncated_at_50_chars(self):
        """Description field must be truncated to 50 chars to avoid table overflow."""
        long_desc = "A" * 100
        aws = self._make_aws(groups=[{
            "group_id": "sg-0001", "group_name": "sg1", "vpc_id": "vpc-1",
            "description": long_desc,
        }])
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_service=aws)
        result = run(tools.aws_list_security_groups(region="us-east-1"))
        # The full 100-char description should NOT appear in output
        assert long_desc not in result
        # But the truncated 50-char version should
        assert "A" * 50 in result


# ---------------------------------------------------------------------------
# aws_service=None paths — _aws_unavailable helper coverage
# ---------------------------------------------------------------------------

def _make_tools_no_aws(guard_level=GuardLevel.DANGEROUS):
    """Build ServonautTools with aws_service=None to test unavailability paths."""
    config = AppConfig(mcp=MCPConfig(guard_level=guard_level))
    config_manager = MagicMock()
    config_manager.get.return_value = config
    guard = CommandGuard(config.mcp)
    audit = MagicMock()
    audit.log = MagicMock()
    custom_svc = MagicMock()
    custom_svc.list_as_instances.return_value = []
    ovh_svc = MagicMock()
    ovh_svc.fetch_instances_cached = AsyncMock(return_value=[])
    return ServonautTools(
        config_manager, None, custom_svc, MagicMock(),
        MagicMock(), MagicMock(), MagicMock(),
        guard, audit,
        ovh_service=ovh_svc,
    )


class TestAwsServiceUnavailable:
    """Cover the _aws_unavailable() helper path (aws_service is None)."""

    def test_aws_start_returns_unavailable_error(self):
        tools = _make_tools_no_aws()
        result = run(tools.aws_start_instance("i-abc123", "us-east-1"))
        assert "Error" in result
        assert "AWS service" in result
        assert tools._audit.log.call_args[0][4] == "aws_unavailable"

    def test_aws_terminate_returns_unavailable_error(self):
        tools = _make_tools_no_aws()
        result = run(tools.aws_terminate_instance("i-abc123", "us-east-1"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "aws_unavailable"

    def test_aws_run_instances_returns_unavailable_error(self):
        tools = _make_tools_no_aws()
        result = run(tools.aws_run_instances(**VALID_RUN_KWARGS))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "aws_unavailable"

    def test_aws_list_regions_returns_unavailable_error(self):
        tools = _make_tools_no_aws(guard_level=GuardLevel.READONLY)
        result = run(tools.aws_list_regions())
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "aws_unavailable"

    def test_aws_list_amis_returns_unavailable_error(self):
        tools = _make_tools_no_aws(guard_level=GuardLevel.READONLY)
        result = run(tools.aws_list_amis(region="us-east-1"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "aws_unavailable"

    def test_aws_list_instance_types_returns_unavailable_error(self):
        tools = _make_tools_no_aws(guard_level=GuardLevel.READONLY)
        result = run(tools.aws_list_instance_types(region="us-east-1"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "aws_unavailable"

    def test_aws_list_key_pairs_returns_unavailable_error(self):
        tools = _make_tools_no_aws(guard_level=GuardLevel.READONLY)
        result = run(tools.aws_list_key_pairs(region="us-east-1"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "aws_unavailable"

    def test_aws_list_subnets_returns_unavailable_error(self):
        tools = _make_tools_no_aws(guard_level=GuardLevel.READONLY)
        result = run(tools.aws_list_subnets(region="us-east-1"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "aws_unavailable"

    def test_aws_list_security_groups_returns_unavailable_error(self):
        tools = _make_tools_no_aws(guard_level=GuardLevel.READONLY)
        result = run(tools.aws_list_security_groups(region="us-east-1"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "aws_unavailable"
