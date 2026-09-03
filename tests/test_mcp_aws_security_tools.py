"""Tests for the AWS CloudWatch / CloudTrail / IP-ban MCP tools.

Covers ``cloudwatch_list_log_groups``, ``cloudwatch_get_log_events``,
``cloudwatch_top_ips``, ``cloudtrail_lookup_events``, ``ip_ban_list_configs``,
``ip_ban_list_banned``, and ``ip_ban_set``.

For each tool we assert: service-unavailable handling, guard rejection at
the wrong tier, dispatch to the right underlying service method, output
formatting, and that error/edge paths surface a useful message.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

from servonaut.config.schema import AppConfig, IPBanConfig, MCPConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tools import ServonautTools
from servonaut.services.cloudwatch_service import CloudWatchService

# The filter normalizer is pure; wire the real one onto mocked CloudWatch
# services so the tool's auto-quote path behaves as in production rather than
# returning a truthy MagicMock for the effective filter pattern.
_NORMALIZE = CloudWatchService.normalize_filter_pattern


def _run(coro):
    return asyncio.run(coro)


def _make_tools(
    *,
    guard_level: str = GuardLevel.DANGEROUS,
    cloudwatch_service=None,
    cloudtrail_service=None,
    ip_ban_service=None,
    ip_ban_configs=None,
):
    """Construct a ServonautTools wired with mocked AWS security services."""
    config = AppConfig(mcp=MCPConfig(guard_level=guard_level))
    if ip_ban_configs is not None:
        config.ip_ban_configs = ip_ban_configs
    config_manager = MagicMock()
    config_manager.get.return_value = config

    aws_service = MagicMock()
    aws_service.fetch_instances_cached = AsyncMock(return_value=[])
    custom_server_service = MagicMock()
    custom_server_service.list_as_instances.return_value = []
    cache_service = MagicMock()
    ssh_service = MagicMock()
    connection_service = MagicMock()
    scp_service = MagicMock()
    audit = MagicMock()
    audit.log = MagicMock()
    guard = CommandGuard(config.mcp, config_manager)

    return ServonautTools(
        config_manager, aws_service, custom_server_service, cache_service,
        ssh_service, connection_service, scp_service,
        guard, audit,
        cloudwatch_service=cloudwatch_service,
        cloudtrail_service=cloudtrail_service,
        ip_ban_service=ip_ban_service,
    )


# ---------------------------------------------------------------------------
# CloudWatch: list_log_groups
# ---------------------------------------------------------------------------

class TestCloudWatchListLogGroups:
    def test_unavailable_when_no_service(self):
        tools = _make_tools()
        out = _run(tools.cloudwatch_list_log_groups())
        assert "CloudWatch service is not available" in out
        tools._audit.log.assert_called_once()

    def test_lists_groups(self):
        cw = MagicMock()
        cw.list_log_groups = AsyncMock(return_value=[
            {"name": "/aws/waf/prod", "stored_bytes": 2048, "retention_days": 30},
            {"name": "/aws/alb/prod", "stored_bytes": 99, "retention_days": None},
        ])
        tools = _make_tools(cloudwatch_service=cw)
        out = _run(tools.cloudwatch_list_log_groups(prefix="/aws/"))
        assert "/aws/waf/prod" in out
        assert "30d" in out
        assert "never expire" in out
        cw.list_log_groups.assert_awaited_once_with("/aws/", "")

    def test_empty(self):
        cw = MagicMock()
        cw.list_log_groups = AsyncMock(return_value=[])
        tools = _make_tools(cloudwatch_service=cw)
        out = _run(tools.cloudwatch_list_log_groups())
        assert "No CloudWatch log groups found" in out


# ---------------------------------------------------------------------------
# CloudWatch: get_log_events
# ---------------------------------------------------------------------------

class TestCloudWatchGetLogEvents:
    def test_dispatch_and_format(self):
        cw = MagicMock()
        cw.normalize_filter_pattern = _NORMALIZE
        cw.get_log_events = AsyncMock(return_value=[
            {"timestamp": datetime(2026, 5, 21, 10, 0, 0),
             "message": "hello", "log_stream": "s1"},
        ])
        tools = _make_tools(cloudwatch_service=cw)
        out = _run(tools.cloudwatch_get_log_events("/aws/waf/prod", hours_back=3))
        assert "hello" in out
        assert "2026-05-21 10:00:00" in out
        # log_group is the first positional arg; start/end are datetimes.
        call = cw.get_log_events.await_args
        assert call.args[0] == "/aws/waf/prod"
        assert isinstance(call.args[1], datetime)
        assert isinstance(call.args[2], datetime)

    def test_empty(self):
        cw = MagicMock()
        cw.normalize_filter_pattern = _NORMALIZE
        cw.get_log_events = AsyncMock(return_value=[])
        tools = _make_tools(cloudwatch_service=cw)
        out = _run(tools.cloudwatch_get_log_events("/aws/waf/prod"))
        assert "No log events" in out

    def test_empty_with_filter_distinguishes_no_match(self):
        # A filtered empty result must NOT read as "the group is empty" — that
        # conflation produced a false WAF-bypass conclusion in the field.
        cw = MagicMock()
        cw.normalize_filter_pattern = _NORMALIZE
        cw.get_log_events = AsyncMock(return_value=[])
        tools = _make_tools(cloudwatch_service=cw)
        out = _run(tools.cloudwatch_get_log_events(
            "/aws/waf/prod", filter_pattern="9.9.9.9"))
        assert "0 events matched filter" in out
        assert '"9.9.9.9"' in out  # auto-quoted


# ---------------------------------------------------------------------------
# CloudWatch: top_ips
# ---------------------------------------------------------------------------

class TestCloudWatchTopIps:
    def test_invalid_action_filter(self):
        cw = MagicMock()
        tools = _make_tools(cloudwatch_service=cw)
        out = _run(tools.cloudwatch_top_ips("/aws/waf/prod", action_filter="MAYBE"))
        assert "action_filter must be" in out

    def test_ranks_ips(self):
        cw = MagicMock()
        cw.get_log_events = AsyncMock(return_value=[{"message": "x"}])
        cw.extract_top_ips = MagicMock(return_value=[
            {"ip": "1.2.3.4", "count": 50, "allowed": 10, "blocked": 40},
        ])
        tools = _make_tools(cloudwatch_service=cw)
        out = _run(tools.cloudwatch_top_ips("/aws/waf/prod", action_filter="block"))
        assert "1.2.3.4" in out
        assert "40" in out
        # action_filter is upper-cased before reaching the service.
        cw.extract_top_ips.assert_called_once()
        assert cw.extract_top_ips.call_args.args[2] == "BLOCK"

    def test_no_ips_found(self):
        cw = MagicMock()
        cw.get_log_events = AsyncMock(return_value=[])
        cw.extract_top_ips = MagicMock(return_value=[])
        tools = _make_tools(cloudwatch_service=cw)
        out = _run(tools.cloudwatch_top_ips("/aws/waf/prod"))
        assert "No client IPs found" in out


# ---------------------------------------------------------------------------
# CloudTrail: lookup_events
# ---------------------------------------------------------------------------

class TestCloudTrailLookupEvents:
    def test_unavailable_when_no_service(self):
        tools = _make_tools()
        out = _run(tools.cloudtrail_lookup_events())
        assert "CloudTrail service is not available" in out

    def test_dispatch_and_format(self):
        ct = MagicMock()
        ct.lookup_events = AsyncMock(return_value=[
            {"event_time": datetime(2026, 5, 21, 9, 0, 0),
             "event_name": "RunInstances", "username": "alice",
             "source_ip": "203.0.113.5", "resource_type": "AWS::EC2::Instance",
             "resource_name": "i-abc", "region": "us-east-1", "error_code": ""},
        ])
        tools = _make_tools(cloudtrail_service=ct)
        out = _run(tools.cloudtrail_lookup_events(event_name="RunInstances"))
        assert "RunInstances" in out
        assert "alice" in out
        assert "203.0.113.5" in out
        ct.lookup_events.assert_awaited_once()
        assert ct.lookup_events.await_args.kwargs["event_name"] == "RunInstances"

    def test_empty(self):
        ct = MagicMock()
        ct.lookup_events = AsyncMock(return_value=[])
        tools = _make_tools(cloudtrail_service=ct)
        out = _run(tools.cloudtrail_lookup_events())
        assert "No CloudTrail events matched" in out

    def test_combined_filters_reach_the_api_and_the_local_pass(self):
        """End to end through the real service: CloudTrail honours only the
        first lookup attribute, so an agent asking for two used to get rows
        matching just one of them."""
        from unittest.mock import patch

        from servonaut.services.cloudtrail_service import CloudTrailService

        matches_both = {
            "EventTime": datetime(2026, 5, 21, 9, 0, 0), "EventName": "AssumeRole",
            "Username": "deploy", "CloudTrailEvent": "{}",
            "Resources": [{"ResourceType": "AWS::IAM::Role", "ResourceName": "r"}],
        }
        matches_first_only = dict(matches_both, Username="someone-else")
        client = MagicMock()
        client.lookup_events.return_value = {
            "Events": [matches_both, matches_first_only],
        }

        config_manager = MagicMock()
        config_manager.get.return_value = AppConfig()
        service = CloudTrailService(config_manager)
        tools = _make_tools(cloudtrail_service=service)

        with patch("boto3.client", return_value=client):
            out = _run(tools.cloudtrail_lookup_events(
                region="us-east-1", event_name="AssumeRole", username="deploy",
            ))

        sent = client.lookup_events.call_args[1]["LookupAttributes"]
        assert sent == [{"AttributeKey": "EventName", "AttributeValue": "AssumeRole"}]
        assert "deploy" in out
        assert "someone-else" not in out


# ---------------------------------------------------------------------------
# IP ban: list_configs / list_banned
# ---------------------------------------------------------------------------

class TestIPBanListConfigs:
    def test_lists_configs(self):
        svc = MagicMock()
        svc.get_configs = MagicMock(return_value=[
            IPBanConfig(name="prod-waf", method="waf", region="us-east-1",
                        ip_set_name="blocklist"),
        ])
        tools = _make_tools(ip_ban_service=svc)
        out = _run(tools.ip_ban_list_configs())
        assert "prod-waf" in out
        assert "waf" in out
        assert "blocklist" in out

    def test_no_configs(self):
        svc = MagicMock()
        svc.get_configs = MagicMock(return_value=[])
        tools = _make_tools(ip_ban_service=svc)
        out = _run(tools.ip_ban_list_configs())
        assert "No IP ban configurations defined" in out


class TestIPBanListBanned:
    def test_lists_banned(self):
        svc = MagicMock()
        svc.list_banned = AsyncMock(return_value=["1.2.3.4/32", "5.6.7.8/32"])
        tools = _make_tools(ip_ban_service=svc)
        out = _run(tools.ip_ban_list_banned("prod-waf"))
        assert "1.2.3.4/32" in out
        assert "5.6.7.8/32" in out

    def test_unknown_config(self):
        svc = MagicMock()
        svc.list_banned = AsyncMock(side_effect=ValueError("Unknown IP ban config: nope"))
        tools = _make_tools(ip_ban_service=svc)
        out = _run(tools.ip_ban_list_banned("nope"))
        assert "Unknown IP ban config" in out


# ---------------------------------------------------------------------------
# IP ban: set (ban / unban)
# ---------------------------------------------------------------------------

class TestIPBanSet:
    def test_blocked_in_standard_mode(self):
        # ip_ban_set is a dangerous-tier tool — standard mode must refuse it.
        svc = MagicMock()
        svc.ban_ip = AsyncMock()
        tools = _make_tools(guard_level=GuardLevel.STANDARD, ip_ban_service=svc)
        out = _run(tools.ip_ban_set("1.2.3.4", "prod-waf", action="ban"))
        assert out.startswith("Blocked: ")
        svc.ban_ip.assert_not_called()

    def test_unavailable_when_no_service(self):
        tools = _make_tools()
        out = _run(tools.ip_ban_set("1.2.3.4", "prod-waf"))
        assert "IP ban service is not available" in out

    def test_invalid_action(self):
        svc = MagicMock()
        svc.ban_ip = AsyncMock()
        tools = _make_tools(ip_ban_service=svc)
        out = _run(tools.ip_ban_set("1.2.3.4", "prod-waf", action="purge"))
        assert "action must be 'ban' or 'unban'" in out
        svc.ban_ip.assert_not_called()

    def test_ban_success(self):
        # Enhanced ip_ban_set returns an applied/failed split (not "OK:/Failed:").
        svc = MagicMock()
        svc.ban_ip = AsyncMock(
            return_value={"success": True, "message": "Banned 1.2.3.4 via WAF IP set"}
        )
        tools = _make_tools(ip_ban_service=svc)
        out = _run(tools.ip_ban_set("1.2.3.4", "prod-waf", action="ban"))
        assert "Banned (1): 1.2.3.4" in out
        assert "reverse_hint: ip_ban_set action=unban" in out
        svc.ban_ip.assert_awaited_once_with("1.2.3.4", "prod-waf")

    def test_unban_dispatch(self):
        svc = MagicMock()
        svc.unban_ip = AsyncMock(
            return_value={"success": True, "message": "Unbanned 1.2.3.4"}
        )
        tools = _make_tools(ip_ban_service=svc)
        out = _run(tools.ip_ban_set("1.2.3.4", "prod-waf", action="unban"))
        assert "Unbanned (1): 1.2.3.4" in out
        svc.unban_ip.assert_awaited_once_with("1.2.3.4", "prod-waf")

    def test_ban_failure_surfaces_message(self):
        svc = MagicMock()
        svc.ban_ip = AsyncMock(
            return_value={"success": False, "message": "Invalid IP address: nope"}
        )
        tools = _make_tools(ip_ban_service=svc)
        out = _run(tools.ip_ban_set("nope", "prod-waf", action="ban"))
        assert "Failed (1)" in out
        assert "Invalid IP address" in out
