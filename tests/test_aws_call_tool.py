"""Tests for the generic aws_call passthrough + cloudwatch_insights tool, and
the cloudwatch_get_log_events filter-quoting fix.

aws_call branches covered: guard rejection, service/operation validation,
destructive-verb refusal, read dispatch (auto-paginate), mutate-required gate,
and mutate dispatch at the dangerous tier. Each asserts the audit row.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

from servonaut.config.schema import AppConfig, MCPConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tools import ServonautTools
from servonaut.services.cloudwatch_service import CloudWatchService

# The real normalizer is pure; reuse it on the mocked service so the tool's
# auto-quote path runs exactly as in production.
_NORMALIZE = CloudWatchService.normalize_filter_pattern


def _run(coro):
    return asyncio.run(coro)


def _make_tools(*, guard_level=GuardLevel.READONLY, aws_factory=None,
                cloudwatch_service=None):
    config = AppConfig(mcp=MCPConfig(guard_level=guard_level))
    config_manager = MagicMock()
    config_manager.get.return_value = config

    aws_service = MagicMock()
    custom_server_service = MagicMock()
    custom_server_service.list_as_instances.return_value = []
    audit = MagicMock()
    audit.log = MagicMock()
    guard = CommandGuard(config.mcp, config_manager)

    return ServonautTools(
        config_manager, aws_service, custom_server_service, MagicMock(),
        MagicMock(), MagicMock(), MagicMock(),
        guard, audit,
        cloudwatch_service=cloudwatch_service,
        aws_client_factory=aws_factory,
    )


class _FakeFactory:
    """Records client() calls and returns a preset boto3-like client."""

    def __init__(self, client):
        self._client = client
        self.calls = []

    def client(self, service, region="", account="", mutate=False):
        self.calls.append((service, region, account, mutate))
        return self._client


# --- aws_call: validation + guard ---


def test_aws_call_guard_rejects_when_below_tier():
    # aws_call is readonly-tier; force a guard that disallows it by stubbing.
    tools = _make_tools()
    tools._guard.check_tool = lambda name: (False, "nope")
    out = _run(tools.aws_call("ec2", "describe_instances"))
    assert out.startswith("Blocked:")
    tools._audit.log.assert_called_once()
    assert tools._audit.log.call_args.args[3] is False


def test_aws_call_invalid_operation():
    tools = _make_tools()
    out = _run(tools.aws_call("ec2", "Describe-Instances!"))
    assert "invalid operation" in out
    assert tools._audit.log.call_args.args[4].startswith("validation:")


def test_aws_call_invalid_service():
    tools = _make_tools()
    out = _run(tools.aws_call("EC2!!", "describe_instances"))
    assert "invalid service" in out


def test_aws_call_destructive_refused_even_with_mutate():
    tools = _make_tools(guard_level=GuardLevel.DANGEROUS)
    out = _run(tools.aws_call("s3", "delete_bucket",
                              params={"Bucket": "x"}, mutate=True))
    assert "destructive" in out.lower()
    assert tools._audit.log.call_args.args[4] == "blocked_destructive"


# --- aws_call: read dispatch ---


def test_aws_call_read_dispatch_paginates():
    client = MagicMock()
    client.can_paginate.return_value = True
    paginator = MagicMock()
    paginator.paginate.return_value.build_full_result.return_value = {
        "SecurityGroupRules": [{"GroupId": "sg-1"}],
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }
    client.get_paginator.return_value = paginator
    factory = _FakeFactory(client)
    tools = _make_tools(aws_factory=factory)

    out = _run(tools.aws_call(
        "ec2", "describe_security_group_rules",
        params={"Filters": [{"Name": "group-id", "Values": ["sg-1"]}]},
        region="us-east-1",
    ))
    assert "aws_call ec2.describe_security_group_rules" in out
    # ResponseMetadata stripped from the serialized body.
    assert "ResponseMetadata" not in out
    assert "sg-1" in out
    # Pinned region passed through; read path → mutate=False.
    assert factory.calls == [("ec2", "us-east-1", "", False)]
    # Pagination cap applied.
    pag_kwargs = paginator.paginate.call_args.kwargs
    assert pag_kwargs["PaginationConfig"]["MaxItems"] == 1000
    assert tools._audit.log.call_args.args[3] is True


def test_aws_call_read_non_paginable_direct_call():
    client = MagicMock()
    client.can_paginate.return_value = False
    client.get_ip_set.return_value = {
        "IPSet": {"Addresses": ["1.2.3.4/32"]},
        "ResponseMetadata": {},
    }
    factory = _FakeFactory(client)
    tools = _make_tools(aws_factory=factory)
    out = _run(tools.aws_call("wafv2", "get_ip_set",
                              params={"Name": "n", "Id": "i", "Scope": "REGIONAL"}))
    assert "1.2.3.4/32" in out
    client.get_ip_set.assert_called_once_with(Name="n", Id="i", Scope="REGIONAL")


# --- aws_call: mutate gating ---


def test_aws_call_mutate_required_for_write():
    tools = _make_tools(guard_level=GuardLevel.READONLY)
    out = _run(tools.aws_call("wafv2", "update_ip_set", params={"Id": "i"}))
    assert "mutate=true" in out
    assert tools._audit.log.call_args.args[4] == "mutate_required"


def test_aws_call_mutate_blocked_below_dangerous():
    tools = _make_tools(guard_level=GuardLevel.STANDARD)
    out = _run(tools.aws_call("wafv2", "update_ip_set",
                              params={"Id": "i"}, mutate=True))
    assert out.startswith("Blocked:")


def test_aws_call_mutate_dispatches_at_dangerous():
    client = MagicMock()
    client.can_paginate.return_value = False
    client.update_ip_set.return_value = {"NextLockToken": "tok"}
    factory = _FakeFactory(client)
    tools = _make_tools(guard_level=GuardLevel.DANGEROUS, aws_factory=factory)
    out = _run(tools.aws_call("wafv2", "update_ip_set",
                              params={"Id": "i", "Addresses": ["1.2.3.4/32"]},
                              mutate=True))
    assert "NextLockToken" in out
    client.update_ip_set.assert_called_once()
    # Write path must request the client with mutate=True (→ mutate role).
    assert factory.calls[-1] == ("wafv2", "", "", True)
    assert tools._audit.log.call_args.args[3] is True


# --- cloudwatch_get_log_events: filter quoting + empty messaging ---


def test_get_log_events_auto_quotes_and_reports_match():
    cw = MagicMock()
    cw.normalize_filter_pattern = _NORMALIZE
    cw.get_log_events = AsyncMock(return_value=[
        {"timestamp": datetime(2024, 6, 1, 12, 0, 0),
         "message": "hit from 9.9.9.9"},
    ])
    tools = _make_tools(cloudwatch_service=cw)
    out = _run(tools.cloudwatch_get_log_events(
        "/aws/waf/logs", filter_pattern="9.9.9.9",
    ))
    # The effective (quoted) pattern reached the service.
    effective = cw.get_log_events.call_args.args[3]
    assert effective == '"9.9.9.9"'
    assert "matched events" in out
    assert "normalized to" in out


def test_get_log_events_empty_filtered_is_not_empty_group():
    cw = MagicMock()
    cw.normalize_filter_pattern = _NORMALIZE
    cw.get_log_events = AsyncMock(return_value=[])
    tools = _make_tools(cloudwatch_service=cw)
    out = _run(tools.cloudwatch_get_log_events(
        "/aws/waf/logs", filter_pattern="9.9.9.9",
    ))
    assert "0 events matched filter" in out
    assert "doesn't match" in out  # explicitly warns it's not an empty group


def test_get_log_events_client_ip_builds_selector():
    cw = MagicMock()
    cw.normalize_filter_pattern = _NORMALIZE
    cw.get_log_events = AsyncMock(return_value=[])
    tools = _make_tools(cloudwatch_service=cw)
    _run(tools.cloudwatch_get_log_events("/g", client_ip="9.9.9.9"))
    effective = cw.get_log_events.call_args.args[3]
    assert effective == '{ $.httpRequest.clientIp = "9.9.9.9" }'


def test_get_log_events_rejects_bad_client_ip():
    cw = MagicMock()
    tools = _make_tools(cloudwatch_service=cw)
    out = _run(tools.cloudwatch_get_log_events("/g", client_ip="not-an-ip"))
    assert "not a valid IP" in out


# --- cloudwatch_insights tool ---


def test_cloudwatch_insights_formats_rows():
    cw = MagicMock()
    cw.run_insights_query = AsyncMock(return_value={
        "status": "Complete",
        "columns": ["clientIp", "hits"],
        "rows": [{"clientIp": "1.2.3.4", "hits": "50"}],
        "statistics": {},
    })
    tools = _make_tools(cloudwatch_service=cw)
    out = _run(tools.cloudwatch_insights(
        query="stats count(*) by clientIp", log_group="/aws/waf/logs",
    ))
    assert "1.2.3.4" in out and "hits" in out
    assert tools._audit.log.call_args.args[3] is True


def test_cloudwatch_insights_requires_group():
    cw = MagicMock()
    tools = _make_tools(cloudwatch_service=cw)
    out = _run(tools.cloudwatch_insights(query="fields @message"))
    assert "log_group" in out
    assert tools._audit.log.call_args.args[4] == "no_log_group"


def test_cloudwatch_insights_reports_timeout():
    cw = MagicMock()
    cw.run_insights_query = AsyncMock(return_value={
        "status": "Timeout", "rows": [], "columns": [],
    })
    tools = _make_tools(cloudwatch_service=cw)
    out = _run(tools.cloudwatch_insights(query="q", log_group="/g"))
    assert "Timeout" in out
