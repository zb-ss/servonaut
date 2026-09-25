"""Journey: an MCP client investigates WAF traffic with the CloudWatch tools.

``cloudwatch_top_ips`` ranks client addresses with allowed and blocked
counts, optionally for one WAF action. ``cloudwatch_get_log_events`` with
``client_ip`` returns only that client's requests, and quotes a bare literal
filter so CloudWatch matches it. A filter that matches nothing is reported
as exactly that, never as an empty log group, which is a different finding.

Filter patterns are evaluated as CloudWatch documents them (see
``e2e/harness/aws_logs_filter.py``).
"""

from __future__ import annotations

import pytest

from e2e.harness import fleet
from e2e.harness.aws import waf_log_record
from e2e.journeys.aws.support import audit_rows

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

WAF_GROUP = "aws-waf-logs-e2e"
QUIET_GROUP = "aws-waf-logs-e2e-quiet"
TRAFFIC = (
    [waf_log_record("9.9.9.9", "ALLOW", uri=f"/page/{n}") for n in range(5)]
    + [waf_log_record("9.9.9.9", "BLOCK", uri="/wp-login.php", status=403) for _ in range(2)]
    + [waf_log_record("1.1.1.1", "BLOCK", uri="/wp-login.php", status=403) for _ in range(3)]
    + [waf_log_record("8.8.8.8", "ALLOW", uri="/") for _ in range(2)]
    + [waf_log_record(fleet.APP_1.private_ip, "ALLOW", uri="/health")]
)


def _table(text: str) -> list[list[str]]:
    """Rows under the dashed rule of a Top IPs answer."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip().startswith("---")) + 1
    return [line.split() for line in lines[start:] if line.strip()]


def _event_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("  [")]


async def test_top_ips_with_allowed_and_blocked_counts(mcp, mcp_home, cloudwatch):
    cloudwatch.seed_log_events(WAF_GROUP, TRAFFIC)
    sandbox = mcp_home()
    async with mcp(sandbox) as session:
        groups = await session.call("cloudwatch_list_log_groups", {"region": "us-east-1"})
        everything = await session.call(
            "cloudwatch_top_ips", {"log_group": WAF_GROUP, "region": "us-east-1"}
        )
        blocked = await session.call(
            "cloudwatch_top_ips",
            {"log_group": WAF_GROUP, "region": "us-east-1", "action_filter": "block"},
        )

    assert "CloudWatch log groups (1 total):" in groups
    assert WAF_GROUP in groups
    assert everything.startswith(f"Top 3 client IPs in {WAF_GROUP} (last 24h, 13 events):")
    # IP, total, allowed, blocked. The private health-check address is left out.
    assert _table(everything) == [
        ["9.9.9.9", "7", "5", "2"],
        ["1.1.1.1", "3", "0", "3"],
        ["8.8.8.8", "2", "2", "0"],
    ]
    assert blocked.startswith(f"Top 2 client IPs in {WAF_GROUP} (last 24h, 13 events, action=BLOCK):")
    assert _table(blocked) == [["1.1.1.1", "3", "0", "3"], ["9.9.9.9", "2", "0", "2"]]
    assert [row["allowed"] for row in audit_rows(sandbox)] == [True, True, True]


async def test_log_events_for_one_client_and_filtered_empty_results(mcp, mcp_home, cloudwatch):
    cloudwatch.seed_log_events(WAF_GROUP, TRAFFIC)
    cloudwatch.seed_log_events(QUIET_GROUP)
    sandbox = mcp_home()
    fetch = {"log_group": WAF_GROUP, "region": "us-east-1"}
    async with mcp(sandbox) as session:
        one_client = await session.call("cloudwatch_get_log_events", {**fetch, "client_ip": "1.1.1.1"})
        bare_path = await session.call(
            "cloudwatch_get_log_events", {**fetch, "filter_pattern": "/wp-login.php"}
        )
        nothing = await session.call(
            "cloudwatch_get_log_events", {**fetch, "filter_pattern": "/no-such-page"}
        )
        quiet = await session.call(
            "cloudwatch_get_log_events", {"log_group": QUIET_GROUP, "region": "us-east-1"}
        )

    # client_ip builds a JSON selector: only that client's three requests.
    assert one_client.startswith(f"CloudWatch events: {WAF_GROUP} (last 1h, 3 matched events)")
    assert len(_event_lines(one_client)) == 3
    assert all('"clientIp": "1.1.1.1"' in line for line in _event_lines(one_client))

    # A bare path is quoted so it matches, and the answer says so.
    assert bare_path.startswith(f"CloudWatch events: {WAF_GROUP} (last 1h, 5 matched events)")
    assert "filter normalized to '\"/wp-login.php\"'" in bare_path

    # Nothing matched: the group is not called empty.
    assert nothing.startswith(
        f"0 events matched filter '\"/no-such-page\"' in {WAF_GROUP} over the last 1h."
    )
    assert "No log events" not in nothing
    # An empty group without a filter is the other message.
    assert quiet == f"No log events in {QUIET_GROUP} for the last 1h."
