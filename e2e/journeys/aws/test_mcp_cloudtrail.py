"""Journey: an MCP client looks up CloudTrail events.

``cloudtrail_lookup_events`` filters by event name or user; two filters
combine even though the API applies only one per call. An event whose
resource has no type is listed like any other.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from e2e.harness import fleet
from e2e.harness.cloudtrail_stub import cloudtrail_event
from e2e.journeys.aws.support import rows_under_rule

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

INSTANCE_ROLE = fleet.APP_1.instance_id


def _events() -> list[dict]:
    now = datetime.now(timezone.utc)
    plan = [
        ("StopInstances", "e2e-operator"),
        ("StopInstances", INSTANCE_ROLE),
        ("StartInstances", INSTANCE_ROLE),
        ("AuthorizeSecurityGroupIngress", "e2e-operator"),
        ("StopInstances", "e2e-operator"),
    ]
    return [
        cloudtrail_event(
            name,
            now - timedelta(minutes=5 * (index + 1)),
            username=user,
            resources=[{"ResourceName": "sg-0e2e0000000000001"}],  # no ResourceType
        )
        for index, (name, user) in enumerate(plan)
    ]


def _listed(text: str) -> list[tuple[str, ...]]:
    """(event, user) of every row: the columns after the date and time."""
    return [tuple(row[2:4]) for row in rows_under_rule(text)]


async def test_lookup_filters_combine(mcp, mcp_home, cloudtrail):
    from servonaut.config.schema import MCPConfig

    cloudtrail.seed(_events(), region="us-east-1")
    sandbox = mcp_home(mcp=MCPConfig(guard_level="readonly"))
    lookup = {"region": "us-east-1", "hours_back": 2}
    async with mcp(sandbox) as session:
        stops = await session.call("cloudtrail_lookup_events", {**lookup, "event_name": "StopInstances"})
        both = await session.call(
            "cloudtrail_lookup_events",
            {**lookup, "event_name": "StopInstances", "username": INSTANCE_ROLE},
        )
        none = await session.call("cloudtrail_lookup_events", {**lookup, "event_name": "RebootInstances"})

    assert stops.startswith("CloudTrail events (3 found):")
    assert _listed(stops) == [
        ("StopInstances", "e2e-operator"),
        ("StopInstances", INSTANCE_ROLE),
        ("StopInstances", "e2e-operator"),
    ]
    assert both.startswith("CloudTrail events (1 found):")
    assert _listed(both) == [("StopInstances", INSTANCE_ROLE)]
    assert none == "No CloudTrail events matched the given filters."
    # The API honours one attribute per call, so no call sends more; the
    # combined lookup asks for the event name and narrows by user itself.
    lookups = cloudtrail.lookups()
    assert all(len(request.get("LookupAttributes") or []) <= 1 for request in lookups)
    assert [request["LookupAttributes"] for request in lookups] == [
        [{"AttributeKey": "EventName", "AttributeValue": "StopInstances"}],
        [{"AttributeKey": "EventName", "AttributeValue": "StopInstances"}],
        [{"AttributeKey": "EventName", "AttributeValue": "RebootInstances"}],
    ]
