"""Journey: an MCP client uses ``aws_call``, the generic AWS passthrough.

Reads run at every guard level and page through the whole result up to
``max_items``; boto3's ``ResponseMetadata`` never reaches the client. A
write needs both ``mutate=true`` and the dangerous level, and runs with the
separate write role, never the read-only one. Delete-style verbs are refused
outright with the default configuration, and the most destructive ones are
refused by a floor no setting lifts. Every refusal leaves one audit row.

moto answers a request made with an assumed role's credentials in that
role's own account, so the read and write roles live in different accounts:
where a write lands shows which role made it.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness.aws import MUTATE_ROLE_ACCOUNT, READ_ROLE_ACCOUNT
from e2e.journeys.aws.support import audit_rows

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

READ_ROLE = "e2e-control-plane-read"
WRITE_ROLE = "e2e-control-plane-write"
SESSION_NAME = "e2e-servonaut"
GROUPS = [f"/e2e/app-{n:02d}" for n in range(1, 13)]
INGRESS = {
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [{"CidrIp": "9.9.9.9/32", "Description": "e2e partner"}],
        }
    ]
}


def _body(text: str, service: str, operation: str) -> dict:
    """The JSON document under an ``aws_call`` result header."""
    header, _, body = text.partition("\n")
    assert header == f"aws_call {service}.{operation} →", text[:300]
    return json.loads(body)


def _config(level: str, *, roles: dict | None = None) -> dict:
    from servonaut.config.schema import AWSConfig, MCPConfig

    aws = AWSConfig(assume_role_session_name=SESSION_NAME, **(roles or {}))
    return {"mcp": MCPConfig(guard_level=level), "aws": aws}


def _roles(moto) -> dict:
    return {
        "control_plane_role_arn": moto.seed_role(READ_ROLE, READ_ROLE_ACCOUNT),
        "control_plane_mutate_role_arn": moto.seed_role(WRITE_ROLE, MUTATE_ROLE_ACCOUNT),
        "control_plane_external_id": "e2e-external-id",
    }


async def test_reads_page_up_to_max_items_without_response_metadata(
    mcp, mcp_home, moto
):
    for group in GROUPS:
        moto.seed_log_events(group)
    sandbox = mcp_home(**_config("readonly"))
    list_groups = {
        "service": "logs",
        "operation": "describe_log_groups",
        # Five per page, so every answer below spans several pages.
        "params": {"logGroupNamePrefix": "/e2e/", "limit": 5},
    }
    async with mcp(sandbox) as session:
        capped = _body(
            await session.call("aws_call", {**list_groups, "max_items": 8}),
            "logs",
            "describe_log_groups",
        )
        everything = _body(
            await session.call("aws_call", list_groups), "logs", "describe_log_groups"
        )
        identity_text = await session.call(
            "aws_call", {"service": "sts", "operation": "get_caller_identity"}
        )

    assert [g["logGroupName"] for g in capped["logGroups"]] == GROUPS[:8]
    assert capped.get("NextToken")  # there is more, and the answer says so
    assert [g["logGroupName"] for g in everything["logGroups"]] == GROUPS
    assert "NextToken" not in everything

    identity = _body(identity_text, "sts", "get_caller_identity")
    assert set(identity) == {"Account", "Arn", "UserId"}
    assert "ResponseMetadata" not in identity_text
    assert "RequestId" not in identity_text
    assert [row["allowed"] for row in audit_rows(sandbox)] == [True, True, True]


async def test_writes_need_the_dangerous_level(mcp, mcp_home, moto):
    group_id = moto.seed_security_group("e2e-web")
    sandbox = mcp_home(**_config("standard"))
    write = {
        "service": "ec2",
        "operation": "authorize_security_group_ingress",
        "params": {"GroupId": group_id, **INGRESS},
        "mutate": True,
    }
    async with mcp(sandbox) as session:
        refused = await session.call("aws_call", write)

    assert refused == "Blocked: Tool 'aws_call_mutate' not available in standard mode"
    assert moto.ingress_ranges(group_id) == []
    (row,) = audit_rows(sandbox)
    assert (row["tool"], row["allowed"]) == ("aws_call", False)
    assert row["reason"] == "Tool 'aws_call_mutate' not available in standard mode"


async def test_writes_use_the_separate_write_role(mcp, mcp_home, moto):
    roles = _roles(moto)
    write_ec2 = moto.client_as(roles["control_plane_mutate_role_arn"], "ec2")
    group_id = moto.seed_security_group("e2e-web", ec2=write_ec2)
    sandbox = mcp_home(**_config("dangerous", roles=roles))
    write = {
        "service": "ec2",
        "operation": "authorize_security_group_ingress",
        "params": {"GroupId": group_id, **INGRESS},
    }
    async with mcp(sandbox) as session:
        identity = _body(
            await session.call("aws_call", {"service": "sts", "operation": "get_caller_identity"}),
            "sts",
            "get_caller_identity",
        )
        without_flag = await session.call("aws_call", write)
        written = await session.call("aws_call", {**write, "mutate": True})

    # Reads run as the read role.
    assert identity["Account"] == READ_ROLE_ACCOUNT
    assert f":assumed-role/{READ_ROLE}/{SESSION_NAME}" in identity["Arn"]
    # A write without mutate=true is refused before any request.
    assert without_flag.startswith(
        "Error: 'authorize_security_group_ingress' is not a read operation."
    )
    # With it, the write succeeds; the group exists only in the write role's
    # account, so the write role made the call.
    assert _body(written, "ec2", "authorize_security_group_ingress")["Return"] is True
    assert moto.ingress_ranges(group_id, ec2=write_ec2) == [
        {"CidrIp": "9.9.9.9/32", "Description": "e2e partner"}
    ]
    rows = audit_rows(sandbox)
    assert [(r["allowed"], r["reason"]) for r in rows[1:]] == [
        (False, "mutate_required"),
        (True, ""),
    ]


async def test_destructive_verbs_are_refused(mcp, mcp_home, moto):
    group_id = moto.seed_security_group("e2e-web")
    moto.seed_bucket("e2e-assets", {"keep.txt": b"keep"})
    sandbox = mcp_home(**_config("dangerous"))
    async with mcp(sandbox) as session:
        delete_group = await session.call(
            "aws_call",
            {
                "service": "ec2",
                "operation": "delete_security_group",
                "params": {"GroupId": group_id},
                "mutate": True,
            },
        )
        delete_bucket = await session.call(
            "aws_call",
            {
                "service": "s3",
                "operation": "delete_bucket",
                "params": {"Bucket": "e2e-assets"},
                "mutate": True,
            },
        )

    assert delete_group.startswith(
        "Error: 'delete_security_group' is a destructive operation. It is disabled by default."
    )
    assert "never available via aws_call" in delete_bucket
    # Nothing was deleted.
    ec2 = moto.client("ec2")
    assert ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    assert moto.object_bytes("e2e-assets", "keep.txt") == b"keep"
    assert [(r["allowed"], r["reason"]) for r in audit_rows(sandbox)] == [
        (False, "blocked_destructive_disabled"),
        (False, "blocked_destructive_floor"),
    ]
