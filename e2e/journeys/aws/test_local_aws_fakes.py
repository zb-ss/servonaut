"""The local AWS stand-ins refuse what AWS refuses.

The journeys trust two stand-ins: the CloudTrail ``LookupEvents`` endpoint
and the CloudWatch Logs filter emulation. Each is only useful if it is no
more lenient than AWS, so these checks call them directly with requests AWS
rejects and expect the same error, plus a record the fixtures fail on.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from botocore.exceptions import ClientError

from e2e.harness import aws_logs_filter
from e2e.harness.cloudtrail_stub import cloudtrail_event
from e2e.journeys.aws.support import WAF_GROUP, waf_traffic

pytestmark = [pytest.mark.e2e_pr]

_CREDENTIALS = {"aws_access_key_id": "testing", "aws_secret_access_key": "testing"}
_LOOKUP_TARGET = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"
_SCOPE = "us-east-1/cloudtrail/aws4_request"


def _error_code(call) -> str:
    with pytest.raises(ClientError) as caught:
        call()
    return caught.value.response["Error"]["Code"]


def test_cloudtrail_page_tokens_are_bound_to_the_query(cloudtrail):
    now = datetime.now(timezone.utc)
    cloudtrail.seed(
        [cloudtrail_event("StopInstances", now - timedelta(minutes=m), username="e2e-operator")
         for m in range(1, 8)],
        region="us-east-1",
    )
    client = boto3.client(
        "cloudtrail", region_name="us-east-1", endpoint_url=cloudtrail.url, **_CREDENTIALS
    )
    query = {"StartTime": now - timedelta(hours=1), "EndTime": now, "MaxResults": 5}
    first = client.lookup_events(**query)
    token = first["NextToken"]
    second = client.lookup_events(**query, NextToken=token)
    assert len(first["Events"]) + len(second["Events"]) == 7
    assert "NextToken" not in second

    moved = {**query, "EndTime": now + timedelta(seconds=1), "NextToken": token}
    assert _error_code(lambda: client.lookup_events(**moved)) == "InvalidNextTokenException"
    narrowed = {
        **query,
        "NextToken": token,
        "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "StopInstances"}],
    }
    assert _error_code(lambda: client.lookup_events(**narrowed)) == "InvalidNextTokenException"
    other_region = boto3.client(
        "cloudtrail", region_name="eu-west-1", endpoint_url=cloudtrail.url, **_CREDENTIALS
    )
    assert (
        _error_code(lambda: other_region.lookup_events(**query, NextToken=token))
        == "InvalidNextTokenException"
    )
    too_many = {**query, "MaxResults": 51}
    assert _error_code(lambda: client.lookup_events(**too_many)) == "InvalidMaxResultsException"
    unimplemented = {
        **query,
        "LookupAttributes": [{"AttributeKey": "ReadOnly", "AttributeValue": "true"}],
    }
    assert (
        _error_code(lambda: client.lookup_events(**unimplemented))
        == "InvalidLookupAttributesException"
    )
    backwards = {"StartTime": now, "EndTime": now - timedelta(hours=1)}
    assert _error_code(lambda: client.lookup_events(**backwards)) == "InvalidTimeRangeException"

    # boto3 always sends numbers for timestamps; a raw request can send text.
    request = urllib.request.Request(
        cloudtrail.url,
        data=json.dumps({"StartTime": "yesterday"}).encode(),
        headers={
            "X-Amz-Target": _LOOKUP_TARGET,
            "Authorization": f"AWS4-HMAC-SHA256 Credential=testing/20260101/{_SCOPE}",
        },
    )
    with pytest.raises(urllib.error.HTTPError) as raw:
        urllib.request.urlopen(request, timeout=10)
    assert raw.value.code == 400
    assert json.loads(raw.value.read())["__type"] == "SerializationException"

    rejected = cloudtrail.take_rejections()
    assert len(rejected) == 7, rejected


@pytest.mark.parametrize(
    "pattern",
    [
        "?BLOCK ?ALLOW",  # optional terms
        "BLOCK -ALLOW",  # exclusion
        "1.1.1.1",  # unquoted punctuation: CloudWatch tokenises it
        '"wp-*"',  # wildcard
        '{ $.httpRequest.clientIp = "1.1.*" }',
        "{ $.responseCodeSent = 403 }",  # numeric comparison
        '{ $.action != "BLOCK" }',
        '{ $.action = "BLOCK" && $.httpRequest.clientIp = "1.1.1.1" }',
        '{ $.responseCodeSent = "403" }',  # text against a number
        "[ip, user, time]",  # space-delimited
    ],
)
def test_unemulated_filter_patterns_are_refused(moto, pattern):
    moto.seed_log_events(WAF_GROUP, waf_traffic())
    logs = moto.client("logs")
    code = _error_code(
        lambda: logs.filter_log_events(logGroupName=WAF_GROUP, filterPattern=pattern)
    )
    assert code == "InvalidParameterException"
    refused = aws_logs_filter.take_refused()
    assert len(refused) == 1 and refused[0].startswith(repr(pattern)), refused


def test_emulated_filter_patterns_match_as_documented(moto):
    moto.seed_log_events(WAF_GROUP, waf_traffic())
    logs = moto.client("logs")

    def count(pattern: str) -> int:
        return len(logs.filter_log_events(logGroupName=WAF_GROUP, filterPattern=pattern)["events"])

    assert count("") == 13
    assert count('"wp-login"') == 5
    assert count('"/wp-login.php" BLOCK') == 5
    assert count("NOMATCH") == 0
    assert count('{ $.httpRequest.clientIp = "1.1.1.1" }') == 3
    assert count('{ $.httpRequest.missing = "x" }') == 0
    # Each record carries its own event time, as WAF writes it.
    events = logs.filter_log_events(logGroupName=WAF_GROUP)["events"]
    assert all(json.loads(e["message"])["timestamp"] == e["timestamp"] for e in events)
