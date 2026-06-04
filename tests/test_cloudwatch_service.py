"""Tests for CloudWatchService."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from servonaut.services.cloudwatch_service import CloudWatchService


@pytest.fixture
def service() -> CloudWatchService:
    return CloudWatchService()


# --- extract_top_ips ---


def test_extract_top_ips_ranks_correctly(service: CloudWatchService) -> None:
    events = [
        {"message": "Request from 1.2.3.4 blocked"},
        {"message": "Request from 1.2.3.4 blocked"},
        {"message": "Request from 5.6.7.8 allowed"},
        {"message": "No IP here"},
    ]
    result = CloudWatchService.extract_top_ips(events)
    assert len(result) >= 2
    assert result[0]["ip"] == "1.2.3.4"
    assert result[0]["count"] == 2
    assert result[1]["ip"] == "5.6.7.8"
    assert result[1]["count"] == 1


def test_extract_top_ips_filters_private(service: CloudWatchService) -> None:
    events = [
        {"message": "internal 10.0.0.1 request"},
        {"message": "internal 172.16.5.5 request"},
        {"message": "internal 192.168.1.100 request"},
        {"message": "loopback 127.0.0.1 request"},
        {"message": "public 203.0.113.42 request"},
    ]
    result = CloudWatchService.extract_top_ips(events)
    ips = [entry["ip"] for entry in result]
    assert "10.0.0.1" not in ips
    assert "172.16.5.5" not in ips
    assert "192.168.1.100" not in ips
    assert "127.0.0.1" not in ips
    assert "203.0.113.42" in ips


def test_extract_top_ips_empty(service: CloudWatchService) -> None:
    result = CloudWatchService.extract_top_ips([])
    assert result == []


def test_extract_top_ips_no_ips_in_messages(service: CloudWatchService) -> None:
    events = [
        {"message": "Hello world"},
        {"message": "No addresses here"},
    ]
    result = CloudWatchService.extract_top_ips(events)
    assert result == []


def test_extract_top_ips_respects_limit(service: CloudWatchService) -> None:
    events = [
        {"message": f"request from {i}.0.0.1"} for i in range(1, 30)
    ]
    result = CloudWatchService.extract_top_ips(events, limit=5)
    assert len(result) <= 5


def test_extract_top_ips_handles_malformed_ip(service: CloudWatchService) -> None:
    events = [
        {"message": "invalid 999.999.999.999 address"},
        {"message": "valid 8.8.8.8 address"},
    ]
    result = CloudWatchService.extract_top_ips(events)
    ips = [entry["ip"] for entry in result]
    assert "8.8.8.8" in ips
    assert "999.999.999.999" not in ips


# --- list_log_groups ---


def test_list_log_groups_sync(service: CloudWatchService) -> None:
    mock_response = {
        "logGroups": [
            {"logGroupName": "/aws/lambda/my-fn", "storedBytes": 1024, "retentionInDays": 7},
            {"logGroupName": "/aws/ec2/app", "storedBytes": 2048},
        ]
    }
    mock_client = MagicMock()
    mock_client.describe_log_groups.return_value = mock_response

    with patch("boto3.client", return_value=mock_client):
        result = service._list_log_groups_sync("", "us-east-1")

    assert len(result) == 2
    assert result[0]["name"] == "/aws/lambda/my-fn"
    assert result[0]["stored_bytes"] == 1024
    assert result[0]["retention_days"] == 7
    assert result[1]["name"] == "/aws/ec2/app"
    assert result[1]["retention_days"] is None


def test_list_log_groups_async(service: CloudWatchService) -> None:
    mock_response = {
        "logGroups": [
            {"logGroupName": "/aws/rds/cluster", "storedBytes": 512},
        ]
    }
    mock_client = MagicMock()
    mock_client.describe_log_groups.return_value = mock_response

    with patch("boto3.client", return_value=mock_client):
        result = asyncio.run(
            service.list_log_groups(region="eu-west-1")
        )

    assert len(result) == 1
    assert result[0]["name"] == "/aws/rds/cluster"


def test_list_log_groups_with_prefix(service: CloudWatchService) -> None:
    mock_response = {"logGroups": []}
    mock_client = MagicMock()
    mock_client.describe_log_groups.return_value = mock_response

    with patch("boto3.client", return_value=mock_client):
        service._list_log_groups_sync("/aws/lambda", "us-east-1")

    call_kwargs = mock_client.describe_log_groups.call_args[1]
    assert call_kwargs["logGroupNamePrefix"] == "/aws/lambda"


# --- get_log_events ---


def test_get_log_events_sync(service: CloudWatchService) -> None:
    ts_ms = int(datetime(2024, 6, 1, 12, 0, 0).timestamp() * 1000)
    mock_response = {
        "events": [
            {
                "timestamp": ts_ms,
                "message": "ERROR something went wrong",
                "logStreamName": "stream-1",
            }
        ]
    }
    mock_client = MagicMock()
    mock_client.filter_log_events.return_value = mock_response

    start = datetime(2024, 6, 1, 11, 0, 0)
    end = datetime(2024, 6, 1, 13, 0, 0)

    with patch("boto3.client", return_value=mock_client):
        result = service._get_log_events_sync(
            "/aws/lambda/test", start, end, "ERROR", "us-east-1", 100
        )

    assert len(result) == 1
    assert result[0]["message"] == "ERROR something went wrong"
    assert result[0]["log_stream"] == "stream-1"
    assert isinstance(result[0]["timestamp"], datetime)


def test_get_log_events_async(service: CloudWatchService) -> None:
    ts_ms = int(datetime(2024, 6, 1, 12, 0, 0).timestamp() * 1000)
    mock_response = {
        "events": [
            {
                "timestamp": ts_ms,
                "message": "INFO request processed",
                "logStreamName": "stream-2",
            }
        ]
    }
    mock_client = MagicMock()
    mock_client.filter_log_events.return_value = mock_response

    start = datetime(2024, 6, 1, 11, 0, 0)
    end = datetime(2024, 6, 1, 13, 0, 0)

    with patch("boto3.client", return_value=mock_client):
        result = asyncio.run(
            service.get_log_events(
                log_group="/aws/lambda/test",
                start_time=start,
                end_time=end,
                region="us-east-1",
            )
        )

    assert len(result) == 1
    assert result[0]["log_stream"] == "stream-2"


def test_get_log_events_filter_pattern_passed(service: CloudWatchService) -> None:
    mock_response = {"events": []}
    mock_client = MagicMock()
    mock_client.filter_log_events.return_value = mock_response

    start = datetime(2024, 6, 1, 11, 0, 0)
    end = datetime(2024, 6, 1, 13, 0, 0)

    with patch("boto3.client", return_value=mock_client):
        service._get_log_events_sync(
            "/aws/lambda/test", start, end, "ERROR", "us-east-1", 100
        )

    call_kwargs = mock_client.filter_log_events.call_args[1]
    assert call_kwargs["filterPattern"] == "ERROR"


def test_get_log_events_max_events_respected(service: CloudWatchService) -> None:
    ts_ms = int(datetime(2024, 6, 1, 12, 0, 0).timestamp() * 1000)
    events = [
        {"timestamp": ts_ms, "message": f"event {i}", "logStreamName": "s"}
        for i in range(10)
    ]
    mock_response = {"events": events}
    mock_client = MagicMock()
    mock_client.filter_log_events.return_value = mock_response

    start = datetime(2024, 6, 1, 11, 0, 0)
    end = datetime(2024, 6, 1, 13, 0, 0)

    with patch("boto3.client", return_value=mock_client):
        result = service._get_log_events_sync(
            "/aws/lambda/test", start, end, "", "us-east-1", 3
        )

    assert len(result) == 3


# --- pagination ---


def test_list_log_groups_pagination(service: CloudWatchService) -> None:
    page1 = {
        "logGroups": [{"logGroupName": "/group/1", "storedBytes": 0}],
        "nextToken": "tok-abc",
    }
    page2 = {
        "logGroups": [{"logGroupName": "/group/2", "storedBytes": 0}],
    }
    mock_client = MagicMock()
    mock_client.describe_log_groups.side_effect = [page1, page2]

    with patch("boto3.client", return_value=mock_client):
        result = service._list_log_groups_sync("", "us-east-1")

    assert len(result) == 2
    assert mock_client.describe_log_groups.call_count == 2
    second_call_kwargs = mock_client.describe_log_groups.call_args_list[1][1]
    assert second_call_kwargs["nextToken"] == "tok-abc"


def test_get_log_events_pagination(service: CloudWatchService) -> None:
    ts_ms = int(datetime(2024, 6, 1, 12, 0, 0).timestamp() * 1000)

    def make_event(msg: str) -> dict:
        return {"timestamp": ts_ms, "message": msg, "logStreamName": "s"}

    page1 = {"events": [make_event("event-1")], "nextToken": "tok-xyz"}
    page2 = {"events": [make_event("event-2")]}
    mock_client = MagicMock()
    mock_client.filter_log_events.side_effect = [page1, page2]

    start = datetime(2024, 6, 1, 11, 0, 0)
    end = datetime(2024, 6, 1, 13, 0, 0)

    with patch("boto3.client", return_value=mock_client):
        result = service._get_log_events_sync(
            "/aws/lambda/test", start, end, "", "us-east-1", 100
        )

    assert len(result) == 2
    assert mock_client.filter_log_events.call_count == 2
    second_call_kwargs = mock_client.filter_log_events.call_args_list[1][1]
    assert second_call_kwargs["nextToken"] == "tok-xyz"


# --- normalize_filter_pattern (the auto-quote fix) ---


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("9.9.9.9", '"9.9.9.9"'),   # bare IP must be quoted
        ("/wp-login.php", '"/wp-login.php"'),     # path must be quoted
        ("ERROR", "ERROR"),                        # alnum token unchanged
        ("404", "404"),                            # numeric token unchanged
        ('"9.9.9.9"', '"9.9.9.9"'),   # already quoted unchanged
        ("{ $.httpRequest.clientIp = \"1.2.3.4\" }",
         "{ $.httpRequest.clientIp = \"1.2.3.4\" }"),  # JSON selector unchanged
        ("[ip, user, ts]", "[ip, user, ts]"),     # space-delimited unchanged
        ("?ERROR ?WARN", "?ERROR ?WARN"),          # multi-term unchanged
        ("-/health", '-"/health"'),                # exclusion path: sign kept
        ("", ""),
    ],
)
def test_normalize_filter_pattern(raw, expected):
    assert CloudWatchService.normalize_filter_pattern(raw) == expected


# --- run_insights_query ---


def test_run_insights_query_polls_until_complete():
    service = CloudWatchService()
    client = MagicMock()
    client.start_query.return_value = {"queryId": "q-1"}
    client.get_query_results.side_effect = [
        {"status": "Running", "results": []},
        {
            "status": "Complete",
            "results": [
                [{"field": "clientIp", "value": "1.2.3.4"},
                 {"field": "hits", "value": "50"}],
                [{"field": "clientIp", "value": "5.6.7.8"},
                 {"field": "hits", "value": "9"}],
            ],
            "statistics": {"recordsScanned": 1000},
        },
    ]
    start = datetime(2024, 6, 1, 11, 0, 0)
    end = datetime(2024, 6, 1, 12, 0, 0)
    with patch.object(service, "_logs_client", return_value=client), \
            patch("servonaut.services.cloudwatch_service.time.sleep"):
        res = service._run_insights_query_sync(
            ["/aws/waf/logs"], "stats count(*) by clientIp",
            start, end, "us-east-1", 1000, 60,
        )
    assert res["status"] == "Complete"
    assert res["columns"] == ["clientIp", "hits"]
    assert res["rows"][0] == {"clientIp": "1.2.3.4", "hits": "50"}
    # start_query used epoch seconds, not millis.
    assert client.start_query.call_args.kwargs["startTime"] == int(start.timestamp())


def test_run_insights_query_timeout_stops_query():
    service = CloudWatchService()
    client = MagicMock()
    client.start_query.return_value = {"queryId": "q-2"}
    client.get_query_results.return_value = {"status": "Running", "results": []}
    start = datetime(2024, 6, 1, 11, 0, 0)
    end = datetime(2024, 6, 1, 12, 0, 0)
    # Make the deadline already past so the loop exits immediately.
    times = iter([1000.0, 2000.0, 3000.0, 4000.0])
    with patch.object(service, "_logs_client", return_value=client), \
            patch("servonaut.services.cloudwatch_service.time.sleep"), \
            patch("servonaut.services.cloudwatch_service.time.time",
                  side_effect=lambda: next(times)):
        res = service._run_insights_query_sync(
            ["/g"], "fields @message", start, end, "", 100, 5,
        )
    assert res["status"] == "Timeout"
    client.stop_query.assert_called_once_with(queryId="q-2")
