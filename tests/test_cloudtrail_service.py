"""Tests for CloudTrailService."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from servonaut.config.schema import AppConfig
from servonaut.services.cloudtrail_service import CloudTrailService


@pytest.fixture
def mock_config_manager():
    config = AppConfig(
        cloudtrail_default_region="us-east-1",
        cloudtrail_max_events=50,
        cloudtrail_default_lookback_hours=12,
    )
    manager = MagicMock()
    manager.get.return_value = config
    return manager


@pytest.fixture
def service(mock_config_manager):
    return CloudTrailService(mock_config_manager)


def _make_raw_event(event_name="RunInstances", username="alice", source_ip="1.2.3.4",
                    error_code="", region="us-east-1"):
    detail = {"sourceIPAddress": source_ip}
    if error_code:
        detail["errorCode"] = error_code
    return {
        "EventTime": datetime(2024, 1, 15, 10, 30, 0),
        "EventName": event_name,
        "Username": username,
        "CloudTrailEvent": json.dumps(detail),
        "Resources": [{"ResourceType": "AWS::EC2::Instance", "ResourceName": "i-abc123"}],
    }


# --- _parse_event ---

def test_parse_event_extracts_all_fields(service):
    raw = _make_raw_event(region="eu-west-1")
    result = service._parse_event(raw, "eu-west-1")

    assert result["event_name"] == "RunInstances"
    assert result["username"] == "alice"
    assert result["source_ip"] == "1.2.3.4"
    assert result["resource_type"] == "AWS::EC2::Instance"
    assert result["resource_name"] == "i-abc123"
    assert result["region"] == "eu-west-1"
    assert result["error_code"] == ""
    assert result["event_time"] == datetime(2024, 1, 15, 10, 30, 0)


def test_parse_event_captures_error_code(service):
    raw = _make_raw_event(error_code="AccessDenied")
    result = service._parse_event(raw, "us-east-1")
    assert result["error_code"] == "AccessDenied"


def test_parse_event_handles_missing_resources(service):
    raw = _make_raw_event()
    raw["Resources"] = []
    result = service._parse_event(raw, "us-east-1")
    assert result["resource_type"] == ""
    assert result["resource_name"] == ""


def test_parse_event_handles_invalid_json(service):
    raw = _make_raw_event()
    raw["CloudTrailEvent"] = "not-json"
    result = service._parse_event(raw, "us-east-1")
    assert result["source_ip"] == ""


# --- lookup_events ---

def test_lookup_events_builds_correct_kwargs(service):
    mock_response = {"Events": [_make_raw_event()]}
    mock_client = MagicMock()
    mock_client.lookup_events.return_value = mock_response

    with patch("boto3.client", return_value=mock_client):
        result = asyncio.run(
            service.lookup_events(region="us-east-1", max_results=10)
        )

    call_kwargs = mock_client.lookup_events.call_args[1]
    assert call_kwargs["MaxResults"] == 10
    assert "StartTime" in call_kwargs
    assert "EndTime" in call_kwargs
    assert len(result) == 1


def test_lookup_events_respects_max_results(service):
    events = [_make_raw_event(event_name=f"Event{i}") for i in range(5)]
    mock_response = {"Events": events}
    mock_client = MagicMock()
    mock_client.lookup_events.return_value = mock_response

    with patch("boto3.client", return_value=mock_client):
        result = asyncio.run(
            service.lookup_events(region="us-east-1", max_results=3)
        )

    assert len(result) <= 3


def test_lookup_events_with_event_name_filter(service):
    mock_response = {"Events": [_make_raw_event(event_name="TerminateInstances")]}
    mock_client = MagicMock()
    mock_client.lookup_events.return_value = mock_response

    with patch("boto3.client", return_value=mock_client):
        asyncio.run(
            service.lookup_events(region="us-east-1", event_name="TerminateInstances")
        )

    call_kwargs = mock_client.lookup_events.call_args[1]
    assert call_kwargs["LookupAttributes"] == [
        {"AttributeKey": "EventName", "AttributeValue": "TerminateInstances"}
    ]


def test_lookup_events_with_username_filter(service):
    mock_response = {"Events": [_make_raw_event(username="bob")]}
    mock_client = MagicMock()
    mock_client.lookup_events.return_value = mock_response

    with patch("boto3.client", return_value=mock_client):
        asyncio.run(
            service.lookup_events(region="us-east-1", username="bob")
        )

    call_kwargs = mock_client.lookup_events.call_args[1]
    assert call_kwargs["LookupAttributes"] == [
        {"AttributeKey": "Username", "AttributeValue": "bob"}
    ]


def test_lookup_events_pagination(service):
    page1 = {"Events": [_make_raw_event(event_name="Event1")], "NextToken": "token-abc"}
    page2 = {"Events": [_make_raw_event(event_name="Event2")]}
    mock_client = MagicMock()
    mock_client.lookup_events.side_effect = [page1, page2]

    with patch("boto3.client", return_value=mock_client):
        result = asyncio.run(
            service.lookup_events(region="us-east-1", max_results=100)
        )

    assert len(result) == 2
    assert mock_client.lookup_events.call_count == 2
    second_call_kwargs = mock_client.lookup_events.call_args_list[1][1]
    assert second_call_kwargs["NextToken"] == "token-abc"


def test_get_available_regions(service):
    mock_response = {
        "Regions": [
            {"RegionName": "us-east-1"},
            {"RegionName": "eu-west-1"},
            {"RegionName": "ap-southeast-1"},
        ]
    }
    mock_client = MagicMock()
    mock_client.describe_regions.return_value = mock_response

    with patch("boto3.client", return_value=mock_client):
        regions = asyncio.run(
            service.get_available_regions()
        )

    assert "us-east-1" in regions
    assert "eu-west-1" in regions
    assert len(regions) == 3


def test_lookup_events_uses_config_lookback_hours(service):
    mock_response = {"Events": []}
    mock_client = MagicMock()
    mock_client.lookup_events.return_value = mock_response

    before = datetime.utcnow()

    with patch("boto3.client", return_value=mock_client):
        asyncio.run(
            service.lookup_events(region="us-east-1")
        )

    after = datetime.utcnow()
    call_kwargs = mock_client.lookup_events.call_args[1]
    start_time = call_kwargs["StartTime"]

    # Config has lookback_hours=12, so start_time should be ~12 hours ago
    expected_start = before - timedelta(hours=12)
    assert abs((start_time - expected_start).total_seconds()) < 5
