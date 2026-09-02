"""A failed AWS inventory fetch must never be persisted as an empty fleet.

Regression for the cache wipe: an MCP server whose environment carried
``AWS_PROFILE=""`` could not list regions, the service returned ``[]`` and
``fetch_instances_cached`` saved that over a good cache, so the TUI loaded a
"fresh" empty inventory and skipped its own fetch.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.services.aws_service import AWSFetchError, AWSService
from servonaut.services.cache_service import CacheService

CACHED = [{'id': 'i-0123456789abcdef0', 'name': 'web-1', 'region': 'eu-west-2'}]
FRESH = [{'id': 'i-0fedcba987654321f', 'name': 'web-2', 'region': 'eu-west-2'}]
PROFILE_ERROR = RuntimeError("The config profile () could not be found")


def _cache(stale=CACHED):
    cache = MagicMock(spec=CacheService)
    cache.load.return_value = None  # expired: every cached call must fetch
    cache.load_any.return_value = stale
    return cache


def _regions(*names):
    """boto3 stand-in whose ec2 client lists the given regions."""
    boto3 = MagicMock()
    boto3.client.return_value.describe_regions.return_value = {
        'Regions': [{'RegionName': n} for n in names],
    }
    return boto3


def _regions_failing():
    boto3 = MagicMock()
    boto3.client.return_value.describe_regions.side_effect = PROFILE_ERROR
    return boto3


@pytest.mark.asyncio
async def test_regions_failure_raises_instead_of_returning_empty():
    svc = AWSService(_cache())
    with patch('servonaut.services.aws_service.boto3', _regions_failing()):
        with pytest.raises(AWSFetchError, match="could not list AWS regions"):
            await svc.fetch_instances()


@pytest.mark.asyncio
async def test_failed_fetch_keeps_stale_cache_and_never_saves():
    cache = _cache()
    svc = AWSService(cache)
    with patch('servonaut.services.aws_service.boto3', _regions_failing()):
        result = await svc.fetch_instances_cached(force_refresh=True)

    assert result == CACHED
    cache.save.assert_not_called()
    assert "config profile" in svc.last_fetch_error


@pytest.mark.asyncio
async def test_failed_fetch_without_any_cache_returns_empty_and_never_saves():
    cache = _cache(stale=None)
    svc = AWSService(cache)
    with patch('servonaut.services.aws_service.boto3', _regions_failing()):
        result = await svc.fetch_instances_cached(force_refresh=True)

    assert result == []
    cache.save.assert_not_called()
    assert svc.last_fetch_error


@pytest.mark.asyncio
async def test_every_region_failing_counts_as_a_failed_fetch():
    cache = _cache()
    svc = AWSService(cache)
    svc._fetch_region = MagicMock(side_effect=PROFILE_ERROR)
    with patch('servonaut.services.aws_service.boto3', _regions('eu-west-2', 'us-east-1')):
        result = await svc.fetch_instances_cached(force_refresh=True)

    assert result == CACHED
    cache.save.assert_not_called()
    assert "all 2 AWS regions failed" in svc.last_fetch_error


@pytest.mark.asyncio
async def test_partial_region_failure_is_shown_but_not_persisted():
    cache = _cache()
    svc = AWSService(cache)
    svc._fetch_region = MagicMock(
        side_effect=lambda region: FRESH if region == 'eu-west-2' else (_ for _ in ()).throw(PROFILE_ERROR)
    )
    with patch('servonaut.services.aws_service.boto3', _regions('eu-west-2', 'us-east-1')):
        result = await svc.fetch_instances_cached(force_refresh=True)

    assert result == FRESH
    cache.save.assert_not_called()
    assert "us-east-1" in svc.last_fetch_error


@pytest.mark.asyncio
async def test_successful_fetch_saves_and_clears_the_error():
    cache = _cache()
    svc = AWSService(cache)
    svc.last_fetch_error = "stale from an earlier failure"
    svc._fetch_region = MagicMock(return_value=FRESH)
    with patch('servonaut.services.aws_service.boto3', _regions('eu-west-2')):
        result = await svc.fetch_instances_cached(force_refresh=True)

    assert result == FRESH
    cache.save.assert_called_once_with(FRESH)
    assert svc.last_fetch_error is None


@pytest.mark.asyncio
async def test_genuinely_empty_account_is_a_valid_cacheable_result():
    cache = _cache()
    svc = AWSService(cache)
    svc._fetch_region = MagicMock(return_value=[])
    with patch('servonaut.services.aws_service.boto3', _regions('eu-west-2')):
        result = await svc.fetch_instances_cached(force_refresh=True)

    assert result == []
    cache.save.assert_called_once_with([])
    assert svc.last_fetch_error is None


@pytest.mark.asyncio
async def test_fresh_cache_is_served_without_touching_aws():
    cache = _cache()
    cache.load.return_value = CACHED
    svc = AWSService(cache)
    with patch('servonaut.services.aws_service.boto3', _regions_failing()) as boto3:
        result = await svc.fetch_instances_cached()

    assert result == CACHED
    boto3.client.assert_not_called()


# --- MCP surface -----------------------------------------------------------

@pytest.mark.asyncio
async def test_list_instances_warns_when_the_inventory_is_stale():
    from tests.test_mcp_tools import make_tools

    aws = MagicMock()
    aws.fetch_instances_cached = AsyncMock(return_value=CACHED)
    aws.last_fetch_error = "could not list AWS regions: The config profile () could not be found"
    tools = make_tools(aws_service=aws)

    out = await tools.list_instances()

    assert 'web-1' in out
    assert 'Warning: the AWS inventory could not be refreshed' in out
    assert 'config profile' in out


@pytest.mark.asyncio
async def test_list_instances_has_no_warning_after_a_good_fetch():
    from tests.test_mcp_tools import make_tools

    aws = MagicMock()
    aws.fetch_instances_cached = AsyncMock(return_value=CACHED)
    aws.last_fetch_error = None
    tools = make_tools(aws_service=aws)

    out = await tools.list_instances()

    assert 'Warning' not in out
