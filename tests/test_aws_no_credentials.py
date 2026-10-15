"""No AWS credentials at all means AWS is not set up here, not a failed refresh.

A Hetzner- or OVH-only user, or a new team member, has no AWS credentials;
every refresh used to end in an "AWS refresh failed" warning for them. With no
credentials and nothing ever listed, the fetch now returns no instances and
reports nothing. With an earlier listing on disk, or credentials that fail,
the warning stays.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import NoCredentialsError

from servonaut.config.accounts import AccountRef
from servonaut.services.accounts import AccountBinding, AccountFleet
from servonaut.services.aws_service import AWSFetchError, AWSNoCredentialsError, AWSService
from servonaut.services.cache_service import CacheService

CACHED = [{"id": "i-0123456789abcdef0", "name": "web-1", "region": "eu-west-2"}]
FRESH = [{"id": "i-0fedcba987654321f", "name": "web-2", "region": "eu-west-2"}]


def _cache(stale=None):
    cache = MagicMock(spec=CacheService)
    cache.load.return_value = None
    cache.load_any.return_value = stale
    return cache


def _boto3(*, regions=("eu-west-2", "us-east-1"), regions_error=None):
    boto3 = MagicMock()
    describe = boto3.client.return_value.describe_regions
    if regions_error is not None:
        describe.side_effect = regions_error
    else:
        describe.return_value = {"Regions": [{"RegionName": name} for name in regions]}
    return boto3


@pytest.mark.asyncio
async def test_no_credentials_and_nothing_listed_before_is_quiet():
    cache = _cache(stale=None)
    svc = AWSService(cache)
    with patch("servonaut.services.aws_service.boto3", _boto3(regions_error=NoCredentialsError())):
        rows = await svc.fetch_instances_cached(force_refresh=True)

    assert rows == []
    assert svc.last_fetch_error is None
    assert svc.credentials_missing is True
    assert isinstance(svc.last_fetch_exception, AWSNoCredentialsError)
    cache.save.assert_not_called()


@pytest.mark.asyncio
async def test_every_region_without_credentials_is_quiet():
    svc = AWSService(_cache(stale=None))
    with patch("servonaut.services.aws_service.boto3", _boto3()), \
            patch.object(AWSService, "_fetch_region", side_effect=NoCredentialsError()):
        rows = await svc.fetch_instances_cached(force_refresh=True)

    assert rows == []
    assert svc.last_fetch_error is None
    assert svc.credentials_missing is True


@pytest.mark.asyncio
async def test_an_earlier_listing_keeps_the_warning():
    """Credentials that disappeared after AWS was listed are worth telling the user."""
    svc = AWSService(_cache(stale=CACHED))
    with patch("servonaut.services.aws_service.boto3", _boto3(regions_error=NoCredentialsError())):
        rows = await svc.fetch_instances_cached(force_refresh=True)

    assert rows == CACHED
    assert "could not list AWS regions" in svc.last_fetch_error
    assert svc.credentials_missing is False


@pytest.mark.asyncio
async def test_credentials_that_fail_still_warn():
    svc = AWSService(_cache(stale=None))
    errors = [NoCredentialsError(), RuntimeError("AuthFailure: credentials expired")]
    with patch("servonaut.services.aws_service.boto3", _boto3()), \
            patch.object(AWSService, "_fetch_region", side_effect=errors):
        rows = await svc.fetch_instances_cached(force_refresh=True)

    assert rows == []
    assert "all 2 AWS regions failed" in svc.last_fetch_error
    assert svc.credentials_missing is False


@pytest.mark.asyncio
async def test_no_credentials_is_still_an_error_for_a_direct_fetch():
    """fetch_instances itself never turns a failed call into "no instances"."""
    svc = AWSService(_cache(stale=None))
    with patch("servonaut.services.aws_service.boto3", _boto3(regions_error=NoCredentialsError())):
        with pytest.raises(AWSFetchError):
            await svc.fetch_instances()


@pytest.mark.asyncio
async def test_a_later_clean_refresh_clears_the_flag():
    svc = AWSService(_cache(stale=None))
    with patch("servonaut.services.aws_service.boto3", _boto3(regions_error=NoCredentialsError())):
        await svc.fetch_instances_cached(force_refresh=True)
    with patch("servonaut.services.aws_service.boto3", _boto3(regions=("eu-west-2",))), \
            patch.object(AWSService, "_fetch_region", return_value=FRESH):
        rows = await svc.fetch_instances_cached(force_refresh=True)

    assert rows == FRESH
    assert svc.credentials_missing is False


def test_the_fleet_reports_missing_credentials_only_when_every_account_has_none():
    def binding(label, missing):
        return AccountBinding(AccountRef("aws", label, label == "aws"), SimpleNamespace(credentials_missing=missing))

    assert AccountFleet("aws", [binding("aws", True), binding("prod", True)]).credentials_missing is True
    assert AccountFleet("aws", [binding("aws", True), binding("prod", False)]).credentials_missing is False
