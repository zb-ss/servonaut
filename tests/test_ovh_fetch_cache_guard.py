"""A failed OVH inventory fetch must never be persisted as an empty fleet.

Same class as the AWS cache wipe: a revoked key made every per-type call
fail, ``fetch_instances`` returned ``[]`` and ``fetch_instances_cached``
saved it over the good cache.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from servonaut.services.ovh_service import OVHFetchError, OVHService
from tests.test_ovh_service import _make_config

CACHED = [{'id': 'vps-1', 'name': 'web-1', 'provider_type': 'vps'}]
FRESH = [{'id': 'vps-2', 'name': 'web-2', 'provider_type': 'vps'}]


def _raise(message="Invalid credential"):
    def _inner(*_args, **_kwargs):
        raise Exception(message)
    return _inner


def _service(stale=CACHED):
    svc = OVHService(_make_config(include_dedicated=True, include_vps=True, include_cloud=False))
    svc._load_cache = lambda ignore_ttl=False: (stale if ignore_ttl else None)  # expired
    svc._save_cache = lambda instances: saved.append(instances)
    return svc


saved: list = []


@pytest.fixture(autouse=True)
def _reset_saved():
    saved.clear()


@pytest.mark.asyncio
async def test_every_source_failing_raises_instead_of_returning_empty():
    svc = _service()
    with patch.object(svc, "_fetch_dedicated", side_effect=_raise()), \
         patch.object(svc, "_fetch_vps", side_effect=_raise()):
        with pytest.raises(OVHFetchError, match="all 2 OVH source"):
            await svc.fetch_instances()


@pytest.mark.asyncio
async def test_failed_fetch_keeps_stale_cache_and_never_saves():
    svc = _service()
    with patch.object(svc, "_fetch_dedicated", side_effect=_raise()), \
         patch.object(svc, "_fetch_vps", side_effect=_raise()):
        result = await svc.fetch_instances_cached(force_refresh=True)

    assert result == CACHED
    assert saved == []
    assert "Invalid credential" in svc.last_fetch_error


@pytest.mark.asyncio
async def test_failed_fetch_without_any_cache_returns_empty_and_never_saves():
    svc = _service(stale=None)
    with patch.object(svc, "_fetch_dedicated", side_effect=_raise()), \
         patch.object(svc, "_fetch_vps", side_effect=_raise()):
        result = await svc.fetch_instances_cached(force_refresh=True)

    assert result == []
    assert saved == []
    assert svc.last_fetch_error


@pytest.mark.asyncio
async def test_partial_failure_is_shown_but_not_persisted():
    svc = _service()
    with patch.object(svc, "_fetch_dedicated", side_effect=_raise()), \
         patch.object(svc, "_fetch_vps", return_value=FRESH):
        result = await svc.fetch_instances_cached(force_refresh=True)

    assert result == FRESH
    assert saved == []
    assert "dedicated" in svc.last_fetch_error


@pytest.mark.asyncio
async def test_successful_fetch_saves_and_clears_the_error():
    svc = _service()
    svc.last_fetch_error = "stale from an earlier failure"
    with patch.object(svc, "_fetch_dedicated", return_value=[]), \
         patch.object(svc, "_fetch_vps", return_value=FRESH):
        result = await svc.fetch_instances_cached(force_refresh=True)

    assert result == FRESH
    assert saved == [FRESH]
    assert svc.last_fetch_error is None


@pytest.mark.asyncio
async def test_genuinely_empty_account_is_a_valid_cacheable_result():
    svc = _service()
    with patch.object(svc, "_fetch_dedicated", return_value=[]), \
         patch.object(svc, "_fetch_vps", return_value=[]):
        result = await svc.fetch_instances_cached(force_refresh=True)

    assert result == []
    assert saved == [[]]
    assert svc.last_fetch_error is None
