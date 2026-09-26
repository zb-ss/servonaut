"""A failed OVH inventory fetch must never be persisted as an empty fleet.

Same class as the AWS cache wipe: a revoked key made every per-type call
fail, ``fetch_instances`` returned ``[]`` and ``fetch_instances_cached``
saved it over the good cache.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

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


DEDICATED_ROW = {'id': 'ns1.example', 'name': 'db-1', 'provider_type': 'dedicated'}


@pytest.mark.asyncio
async def test_one_failing_source_keeps_its_cached_rows_and_saves_the_rest():
    # The cached VPS row is replaced by the fresh listing; the dedicated
    # server, whose listing was refused, stays from the cache.
    svc = _service(stale=CACHED + [DEDICATED_ROW])
    with patch.object(svc, "_fetch_dedicated",
                      side_effect=_raise("This call has not been granted\nOVH-Query-ID: x")), \
         patch.object(svc, "_fetch_vps", return_value=FRESH):
        result = await svc.fetch_instances_cached(force_refresh=True)

    assert result == FRESH + [DEDICATED_ROW]
    assert saved == [FRESH + [DEDICATED_ROW]]
    assert svc.last_fetch_partial is True
    assert svc.last_fetch_error == (
        "Could not list OVH dedicated servers (This call has not been granted); "
        "showing 1 cached row."
    )


@pytest.mark.asyncio
async def test_one_failing_source_without_a_cache_saves_what_was_listed():
    svc = _service(stale=None)
    with patch.object(svc, "_fetch_dedicated", side_effect=_raise("This call has not been granted")), \
         patch.object(svc, "_fetch_vps", return_value=FRESH):
        result = await svc.fetch_instances_cached(force_refresh=True)

    assert result == FRESH
    assert saved == [FRESH]
    assert svc.last_fetch_partial is True
    assert svc.last_fetch_error == (
        "Could not list OVH dedicated servers (This call has not been granted); "
        "none cached to show."
    )


@pytest.mark.asyncio
async def test_a_stale_cloud_project_keeps_only_its_own_cached_rows():
    gone = [{'id': 'p-gone/1', 'name': 'app-1', 'provider_type': 'cloud'},
            {'id': 'p-gone/2', 'name': 'app-2', 'provider_type': 'cloud'}]
    live_old = [{'id': 'p-live/9', 'name': 'app-9', 'provider_type': 'cloud'}]
    live_new = [{'id': 'p-live/10', 'name': 'app-10', 'provider_type': 'cloud'}]
    svc = OVHService(_make_config(
        include_dedicated=False, include_vps=False, cloud_project_ids=["p-gone", "p-live"],
    ))
    svc._load_cache = lambda ignore_ttl=False: (gone + live_old if ignore_ttl else None)
    svc._save_cache = lambda instances: saved.append(instances)

    def fetch_cloud(project_id):
        if project_id == "p-gone":
            raise Exception("This service does not exist")
        return live_new

    with patch.object(svc, "_fetch_cloud", side_effect=fetch_cloud):
        result = await svc.fetch_instances_cached(force_refresh=True)

    assert result == live_new + gone
    assert saved == [live_new + gone]
    assert "Public Cloud project p-gone (This service does not exist)" in svc.last_fetch_error
    assert "showing 2 cached rows" in svc.last_fetch_error


@pytest.mark.asyncio
async def test_a_full_refresh_after_a_partial_one_clears_the_flag():
    svc = _service(stale=None)
    with patch.object(svc, "_fetch_dedicated", side_effect=_raise()), \
         patch.object(svc, "_fetch_vps", return_value=FRESH):
        await svc.fetch_instances_cached(force_refresh=True)
    with patch.object(svc, "_fetch_dedicated", return_value=[]), \
         patch.object(svc, "_fetch_vps", return_value=FRESH):
        await svc.fetch_instances_cached(force_refresh=True)

    assert svc.last_fetch_partial is False
    assert svc.last_fetch_error is None


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
    assert svc.last_fetch_partial is False


@pytest.mark.asyncio
async def test_refused_listing_calls_keep_the_cache():
    """The real listing helpers must report a refusal, not an empty account."""
    svc = OVHService(_make_config(cloud_project_ids=["proj1"]))
    svc._load_cache = lambda ignore_ttl=False: (CACHED if ignore_ttl else None)
    svc._save_cache = lambda instances: saved.append(instances)
    client = MagicMock()
    client.get.side_effect = Exception("This credential is not valid")
    svc._client = client

    result = await svc.fetch_instances_cached(force_refresh=True)

    assert result == CACHED
    assert saved == []
    assert "credential is not valid" in svc.last_fetch_error
    listed = {c.args[0] for c in client.get.call_args_list}
    assert listed == {"/dedicated/server", "/vps", "/cloud/project/proj1/instance"}


# --- MCP surface -----------------------------------------------------------

@pytest.mark.asyncio
async def test_list_instances_names_the_partly_refreshed_ovh_sources():
    from unittest.mock import AsyncMock

    from tests.test_mcp_tools import make_tools

    ovh = MagicMock()
    ovh.fetch_instances_cached = AsyncMock(return_value=FRESH + [DEDICATED_ROW])
    ovh.last_fetch_partial = True
    ovh.last_fetch_error = (
        "Could not list OVH dedicated servers (This call has not been granted); "
        "showing 1 cached row."
    )
    aws = MagicMock()
    aws.fetch_instances_cached = AsyncMock(return_value=[])
    aws.last_fetch_error = None
    tools = make_tools(aws_service=aws, ovh_service=ovh)

    out = await tools.list_instances()

    assert (
        "Warning: the OVH inventory was only partly refreshed. Could not list OVH "
        "dedicated servers (This call has not been granted); showing 1 cached row."
    ) in out
    assert "last successful fetch" not in out
