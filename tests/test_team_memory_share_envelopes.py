"""Sharing a server reads the owner's envelopes; a failed read must not shrink the grant.

A grant posted without one module's wraps is refused by the service as
``insufficient_wraps``, which the forms report as a member's changed key. The
read's own failure (a rate limit, a locked memory key, a server error) is the
truth to report, and nothing is posted. A module with no envelope (404) is
still left out, as before.
"""

from __future__ import annotations

import asyncio

import pytest

from servonaut.services.api_client import APIError, RateLimitedError
from servonaut.services.memory.team_service import MemorySyncLockedError
from tests._bulk_share_fakes import (
    SLUG,
    FakeTeamBackend,
    grant,
    member,
    rate_limited,
    team_memory_service,
)
from servonaut.services.memory.interfaces import MemoryNotFound


def _share(backend: FakeTeamBackend, *, locked: bool = False, modules=("os", "logs")):
    service = team_memory_service(backend, locked=locked)
    keys = asyncio.run(service.list_team_member_keys(SLUG))
    return asyncio.run(service.share_instance(SLUG, "web-1", "member", list(modules), keys))


def _backend() -> FakeTeamBackend:
    return FakeTeamBackend(members=[member(2, "Kim")], stored={"web-1": ["os", "logs"]})


def test_a_rate_limited_envelope_read_is_raised_and_nothing_is_posted():
    backend = _backend()
    backend.envelope_errors["web-1/logs"] = [rate_limited("3")]
    with pytest.raises(RateLimitedError):
        _share(backend)
    assert backend.writes() == []


def test_a_failed_envelope_read_is_raised_and_nothing_is_posted():
    backend = _backend()
    backend.envelope_errors["web-1/logs"] = [APIError(code="x", message="boom", status=500)]
    with pytest.raises(APIError):
        _share(backend)
    assert backend.writes() == []


def test_a_module_with_no_envelope_is_still_left_out():
    backend = _backend()
    backend.envelope_errors["web-1/logs"] = [MemoryNotFound("access_revoked")]
    created = _share(backend)
    assert created.instance_id == "web-1"
    assert {w["envelope_id"] for w in backend.posted[0]["wraps"]} == {"e-os"}


def test_a_locked_memory_key_raises_instead_of_posting_an_empty_grant():
    backend = _backend()
    with pytest.raises(MemorySyncLockedError):
        _share(backend, locked=True)
    assert backend.writes() == []


def test_share_again_with_a_locked_memory_key_keeps_the_share():
    backend = FakeTeamBackend(members=[member(2, "Kim")], stored={"web-1": ["os"]},
                              live=[grant("web-1")])
    service = team_memory_service(backend, locked=True)
    keys = asyncio.run(service.list_team_member_keys(SLUG))
    with pytest.raises(MemorySyncLockedError):
        asyncio.run(service.reshare_instance(SLUG, "g-1", "web-1", "member", ["os"], keys))
    assert backend.writes() == []  # never revoked
