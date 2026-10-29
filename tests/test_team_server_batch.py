"""Sharing many servers with a team: one inventory read, each server once, rate limits respected."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.api_client import APIClient, APIError, RateLimitedError
from servonaut.services.team_service import TeamService
from servonaut.config.schema import AppConfig


def _payload(name: str, host: str, *, port: int | None = None, instance_id: str | None = None) -> dict:
    payload = {"name": name, "hostname": host}
    if port is not None:
        payload["port"] = port
    if instance_id is not None:
        payload["instance_id"] = instance_id
    return payload


@pytest.fixture
def api():
    api = MagicMock(spec=APIClient)
    api.get = AsyncMock(return_value={"data": []})
    api.post = AsyncMock(side_effect=lambda _path, json: {"data": {"id": f"srv-{json['name']}", **json}})
    return api


@pytest.fixture
def sleeps(monkeypatch):
    waited: list[float] = []

    async def no_wait(seconds):
        waited.append(seconds)

    monkeypatch.setattr("servonaut.services.team_service.asyncio.sleep", no_wait)
    return waited


def _push(service, servers, **kwargs):
    return asyncio.run(service.push_servers("team-a", servers, **kwargs))


def _rate_limited(retry_after: str | None) -> RateLimitedError:
    headers = {"retry-after": retry_after} if retry_after is not None else {}
    return RateLimitedError(code="rate_limited", message="Too many requests", status=429, response_headers=headers)


def test_a_batch_reads_the_inventory_once_and_shares_each_server(api):
    # Regression: each share re-read the whole inventory first (GET + POST
    # per server against the per-user rate limit), so a batch of ~50 servers
    # failed half way.
    progress: list[tuple[int, int, str]] = []
    servers = [_payload(f"web-{n}", f"web-{n}.example.com") for n in range(1, 6)]

    results = _push(TeamService(api), servers, on_progress=lambda i, total, r: progress.append((i, total, r.status)))

    assert api.get.await_count == 1
    assert api.post.await_count == 5
    assert [r.status for r in results] == ["shared"] * 5
    assert [r.server["id"] for r in results] == [f"srv-web-{n}" for n in range(1, 6)]
    assert progress == [(n, 5, "shared") for n in range(1, 6)]


def test_rate_limit_policy_comes_from_config(api, sleeps):
    api.post.side_effect = [_rate_limited("1"), {"data": {"id": "shared-1"}}]
    config = AppConfig(team_share_rate_limit_wait_seconds=0, team_share_rate_limit_retries=0)
    result = _push(TeamService(api, config=config), [_payload("web-1", "web-1.example.com")])
    assert result[0].status == "failed"
    assert api.post.await_count == 1 and sleeps == []


def test_custom_retry_count_still_obeys_total_wait_budget(api, sleeps):
    api.post.side_effect = [_rate_limited("2"), _rate_limited("2"), {"data": {"id": "shared-1"}}]
    config = AppConfig(team_share_rate_limit_wait_seconds=3, team_share_rate_limit_retries=2)
    result = _push(TeamService(api, config=config), [_payload("web-1", "web-1.example.com")])
    assert result[0].status == "failed"
    assert api.post.await_count == 2 and sleeps == [2.0]


def test_already_shared_servers_and_repeats_in_the_batch_are_not_posted(api):
    api.get.return_value = {"data": [{"id": "srv-1", "name": "web-1", "hostname": "web-1.example.com"}]}
    servers = [
        _payload("web-1", "web-1.example.com"),
        _payload("web-2", "web-2.example.com"),
        _payload("web-2 again", "web-2.example.com"),
    ]

    results = _push(TeamService(api), servers)

    assert [r.status for r in results] == ["already_shared", "shared", "already_shared"]
    assert [call.kwargs["json"]["name"] for call in api.post.await_args_list] == ["web-2"]


def test_one_failure_does_not_stop_the_batch(api):
    def post(_path, json):
        if json["name"] == "web-2":
            raise APIError(code="validation_failed", message="hostname is invalid", status=422)
        return {"data": {"id": f"srv-{json['name']}", **json}}

    api.post.side_effect = post
    servers = [_payload(f"web-{n}", f"web-{n}.example.com") for n in range(1, 4)]

    results = _push(TeamService(api), servers)

    assert [r.status for r in results] == ["shared", "failed", "shared"]
    assert results[1].error == "hostname is invalid"


def test_a_rate_limit_waits_as_asked_and_tries_once_more(api, sleeps):
    calls = {"n": 0}

    def post(_path, json):
        calls["n"] += 1
        if calls["n"] == 2:
            raise _rate_limited("3")
        return {"data": {"id": f"srv-{json['name']}", **json}}

    api.post.side_effect = post
    servers = [_payload(f"web-{n}", f"web-{n}.example.com") for n in range(1, 4)]

    results = _push(TeamService(api), servers)

    assert [r.status for r in results] == ["shared", "shared", "shared"]
    assert sleeps == [3.0]
    assert api.post.await_count == 4


def test_a_rate_limit_that_persists_stops_posting_the_rest(api, sleeps):
    def post(_path, json):
        if json["name"] != "web-1":
            raise _rate_limited("5")
        return {"data": {"id": "srv-web-1", **json}}

    api.post.side_effect = post
    servers = [_payload(f"web-{n}", f"web-{n}.example.com") for n in range(1, 5)]

    results = _push(TeamService(api), servers)

    assert [r.status for r in results] == ["shared", "failed", "failed", "failed"]
    # web-2 twice (first try and the one retry), then nothing more is sent.
    assert [call.kwargs["json"]["name"] for call in api.post.await_args_list] == ["web-1", "web-2", "web-2"]
    assert all("rate limited" in (r.error or "") for r in results[1:])
    assert results[1].retry_after == 5.0


def test_a_rate_limit_longer_than_the_batch_waits_fails_at_once(api, sleeps):
    api.post.side_effect = lambda _path, json: (_ for _ in ()).throw(_rate_limited("600"))
    servers = [_payload(f"web-{n}", f"web-{n}.example.com") for n in range(1, 3)]

    results = _push(TeamService(api), servers)

    assert [r.status for r in results] == ["failed", "failed"]
    assert sleeps == []
    assert api.post.await_count == 1
    assert "try again in 10 min" in results[0].error


def test_an_unreadable_inventory_shares_nothing(api):
    api.get.side_effect = APIError(code="forbidden", message="not a member", status=403)

    with pytest.raises(APIError):
        _push(TeamService(api), [_payload("web-1", "web-1.example.com")])
    api.post.assert_not_awaited()


@pytest.mark.parametrize("header", [None, "inf", "-inf", "nan", "1e999", "soon"])
def test_a_rate_limit_without_a_usable_retry_after_waits_the_default_once(api, sleeps, header):
    # The service's shared-server limiter sends 429 without Retry-After, so
    # the configured budget never applied and the first 429 ended the batch.
    # A malformed header ("inf", "soon"...) is treated like a missing one.
    calls = {"n": 0}

    def post(_path, json):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _rate_limited(header)
        return {"data": {"id": f"srv-{json['name']}", **json}}

    api.post.side_effect = post
    servers = [_payload(f"web-{n}", f"web-{n}.example.com") for n in range(1, 3)]

    results = _push(TeamService(api), servers)

    assert [r.status for r in results] == ["shared", "shared"]
    assert sleeps == [5.0]


def test_a_rate_limit_without_retry_after_that_persists_stops_the_rest(api, sleeps):
    api.post.side_effect = lambda _path, json: (_ for _ in ()).throw(_rate_limited(None))
    servers = [_payload(f"web-{n}", f"web-{n}.example.com") for n in range(1, 4)]

    results = _push(TeamService(api), servers)

    assert [r.status for r in results] == ["failed", "failed", "failed"]
    assert sleeps == [5.0]
    assert api.post.await_count == 2
    assert results[0].retry_after is None
    assert "rate limited: try again later" in results[0].error


def test_without_retry_after_the_default_wait_stays_within_the_budget(api, sleeps):
    api.post.side_effect = [_rate_limited(None), {"data": {"id": "shared-1"}}]
    config = AppConfig(team_share_rate_limit_wait_seconds=2, team_share_rate_limit_retries=1)

    results = _push(TeamService(api, config=config), [_payload("web-1", "web-1.example.com")])

    assert results[0].status == "shared"
    assert sleeps == [2.0]


def test_without_retry_after_a_zero_budget_fails_at_once(api, sleeps):
    api.post.side_effect = [_rate_limited(None), {"data": {"id": "shared-1"}}]
    config = AppConfig(team_share_rate_limit_wait_seconds=0, team_share_rate_limit_retries=1)

    results = _push(TeamService(api, config=config), [_payload("web-1", "web-1.example.com")])

    assert results[0].status == "failed"
    assert sleeps == [] and api.post.await_count == 1


def test_the_default_wait_without_retry_after_comes_from_config(api, sleeps):
    api.post.side_effect = [_rate_limited(None), {"data": {"id": "shared-1"}}]
    config = AppConfig(team_share_rate_limit_default_wait_seconds=1.5)

    results = _push(TeamService(api, config=config), [_payload("web-1", "web-1.example.com")])

    assert results[0].status == "shared"
    assert sleeps == [1.5]


@pytest.mark.parametrize("value", [float("inf"), float("nan"), -1.0])
def test_an_unusable_default_wait_is_refused_before_anything_is_sent(api, value):
    config = AppConfig(team_share_rate_limit_default_wait_seconds=value)

    with pytest.raises(ValueError):
        _push(TeamService(api, config=config), [_payload("web-1", "web-1.example.com")])
    api.post.assert_not_awaited()
