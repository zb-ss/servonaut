"""Personal binding reads: reused briefly, paused after the service refuses one."""
from __future__ import annotations

import asyncio

import pytest

from servonaut.services.api_client import APIError
from servonaut.services.vault.binding_reads import BindingReadsPaused, PersonalBindingReads
from servonaut.services.vault.errors import vault_failure_reason


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _Fetch:
    """Counts calls; answers with *result* or raises *error*."""

    def __init__(self, result=None, error: Exception | None = None) -> None:
        self.calls = 0
        self.result = result
        self.error = error

    async def __call__(self):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result


def _reads(clock: _Clock, *, ttl: float = 60.0, backoff: float = 30.0, session=lambda: "token-1") -> PersonalBindingReads:
    return PersonalBindingReads(ttl_seconds=ttl, backoff_seconds=backoff, session=session, clock=clock)


def _refusal(status: int, retry_after: str | None = None) -> APIError:
    headers = {"retry-after": retry_after} if retry_after is not None else {}
    return APIError(code="rate_limited" if status == 429 else "unauthorized", message="opaque",
                    status=status, response_headers=headers)


@pytest.mark.asyncio
async def test_an_answer_is_reused_until_it_expires() -> None:
    clock = _Clock()
    reads = _reads(clock)
    fetch = _Fetch({"vault_id": "v"})

    assert await reads.read("k", fetch) == {"vault_id": "v"}
    clock.now += 59
    assert await reads.read("k", fetch) == {"vault_id": "v"}
    assert fetch.calls == 1
    clock.now += 2
    await reads.read("k", fetch)
    assert fetch.calls == 2


@pytest.mark.asyncio
async def test_nothing_bound_is_remembered_too() -> None:
    # Most own servers have no binding (404): those reads are the bulk of a fleet loop.
    reads = _reads(_Clock())
    fetch = _Fetch(None)
    assert await reads.read("k", fetch) is None
    assert await reads.read("k", fetch) is None
    assert fetch.calls == 1


@pytest.mark.asyncio
async def test_a_fresh_read_skips_the_remembered_answer_and_replaces_it() -> None:
    reads = _reads(_Clock())
    await reads.read("k", _Fetch(None))
    newer = _Fetch({"vault_id": "v"})
    assert await reads.read("k", newer, fresh=True) == {"vault_id": "v"}
    assert await reads.read("k", _Fetch(None)) == {"vault_id": "v"}
    assert newer.calls == 1


@pytest.mark.asyncio
async def test_forget_drops_one_answer() -> None:
    reads = _reads(_Clock())
    await reads.read("a", _Fetch(None))
    await reads.read("b", _Fetch(None))
    reads.forget("a")
    a, b = _Fetch(None), _Fetch(None)
    await reads.read("a", a)
    await reads.read("b", b)
    assert (a.calls, b.calls) == (1, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("ttl, key", [(0, "k"), (60.0, None)])
async def test_a_zero_window_or_no_key_reads_every_time(ttl, key) -> None:
    reads = _reads(_Clock(), ttl=ttl)
    fetch = _Fetch(None)
    await reads.read(key, fetch)
    await reads.read(key, fetch)
    assert fetch.calls == 2


@pytest.mark.asyncio
async def test_callers_get_a_copy_of_the_remembered_answer() -> None:
    reads = _reads(_Clock())
    first = await reads.read("k", _Fetch({"host_keys": ["a"]}))
    first["host_keys"].append("changed")
    assert await reads.read("k", _Fetch(None)) == {"host_keys": ["a"]}


@pytest.mark.asyncio
async def test_a_failed_read_is_not_remembered_and_other_errors_pass_through() -> None:
    reads = _reads(_Clock())
    unavailable = APIError(code="unavailable", message="opaque", status=503)
    with pytest.raises(APIError) as caught:
        await reads.read("k", _Fetch(error=unavailable))
    assert caught.value is unavailable
    retry = _Fetch(None)
    await reads.read("k", retry)
    assert retry.calls == 1


@pytest.mark.asyncio
async def test_a_429_pauses_every_read_for_its_retry_after() -> None:
    clock = _Clock()
    reads = _reads(clock, backoff=30.0)
    refused = _refusal(429, retry_after="42")

    with pytest.raises(BindingReadsPaused) as caught:
        await reads.read("a", _Fetch(error=refused))
    assert caught.value.__cause__ is refused
    assert "limiting requests" in vault_failure_reason(caught.value)
    assert "try again in 42 s" in str(caught.value)

    # Other servers' reads send nothing until the wait is over.
    later = _Fetch(None)
    clock.now += 40
    with pytest.raises(BindingReadsPaused, match="try again in 2 s"):
        await reads.read("b", later)
    assert later.calls == 0
    clock.now += 2
    assert await reads.read("b", later) is None
    assert later.calls == 1


@pytest.mark.asyncio
async def test_a_remembered_answer_is_given_while_paused_but_a_fresh_read_is_refused() -> None:
    clock = _Clock()
    reads = _reads(clock)
    await reads.read("a", _Fetch({"vault_id": "v"}))
    with pytest.raises(BindingReadsPaused):
        await reads.read("b", _Fetch(error=_refusal(429, retry_after="30")))

    assert await reads.read("a", _Fetch(None)) == {"vault_id": "v"}
    fresh = _Fetch(None)
    with pytest.raises(BindingReadsPaused):
        await reads.read("a", fresh, fresh=True)
    assert fresh.calls == 0


@pytest.mark.asyncio
async def test_a_429_without_retry_after_pauses_for_the_configured_backoff() -> None:
    clock = _Clock()
    reads = _reads(clock, backoff=30.0)
    with pytest.raises(BindingReadsPaused, match="try again in 30 s"):
        await reads.read("a", _Fetch(error=_refusal(429)))
    clock.now += 29
    with pytest.raises(BindingReadsPaused):
        await reads.read("a", _Fetch(None))
    clock.now += 1
    assert await reads.read("a", _Fetch(None)) is None


@pytest.mark.asyncio
async def test_concurrent_refusals_keep_the_longest_wait() -> None:
    clock = _Clock()
    reads = _reads(clock)
    answer = asyncio.Event()

    async def refused(wait: str):
        await answer.wait()
        raise _refusal(429, wait)

    # Both requests are already out when the first refusal arrives.
    tasks = [asyncio.create_task(reads.read(key, lambda wait=wait: refused(wait)))
             for key, wait in (("a", "50"), ("b", "10"))]
    await asyncio.sleep(0)
    answer.set()
    for task in tasks:
        with pytest.raises(BindingReadsPaused):
            await task
    clock.now += 20
    with pytest.raises(BindingReadsPaused, match="try again in 30 s"):
        await reads.read("a", _Fetch(None))


@pytest.mark.asyncio
async def test_a_401_pauses_until_the_sign_in_changes() -> None:
    clock = _Clock()
    session = {"token": "dead"}
    reads = _reads(clock, backoff=300.0, session=lambda: session["token"])

    with pytest.raises(BindingReadsPaused) as caught:
        await reads.read("a", _Fetch(error=_refusal(401)))
    assert "servonaut login" in str(caught.value)
    blocked = _Fetch(None)
    with pytest.raises(BindingReadsPaused, match="servonaut login"):
        await reads.read("b", blocked)
    assert blocked.calls == 0

    session["token"] = "fresh"  # `servonaut login`, or another process refreshed
    assert await reads.read("b", blocked) is None
    assert blocked.calls == 1


@pytest.mark.asyncio
async def test_a_401_pause_also_ends_after_the_backoff() -> None:
    clock = _Clock()
    reads = _reads(clock, backoff=60.0)
    with pytest.raises(BindingReadsPaused):
        await reads.read("a", _Fetch(error=_refusal(401)))
    clock.now += 60
    assert await reads.read("a", _Fetch(None)) is None


@pytest.mark.asyncio
async def test_clear_drops_answers_and_the_pause() -> None:
    reads = _reads(_Clock())
    await reads.read("a", _Fetch(None))
    with pytest.raises(BindingReadsPaused):
        await reads.read("b", _Fetch(error=_refusal(429)))
    reads.clear()
    fetch = _Fetch(None)
    await reads.read("a", fetch)
    assert fetch.calls == 1
