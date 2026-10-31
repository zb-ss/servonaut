"""A confirmed member key is never lost, guessed or reported wrongly.

Covers the pin store schema, the expectation each automatic pin is bound to,
the strict reading of the service's acknowledgements, and the pin writes
staying off the event loop.
"""

from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock

import pytest

from servonaut.services.memory.team_wraps import (
    UNREADABLE_PIN,
    WrapPinStore,
    pinned_fingerprint,
    stored_wraps,
)
from servonaut.utils.file_lock import FileLock
from tests.test_memory_sync_service import _make_module_result
from tests.test_memory_sync_team_topup import (
    WRAPS,
    _drain,
    _missing,
    _recipient,
    _Server,
    _service as _sync_service,
)
from tests.test_team_key_confirmation import (
    OWNER,
    SLUG,
    _coverage,
    _descriptor,
    _member,
    _pair,
    _service,
    run,
)

FP_A, FP_B = "a" * 64, "b" * 64
STORED_ONE = {"wraps_stored": 1, "wraps_unchanged": 0, "skipped_recipients": []}


# --- the whole pin file is validated -------------------------------

@pytest.mark.parametrize("entry", [
    {"team-a:2": None},
    {"team-a:2": 7},
    {"team-a:2": ["x"]},
    {"team-a:2": {"x": 1}},
    {"team-a:2": "A" * 64},
    {"team-a:2": "a" * 63},
    {"team-a:two": "a" * 64},
    {"team-a:0": "a" * 64},
    {"team-a:-1": "a" * 64},
    {"../x:2": "a" * 64},
    {"nocolon": "a" * 64},
])
def test_one_malformed_entry_makes_the_whole_store_unreadable(tmp_path, entry):
    path = tmp_path / "pins.json"
    path.write_text(json.dumps({**entry, "team-a:3": FP_A}))
    store = WrapPinStore(path)
    assert store.get("team-a", 3) == UNREADABLE_PIN  # the valid sibling is not trusted either
    assert store.set_if_seen({("team-a", 3, FP_B): FP_B}, {("team-a", 3, FP_B): FP_A}) == set()
    assert json.loads(path.read_text()) == {**entry, "team-a:3": FP_A}
    assert not list(tmp_path.glob("*.unreadable-*"))


def test_an_explicit_confirmation_moves_a_malformed_store_aside(tmp_path):
    path = tmp_path / "pins.json"
    path.write_text(json.dumps({"team-a:2": None}))
    WrapPinStore(path).set_many({("team-a", 2): FP_B})
    [aside] = tmp_path.glob("pins.json.unreadable-*")
    assert json.loads(aside.read_text()) == {"team-a:2": None}


def test_a_well_formed_store_is_read_as_before(tmp_path):
    path = tmp_path / "pins.json"
    path.write_text(json.dumps({"team-a:2": FP_A, "team_b-1:10": FP_B}))
    store = WrapPinStore(path)
    assert (store.get("team-a", 2), store.get("team_b-1", 10)) == (FP_A, FP_B)


# --- an automatic pin keeps the expectation of its own decision -----

def test_a_later_envelope_does_not_change_what_an_earlier_seal_expected(tmp_path):
    svc, api, pins = _service(tmp_path)
    key_a = _pair()
    pins.set_many({(SLUG, 3): key_a.fingerprint})
    payload = _coverage(svc, [_descriptor(3, key_a, name="Lee")])
    second = dict(payload["envelopes"][0], envelope_id="e-services", module="services")
    payload["envelopes"].append(second)
    api.get.return_value = payload
    fetched = []

    async def raw(_instance, module):
        fetched.append(module)
        if len(fetched) == 1:  # another window confirms a different key meanwhile
            pins.set_many({(SLUG, 3): FP_B})
        return {"id": "e-os" if module == "os" else "e-services", "wrapped_dek": svc.own_wrap()}

    svc._retrieval_service.get_module_envelope_raw = AsyncMock(side_effect=raw)
    api.post.return_value = STORED_ONE
    run(svc.top_up_grant(SLUG, "g", OWNER, None))
    assert pinned_fingerprint(pins, SLUG, 3) == FP_B


def test_a_catch_up_batch_keeps_the_expectation_of_its_first_decision(tmp_path):
    first, _p = _recipient(8)
    entries = [_missing([first]), _missing([first], envelope_id="env-2", module="services")]

    server = _Server(entries)
    svc = _sync_service(tmp_path, server)
    svc._pin_store().set_many({("team-a", 8): first["fingerprint"]})
    original = svc._pin_store().get
    reads = []

    def get(team, user):
        reads.append(1)
        value = original(team, user)
        if len(reads) == 1:  # the first entry was judged; now the user confirms another key
            svc._pin_store().set_many({("team-a", 8): FP_B})
        return value

    svc._pin_store().get = get
    _drain(svc)
    assert original("team-a", 8) == FP_B


# --- Share never pins a recipient the grant create skipped ----------

def _share(svc, members):
    return run(svc.share_instance(SLUG, OWNER, "member", ["os"], members))


@pytest.mark.parametrize("skipped", [
    [{"user_id": 2, "reason": "not_eligible"}],
    [{"user_id": 2, "reason": "no_memory_key"}],
])
def test_share_does_not_pin_a_recipient_the_service_skipped(tmp_path, skipped):
    svc, api, pins = _service(tmp_path)
    lee, _p = _member(2, "Lee")
    kim, _q = _member(3, "Kim")
    api.post.return_value = {**api.post.return_value, "skipped_recipients": skipped}
    _share(svc, [lee, kim])
    assert pinned_fingerprint(pins, SLUG, 2) is None
    assert pinned_fingerprint(pins, SLUG, 3) == kim.fingerprint


@pytest.mark.parametrize("skipped", ["x", {"user_id": 2}, [{"user_id": "2", "reason": "r"}],
                                     [{"user_id": 2}], [{"reason": "r"}], [7]])
def test_a_malformed_skip_list_pins_nobody_but_the_share_stands(tmp_path, skipped):
    svc, api, pins = _service(tmp_path)
    lee, _p = _member(2, "Lee")
    api.post.return_value = {**api.post.return_value, "skipped_recipients": skipped}
    grant = _share(svc, [lee])
    assert grant.id == "g"
    assert pinned_fingerprint(pins, SLUG, 2) is None


def test_a_grant_response_without_a_skip_list_pins_nobody_but_the_share_stands(tmp_path):
    svc, api, pins = _service(tmp_path)
    lee, _p = _member(2, "Lee")
    response = dict(api.post.return_value)
    response.pop("skipped_recipients", None)
    api.post.return_value = response
    grant = _share(svc, [lee])
    assert grant.id == "g"
    assert pinned_fingerprint(pins, SLUG, 2) is None


def test_share_again_does_not_pin_a_skipped_recipient(tmp_path):
    svc, api, pins = _service(tmp_path)
    lee, _p = _member(2, "Lee")
    api.post.return_value = {**api.post.return_value,
                             "skipped_recipients": [{"user_id": 2, "reason": "not_eligible"}]}
    run(svc.reshare_instance(SLUG, "g", OWNER, "member", ["os"], [lee]))
    assert pinned_fingerprint(pins, SLUG, 2) is None


# --- the wraps acknowledgement has to add up ------------------------

def _wraps(*users, envelopes=("e1",)):
    return [{"recipient_user_id": u, "envelope_id": e} for u in users for e in envelopes]


@pytest.mark.parametrize("response", [
    {"wraps_stored": 1, "wraps_unchanged": 0, "skipped_recipients": []},  # 1 of 2
    {"wraps_stored": 99, "wraps_unchanged": 0, "skipped_recipients": []},
    {"wraps_stored": 2, "wraps_unchanged": 1, "skipped_recipients": []},
    {"wraps_stored": 2, "wraps_unchanged": 0, "skipped_recipients": [{"user_id": 3}]},
    {"wraps_stored": 1, "wraps_unchanged": 0,
     "skipped_recipients": [{"user_id": 3, "reason": ""}]},
    {"wraps_stored": 1, "wraps_unchanged": 0,
     "skipped_recipients": [{"user_id": 3, "reason": 5}]},
    {"wraps_stored": 1, "wraps_unchanged": 0,
     "skipped_recipients": [{"user_id": True, "reason": "x"}]},
])
def test_an_acknowledgement_that_does_not_add_up_counts_nothing_as_stored(response):
    assert stored_wraps(_wraps(2, 3), response) == []


@pytest.mark.parametrize("response", [
    {"wraps_stored": 2, "wraps_unchanged": 0, "skipped_recipients": []},
    {"wraps_stored": 1, "wraps_unchanged": 1, "skipped_recipients": []},
    {"wraps_stored": 0, "wraps_unchanged": 2, "skipped_recipients": []},
])
def test_a_consistent_acknowledgement_keeps_every_wrap(response):
    assert len(stored_wraps(_wraps(2, 3), response)) == 2


def test_the_count_is_over_unique_recipient_envelope_pairs_of_the_unskipped():
    wraps = _wraps(2, 3, envelopes=("e1", "e2")) + _wraps(2)  # one duplicate pair
    ok = {"wraps_stored": 2, "wraps_unchanged": 0,
          "skipped_recipients": [{"user_id": 3, "reason": "key_changed"}]}
    assert {w["recipient_user_id"] for w in stored_wraps(wraps, ok)} == {2}
    assert stored_wraps(wraps, dict(ok, wraps_stored=3)) == []


def test_top_up_reports_an_inconsistent_acknowledgement_as_unconfirmed(tmp_path):
    svc, api, pins = _service(tmp_path)
    api.get.return_value = _coverage(svc, [_descriptor(3, _pair(), name="Kim"),
                                           _descriptor(4, _pair(), name="Lee")])
    api.post.return_value = STORED_ONE  # two posted, one stored
    result = run(svc.top_up_grant(SLUG, "g", OWNER, ["os"]))
    assert result.sealed_names == ()
    assert sorted(result.skipped_names) == ["Kim", "Lee"]
    assert dict(zip(result.skipped_names, result.skipped_reasons)) == {
        "Kim": "unconfirmed", "Lee": "unconfirmed"}
    assert pinned_fingerprint(pins, SLUG, 3) is None


# --- a skipped recipient keeps its validated reason -----------------

@pytest.mark.parametrize("sent,expected", [
    ("key_changed", "key_changed"), ("no_memory_key", "no_memory_key"),
    ("not_eligible", "not_eligible"), ("something_new", "unconfirmed"),
])
def test_top_up_keeps_the_skip_reason_of_each_recipient(tmp_path, sent, expected):
    svc, api, _ = _service(tmp_path)
    api.get.return_value = _coverage(svc, [_descriptor(3, _pair(), name="Kim"),
                                           _descriptor(4, _pair(), name="Lee")])
    api.post.return_value = {"wraps_stored": 1, "wraps_unchanged": 0,
                             "skipped_recipients": [{"user_id": 4, "reason": sent}]}
    result = run(svc.top_up_grant(SLUG, "g", OWNER, ["os"]))
    assert result.skipped_names == ("Lee",) and result.skipped_reasons == (expected,)


# --- pin writes never block the event loop --------------------------

def _hold(tmp_path):
    holder = FileLock(tmp_path / "pins.json.lock")
    assert holder.try_acquire()
    return holder


async def _ticks_while(coro):
    """How many 10 ms ticks fired while *coro* ran."""
    ticks = 0
    stop = False

    async def ticker():
        nonlocal ticks
        while not stop:
            await asyncio.sleep(0.01)
            ticks += 1

    task = asyncio.create_task(ticker())
    try:
        await coro
    finally:
        stop = True
        await task
    return ticks


def _slow_store(svc, tmp_path):
    pins = WrapPinStore(tmp_path / "pins.json", lock_wait=lambda: (0.3, 0.01))
    svc._pin_store_provider = lambda: pins
    return pins


def test_the_automatic_pins_of_a_top_up_keep_the_loop_running(tmp_path):
    svc, api, _ = _service(tmp_path)
    _slow_store(svc, tmp_path)
    api.get.return_value = _coverage(svc, [_descriptor(3, _pair(), name="Kim")])
    api.post.return_value = STORED_ONE
    holder = _hold(tmp_path)
    try:
        ticks = asyncio.run(_ticks_while(svc.top_up_grant(SLUG, "g", OWNER, ["os"])))
    finally:
        holder.release()
    assert ticks >= 10


def test_the_automatic_pins_of_share_keep_the_loop_running(tmp_path):
    svc, _api, _ = _service(tmp_path)
    _slow_store(svc, tmp_path)
    lee, _p = _member(2, "Lee")
    holder = _hold(tmp_path)
    try:
        ticks = asyncio.run(_ticks_while(svc.share_instance(SLUG, OWNER, "member", ["os"], [lee])))
    finally:
        holder.release()
    assert ticks >= 10


def test_the_automatic_pins_of_a_catch_up_keep_the_loop_running(tmp_path):
    entry, _p = _recipient(7)
    server = _Server([_missing([entry])])
    svc = _sync_service(tmp_path, server)
    store = svc._pin_store()
    store._lock_wait = lambda: (0.3, 0.01)
    holder = FileLock(store._path.with_name(store._path.name + ".lock"))
    assert holder.try_acquire()
    svc.enqueue_module({"id": "web-1", "name": "web-1"}, "os",
                       _make_module_result(instance_id="web-1"))
    try:
        ticks = asyncio.run(_ticks_while(svc.drain_now()))
    finally:
        holder.release()
    assert ticks >= 10
