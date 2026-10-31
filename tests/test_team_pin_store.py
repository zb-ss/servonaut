"""The pin store is locked, compare-and-set for automatic writes, and fails closed."""

from __future__ import annotations

import base64
import multiprocessing
import os
import stat

import pytest

from servonaut.services.memory import crypto
from servonaut.services.memory.team_wraps import (
    UNREADABLE_PIN,
    Recipient,
    WrapPinStore,
    split_recipients,
)
from servonaut.utils.file_lock import FileLock

FP_A, FP_B, FP_C = "a" * 64, "b" * 64, "c" * 64


def _writer(path: str, worker: int, count: int) -> None:
    store = WrapPinStore(__import__("pathlib").Path(path))
    for index in range(count):
        store.set_many({("team-a", worker * 1000 + index): FP_A})


def test_parallel_processes_do_not_lose_each_others_pins(tmp_path):
    path = tmp_path / "pins.json"
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_writer, args=(str(path), w, 25)) for w in range(4)]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(60)
        assert proc.exitcode == 0
    store = WrapPinStore(path)
    kept = sum(
        store.get("team-a", w * 1000 + i) == FP_A for w in range(4) for i in range(25)
    )
    assert kept == 100


def test_a_missing_file_is_an_empty_store(tmp_path):
    assert WrapPinStore(tmp_path / "pins.json").get("team-a", 1) is None


@pytest.mark.parametrize("content", ["{not json", "[]", '"text"', ""])
def test_an_unreadable_file_is_not_an_empty_store(tmp_path, content):
    path = tmp_path / "pins.json"
    path.write_text(content)
    store = WrapPinStore(path)
    assert store.get("team-a", 1) == UNREADABLE_PIN


def test_every_member_needs_confirming_when_the_file_is_unreadable(tmp_path):
    path = tmp_path / "pins.json"
    path.write_text("{broken")
    pair = crypto.generate_keypair()
    recipient = Recipient(2, pair.fingerprint, pair.public_key, "Lee", flagged=False)
    split = split_recipients(WrapPinStore(path), "team-a", (recipient,))
    assert split.sealable == ()
    [change] = split.changed
    assert change.previous_fingerprint is None  # the sentinel is never shown as a key


def test_automatic_writes_never_overwrite_an_unreadable_file(tmp_path):
    path = tmp_path / "pins.json"
    path.write_text("{broken")
    store = WrapPinStore(path)
    written = store.set_if_seen({("team-a", 2): FP_A}, {("team-a", 2): UNREADABLE_PIN})
    assert written == set()
    assert path.read_text() == "{broken"
    assert not list(tmp_path.glob("*.unreadable-*"))


def test_an_explicit_confirmation_moves_the_unreadable_file_aside_first(tmp_path):
    path = tmp_path / "pins.json"
    path.write_text("{broken")
    store = WrapPinStore(path)
    store.set_many({("team-a", 2): FP_A})
    [aside] = tmp_path.glob("pins.json.unreadable-*")
    assert aside.read_text() == "{broken"
    assert stat.S_IMODE(aside.stat().st_mode) == 0o600
    assert store.get("team-a", 2) == FP_A
    assert store.get("team-a", 3) is None


def test_an_automatic_write_leaves_a_pin_that_changed_since_it_was_seen(tmp_path):
    store = WrapPinStore(tmp_path / "pins.json")
    store.set_many({("team-a", 2): FP_A, ("team-a", 3): FP_A})
    # The decision saw FP_A for both; user 2 was confirmed to FP_B meanwhile.
    store.set_many({("team-a", 2): FP_B})
    written = store.set_if_seen(
        {("team-a", 2): FP_A, ("team-a", 3): FP_C, ("team-a", 4): FP_A},
        {("team-a", 2): FP_A, ("team-a", 3): FP_A, ("team-a", 4): None},
    )
    assert written == {("team-a", 3), ("team-a", 4)}
    assert store.get("team-a", 2) == FP_B
    assert store.get("team-a", 3) == FP_C
    assert store.get("team-a", 4) == FP_A


def test_a_busy_lock_means_not_saved(tmp_path):
    path = tmp_path / "pins.json"
    store = WrapPinStore(path, lock_wait=lambda: (0.05, 0.01))
    holder = FileLock(tmp_path / "pins.json.lock")
    assert holder.try_acquire()
    try:
        with pytest.raises(OSError):
            store.set_many({("team-a", 2): FP_A})
    finally:
        holder.release()
    assert not path.exists()


def test_the_pin_file_stays_private(tmp_path):
    store = WrapPinStore(tmp_path / "pins.json")
    store.set_many({("team-a", 2): FP_A})
    assert stat.S_IMODE(os.stat(tmp_path / "pins.json").st_mode) == 0o600
