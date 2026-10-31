"""A snapshot uploaded for a shared server reaches the members of the live share.

The service accepts the owner's upload with the owner's wrap only and names the
members that still miss one (``missing_team_wraps``). The client seals the
snapshot's data key for exactly those members and posts the wraps to the
share's catch-up route. Real crypto with generated keys; only HTTP is faked.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
from typing import Any, Dict, List

import pytest

from servonaut.services.api_client import APIError, NotFoundError, RateLimitedError
from servonaut.services.memory import crypto
from servonaut.services.memory import sync_service as sync_module
from tests.test_memory_sync_service import (
    _make_api_client,
    _make_module_result,
    _make_service,
)

SELF_ID = 42
SERVER = {"id": "web-1", "name": "web-1"}
SYNC = "/api/v1/memory/sync"
WRAPS = "/api/v1/teams/team-a/memory/grant/grant-1/wraps"


def _recipient(uid: int, /, **overrides: Any):
    pair = crypto.generate_keypair()
    entry = {
        "user_id": uid,
        "name": f"member-{uid}",
        "fingerprint": pair.fingerprint,
        "public_key_b64": base64.b64encode(pair.public_key).decode(),
        "key_changed": False,
        "previous_fingerprint": None,
        "key_rotated_at": None,
    }
    entry.update(overrides)
    return entry, pair


def _missing(recipients: List[Dict[str, Any]], **overrides: Any) -> Dict[str, Any]:
    entry = {
        "envelope_id": "env-1",
        "instance_id": "web-1",
        "module": "os",
        "team_slug": "team-a",
        "grant_id": "grant-1",
        "recipients": recipients,
    }
    entry.update(overrides)
    return entry


class _Server:
    """Records the uploaded envelopes and the catch-up posts; answers both."""

    def __init__(self, missing: Any, wraps_effects: List[Any] = ()) -> None:
        self.missing = missing
        self.uploads: List[Dict[str, Any]] = []
        self.wrap_posts: List[Dict[str, Any]] = []
        self.wrap_effects = list(wraps_effects)

    async def post(self, path: str, *, json: Any = None, **_: Any) -> Dict[str, Any]:
        if path == SYNC:
            self.uploads.extend(json["envelopes"])
            response = {"accepted": [{"id": "env-1", "module": "os"}], "rejected": []}
            missing = self.missing(self.uploads) if callable(self.missing) else self.missing
            if missing is not None:
                response["missing_team_wraps"] = missing
            return response
        self.wrap_posts.append({"path": path, "json": json})
        if self.wrap_effects:
            effect = self.wrap_effects.pop(0)
            if isinstance(effect, Exception):
                raise effect
        return {"wraps_stored": len(json["wraps"]), "wraps_unchanged": 0, "skipped_recipients": []}


def _service(tmp_path, server: _Server):
    api = _make_api_client()
    api.post.side_effect = server.post
    svc = _make_service(api_client=api, tmp_path=tmp_path)
    own = crypto.generate_keypair()
    svc._self_pubkey, svc._self_privkey, svc._self_user_id = (
        own.public_key, own.private_key, SELF_ID,
    )
    return svc


def _drain(svc):
    svc.enqueue_module(SERVER, "os", _make_module_result(instance_id="web-1"))
    return asyncio.run(svc.drain_now())


def _opens(server: _Server, wrap: Dict[str, Any], pair, index: int = 0) -> Dict[str, Any]:
    """The recipient's private key opens the wrap and the data key opens the upload."""
    upload = server.uploads[index]
    shape = {k: upload[k] for k in ("iv", "tag", "ciphertext")}
    shape["wrapped_dek"] = wrap["wrapped_dek"]
    plain = crypto.decrypt_envelope(
        shape, self_user_id=wrap["recipient_user_id"],
        self_private_key=pair.private_key, self_public_key=pair.public_key,
    )
    return json.loads(plain)


@pytest.fixture(autouse=True)
def _no_pause(monkeypatch):
    waits: List[float] = []

    async def fake(seconds: float) -> None:
        waits.append(seconds)

    monkeypatch.setattr(sync_module, "_pause", fake, raising=False)
    return waits


def test_each_named_member_gets_a_wrap_that_opens_the_snapshot(tmp_path):
    first, first_pair = _recipient(7)
    second, second_pair = _recipient(8)
    server = _Server([_missing([first, second])])
    result = _drain(_service(tmp_path, server))
    assert len(result.accepted) == 1
    assert len(server.wrap_posts) == 1  # one POST per grant
    post = server.wrap_posts[0]
    assert post["path"] == WRAPS
    wraps = {w["recipient_user_id"]: w for w in post["json"]["wraps"]}
    assert set(wraps) == {7, 8}
    assert all(w["envelope_id"] == "env-1" for w in wraps.values())
    assert wraps[7]["recipient_fingerprint"] == first["fingerprint"]
    assert wraps[8]["recipient_fingerprint"] == second["fingerprint"]
    for uid, pair in ((7, first_pair), (8, second_pair)):
        assert _opens(server, wraps[uid], pair)["observed"] == {"cpu_count": 4, "ram_gb": 8}


def test_a_member_whose_key_changed_is_never_sealed_for_and_is_logged_once(tmp_path, caplog):
    keep, keep_pair = _recipient(7)
    changed, _ = _recipient(8, key_changed=True)
    other_entry = _missing([changed], envelope_id="env-2", module="runtimes")
    server = _Server([_missing([keep, changed]), other_entry])
    with caplog.at_level(logging.INFO):
        _drain(_service(tmp_path, server))
    sent = [w["recipient_user_id"] for p in server.wrap_posts for w in p["json"]["wraps"]]
    assert sent == [7]
    notes = [r.getMessage() for r in caplog.records if "key changed" in r.getMessage()]
    assert len(notes) == 1  # once per grant, however many envelopes


def test_a_grant_that_is_not_live_or_gone_is_skipped_without_failing_the_upload(tmp_path):
    for error in (
        APIError(code="grant_not_live", message="revoked", status=409),
        NotFoundError(code="not_found", message="gone", status=404),
    ):
        member, _ = _recipient(7)
        server = _Server([_missing([member])], [error])
        svc = _service(tmp_path, server)
        result = _drain(svc)
        assert len(result.accepted) == 1
        assert svc.status.state == "idle" and svc.status.last_error is None
        assert len(server.wrap_posts) == 1  # no retry


def test_a_rate_limited_catch_up_waits_once_and_retries_once(tmp_path, _no_pause):
    member, pair = _recipient(7)
    limited = RateLimitedError(
        code="rate_limited", message="slow", status=429,
        response_headers={"retry-after": "3"},
    )
    server = _Server([_missing([member])], [limited])
    result = _drain(_service(tmp_path, server))
    assert len(result.accepted) == 1
    assert len(server.wrap_posts) == 2
    assert _no_pause == [3.0]
    wrap = server.wrap_posts[1]["json"]["wraps"][0]
    assert _opens(server, wrap, pair)["observed"]["cpu_count"] == 4


def test_a_second_rate_limit_gives_up_for_this_batch(tmp_path, _no_pause):
    member, _ = _recipient(7)
    limited = RateLimitedError(code="rate_limited", message="slow", status=429)
    server = _Server([_missing([member])], [limited, limited])
    svc = _service(tmp_path, server)
    result = _drain(svc)
    assert len(result.accepted) == 1
    assert len(server.wrap_posts) == 2
    assert svc.status.last_error is None


def test_a_wait_longer_than_the_cap_is_not_slept(tmp_path, _no_pause):
    member, _ = _recipient(7)
    limited = RateLimitedError(
        code="rate_limited", message="slow", status=429,
        response_headers={"retry-after": "3600"},
    )
    server = _Server([_missing([member])], [limited])
    _drain(_service(tmp_path, server))
    assert _no_pause == []
    assert len(server.wrap_posts) == 1


def test_any_catch_up_failure_leaves_the_upload_and_status_alone(tmp_path):
    member, _ = _recipient(7)
    server = _Server([_missing([member])], [RuntimeError("boom"), ])
    svc = _service(tmp_path, server)
    result = _drain(svc)
    assert len(result.accepted) == 1
    assert svc.status.state == "idle"
    assert svc.status.last_error is None
    assert svc.pending_count() == 0


@pytest.mark.parametrize(
    "payload",
    [
        "nope",
        {"envelope_id": "env-1"},
        [None, 5, "x"],
        [{"envelope_id": 1, "instance_id": "web-1", "module": "os",
          "team_slug": "team-a", "grant_id": "grant-1", "recipients": []}],
        [{"envelope_id": "env-1", "instance_id": "web-1", "module": "os",
          "team_slug": "../x", "grant_id": "grant-1", "recipients": [{}]}],
        [{"envelope_id": "env-1", "instance_id": "web-1", "module": "os",
          "team_slug": "team-a", "grant_id": "g/../1", "recipients": [{}]}],
        [{"envelope_id": "env-1", "instance_id": "web-1", "module": "os",
          "team_slug": "team-a", "grant_id": "grant-1", "recipients": "nobody"}],
    ],
)
def test_a_malformed_payload_is_ignored_with_a_shape_only_log(tmp_path, caplog, payload):
    server = _Server(payload)
    with caplog.at_level(logging.DEBUG):
        result = _drain(_service(tmp_path, server))
    assert len(result.accepted) == 1
    assert server.wrap_posts == []
    logged = " ".join(r.getMessage() for r in caplog.records if "missing_team_wraps" in r.getMessage())
    assert logged  # ignored visibly, at debug level
    assert "grant-1" not in logged and "env-1" not in logged  # the shape, never the values


@pytest.mark.parametrize(
    "tweak",
    [
        {"public_key_b64": "!!!not-base64"},
        {"public_key_b64": base64.b64encode(b"short").decode()},
        {"user_id": "7"},
        {"user_id": True},
        {"fingerprint": "0" * 64},  # does not belong to the key
        {"key_changed": None},
    ],
)
def test_a_malformed_recipient_is_skipped_and_the_good_one_still_served(tmp_path, tweak):
    bad, _ = _recipient(9, **tweak)
    good, good_pair = _recipient(7)
    server = _Server([_missing([bad, good])])
    _drain(_service(tmp_path, server))
    sent = [w["recipient_user_id"] for p in server.wrap_posts for w in p["json"]["wraps"]]
    assert sent == [7]


def test_nothing_is_sent_when_the_response_names_nobody(tmp_path):
    server = _Server(None)
    result = _drain(_service(tmp_path, server))
    assert len(result.accepted) == 1
    assert server.wrap_posts == []


def test_an_envelope_not_in_this_batch_is_not_wrapped(tmp_path):
    member, _ = _recipient(7)
    server = _Server([_missing([member], instance_id="db-9")])
    _drain(_service(tmp_path, server))
    assert server.wrap_posts == []


def test_no_data_key_or_private_key_reaches_the_log(tmp_path, caplog):
    member, _ = _recipient(7)
    bad, _ = _recipient(8, public_key_b64=base64.b64encode(b"\x00" * 32).decode())
    server = _Server([_missing([member, bad]), "garbage"], [RuntimeError("boom")])
    svc = _service(tmp_path, server)
    with caplog.at_level(logging.DEBUG):
        _drain(svc)
    upload = server.uploads[0]
    own = next(w for w in upload["dek_wraps"] if w["recipient_user_id"] == SELF_ID)
    import nacl.public
    dek = nacl.public.SealedBox(nacl.public.PrivateKey(svc._self_privkey)).decrypt(
        base64.b64decode(own["wrapped_dek"])
    )
    secrets = {
        "dek": dek, "private": svc._self_privkey,
    }
    text = caplog.text
    for name, raw in secrets.items():
        for form in (raw.hex(), base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode(), repr(raw)):
            assert form not in text, name
    for wrap in upload["dek_wraps"]:
        assert wrap["wrapped_dek"] not in text


def test_two_snapshots_of_one_module_each_get_their_wraps_over_two_batches(tmp_path):
    member, pair = _recipient(7)

    def missing(uploads):
        return [_missing([member], envelope_id=f"env-{len(uploads)}")]

    server = _Server(missing)
    svc = _service(tmp_path, server)
    svc.enqueue_module(SERVER, "os", _make_module_result(instance_id="web-1"))
    svc.enqueue_module(SERVER, "os", _make_module_result(instance_id="web-1"))
    first = asyncio.run(svc.drain_now())
    second = asyncio.run(svc.drain_now())
    assert (len(first.accepted), len(second.accepted)) == (1, 1)
    assert [len(u["dek_wraps"]) for u in server.uploads] == [1, 1]
    assert [p["json"]["wraps"][0]["envelope_id"] for p in server.wrap_posts] == ["env-1", "env-2"]
    for index, post in enumerate(server.wrap_posts):
        assert _opens(server, post["json"]["wraps"][0], pair, index)["observed"]["cpu_count"] == 4


def test_a_cancelled_catch_up_wait_never_requeues_the_accepted_upload(tmp_path, monkeypatch):
    member, _ = _recipient(7)
    limited = RateLimitedError(
        code="rate_limited", message="slow", status=429,
        response_headers={"retry-after": "3"},
    )
    server = _Server([_missing([member])], [limited])

    async def cancelled(seconds: float) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(sync_module, "_pause", cancelled)
    svc = _service(tmp_path, server)
    svc.enqueue_module(SERVER, "os", _make_module_result(instance_id="web-1"))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(svc.drain_now())
    assert svc.pending_count() == 0
    assert svc._inflight is None
    asyncio.run(svc.drain_now())
    assert len(server.uploads) == 1  # no second upload


@pytest.mark.parametrize("key", [b"\x00" * 32, b"\x01" + b"\x00" * 31, bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")])
def test_a_bad_recipient_key_costs_only_that_recipient(tmp_path, key):
    bad, _ = _recipient(
        9, public_key_b64=base64.b64encode(key).decode(), fingerprint=crypto.fingerprint(key)
    )
    good, good_pair = _recipient(7)
    server = _Server([_missing([bad, good])])
    _drain(_service(tmp_path, server))
    wraps = [w for p in server.wrap_posts for w in p["json"]["wraps"]]
    assert [w["recipient_user_id"] for w in wraps] == [7]
    assert _opens(server, wraps[0], good_pair)["observed"]["cpu_count"] == 4


def test_a_member_whose_key_differs_from_the_one_sealed_for_before_is_skipped(tmp_path, caplog):
    first, _ = _recipient(7)
    server = _Server(lambda uploads: [_missing([first], envelope_id=f"env-{len(uploads)}")])
    svc = _service(tmp_path, server)
    _drain(svc)
    assert len(server.wrap_posts) == 1
    pin_file = tmp_path / "memory" / "team_wrap_pins.json"
    assert pin_file.stat().st_mode & 0o777 == 0o600

    swapped, _ = _recipient(7)  # same user, another key, not flagged key_changed
    fresh, _ = _recipient(8)
    server.missing = lambda uploads: [_missing([swapped, fresh], envelope_id="env-2")]
    with caplog.at_level(logging.INFO):
        _drain(svc)
    sent = [w["recipient_user_id"] for w in server.wrap_posts[1]["json"]["wraps"]]
    assert sent == [8]  # a new member is sealed (and pinned), the swapped key is not
    assert sum("key changed" in r.getMessage() for r in caplog.records) == 1
    server.missing = lambda uploads: [_missing([first], envelope_id="env-3")]
    _drain(svc)
    assert [w["recipient_user_id"] for w in server.wrap_posts[2]["json"]["wraps"]] == [7]


def test_the_client_method_posts_wraps_with_a_json_keyword():
    from unittest.mock import MagicMock

    from servonaut.services.memory.team_service import TeamMemoryService

    api = _make_api_client(post_return={"wraps_stored": 1})
    service = TeamMemoryService(api, MagicMock(), MagicMock(), lambda: None, MagicMock())
    body = [{"recipient_user_id": 7, "envelope_id": "e", "wrapped_dek": "x",
             "recipient_fingerprint": "f"}]
    asyncio.run(service.post_grant_wraps("team-a", "grant-1", body))
    api.post.assert_awaited_once_with(WRAPS, json={"wraps": body})


def test_catch_up_waits_default_to_the_config_fields():
    from servonaut.config.schema import MemoryConfig

    defaults = MemoryConfig()
    assert (defaults.team_wrap_retry_seconds, defaults.team_wrap_max_wait_seconds) == (5.0, 30.0)
