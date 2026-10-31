"""An automatic pin never overwrites what the user confirmed while it was in flight."""

from __future__ import annotations

from tests.test_memory_sync_team_topup import (  # noqa: F401  (fixture re-export)
    WRAPS,
    _Server,
    _drain,
    _missing,
    _no_pause,
    _recipient,
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
from servonaut.services.memory.team_wraps import pinned_fingerprint

CONFIRMED = "b" * 64


def test_a_catch_up_in_flight_leaves_a_key_confirmed_meanwhile(tmp_path):
    entry, _pair_ = _recipient(8)

    class Racing(_Server):
        async def post(self, path, *, json=None, **kw):
            if path == WRAPS:
                self.svc._pin_store().set_many({("team-a", 8): CONFIRMED})
            return await super().post(path, json=json, **kw)

    server = Racing([_missing([entry])])
    server.svc = _sync_service(tmp_path, server)
    _drain(server.svc)
    assert server.svc._pin_store().get("team-a", 8) == CONFIRMED


def test_share_leaves_a_key_confirmed_while_the_grant_was_being_created(tmp_path):
    svc, api, pins = _service(tmp_path)
    lee, _p = _member(2, "Lee")
    original = api.post.side_effect

    async def racing(*args, **kwargs):
        pins.set_many({(SLUG, 2): CONFIRMED})
        return await original(*args, **kwargs) if original else api.post.return_value

    api.post.side_effect = racing
    run(svc.share_instance(SLUG, OWNER, "member", ["os"], [lee]))
    assert pinned_fingerprint(pins, SLUG, 2) == CONFIRMED


def test_top_up_leaves_a_key_confirmed_while_the_wraps_were_posted(tmp_path):
    svc, api, pins = _service(tmp_path)
    pair = _pair()
    api.get.return_value = _coverage(svc, [_descriptor(3, pair)])

    async def racing(*args, **kwargs):
        pins.set_many({(SLUG, 3): CONFIRMED})
        return {"wraps_stored": 1}

    api.post.side_effect = racing
    run(svc.top_up_grant(SLUG, "g"))
    assert pinned_fingerprint(pins, SLUG, 3) == CONFIRMED
