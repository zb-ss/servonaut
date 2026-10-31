"""Service-level guards for shared team memory (reader, service, paths)."""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import nacl.public
import pytest

import servonaut.services.memory.crypto as crypto_module
from servonaut.services.api_client import APIClient
from servonaut.services.memory.shared_view import SharedMemoryReader, merge_shared
from servonaut.services.memory.team_service import (
    KeyChangedError,
    TeamMemberKey,
    TeamMemoryService,
)

SLUG = "team-a"
OWNER = "i-owner-1"


def run(coro):
    return asyncio.run(coro)


def _material() -> Any:
    private = nacl.public.PrivateKey.generate()
    km = MagicMock()
    km.user_id = 7
    km.private_key, km.public_key = bytes(private), bytes(private.public_key)
    return km


def _sealed(material, payload, *, instance=OWNER, module="os", probed_at=None):
    env = crypto_module.encrypt_envelope(
        json.dumps(payload).encode(),
        self_public_key=material.public_key, self_user_id=material.user_id,
    ).to_dict()
    env["wrapped_dek"] = env.pop("dek_wraps")[0]["wrapped_dek"]
    env.update({
        "id": "e-1", "instance_id": instance, "module": module,
        "probed_at": probed_at or "2026-10-20T08:00:00Z", "is_latest": True,
    })
    return env


def _service(api, material, *, skew=300.0):
    auth = MagicMock()
    auth.has_feature = MagicMock(return_value=True)
    return TeamMemoryService(
        api_client=api, auth_service=auth, crypto=crypto_module,
        key_store_provider=lambda: material, retrieval_service=MagicMock(),
        future_skew_provider=lambda: skew,
    )


def _api(reply):
    api = MagicMock(spec=APIClient)
    api.get = AsyncMock(return_value=reply)
    api.post = AsyncMock()
    api.delete = AsyncMock()
    return api


class TestReplyBinding:
    def test_a_reply_for_another_server_is_refused(self):
        m = _material()
        api = _api(_sealed(m, {"observed": {"x": 1}}, instance="i-other"))
        assert run(_service(api, m).read_shared_module(SLUG, OWNER, "os")) is None

    def test_a_reply_for_another_module_is_refused(self):
        m = _material()
        api = _api(_sealed(m, {"observed": {"x": 1}}, module="services"))
        assert run(_service(api, m).read_shared_module(SLUG, OWNER, "os")) is None

    def test_a_future_probed_at_is_clamped_and_cannot_beat_a_local_snapshot(self):
        m = _material()
        api = _api(_sealed(m, {"observed": {"x": 1}}, probed_at="9999-01-01T00:00:00Z"))
        opened = run(_service(api, m).read_shared_module(SLUG, OWNER, "os"))
        stamp = datetime.fromisoformat(opened["probed_at"])
        assert stamp <= datetime.now(timezone.utc) + timedelta(seconds=5)
        local = {"os": {"observed": {"x": "local"},
                        "probed_at": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()}}
        shared = MagicMock(modules={"os": opened})
        assert merge_shared(local, shared)["os"]["observed"] == {"x": "local"}


class TestPathSegments:
    @pytest.mark.parametrize("bad", ["../x", "a/b", "a%2fb", "a\nb", "", "..", "a b"])
    def test_bad_segments_never_reach_a_url(self, bad):
        m = _material()
        api = _api({})
        svc = _service(api, m)
        for call in (
            svc.read_shared_module(bad, OWNER, "os"),
            svc.read_shared_module(SLUG, bad, "os"),
            svc.read_shared_module(SLUG, OWNER, bad),
            svc.revoke_grant(SLUG, bad),
            svc.purge_grant(bad, "g-1"),
        ):
            with pytest.raises(ValueError):
                run(call)
        api.get.assert_not_awaited()
        api.delete.assert_not_awaited()
        api.post.assert_not_awaited()

    def test_the_reader_skips_a_listing_with_an_unsafe_instance_id(self):
        m = _material()
        item = MagicMock()
        item.grant.instance_id = "../etc"
        item.instance = {}
        item.readable_modules = ["os"]
        team = MagicMock()
        team.list_shared_instances = AsyncMock(return_value=[item])
        team.read_shared_module = AsyncMock(side_effect=ValueError("bad"))
        reader = SharedMemoryReader(team, lambda: 0.0)
        assert run(reader.read(SLUG, "T", "../etc")) is None


class TestAuthoredModules:
    def test_annotations_and_findings_keep_their_payload(self):
        m = _material()
        reader_for = lambda payload, module: run(SharedMemoryReader(
            _svc_returning(m, payload, module), lambda: 0.0).read(SLUG, "T", OWNER))
        notes = reader_for({"content": "Restart workers after deploy."}, "annotations")
        assert notes.modules["annotations"]["content"] == "Restart workers after deploy."
        assert "Restart workers" in str(notes.modules["annotations"]["observed"])
        found = reader_for({"findings": [{"title": "Disk nearly full"}]}, "findings")
        assert found.modules["findings"]["findings"] == [{"title": "Disk nearly full"}]
        assert "Disk nearly full" in str(found.modules["findings"]["observed"])


def _svc_returning(material, payload, module):
    api = MagicMock(spec=APIClient)

    async def get(path, **_kw):
        if path.endswith("/memory"):
            return {"instances": [{
                "grant": {"id": "g-1", "instance_id": OWNER, "required_role": "member",
                          "modules": None, "status": "active", "granted_by_user_id": 1,
                          "created_at": "2026-10-01T10:00:00Z", "revoked_at": None},
                "instance": {"instance_id": OWNER}, "readable_modules": [module],
                "stale_modules": []}]}
        return _sealed(material, payload, module=module)

    api.get = AsyncMock(side_effect=get)
    return _service(api, material)


class TestChangedKeys:
    def _members(self):
        def member(uid, name, changed):
            raw = bytes(nacl.public.PrivateKey.generate().public_key)
            return TeamMemberKey(uid, crypto_module.fingerprint(raw),
                                 base64.b64encode(raw).decode(), "member", name,
                                 key_changed=changed)

        return [member(1, "Kim", False), member(2, "Lee", True)]

    def test_share_again_with_a_changed_key_revokes_nothing_and_posts_nothing(self):
        api = _api({})
        svc = _service(api, _material())
        with pytest.raises(KeyChangedError) as err:
            run(svc.reshare_instance(SLUG, "g-1", OWNER, "member", ["os"], self._members()))
        assert err.value.names == ["Lee"]
        api.delete.assert_not_awaited()
        api.post.assert_not_awaited()

    def test_a_first_share_with_a_changed_key_posts_nothing(self):
        api = _api({})
        svc = _service(api, _material())
        with pytest.raises(KeyChangedError):
            run(svc.share_instance(SLUG, OWNER, "member", ["os"], self._members()))
        api.post.assert_not_awaited()

    def test_a_changed_key_below_the_role_does_not_block(self):
        api = _api({})
        api.post.return_value = {"id": "g", "instance_id": OWNER, "required_role": "admin",
                                 "modules": ["os"], "created_at": "2026-10-01T10:00:00Z"}
        svc = _service(api, _material())
        svc._retrieval_service.list_instance_modules = AsyncMock(return_value={"modules": []})
        run(svc.share_instance(SLUG, OWNER, "admin", ["os"], self._members()))
        api.post.assert_awaited_once()


def test_the_real_access_revoked_code_is_nothing_shared():
    from servonaut.services.api_client import APIError

    m = _material()
    api = _api({})
    api.get.side_effect = APIError(code="access_revoked", message="no readable copy", status=404)
    assert run(_service(api, m).read_shared_module(SLUG, OWNER, "os")) is None


def test_another_error_status_is_still_an_error():
    from servonaut.services.api_client import APIError

    m = _material()
    api = _api({})
    api.get.side_effect = APIError(code="boom", message="x", status=500)
    with pytest.raises(APIError):
        run(_service(api, m).read_shared_module(SLUG, OWNER, "os"))
