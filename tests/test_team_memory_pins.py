"""Share and Share again honour, and record, the sealed-for fingerprints."""

from __future__ import annotations

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock

import nacl.public
import pytest

import servonaut.services.memory.crypto as crypto_module
from servonaut.services.api_client import APIClient
from servonaut.services.memory.team_service import (
    KeyChangedError,
    TeamMemberKey,
    TeamMemoryService,
)
from servonaut.services.memory.team_wraps import WrapPinStore, pinned_fingerprint

SLUG = "team-a"
OWNER = "i-owner-1"
GRANT = {"id": "g", "instance_id": OWNER, "required_role": "member", "modules": ["os"],
         "created_at": "2026-10-01T10:00:00Z"}


def run(coro):
    return asyncio.run(coro)


def _member(uid: int, fp: str, name: str = "Kim") -> TeamMemberKey:
    pub = base64.b64encode(bytes(nacl.public.PrivateKey.generate().public_key)).decode()
    return TeamMemberKey(uid, fp, pub, "member", name)


def _service(tmp_path):
    api = MagicMock(spec=APIClient)
    api.post = AsyncMock(return_value=dict(GRANT))
    api.delete = AsyncMock(return_value=dict(GRANT, status="revoked"))
    api.get = AsyncMock()
    auth = MagicMock()
    auth.has_feature = MagicMock(return_value=True)
    owner = nacl.public.PrivateKey.generate()
    km = MagicMock(user_id=1, private_key=bytes(owner), public_key=bytes(owner.public_key))

    async def raw(_i, _m):
        env = crypto_module.encrypt_envelope(b"{}", self_public_key=km.public_key,
                                             self_user_id=1).to_dict()
        return {"id": "e-os", "wrapped_dek": env["dek_wraps"][0]["wrapped_dek"]}

    retrieval = MagicMock(list_instance_modules=AsyncMock(return_value={"modules": ["os"]}),
                          get_module_envelope_raw=AsyncMock(side_effect=raw))
    pins = WrapPinStore(tmp_path / "pins.json")
    svc = TeamMemoryService(api_client=api, auth_service=auth, crypto=crypto_module,
                            key_store_provider=lambda: km, retrieval_service=retrieval,
                            pin_store_provider=lambda: pins)
    return svc, api, pins


def test_a_member_whose_fingerprint_differs_from_the_pin_is_refused(tmp_path):
    svc, api, pins = _service(tmp_path)
    pins.set_many({(SLUG, 2): "a" * 64})
    with pytest.raises(KeyChangedError) as err:
        run(svc.reshare_instance(SLUG, "g", OWNER, "member", ["os"], [_member(2, "b" * 64, "Lee")]))
    assert err.value.names == ["Lee"]
    api.delete.assert_not_awaited()
    api.post.assert_not_awaited()


def test_a_first_share_with_a_differing_pin_is_refused_too(tmp_path):
    svc, api, pins = _service(tmp_path)
    pins.set_many({(SLUG, 2): "a" * 64})
    with pytest.raises(KeyChangedError):
        run(svc.share_instance(SLUG, OWNER, "member", ["os"], [_member(2, "b" * 64)]))
    api.post.assert_not_awaited()


def test_share_pins_the_fingerprints_it_sealed_for(tmp_path):
    svc, api, pins = _service(tmp_path)
    run(svc.share_instance(SLUG, OWNER, "member", ["os"], [_member(2, "c" * 64)]))
    assert pinned_fingerprint(pins, SLUG, 2) == "c" * 64


def test_share_again_pins_them_too_and_accepts_a_matching_pin(tmp_path):
    svc, api, pins = _service(tmp_path)
    pins.set_many({(SLUG, 2): "c" * 64})
    run(svc.reshare_instance(SLUG, "g", OWNER, "member", ["os"], [_member(2, "c" * 64)]))
    api.delete.assert_awaited_once()
    assert pinned_fingerprint(pins, SLUG, 2) == "c" * 64


def test_a_failed_share_pins_nothing(tmp_path):
    svc, api, pins = _service(tmp_path)
    api.post.side_effect = RuntimeError("boom")
    with pytest.raises(RuntimeError):
        run(svc.share_instance(SLUG, OWNER, "member", ["os"], [_member(2, "c" * 64)]))
    assert pinned_fingerprint(pins, SLUG, 2) is None


def test_there_is_one_path_validator_in_the_codebase():
    import pathlib
    import re

    root = pathlib.Path(__file__).parent.parent / "src" / "servonaut" / "services"
    pattern = re.compile(r"A-Za-z0-9\]\[A-Za-z0-9\._-\]")
    hits = [str(p) for p in root.rglob("*.py") if pattern.search(p.read_text(encoding="utf-8"))]
    assert [pathlib.Path(h).name for h in hits] == ["path_segments.py"]
