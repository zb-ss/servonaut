"""The e2e fake keeps to the service's grant and coverage contract."""

from __future__ import annotations

import base64

import nacl.public
import pytest

from e2e.harness.fake_cloud.routes_memory import MemoryCloud

pytestmark = [pytest.mark.e2e_pr]

OWNER_ID, TEAM = 1, "team-a"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _sealed_dek(public: bytes) -> str:
    return _b64(nacl.public.SealedBox(nacl.public.PublicKey(public)).encrypt(bytes(32)))


@pytest.fixture
def cloud():
    memory = MemoryCloud(lambda: OWNER_ID)
    owner = bytes(nacl.public.PrivateKey.generate().public_key)
    memory._keys[OWNER_ID] = {"public_key": _b64(owner), "fingerprint": __import__("hashlib").sha256(owner).hexdigest()}
    memory._instances["web-1"] = {"id": "web-1"}
    memory._envelopes.append({
        "id": "e-os", "instance_id": "web-1", "module": "os", "snapshot_version": 1,
        "dek_wraps": [{"recipient_user_id": OWNER_ID, "wrapped_dek": _sealed_dek(owner)}],
    })
    lee = bytes(nacl.public.PrivateKey.generate().public_key)
    memory.add_team_member(TEAM, 2, _b64(lee), name="Lee")
    memory.lee_key = lee
    return memory


def _grant_body(cloud, *, fingerprint=None):
    wrap = {"recipient_user_id": 2, "envelope_id": "e-os", "wrapped_dek": _sealed_dek(cloud.lee_key)}
    if fingerprint is not None:
        wrap["recipient_fingerprint"] = fingerprint
    return {"instance_id": "web-1", "required_role": "member", "modules": ["os"], "wraps": [wrap]}


def test_a_create_with_a_stale_fingerprint_leaves_the_member_missing(cloud):
    status, body = cloud.create_grant(TEAM, _grant_body(cloud, fingerprint="0" * 64))
    assert status == 422 and body["error"]["code"] == "insufficient_wraps"
    assert body["error"]["details"]["missing"] == [{"envelope_id": "e-os", "recipient_user_id": 2}]


def test_a_create_with_the_current_fingerprint_or_none_is_stored(cloud):
    current = next(m for m in cloud.team_keys(TEAM) if m["user_id"] == 2)["fingerprint"]
    assert cloud.create_grant(TEAM, _grant_body(cloud, fingerprint=current))[0] == 201


def test_a_fully_covered_grant_reports_no_envelopes_and_names_its_server(cloud):
    status, grant = cloud.create_grant(TEAM, _grant_body(cloud))
    assert status == 201
    status, coverage = cloud.wrap_coverage(TEAM, grant["id"])
    assert status == 200
    assert coverage["grant_id"] == grant["id"] and coverage["instance_id"] == "web-1"
    assert coverage["envelopes"] == []


def test_only_envelopes_with_missing_recipients_are_listed(cloud):
    _, grant = cloud.create_grant(TEAM, _grant_body(cloud))
    owner_wrap = cloud._envelopes[0]["dek_wraps"]
    cloud._envelopes.append({"id": "e-os-2", "instance_id": "web-1", "module": "os",
                             "snapshot_version": 2, "dek_wraps": owner_wrap})
    _, coverage = cloud.wrap_coverage(TEAM, grant["id"])
    assert [e["envelope_id"] for e in coverage["envelopes"]] == ["e-os-2"]
    assert [r["user_id"] for r in coverage["envelopes"][0]["missing_recipients"]] == [2]


def test_coverage_of_a_revoked_grant_is_grant_not_live(cloud):
    _, grant = cloud.create_grant(TEAM, _grant_body(cloud))
    cloud.revoke_grant(TEAM, grant["id"])
    status, body = cloud.wrap_coverage(TEAM, grant["id"])
    assert status == 409 and body["error"]["code"] == "grant_not_live"
