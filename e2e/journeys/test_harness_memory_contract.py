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


# ---------------------------------------------------------------------------
# Key custody over HTTP (B1, B2, B3, B8) and the two switches
# ---------------------------------------------------------------------------

import hashlib  # noqa: E402
import json  # noqa: E402

from e2e.harness.vault_custody import put_key_item, seed_personal_vault, signed_call  # noqa: E402

MEMORY_PATH = "/api/v1/memory"


def _pair():
    private = nacl.public.PrivateKey.generate()
    public = bytes(private.public_key)
    return bytes(private), _b64(public), hashlib.sha256(public).hexdigest()


def _passphrase_body():
    _, public, fingerprint = _pair()
    wrapped = {"kdf": "argon2id", "salt": _b64(bytes(16)), "nonce": _b64(bytes(24)), "ct": _b64(bytes(48))}
    return {"public_key": public, "fingerprint": fingerprint, "wrapped_private_key": json.dumps(wrapped)}


def _vault_body(public, fingerprint):
    return {"public_key": public, "fingerprint": fingerprint, "custody": "vault"}


def _code(response):
    return response.json()["error"]["code"]


@pytest.fixture
def account(fake_cloud):
    """The scenario account with a grantable vault identity, device and personal vault."""
    return seed_personal_vault(fake_cloud)


def _enrol_passphrase(fake_cloud, account):
    body = _passphrase_body()
    response = signed_call(fake_cloud, None, "POST", f"{MEMORY_PATH}/keys", body)
    assert response.status_code == 201, response.text
    return body


def _vault_key_with_item(fake_cloud, account):
    private, public, fingerprint = _pair()
    assert put_key_item(fake_cloud, account, "memory_key", fingerprint)[0] == 201
    return private, public, fingerprint


def test_keys_me_describes_custody_and_never_404s_a_vault_row(fake_cloud, account):
    assert signed_call(fake_cloud, None, "GET", f"{MEMORY_PATH}/keys/me").status_code == 404
    body = _enrol_passphrase(fake_cloud, account)
    row = signed_call(fake_cloud, None, "GET", f"{MEMORY_PATH}/keys/me").json()
    assert row["custody"] == "passphrase" and row["custody_changed_at"] is None
    assert row["wrapped_private_key"] == body["wrapped_private_key"] and isinstance(row["id"], int)

    seeded = fake_cloud.memory.seed_vault_custody_key()
    row = signed_call(fake_cloud, None, "GET", f"{MEMORY_PATH}/keys/me").json()
    assert row["custody"] == "vault" and row["wrapped_private_key"] is None
    assert row["custody_changed_at"] is None and row["fingerprint"] == seeded["fingerprint"]


def test_the_switch_keeps_the_row_id_and_nulls_the_wrap(fake_cloud, account):
    body = _enrol_passphrase(fake_cloud, account)
    before = signed_call(fake_cloud, None, "GET", f"{MEMORY_PATH}/keys/me").json()
    assert put_key_item(fake_cloud, account, "memory_key", body["fingerprint"])[0] == 201
    response = signed_call(fake_cloud, account["persona"], "POST", f"{MEMORY_PATH}/keys/me/custody",
                           {"custody": "vault", "fingerprint": body["fingerprint"]})
    assert response.status_code == 200, response.text
    after = signed_call(fake_cloud, None, "GET", f"{MEMORY_PATH}/keys/me").json()
    assert after["id"] == before["id"] and after["fingerprint"] == before["fingerprint"]
    assert after["custody"] == "vault" and after["wrapped_private_key"] is None
    assert after["custody_changed_at"] is not None
    assert response.json()["id"] == before["id"]
    assert fake_cloud.memory.key_history() == []  # no rotation, so teammates see no key_changed

    again = signed_call(fake_cloud, account["persona"], "POST", f"{MEMORY_PATH}/keys/me/custody",
                        {"custody": "vault", "fingerprint": body["fingerprint"]})
    assert again.status_code == 200 and again.json()["custody_changed_at"] == after["custody_changed_at"]


def test_custody_switch_refusals(fake_cloud, account):
    path, persona = f"{MEMORY_PATH}/keys/me/custody", account["persona"]
    fp = "a" * 64
    assert _code(signed_call(fake_cloud, persona, "POST", path, {"custody": "vault", "fingerprint": fp})) == "not_found"
    body = _enrol_passphrase(fake_cloud, account)
    unsigned = signed_call(fake_cloud, None, "POST", path, {"custody": "vault", "fingerprint": body["fingerprint"]})
    assert unsigned.status_code == 403 and _code(unsigned) == "device_signature_required"
    wrong = signed_call(fake_cloud, persona, "POST", path, {"custody": "vault", "fingerprint": fp})
    assert wrong.status_code == 409 and _code(wrong) == "fingerprint_mismatch"
    assert wrong.json()["error"]["message"] == "The fingerprint does not match your active Memory Sync key."
    not_ready = signed_call(fake_cloud, persona, "POST", path, {"custody": "vault", "fingerprint": body["fingerprint"]})
    assert not_ready.status_code == 409 and _code(not_ready) == "vault_not_ready"
    bad = signed_call(fake_cloud, persona, "POST", path, {"custody": "passphrase", "fingerprint": fp})
    assert bad.status_code == 422 and bad.json()["error"]["details"]["field"] == "custody"
    assert signed_call(fake_cloud, persona, "POST", path, {"custody": "vault", "fingerprint": "A" * 64}).status_code == 422
    # The row is untouched by every refusal.
    assert signed_call(fake_cloud, None, "GET", f"{MEMORY_PATH}/keys/me").json()["custody"] == "passphrase"


def test_an_item_for_another_key_or_an_ungrantable_identity_is_not_ready(fake_cloud, account):
    body = _enrol_passphrase(fake_cloud, account)
    put_key_item(fake_cloud, account, "memory_key", "b" * 64)  # a different key's item
    request = {"custody": "vault", "fingerprint": body["fingerprint"]}
    path = f"{MEMORY_PATH}/keys/me/custody"
    assert _code(signed_call(fake_cloud, account["persona"], "POST", path, request)) == "vault_not_ready"
    put_key_item(fake_cloud, account, "memory_key", body["fingerprint"])
    fake_cloud.vault._identities[account["user_id"]]["grantable"] = False
    assert _code(signed_call(fake_cloud, account["persona"], "POST", path, request)) == "vault_not_ready"


def test_the_vault_custody_switch_gates_every_vault_write(fake_cloud, account):
    private, public, fingerprint = _vault_key_with_item(fake_cloud, account)
    body = _enrol_passphrase(fake_cloud, account)
    fake_cloud.memory.set_vault_custody(False)
    persona = account["persona"]
    for path, payload in (
        (f"{MEMORY_PATH}/keys", _vault_body(public, fingerprint)),
        (f"{MEMORY_PATH}/keys/rotate", _vault_body(public, fingerprint)),
        (f"{MEMORY_PATH}/keys/me/custody", {"custody": "vault", "fingerprint": body["fingerprint"]}),
    ):
        response = signed_call(fake_cloud, persona, "POST", path, payload)
        assert (response.status_code, _code(response)) == (503, "feature_disabled"), path
    status, refusal = put_key_item(fake_cloud, account, "memory_key", "c" * 64)
    assert (status, refusal["error"]["code"]) == (503, "feature_disabled")
    # The passphrase shape is not a vault-custody write, and deletes are not gated.
    assert signed_call(fake_cloud, None, "POST", f"{MEMORY_PATH}/keys", _passphrase_body()).status_code == 201
    fake_cloud.memory.set_vault_custody(True)
    assert signed_call(fake_cloud, persona, "POST", f"{MEMORY_PATH}/keys/rotate",
                       _vault_body(public, fingerprint)).status_code == 201


def test_a_key_enrolled_directly_in_vault_custody_has_no_custody_timestamp(fake_cloud, account):
    _, public, fingerprint = _vault_key_with_item(fake_cloud, account)
    unsigned = signed_call(fake_cloud, None, "POST", f"{MEMORY_PATH}/keys", _vault_body(public, fingerprint))
    assert unsigned.status_code == 403 and _code(unsigned) == "device_signature_required"
    response = signed_call(fake_cloud, account["persona"], "POST", f"{MEMORY_PATH}/keys", _vault_body(public, fingerprint))
    assert response.status_code == 201 and response.json()["custody"] == "vault"
    row = signed_call(fake_cloud, None, "GET", f"{MEMORY_PATH}/keys/me").json()
    assert row["custody"] == "vault" and row["custody_changed_at"] is None and row["wrapped_private_key"] is None


def test_vault_shape_validation_and_item_precondition(fake_cloud, account):
    private, public, fingerprint = _pair()
    persona, path = account["persona"], f"{MEMORY_PATH}/keys"
    not_ready = signed_call(fake_cloud, persona, "POST", path, _vault_body(public, fingerprint))
    assert not_ready.status_code == 409 and _code(not_ready) == "vault_not_ready"
    mismatch = signed_call(fake_cloud, persona, "POST", path, _vault_body(public, "0" * 64))
    assert mismatch.status_code == 422 and mismatch.json()["error"]["details"]["field"] == "fingerprint"
    wrapped = signed_call(fake_cloud, persona, "POST", path, {**_vault_body(public, fingerprint),
                                                              "wrapped_private_key": "{}"})
    assert wrapped.status_code == 422
    short = signed_call(fake_cloud, persona, "POST", path, _vault_body(_b64(b"x" * 8), fingerprint))
    assert short.status_code == 422 and short.json()["error"]["details"]["field"] == "public_key"


def test_rotation_keeps_the_old_row_as_rotated(fake_cloud, account):
    persona, path = account["persona"], f"{MEMORY_PATH}/keys/rotate"
    _, public, fingerprint = _vault_key_with_item(fake_cloud, account)
    assert _code(signed_call(fake_cloud, persona, "POST", path, _vault_body(public, fingerprint))) == "not_found"
    fake_cloud.memory.seed_vault_custody_key()
    old = signed_call(fake_cloud, None, "GET", f"{MEMORY_PATH}/keys/me").json()
    unsigned = signed_call(fake_cloud, None, "POST", path, _vault_body(public, fingerprint))
    assert unsigned.status_code == 403 and _code(unsigned) == "device_signature_required"
    _, public2, fingerprint2 = _pair()
    not_ready = signed_call(fake_cloud, persona, "POST", path, _vault_body(public2, fingerprint2))
    assert not_ready.status_code == 409 and _code(not_ready) == "vault_not_ready"
    rotated = signed_call(fake_cloud, persona, "POST", path, _vault_body(public, fingerprint))
    assert rotated.status_code == 201 and rotated.json()["rotated_from_previous"] is True
    new = signed_call(fake_cloud, None, "GET", f"{MEMORY_PATH}/keys/me").json()
    assert new["fingerprint"] == fingerprint and new["id"] != old["id"]
    history = fake_cloud.memory.key_history()
    assert [h["fingerprint"] for h in history] == [old["fingerprint"]] and history[0]["rotated_at"]


def test_the_passphrase_shape_is_refused_for_a_vault_key_and_by_the_second_switch(fake_cloud, account):
    path = f"{MEMORY_PATH}/keys"
    assert signed_call(fake_cloud, None, "POST", path, _passphrase_body()).status_code == 201
    fake_cloud.memory.set_passphrase_custody(False)
    refused = signed_call(fake_cloud, None, "POST", path, _passphrase_body())
    assert refused.status_code == 409 and _code(refused) == "memory_key_custody_vault"
    assert refused.json()["error"]["message"] == "Update Servonaut to set up Memory Sync."
    assert _code(signed_call(fake_cloud, None, "POST", f"{path}/rotate", _passphrase_body())) == "memory_key_custody_vault"
    fake_cloud.memory.set_passphrase_custody(True)
    assert signed_call(fake_cloud, None, "POST", f"{path}/rotate", _passphrase_body()).status_code == 201
    fake_cloud.memory.seed_vault_custody_key()
    again = signed_call(fake_cloud, None, "POST", path, _passphrase_body())
    assert again.status_code == 409 and _code(again) == "memory_key_custody_vault"


def test_key_writes_need_the_memory_sync_entitlement(fake_cloud, account):
    _, public, fingerprint = _vault_key_with_item(fake_cloud, account)
    body = _enrol_passphrase(fake_cloud, account)
    fake_cloud.configure(plan="free")
    persona = account["persona"]
    calls = (
        (None, f"{MEMORY_PATH}/keys", _passphrase_body()),
        (None, f"{MEMORY_PATH}/keys/rotate", _passphrase_body()),
        (persona, f"{MEMORY_PATH}/keys", _vault_body(public, fingerprint)),
        (persona, f"{MEMORY_PATH}/keys/rotate", _vault_body(public, fingerprint)),
        (persona, f"{MEMORY_PATH}/keys/me/custody", {"custody": "vault", "fingerprint": body["fingerprint"]}),
    )
    for who, path, payload in calls:
        response = signed_call(fake_cloud, who, "POST", path, payload)
        assert (response.status_code, _code(response)) == (403, "forbidden_entitlement"), path
    # Reads stay open; a member of a team keeps the entitlement.
    assert signed_call(fake_cloud, None, "GET", f"{MEMORY_PATH}/keys/me").status_code == 200
    fake_cloud.memory.add_team_member(TEAM, account["user_id"], body["public_key"])
    assert signed_call(fake_cloud, None, "POST", f"{MEMORY_PATH}/keys", _passphrase_body()).status_code == 201


def test_the_control_routes_flip_the_switches(fake_cloud):
    import httpx

    with httpx.Client(base_url=fake_cloud.url, verify=False, timeout=10) as client:
        off = client.post("/__e2e/memory/custody", json={"vault_custody_enabled": False}).json()
        assert off == {"vault_custody_enabled": False, "passphrase_custody_accepted": True}
        assert client.post("/__e2e/memory/custody", json={"passphrase_custody_accepted": False}).json() == {
            "vault_custody_enabled": False, "passphrase_custody_accepted": False}
    assert fake_cloud.memory.vault_custody_enabled is False
    fake_cloud.reset()
    assert fake_cloud.memory.vault_custody_enabled and fake_cloud.memory.passphrase_custody_accepted


# -- which key a stored wrap points at ---------------------------------------


def _upload(fake_cloud, private_public_key_b64, user_id, module="os", *, instance="web-1"):
    """Store an envelope sealed to *private_public_key_b64* through the fake's own intake."""
    from servonaut.services.memory.crypto import encrypt_envelope

    fake_cloud.memory.upsert_instance({"instance_id": instance})
    envelope = encrypt_envelope(b'{"a": 1}', self_public_key=base64.b64decode(private_public_key_b64),
                                self_user_id=user_id).to_dict()
    result = fake_cloud.memory.accept([{
        "instance_id": instance, "module": module, "probed_at": "2030-01-01T00:00:00+00:00", **envelope}])
    assert result["rejected"] == [], result
    return result["accepted"][0]["id"]


def _delete(fake_cloud, account, item):
    return fake_cloud.vault.delete_item(account["vault_id"], item["item_id"], {"revision": item["revision"] + 1},
                                        account["user_id"])


def test_a_rotated_key_stays_in_use_while_any_wrap_points_at_it_until_the_history_is_pruned(fake_cloud, account):
    persona, uid = account["persona"], account["user_id"]
    _, public1, fp1 = _pair()
    _, public2, fp2 = _pair()
    status, item1 = put_key_item(fake_cloud, account, "memory_key", fp1)
    assert status == 201
    put_key_item(fake_cloud, account, "memory_key", fp2)
    assert signed_call(fake_cloud, persona, "POST", f"{MEMORY_PATH}/keys", _vault_body(public1, fp1)).status_code == 201
    _upload(fake_cloud, public1, uid)
    # While it is the active vault-custody key the item cannot go.
    refused = _delete(fake_cloud, account, item1)
    assert refused[0] == 409 and refused[1]["error"]["code"] == "memory_key_in_use"
    assert refused[1]["error"]["message"] == "This item holds your Memory Sync key."

    assert signed_call(fake_cloud, persona, "POST", f"{MEMORY_PATH}/keys/rotate", _vault_body(public2, fp2)).status_code == 201
    # A newer upload under the new key does not clear it: the old wrap is still stored.
    _upload(fake_cloud, public2, uid)
    assert _delete(fake_cloud, account, item1)[1]["error"]["code"] == "memory_key_in_use"
    # The latest envelope per module is always kept, so a prune alone clears it here.
    assert fake_cloud.memory.prune_history(0) == {"envelopes_removed": 1, "grant_wraps_removed": 0}
    status, deleted = _delete(fake_cloud, account, item1)
    assert status == 200 and deleted["deleted_at"]


def test_a_wrap_shared_by_a_teammate_keeps_the_key_in_use(fake_cloud, account):
    from e2e.harness.vault_custody import seed_incoming_share

    uid = account["user_id"]
    _, public1, fp1 = _pair()
    _, item1 = put_key_item(fake_cloud, account, "memory_key", fp1)
    fake_cloud.memory.seed_vault_custody_key(public_key_b64=public1)
    seed_incoming_share(fake_cloud, team_slug=TEAM, from_user_id=2, instance_id="db-1", module="os",
                        observed={"k": "v"})
    _, public2, fp2 = _pair()
    put_key_item(fake_cloud, account, "memory_key", fp2)
    assert signed_call(fake_cloud, account["persona"], "POST", f"{MEMORY_PATH}/keys/rotate",
                       _vault_body(public2, fp2)).status_code == 201
    assert _delete(fake_cloud, account, {"item_id": item1["item_id"], "revision": item1["revision"]})[0] == 409
    assert fake_cloud.memory.key_in_use(uid, fp1)
    # The only envelope of its module is kept by the prune, so the shared wrap keeps blocking.
    assert fake_cloud.memory.prune_history(0)["envelopes_removed"] == 0
    assert fake_cloud.memory.key_in_use(uid, fp1)


def test_pruning_keeps_the_newest_envelope_and_honours_the_age(fake_cloud, account):
    _, public, _ = _pair()
    fake_cloud.memory.seed_vault_custody_key(public_key_b64=public)
    for _ in range(3):
        _upload(fake_cloud, public, account["user_id"])
    assert fake_cloud.memory.prune_history(3600)["envelopes_removed"] == 0
    assert fake_cloud.memory.prune_history(0)["envelopes_removed"] == 2
    assert len(fake_cloud.memory.envelopes("web-1", "os")) == 1
    import httpx
    with httpx.Client(base_url=fake_cloud.url, verify=False, timeout=10) as client:
        assert client.post("/__e2e/memory/prune-history", json={"older_than_seconds": 0}).json()["envelopes_removed"] == 0


# ---------------------------------------------------------------------------
# Config snapshots (B4)
# ---------------------------------------------------------------------------

CONFIGS_PATH = "/api/v1/configs"


def _envelope(**extra):
    return {"encryption": "aes-256-gcm", "data": _b64(b"x" * 32), "iv": _b64(bytes(12)), "tag": _b64(bytes(16)), **extra}


def _passphrase_snapshot(**extra):
    return _envelope(salt=_b64(bytes(16)), name="default", **extra)


def _vault_snapshot(key_id, **extra):
    return _envelope(key_custody="vault", key_id=key_id, name="default", **extra)


def test_config_passphrase_snapshots_carry_custody_fields(fake_cloud):
    created = signed_call(fake_cloud, None, "POST", CONFIGS_PATH, _passphrase_snapshot())
    assert created.status_code == 201
    assert created.json()["key_custody"] == "passphrase" and created.json()["key_id"] is None
    listed = signed_call(fake_cloud, None, "GET", CONFIGS_PATH).json()["snapshots"]
    assert listed[0]["key_custody"] == "passphrase" and listed[0]["key_id"] is None
    latest = signed_call(fake_cloud, None, "GET", f"{CONFIGS_PATH}/latest").json()
    assert latest["salt"] and latest["key_custody"] == "passphrase"
    # key_id belongs to vault snapshots; a snapshot still needs its salt.
    assert signed_call(fake_cloud, None, "POST", CONFIGS_PATH, _passphrase_snapshot(key_id="a" * 64)).status_code == 422
    assert signed_call(fake_cloud, None, "POST", CONFIGS_PATH, _envelope()).status_code == 422


def test_config_vault_snapshot_rules(fake_cloud, account):
    key_id = "d" * 64
    not_ready = signed_call(fake_cloud, None, "POST", CONFIGS_PATH, _vault_snapshot(key_id))
    assert not_ready.status_code == 409 and _code(not_ready) == "config_key_not_ready"
    assert put_key_item(fake_cloud, account, "config_sync_key", key_id)[0] == 201
    salted = signed_call(fake_cloud, None, "POST", CONFIGS_PATH, _vault_snapshot(key_id, salt=_b64(bytes(16))))
    assert salted.status_code == 422 and salted.json()["error"]["details"]["field"] == "salt"
    for bad in ("short", "D" * 64, None):
        response = signed_call(fake_cloud, None, "POST", CONFIGS_PATH, _vault_snapshot(bad))
        assert response.status_code == 422 and response.json()["error"]["details"]["field"] == "key_id"
    created = signed_call(fake_cloud, None, "POST", CONFIGS_PATH, _vault_snapshot(key_id))
    assert created.status_code == 201, created.text
    assert created.json()["key_custody"] == "vault" and created.json()["key_id"] == key_id
    fetched = signed_call(fake_cloud, None, "GET", f"{CONFIGS_PATH}/{created.json()['id']}").json()
    assert fetched["salt"] is None and fetched["key_id"] == key_id
    assert signed_call(fake_cloud, None, "POST", CONFIGS_PATH, {**_vault_snapshot(key_id), "key_custody": "other"}).status_code == 422


def test_config_switches(fake_cloud, account):
    key_id = "e" * 64
    put_key_item(fake_cloud, account, "config_sync_key", key_id)
    fake_cloud.memory.set_passphrase_custody(False)
    refused = signed_call(fake_cloud, None, "POST", CONFIGS_PATH, _passphrase_snapshot())
    assert refused.status_code == 409 and _code(refused) == "config_key_custody_vault"
    assert refused.json()["error"]["message"] == "Update Servonaut to use config sync."
    assert signed_call(fake_cloud, None, "POST", CONFIGS_PATH, _vault_snapshot(key_id)).status_code == 201
    fake_cloud.memory.set_vault_custody(False)
    off = signed_call(fake_cloud, None, "POST", CONFIGS_PATH, _vault_snapshot(key_id))
    assert (off.status_code, _code(off)) == (503, "feature_disabled")


def test_config_bulk_delete(fake_cloud, account):
    key_id = "f" * 64
    put_key_item(fake_cloud, account, "config_sync_key", key_id)
    assert signed_call(fake_cloud, None, "POST", CONFIGS_PATH, _passphrase_snapshot()).status_code == 201
    assert signed_call(fake_cloud, None, "POST", CONFIGS_PATH, _passphrase_snapshot()).status_code == 201
    guard = signed_call(fake_cloud, None, "DELETE", CONFIGS_PATH, query={"key_custody": "passphrase"})
    assert guard.status_code == 409 and _code(guard) == "no_vault_snapshot"
    assert guard.json()["error"]["message"] == "Upload your config under the vault key before removing the old copies."
    assert len(fake_cloud.configs.all()) == 2
    for query in ({}, {"key_custody": "passphrase", "key_id": key_id}, {"key_custody": "vault"}, {"key_id": "zz"}):
        assert signed_call(fake_cloud, None, "DELETE", CONFIGS_PATH, query=query).status_code == 422, query
    assert signed_call(fake_cloud, None, "POST", CONFIGS_PATH, _vault_snapshot(key_id)).status_code == 201
    done = signed_call(fake_cloud, None, "DELETE", CONFIGS_PATH, query={"key_custody": "passphrase"})
    assert done.status_code == 200 and done.json() == {"deleted": 2}
    assert [s["key_custody"] for s in fake_cloud.configs.all()] == ["vault"]
    # By key id: refused unless a snapshot under another key id exists.
    only = signed_call(fake_cloud, None, "DELETE", CONFIGS_PATH, query={"key_id": key_id})
    assert only.status_code == 409 and _code(only) == "no_vault_snapshot"
    other = fake_cloud.configs.seed_vault_snapshot()
    assert other["key_id"] != key_id
    gone = signed_call(fake_cloud, None, "DELETE", CONFIGS_PATH, query={"key_id": key_id})
    assert gone.status_code == 200 and gone.json() == {"deleted": 1}


def test_config_key_item_delete_guard(fake_cloud, account):
    key_id = "9" * 64
    _, item = put_key_item(fake_cloud, account, "config_sync_key", key_id)
    assert signed_call(fake_cloud, None, "POST", CONFIGS_PATH, _vault_snapshot(key_id)).status_code == 201
    refused = _delete(fake_cloud, account, item)
    assert refused[0] == 409 and refused[1]["error"]["code"] == "config_key_in_use"
    assert refused[1]["error"]["message"] == "This item holds your config sync key."
    fake_cloud.configs.reset()
    assert _delete(fake_cloud, account, item)[0] == 200


# ---------------------------------------------------------------------------
# Hosted summaries (B9)
# ---------------------------------------------------------------------------

SUMMARY = f"{MEMORY_PATH}/summary"


@pytest.fixture
def summary_account(fake_cloud):
    """A vault-custody account with an envelope for two modules of web-1."""
    private, public, _ = _pair()
    fake_cloud.memory.seed_vault_custody_key(public_key_b64=public)
    uid = fake_cloud.entitlements()["user_id"]
    ids = {m: _upload(fake_cloud, public, uid, m) for m in ("os", "services")}
    return {"private": private, "public": public, "ids": ids, "user_id": uid}


def _keys_for(fake_cloud, account, ids=None):
    from servonaut.services.memory.crypto import secure_zero  # noqa: F401

    box = nacl.public.SealedBox(nacl.public.PrivateKey(account["private"]))
    out = []
    for envelope_id in (ids or account["ids"]).values():
        stored = fake_cloud.memory.find(id=envelope_id)[0]
        wrap = next(w for w in stored["dek_wraps"] if w["recipient_user_id"] == account["user_id"])
        out.append({"envelope_id": envelope_id, "dek": _b64(box.decrypt(base64.b64decode(wrap["wrapped_dek"])))})
    return out


def _consent(fake_cloud, instance="web-1", **body):
    response = signed_call(fake_cloud, None, "POST", f"{SUMMARY}/{instance}/consent",
                           {"mode": "server_60s", "provider_ack": True, **body})
    return response


def _dispatch(fake_cloud, consent, **body):
    return signed_call(fake_cloud, None, "POST", f"{SUMMARY}/web-1", {
        "consent_token": consent["token"], "mode": consent["mode"], **body})


def test_provider_info_and_consent_shape(fake_cloud, summary_account):
    info = signed_call(fake_cloud, None, "GET", f"{MEMORY_PATH}/ai-provider-info")
    assert info.status_code == 200
    assert {"provider_name", "retention_days", "retention_text", "supports_zdr"} <= set(info.json())
    consent = _consent(fake_cloud)
    assert consent.status_code == 201
    body = consent.json()
    assert body["modules"] == ["os", "services"] and body["mode"] == "server_60s" and body["expires_at"]
    assert body["envelope_ids"] == summary_account["ids"]
    narrowed = _consent(fake_cloud, modules=["os"]).json()
    assert narrowed["modules"] == ["os"] and list(narrowed["envelope_ids"]) == ["os"]
    fake_cloud.summaries.hide_envelope_ids()
    assert "envelope_ids" not in _consent(fake_cloud).json()
    assert _consent(fake_cloud, provider_ack=False).status_code == 422
    assert _consent(fake_cloud, instance="nope").status_code == 404


def test_dispatch_with_data_keys_returns_a_result_only_the_account_can_open(fake_cloud, summary_account):
    from servonaut.services.memory.crypto import decrypt_envelope

    consent = _consent(fake_cloud).json()
    response = _dispatch(fake_cloud, consent, envelope_keys=_keys_for(fake_cloud, summary_account))
    assert response.status_code == 200, response.text
    queued = response.json()
    assert queued["status"] == "queued" and queued["previous_summary_id"] is None
    latest = signed_call(fake_cloud, None, "GET", f"{SUMMARY}/web-1/latest").json()
    assert latest["module"] == "ai_summary" and latest["instance_id"] == "web-1"
    plain = decrypt_envelope(latest, self_user_id=summary_account["user_id"],
                             self_private_key=summary_account["private"],
                             self_public_key=base64.b64decode(summary_account["public"]))
    assert "summary" in json.loads(plain)
    waiting = signed_call(fake_cloud, None, "GET", f"{SUMMARY}/web-1/latest", query={"after": latest["id"]}).json()
    assert waiting["status"] == "pending" and waiting["previous_summary_id"] == latest["id"]
    second = _dispatch(fake_cloud, _consent(fake_cloud).json(), envelope_keys=_keys_for(fake_cloud, summary_account))
    assert second.json()["previous_summary_id"] == latest["id"]


def test_dispatch_body_rules(fake_cloud, summary_account):
    consent = _consent(fake_cloud).json()
    keys = _keys_for(fake_cloud, summary_account)

    def field(response):
        assert response.status_code == 422, response.text
        return response.json()["error"]["details"]["field"]

    assert field(_dispatch(fake_cloud, consent)) == "envelope_keys"
    assert field(_dispatch(fake_cloud, consent, envelope_keys=keys, passphrase="pw")) == "envelope_keys"
    assert field(_dispatch(fake_cloud, {**consent, "token": "nope"}, envelope_keys=keys)) == "consent_token"
    assert field(_dispatch(fake_cloud, {**consent, "mode": "client"}, envelope_keys=keys)) == "mode"
    assert field(_dispatch(fake_cloud, consent, envelope_keys=keys[:1])) == "envelope_keys"
    assert field(_dispatch(fake_cloud, consent, envelope_keys=[keys[0], keys[0]])) == "envelope_keys"
    assert field(_dispatch(fake_cloud, consent, envelope_keys=[{**keys[0], "dek": _b64(b"short")}, keys[1]])) == "envelope_keys"
    assert field(_dispatch(fake_cloud, consent, envelope_keys=[{**keys[0], "envelope_id": "nope"}, keys[1]])) == "envelope_keys"
    # An envelope of another instance is a foreign one.
    other = _upload(fake_cloud, summary_account["public"], summary_account["user_id"], "os", instance="db-1")
    foreign = _keys_for(fake_cloud, summary_account, {"os": other, "services": summary_account["ids"]["services"]})
    assert field(_dispatch(fake_cloud, consent, envelope_keys=foreign)) == "envelope_keys"
    assert fake_cloud.summaries.jobs() == []


def test_stale_envelopes_and_the_forced_one_shot(fake_cloud, summary_account):
    consent = _consent(fake_cloud).json()
    keys = _keys_for(fake_cloud, summary_account)
    _upload(fake_cloud, summary_account["public"], summary_account["user_id"], "os")  # a newer envelope
    stale = _dispatch(fake_cloud, consent, envelope_keys=keys)
    assert stale.status_code == 409 and _code(stale) == "stale_envelopes"
    fresh = _consent(fake_cloud).json()
    current = {m: fake_cloud.memory.find(instance_id="web-1", module=m)[-1]["id"] for m in ("os", "services")}
    keys = _keys_for(fake_cloud, {**summary_account, "ids": current})
    fake_cloud.summaries.force_stale_once()
    assert _code(_dispatch(fake_cloud, fresh, envelope_keys=keys)) == "stale_envelopes"
    assert _dispatch(fake_cloud, fresh, envelope_keys=keys).status_code == 200


def test_summary_switch_and_passphrase_form(fake_cloud, summary_account):
    consent = _consent(fake_cloud).json()
    keys = _keys_for(fake_cloud, summary_account)
    fake_cloud.memory.set_vault_custody(False)
    off = _dispatch(fake_cloud, consent, envelope_keys=keys)
    assert (off.status_code, _code(off)) == (503, "feature_disabled")
    fake_cloud.memory.set_vault_custody(True)
    vault = _dispatch(fake_cloud, consent, passphrase="correct horse")
    assert vault.status_code == 409 and _code(vault) == "memory_key_custody_vault"
    assert fake_cloud.summaries.jobs() == []


def test_the_passphrase_form_is_accepted_for_a_passphrase_key_that_it_opens(fake_cloud):
    from servonaut.services.memory.crypto import generate_keypair, wrap_private_key

    pair = generate_keypair()
    passphrase = "correct horse battery staple 42!"
    wrapped = wrap_private_key(pair.private_key, passphrase).to_json()
    public = _b64(pair.public_key)
    assert signed_call(fake_cloud, None, "POST", f"{MEMORY_PATH}/keys", {
        "public_key": public, "fingerprint": pair.fingerprint, "wrapped_private_key": wrapped}).status_code == 201
    uid = fake_cloud.entitlements()["user_id"]
    ids = {"os": _upload(fake_cloud, public, uid)}
    consent = _consent(fake_cloud).json()
    wrong = _dispatch(fake_cloud, consent, passphrase="not it")
    assert wrong.status_code == 422 and wrong.json()["error"]["details"]["field"] == "passphrase"
    assert _dispatch(fake_cloud, consent, passphrase=passphrase).status_code == 200
    # The data-key form works for a passphrase-custody account too.
    account = {"private": pair.private_key, "user_id": uid, "ids": ids}
    again = _dispatch(fake_cloud, _consent(fake_cloud).json(), envelope_keys=_keys_for(fake_cloud, account))
    assert again.status_code == 200
    fake_cloud.memory.set_passphrase_custody(False)
    assert _code(_dispatch(fake_cloud, _consent(fake_cloud).json(), passphrase=passphrase)) == "memory_key_custody_vault"


def test_a_data_key_that_does_not_open_the_envelope_fails_the_job(fake_cloud, summary_account):
    consent = _consent(fake_cloud).json()
    keys = _keys_for(fake_cloud, summary_account)
    keys[0]["dek"] = _b64(bytes(32))
    assert _dispatch(fake_cloud, consent, envelope_keys=keys).status_code == 200
    latest = signed_call(fake_cloud, None, "GET", f"{SUMMARY}/web-1/latest")
    assert latest.status_code == 200 and latest.json()["status"] == "failed" and latest.json()["reason"]
    assert [j["status"] for j in fake_cloud.summaries.jobs()] == ["failed"]


def test_latest_is_pending_until_the_result_is_ready(fake_cloud, summary_account):
    assert signed_call(fake_cloud, None, "GET", f"{SUMMARY}/web-1/latest").status_code == 404
    fake_cloud.summaries.set_pending_polls(2)
    _dispatch(fake_cloud, _consent(fake_cloud).json(), envelope_keys=_keys_for(fake_cloud, summary_account))
    states = [signed_call(fake_cloud, None, "GET", f"{SUMMARY}/web-1/latest").json().get("status") for _ in range(3)]
    assert states == ["pending", "pending", None]


def test_summary_controls_over_http(fake_cloud, summary_account):
    import httpx

    with httpx.Client(base_url=fake_cloud.url, verify=False, timeout=10) as client:
        assert client.post("/__e2e/memory/summary", json={"hide_envelope_ids": True, "force_stale_once": 1,
                                                          "pending_polls": 1}).status_code == 200
    assert "envelope_ids" not in _consent(fake_cloud).json()
