"""Journey helpers for vault custody of the Memory Sync and config sync keys.

* :func:`setup_vault` runs ``servonaut vault setup`` in a child home (the recipe
  the Vault journeys share), so the account has a vault identity, a device and
  a recovery key before a journey enrols Memory Sync in it.
* :func:`seed_incoming_share` stores a teammate's memory for a server, shared
  with the scenario account: the data key is sealed to the account's Memory
  Sync public key inside a team grant, as the teammate's client would do.

The fake's own fixtures (``fake_cloud.memory.seed_vault_custody_key``,
``fake_cloud.configs.seed_vault_snapshot``) are the other half.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Mapping, Optional


def setup_vault(journey: Any, home: Any, servonaut_cmd: list[str]) -> tuple[Any, str]:
    """Set up the vault in *home* with a throwaway device key and a null keyring.

    Returns the finished ``vault setup`` process and the recovery key it showed
    (answering the two confirmation prompts). The journey's child environment
    keeps the test custody for every later child of the same journey.
    """
    from e2e.journeys.vault.test_cli_vault import (
        _assert_only_getpass_tty_access,
        _configure_test_custody,
        _setup_with_recovery_confirmation,
    )

    _configure_test_custody(journey)
    setup, recovery_key = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    return setup, recovery_key


def seed_incoming_share(
    fake_cloud: Any,
    *,
    team_slug: str,
    from_user_id: int,
    instance_id: str,
    module: str,
    observed: Mapping[str, Any],
    to_user_id: Optional[int] = None,
    teammate_public_key_b64: Optional[str] = None,
) -> dict[str, str]:
    """A teammate's memory for *instance_id*, readable by the account through a grant.

    The account must already have a Memory Sync key on the fake (enrolled, or
    ``seed_vault_custody_key``). The teammate is added to *team_slug* with a
    generated key unless *teammate_public_key_b64* is given. Returns the
    envelope id and the teammate's public key.
    """
    import nacl.public

    from servonaut.services.memory.crypto import encrypt_envelope

    memory = fake_cloud.memory
    recipient_id = to_user_id if to_user_id is not None else fake_cloud.entitlements()["user_id"]
    recipient_key = memory.enrolled_key(recipient_id)
    if recipient_key is None:
        raise ValueError("enrol or seed the account's Memory Sync key before sharing memory with it")
    if teammate_public_key_b64 is None:
        teammate_public_key_b64 = base64.b64encode(bytes(nacl.public.PrivateKey.generate().public_key)).decode()
    memory.add_team_member(team_slug, from_user_id, teammate_public_key_b64, name="Teammate")

    plaintext = json.dumps({"module": module, "instance_id": instance_id, "observed": dict(observed)}).encode()
    envelope = encrypt_envelope(
        plaintext,
        self_public_key=base64.b64decode(teammate_public_key_b64),
        self_user_id=from_user_id,
        additional_recipients=[(recipient_id, base64.b64decode(recipient_key["public_key"]))],
    ).to_dict()
    recipient_wrap = next(w for w in envelope["dek_wraps"] if w["recipient_user_id"] == recipient_id)
    envelope["dek_wraps"] = [w for w in envelope["dek_wraps"] if w["recipient_user_id"] != recipient_id]
    envelope_id = memory.seed_shared_envelope(
        team_slug, from_user_id, instance_id, module, envelope, recipient_wrap,
    )
    return {"envelope_id": envelope_id, "teammate_public_key": teammate_public_key_b64}


# ---------------------------------------------------------------------------
# Contract-test helpers: a personal vault in the fake and signed HTTP calls
# ---------------------------------------------------------------------------


def seed_personal_vault(fake_cloud: Any, user_id: Optional[int] = None) -> dict[str, Any]:
    """A grantable identity with a device and an empty personal vault, inside the fake.

    Returns the persona (device keys for :func:`signed_call`) and the vault id.
    The vault is not a client-verifiable chain: it serves the fake's own
    item rules, not a client reading it back.
    """
    import uuid

    uid = user_id if user_id is not None else fake_cloud.entitlements()["user_id"]
    vault = fake_cloud.vault
    persona = vault.seed_identity(uid)
    vault_id = str(uuid.uuid4())
    vault._vaults[vault_id] = vault._new_vault(vault_id, "personal", f"user:{uid}", uid, None, [uid])
    vault._items[vault_id], vault._exposures[vault_id] = {}, []
    return {"persona": persona, "vault_id": vault_id, "user_id": uid}


def put_key_item(
    fake_cloud: Any, personal: Mapping[str, Any], item_type: str, fingerprint: str,
    *, item_id: Optional[str] = None, **changes: Any,
) -> tuple[int, dict[str, Any]]:
    """PUT an app-key item into the personal vault (state-level, as the route does)."""
    import os
    import uuid

    body = {
        "type": item_type, "public_fingerprint": fingerprint, "expected_revision": 0,
        "nonce": base64.b64encode(os.urandom(24)).decode(),
        "ciphertext": base64.b64encode(os.urandom(48)).decode(),
        **changes,
    }
    return fake_cloud.vault.put_item(
        personal["vault_id"], item_id or str(uuid.uuid4()), body, personal["user_id"],
    )


def signed_call(
    fake_cloud: Any, persona: Optional[Mapping[str, Any]], method: str, path: str,
    body: Optional[Mapping[str, Any]] = None, *, query: Optional[Mapping[str, str]] = None,
) -> Any:
    """One bearer request to the fake, device-signed with *persona* (None = unsigned)."""
    import os
    import time

    import httpx
    from nacl.signing import SigningKey

    from servonaut.services.vault.crypto import request_message

    raw = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
    access, _ = fake_cloud.tokens()
    headers = {"Authorization": f"Bearer {access}", "Content-Type": "application/json"}
    target = path
    if query:
        target = f"{path}?{httpx.QueryParams(query)}"
    if persona is not None:
        nonce, moment = os.urandom(16), int(time.time())
        device = persona["device"]["device_id"]
        signature = SigningKey(base64.b64decode(persona["device_signing_key"])).sign(
            request_message(method, target, moment, nonce, device, raw)
        ).signature
        headers.update({
            "X-Servonaut-Device": device, "X-Servonaut-Timestamp": str(moment),
            "X-Servonaut-Nonce": base64.b64encode(nonce).decode(),
            "X-Servonaut-Signature": base64.b64encode(signature).decode(),
        })
    with httpx.Client(base_url=fake_cloud.url, verify=False, timeout=10) as client:
        return client.request(method, target, content=raw, headers=headers)
