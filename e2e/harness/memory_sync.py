"""Helpers for the Memory Sync journeys: user steps and envelope checks.

The passphrase comes from ``SERVONAUT_MEMORY_PASSPHRASE`` (set with
:func:`use_passphrase`), the way a headless or scripted session supplies it,
so no passphrase dialog is involved. Every UI step waits for what the user
sees: the status line, the toasts, and the action buttons becoming
available.

:func:`enrolled_keypair`, :func:`envelope_key` and :func:`open_envelope`
let a journey prove that what FakeCloud stored is readable by the right key
holder only. They follow the published scheme with PyNaCl and
``cryptography`` directly (Argon2id + SecretBox for the wrapped private key,
an X25519 sealed box per data key, AES-256-GCM for the payload) rather than
the product's own helpers, so a bug shared by both sides cannot hide.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

from rich.text import Text

from e2e.harness.artifacts import register_secret

PASSPHRASE_ENV = "SERVONAUT_MEMORY_PASSPHRASE"
# Fabricated for the suite; strong enough for the client's passphrase check.
PASSPHRASE = "Correct-Horse-Battery-Staple-2030!"
ACTIVE = "● Active"


def use_passphrase(monkeypatch: Any, passphrase: str = PASSPHRASE) -> None:
    """Supply *passphrase* the headless way (and keep it out of artifacts)."""
    register_secret(passphrase)
    monkeypatch.setenv(PASSPHRASE_ENV, passphrase)


def plain(markup: object) -> str:
    return Text.from_markup(str(markup)).plain


def status(t: Any) -> str:
    """The Memory Sync status line, as the user reads it."""
    return plain(t.on_screen("#msync_status").render())


async def open_memory_sync(t: Any) -> None:
    await t.nav("nav_memory_sync")
    await t.wait_for_screen("MemorySyncSetupScreen")


async def unlock(t: Any) -> None:
    """Press "Unlock Memory Sync" and wait until the store is active."""
    await t.click("#msync_btn_setup")
    await t.wait_for_toast(r"^Memory Sync is now active\.$")
    await t.wait_until(lambda: status(t) == ACTIVE, desc="Memory Sync active")


def synced_toasts(t: Any) -> int:
    return sum(bool(re.fullmatch(r"Synced \d+ envelope\(s\)\.", m)) for _, m in t.toasts())


def _idle(t: Any) -> bool:
    return status(t) == ACTIVE and not t.on_screen("#msync_btn_sync_now").disabled


async def sync_all(t: Any) -> str:
    """Press "Sync all local memory"; return the toast once the run finished."""
    await t.wait_until(lambda: _idle(t), desc="sync available")
    before = synced_toasts(t)
    await t.click("#msync_btn_sync_now")
    await t.wait_until(lambda: synced_toasts(t) > before, desc="sync toast")
    # After the upload the screen still pulls remote annotations, then
    # redraws its card.
    await t.wait_until(lambda: _idle(t), desc="sync finished")
    return [m for _, m in t.toasts() if m.startswith("Synced ")][-1]


# ---------------------------------------------------------------------------
# Envelopes
# ---------------------------------------------------------------------------


def enrolled_keypair(fake_cloud: Any, passphrase: str = PASSPHRASE) -> tuple[bytes, bytes]:
    """The enrolled (public, private) keypair, unwrapped as a device would.

    Also proves the uploaded public key is the public half of the private
    key the passphrase unwraps.
    """
    import nacl.public
    import nacl.pwhash
    import nacl.secret

    key = fake_cloud.memory.enrolled_key()
    wrapped = json.loads(key["wrapped_private_key"])
    assert wrapped["kdf"] == "argon2id"
    derived = nacl.pwhash.argon2id.kdf(
        nacl.secret.SecretBox.KEY_SIZE,
        passphrase.encode("utf-8"),
        base64.b64decode(wrapped["salt"]),
        opslimit=wrapped["ops_limit"],
        memlimit=wrapped["mem_limit"],
    )
    private = nacl.secret.SecretBox(derived).decrypt(
        base64.b64decode(wrapped["ct"]), base64.b64decode(wrapped["nonce"])
    )
    public = base64.b64decode(key["public_key"])
    assert bytes(nacl.public.PrivateKey(private).public_key) == public
    return public, private


def envelope_key(envelope: dict, user_id: int, private_key: bytes) -> bytes:
    """The data key an envelope wraps for *user_id*, opened with their key."""
    import nacl.public

    (wrap,) = [w for w in envelope["dek_wraps"] if w["recipient_user_id"] == user_id]
    sealed = nacl.public.SealedBox(nacl.public.PrivateKey(private_key))
    return sealed.decrypt(base64.b64decode(wrap["wrapped_dek"]))


def open_envelope(envelope: dict, user_id: int, keypair: tuple[bytes, bytes]) -> dict:
    """Decrypt a stored envelope with the data key wrapped to *user_id*."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    data_key = envelope_key(envelope, user_id, keypair[1])
    plaintext = AESGCM(data_key).decrypt(
        base64.b64decode(envelope["iv"]),
        base64.b64decode(envelope["ciphertext"]) + base64.b64decode(envelope["tag"]),
        None,
    )
    return json.loads(plaintext)
