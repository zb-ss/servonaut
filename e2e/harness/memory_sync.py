"""Helpers for the Memory Sync journeys: user steps and envelope checks.

The passphrase comes from ``SERVONAUT_MEMORY_PASSPHRASE`` (set by the
journey), the way a headless or scripted session supplies it, so no
passphrase dialog is involved. Every UI step waits for what the user sees:
the status line, the toasts, and the action buttons becoming available.

:func:`enrolled_keypair` and :func:`open_envelope` let a journey prove that
what FakeCloud stored is readable by the right key holder only.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

from rich.text import Text

PASSPHRASE_ENV = "SERVONAUT_MEMORY_PASSPHRASE"
# Fabricated for the suite; strong enough for the client's passphrase check.
PASSPHRASE = "Correct-Horse-Battery-Staple-2030!"
ACTIVE = "● Active"


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
    """The enrolled (public, private) keypair, unwrapped as a device would."""
    from servonaut.services.memory.crypto import WrappedPrivateKey, unwrap_private_key

    key = fake_cloud.memory.enrolled_key()
    wrapped = WrappedPrivateKey.from_json(key["wrapped_private_key"])
    return base64.b64decode(key["public_key"]), unwrap_private_key(wrapped, passphrase)


def open_envelope(envelope: dict, user_id: int, keypair: tuple[bytes, bytes]) -> dict:
    """Decrypt a stored envelope with the DEK wrapped to *user_id*."""
    from servonaut.services.memory.crypto import decrypt_envelope

    public, private = keypair
    plaintext = decrypt_envelope(
        envelope, self_user_id=user_id, self_private_key=private, self_public_key=public
    )
    return json.loads(plaintext)
