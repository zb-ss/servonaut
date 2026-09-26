"""Byte-size checks the fakes apply to encrypted payloads, like the service.

A fake that accepted any string labelled ``aes-256-gcm`` would also accept
plaintext. These helpers decode strict base64 and check sizes, so an upload
only passes if it has the shape of real ciphertext: a 12-byte GCM nonce, a
16-byte tag, a 16-byte KDF salt, an 80-byte X25519 sealed box around a
32-byte data key.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any, Optional

GCM_IV = 12
GCM_TAG = 16
KDF_SALT = 16
X25519_KEY = 32
# A sealed box adds an ephemeral public key (32) and a MAC (16) to the key.
SEALED_DATA_KEY = 32 + 32 + 16
SECRETBOX_NONCE = 24
SECRETBOX_MAC = 16


def b64_size(value: Any) -> Optional[int]:
    """The decoded length of strict base64 *value*, or None if it is not."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return len(base64.b64decode(value, validate=True))
    except (binascii.Error, ValueError):
        return None


def has_size(value: Any, size: int) -> bool:
    return b64_size(value) == size


def has_bytes(value: Any) -> bool:
    return (b64_size(value) or 0) > 0
