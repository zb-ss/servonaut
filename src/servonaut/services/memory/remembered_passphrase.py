"""Rules for the Memory Sync passphrase remembered on this device."""
from __future__ import annotations

from datetime import datetime, timezone


def remember_passphrase_expired(expires_at: str) -> bool:
    """Return ``True`` when the remembered passphrase has passed its TTL.

    *expires_at* is ``config.memory.sync_remember_expires_at`` (ISO-8601 UTC).
    An empty value means "no expiry recorded" (legacy enrolment from before
    the TTL feature) and is treated as NOT expired so existing users are not
    surprised by a sudden re-prompt; the timestamp is stamped the next time
    they re-enter the passphrase. Unparseable values fail open (not expired):
    a malformed timestamp should not lock a user out.
    """
    raw = expires_at or ""
    if not raw:
        return False
    try:
        expires = datetime.fromisoformat(raw)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= expires
    except (TypeError, ValueError):
        return False
