"""User-facing wording for a Memory Sync bootstrap that failed.

The Memory Sync screen and the unlock prompt that opens with a memory
section run the same bootstrap, so they describe its failures in the same
words.
"""

from __future__ import annotations

WRONG_PASSPHRASE_MESSAGE = "Wrong passphrase — try again."

_RATE_LIMIT_KINDS = frozenset({"RateLimitedError", "RateLimited", "RateLimitTimeoutError"})

# Typed memory exceptions with a routing hint instead of their raw text.
_KNOWN_FAILURES = {
    "BackendMaintenance": "Memory backend is in maintenance — try again later.",
    "BetaWaitlist": "Memory Sync is in beta — your account is not on the allowlist yet.",
    "UpsellRequired": "Your plan doesn't include Memory Sync — upgrade to enable.",
    "WeakPassphraseError": "Passphrase is too weak — pick a stronger one.",
}


def is_wrong_passphrase(exc: BaseException) -> bool:
    """Whether *exc* means the passphrase did not decrypt the keypair.

    The crypto layer raises ``DecryptionFailedError`` for a wrong
    passphrase; the message check covers the same failure re-raised as a
    plain exception.
    """
    return (
        exc.__class__.__name__ == "DecryptionFailedError"
        or "decryption failed" in str(exc).lower()
    )


def describe_sync_error(exc: BaseException, *, failure_prefix: str) -> str:
    """Return the message to show for a failed Memory Sync bootstrap.

    Args:
        exc: The exception the bootstrap raised.
        failure_prefix: Lead-in for a failure without specific wording,
            e.g. ``"Setup failed"``; the exception's text follows it.

    Returns:
        Plain text (no Rich markup): the exception text may come from the
        server, so callers show it with markup off or escaped.
    """
    msg = str(exc) or exc.__class__.__name__
    kind = exc.__class__.__name__
    if kind in _RATE_LIMIT_KINDS or "rate limit" in msg.lower():
        return _rate_limit_message(exc)
    if is_wrong_passphrase(exc):
        return WRONG_PASSPHRASE_MESSAGE
    return _KNOWN_FAILURES.get(kind) or f"{failure_prefix}: {msg}"


def _rate_limit_message(exc: BaseException) -> str:
    """Tell the user to wait: retrying at once only hits the limit again.

    Covers both ``api_client.RateLimitedError`` (HTTP 429) and the
    memory-domain ``RateLimited`` wrapper. The key endpoints allow 3 setup
    attempts per hour, so repeated attempts use the quota up quickly.
    """
    endpoint = getattr(exc, "endpoint", None)
    retry_s = getattr(exc, "retry_after_s", None)
    if endpoint and "keys/me" in str(endpoint):
        return (
            "Server rate limit hit on /keys/me (3 attempts per hour). "
            "Wait ~20 minutes and try again."
        )
    if retry_s:
        wait_min = max(1, int(retry_s) // 60)
        return f"Server rate limit hit. Try again in ~{wait_min} min."
    return (
        "Server rate limit hit. Try again in a few minutes "
        "(spec caps key endpoints at 3 setup attempts per hour)."
    )
