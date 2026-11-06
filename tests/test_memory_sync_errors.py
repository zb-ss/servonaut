"""Wording for a failed Memory Sync bootstrap, shared by the screen and the unlock prompt."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from servonaut.services.memory.crypto import DecryptionFailedError, WeakPassphraseError
from servonaut.services.memory.interfaces import (
    BackendMaintenance,
    BetaWaitlist,
    RateLimited,
    UpsellRequired,
)
from servonaut.services.memory.sync_errors import (
    WRONG_PASSPHRASE_MESSAGE,
    describe_sync_error,
    is_wrong_passphrase,
)


class RateLimitedError(Exception):
    """Stands in for ``api_client.RateLimitedError``: matched by class name."""

    def __init__(self, message: str, *, endpoint: str = "", retry_after_s: int = 0) -> None:
        super().__init__(message)
        self.endpoint = endpoint
        self.retry_after_s = retry_after_s


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (DecryptionFailedError("decryption failed"), WRONG_PASSPHRASE_MESSAGE),
        (ValueError("Decryption failed: bad MAC"), WRONG_PASSPHRASE_MESSAGE),
        (BackendMaintenance("Server feature_disabled"),
         "Memory backend is in maintenance — try again later."),
        (BetaWaitlist("feature_not_available"),
         "Memory Sync is in beta — your account is not on the allowlist yet."),
        (UpsellRequired("free"), "Your plan doesn't include Memory Sync — upgrade to enable."),
        (WeakPassphraseError("too weak"), "Passphrase is too weak — pick a stronger one."),
        (OSError("connection reset"), "Prefix: connection reset"),
        (OSError(), "Prefix: OSError"),
    ],
)
def test_each_failure_reads_the_same_wherever_it_is_shown(exc, expected):
    assert describe_sync_error(exc, failure_prefix="Prefix") == expected


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (RateLimitedError("429", endpoint="/api/v1/memory/keys/me"),
         "Server rate limit hit on /keys/me (3 attempts per hour). Wait ~20 minutes and try again."),
        (RateLimitedError("429", retry_after_s=600), "Server rate limit hit. Try again in ~10 min."),
        (RateLimitedError("429", retry_after_s=30), "Server rate limit hit. Try again in ~1 min."),
        (RateLimited("/api/v1/memory/sync", 0),
         "Server rate limit hit. Try again in a few minutes "
         "(spec caps key endpoints at 3 setup attempts per hour)."),
        (OSError("rate limit exceeded"),
         "Server rate limit hit. Try again in a few minutes "
         "(spec caps key endpoints at 3 setup attempts per hour)."),
    ],
)
def test_rate_limits_say_how_long_to_wait(exc, expected):
    assert describe_sync_error(exc, failure_prefix="Prefix") == expected


def test_only_a_decryption_failure_is_a_wrong_passphrase():
    assert is_wrong_passphrase(DecryptionFailedError("decryption failed"))
    assert not is_wrong_passphrase(BackendMaintenance("Server feature_disabled"))
    assert not is_wrong_passphrase(RuntimeError("cancelled"))


class TestSetupScreenWording:
    """The Memory Sync screen keeps its wording and shows server text as plain text."""

    @staticmethod
    def _show(exc: Exception) -> MagicMock:
        from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen

        notify = MagicMock()
        screen = SimpleNamespace(app=SimpleNamespace(notify=notify), query_one=MagicMock())
        MemorySyncSetupScreen._show_setup_error(screen, exc)  # type: ignore[arg-type]
        return notify

    @pytest.mark.parametrize(
        ("exc", "label"),
        [
            (RuntimeError("Memory keypair unlock cancelled by user"), "Setup cancelled."),
            (DecryptionFailedError("decryption failed"), WRONG_PASSPHRASE_MESSAGE),
            (OSError("[red]boom[/red]"), "Setup failed: [red]boom[/red]"),
        ],
    )
    def test_setup_errors(self, exc, label):
        notify = self._show(exc)
        notify.assert_called_once_with(label, severity="error", timeout=8, markup=False)
