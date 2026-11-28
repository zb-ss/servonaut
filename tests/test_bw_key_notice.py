"""Tests for servonaut.services.bw_key_notice."""

from __future__ import annotations

import pytest

from servonaut.services.bw_errors import (
    BwCliMissingError,
    BwItemNotFoundError,
    BwItemShapeError,
    BwSessionMissingError,
)
from servonaut.services.bw_key_notice import (
    BW_KEY_UNREADABLE,
    bw_key_notice,
    bw_key_reason,
    is_bw_key_notice,
    uses_bw_key,
)

REASONS = [
    "BwCliMissingError",
    "BwSessionMissingError",
    "BwItemNotFoundError",
    "BwItemShapeError",
    BW_KEY_UNREADABLE,
]


class _Sub(BwSessionMissingError):
    pass


class TestReason:
    @pytest.mark.parametrize("exc,code", [
        (BwCliMissingError("x"), "BwCliMissingError"),
        (BwSessionMissingError("x"), "BwSessionMissingError"),
        (BwItemNotFoundError("x"), "BwItemNotFoundError"),
        (BwItemShapeError("x"), "BwItemShapeError"),
        (_Sub("x"), "BwSessionMissingError"),
        (OSError("x"), "BwKeyUnreadable"),
    ])
    def test_reason(self, exc, code):
        assert bw_key_reason(exc) == code


class TestNotice:
    def test_in_app_locked(self):
        assert bw_key_notice("BwSessionMissingError") == (
            "Bitwarden is locked, so this server's Bitwarden key was not used. "
            "Unlock it under Settings > Bitwarden SSH and retry."
        )

    def test_headless_locked(self):
        assert bw_key_notice("BwSessionMissingError", headless=True) == (
            "Bitwarden is locked, so this server's Bitwarden key was not used. "
            "Ask the user to unlock Bitwarden and restart this MCP server with "
            "BW_SESSION set in its environment; do not request or handle the "
            "session value yourself."
        )

    @pytest.mark.parametrize("reason", REASONS)
    @pytest.mark.parametrize("headless", [False, True])
    def test_every_reason(self, reason, headless):
        notice = bw_key_notice(reason, headless=headless)
        assert notice and is_bw_key_notice(notice)

    def test_unknown_reason_is_unreadable(self):
        assert bw_key_notice("weird") == bw_key_notice(BW_KEY_UNREADABLE)

    @pytest.mark.parametrize("reason", [None, ""])
    def test_no_reason(self, reason):
        assert bw_key_notice(reason) is None

    def test_is_notice_negative(self):
        assert not is_bw_key_notice("Permission denied")
        assert not is_bw_key_notice(bw_key_notice("BwSessionMissingError") + " extra")


class TestUsesBwKey:
    @pytest.mark.parametrize("source,expected", [
        ("bw_personal", True), ("bw_team", True), ("vault_ca", False), (None, False),
    ])
    def test_uses(self, source, expected):
        assert uses_bw_key({"key_source": source}) is expected
