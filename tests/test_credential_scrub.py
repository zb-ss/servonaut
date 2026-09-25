"""Tests for masking credentials in text bound for logs and the UI."""

from __future__ import annotations

import pytest

from servonaut.utils.credential_scrub import proxy_credentials, scrub_credentials


class TestScrubCredentials:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("GET http://user:secret@h:3128/x failed", "GET http://***@h:3128/x failed"),
            # A password holding "@" is masked whole, not up to its first "@".
            ("via http://u:p@ss@h:3128", "via http://***@h:3128"),
            ("HTTPS://Admin:Pa%40ss@example.com:8080 refused", "HTTPS://***@example.com:8080 refused"),
            ("proxy user:secret@host:3128 failed", "proxy ***@host:3128 failed"),
            ("proxy u:p@ss@host:3128 failed", "proxy ***@host:3128 failed"),
        ],
    )
    def test_credentials_are_masked(self, text: str, expected: str) -> None:
        assert scrub_credentials(text) == expected

    @pytest.mark.parametrize(
        "text",
        [
            "contact admin@example.com",
            "git@example.com:org/repo.git",
            "ERROR: foo@bar",
            "https://example.com/a?b=c@d",
            "Downloading voice packages (3/8)",
        ],
    )
    def test_ordinary_text_is_left_alone(self, text: str) -> None:
        assert scrub_credentials(text) == text

    def test_given_literals_are_masked_anywhere(self) -> None:
        assert scrub_credentials("auth failed: hunter22", ["hunter22"]) == "auth failed: ***"


class TestProxyCredentials:
    def test_raw_and_decoded_forms_are_collected(self) -> None:
        env = {
            "HTTPS_PROXY": "http://alice:s%40cret99@example.com:3128",
            "NO_PROXY": "localhost",
            "PATH": "/usr/bin",
        }
        found = set(proxy_credentials(env))
        assert {"s%40cret99", "s@cret99", "alice:s%40cret99", "alice:s@cret99"} <= found

    def test_a_proxy_without_credentials_yields_nothing(self) -> None:
        assert proxy_credentials({"HTTPS_PROXY": "http://example.com:3128"}) == ()

    def test_decoded_secrets_echoed_by_a_program_are_masked(self) -> None:
        env = {"https_proxy": "http://alice:s%40cret99@example.com:3128"}
        text = "proxy auth with password s@cret99 rejected"
        assert "s@cret99" not in scrub_credentials(text, proxy_credentials(env))
