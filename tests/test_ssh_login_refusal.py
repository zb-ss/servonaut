"""Tests for is_ssh_login_refusal."""

from __future__ import annotations

import time

import pytest

from servonaut.utils.ssh_utils import is_ssh_login_refusal


class TestIsSshLoginRefusal:
    @pytest.mark.parametrize("text", [
        "deploy@web-1: Permission denied (publickey).",
        "Permission denied (publickey,password).",
        "Permission denied (publickey,gssapi-keyex,gssapi-with-mic).",
    ])
    def test_login_refusals(self, text):
        assert is_ssh_login_refusal(text) is True

    @pytest.mark.parametrize("text", [
        "ls: cannot open directory '/mnt/efs': Permission denied",
        "Permission denied, please try again.",
        "",
        None,
    ])
    def test_other_text(self, text):
        assert is_ssh_login_refusal(text) is False

    def test_long_input_is_fast(self):
        start = time.monotonic()
        assert is_ssh_login_refusal("permission denied (" + "a" * 50_000) is False
        assert time.monotonic() - start < 1


# --- ssh's own refusal: its exit code and its own line ---------------------

@pytest.mark.parametrize("text", [
    "deploy@web-1: Permission denied (publickey).",
    "Warning: Permanently added 'web-1' (ED25519) to the list of known hosts.\n"
    "deploy@192.0.2.10: Permission denied (publickey,password).",
])
def test_ssh_s_own_refusal_line_with_its_failure_code(text):
    from servonaut.utils.ssh_utils import is_ssh_own_login_refusal

    assert is_ssh_own_login_refusal(text, ssh_failed=True)
    assert not is_ssh_own_login_refusal(text, ssh_failed=False)


@pytest.mark.parametrize("text", [
    "ls: cannot open directory 'deploy@web-1: Permission denied (publickey).': Permission denied",
    "scp: /srv/deploy@web-1: Permission denied (publickey).: No such file or directory",
    "ls: cannot open directory '/mnt/efs': Permission denied",
])
def test_refusal_words_inside_a_remote_error_are_not_a_refusal(text):
    from servonaut.utils.ssh_utils import is_ssh_own_login_refusal

    assert not is_ssh_own_login_refusal(text, ssh_failed=True)
