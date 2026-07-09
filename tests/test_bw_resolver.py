"""Tests for BwResolver — Bitwarden CLI SSH key resolution."""

from __future__ import annotations

import json
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest

from servonaut.services.bw_resolver import (
    BwCliMissingError,
    BwItemNotFoundError,
    BwItemShapeError,
    BwResolver,
    BwSessionMissingError,
)
from servonaut.utils.validation import ValidationError

VALID_ITEM_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
VALID_ITEM_ID_SHORT = "abc123"
SAMPLE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nfakekey\n-----END OPENSSH PRIVATE KEY-----"


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> CompletedProcess:  # type: ignore[type-arg]
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _bw_item_json(private_key: object) -> str:
    return json.dumps({"sshKey": {"privateKey": private_key}})


class TestHappyPath:
    def test_returns_key_body(self, caplog):
        with patch("shutil.which", return_value="/usr/bin/bw"), \
             patch("subprocess.run", return_value=_completed(stdout=_bw_item_json(SAMPLE_KEY))):
            resolver = BwResolver()
            key = resolver.resolve_ssh_key(VALID_ITEM_ID)
        assert key == SAMPLE_KEY

    def test_debug_breadcrumb_emitted(self, caplog):
        with patch("shutil.which", return_value="/usr/bin/bw"), \
             patch("subprocess.run", return_value=_completed(stdout=_bw_item_json(SAMPLE_KEY))):
            with caplog.at_level("DEBUG", logger="servonaut.services.bw_resolver"):
                BwResolver().resolve_ssh_key(VALID_ITEM_ID)
        assert any("sshKey.privateKey" in r.message for r in caplog.records)
        assert any("BW 2023.10+" in r.message for r in caplog.records)


class TestBwNotOnPath:
    def test_raises_bw_cli_missing(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(BwCliMissingError) as exc_info:
                BwResolver().resolve_ssh_key(VALID_ITEM_ID)
        assert exc_info.value.message
        assert "PATH" in exc_info.value.message

    def test_does_not_call_subprocess_when_binary_missing(self):
        with patch("shutil.which", return_value=None), \
             patch("subprocess.run") as mock_run:
            with pytest.raises(BwCliMissingError):
                BwResolver().resolve_ssh_key(VALID_ITEM_ID)
        mock_run.assert_not_called()


class TestVaultLocked:
    def test_not_logged_in_stderr(self):
        with patch("shutil.which", return_value="/usr/bin/bw"), \
             patch("subprocess.run", return_value=_completed(stderr="You are not logged in")):
            with pytest.raises(BwSessionMissingError) as exc_info:
                BwResolver().resolve_ssh_key(VALID_ITEM_ID)
        assert exc_info.value.message

    def test_vault_is_locked_stderr(self):
        with patch("shutil.which", return_value="/usr/bin/bw"), \
             patch("subprocess.run", return_value=_completed(stderr="Vault is locked")):
            with pytest.raises(BwSessionMissingError) as exc_info:
                BwResolver().resolve_ssh_key(VALID_ITEM_ID)
        assert "unlock" in exc_info.value.message.lower()

    def test_mac_failed_stderr(self):
        with patch("shutil.which", return_value="/usr/bin/bw"), \
             patch("subprocess.run", return_value=_completed(stderr="Mac failed. Invalid key.")):
            with pytest.raises(BwSessionMissingError):
                BwResolver().resolve_ssh_key(VALID_ITEM_ID)


class TestItemNotFound:
    def test_not_found_phrase_in_stderr(self):
        with patch("shutil.which", return_value="/usr/bin/bw"), \
             patch("subprocess.run", return_value=_completed(stderr="Not found.")):
            with pytest.raises(BwItemNotFoundError) as exc_info:
                BwResolver().resolve_ssh_key(VALID_ITEM_ID)
        assert VALID_ITEM_ID in exc_info.value.message


class TestItemShapeErrors:
    def test_missing_ssh_key_field(self):
        payload = json.dumps({"type": 5, "name": "My Server Key"})
        with patch("shutil.which", return_value="/usr/bin/bw"), \
             patch("subprocess.run", return_value=_completed(stdout=payload)):
            with pytest.raises(BwItemShapeError) as exc_info:
                BwResolver().resolve_ssh_key(VALID_ITEM_ID)
        assert "sshKey.privateKey" in exc_info.value.message

    def test_private_key_is_null(self):
        with patch("shutil.which", return_value="/usr/bin/bw"), \
             patch("subprocess.run", return_value=_completed(stdout=_bw_item_json(None))):
            with pytest.raises(BwItemShapeError) as exc_info:
                BwResolver().resolve_ssh_key(VALID_ITEM_ID)
        assert "sshKey.privateKey" in exc_info.value.message

    def test_private_key_is_empty_string(self):
        with patch("shutil.which", return_value="/usr/bin/bw"), \
             patch("subprocess.run", return_value=_completed(stdout=_bw_item_json(""))):
            with pytest.raises(BwItemShapeError) as exc_info:
                BwResolver().resolve_ssh_key(VALID_ITEM_ID)
        assert "sshKey.privateKey" in exc_info.value.message

    def test_stdout_not_valid_json(self):
        with patch("shutil.which", return_value="/usr/bin/bw"), \
             patch("subprocess.run", return_value=_completed(stdout="not-json-at-all")):
            with pytest.raises(BwItemShapeError) as exc_info:
                BwResolver().resolve_ssh_key(VALID_ITEM_ID)
        assert exc_info.value.message


class TestInvalidItemId:
    @pytest.mark.parametrize("bad_id", [
        "../../etc/passwd",
        "../relative",
        "",
        "a" * 65,
        "has space",
        "has/slash",
    ])
    def test_raises_validation_error_before_shelling_out(self, bad_id: str):
        with patch("shutil.which", return_value="/usr/bin/bw"), \
             patch("subprocess.run") as mock_run:
            with pytest.raises(ValidationError):
                BwResolver().resolve_ssh_key(bad_id)
        mock_run.assert_not_called()


class TestCustomBwBinary:
    def test_uses_custom_binary_path(self):
        with patch("shutil.which", return_value="/opt/bw/bw") as mock_which, \
             patch("subprocess.run", return_value=_completed(stdout=_bw_item_json(SAMPLE_KEY))) as mock_run:
            BwResolver(bw_binary="/opt/bw/bw").resolve_ssh_key(VALID_ITEM_ID_SHORT)
        mock_which.assert_called_once_with("/opt/bw/bw")
        args = mock_run.call_args[0][0]
        assert args[0] == "/opt/bw/bw"

    def test_missing_custom_binary_raises_bw_cli_missing(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(BwCliMissingError) as exc_info:
                BwResolver(bw_binary="/opt/bw/bw").resolve_ssh_key(VALID_ITEM_ID_SHORT)
        assert "/opt/bw/bw" in exc_info.value.message


class TestSessionInjection:
    """The injected session getter must reach ``bw`` via env, never argv;
    ambient ``BW_SESSION`` stays a fallback (Phase 1 security pins)."""

    def test_injected_session_passed_via_env_not_argv(self):
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=_bw_item_json(SAMPLE_KEY))
        ) as mock_run:
            resolver = BwResolver(session_getter=lambda: "sess-INJECTED")
            resolver.resolve_ssh_key(VALID_ITEM_ID)
        argv = mock_run.call_args[0][0]
        assert "sess-INJECTED" not in argv
        assert all("sess-INJECTED" not in str(tok) for tok in argv)
        assert mock_run.call_args.kwargs["env"]["BW_SESSION"] == "sess-INJECTED"

    def test_ambient_session_preserved_without_getter(self, monkeypatch):
        monkeypatch.setenv("BW_SESSION", "ambient-sess")
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=_bw_item_json(SAMPLE_KEY))
        ) as mock_run:
            BwResolver().resolve_ssh_key(VALID_ITEM_ID)
        assert mock_run.call_args.kwargs["env"]["BW_SESSION"] == "ambient-sess"

    def test_getter_returning_none_falls_back_to_ambient(self, monkeypatch):
        monkeypatch.setenv("BW_SESSION", "ambient-sess")
        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=_bw_item_json(SAMPLE_KEY))
        ) as mock_run:
            BwResolver(session_getter=lambda: None).resolve_ssh_key(VALID_ITEM_ID)
        assert mock_run.call_args.kwargs["env"]["BW_SESSION"] == "ambient-sess"

    def test_broken_getter_does_not_block_resolution(self):
        def _boom():
            raise RuntimeError("getter exploded")

        with patch("shutil.which", return_value="/usr/bin/bw"), patch(
            "subprocess.run", return_value=_completed(stdout=_bw_item_json(SAMPLE_KEY))
        ):
            key = BwResolver(session_getter=_boom).resolve_ssh_key(VALID_ITEM_ID)
        assert key == SAMPLE_KEY
