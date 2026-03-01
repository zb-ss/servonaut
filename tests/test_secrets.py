"""Tests for centralized secret resolution."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from servonaut.config.secrets import resolve_secret, is_secret_ref, load_secrets_env


# ---------------------------------------------------------------------------
# resolve_secret
# ---------------------------------------------------------------------------

class TestResolveSecret:
    def test_plain_text_returned_as_is(self):
        assert resolve_secret("sk-abc123") == "sk-abc123"

    def test_empty_string_returned_as_is(self):
        assert resolve_secret("") == ""

    def test_env_var_resolved(self, monkeypatch):
        monkeypatch.setenv("MY_SECRET", "resolved-value")
        assert resolve_secret("$MY_SECRET") == "resolved-value"

    def test_env_var_missing_returns_empty(self, monkeypatch):
        monkeypatch.delenv("NONEXISTENT_VAR_XYZ", raising=False)
        assert resolve_secret("$NONEXISTENT_VAR_XYZ") == ""

    def test_file_reference_resolved(self, tmp_path):
        secret_file = tmp_path / "api_key"
        secret_file.write_text("  file-secret-value  \n")
        assert resolve_secret(f"file:{secret_file}") == "file-secret-value"

    def test_file_reference_with_tilde(self, tmp_path, monkeypatch):
        secret_file = tmp_path / "key"
        secret_file.write_text("tilde-value")
        monkeypatch.setenv("HOME", str(tmp_path))
        assert resolve_secret("file:~/key") == "tilde-value"

    def test_file_reference_missing_returns_empty(self):
        assert resolve_secret("file:/nonexistent/path/secret") == ""

    def test_dollar_sign_only(self, monkeypatch):
        # Edge case: "$" alone means env var name is empty string
        monkeypatch.delenv("", raising=False)
        assert resolve_secret("$") == ""


# ---------------------------------------------------------------------------
# is_secret_ref
# ---------------------------------------------------------------------------

class TestIsSecretRef:
    def test_env_var_is_ref(self):
        assert is_secret_ref("$MY_VAR") is True

    def test_file_is_ref(self):
        assert is_secret_ref("file:/some/path") is True

    def test_plain_text_is_not_ref(self):
        assert is_secret_ref("sk-abc123") is False

    def test_empty_is_not_ref(self):
        assert is_secret_ref("") is False


# ---------------------------------------------------------------------------
# load_secrets_env
# ---------------------------------------------------------------------------

class TestLoadSecretsEnv:
    def test_loads_key_value_pairs(self, tmp_path, monkeypatch):
        env_file = tmp_path / "test.env"
        env_file.write_text("SECRET_A=value_a\nSECRET_B=value_b\n")
        monkeypatch.delenv("SECRET_A", raising=False)
        monkeypatch.delenv("SECRET_B", raising=False)

        load_secrets_env(env_file)

        assert os.environ["SECRET_A"] == "value_a"
        assert os.environ["SECRET_B"] == "value_b"

        # Cleanup
        monkeypatch.delenv("SECRET_A")
        monkeypatch.delenv("SECRET_B")

    def test_existing_env_takes_precedence(self, tmp_path, monkeypatch):
        env_file = tmp_path / "test.env"
        env_file.write_text("EXISTING_VAR=file-value\n")
        monkeypatch.setenv("EXISTING_VAR", "env-value")

        load_secrets_env(env_file)

        assert os.environ["EXISTING_VAR"] == "env-value"

    def test_skips_comments_and_blank_lines(self, tmp_path, monkeypatch):
        env_file = tmp_path / "test.env"
        env_file.write_text("# comment\n\nKEY_C=val_c\n  # another comment\n")
        monkeypatch.delenv("KEY_C", raising=False)

        load_secrets_env(env_file)

        assert os.environ["KEY_C"] == "val_c"
        monkeypatch.delenv("KEY_C")

    def test_strips_quotes(self, tmp_path, monkeypatch):
        env_file = tmp_path / "test.env"
        env_file.write_text('DQ_VAR="double-quoted"\nSQ_VAR=\'single-quoted\'\n')
        monkeypatch.delenv("DQ_VAR", raising=False)
        monkeypatch.delenv("SQ_VAR", raising=False)

        load_secrets_env(env_file)

        assert os.environ["DQ_VAR"] == "double-quoted"
        assert os.environ["SQ_VAR"] == "single-quoted"
        monkeypatch.delenv("DQ_VAR")
        monkeypatch.delenv("SQ_VAR")

    def test_missing_file_silently_skipped(self, tmp_path):
        load_secrets_env(tmp_path / "nonexistent.env")
        # No exception raised

    def test_malformed_line_skipped(self, tmp_path, monkeypatch):
        env_file = tmp_path / "test.env"
        env_file.write_text("NO_EQUALS_SIGN\nGOOD_KEY=good_val\n")
        monkeypatch.delenv("GOOD_KEY", raising=False)

        load_secrets_env(env_file)

        assert os.environ["GOOD_KEY"] == "good_val"
        monkeypatch.delenv("GOOD_KEY")

    def test_value_with_equals_sign(self, tmp_path, monkeypatch):
        env_file = tmp_path / "test.env"
        env_file.write_text("URL=https://example.com?foo=bar&baz=1\n")
        monkeypatch.delenv("URL", raising=False)

        load_secrets_env(env_file)

        assert os.environ["URL"] == "https://example.com?foo=bar&baz=1"
        monkeypatch.delenv("URL")
