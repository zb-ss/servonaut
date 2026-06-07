"""Tests for :class:`LocalProvider` and the :class:`SecretProviderInterface`.

These tests pin down the secrets-management contract:

- LocalProvider is the foundation backend; every CLI install gets
  one regardless of plan/entitlement state.
- Interface methods are async and return raw secret strings; missing
  secrets resolve to ``None``, not exceptions.
- Storage is mode 0600, atomically written, JSON dict on disk.
- List-secrets returns sorted names; values NEVER leak through it.
- The file gets created on first write, not on first read.

Tests deliberately stay close to :mod:`tests.test_auth_service`'s
shape — secrets.json and auth.json share the same write pattern and
trust model, so future readers can transfer intuition cleanly.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from servonaut.services.secret_provider import LocalProvider


def run(coro):
    """Run a coroutine synchronously (matches test_auth_service)."""
    return asyncio.run(coro)


@pytest.fixture
def secrets_file(tmp_path: Path, monkeypatch) -> Path:
    """Per-test secrets path under pytest's tmp dir.

    Returned path is guaranteed NOT to exist yet so individual tests
    can assert on creation vs. update semantics independently.

    Redirects :data:`LOCAL_PROVIDER_ROOT` at ``tmp_path`` so the
    production path-traversal guard still fires (rather than being
    bypassed) — every test exercises the guard implicitly with the
    legitimate-path code path.
    """
    monkeypatch.setattr(
        "servonaut.services.secret_provider.LOCAL_PROVIDER_ROOT",
        tmp_path,
    )
    return tmp_path / "secrets.json"


@pytest.fixture
def provider(secrets_file: Path) -> LocalProvider:
    return LocalProvider(secrets_file=secrets_file)


class TestInterfaceBasics:
    def test_provider_name_is_stable_identifier(self, provider):
        # provider_name is read by AdminAuditService entries + the
        # CLI status UI — a stable string contract.
        assert provider.provider_name == "local"

    def test_path_property_exposes_storage_location(self, provider, secrets_file):
        assert provider.path == secrets_file


class TestEmptyStore:
    """First-run / fresh-install behaviour. No file on disk."""

    def test_get_unknown_returns_none_not_exception(self, provider):
        assert run(provider.get_secret("anything")) is None

    def test_list_returns_empty_list_not_none(self, provider):
        assert run(provider.list_secrets()) == []

    def test_delete_missing_returns_false_idempotent(self, provider):
        # The interface contract says delete is idempotent: deleting
        # a name that wasn't there is NOT an error. Callers must be
        # able to swallow the False without special-casing.
        assert run(provider.delete_secret("ghost")) is False

    def test_file_not_created_on_pure_reads(self, provider, secrets_file):
        # Reading should never materialise the file — important for
        # an unattended dry-run on a read-only home dir.
        run(provider.list_secrets())
        run(provider.get_secret("x"))
        assert not secrets_file.exists()


class TestRoundTrip:
    def test_set_then_get_returns_value(self, provider):
        run(provider.set_secret("api_key", "sk-abc-123"))
        assert run(provider.get_secret("api_key")) == "sk-abc-123"

    def test_set_overwrites_existing(self, provider):
        run(provider.set_secret("api_key", "old"))
        run(provider.set_secret("api_key", "new"))
        assert run(provider.get_secret("api_key")) == "new"

    def test_delete_removes(self, provider):
        run(provider.set_secret("api_key", "v"))
        deleted = run(provider.delete_secret("api_key"))
        assert deleted is True
        assert run(provider.get_secret("api_key")) is None

    def test_secret_names_are_case_sensitive(self, provider):
        # Contract: providers must NOT silently canonicalise names.
        # Mixing API_KEY and api_key MUST refer to two distinct secrets.
        run(provider.set_secret("API_KEY", "upper"))
        run(provider.set_secret("api_key", "lower"))
        assert run(provider.get_secret("API_KEY")) == "upper"
        assert run(provider.get_secret("api_key")) == "lower"

    def test_list_returns_sorted_names_only(self, provider):
        # Sorted output is contractual so consumers can diff two
        # snapshots without normalising. Also pins that list_secrets
        # MUST NOT return values — only names.
        run(provider.set_secret("zeta", "z"))
        run(provider.set_secret("alpha", "a"))
        run(provider.set_secret("middle", "m"))
        names = run(provider.list_secrets())
        assert names == ["alpha", "middle", "zeta"]


class TestPersistenceAcrossInstances:
    """The store is on disk — a fresh provider on the same path must
    see writes from a prior instance. Multi-process scenario: TUI
    writes, headless ``servonaut --mcp`` reads on its next call.
    """

    def test_second_instance_sees_first_writes(self, secrets_file):
        a = LocalProvider(secrets_file=secrets_file)
        run(a.set_secret("shared", "v1"))

        b = LocalProvider(secrets_file=secrets_file)
        assert run(b.get_secret("shared")) == "v1"

    def test_second_instance_sees_first_deletes(self, secrets_file):
        a = LocalProvider(secrets_file=secrets_file)
        run(a.set_secret("transient", "v"))

        b = LocalProvider(secrets_file=secrets_file)
        run(b.delete_secret("transient"))

        c = LocalProvider(secrets_file=secrets_file)
        assert run(c.get_secret("transient")) is None


class TestFilePermissions:
    """Secrets at rest must be owner-only (0600). Same trust model as
    auth.json — see test_auth_service.py::TestAuthTokenFilePermissions.
    """

    def test_first_write_creates_0600(self, provider, secrets_file):
        run(provider.set_secret("k", "v"))
        mode = secrets_file.stat().st_mode & 0o777
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_subsequent_writes_keep_0600(self, provider, secrets_file):
        run(provider.set_secret("k1", "v1"))
        run(provider.set_secret("k2", "v2"))
        mode = secrets_file.stat().st_mode & 0o777
        assert mode == 0o600

    def test_load_tightens_world_readable_legacy_file(
        self, provider, secrets_file
    ):
        """A file written by some hypothetical older code path with
        looser permissions must be re-chmod'd silently on next read.
        Mirrors :meth:`AuthService._ensure_secure_mode`.
        """
        secrets_file.write_text(json.dumps({"k": "v"}))
        os.chmod(secrets_file, 0o644)
        assert (secrets_file.stat().st_mode & 0o777) == 0o644

        # Any read triggers the fix-up path.
        assert run(provider.get_secret("k")) == "v"
        assert (secrets_file.stat().st_mode & 0o777) == 0o600


class TestAtomicWrite:
    def test_no_tmp_file_left_on_success(self, provider, secrets_file):
        run(provider.set_secret("k", "v"))
        tmp = secrets_file.with_suffix(secrets_file.suffix + ".tmp")
        assert not tmp.exists(), "tmp file should have been os.replace'd"
        assert secrets_file.exists()

    def test_interrupted_write_preserves_original_file(
        self, secrets_file, tmp_path
    ):
        """If ``os.replace`` blows up mid-save, the previously-good
        secrets file must survive — same invariant we pin for
        auth.json.
        """
        # Seed a known-good store.
        provider = LocalProvider(secrets_file=secrets_file)
        run(provider.set_secret("keep_me", "v"))

        # Force os.replace to fail; ``set_secret`` should raise without
        # clobbering the on-disk file.
        with patch(
            "servonaut.services.secret_provider.os.replace",
            side_effect=OSError("boom"),
        ):
            with pytest.raises(OSError):
                run(provider.set_secret("NEW", "should-not-land"))

        # Original survives.
        data = json.loads(secrets_file.read_text())
        assert data == {"keep_me": "v"}


class TestCorruptStoreRecovery:
    """A corrupt or hand-edited file must NOT crash the CLI — log and
    start from empty. Otherwise users with a broken secrets.json can
    no longer authenticate at all.
    """

    def test_invalid_json_returns_empty_store(self, provider, secrets_file):
        secrets_file.write_text("{not valid json")
        os.chmod(secrets_file, 0o600)
        assert run(provider.list_secrets()) == []
        assert run(provider.get_secret("anything")) is None

    def test_wrong_shape_returns_empty_store(self, provider, secrets_file):
        # Someone hand-edited the file to a list — recover, don't
        # explode. Future-CLI shapes (e.g. nested namespaces) would
        # land here until we read them properly.
        secrets_file.write_text(json.dumps(["not", "a", "dict"]))
        os.chmod(secrets_file, 0o600)
        assert run(provider.list_secrets()) == []

    def test_non_string_values_are_dropped(self, provider, secrets_file):
        # If something wrote ints/lists/null in there, drop them
        # rather than crash on str-typed accessors downstream.
        secrets_file.write_text(json.dumps({
            "good": "v",
            "bad_int": 42,
            "bad_list": ["a"],
            "bad_null": None,
        }))
        os.chmod(secrets_file, 0o600)
        names = run(provider.list_secrets())
        assert names == ["good"]
        assert run(provider.get_secret("good")) == "v"
        assert run(provider.get_secret("bad_int")) is None
