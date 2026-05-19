"""Tests for Step 5 — :class:`SSHService` integration with
:class:`SecretProviderInterface`.

Covers the new :meth:`SSHService.discover_key_async` cascade:

1. No provider → falls through to ``discover_key`` (~/.ssh).
2. Provider has the key + value parses as a private key → write to
   ``~/.servonaut/keys/<sanitised>``, return that path. Perms 0600.
3. Provider returns None → fall through.
4. Provider returns a non-private-key value (public key, garbage,
   empty) → fall through with WARNING.
5. Provider raises → fall through with WARNING (don't break SSH
   over a transient provider hiccup).
6. Key name with path-traversal-shaped characters is sanitised so
   the written file CANNOT escape :data:`PROVIDER_KEYS_DIR`.
7. Directory perms tightened to 0700 on write.
"""
from __future__ import annotations

import asyncio
import os
import stat
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.ssh_service import (
    PROVIDER_KEYS_DIR,
    SSHService,
)


# Real RSA private-key marker — enough that ``_looks_like_private_key``
# accepts the blob. Body is bogus on purpose; tests are about routing,
# not crypto. Production code defers cryptographic validation to
# OpenSSH which fails loud on a malformed key.
SAMPLE_RSA_PRIVATE = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEogIBAAKCAQEA...this-is-a-fake-key-body...==\n"
    "-----END RSA PRIVATE KEY-----\n"
)

SAMPLE_OPENSSH_PRIVATE = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU...==\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def keys_dir(tmp_path: Path, monkeypatch) -> Path:
    """Redirect :data:`PROVIDER_KEYS_DIR` at the pytest tmp dir.

    Same fixture pattern the LocalProvider tests use — monkeypatch
    the production constant so the path guard still fires, but the
    actual writes land under tmp_path."""
    target = tmp_path / "keys"
    monkeypatch.setattr(
        "servonaut.services.ssh_service.PROVIDER_KEYS_DIR", target,
    )
    return target


@pytest.fixture
def ssh_dir(tmp_path: Path, monkeypatch) -> Path:
    """Empty ~/.ssh stub so the fallback path can be tested without
    polluting the real user's directory.

    Monkeypatches ``Path.home`` inside the ssh_service module so
    SSHService.__init__'s ``self._ssh_dir = Path.home() / '.ssh'``
    resolves to ``tmp_path / .ssh``. Setting the attribute directly
    on the class wouldn't survive __init__ overwriting it on the
    instance.
    """
    monkeypatch.setattr(
        "servonaut.services.ssh_service.Path.home", lambda: tmp_path,
    )
    target = tmp_path / ".ssh"
    target.mkdir()
    return target


@pytest.fixture
def config_manager() -> MagicMock:
    cm = MagicMock()
    config = MagicMock()
    config.instance_keys = {}
    config.default_key = ""
    cm.get.return_value = config
    return cm


def _mock_provider(get_secret_return=None, get_secret_side_effect=None) -> MagicMock:
    p = MagicMock()
    p.provider_name = "mock"
    # SecretProviderInterface methods are async — must be AsyncMock.
    if get_secret_side_effect is not None:
        p.get_secret = AsyncMock(side_effect=get_secret_side_effect)
    else:
        p.get_secret = AsyncMock(return_value=get_secret_return)
    return p


# ---------------------------------------------------------------------------
# 1. No provider: behaviour unchanged
# ---------------------------------------------------------------------------


class TestNoProvider:
    def test_no_provider_falls_through_to_ssh_dir(
        self, config_manager, ssh_dir, keys_dir,
    ):
        # Existing ~/.ssh discovery is the only resolver.
        (ssh_dir / "prod-server").write_text("not really a key")
        svc = SSHService(config_manager, secret_provider=None)
        result = run(svc.discover_key_async("prod-server"))
        assert result == str(ssh_dir / "prod-server")

    def test_no_provider_and_no_ssh_match_returns_none(
        self, config_manager, ssh_dir, keys_dir,
    ):
        svc = SSHService(config_manager, secret_provider=None)
        assert run(svc.discover_key_async("does-not-exist")) is None

    def test_default_constructor_omits_provider(self, config_manager):
        # Backward-compat: existing call sites that don't pass a
        # provider must still construct cleanly and behave as before.
        svc = SSHService(config_manager)
        assert svc._secret_provider is None


# ---------------------------------------------------------------------------
# 2. Provider has the key
# ---------------------------------------------------------------------------


class TestProviderProvidesKey:
    def test_writes_key_to_provider_dir_mode_0600(
        self, config_manager, ssh_dir, keys_dir,
    ):
        provider = _mock_provider(get_secret_return=SAMPLE_RSA_PRIVATE)
        svc = SSHService(config_manager, secret_provider=provider)
        result = run(svc.discover_key_async("prod-server"))
        assert result is not None
        path = Path(result)
        # Lives under the provider keys dir, not ~/.ssh.
        assert path.parent == keys_dir
        # Mode 0600 — secrets at rest.
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"
        # Content round-tripped intact.
        assert path.read_text() == SAMPLE_RSA_PRIVATE

    def test_dir_perms_tightened_to_0700(
        self, config_manager, ssh_dir, keys_dir,
    ):
        # Pre-create the dir with loose perms — should be tightened.
        keys_dir.mkdir()
        os.chmod(keys_dir, 0o755)
        provider = _mock_provider(get_secret_return=SAMPLE_RSA_PRIVATE)
        svc = SSHService(config_manager, secret_provider=provider)
        run(svc.discover_key_async("prod-server"))
        mode = stat.S_IMODE(keys_dir.stat().st_mode)
        assert mode == 0o700, f"expected 0700 on keys dir, got {oct(mode)}"

    def test_openssh_format_accepted(
        self, config_manager, ssh_dir, keys_dir,
    ):
        provider = _mock_provider(get_secret_return=SAMPLE_OPENSSH_PRIVATE)
        svc = SSHService(config_manager, secret_provider=provider)
        result = run(svc.discover_key_async("openssh-key"))
        assert result is not None

    def test_provider_path_overrides_ssh_dir_match(
        self, config_manager, ssh_dir, keys_dir,
    ):
        # Even when a same-named key exists in ~/.ssh, the provider
        # wins. The point of secrets management is centralised
        # truth; a stale local copy must not shadow it.
        (ssh_dir / "prod-server").write_text("stale local")
        provider = _mock_provider(get_secret_return=SAMPLE_RSA_PRIVATE)
        svc = SSHService(config_manager, secret_provider=provider)
        result = run(svc.discover_key_async("prod-server"))
        assert result is not None
        path = Path(result)
        assert path.parent == keys_dir  # not ssh_dir
        assert path.read_text() == SAMPLE_RSA_PRIVATE


# ---------------------------------------------------------------------------
# 3. Provider misses → fall through
# ---------------------------------------------------------------------------


class TestProviderMisses:
    def test_provider_returns_none_falls_through(
        self, config_manager, ssh_dir, keys_dir,
    ):
        (ssh_dir / "prod-server").write_text("local-key")
        provider = _mock_provider(get_secret_return=None)
        svc = SSHService(config_manager, secret_provider=provider)
        result = run(svc.discover_key_async("prod-server"))
        assert result == str(ssh_dir / "prod-server")

    def test_provider_returns_empty_string_falls_through(
        self, config_manager, ssh_dir, keys_dir,
    ):
        (ssh_dir / "prod-server").write_text("local-key")
        provider = _mock_provider(get_secret_return="")
        svc = SSHService(config_manager, secret_provider=provider)
        result = run(svc.discover_key_async("prod-server"))
        assert result == str(ssh_dir / "prod-server")

    def test_provider_returns_public_key_falls_through(
        self, config_manager, ssh_dir, keys_dir, caplog,
    ):
        # A public key is useless for outbound SSH. The provider
        # value must be a PRIVATE key blob; otherwise we fall back.
        (ssh_dir / "prod-server").write_text("local-key")
        provider = _mock_provider(
            get_secret_return="ssh-rsa AAAAB3Nz...== prod@server",
        )
        svc = SSHService(config_manager, secret_provider=provider)
        result = run(svc.discover_key_async("prod-server"))
        assert result == str(ssh_dir / "prod-server")
        # Nothing in the provider dir.
        if keys_dir.exists():
            assert list(keys_dir.iterdir()) == []

    def test_provider_returns_garbage_falls_through(
        self, config_manager, ssh_dir, keys_dir,
    ):
        (ssh_dir / "prod-server").write_text("local-key")
        provider = _mock_provider(get_secret_return="just some text, not a key")
        svc = SSHService(config_manager, secret_provider=provider)
        result = run(svc.discover_key_async("prod-server"))
        assert result == str(ssh_dir / "prod-server")


# ---------------------------------------------------------------------------
# 4. Provider raises → fall through (transient hiccup must not break SSH)
# ---------------------------------------------------------------------------


class TestProviderFailure:
    def test_provider_exception_falls_through(
        self, config_manager, ssh_dir, keys_dir,
    ):
        (ssh_dir / "prod-server").write_text("local-key")
        provider = _mock_provider(
            get_secret_side_effect=RuntimeError("BWS timed out"),
        )
        svc = SSHService(config_manager, secret_provider=provider)
        # Must NOT raise — a provider hiccup falls back to ~/.ssh.
        result = run(svc.discover_key_async("prod-server"))
        assert result == str(ssh_dir / "prod-server")

    def test_provider_exception_with_no_fallback_returns_none(
        self, config_manager, ssh_dir, keys_dir,
    ):
        # No ~/.ssh match either; result is None, not crash.
        provider = _mock_provider(
            get_secret_side_effect=RuntimeError("BWS timed out"),
        )
        svc = SSHService(config_manager, secret_provider=provider)
        assert run(svc.discover_key_async("nowhere")) is None


# ---------------------------------------------------------------------------
# 5. Filename sanitisation — path-traversal defence
# ---------------------------------------------------------------------------


class TestSanitiseKeyFilename:
    @pytest.mark.parametrize("bad_name,expected", [
        # Single-pass char substitution + leading-dot-and-dash strip.
        # The exact form is implementation-detail; what matters is
        # (a) only safe chars survive, (b) no leading dot or dash,
        # (c) the resulting filename can't escape the keys dir
        # — pinned by test_sanitised_name_lives_under_keys_dir below.
        ("../etc/passwd", "_etc_passwd"),
        ("..//../id_rsa", "_.._id_rsa"),
        ("prod/key", "prod_key"),
        ("prod\\key", "prod_key"),
        ("prod server with spaces", "prod_server_with_spaces"),
        ("évil-key", "_vil-key"),  # non-ASCII folded
        (".hidden", "hidden"),  # leading dot stripped
        ("---", None),  # all dashes → empty after lstrip → ValueError
        ("...", None),  # all dots → empty after lstrip → ValueError
        ("/", "_"),  # single bad char → substituted to "_", which is safe
    ])
    def test_sanitisation_examples(self, bad_name, expected):
        if expected is None:
            with pytest.raises(ValueError):
                SSHService._sanitise_key_filename(bad_name)
        else:
            out = SSHService._sanitise_key_filename(bad_name)
            assert out == expected, (
                f"sanitise({bad_name!r}) → {out!r}, expected {expected!r}"
            )

    def test_sanitisation_never_produces_dot_or_dash_prefix(self):
        # Whatever the input, the output must never start with `.` or `-`
        # (hidden files / argv-confusable). This is the durable invariant
        # — the exact transformation is implementation detail.
        for bad in [
            ".", "..", "...", "-foo", "-.bar", "..baz",
            "...//~~/x", ".-.", "--foo",
        ]:
            try:
                out = SSHService._sanitise_key_filename(bad)
            except ValueError:
                continue  # legitimate refusal — also fine
            assert not out.startswith("."), f"output {out!r} starts with dot"
            assert not out.startswith("-"), f"output {out!r} starts with dash"

    def test_empty_input_rejected(self):
        with pytest.raises(ValueError):
            SSHService._sanitise_key_filename("")

    def test_long_input_truncated(self):
        out = SSHService._sanitise_key_filename("a" * 500)
        assert len(out) <= 255

    def test_sanitised_name_lives_under_keys_dir(
        self, config_manager, ssh_dir, keys_dir,
    ):
        """A path-traversal-shaped key name must NOT escape the
        provider keys dir when written. This is the integration
        test for the regression — sanitisation in isolation isn't
        enough; the write must land where we expect."""
        provider = _mock_provider(get_secret_return=SAMPLE_RSA_PRIVATE)
        svc = SSHService(config_manager, secret_provider=provider)
        result = run(svc.discover_key_async("../../id_rsa"))
        assert result is not None
        path = Path(result)
        # Resolved path is genuinely under keys_dir, not anywhere else.
        resolved = path.resolve()
        expected_root = keys_dir.resolve()
        try:
            resolved.relative_to(expected_root)
        except ValueError:
            pytest.fail(
                f"provider key escaped {expected_root}: wrote to {resolved}"
            )


# ---------------------------------------------------------------------------
# 6. _looks_like_private_key shape check
# ---------------------------------------------------------------------------


class TestLooksLikePrivateKey:
    @pytest.mark.parametrize("good", [
        SAMPLE_RSA_PRIVATE,
        SAMPLE_OPENSSH_PRIVATE,
        "-----BEGIN EC PRIVATE KEY-----\nfoo\n-----END EC PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----\nfoo\n-----END PRIVATE KEY-----",  # PKCS#8
        "-----BEGIN DSA PRIVATE KEY-----\nfoo\n-----END DSA PRIVATE KEY-----",
    ])
    def test_accepts_private_keys(self, good):
        assert SSHService._looks_like_private_key(good) is True

    @pytest.mark.parametrize("bad", [
        "",
        "ssh-rsa AAAAB3Nz...",  # public key
        "ssh-ed25519 AAAA...",
        "random text not a key",
        "-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----",  # cert
        "-----BEGIN PUBLIC KEY-----\nfoo\n-----END PUBLIC KEY-----",
    ])
    def test_rejects_non_private_keys(self, bad):
        assert SSHService._looks_like_private_key(bad) is False
