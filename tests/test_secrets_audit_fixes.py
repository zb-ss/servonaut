"""Tests pinning the 8 audit fixes applied after a
"zero-tolerance" security review.

One test class per audit-fix item so a future regression points
directly back at the security concern it guards.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import SecretsConfig
from servonaut.services.api_client import APIClient
from servonaut.services.auth_service import (
    AuthService,
    AuthToken,
    SECRETS_PAYLOAD_MAX_BYTES,
)
from servonaut.services.bitwarden_provider import (
    BitwardenAPIError,
    BitwardenProvider,
    _redact_token_material,
)
from servonaut.services.interfaces import (
    SECRET_NAME_MAX_LENGTH,
    SECRET_VALUE_MAX_LENGTH,
    SecretProviderInterface,
    _validate_secret_name,
    _validate_secret_value,
)
from servonaut.services.secret_provider import (
    LOCAL_PROVIDER_ROOT,
    LocalProvider,
)


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def api_client() -> APIClient:
    auth = MagicMock()
    auth.access_token = "test-bearer-token"
    auth.refresh_token = AsyncMock(return_value=False)
    return APIClient(auth)


# ---------------------------------------------------------------------------
# Fix 1 — slug URL injection
# ---------------------------------------------------------------------------


class TestFix1SlugRegexValidation:
    """A malicious slug must not be interpolated into the URL path —
    ``../admin/users`` would be normalised by the path resolver into
    a wholly different endpoint."""

    @pytest.mark.parametrize("bad_slug", [
        "../admin",
        "team/../etc/passwd",
        "team..slug",
        "team with spaces",
        "team@email",
        "team\nlinefeed",
        "team%2Fpath",
        "team?query=1",
        "team#frag",
        "a" * 65,  # too long
    ])
    def test_rejects_url_injection_shapes(self, api_client, bad_slug):
        with pytest.raises(ValueError, match="slug must match"):
            run(api_client.get_team_secrets_config(slug=bad_slug))

    @pytest.mark.parametrize("good_slug", [
        "acme",
        "acme-corp",
        "acme_corp",
        "team-1",
        "a",  # one char fine
        "a" * 64,  # max length fine
    ])
    def test_accepts_locked_shape(self, good_slug):
        # Building a real APIClient here would need an httpx mock;
        # we just need the regex check itself to NOT raise for valid
        # shapes. Construct the client and exercise the validator
        # via the public method, mocking the network so we can
        # assert "got past the validation".
        auth = MagicMock()
        auth.access_token = "tok"
        auth.refresh_token = AsyncMock(return_value=False)
        client = APIClient(auth)

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.request = AsyncMock(return_value=MagicMock(
            status_code=200,
            json=lambda: {"provider": "local", "config": {}, "updated_at": ""},
            headers={"content-type": "application/json"},
        ))
        with patch(
            "servonaut.services.api_client.httpx.AsyncClient",
            return_value=mock_client,
        ):
            # Should not raise — fully validated.
            result = run(client.get_team_secrets_config(slug=good_slug))
            assert result is not None


# ---------------------------------------------------------------------------
# Fix 2 — provider allowlist
# ---------------------------------------------------------------------------


class TestFix2ProviderAllowlist:
    """SecretsConfig.from_wire MUST coerce unknown provider names to
    'local' so a malicious / buggy server cannot trick the CLI into
    instantiating an arbitrary string downstream."""

    def test_known_providers_pass_through(self):
        for provider in ["local", "bitwarden"]:
            cfg = SecretsConfig.from_wire({"provider": provider, "config": {}, "updated_at": ""})
            assert cfg.provider == provider

    def test_unknown_provider_coerces_to_local(self, caplog):
        cfg = SecretsConfig.from_wire({
            "provider": "vault",  # not in known set yet
            "config": {"any": "thing"},
            "updated_at": "",
        })
        assert cfg.provider == "local"
        # config is dropped because the LocalProvider doesn't use it
        # — wait, we DO retain config. We only reset the provider.
        # Re-read: the audit fix coerces provider, not config.
        # So config is kept as-is.
        assert cfg.config == {"any": "thing"}

    @pytest.mark.parametrize("malicious", [
        "../../shell",
        "$(rm -rf)",
        "; cat /etc/passwd",
        "local\nbitwarden",
        "",  # empty string falls through to default "local"
    ])
    def test_path_traversal_and_injection_strings_coerce_safely(self, malicious):
        cfg = SecretsConfig.from_wire({"provider": malicious, "config": {}, "updated_at": ""})
        assert cfg.provider == "local"


# ---------------------------------------------------------------------------
# Fix 3 — payload size cap
# ---------------------------------------------------------------------------


class TestFix3PayloadSizeCap:
    """``apply_secrets_config`` must refuse a payload larger than
    :data:`SECRETS_PAYLOAD_MAX_BYTES` so a pathological 100MB blob
    cannot fill the user's disk via auth.json."""

    def _seed_authed_service(self, tmp_path, monkeypatch) -> AuthService:
        auth_file = tmp_path / "auth.json"
        auth_file.write_text(json.dumps({
            "access_token": "A", "refresh_token": "R",
            "expires_at": time.time() + 3600, "plan": "teams",
            "entitlements": {}, "entitlements_fetched_at": 0,
        }))
        monkeypatch.setattr(
            "servonaut.services.auth_service.AUTH_FILE", auth_file
        )
        return AuthService()

    def test_normal_payload_within_cap_persists(self, tmp_path, monkeypatch):
        svc = self._seed_authed_service(tmp_path, monkeypatch)
        svc.apply_secrets_config({
            "provider": "bitwarden",
            "config": {"project_id": "abc", "token_env_var": "BWS_ACCESS_TOKEN"},
            "updated_at": "2026-05-16T16:00:00Z",
        })
        assert svc.is_secrets_cache_present()

    def test_oversize_payload_refused_silently(self, tmp_path, monkeypatch, caplog):
        svc = self._seed_authed_service(tmp_path, monkeypatch)
        # Build a payload that JSON-serialises >SECRETS_PAYLOAD_MAX_BYTES.
        big_value = "x" * (SECRETS_PAYLOAD_MAX_BYTES + 100)
        svc.apply_secrets_config({
            "provider": "bitwarden",
            "config": {"big": big_value},
            "updated_at": "",
        })
        # Cache stayed empty — the bad write was refused.
        assert not svc.is_secrets_cache_present()
        assert svc._token.secrets_config == {}

    def test_non_serialisable_payload_refused(self, tmp_path, monkeypatch):
        svc = self._seed_authed_service(tmp_path, monkeypatch)

        # An object json.dumps can't handle. Won't make it to disk.
        class _Bogus:
            pass

        svc.apply_secrets_config({
            "provider": "bitwarden",
            "config": {"bad": _Bogus()},
            "updated_at": "",
        })
        assert not svc.is_secrets_cache_present()


# ---------------------------------------------------------------------------
# Fix 4 — token redaction in BitwardenAPIError
# ---------------------------------------------------------------------------


class TestFix4TokenRedaction:
    """BitwardenAPIError's message + stderr must never contain
    token-shaped material. /proc/<pid>/cmdline is one exposure; log
    leakage via str(exc) is another."""

    def test_redacts_generic_access_token_fragment(self):
        out = _redact_token_material("access_token=verysecretvalue123")
        assert "verysecretvalue123" not in out
        assert "<redacted>" in out
        # Prefix retained so an operator can SEE that a token was scrubbed.
        assert "access_token=" in out

    def test_redacts_bws_shaped_token(self):
        # The classic BWS access token shape: 0.<base64>.<base64>
        token = "0.aZ9bC8dE7fG6hI5jK4lM3nO2pQ1rS-tU_vW=xY"
        out = _redact_token_material(f"bws error: {token} not valid")
        assert token not in out

    def test_redacts_explicit_literal(self):
        secret = "abcDEF12345xyz"
        out = _redact_token_material(
            f"some message containing {secret} verbatim",
            extra_literals=[secret],
        )
        assert secret not in out

    def test_error_construction_redacts_message_and_stderr(self):
        err = BitwardenAPIError(
            "subprocess failed: access_token=leaktastic returned 401",
            stderr="bws debug: token=anotherleak revealed",
            token_literal="my-secret-token-value",
        )
        assert "leaktastic" not in str(err)
        assert "anotherleak" not in err.stderr
        # The explicit literal is also scrubbed.
        msg = BitwardenAPIError(
            "context with my-secret-token-value inside",
            token_literal="my-secret-token-value",
        )
        assert "my-secret-token-value" not in str(msg)

    def test_redaction_never_raises_on_weird_input(self):
        # Defensive: redactor should never crash on weird input even
        # if the regex misbehaves on some unicode edge case.
        for weird in ["", "no token here", "\x00\x01\x02", "a" * 100000]:
            # Just must not raise.
            assert isinstance(_redact_token_material(weird), str)


# ---------------------------------------------------------------------------
# Fix 5 — name/value length caps
# ---------------------------------------------------------------------------


class TestFix5NameValueCaps:
    """Reject overlong secret names + values BEFORE any backend
    call. Prevents a buggy caller from polluting auth.json or a
    BWS project with massive entries."""

    def test_name_too_long_rejected(self):
        with pytest.raises(ValueError, match="≤"):
            _validate_secret_name("a" * (SECRET_NAME_MAX_LENGTH + 1))

    def test_value_too_long_rejected(self):
        with pytest.raises(ValueError, match="≤"):
            _validate_secret_value("x" * (SECRET_VALUE_MAX_LENGTH + 1))

    def test_name_empty_rejected(self):
        with pytest.raises(ValueError, match="non-empty"):
            _validate_secret_name("")

    def test_value_empty_allowed(self):
        # Empty VALUE is a legitimate "explicitly cleared" state.
        assert _validate_secret_value("") == ""

    def test_non_string_name_rejected(self):
        with pytest.raises(TypeError):
            _validate_secret_name(123)  # type: ignore[arg-type]

    def test_non_string_value_rejected(self):
        with pytest.raises(TypeError):
            _validate_secret_value(123)  # type: ignore[arg-type]

    def test_local_provider_enforces_caps(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "servonaut.services.secret_provider.LOCAL_PROVIDER_ROOT",
            tmp_path,
        )
        provider = LocalProvider(secrets_file=tmp_path / "secrets.json")
        with pytest.raises(ValueError, match="≤"):
            run(provider.set_secret("ok-name", "v" * (SECRET_VALUE_MAX_LENGTH + 1)))
        with pytest.raises(ValueError, match="≤"):
            run(provider.set_secret("x" * (SECRET_NAME_MAX_LENGTH + 1), "v"))

    def test_bitwarden_provider_enforces_caps(self, monkeypatch):
        monkeypatch.setenv("BWS_ACCESS_TOKEN", "tok")
        provider = BitwardenProvider(
            project_id="00000000-0000-0000-0000-000000000001",
            bws_path="/usr/bin/fake-bws",
        )
        # No bws invocation should happen for a rejected input.
        with patch(
            "servonaut.services.bitwarden_provider.asyncio.create_subprocess_exec",
            side_effect=AssertionError("must not exec bws for invalid input"),
        ):
            with pytest.raises(ValueError, match="≤"):
                run(provider.set_secret("x" * (SECRET_NAME_MAX_LENGTH + 1), "v"))


# ---------------------------------------------------------------------------
# Fix 6 — LocalProvider path guard
# ---------------------------------------------------------------------------


class TestFix6PathGuard:
    """A misconfigured ``secrets_file`` MUST NOT silently overwrite
    arbitrary files in the user's home dir."""

    def test_path_under_root_accepted(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "servonaut.services.secret_provider.LOCAL_PROVIDER_ROOT",
            tmp_path,
        )
        # No raise.
        LocalProvider(secrets_file=tmp_path / "subdir" / "secrets.json")

    def test_path_outside_root_rejected(self, tmp_path, monkeypatch):
        # Pin the root somewhere specific then try to write elsewhere.
        monkeypatch.setattr(
            "servonaut.services.secret_provider.LOCAL_PROVIDER_ROOT",
            tmp_path / "safe-zone",
        )
        with pytest.raises(ValueError, match="must be under"):
            LocalProvider(secrets_file=tmp_path / "elsewhere" / "secrets.json")

    def test_traversal_via_dot_dot_rejected(self, tmp_path, monkeypatch):
        # Even a "..-escaped" path that LOOKS like it points at safe-zone
        # must resolve and get rejected.
        monkeypatch.setattr(
            "servonaut.services.secret_provider.LOCAL_PROVIDER_ROOT",
            tmp_path / "safe-zone",
        )
        # tmp_path/safe-zone/../elsewhere resolves to tmp_path/elsewhere
        bad_path = tmp_path / "safe-zone" / ".." / "elsewhere" / "secrets.json"
        with pytest.raises(ValueError, match="must be under"):
            LocalProvider(secrets_file=bad_path)


# ---------------------------------------------------------------------------
# Fix 7 — MCP boundary sentinel
# ---------------------------------------------------------------------------


class TestFix7McpBoundarySentinel:
    """A machine-readable marker the future MCP registry inspects to
    refuse any tool whose IO ultimately resolves to a
    :class:`SecretProviderInterface`."""

    def test_marker_present_on_interface(self):
        assert hasattr(SecretProviderInterface, "_servonaut_secret_boundary")
        assert SecretProviderInterface._servonaut_secret_boundary is True

    def test_marker_inherited_by_concrete_providers(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "servonaut.services.secret_provider.LOCAL_PROVIDER_ROOT",
            tmp_path,
        )
        provider = LocalProvider(secrets_file=tmp_path / "secrets.json")
        # Subclasses inherit the marker so the MCP registry can ALSO
        # see it on the concrete instance, not just the ABC.
        assert provider._servonaut_secret_boundary is True


# ---------------------------------------------------------------------------
# Fix 8 — last-write-wins documented (string-level test for the docstring
#                                     so a future cleanup can't silently
#                                     remove the warning)
# ---------------------------------------------------------------------------


class TestFix8RaceDocumented:
    def test_local_provider_docstring_mentions_last_write_wins(self):
        # Pin the documented contract so a future cleanup that drops
        # this warning trips a regression.
        assert "last-write-wins" in (LocalProvider.__doc__ or "").lower()

    def test_local_provider_docstring_points_at_bitwarden_alternative(self):
        # If you genuinely need concurrent writes, the docstring
        # MUST direct you at BitwardenProvider.
        doc = LocalProvider.__doc__ or ""
        assert "BitwardenProvider" in doc
