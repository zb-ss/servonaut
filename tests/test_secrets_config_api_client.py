"""Tests for the Step 4 wire seam.

Covers the two paths the rest of the CLI will integrate against:

1. :meth:`APIClient.get_team_secrets_config` — production path
   against the live endpoint. Mocks at the httpx.AsyncClient layer
   so we test the contract translation (status code → typed
   exception, flat-envelope error parsing, 404 → None) without
   hitting the network.
2. :class:`FakeSecretsConfigClient` — in-memory stand-in. The shape
   contract is "callable signature identical to APIClient's method".

The 402 PaymentRequiredError properties (upgrade_url, doc_url,
required_tier) are pinned here because the chat-panel error toast
will surface ``upgrade_url`` directly — a future server-side rename
must trip these tests before it ships.

Team identifier is a slug string (matches the rest of
``/api/v1/teams/{slug}/*`` — confirmed server-side).
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.services.api_client import (
    APIClient,
    APIError,
    ForbiddenError,
    NotFoundError,
    PaymentRequiredError,
)
from servonaut.services.fake_secrets_config_client import FakeSecretsConfigClient


# Tests use this slug locally so the path the CLI sends matches
# the path the eventual joint E2E will hit against a seeded staging team.
TEST_TEAM_SLUG = "cli-integration-test-team"


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# httpx response helper
# ---------------------------------------------------------------------------


class _FakeResponse:
    """Minimum surface :class:`APIClient` calls on a response."""

    def __init__(
        self,
        status_code: int,
        body: Any = None,
        *,
        text: str = "",
        content_type: str = "application/json",
    ) -> None:
        self.status_code = status_code
        self._body = body
        self.text = text if text else (json.dumps(body) if body is not None else "")
        self.headers = {"content-type": content_type}

    def json(self) -> Any:
        if self._body is None:
            raise ValueError("no JSON body")
        return self._body


def _patch_httpx_with(response: _FakeResponse):
    """Patch ``httpx.AsyncClient`` so a single request returns ``response``."""
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.request = AsyncMock(return_value=response)
    return patch(
        "servonaut.services.api_client.httpx.AsyncClient",
        return_value=client,
    )


@pytest.fixture
def api_client() -> APIClient:
    auth = MagicMock()
    auth.access_token = "test-bearer-token"
    auth.refresh_token = AsyncMock(return_value=False)
    return APIClient(auth)


# ---------------------------------------------------------------------------
# APIClient.get_team_secrets_config — wire contract translation
# ---------------------------------------------------------------------------


class TestGetTeamSecretsConfig200:
    """The locked 200 shape: provider + config + updated_at.
    Returned as a parsed dict; caller passes it to
    ``AuthService.apply_secrets_config``."""

    def test_returns_parsed_payload_on_200(self, api_client):
        payload = {
            "provider": "bitwarden",
            "config": {
                "project_id": "11111111-2222-3333-4444-555555555555",
                "token_env_var": "BWS_ACCESS_TOKEN",
            },
            "updated_at": "2026-05-16T16:00:00Z",
        }
        with _patch_httpx_with(_FakeResponse(200, payload)):
            result = run(api_client.get_team_secrets_config(slug=TEST_TEAM_SLUG))
        assert result == payload

    def test_returns_local_provider_shape_when_team_uses_local(self, api_client):
        """A team admin can legitimately set provider=local — the
        endpoint still returns 200, NOT 404. Distinguishing this
        from "no row exists" is the whole point of the
        200-vs-404 split."""
        payload = {
            "provider": "local",
            "config": {},
            "updated_at": "2026-05-16T17:00:00Z",
        }
        with _patch_httpx_with(_FakeResponse(200, payload)):
            result = run(api_client.get_team_secrets_config(slug="another-team"))
        assert result == payload

    def test_url_path_uses_slug_not_id(self, api_client):
        """The endpoint is keyed on slug (confirmed server-side);
        pin that the path matches so a future refactor can't silently
        drift back to integer ids."""
        with _patch_httpx_with(_FakeResponse(200, {
            "provider": "local", "config": {}, "updated_at": "",
        })) as patched:
            run(api_client.get_team_secrets_config(slug="acme-corp"))
        call_args = patched.return_value.request.call_args
        url = call_args.args[1] if len(call_args.args) > 1 else call_args.kwargs["url"]
        assert "/teams/acme-corp/secrets-config" in url

    def test_strips_whitespace_from_slug(self, api_client):
        """Defensive: a caller threading the slug through a config
        file with trailing whitespace shouldn't end up calling
        ``/teams/acme%20/...``."""
        with _patch_httpx_with(_FakeResponse(200, {
            "provider": "local", "config": {}, "updated_at": "",
        })) as patched:
            run(api_client.get_team_secrets_config(slug="  acme  "))
        url = patched.return_value.request.call_args.args[1]
        assert "/teams/acme/secrets-config" in url
        assert "  " not in url

    def test_empty_slug_rejected_before_request(self, api_client):
        """An empty slug would hit a 404 against a non-existent route
        and obscure the real bug — fail loud at the call site
        instead."""
        with pytest.raises(ValueError, match="non-empty"):
            run(api_client.get_team_secrets_config(slug=""))
        with pytest.raises(ValueError, match="non-empty"):
            run(api_client.get_team_secrets_config(slug="   "))


class TestGetTeamSecretsConfig404:
    """404 → None (caller falls back to LocalProvider). Kickoff doc
    explicitly lists this as a non-exceptional path."""

    def test_404_with_envelope_returns_none(self, api_client):
        with _patch_httpx_with(_FakeResponse(
            404, {"error": {"code": "not_found", "message": "No config"}},
        )):
            result = run(api_client.get_team_secrets_config(slug=TEST_TEAM_SLUG))
        assert result is None

    def test_404_with_flat_envelope_returns_none(self, api_client):
        # New endpoint may emit the flat error shape on 404 too.
        with _patch_httpx_with(_FakeResponse(
            404, {"error": "not_found", "message": "No config"},
        )):
            result = run(api_client.get_team_secrets_config(slug=TEST_TEAM_SLUG))
        assert result is None


class TestGetTeamSecretsConfig402:
    """Free-tier user → 402 with upgrade_url. The exception MUST
    expose the URL via a property so the chat-panel toast can render
    a clickable upgrade link."""

    LOCKED_402_BODY = {
        "error": "payment_required",
        "message": "Secrets management requires a Solo or Teams subscription.",
        "required_tier": "solo",
        "upgrade_url": "https://servonaut.dev/pricing",
        "doc_url": "https://servonaut.dev/docs/secrets-management",
    }

    def test_402_raises_payment_required(self, api_client):
        with _patch_httpx_with(_FakeResponse(402, self.LOCKED_402_BODY)):
            with pytest.raises(PaymentRequiredError) as exc_info:
                run(api_client.get_team_secrets_config(slug=TEST_TEAM_SLUG))
        err = exc_info.value
        assert err.status == 402
        assert err.code == "payment_required"

    def test_402_exposes_upgrade_url(self, api_client):
        # The chat-panel uses this directly to render the upgrade
        # link. A server-side rename of upgrade_url MUST trip this
        # test before it ships.
        with _patch_httpx_with(_FakeResponse(402, self.LOCKED_402_BODY)):
            with pytest.raises(PaymentRequiredError) as exc_info:
                run(api_client.get_team_secrets_config(slug=TEST_TEAM_SLUG))
        err = exc_info.value
        assert err.upgrade_url == "https://servonaut.dev/pricing"
        assert err.doc_url == "https://servonaut.dev/docs/secrets-management"
        assert err.required_tier == "solo"

    def test_402_message_carries_human_copy(self, api_client):
        with _patch_httpx_with(_FakeResponse(402, self.LOCKED_402_BODY)):
            with pytest.raises(PaymentRequiredError) as exc_info:
                run(api_client.get_team_secrets_config(slug=TEST_TEAM_SLUG))
        # The message is what the user sees; pin the locked copy so
        # a docs-side rewrite goes through review before landing.
        assert "Solo" in exc_info.value.message
        assert "Teams" in exc_info.value.message


class TestGetTeamSecretsConfig403:
    """Not a team member (or unknown slug) → 403 with code=forbidden,
    distinct from forbidden_entitlement which is feature-gating.

    Note: the endpoint intentionally collapses
    'non-member' and 'unknown slug' into the same 403 to prevent
    slug enumeration through error-shape. CLI doesn't distinguish."""

    def test_403_raises_forbidden(self, api_client):
        body = {
            "error": "forbidden",
            "message": "You are not a member of this team.",
        }
        with _patch_httpx_with(_FakeResponse(403, body)):
            with pytest.raises(ForbiddenError) as exc_info:
                run(api_client.get_team_secrets_config(slug=TEST_TEAM_SLUG))
        err = exc_info.value
        assert err.status == 403
        assert err.code == "forbidden"
        assert "team" in err.message.lower()

    def test_403_distinguishes_from_forbidden_entitlement(self, api_client):
        """If the server returns code=forbidden_entitlement, we MUST
        raise the entitlement-specific class, not the generic
        ForbiddenError — different UX copy ("upgrade your plan" vs
        "you're not a team member")."""
        body = {
            "error": {
                "code": "forbidden_entitlement",
                "message": "Your plan does not include this feature.",
            },
        }
        with _patch_httpx_with(_FakeResponse(403, body)):
            with pytest.raises(APIError) as exc_info:
                run(api_client.get_team_secrets_config(slug=TEST_TEAM_SLUG))
        # Specifically the entitlement subclass, NOT the team-membership one.
        from servonaut.services.api_client import ForbiddenEntitlementError
        assert isinstance(exc_info.value, ForbiddenEntitlementError)


# ---------------------------------------------------------------------------
# _parse_error envelope shapes (nested + flat)
# ---------------------------------------------------------------------------


class TestParseErrorEnvelopes:
    """The nested + flat handling lives in :meth:`APIClient._parse_error`;
    pin both shapes so a future cleanup can't silently regress one."""

    def test_nested_envelope_preserved(self, api_client):
        resp = _FakeResponse(403, {
            "error": {
                "code": "forbidden_entitlement",
                "message": "nope",
                "details": {"plan": "free"},
            },
        })
        err = api_client._parse_error(resp)
        assert err.code == "forbidden_entitlement"
        assert err.message == "nope"
        assert err.details == {"plan": "free"}

    def test_flat_envelope_lifts_extras_into_details(self, api_client):
        resp = _FakeResponse(402, {
            "error": "payment_required",
            "message": "upgrade",
            "upgrade_url": "https://example.com/upgrade",
            "required_tier": "solo",
        })
        err = api_client._parse_error(resp)
        assert err.code == "payment_required"
        assert err.message == "upgrade"
        # Extras land in details so PaymentRequiredError properties
        # have a place to read from.
        assert err.details["upgrade_url"] == "https://example.com/upgrade"
        assert err.details["required_tier"] == "solo"
        # ``error`` and ``message`` themselves are NOT duplicated in details.
        assert "error" not in err.details
        assert "message" not in err.details


# ---------------------------------------------------------------------------
# FakeSecretsConfigClient
# ---------------------------------------------------------------------------


class TestFakeSecretsConfigClient:
    def test_returns_none_for_unconfigured_slug(self):
        fake = FakeSecretsConfigClient()
        assert run(fake.get_team_secrets_config(slug="anything")) is None

    def test_returns_configured_payload(self):
        fake = FakeSecretsConfigClient()
        payload = {
            "provider": "bitwarden",
            "config": {"project_id": "abc", "token_env_var": "BWS_ACCESS_TOKEN"},
            "updated_at": "2026-05-16T16:00:00Z",
        }
        fake.configure(slug=TEST_TEAM_SLUG, payload=payload)
        result = run(fake.get_team_secrets_config(slug=TEST_TEAM_SLUG))
        assert result == payload

    def test_defensive_copy_on_input(self):
        """Caller may mutate the dict they passed to configure AFTER
        the call; the fake's stored state must not follow along."""
        fake = FakeSecretsConfigClient()
        payload = {"provider": "bitwarden", "config": {}, "updated_at": ""}
        fake.configure(slug=TEST_TEAM_SLUG, payload=payload)
        payload["provider"] = "POISONED"
        payload["config"]["project_id"] = "POISONED"
        result = run(fake.get_team_secrets_config(slug=TEST_TEAM_SLUG))
        assert result["provider"] == "bitwarden"

    def test_defensive_copy_on_output(self):
        """Caller may mutate the result dict; subsequent calls must
        observe the original configured state."""
        fake = FakeSecretsConfigClient()
        fake.configure(slug=TEST_TEAM_SLUG, payload={
            "provider": "bitwarden", "config": {}, "updated_at": "",
        })
        result = run(fake.get_team_secrets_config(slug=TEST_TEAM_SLUG))
        result["provider"] = "POISONED"
        # Next call sees the original.
        result2 = run(fake.get_team_secrets_config(slug=TEST_TEAM_SLUG))
        assert result2["provider"] == "bitwarden"

    def test_configure_error_instance(self):
        fake = FakeSecretsConfigClient()
        boom = RuntimeError("scripted failure")
        fake.configure_error(slug=TEST_TEAM_SLUG, err=boom)
        with pytest.raises(RuntimeError, match="scripted failure"):
            run(fake.get_team_secrets_config(slug=TEST_TEAM_SLUG))

    def test_configure_error_factory(self):
        """Callable factory variant — useful when the test wants a
        fresh exception object on each call (e.g. distinct stack
        traces for "first call fails, second call fails differently")."""
        fake = FakeSecretsConfigClient()
        counter = {"n": 0}

        def factory() -> Exception:
            counter["n"] += 1
            return RuntimeError(f"attempt {counter['n']}")

        fake.configure_error(slug=TEST_TEAM_SLUG, err=factory)
        with pytest.raises(RuntimeError, match="attempt 1"):
            run(fake.get_team_secrets_config(slug=TEST_TEAM_SLUG))
        with pytest.raises(RuntimeError, match="attempt 2"):
            run(fake.get_team_secrets_config(slug=TEST_TEAM_SLUG))

    def test_payload_and_error_are_mutually_exclusive(self):
        fake = FakeSecretsConfigClient()
        fake.configure(slug=TEST_TEAM_SLUG, payload={
            "provider": "local", "config": {}, "updated_at": "",
        })
        # Switching to error mode for the same slug clears the payload.
        fake.configure_error(slug=TEST_TEAM_SLUG, err=ValueError("nope"))
        with pytest.raises(ValueError):
            run(fake.get_team_secrets_config(slug=TEST_TEAM_SLUG))

        # And switching back to a payload clears the error.
        fake.configure(slug=TEST_TEAM_SLUG, payload={
            "provider": "bitwarden", "config": {}, "updated_at": "",
        })
        result = run(fake.get_team_secrets_config(slug=TEST_TEAM_SLUG))
        assert result["provider"] == "bitwarden"

    def test_clear_one_slug(self):
        fake = FakeSecretsConfigClient()
        fake.configure(slug="team-a", payload={
            "provider": "bitwarden", "config": {}, "updated_at": "",
        })
        fake.configure(slug="team-b", payload={
            "provider": "local", "config": {}, "updated_at": "",
        })
        fake.clear(slug="team-a")
        assert run(fake.get_team_secrets_config(slug="team-a")) is None
        assert run(fake.get_team_secrets_config(slug="team-b")) is not None

    def test_clear_all_slugs(self):
        fake = FakeSecretsConfigClient()
        fake.configure(slug="team-a", payload={
            "provider": "bitwarden", "config": {}, "updated_at": "",
        })
        fake.clear()  # no slug → clear everything
        assert run(fake.get_team_secrets_config(slug="team-a")) is None

    def test_latency_injection(self):
        fake = FakeSecretsConfigClient()
        fake.set_latency(0.0)  # default — instant
        fake.configure(slug=TEST_TEAM_SLUG, payload={
            "provider": "local", "config": {}, "updated_at": "",
        })
        # Cheap call — completes synchronously inside one event-loop tick.
        run(fake.get_team_secrets_config(slug=TEST_TEAM_SLUG))

        # Inject a small delay; verify it actually delayed the call.
        fake.set_latency(0.02)
        import time
        start = time.monotonic()
        run(fake.get_team_secrets_config(slug=TEST_TEAM_SLUG))
        assert time.monotonic() - start >= 0.015

    def test_signature_matches_api_client(self, api_client):
        """The whole reason the fake exists is to be drop-in
        replaceable for APIClient.get_team_secrets_config. Pin the
        signature so a future change to one MUST break this test
        before landing."""
        import inspect
        sig_real = inspect.signature(api_client.get_team_secrets_config)
        fake = FakeSecretsConfigClient()
        sig_fake = inspect.signature(fake.get_team_secrets_config)
        # Both single positional/keyword arg ``slug``.
        assert list(sig_real.parameters.keys()) == list(sig_fake.parameters.keys())
        assert sig_real.return_annotation == sig_fake.return_annotation

    def test_empty_slug_rejected(self):
        fake = FakeSecretsConfigClient()
        with pytest.raises(ValueError):
            fake.configure(slug="", payload={})
        with pytest.raises(ValueError):
            run(fake.get_team_secrets_config(slug=""))

    def test_slug_whitespace_normalised(self):
        """Match :meth:`APIClient.get_team_secrets_config`'s strip so
        a test that configures `"acme"` and a call site that sends
        `" acme "` resolve to the same slot."""
        fake = FakeSecretsConfigClient()
        fake.configure(slug="acme", payload={
            "provider": "bitwarden", "config": {}, "updated_at": "",
        })
        result = run(fake.get_team_secrets_config(slug="  acme  "))
        assert result is not None
        assert result["provider"] == "bitwarden"
