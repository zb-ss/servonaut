"""Unit tests for services/memory/ai_summary_service.py.

Covers:
- get_provider_info: happy path, entitlement gate, API error translation
- confirm_provider_disclosure_shown: state tracking
- request_consent_token: without disclosure (ConsentNotConfirmedError), with
  disclosure (ConsentToken returned), rate limiter acquired, entitlement gate
- dispatch_summary: happy path (202), rate limiter acquired, entitlement gate
- get_latest_summary: 200 returns dict, 404 returns None, entitlement gate
- API error mapping: forbidden_entitlement, feature_not_available,
  feature_disabled, validation_failed
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.memory.ai_summary_service import (
    AISummaryService,
    ConsentNotConfirmedError,
    ConsentToken,
    ProviderInfo,
    SummaryDispatchResult,
)
from servonaut.services.memory.interfaces import (
    BackendMaintenance,
    BetaWaitlist,
    MemoryBackendError,
    UpsellRequired,
    ValidationFailed,
)
from servonaut.services.memory.rate_limiter import RateLimitKey, RateLimiter
from servonaut.services.api_client import (
    ForbiddenEntitlementError,
    FeatureNotAvailableError,
    FeatureDisabledError,
    ValidationFailedError,
    NotFoundError,
)


def run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_api():
    api = MagicMock()
    api.get = AsyncMock()
    api.post = AsyncMock()
    return api


@pytest.fixture
def mock_rate_limiter():
    rl = MagicMock(spec=RateLimiter)
    rl.acquire = AsyncMock()
    return rl


@pytest.fixture
def mock_auth():
    auth = MagicMock()
    auth.has_feature = MagicMock(return_value=True)
    return auth


@pytest.fixture
def mock_config():
    return MagicMock()


@pytest.fixture
def service(mock_api, mock_rate_limiter, mock_auth, mock_config):
    return AISummaryService(
        api_client=mock_api,
        rate_limiter=mock_rate_limiter,
        auth_service=mock_auth,
        config_manager=mock_config,
    )


@pytest.fixture
def service_no_entitlement(mock_api, mock_rate_limiter, mock_config):
    auth = MagicMock()
    auth.has_feature = MagicMock(return_value=False)
    return AISummaryService(
        api_client=mock_api,
        rate_limiter=mock_rate_limiter,
        auth_service=auth,
        config_manager=mock_config,
    )


_PROVIDER_RESPONSE = {
    "provider_name": "Anthropic",
    "retention_days": 30,
    "retention_text": "Data is retained for 30 days for safety monitoring.",
    "supports_zdr": False,
}

_CONSENT_RESPONSE = {
    "token": "jwt.consent.token",
    "expires_at": "2026-04-25T14:00:00+00:00",
    "mode": "server_60s",
    "modules": ["os", "services"],
}

_DISPATCH_RESPONSE = {
    "status": "queued",
    "previous_summary_id": "old-envelope",
    "queued_at": "2026-08-27T13:00:00Z",
    "poll_after_seconds": 3,
    "message": "Summary dispatched; fetch /api/v1/memory/summary/{instance_id}/latest when ready",
}


# ---------------------------------------------------------------------------
# get_provider_info
# ---------------------------------------------------------------------------

class TestGetProviderInfo:
    def test_happy_path(self, service, mock_api):
        mock_api.get.return_value = _PROVIDER_RESPONSE.copy()
        result = run(service.get_provider_info())

        assert isinstance(result, ProviderInfo)
        assert result.provider_name == "Anthropic"
        assert result.retention_days == 30
        assert result.retention_text == "Data is retained for 30 days for safety monitoring."
        assert result.supports_zdr is False
        mock_api.get.assert_called_once_with("/api/v1/memory/ai-provider-info")

    def test_entitlement_gate_raises_upsell(self, service_no_entitlement):
        with pytest.raises(UpsellRequired) as exc_info:
            run(service_no_entitlement.get_provider_info())
        assert exc_info.value.plan == "memory_ai_summary"

    def test_forbidden_entitlement_from_api(self, service, mock_api):
        mock_api.get.side_effect = ForbiddenEntitlementError(
            code="forbidden_entitlement", message="no", status=403
        )
        with pytest.raises(UpsellRequired):
            run(service.get_provider_info())

    def test_feature_not_available(self, service, mock_api):
        mock_api.get.side_effect = FeatureNotAvailableError(
            code="feature_not_available", message="beta", status=403
        )
        with pytest.raises(BetaWaitlist):
            run(service.get_provider_info())

    def test_feature_disabled(self, service, mock_api):
        mock_api.get.side_effect = FeatureDisabledError(
            code="feature_disabled", message="maint", status=503
        )
        with pytest.raises(BackendMaintenance):
            run(service.get_provider_info())

    def test_supports_zdr_defaults_false(self, service, mock_api):
        response = dict(_PROVIDER_RESPONSE)
        del response["supports_zdr"]
        mock_api.get.return_value = response
        result = run(service.get_provider_info())
        assert result.supports_zdr is False


# ---------------------------------------------------------------------------
# confirm_provider_disclosure_shown
# ---------------------------------------------------------------------------

class TestConfirmDisclosure:
    def test_marks_instance_confirmed(self, service):
        assert "i-123" not in service._disclosure_confirmed
        service.confirm_provider_disclosure_shown("i-123")
        assert "i-123" in service._disclosure_confirmed

    def test_multiple_instances_independent(self, service):
        service.confirm_provider_disclosure_shown("i-abc")
        service.confirm_provider_disclosure_shown("i-def")
        assert "i-abc" in service._disclosure_confirmed
        assert "i-def" in service._disclosure_confirmed

    def test_repeated_call_is_idempotent(self, service):
        service.confirm_provider_disclosure_shown("i-123")
        service.confirm_provider_disclosure_shown("i-123")
        assert "i-123" in service._disclosure_confirmed


# ---------------------------------------------------------------------------
# request_consent_token
# ---------------------------------------------------------------------------

class TestRequestConsentToken:
    def test_raises_consent_not_confirmed_without_disclosure(self, service, mock_api):
        with pytest.raises(ConsentNotConfirmedError) as exc_info:
            run(service.request_consent_token("i-123", "server_60s"))
        assert exc_info.value.instance_id == "i-123"
        mock_api.post.assert_not_called()

    def test_raises_after_wrong_instance_disclosed(self, service, mock_api):
        service.confirm_provider_disclosure_shown("i-other")
        with pytest.raises(ConsentNotConfirmedError):
            run(service.request_consent_token("i-123", "server_60s"))

    def test_happy_path(self, service, mock_api, mock_rate_limiter):
        service.confirm_provider_disclosure_shown("i-123")
        mock_api.post.return_value = _CONSENT_RESPONSE.copy()

        result = run(service.request_consent_token("i-123", "server_60s", ["os"]))

        assert isinstance(result, ConsentToken)
        assert result.token == "jwt.consent.token"
        assert result.mode == "server_60s"
        assert result.modules == ["os", "services"]
        mock_rate_limiter.acquire.assert_called_once_with(RateLimitKey.SUMMARY)
        mock_api.post.assert_called_once_with(
            "/api/v1/memory/summary/i-123/consent",
            json={
                "mode": "server_60s",
                "provider_ack": True,
                "modules": ["os"],
            },
        )

    def test_modules_none_not_included_in_body(self, service, mock_api, mock_rate_limiter):
        service.confirm_provider_disclosure_shown("i-123")
        mock_api.post.return_value = _CONSENT_RESPONSE.copy()
        run(service.request_consent_token("i-123", "server_60s"))

        call_kwargs = mock_api.post.call_args.kwargs
        assert "modules" not in call_kwargs["json"]

    def test_rate_limiter_acquired_before_api_call(self, service, mock_api, mock_rate_limiter):
        """Rate limiter must be called before the POST."""
        call_order = []
        mock_rate_limiter.acquire.side_effect = lambda k: (call_order.append("limiter") or asyncio.coroutine(lambda: None)())
        async def post_side_effect(*a, **kw):
            call_order.append("api")
            return _CONSENT_RESPONSE.copy()
        mock_api.post.side_effect = post_side_effect

        service.confirm_provider_disclosure_shown("i-123")
        # patch acquire to be a proper coroutine
        mock_rate_limiter.acquire = AsyncMock(side_effect=lambda k: call_order.append("limiter"))
        mock_api.post = AsyncMock(side_effect=post_side_effect)

        run(service.request_consent_token("i-123", "server_60s"))
        assert call_order == ["limiter", "api"]

    def test_entitlement_gate_raises(self, service_no_entitlement):
        service_no_entitlement.confirm_provider_disclosure_shown("i-123")
        with pytest.raises(UpsellRequired):
            run(service_no_entitlement.request_consent_token("i-123", "server_60s"))

    def test_validation_failed(self, service, mock_api, mock_rate_limiter):
        service.confirm_provider_disclosure_shown("i-123")
        mock_api.post.side_effect = ValidationFailedError(
            code="validation_failed", message="bad", status=422,
            details={"errors": [{"key": "mode", "error": "unknown"}]},
        )
        with pytest.raises(ValidationFailed) as exc_info:
            run(service.request_consent_token("i-123", "server_60s"))
        assert exc_info.value.errors == [{"key": "mode", "error": "unknown"}]

    def test_expires_at_parsed(self, service, mock_api, mock_rate_limiter):
        service.confirm_provider_disclosure_shown("i-123")
        mock_api.post.return_value = {
            "token": "tok",
            "expires_at": "2026-04-25T14:00:00+00:00",
            "mode": "server_60s",
            "modules": [],
        }
        result = run(service.request_consent_token("i-123", "server_60s"))
        assert result.expires_at.year == 2026


# ---------------------------------------------------------------------------
# dispatch_summary
# ---------------------------------------------------------------------------

class TestDispatchSummary:
    def test_happy_path(self, service, mock_api, mock_rate_limiter):
        mock_api.post.return_value = _DISPATCH_RESPONSE.copy()
        service.confirm_provider_disclosure_shown("i-123")

        result = run(
            service.dispatch_summary(
                "i-123",
                "jwt.consent.token",
                "server_60s",
                passphrase="my-passphrase-123!",
            )
        )

        assert isinstance(result, SummaryDispatchResult)
        assert result.status == "queued"
        assert result.previous_summary_id == "old-envelope"
        assert result.queued_at == "2026-08-27T13:00:00Z"
        assert result.poll_after_seconds == 3.0
        assert result.correlation_supported is True
        mock_rate_limiter.acquire.assert_called_once_with(RateLimitKey.SUMMARY)
        mock_api.post.assert_called_once_with(
            "/api/v1/memory/summary/i-123",
            json={
                "consent_token": "jwt.consent.token",
                "mode": "server_60s",
                "passphrase": "my-passphrase-123!",
            },
            retry_on_401=False,
        )

    def test_dispatch_without_disclosure_raises(self, service, mock_api):
        with pytest.raises(ConsentNotConfirmedError):
            run(service.dispatch_summary("i-123", "tok", "server_60s", passphrase="pass"))
        mock_api.post.assert_not_called()

    def test_entitlement_gate(self, service_no_entitlement):
        with pytest.raises(UpsellRequired):
            run(service_no_entitlement.dispatch_summary("i-123", "tok", "server_60s", passphrase="pass"))

    def test_rate_limiter_acquired(self, service, mock_api, mock_rate_limiter):
        mock_api.post.return_value = _DISPATCH_RESPONSE.copy()
        service.confirm_provider_disclosure_shown("i-123")
        run(service.dispatch_summary("i-123", "tok", "server_60s", passphrase="pass"))
        mock_rate_limiter.acquire.assert_called_once_with(RateLimitKey.SUMMARY)

    def test_backend_maintenance(self, service, mock_api, mock_rate_limiter):
        mock_api.post.side_effect = FeatureDisabledError(
            code="feature_disabled", message="maint", status=503
        )
        service.confirm_provider_disclosure_shown("i-123")
        with pytest.raises(BackendMaintenance):
            run(service.dispatch_summary("i-123", "tok", "server_60s", passphrase="pass"))

    def test_message_field_defaults_empty(self, service, mock_api, mock_rate_limiter):
        mock_api.post.return_value = {"status": "queued"}
        service.confirm_provider_disclosure_shown("i-123")
        result = run(service.dispatch_summary("i-123", "tok", "server_60s", passphrase="pass"))
        assert result.message == ""

        assert result.correlation_supported is False


# ---------------------------------------------------------------------------
# get_latest_summary
# ---------------------------------------------------------------------------

class TestGetLatestSummary:
    def test_returns_dict_on_success(self, service, mock_api):
        envelope = {"id": "env-uuid", "module": "ai_summary", "ciphertext": "abc"}
        mock_api.get.return_value = envelope

        result = run(service.get_latest_summary("i-123"))
        assert result == envelope
        mock_api.get.assert_called_once_with(
            "/api/v1/memory/summary/i-123/latest"
        )

    def test_returns_pending_status_for_correlated_lookup(self, service, mock_api):
        pending = {
            "status": "pending",
            "previous_summary_id": "old-envelope",
            "poll_after_seconds": 2,
        }
        mock_api.get.return_value = pending

        result = run(service.get_latest_summary("i-123", after="old-envelope"))
        assert result == pending
        mock_api.get.assert_called_once_with(
            "/api/v1/memory/summary/i-123/latest",
            params={"after": "old-envelope"},
        )

    def test_returns_none_on_404(self, service, mock_api):
        mock_api.get.side_effect = NotFoundError(
            code="not_found", message="no summary", status=404
        )
        result = run(service.get_latest_summary("i-123"))
        assert result is None

    def test_entitlement_gate(self, service_no_entitlement):
        with pytest.raises(UpsellRequired):
            run(service_no_entitlement.get_latest_summary("i-123"))

    def test_feature_disabled_propagates(self, service, mock_api):
        mock_api.get.side_effect = FeatureDisabledError(
            code="feature_disabled", message="maint", status=503
        )
        with pytest.raises(BackendMaintenance):
            run(service.get_latest_summary("i-123"))

    def test_wait_for_new_summary_ignores_previous_envelope(
        self,
        service,
        mock_api,
        mock_config,
    ):
        mock_config.get.return_value = SimpleNamespace(
            memory=SimpleNamespace(
                ai_summary_poll_interval_seconds=0.1,
                ai_summary_poll_timeout_seconds=0.35,
            )
        )
        pending = {
            "status": "pending",
            "previous_summary_id": "old-envelope",
            "poll_after_seconds": 0.1,
        }
        new_envelope = {"id": "new-envelope", "module": "ai_summary"}
        mock_api.get.side_effect = [
            pending,
            pending,
            new_envelope,
        ]

        result = run(
            service.wait_for_new_summary(
                "i-123",
                previous_envelope_id="old-envelope",
            )
        )

        assert result == new_envelope
        assert mock_api.get.await_count == 3
        assert all(
            awaited.kwargs == {"params": {"after": "old-envelope"}}
            for awaited in mock_api.get.await_args_list
        )

    def test_wait_for_new_summary_returns_none_on_configured_timeout(
        self,
        service,
        mock_api,
        mock_config,
    ):
        mock_config.get.return_value = SimpleNamespace(
            memory=SimpleNamespace(
                ai_summary_poll_interval_seconds=0.1,
                ai_summary_poll_timeout_seconds=0.11,
            )
        )
        mock_api.get.return_value = {
            "status": "pending",
            "previous_summary_id": "old-envelope",
            "poll_after_seconds": 0.1,
        }

        result = run(
            service.wait_for_new_summary(
                "i-123",
                previous_envelope_id="old-envelope",
            )
        )

        assert result is None
        assert mock_api.get.await_count >= 1

    def test_wait_for_new_summary_rejects_missing_stable_id(
        self,
        service,
        mock_api,
        mock_config,
    ):
        mock_config.get.return_value = SimpleNamespace(
            memory=SimpleNamespace(
                ai_summary_poll_interval_seconds=0.1,
                ai_summary_poll_timeout_seconds=0.1,
            )
        )
        mock_api.get.return_value = {"module": "ai_summary"}

        with pytest.raises(
            MemoryBackendError,
            match="no stable envelope id",
        ):
            run(service.wait_for_new_summary("i-123"))


# ---------------------------------------------------------------------------
# Envelope keys (B9): body forms, run_summary order, failed status
# ---------------------------------------------------------------------------

from servonaut.services.memory.ai_summary_service import (  # noqa: E402
    HostedSummaryUnavailable,
    SummaryFailed,
    summary_error_message,
)
from servonaut.services.memory.retrieval_service import StaleEnvelopes  # noqa: E402

_KEYS = [{"envelope_id": "env-os", "dek": "QUJD"}]
_IDS_CONSENT = {**_CONSENT_RESPONSE, "envelope_ids": {"os": "env-os"}}
_CONSENT_ARGS = ("jwt.consent.token", "server_60s")


def _api_error(cls, code, status, details=None):
    return cls(code=code, message="service wording", status=status, details=details)


def _retrieval(keys=None, side_effect=None):
    retrieval = MagicMock()
    retrieval.envelope_keys = AsyncMock(
        return_value=list(keys if keys is not None else _KEYS), side_effect=side_effect)
    return retrieval


def _run_summary(service, retrieval, *, source="vault", passphrase_provider=None):
    return run(service.run_summary(
        "i-123",
        retrieval=retrieval,
        key_source=lambda: source,
        passphrase_provider=passphrase_provider or AsyncMock(return_value="pw-placeholder"),
    ))


@pytest.fixture
def disclosed(service):
    service.confirm_provider_disclosure_shown("i-123")
    return service


class TestDispatchBodies:
    def test_keys_form_sends_envelope_keys_and_no_passphrase(self, disclosed, mock_api):
        mock_api.post.return_value = _DISPATCH_RESPONSE.copy()
        run(disclosed.dispatch_summary("i-123", "tok", "server_60s", envelope_keys=_KEYS))
        body = mock_api.post.call_args.kwargs["json"]
        assert body == {"consent_token": "tok", "mode": "server_60s", "envelope_keys": _KEYS}
        assert mock_api.post.call_args.kwargs["retry_on_401"] is False

    def test_passphrase_form_never_retries_on_401(self, disclosed, mock_api):
        mock_api.post.return_value = _DISPATCH_RESPONSE.copy()
        run(disclosed.dispatch_summary("i-123", "tok", "server_60s", passphrase="pw"))
        assert mock_api.post.call_args.kwargs["retry_on_401"] is False
        assert "envelope_keys" not in mock_api.post.call_args.kwargs["json"]

    @pytest.mark.parametrize("kwargs", [{}, {"envelope_keys": _KEYS, "passphrase": "pw"}])
    def test_exactly_one_form(self, disclosed, mock_api, kwargs):
        with pytest.raises(ValueError):
            run(disclosed.dispatch_summary("i-123", "tok", "server_60s", **kwargs))
        mock_api.post.assert_not_called()

    def test_consent_parses_envelope_ids(self, disclosed, mock_api):
        mock_api.post.return_value = dict(_IDS_CONSENT)
        consent = run(disclosed.request_consent_token("i-123", "server_60s"))
        assert consent.envelope_ids == {"os": "env-os"}

    def test_older_service_has_no_envelope_ids(self, disclosed, mock_api):
        mock_api.post.return_value = dict(_CONSENT_RESPONSE)
        assert run(disclosed.request_consent_token("i-123", "server_60s")).envelope_ids == {}


class TestRunSummary:
    def _consents(self, mock_api, *answers):
        """Queue consent and dispatch answers in the order the calls happen."""
        mock_api.post.side_effect = list(answers)

    def test_vault_account_sends_keys_and_never_asks_for_a_passphrase(self, disclosed, mock_api):
        self._consents(mock_api, dict(_IDS_CONSENT), _DISPATCH_RESPONSE.copy())
        provider = AsyncMock()
        retrieval = _retrieval()
        result = _run_summary(disclosed, retrieval, source="vault", passphrase_provider=provider)
        assert result.status == "queued"
        provider.assert_not_awaited()
        retrieval.envelope_keys.assert_awaited_once_with("i-123", {"os": "env-os"})
        dispatch_body = mock_api.post.call_args_list[1].kwargs["json"]
        assert "passphrase" not in dispatch_body and "envelope_keys" in dispatch_body

    def test_passphrase_account_also_uses_keys(self, disclosed, mock_api):
        self._consents(mock_api, dict(_IDS_CONSENT), _DISPATCH_RESPONSE.copy())
        provider = AsyncMock()
        _run_summary(disclosed, _retrieval(), source="passphrase", passphrase_provider=provider)
        provider.assert_not_awaited()

    def test_stale_409_is_retried_once_with_a_fresh_consent(self, disclosed, mock_api):
        stale = _api_error(APIErrorClass, "stale_envelopes", 409)
        self._consents(mock_api, dict(_IDS_CONSENT), stale, dict(_IDS_CONSENT), _DISPATCH_RESPONSE.copy())
        result = _run_summary(disclosed, _retrieval())
        assert result.status == "queued"
        assert mock_api.post.await_count == 4

    def test_stale_while_building_keys_is_retried_once(self, disclosed, mock_api):
        self._consents(mock_api, dict(_IDS_CONSENT), dict(_IDS_CONSENT), _DISPATCH_RESPONSE.copy())
        retrieval = MagicMock()
        retrieval.envelope_keys = AsyncMock(side_effect=[StaleEnvelopes(), list(_KEYS)])
        assert _run_summary(disclosed, retrieval).status == "queued"
        assert retrieval.envelope_keys.await_count == 2

    def test_second_stale_is_raised_with_its_text(self, disclosed, mock_api):
        stale = _api_error(APIErrorClass, "stale_envelopes", 409)
        self._consents(mock_api, dict(_IDS_CONSENT), stale, dict(_IDS_CONSENT), stale)
        with pytest.raises(StaleEnvelopes) as caught:
            _run_summary(disclosed, _retrieval())
        assert summary_error_message(caught.value) == (
            "Memory changed while the summary was being prepared. Try again.")
        assert mock_api.post.await_count == 4

    def test_503_falls_back_to_passphrase_for_passphrase_custody(self, disclosed, mock_api):
        off = _api_error(FeatureDisabledError, "feature_disabled", 503)
        self._consents(mock_api, dict(_IDS_CONSENT), off, _DISPATCH_RESPONSE.copy())
        provider = AsyncMock(return_value="pw-placeholder")
        _run_summary(disclosed, _retrieval(), source="passphrase", passphrase_provider=provider)
        provider.assert_awaited_once()
        assert mock_api.post.call_args_list[2].kwargs["json"]["passphrase"] == "pw-placeholder"

    def test_503_for_a_vault_key_never_falls_back(self, disclosed, mock_api):
        off = _api_error(FeatureDisabledError, "feature_disabled", 503)
        self._consents(mock_api, dict(_IDS_CONSENT), off)
        provider = AsyncMock()
        with pytest.raises(HostedSummaryUnavailable) as caught:
            _run_summary(disclosed, _retrieval(), source="vault", passphrase_provider=provider)
        provider.assert_not_awaited()
        assert mock_api.post.await_count == 2
        assert summary_error_message(caught.value) == (
            "Hosted summaries are not available for a key kept in the vault on this "
            "Servonaut service yet. Try again later.")

    def test_older_service_uses_passphrase_for_passphrase_custody(self, disclosed, mock_api):
        self._consents(mock_api, dict(_CONSENT_RESPONSE), _DISPATCH_RESPONSE.copy())
        retrieval = _retrieval()
        _run_summary(disclosed, retrieval, source="passphrase")
        retrieval.envelope_keys.assert_not_awaited()
        assert mock_api.post.call_args_list[1].kwargs["json"]["passphrase"] == "pw-placeholder"

    def test_older_service_vault_custody_gets_the_unavailable_text(self, disclosed, mock_api):
        self._consents(mock_api, dict(_CONSENT_RESPONSE))
        with pytest.raises(HostedSummaryUnavailable):
            _run_summary(disclosed, _retrieval(), source="vault")

    def test_custody_vault_409_and_envelope_keys_422_show_client_text(self, disclosed, mock_api):
        refused = _api_error(APIErrorClass, "memory_key_custody_vault", 409)
        self._consents(mock_api, dict(_CONSENT_RESPONSE), refused)
        with pytest.raises(Exception) as caught:
            _run_summary(disclosed, _retrieval(), source="passphrase")
        assert summary_error_message(caught.value) == (
            "Memory Sync keeps its key in your vault. Set up or unlock your vault on "
            "this device, then try again.")

        invalid = _api_error(
            ValidationFailedError, "validation_failed", 422, {"field": "envelope_keys"})
        self._consents(mock_api, dict(_IDS_CONSENT), invalid)
        with pytest.raises(Exception) as caught:
            _run_summary(disclosed, _retrieval())
        assert summary_error_message(caught.value) == (
            "The summary could not be started because the memory on the service "
            "changed. Sync this server's memory and try again.")

    def test_keys_never_reach_the_log(self, disclosed, mock_api, caplog):
        import logging

        caplog.set_level(logging.DEBUG)
        off = _api_error(FeatureDisabledError, "feature_disabled", 503)
        self._consents(mock_api, dict(_IDS_CONSENT), off)
        with pytest.raises(HostedSummaryUnavailable):
            _run_summary(disclosed, _retrieval(keys=[{"envelope_id": "env-os", "dek": "SECRETDEK"}]))
        assert "SECRETDEK" not in caplog.text


class TestFailedStatus:
    def _config(self, mock_config):
        mock_config.get.return_value = SimpleNamespace(memory=SimpleNamespace(
            ai_summary_poll_interval_seconds=0.1, ai_summary_poll_timeout_seconds=1))

    def test_failed_stops_polling_and_raises(self, service, mock_api, mock_config):
        self._config(mock_config)
        mock_api.get.return_value = {"status": "failed", "reason": "decryption_failed"}
        with pytest.raises(SummaryFailed) as caught:
            run(service.wait_for_new_summary("i-123", previous_envelope_id="old"))
        assert mock_api.get.await_count == 1
        assert caught.value.reason == "decryption_failed"
        assert summary_error_message(caught.value) == (
            "The summary could not be created (the memory could not be opened with "
            "the keys that were sent).")

    def test_unknown_reason_uses_the_generic_text_and_hides_the_code(self, service, mock_api, mock_config, caplog):
        self._config(mock_config)
        mock_api.get.return_value = {"status": "failed", "reason": "weird_new_code"}
        with pytest.raises(SummaryFailed) as caught:
            run(service.wait_for_new_summary("i-123"))
        text = summary_error_message(caught.value)
        assert text == "The summary could not be created (the service reported a problem)."
        assert "weird_new_code" not in text
        assert "weird_new_code" in caplog.text  # logged, not shown

    def test_other_errors_have_no_summary_text(self):
        assert summary_error_message(RuntimeError("x")) is None


from servonaut.services.api_client import APIError as APIErrorClass  # noqa: E402
