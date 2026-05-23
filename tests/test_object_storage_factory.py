"""Tests for services/object_storage_factory.build_object_storage_services.

Covers:
- AWS service always constructed (boto3 credential chain, no access_key required).
- Hetzner service: gated on access_key non-empty AND (region OR endpoint_url).
- OVH service: same gating as Hetzner.
- Endpoint derivation matches provider-specific URL templates.
- Bad region string -> logger.warning + skip construction (returns None).
- resolve_secret called for each credential field.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch, call

import pytest

from servonaut.config.schema import AppConfig, ObjectStorageConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(
    aws_region="us-east-1",
    aws_key="", aws_secret="",
    hetzner_key="", hetzner_secret="", hetzner_region="", hetzner_endpoint="",
    ovh_key="", ovh_secret="", ovh_region="", ovh_endpoint="",
):
    """Build an AppConfig with the given object-storage fields."""
    config = AppConfig()
    config.aws.object_storage.access_key = aws_key
    config.aws.object_storage.secret_key = aws_secret
    config.aws.object_storage.region = aws_region
    config.aws.object_storage.endpoint_url = ""
    config.aws.default_region = aws_region

    config.hetzner.object_storage.access_key = hetzner_key
    config.hetzner.object_storage.secret_key = hetzner_secret
    config.hetzner.object_storage.region = hetzner_region
    config.hetzner.object_storage.endpoint_url = hetzner_endpoint

    config.ovh.object_storage.access_key = ovh_key
    config.ovh.object_storage.secret_key = ovh_secret
    config.ovh.object_storage.region = ovh_region
    config.ovh.object_storage.endpoint_url = ovh_endpoint
    return config


def _call_factory(config, resolve_side_effect=None):
    """Call build_object_storage_services with ObjectStorageService and resolve_secret mocked.

    The factory does late-binding `from X import Y` inside the function body,
    so we must patch at the *source* module, not at the factory module.
    """
    if resolve_side_effect is None:
        resolve_side_effect = lambda v: v  # identity
    with patch(
        "servonaut.services.object_storage_service.ObjectStorageService"
    ) as mock_cls, patch(
        "servonaut.config.secrets.resolve_secret",
        side_effect=resolve_side_effect,
    ):
        from servonaut.services.object_storage_factory import build_object_storage_services
        result = build_object_storage_services(config)
        return result, mock_cls


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------

class TestAWSObjectStorageConstruction:
    def test_aws_service_always_constructed_with_valid_region(self):
        config = _make_config(aws_region="us-east-1")
        result, mock_cls = _call_factory(config)
        aws_svc, _, _ = result
        # ObjectStorageService was instantiated (at least once — for AWS)
        assert mock_cls.called

    def test_aws_service_not_none_on_success(self):
        config = _make_config(aws_region="us-east-1")
        result, mock_cls = _call_factory(config)
        aws_svc, _, _ = result
        assert aws_svc is not None

    def test_aws_service_constructed_without_explicit_key(self):
        """AWS relies on boto3 default credential chain; access_key may be empty."""
        config = _make_config(aws_region="eu-west-1", aws_key="", aws_secret="")
        result, mock_cls = _call_factory(config)
        aws_svc, _, _ = result
        assert aws_svc is not None

    def test_aws_bad_region_returns_none_and_logs_warning(self):
        """An invalid region string should skip construction and log a warning."""
        config = _make_config(aws_region="INVALID_REGION")
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ) as mock_cls, patch(
            "servonaut.config.secrets.resolve_secret",
            side_effect=lambda v: v,
        ), patch(
            "servonaut.services.object_storage_factory.logger"
        ) as mock_logger:
            from servonaut.services.object_storage_factory import build_object_storage_services
            aws_svc, _, _ = build_object_storage_services(config)

        # Service should NOT be constructed for bad region
        assert aws_svc is None
        mock_logger.warning.assert_called()
        warning_text = " ".join(str(c) for c in mock_logger.warning.call_args_list)
        assert "INVALID_REGION" in warning_text or "invalid region" in warning_text.lower()

    def test_aws_resolve_secret_called_for_credentials(self):
        config = _make_config(aws_region="us-east-1", aws_key="$AWS_KEY", aws_secret="$AWS_SECRET")
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ), patch(
            "servonaut.config.secrets.resolve_secret",
            side_effect=lambda v: f"resolved:{v}",
        ) as mock_resolve:
            from servonaut.services.object_storage_factory import build_object_storage_services
            build_object_storage_services(config)
        resolved_vals = [c.args[0] for c in mock_resolve.call_args_list]
        assert "$AWS_KEY" in resolved_vals
        assert "$AWS_SECRET" in resolved_vals


# ---------------------------------------------------------------------------
# Hetzner
# ---------------------------------------------------------------------------

class TestHetznerObjectStorageConstruction:
    def test_hetzner_not_constructed_when_no_access_key(self):
        config = _make_config(hetzner_key="", hetzner_region="fsn1")
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ) as mock_cls, patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ):
            from servonaut.services.object_storage_factory import build_object_storage_services
            _, hetzner_svc, _ = build_object_storage_services(config)
        # Hetzner-specific call should not happen; only AWS may be called
        hetzner_calls = [
            c for c in mock_cls.call_args_list
            if c.kwargs.get("provider") == "hetzner"
        ]
        assert len(hetzner_calls) == 0

    def test_hetzner_constructed_with_key_and_region(self):
        config = _make_config(
            hetzner_key="key123", hetzner_secret="sec456", hetzner_region="fsn1",
        )
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ) as mock_cls, patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ):
            from servonaut.services.object_storage_factory import build_object_storage_services
            _, hetzner_svc, _ = build_object_storage_services(config)
        hetzner_calls = [
            c for c in mock_cls.call_args_list if c.kwargs.get("provider") == "hetzner"
        ]
        assert len(hetzner_calls) == 1

    def test_hetzner_constructed_with_key_and_custom_endpoint(self):
        config = _make_config(
            hetzner_key="key123", hetzner_secret="sec456",
            hetzner_endpoint="https://custom.hetzner.endpoint.com",
        )
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ) as mock_cls, patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ):
            from servonaut.services.object_storage_factory import build_object_storage_services
            _, hetzner_svc, _ = build_object_storage_services(config)
        hetzner_calls = [
            c for c in mock_cls.call_args_list if c.kwargs.get("provider") == "hetzner"
        ]
        assert len(hetzner_calls) == 1

    def test_hetzner_not_constructed_when_key_but_no_region_no_endpoint(self):
        config = _make_config(hetzner_key="key123", hetzner_region="", hetzner_endpoint="")
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ) as mock_cls, patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ), patch(
            "servonaut.services.object_storage_factory.logger"
        ) as mock_logger:
            from servonaut.services.object_storage_factory import build_object_storage_services
            _, hetzner_svc, _ = build_object_storage_services(config)
        hetzner_calls = [
            c for c in mock_cls.call_args_list if c.kwargs.get("provider") == "hetzner"
        ]
        assert len(hetzner_calls) == 0
        mock_logger.warning.assert_called()

    def test_hetzner_endpoint_derived_from_region(self):
        """When no endpoint_url is given, endpoint must be derived from region."""
        config = _make_config(
            hetzner_key="key123", hetzner_secret="sec", hetzner_region="nbg1",
        )
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ) as mock_cls, patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ):
            from servonaut.services.object_storage_factory import build_object_storage_services
            build_object_storage_services(config)
        hetzner_calls = [
            c for c in mock_cls.call_args_list if c.kwargs.get("provider") == "hetzner"
        ]
        assert len(hetzner_calls) == 1
        endpoint_used = hetzner_calls[0].kwargs.get("endpoint_url", "")
        assert "nbg1" in endpoint_used
        assert "your-objectstorage.com" in endpoint_used

    def test_hetzner_bad_region_returns_none_and_logs_warning(self):
        config = _make_config(hetzner_key="key123", hetzner_region="BAD_REGION!")
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ) as mock_cls, patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ), patch(
            "servonaut.services.object_storage_factory.logger"
        ) as mock_logger:
            from servonaut.services.object_storage_factory import build_object_storage_services
            _, hetzner_svc, _ = build_object_storage_services(config)
        hetzner_calls = [
            c for c in mock_cls.call_args_list if c.kwargs.get("provider") == "hetzner"
        ]
        assert len(hetzner_calls) == 0
        mock_logger.warning.assert_called()

    def test_hetzner_resolve_secret_called_for_credentials(self):
        config = _make_config(
            hetzner_key="$HETZNER_KEY", hetzner_secret="$HETZNER_SECRET",
            hetzner_region="fsn1",
        )
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ), patch(
            "servonaut.config.secrets.resolve_secret",
            side_effect=lambda v: f"resolved:{v}",
        ) as mock_resolve:
            from servonaut.services.object_storage_factory import build_object_storage_services
            build_object_storage_services(config)
        resolved_vals = [c.args[0] for c in mock_resolve.call_args_list]
        assert "$HETZNER_KEY" in resolved_vals
        assert "$HETZNER_SECRET" in resolved_vals


# ---------------------------------------------------------------------------
# OVH
# ---------------------------------------------------------------------------

class TestOVHObjectStorageConstruction:
    def test_ovh_not_constructed_when_no_access_key(self):
        config = _make_config(ovh_key="", ovh_region="gra")
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ) as mock_cls, patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ):
            from servonaut.services.object_storage_factory import build_object_storage_services
            _, _, ovh_svc = build_object_storage_services(config)
        ovh_calls = [
            c for c in mock_cls.call_args_list if c.kwargs.get("provider") == "ovh"
        ]
        assert len(ovh_calls) == 0

    def test_ovh_constructed_with_key_and_region(self):
        config = _make_config(ovh_key="key123", ovh_secret="sec456", ovh_region="gra")
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ) as mock_cls, patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ):
            from servonaut.services.object_storage_factory import build_object_storage_services
            _, _, ovh_svc = build_object_storage_services(config)
        ovh_calls = [
            c for c in mock_cls.call_args_list if c.kwargs.get("provider") == "ovh"
        ]
        assert len(ovh_calls) == 1

    def test_ovh_constructed_with_key_and_custom_endpoint(self):
        config = _make_config(
            ovh_key="key123", ovh_secret="sec456",
            ovh_endpoint="https://s3.custom.ovh.net",
        )
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ) as mock_cls, patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ):
            from servonaut.services.object_storage_factory import build_object_storage_services
            _, _, ovh_svc = build_object_storage_services(config)
        ovh_calls = [
            c for c in mock_cls.call_args_list if c.kwargs.get("provider") == "ovh"
        ]
        assert len(ovh_calls) == 1

    def test_ovh_endpoint_derived_from_region(self):
        """When no endpoint_url is given, OVH endpoint must be derived from region."""
        config = _make_config(ovh_key="key123", ovh_secret="sec", ovh_region="gra")
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ) as mock_cls, patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ):
            from servonaut.services.object_storage_factory import build_object_storage_services
            build_object_storage_services(config)
        ovh_calls = [
            c for c in mock_cls.call_args_list if c.kwargs.get("provider") == "ovh"
        ]
        assert len(ovh_calls) == 1
        endpoint_used = ovh_calls[0].kwargs.get("endpoint_url", "")
        assert "gra" in endpoint_used
        assert "ovh.net" in endpoint_used

    def test_ovh_bad_region_returns_none_and_logs_warning(self):
        config = _make_config(ovh_key="key123", ovh_region="BAD REGION")
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ) as mock_cls, patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ), patch(
            "servonaut.services.object_storage_factory.logger"
        ) as mock_logger:
            from servonaut.services.object_storage_factory import build_object_storage_services
            _, _, ovh_svc = build_object_storage_services(config)
        ovh_calls = [
            c for c in mock_cls.call_args_list if c.kwargs.get("provider") == "ovh"
        ]
        assert len(ovh_calls) == 0
        mock_logger.warning.assert_called()

    def test_ovh_not_constructed_when_key_but_no_region_no_endpoint(self):
        config = _make_config(ovh_key="key123", ovh_region="", ovh_endpoint="")
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ) as mock_cls, patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ), patch(
            "servonaut.services.object_storage_factory.logger"
        ) as mock_logger:
            from servonaut.services.object_storage_factory import build_object_storage_services
            _, _, ovh_svc = build_object_storage_services(config)
        ovh_calls = [
            c for c in mock_cls.call_args_list if c.kwargs.get("provider") == "ovh"
        ]
        assert len(ovh_calls) == 0
        mock_logger.warning.assert_called()

    def test_ovh_resolve_secret_called_for_credentials(self):
        config = _make_config(
            ovh_key="$OVH_KEY", ovh_secret="$OVH_SECRET", ovh_region="gra",
        )
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ), patch(
            "servonaut.config.secrets.resolve_secret",
            side_effect=lambda v: f"resolved:{v}",
        ) as mock_resolve:
            from servonaut.services.object_storage_factory import build_object_storage_services
            build_object_storage_services(config)
        resolved_vals = [c.args[0] for c in mock_resolve.call_args_list]
        assert "$OVH_KEY" in resolved_vals
        assert "$OVH_SECRET" in resolved_vals


# ---------------------------------------------------------------------------
# Return shape
# ---------------------------------------------------------------------------

class TestConstructorExceptionHandling:
    """Cover the except ValueError paths when ObjectStorageService.__init__ raises."""

    def test_aws_constructor_raises_valueerror_returns_none_and_logs(self):
        config = _make_config(aws_region="us-east-1", aws_key="badkey")
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService",
            side_effect=ValueError("invalid credentials"),
        ) as mock_cls, patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ), patch(
            "servonaut.services.object_storage_factory.logger"
        ) as mock_logger:
            from servonaut.services.object_storage_factory import build_object_storage_services
            aws_svc, _, _ = build_object_storage_services(config)
        # The ValueError from constructor must be caught and logged, not propagated
        assert aws_svc is None
        mock_logger.warning.assert_called()

    def test_hetzner_constructor_raises_valueerror_returns_none_and_logs(self):
        config = _make_config(hetzner_key="badkey", hetzner_region="fsn1")
        call_count = [0]

        def side_effect_fn(**kwargs):
            if kwargs.get("provider") == "hetzner":
                raise ValueError("hetzner config error")
            call_count[0] += 1
            return MagicMock()

        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService",
            side_effect=side_effect_fn,
        ), patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ), patch(
            "servonaut.services.object_storage_factory.logger"
        ) as mock_logger:
            from servonaut.services.object_storage_factory import build_object_storage_services
            _, hetzner_svc, _ = build_object_storage_services(config)
        assert hetzner_svc is None
        mock_logger.warning.assert_called()

    def test_ovh_constructor_raises_valueerror_returns_none_and_logs(self):
        config = _make_config(ovh_key="badkey", ovh_region="gra")

        def side_effect_fn(**kwargs):
            if kwargs.get("provider") == "ovh":
                raise ValueError("ovh config error")
            return MagicMock()

        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService",
            side_effect=side_effect_fn,
        ), patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ), patch(
            "servonaut.services.object_storage_factory.logger"
        ) as mock_logger:
            from servonaut.services.object_storage_factory import build_object_storage_services
            _, _, ovh_svc = build_object_storage_services(config)
        assert ovh_svc is None
        mock_logger.warning.assert_called()


class TestReturnShape:
    def test_returns_three_tuple(self):
        config = _make_config()
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ), patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ):
            from servonaut.services.object_storage_factory import build_object_storage_services
            result = build_object_storage_services(config)
        assert len(result) == 3

    def test_hetzner_and_ovh_none_when_unconfigured(self):
        config = _make_config(hetzner_key="", ovh_key="")
        with patch(
            "servonaut.services.object_storage_service.ObjectStorageService"
        ) as mock_cls, patch(
            "servonaut.config.secrets.resolve_secret", side_effect=lambda v: v
        ), patch(
            "servonaut.services.object_storage_factory.logger"
        ):
            from servonaut.services.object_storage_factory import build_object_storage_services
            aws_svc, hetzner_svc, ovh_svc = build_object_storage_services(config)
        assert hetzner_svc is None
        assert ovh_svc is None
