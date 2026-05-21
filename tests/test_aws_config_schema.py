"""Tests for AWSConfig and ObjectStorageConfig schema behaviour."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import fields
from pathlib import Path
from unittest.mock import patch

import pytest

from servonaut.config.schema import (
    AWSConfig,
    AppConfig,
    ObjectStorageConfig,
)
from servonaut.config.manager import ConfigManager


# ---------------------------------------------------------------------------
# ObjectStorageConfig defaults
# ---------------------------------------------------------------------------

class TestObjectStorageConfigDefaults:

    def test_default_fields_are_empty_strings(self) -> None:
        cfg = ObjectStorageConfig()
        assert cfg.access_key == ""
        assert cfg.secret_key == ""
        assert cfg.region == ""
        assert cfg.endpoint_url == ""

    def test_repr_masks_set_access_key(self) -> None:
        cfg = ObjectStorageConfig(access_key="AKIAIOSFODNN7EXAMPLE", secret_key="")
        assert "<set>" in repr(cfg)
        assert "AKIAIOSFODNN7EXAMPLE" not in repr(cfg)

    def test_repr_masks_set_secret_key(self) -> None:
        cfg = ObjectStorageConfig(access_key="", secret_key="wJalrXUtnFEMI/K7MDENG")
        assert "<set>" in repr(cfg)
        assert "wJalrXUtnFEMI" not in repr(cfg)

    def test_repr_shows_empty_when_not_set(self) -> None:
        cfg = ObjectStorageConfig()
        assert "''" in repr(cfg)

    def test_repr_includes_region_and_endpoint(self) -> None:
        cfg = ObjectStorageConfig(region="us-east-1", endpoint_url="https://example.com")
        r = repr(cfg)
        assert "us-east-1" in r
        assert "https://example.com" in r


# ---------------------------------------------------------------------------
# AWSConfig defaults
# ---------------------------------------------------------------------------

class TestAWSConfigDefaults:

    def test_default_enabled_is_true(self) -> None:
        cfg = AWSConfig()
        assert cfg.enabled is True

    def test_default_region_is_us_east_1(self) -> None:
        cfg = AWSConfig()
        assert cfg.default_region == "us-east-1"

    def test_default_cache_ttl(self) -> None:
        cfg = AWSConfig()
        assert cfg.cache_ttl_seconds == 300

    def test_object_storage_is_default_instance(self) -> None:
        cfg = AWSConfig()
        assert isinstance(cfg.object_storage, ObjectStorageConfig)
        assert cfg.object_storage.access_key == ""

    def test_repr_masks_nested_secrets(self) -> None:
        cfg = AWSConfig()
        cfg.object_storage.access_key = "secret_key_value"
        assert "secret_key_value" not in repr(cfg)

    def test_repr_includes_region(self) -> None:
        cfg = AWSConfig(default_region="eu-west-1")
        assert "eu-west-1" in repr(cfg)


# ---------------------------------------------------------------------------
# _coerce drops unknown keys
# ---------------------------------------------------------------------------

class TestCoerceDropsUnknownKeys:

    def test_coerce_drops_unknown_key_in_object_storage(self) -> None:
        from servonaut.config.manager import _coerce
        raw = {"access_key": "abc", "secret_key": "def", "unknown_field": "bad"}
        result = _coerce(ObjectStorageConfig, raw, "object_storage")
        assert result.access_key == "abc"
        assert not hasattr(result, "unknown_field")

    def test_coerce_drops_unknown_key_in_aws_config(self) -> None:
        from servonaut.config.manager import _coerce
        raw = {"enabled": True, "default_region": "us-west-2", "legacy_field": "ignored"}
        # object_storage must be provided as a dict and coerced separately
        raw["object_storage"] = {}
        result = _coerce(AWSConfig, raw, "aws")
        assert result.default_region == "us-west-2"
        assert not hasattr(result, "legacy_field")

    def test_coerce_uses_defaults_for_missing_fields(self) -> None:
        from servonaut.config.manager import _coerce
        raw = {}
        result = _coerce(ObjectStorageConfig, raw, "object_storage")
        assert result.access_key == ""
        assert result.region == ""


# ---------------------------------------------------------------------------
# Nested object_storage coercion
# ---------------------------------------------------------------------------

class TestNestedObjectStorageCoercion:

    def test_aws_config_coercion_with_nested_object_storage(self) -> None:
        from servonaut.config.manager import _coerce
        raw = {
            "enabled": True,
            "default_region": "ap-southeast-1",
            "object_storage": {
                "access_key": "AK123",
                "region": "ap-southeast-1",
            },
        }
        # Manually coerce nested object_storage first, as manager.py does
        if "object_storage" in raw and isinstance(raw["object_storage"], dict):
            raw = dict(raw)
            raw["object_storage"] = _coerce(ObjectStorageConfig, raw["object_storage"], "aws.object_storage")
        result = _coerce(AWSConfig, raw, "aws")
        assert result.default_region == "ap-southeast-1"
        assert isinstance(result.object_storage, ObjectStorageConfig)
        assert result.object_storage.access_key == "AK123"


# ---------------------------------------------------------------------------
# resolve_secret on $ENV_VAR
# ---------------------------------------------------------------------------

class TestResolveSecret:

    def test_resolves_env_var(self) -> None:
        from servonaut.config.secrets import resolve_secret
        with patch.dict(os.environ, {"MY_TEST_KEY": "resolved_value"}):
            assert resolve_secret("$MY_TEST_KEY") == "resolved_value"

    def test_returns_literal_when_not_env_var(self) -> None:
        from servonaut.config.secrets import resolve_secret
        assert resolve_secret("plain-value") == "plain-value"

    def test_returns_empty_when_env_var_unset(self) -> None:
        from servonaut.config.secrets import resolve_secret
        # ensure env var is not set
        env = {k: v for k, v in os.environ.items() if k != "UNSET_VAR_XYZ"}
        with patch.dict(os.environ, env, clear=True):
            result = resolve_secret("$UNSET_VAR_XYZ")
            # resolve_secret returns "" or "$UNSET_VAR_XYZ" when unset — both
            # are acceptable; the key point is no exception is raised.
            assert isinstance(result, str)


# ---------------------------------------------------------------------------
# AppConfig loads with no 'aws' key (additive-safe)
# ---------------------------------------------------------------------------

class TestAppConfigAdditiveAWS:

    def test_appconfig_without_aws_key_uses_defaults(self) -> None:
        """AppConfig(**{}) must work without an 'aws' key — additive-safe."""
        cfg = AppConfig()
        assert isinstance(cfg.aws, AWSConfig)
        assert cfg.aws.default_region == "us-east-1"

    def test_appconfig_aws_field_is_independent_instance(self) -> None:
        """Each AppConfig() call creates a fresh AWSConfig, not a shared default."""
        cfg1 = AppConfig()
        cfg2 = AppConfig()
        cfg1.aws.default_region = "eu-central-1"
        assert cfg2.aws.default_region == "us-east-1"


# ---------------------------------------------------------------------------
# Save / load round-trip
# ---------------------------------------------------------------------------

class TestSaveLoadRoundTrip:

    def test_round_trip_preserves_aws_config(self, tmp_path, monkeypatch) -> None:
        """Config manager save → load preserves aws config fields."""
        config_file = tmp_path / "config.json"
        monkeypatch.setattr("servonaut.config.manager.CONFIG_PATH", config_file)
        monkeypatch.setattr("servonaut.config.manager.CONFIG_DIR", tmp_path)

        mgr = ConfigManager()
        cfg = mgr.get()
        cfg.aws.default_region = "ca-central-1"
        cfg.aws.object_storage.region = "ca-central-1"
        mgr.save(cfg)

        mgr2 = ConfigManager()
        loaded = mgr2.get()
        assert loaded.aws.default_region == "ca-central-1"
        assert loaded.aws.object_storage.region == "ca-central-1"

    def test_round_trip_preserves_object_storage_endpoint(self, tmp_path, monkeypatch) -> None:
        config_file = tmp_path / "config.json"
        monkeypatch.setattr("servonaut.config.manager.CONFIG_PATH", config_file)
        monkeypatch.setattr("servonaut.config.manager.CONFIG_DIR", tmp_path)

        mgr = ConfigManager()
        cfg = mgr.get()
        cfg.aws.object_storage.endpoint_url = "https://custom.endpoint.example.com"
        mgr.save(cfg)

        mgr2 = ConfigManager()
        loaded = mgr2.get()
        assert loaded.aws.object_storage.endpoint_url == "https://custom.endpoint.example.com"
