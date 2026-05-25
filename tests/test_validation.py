"""Tests for client-side wire-format validators."""

from __future__ import annotations

import pytest

from servonaut.utils.validation import (
    ALLOWED_PROVIDERS,
    ValidationError,
    validate_instance_id,
    validate_provider,
)


class TestValidateProvider:
    @pytest.mark.parametrize("provider", ["aws", "ovh", "hetzner"])
    def test_accepts_allowed(self, provider: str) -> None:
        assert validate_provider(provider) == provider

    @pytest.mark.parametrize(
        "raw,expected",
        [("AWS", "aws"), ("  ovh ", "ovh"), ("Hetzner", "hetzner")],
    )
    def test_normalizes_case_and_whitespace(self, raw: str, expected: str) -> None:
        assert validate_provider(raw) == expected

    @pytest.mark.parametrize("provider", ["gcp", "digitalocean", "azure", "", " "])
    def test_rejects_unknown(self, provider: str) -> None:
        with pytest.raises(ValidationError, match="Unknown provider"):
            validate_provider(provider)

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ValidationError, match="must be a string"):
            validate_provider(None)  # type: ignore[arg-type]

    def test_allowed_set_is_locked(self) -> None:
        # Locked contract with servonaut.dev — any change requires coordination.
        assert ALLOWED_PROVIDERS == frozenset({"aws", "ovh", "hetzner"})


class TestValidateInstanceId:
    @pytest.mark.parametrize(
        "instance_id",
        [
            "i-0abc1234def567890",
            "hetzner-server-001",
            "my_instance",
            "X",
            "a" * 64,
            "_-_-",
            "ovh-srv_12-AB",
        ],
    )
    def test_accepts_valid(self, instance_id: str) -> None:
        assert validate_instance_id(instance_id) == instance_id

    @pytest.mark.parametrize(
        "instance_id",
        [
            "",
            "a" * 65,
            "with space",
            "with/slash",
            "with.dot",
            "with:colon",
            "with$dollar",
            "with;semi",
            "naïve",
        ],
    )
    def test_rejects_invalid(self, instance_id: str) -> None:
        with pytest.raises(ValidationError, match="must match"):
            validate_instance_id(instance_id)

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ValidationError, match="must be a string"):
            validate_instance_id(12345)  # type: ignore[arg-type]
