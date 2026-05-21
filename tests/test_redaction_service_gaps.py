"""Gap-fill tests for RedactionService — coverage audit pass (workflow 20260519-8967e6).

Covers branches not reached by test_redaction_stream.py or test_demo_mode_coverage.py:

  1. redact_name non-idempotence PIN  — security-audit-mandated regression pin
  2. scrub_stream try/except fallback → <redaction-error>
  3. Primitive guard clauses (empty / "-" / "N/A" inputs)
  4. redact_instance_id custom- prefix branch
  5. redact_key_name with-path branch
  6. redact_instance optional-field branches (private_ip, ssh_key, group, username,
     host, tags, is_custom+region)
  7. ServonautApp.notify timeout=not-None path
"""

from __future__ import annotations

import copy
from unittest.mock import MagicMock, patch

import pytest

from servonaut.services.redaction_service import RedactionService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _svc() -> RedactionService:
    return RedactionService()


# ---------------------------------------------------------------------------
# 1. redact_name non-idempotence PIN
#
# WHY THIS TEST EXISTS:
#   redact_instance() mutates instance["name"] in-place by calling redact_name().
#   The per-handler contract (log_viewer, cloudwatch, etc.) depends on the fact
#   that redact_name("web-prod") == redact_name("web-prod") == same fake value
#   but redact_name(redact_name("web-prod")) != redact_name("web-prod") for any
#   *new* service instance, because the output of the first call is NOT in the
#   _name_cache of the new service.
#
#   However, within a SINGLE service instance redact_name IS idempotent (it is
#   in _name_cache after the first call). The NON-idempotence only matters when
#   a second RedactionService instance encounters an already-substituted name.
#   scrub_stream guards against this for free-text via _fake_names; for the
#   structured field path the guarantee is that redact_instances() is called
#   only once per data source — NOT twice on the same dict.
#
#   This test PINS the known behavior:
#   - Within one service: idempotent (cache hit).
#   - A fresh service seeing an already-fake name: can re-substitute it.
#   If a future "fix" makes redact_name globally idempotent across service
#   instances the per-handler once-only call assumption changes — this test
#   catches that so the design decision is re-examined explicitly.
# ---------------------------------------------------------------------------


class TestRedactNameNonIdempotencePin:
    """PIN test: redact_name non-idempotence across service instances.

    The security audit explicitly required this test to be present so that
    any future change that alters the across-instance idempotence property
    surfaces as a visible test failure requiring deliberate review.
    """

    def test_within_same_service_is_idempotent(self) -> None:
        """Within one service instance redact_name("x") == redact_name("x")."""
        svc = _svc()
        first = svc.redact_name("web-prod-7")
        second = svc.redact_name("web-prod-7")
        assert first == second, (
            "Within one RedactionService, redact_name must return the same "
            "fake name for the same input on every call (cache hit path)."
        )

    def test_across_service_instances_may_not_be_idempotent(self) -> None:
        """A fresh service can re-substitute an already-fake name.

        This is the PINNED behavior: redact_name() output fed into a *new*
        RedactionService is NOT guaranteed to pass through unchanged — the
        fresh service's _name_cache is empty and _fake_names is empty, so
        it will happily re-hash and re-substitute the already-fake name.

        The per-handler design (log_viewer, cloudwatch, etc.) relies on
        redact_instances() being called ONCE per data load, not repeatedly.
        If this property ever changes (i.e., the second call returns the
        same value as the first) the test must be updated with an explicit
        explanation of why the design is still safe.
        """
        svc1 = _svc()
        fake_name = svc1.redact_name("web-prod-7")
        # Confirm fake_name is in svc1's _fake_names set
        assert fake_name in svc1._fake_names

        # A fresh service does NOT have fake_name in its _name_cache or _fake_names
        svc2 = _svc()
        assert fake_name not in svc2._fake_names, (
            "Fresh service must start with empty _fake_names — "
            "this is the precondition for the non-idempotence property."
        )
        # The fresh service CAN re-map the already-fake name
        result = svc2.redact_name(fake_name)
        # We don't assert the exact value (it's deterministic but opaque),
        # but we record that it is DIFFERENT from the fake_name to pin the behavior.
        # If this assertion fails it means redact_name became globally idempotent
        # — review the design change before removing this assertion.
        assert result != fake_name, (
            f"DESIGN CHANGE DETECTED: redact_name('{fake_name}') on a fresh "
            f"RedactionService returned the same value ('{result}'). "
            "This means redact_name is now globally idempotent across service "
            "instances. Review whether the per-handler once-only call assumption "
            "is still valid before removing this assertion."
        )

    def test_scrub_stream_guards_fake_names_for_free_text(self) -> None:
        """scrub_stream uses _fake_names to protect free-text from double-sub.

        This is the mitigation that makes the across-instance non-idempotence
        safe for free-text paths: the log_group and resource_name primitives
        skip names already in _fake_names.  This test verifies the mitigation
        works correctly within a single service (the typical production case).
        """
        svc = _svc()
        # First scrub: /aws/lambda/my-function gets name redacted
        once = svc.scrub_stream("/aws/lambda/my-function")
        assert "my-function" not in once
        # Second scrub: the already-fake function name must pass through unchanged
        twice = svc.scrub_stream(once)
        assert once == twice, (
            "scrub_stream must be idempotent for already-scrubbed log groups "
            "because the fake name is in _fake_names."
        )


# ---------------------------------------------------------------------------
# 2. scrub_stream try/except fallback path → "<redaction-error>"
# ---------------------------------------------------------------------------


class TestScrubStreamFallback:
    """The inner try/except must catch errors and return <redaction-error>."""

    def test_fallback_to_redact_text_when_exception(self) -> None:
        """If a primitive raises, scrub_stream falls back to redact_text only."""
        svc = _svc()
        # Patch redact_arn to raise after redact_text already ran
        with patch.object(svc, "redact_arn", side_effect=RuntimeError("boom")):
            # Input with an IP so the fallback redact_text still does something
            raw = "host 5.6.7.8 arn:aws:iam::123456789012:user/x"
            result = svc.scrub_stream(raw)
        # Fallback: redact_text was called on the orig text → IP redacted
        assert "5.6.7.8" not in result
        # ARN was not redacted (exception fired before redact_arn completed)
        # Result is not the full pipeline output but it is a string (not an exception)
        assert isinstance(result, str)

    def test_fallback_returns_redaction_error_when_even_redact_text_fails(self) -> None:
        """If BOTH the main pipeline AND the fallback redact_text fail, return
        the literal string '<redaction-error>'."""
        svc = _svc()
        with patch.object(svc, "redact_arn", side_effect=RuntimeError("step-fail")):
            with patch.object(svc, "redact_text", side_effect=RuntimeError("fallback-fail")):
                result = svc.scrub_stream("AKIAIOSFODNN7EXAMPLE 1.2.3.4")
        assert result == "<redaction-error>", (
            f"Expected '<redaction-error>' when all fallbacks fail, got {result!r}"
        )


# ---------------------------------------------------------------------------
# 3. Primitive guard clauses — empty / "-" / "N/A" inputs
# ---------------------------------------------------------------------------


class TestPrimitiveGuards:
    """All redact_* methods must return their input unchanged for falsy/sentinel values."""

    def test_redact_ip_empty_string(self) -> None:
        svc = _svc()
        assert svc.redact_ip("") == ""

    def test_redact_ip_dash_sentinel(self) -> None:
        svc = _svc()
        assert svc.redact_ip("-") == "-"

    def test_redact_ip_na_sentinel(self) -> None:
        svc = _svc()
        assert svc.redact_ip("N/A") == "N/A"

    def test_redact_name_empty_string(self) -> None:
        svc = _svc()
        assert svc.redact_name("") == ""

    def test_redact_name_dash_sentinel(self) -> None:
        svc = _svc()
        assert svc.redact_name("-") == "-"

    def test_redact_hostname_empty_string(self) -> None:
        svc = _svc()
        assert svc.redact_hostname("") == ""

    def test_redact_hostname_dash_sentinel(self) -> None:
        svc = _svc()
        assert svc.redact_hostname("-") == "-"

    def test_redact_key_name_empty_string(self) -> None:
        svc = _svc()
        assert svc.redact_key_name("") == ""

    def test_redact_key_name_dash_sentinel(self) -> None:
        svc = _svc()
        assert svc.redact_key_name("-") == "-"

    def test_redact_provider_empty_string(self) -> None:
        svc = _svc()
        assert svc.redact_provider("") == ""

    def test_redact_provider_dash_sentinel(self) -> None:
        svc = _svc()
        assert svc.redact_provider("-") == "-"

    def test_redact_group_empty_string(self) -> None:
        svc = _svc()
        assert svc.redact_group("") == ""

    def test_redact_group_dash_sentinel(self) -> None:
        svc = _svc()
        assert svc.redact_group("-") == "-"

    def test_redact_username_empty_string(self) -> None:
        svc = _svc()
        assert svc.redact_username("") == ""

    def test_redact_username_dash_sentinel(self) -> None:
        svc = _svc()
        assert svc.redact_username("-") == "-"


# ---------------------------------------------------------------------------
# 4. redact_instance_id — custom- prefix branch
# ---------------------------------------------------------------------------


class TestRedactInstanceId:
    """Verify all format-preserving branches of redact_instance_id."""

    def test_custom_prefix_preserved(self) -> None:
        svc = _svc()
        result = svc.redact_instance_id("custom-abc123xyz")
        assert result.startswith("custom-"), (
            f"custom- prefix not preserved: {result!r}"
        )
        assert result != "custom-abc123xyz", "ID was not redacted"

    def test_i_prefix_preserved(self) -> None:
        svc = _svc()
        result = svc.redact_instance_id("i-0abc123def456789a")
        assert result.startswith("i-"), f"i- prefix not preserved: {result!r}"
        assert result != "i-0abc123def456789a", "ID was not redacted"

    def test_unknown_format_returned_unchanged(self) -> None:
        """IDs without known prefixes pass through unchanged (unknown format)."""
        svc = _svc()
        result = svc.redact_instance_id("srv-12345")
        assert result == "srv-12345", (
            f"Unknown-format ID should pass through unchanged, got {result!r}"
        )

    def test_empty_instance_id_returned_unchanged(self) -> None:
        svc = _svc()
        assert svc.redact_instance_id("") == ""

    def test_custom_prefix_shorter_than_12_hex(self) -> None:
        """custom- prefix branch uses only first 12 hex chars."""
        svc = _svc()
        result = svc.redact_instance_id("custom-short")
        assert result.startswith("custom-")
        # The 12-char hex suffix must be exactly 12 chars
        suffix = result[len("custom-"):]
        assert len(suffix) == 12, f"Expected 12-char hex suffix, got {suffix!r}"


# ---------------------------------------------------------------------------
# 5. redact_key_name — with-path branch
# ---------------------------------------------------------------------------


class TestRedactKeyName:
    """Verify key-with-path vs plain-key branches."""

    def test_key_with_path_uses_ssh_prefix(self) -> None:
        svc = _svc()
        result = svc.redact_key_name("/home/alice/.ssh/id_rsa")
        assert result.startswith("~/.ssh/"), (
            f"Path key should get ~/.ssh/ prefix, got {result!r}"
        )

    def test_plain_key_no_path_prefix(self) -> None:
        svc = _svc()
        result = svc.redact_key_name("my-deploy-key")
        assert not result.startswith("~/.ssh/"), (
            f"Plain key should NOT get ~/.ssh/ prefix, got {result!r}"
        )
        # Must be one of _KEY_NAMES
        from servonaut.services.redaction_service import _KEY_NAMES
        assert result in _KEY_NAMES, (
            f"Plain key result {result!r} not in _KEY_NAMES"
        )


# ---------------------------------------------------------------------------
# 6. redact_instance — optional-field branches
# ---------------------------------------------------------------------------


class TestRedactInstanceOptionalFields:
    """Each optional field in redact_instance must be covered."""

    def test_private_ip_redacted(self) -> None:
        svc = _svc()
        inst = {"private_ip": "10.0.0.1"}
        svc.redact_instance(inst)
        assert inst["private_ip"] != "10.0.0.1"

    def test_ssh_key_redacted(self) -> None:
        svc = _svc()
        inst = {"ssh_key": "prod-key-v2"}
        svc.redact_instance(inst)
        assert inst["ssh_key"] != "prod-key-v2"

    def test_group_redacted(self) -> None:
        svc = _svc()
        inst = {"group": "team-backend"}
        svc.redact_instance(inst)
        assert inst["group"] != "team-backend"

    def test_username_redacted(self) -> None:
        svc = _svc()
        inst = {"username": "alice"}
        svc.redact_instance(inst)
        assert inst["username"] != "alice"

    def test_host_redacted(self) -> None:
        svc = _svc()
        inst = {"host": "my-server.internal.company.com"}
        svc.redact_instance(inst)
        assert inst["host"] != "my-server.internal.company.com"
        assert inst["host"].endswith(".example.com"), (
            f"Redacted host should end with .example.com, got {inst['host']!r}"
        )

    def test_tags_dict_values_redacted(self) -> None:
        svc = _svc()
        inst = {"tags": {"Name": "prod-api-gateway", "Env": "production-acme"}}
        svc.redact_instance(inst)
        assert inst["tags"]["Name"] != "prod-api-gateway"
        assert inst["tags"]["Env"] != "production-acme"

    def test_tags_non_dict_not_redacted(self) -> None:
        """Non-dict tags value is left untouched (isinstance guard)."""
        svc = _svc()
        inst = {"tags": ["tag1", "tag2"]}
        svc.redact_instance(inst)
        # Should not crash; list is unchanged
        assert inst["tags"] == ["tag1", "tag2"]

    def test_is_custom_with_non_standard_region_redacted(self) -> None:
        """Custom server with a non-AWS-region region string gets redact_provider."""
        svc = _svc()
        inst = {"is_custom": True, "region": "my-datacenter-rack-3"}
        svc.redact_instance(inst)
        assert inst["region"] != "my-datacenter-rack-3", (
            "Non-standard region on custom server should be redacted"
        )

    def test_is_custom_with_standard_aws_region_not_redacted(self) -> None:
        """Custom server with a standard AWS-style region must NOT be redacted."""
        svc = _svc()
        for region in ("us-east-1", "eu-west-1", "ap-southeast-2", "sa-east-1"):
            inst = {"is_custom": True, "region": region}
            svc.redact_instance(inst)
            assert inst["region"] == region, (
                f"Standard AWS region {region!r} should not be redacted"
            )

    def test_key_name_redacted(self) -> None:
        svc = _svc()
        inst = {"key_name": "acme-prod-key"}
        svc.redact_instance(inst)
        assert inst["key_name"] != "acme-prod-key"

    def test_provider_redacted(self) -> None:
        svc = _svc()
        inst = {"provider": "MyCustomCloud"}
        svc.redact_instance(inst)
        assert inst["provider"] != "MyCustomCloud"

    def test_missing_optional_fields_no_crash(self) -> None:
        """redact_instance must not crash when optional fields are absent."""
        svc = _svc()
        inst = {"name": "web-prod-7"}
        result = svc.redact_instance(inst)
        # Only name should change
        assert result["name"] != "web-prod-7"
        assert "private_ip" not in result

    def test_redact_instances_iterates_all(self) -> None:
        """redact_instances must redact all instances and return the list."""
        svc = _svc()
        instances = [
            {"name": "web-prod-1", "public_ip": "1.2.3.4"},
            {"name": "db-prod-1", "public_ip": "5.6.7.8"},
        ]
        result = svc.redact_instances(instances)
        assert result is instances  # same list reference (in-place mutation)
        assert instances[0]["name"] != "web-prod-1"
        assert instances[1]["name"] != "db-prod-1"
        assert instances[0]["public_ip"] != "1.2.3.4"
        assert instances[1]["public_ip"] != "5.6.7.8"


# ---------------------------------------------------------------------------
# 7. ServonautApp.notify — timeout=not-None path (line 144)
# ---------------------------------------------------------------------------


class TestNotifyTimeoutPath:
    """The timeout-is-not-None branch of notify() must forward timeout to super."""

    def test_notify_forwards_timeout_when_not_none(self) -> None:
        """When timeout is provided, super().notify must receive it."""
        from servonaut.app import ServonautApp

        app = MagicMock(spec=ServonautApp)
        app.demo_mode = False
        app.redaction_service = None

        captured: list = []

        def _super_notify(
            message, *, title="", severity="information", timeout=None, markup=True
        ):
            captured.append({
                "message": message,
                "timeout": timeout,
            })

        with patch("textual.app.App.notify", side_effect=_super_notify):
            ServonautApp.notify(app, "hello", timeout=4.0)

        assert captured, "super().notify was not called"
        assert captured[0]["timeout"] == 4.0, (
            f"timeout not forwarded to super().notify: {captured[0]!r}"
        )

    def test_notify_demo_mode_scrubs_with_timeout(self) -> None:
        """Demo mode scrubbing must apply even when timeout is provided."""
        from servonaut.app import ServonautApp

        app = MagicMock(spec=ServonautApp)
        app.demo_mode = True
        app.redaction_service = RedactionService()

        captured: list = []

        def _super_notify(
            message, *, title="", severity="information", timeout=None, markup=True
        ):
            captured.append({"message": message, "timeout": timeout})

        with patch("textual.app.App.notify", side_effect=_super_notify):
            ServonautApp.notify(app, "Server 10.0.0.1 failed", timeout=5.0)

        assert captured
        assert "10.0.0.1" not in captured[0]["message"], (
            f"IP leaked despite demo mode: {captured[0]['message']!r}"
        )
        assert captured[0]["timeout"] == 5.0
