"""Tests for BugReportService — data-layer of the bug-reporting feature."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, call

import pytest

from servonaut.services.api_client import APIClient, APIError
from servonaut.services.bug_report_service import (
    BugReportConsent,
    BugReportPayload,
    BugReportReceipt,
    BugReportService,
    BugReportSubmissionError,
)


# ---------------------------------------------------------------------------
# Helpers / Factories
# ---------------------------------------------------------------------------

def _make_service(
    *,
    log_path: Optional[Path] = None,
    config_dict: Optional[Dict] = None,
    auth_token: Optional[str] = None,
    api_client=None,
    redactor=None,
) -> BugReportService:
    """Build a BugReportService with safe mocked dependencies."""
    config_manager = MagicMock()
    # config_manager.config returns a simple mock with asdict()-able fields
    mock_cfg = MagicMock()
    # Make dataclasses.asdict() work by supplying a plain dict via __dict__
    config_manager.config = mock_cfg
    if config_dict is not None:
        # Return the dict when asdict is called — we patch asdict in tests that need it.
        config_manager.config = mock_cfg

    auth_service = MagicMock()
    auth_service.access_token = auth_token  # None means anonymous

    update_service = MagicMock()
    update_service.current_version = "2.7.0"
    update_service.detect_install_method.return_value = "pipx"

    if api_client is None:
        api_client = MagicMock(spec=APIClient)

    kwargs: Dict[str, Any] = {}
    if log_path is not None:
        kwargs["log_path"] = log_path
    if redactor is not None:
        kwargs["redactor"] = redactor

    return BugReportService(
        config_manager=config_manager,
        api_client=api_client,
        auth_service=auth_service,
        update_service=update_service,
        **kwargs,
    )


def _minimal_consent(
    *,
    include_logs: bool = False,
    include_config: bool = False,
    include_anonymous_telemetry: bool = False,
    channel: str = "github",
) -> BugReportConsent:
    return BugReportConsent(
        include_logs=include_logs,
        include_config=include_config,
        include_anonymous_telemetry=include_anonymous_telemetry,
        channel=channel,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# collect_diagnostics tests
# ---------------------------------------------------------------------------

class TestCollectDiagnosticsMinimal:
    """All-off consent → all optional fields are None, telemetry dict empty."""

    def test_optional_fields_none_when_all_off(self, tmp_path: Path) -> None:
        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent()

        payload = svc.collect_diagnostics(consent=consent, instances=[])

        assert payload.log_excerpt is None
        assert payload.config_snapshot is None
        assert payload.last_traceback is None
        assert payload.instance_count_by_provider == {}

    def test_redacted_categories_empty_when_no_text(self, tmp_path: Path) -> None:
        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent()
        payload = svc.collect_diagnostics(consent=consent, instances=[])
        assert payload.redacted_categories_found == []

    def test_servonaut_version_from_update_service(self, tmp_path: Path) -> None:
        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent()
        payload = svc.collect_diagnostics(consent=consent, instances=[])
        assert payload.servonaut_version == "2.7.0"

    def test_install_method_from_update_service(self, tmp_path: Path) -> None:
        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent()
        payload = svc.collect_diagnostics(consent=consent, instances=[])
        assert payload.install_method == "pipx"

    def test_anonymous_auth_when_no_token(self, tmp_path: Path) -> None:
        svc = _make_service(log_path=tmp_path / "no_log.log", auth_token=None)
        consent = _minimal_consent()
        payload = svc.collect_diagnostics(consent=consent, instances=[])
        assert payload.auth_state == "anonymous"

    def test_signed_in_auth_when_token_present(self, tmp_path: Path) -> None:
        svc = _make_service(log_path=tmp_path / "no_log.log", auth_token="tok123")
        consent = _minimal_consent()
        payload = svc.collect_diagnostics(consent=consent, instances=[])
        assert payload.auth_state == "signed-in"


class TestCollectDiagnosticsRedaction:
    """Redaction correctness — planted secrets must be scrubbed."""

    def test_redacts_akia_key_in_log_and_reports_category(self, tmp_path: Path) -> None:
        log = tmp_path / "servonaut.log"
        log.write_text("INFO starting\nAKIA1234567890ABCDEF is the key\nINFO done\n")

        svc = _make_service(log_path=log)
        consent = _minimal_consent(include_logs=True)
        payload = svc.collect_diagnostics(
            consent=consent, instances=[], log_tail_lines=200
        )

        assert payload.log_excerpt is not None
        assert "AKIA1234567890ABCDEF" not in payload.log_excerpt
        assert "<redacted:aws-access-key>" in payload.log_excerpt
        assert "aws-access-key" in payload.redacted_categories_found

    def test_redacts_akia_key_in_traceback(self, tmp_path: Path) -> None:
        log = tmp_path / "servonaut.log"
        log.write_text(
            "INFO ok\n"
            "Traceback (most recent call last):\n"
            "  File 'x.py', line 1\n"
            "KeyError: AKIA1234567890ABCDEF\n"
        )
        svc = _make_service(log_path=log)
        consent = _minimal_consent()
        payload = svc.collect_diagnostics(consent=consent, instances=[])

        assert payload.last_traceback is not None
        assert "AKIA1234567890ABCDEF" not in payload.last_traceback
        assert "aws-access-key" in payload.redacted_categories_found


class TestCollectDiagnosticsConfigScrubbing:
    """api_key and other secret-named fields are removed from config snapshot."""

    def test_api_key_removed_before_redaction(self, tmp_path: Path) -> None:
        import dataclasses as _dc

        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent(include_config=True)

        # Patch dataclasses.asdict to return a dict with an api_key
        fake_config = {"provider": "openai", "api_key": "sk-supersecretvalue", "model": "gpt-4"}
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(_dc, "asdict", lambda _: dict(fake_config))
            payload = svc.collect_diagnostics(consent=consent, instances=[])

        assert payload.config_snapshot is not None
        assert payload.config_snapshot.get("api_key") == "<removed:secret-key>"
        # The real value must never appear
        assert "sk-supersecretvalue" not in str(payload.config_snapshot)

    def test_nested_secret_key_removed(self, tmp_path: Path) -> None:
        import dataclasses as _dc

        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent(include_config=True)

        fake_config = {
            "relay": {"token": "mytoken", "host": "relay.example.com"},
        }
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(_dc, "asdict", lambda _: dict(fake_config))
            payload = svc.collect_diagnostics(consent=consent, instances=[])

        assert payload.config_snapshot is not None
        assert payload.config_snapshot["relay"]["token"] == "<removed:secret-key>"
        assert payload.config_snapshot["relay"]["host"] == "relay.example.com"

    def test_provider_secret_keys_all_removed(self, tmp_path: Path) -> None:
        """Regression: OVH/AI/abuseipdb keys leaked because layer-1 only matched
        exact ``api_key`` / ``token`` / ``secret``. Now matches by suffix."""
        import dataclasses as _dc

        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent(include_config=True)

        fake_config = {
            "ai": {
                "provider": "openai",
                "api_key": "legacy-sk-LEAK1",
                "openai_api_key": "sk-LEAK2",
                "anthropic_api_key": "anth-LEAK3",
                "gemini_api_key": "AIza-LEAK4",
                "ollama_api_key": "ollama-LEAK5",
            },
            "ovh": {
                "endpoint": "ovh-eu",
                "application_key": "app-LEAK6",
                "application_secret": "secret-LEAK7",
                "consumer_key": "consumer-LEAK8",
                "client_id": "client-id-not-secret",
                "client_secret": "client-secret-LEAK9",
            },
            "ip_ban": {"abuseipdb_api_key": "abuse-LEAK10"},
        }
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(_dc, "asdict", lambda _: dict(fake_config))
            payload = svc.collect_diagnostics(consent=consent, instances=[])

        snap = payload.config_snapshot
        assert snap is not None
        for path in [
            ("ai", "api_key"),
            ("ai", "openai_api_key"),
            ("ai", "anthropic_api_key"),
            ("ai", "gemini_api_key"),
            ("ai", "ollama_api_key"),
            ("ovh", "application_key"),
            ("ovh", "application_secret"),
            ("ovh", "consumer_key"),
            ("ovh", "client_secret"),
            ("ip_ban", "abuseipdb_api_key"),
        ]:
            section, field = path
            assert snap[section][field] == "<removed:secret-key>", f"{path} not scrubbed: {snap[section][field]!r}"
        # client_id is an OAuth identifier, not a secret — must NOT be scrubbed
        assert snap["ovh"]["client_id"] == "client-id-not-secret"
        assert snap["ovh"]["endpoint"] == "ovh-eu"
        # No leaked value anywhere in the snapshot
        flat = json.dumps(snap)
        for leak in ["LEAK1", "LEAK2", "LEAK3", "LEAK4", "LEAK5",
                     "LEAK6", "LEAK7", "LEAK8", "LEAK9", "LEAK10"]:
            assert leak not in flat, f"{leak} leaked in snapshot: {flat}"

    def test_secret_suffix_does_not_falsely_match(self, tmp_path: Path) -> None:
        """Layer-1 must not scrub max_tokens (plural int), credentials_path
        (path), keyword_store_path, or non-string values like booleans."""
        import dataclasses as _dc

        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent(include_config=True)

        fake_config = {
            "ai": {"max_tokens": 4096, "credentials_path": "/etc/svc.json"},
            "keyword_store_path": "~/.servonaut/keywords.json",
            "memory": {"redaction_enabled": True, "secret": ""},  # empty secret stays as-is
            "name_with_password_in_middle": "harmless",  # only last segment matters
        }
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(_dc, "asdict", lambda _: dict(fake_config))
            payload = svc.collect_diagnostics(consent=consent, instances=[])

        snap = payload.config_snapshot
        assert snap is not None
        assert snap["ai"]["max_tokens"] == 4096
        assert snap["ai"]["credentials_path"] == "/etc/svc.json"
        assert snap["keyword_store_path"] == "~/.servonaut/keywords.json"
        assert snap["memory"]["redaction_enabled"] is True
        assert snap["memory"]["secret"] == ""  # empty string left alone
        assert snap["name_with_password_in_middle"] == "harmless"


class TestCollectDiagnosticsTelemetry:
    """instance_count_by_provider counts correctly."""

    def test_counts_by_provider_key(self, tmp_path: Path) -> None:
        instances = [
            {"provider": "aws"},
            {"provider": "aws"},
            {"provider": "ovh"},
            {"provider": "custom"},
        ]
        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent(include_anonymous_telemetry=True)
        payload = svc.collect_diagnostics(consent=consent, instances=instances)
        assert payload.instance_count_by_provider == {"aws": 2, "ovh": 1, "custom": 1}

    def test_falls_back_to_aws_when_provider_key_absent(self, tmp_path: Path) -> None:
        instances = [{"id": "i-abc"}, {"id": "i-def"}]  # no 'provider' key
        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent(include_anonymous_telemetry=True)
        payload = svc.collect_diagnostics(consent=consent, instances=instances)
        assert payload.instance_count_by_provider == {"aws": 2}

    def test_empty_when_telemetry_disabled(self, tmp_path: Path) -> None:
        instances = [{"provider": "aws"}, {"provider": "ovh"}]
        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent(include_anonymous_telemetry=False)
        payload = svc.collect_diagnostics(consent=consent, instances=instances)
        assert payload.instance_count_by_provider == {}


class TestLastTraceback:
    """last_traceback extraction from log tail."""

    def test_returns_none_when_no_log_file(self, tmp_path: Path) -> None:
        svc = _make_service(log_path=tmp_path / "missing.log")
        consent = _minimal_consent()
        payload = svc.collect_diagnostics(consent=consent, instances=[])
        assert payload.last_traceback is None

    def test_returns_none_when_no_traceback_in_log(self, tmp_path: Path) -> None:
        log = tmp_path / "servonaut.log"
        log.write_text("INFO ok\nINFO still ok\n")
        svc = _make_service(log_path=log)
        consent = _minimal_consent()
        payload = svc.collect_diagnostics(consent=consent, instances=[])
        assert payload.last_traceback is None

    def test_extracts_last_traceback_block(self, tmp_path: Path) -> None:
        log = tmp_path / "servonaut.log"
        log.write_text(
            "INFO a\n"
            "Traceback (most recent call last):\n"
            "  File 'a.py', line 1\n"
            "ValueError: first\n"
            "INFO b\n"
            "Traceback (most recent call last):\n"
            "  File 'b.py', line 2\n"
            "KeyError: second\n"
        )
        svc = _make_service(log_path=log)
        consent = _minimal_consent()
        payload = svc.collect_diagnostics(consent=consent, instances=[])
        # Should return the LAST traceback
        assert payload.last_traceback is not None
        assert "KeyError: second" in payload.last_traceback
        assert "ValueError: first" not in payload.last_traceback


class TestLogExcerpt:
    """log_excerpt behaviour."""

    def test_none_when_include_logs_false(self, tmp_path: Path) -> None:
        log = tmp_path / "servonaut.log"
        log.write_text("some log content\n")
        svc = _make_service(log_path=log)
        consent = _minimal_consent(include_logs=False)
        payload = svc.collect_diagnostics(consent=consent, instances=[])
        assert payload.log_excerpt is None

    def test_none_when_file_missing(self, tmp_path: Path) -> None:
        svc = _make_service(log_path=tmp_path / "no_file.log")
        consent = _minimal_consent(include_logs=True)
        payload = svc.collect_diagnostics(consent=consent, instances=[])
        assert payload.log_excerpt is None

    def test_includes_log_content_when_consented(self, tmp_path: Path) -> None:
        log = tmp_path / "servonaut.log"
        log.write_text("line1\nline2\nline3\n")
        svc = _make_service(log_path=log)
        consent = _minimal_consent(include_logs=True)
        payload = svc.collect_diagnostics(consent=consent, instances=[])
        assert payload.log_excerpt is not None
        assert "line1" in payload.log_excerpt


# ---------------------------------------------------------------------------
# render_preview tests
# ---------------------------------------------------------------------------

class TestRenderPreview:
    """Markdown preview structure."""

    def _make_minimal_payload(self) -> BugReportPayload:
        return BugReportPayload(
            servonaut_version="2.7.0",
            python_version="3.12.0",
            os_release="Linux 6.17.0",
            textual_version="0.80.0",
            install_method="pipx",
            auth_state="anonymous",
            instance_count_by_provider={},
            last_traceback=None,
            log_excerpt=None,
            config_snapshot=None,
            redacted_categories_found=[],
        )

    def test_includes_title_in_output(self) -> None:
        svc = _make_service()
        payload = self._make_minimal_payload()
        preview = svc.render_preview(
            payload=payload, title="My Bug Title", description="desc"
        )
        assert "My Bug Title" in preview

    def test_includes_environment_header(self) -> None:
        svc = _make_service()
        payload = self._make_minimal_payload()
        preview = svc.render_preview(
            payload=payload, title="T", description="D"
        )
        assert "## Environment" in preview

    def test_omits_log_excerpt_section_when_none(self) -> None:
        svc = _make_service()
        payload = self._make_minimal_payload()
        preview = svc.render_preview(
            payload=payload, title="T", description="D"
        )
        assert "## Log excerpt" not in preview

    def test_includes_log_excerpt_when_present(self) -> None:
        svc = _make_service()
        payload = dataclasses.replace(
            self._make_minimal_payload(), log_excerpt="some log line"
        )
        preview = svc.render_preview(
            payload=payload, title="T", description="D"
        )
        assert "## Log excerpt" in preview
        assert "some log line" in preview

    def test_omits_traceback_section_when_none(self) -> None:
        svc = _make_service()
        payload = self._make_minimal_payload()
        preview = svc.render_preview(payload=payload, title="T", description="D")
        assert "## Last traceback" not in preview

    def test_includes_traceback_when_present(self) -> None:
        svc = _make_service()
        payload = dataclasses.replace(
            self._make_minimal_payload(),
            last_traceback="Traceback (most recent call last):\n  ...\nValueError: boom",
        )
        preview = svc.render_preview(payload=payload, title="T", description="D")
        assert "## Last traceback" in preview
        assert "ValueError: boom" in preview

    def test_omits_config_section_when_none(self) -> None:
        svc = _make_service()
        payload = self._make_minimal_payload()
        preview = svc.render_preview(payload=payload, title="T", description="D")
        assert "## Config snapshot" not in preview

    def test_includes_redacted_categories_when_present(self) -> None:
        svc = _make_service()
        payload = dataclasses.replace(
            self._make_minimal_payload(),
            redacted_categories_found=["aws-access-key", "jwt"],
        )
        preview = svc.render_preview(payload=payload, title="T", description="D")
        assert "## Redacted categories detected" in preview
        assert "aws-access-key" in preview
        assert "jwt" in preview

    def test_includes_description_in_output(self) -> None:
        svc = _make_service()
        payload = self._make_minimal_payload()
        preview = svc.render_preview(
            payload=payload, title="T", description="This is my description"
        )
        assert "This is my description" in preview

    def test_separator_present(self) -> None:
        svc = _make_service()
        payload = self._make_minimal_payload()
        preview = svc.render_preview(payload=payload, title="T", description="D")
        assert "---" in preview


# ---------------------------------------------------------------------------
# submit — github channel
# ---------------------------------------------------------------------------

class TestSubmitGitHub:
    """GitHub channel produces correct URL; no network call."""

    @pytest.mark.asyncio
    async def test_url_contains_issues_new(self, tmp_path: Path) -> None:
        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent(channel="github")
        payload = svc.collect_diagnostics(consent=consent, instances=[])

        receipt = await svc.submit(
            payload=payload,
            consent=consent,
            title="Test bug",
            description="Repro steps here",
        )

        assert "issues/new?title=" in receipt.url

    @pytest.mark.asyncio
    async def test_url_contains_urlencoded_title(self, tmp_path: Path) -> None:
        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent(channel="github")
        payload = svc.collect_diagnostics(consent=consent, instances=[])

        title = "My Bug With Spaces"
        receipt = await svc.submit(
            payload=payload, consent=consent, title=title, description="desc"
        )

        # URL-encoded spaces are either + or %20
        assert "My+Bug+With+Spaces" in receipt.url or "My%20Bug%20With%20Spaces" in receipt.url

    @pytest.mark.asyncio
    async def test_report_id_is_none(self, tmp_path: Path) -> None:
        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent(channel="github")
        payload = svc.collect_diagnostics(consent=consent, instances=[])

        receipt = await svc.submit(
            payload=payload, consent=consent, title="T", description="D"
        )

        assert receipt.report_id is None

    @pytest.mark.asyncio
    async def test_channel_is_github(self, tmp_path: Path) -> None:
        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent(channel="github")
        payload = svc.collect_diagnostics(consent=consent, instances=[])

        receipt = await svc.submit(
            payload=payload, consent=consent, title="T", description="D"
        )
        assert receipt.channel == "github"

    @pytest.mark.asyncio
    async def test_submitted_at_iso_format(self, tmp_path: Path) -> None:
        svc = _make_service(log_path=tmp_path / "no_log.log")
        consent = _minimal_consent(channel="github")
        payload = svc.collect_diagnostics(consent=consent, instances=[])

        receipt = await svc.submit(
            payload=payload, consent=consent, title="T", description="D"
        )
        # Must end with Z and contain T separator
        assert receipt.submitted_at_iso.endswith("Z")
        assert "T" in receipt.submitted_at_iso

    @pytest.mark.asyncio
    async def test_api_client_not_called_for_github(self, tmp_path: Path) -> None:
        api_client = MagicMock(spec=APIClient)
        svc = _make_service(log_path=tmp_path / "no_log.log", api_client=api_client)
        consent = _minimal_consent(channel="github")
        payload = svc.collect_diagnostics(consent=consent, instances=[])

        await svc.submit(payload=payload, consent=consent, title="T", description="D")

        api_client.post.assert_not_called()


# ---------------------------------------------------------------------------
# submit — backend channel
# ---------------------------------------------------------------------------

class TestSubmitBackend:
    """Backend channel calls api_client.post exactly once with correct args."""

    def _make_api_client(self, response: Dict) -> MagicMock:
        client = MagicMock(spec=APIClient)
        client.post = AsyncMock(return_value=response)
        return client

    @pytest.mark.asyncio
    async def test_calls_post_with_json_keyword(self, tmp_path: Path) -> None:
        api_client = self._make_api_client(
            {"id": "rpt-123", "url": "https://servonaut.dev/bugs/rpt-123"}
        )
        svc = _make_service(log_path=tmp_path / "no_log.log", api_client=api_client)
        consent = _minimal_consent(channel="backend")
        payload = svc.collect_diagnostics(consent=consent, instances=[])

        await svc.submit(payload=payload, consent=consent, title="T", description="D")

        api_client.post.assert_called_once()
        call_args = api_client.post.call_args
        # Must be called with json= keyword (not positional)
        assert call_args.kwargs.get("json") is not None or (
            "json" in call_args[1]
        ), "post() must be called with json= keyword argument"
        assert call_args.args[0] == "/api/v1/bug-reports"

    @pytest.mark.asyncio
    async def test_receipt_url_from_response(self, tmp_path: Path) -> None:
        api_client = self._make_api_client(
            {"id": "rpt-456", "url": "https://servonaut.dev/bugs/rpt-456"}
        )
        svc = _make_service(log_path=tmp_path / "no_log.log", api_client=api_client)
        consent = _minimal_consent(channel="backend")
        payload = svc.collect_diagnostics(consent=consent, instances=[])

        receipt = await svc.submit(
            payload=payload, consent=consent, title="T", description="D"
        )

        assert receipt.url == "https://servonaut.dev/bugs/rpt-456"
        assert receipt.report_id == "rpt-456"
        assert receipt.channel == "backend"

    @pytest.mark.asyncio
    async def test_payload_asdict_included_in_post_body(self, tmp_path: Path) -> None:
        api_client = self._make_api_client(
            {"id": "rpt-789", "url": "https://servonaut.dev/bugs/rpt-789"}
        )
        svc = _make_service(log_path=tmp_path / "no_log.log", api_client=api_client)
        consent = _minimal_consent(channel="backend")
        payload = svc.collect_diagnostics(consent=consent, instances=[])

        await svc.submit(payload=payload, consent=consent, title="My Title", description="My Desc")

        call_kwargs = api_client.post.call_args.kwargs
        json_body = call_kwargs["json"]
        assert json_body["title"] == "My Title"
        assert json_body["description"] == "My Desc"
        assert "payload" in json_body
        assert json_body["payload"]["servonaut_version"] == "2.7.0"

    @pytest.mark.asyncio
    async def test_api_error_raises_submission_error(self, tmp_path: Path) -> None:
        api_client = MagicMock(spec=APIClient)
        api_client.post = AsyncMock(
            side_effect=APIError(
                code="server_error",
                message="Internal server error",
                status=500,
            )
        )
        svc = _make_service(log_path=tmp_path / "no_log.log", api_client=api_client)
        consent = _minimal_consent(channel="backend")
        payload = svc.collect_diagnostics(consent=consent, instances=[])

        with pytest.raises(BugReportSubmissionError) as exc_info:
            await svc.submit(payload=payload, consent=consent, title="T", description="D")

        assert exc_info.value.cause is not None
        assert isinstance(exc_info.value.cause, APIError)

    @pytest.mark.asyncio
    async def test_api_error_subclass_also_raises_submission_error(
        self, tmp_path: Path
    ) -> None:
        from servonaut.services.api_client import RateLimitedError

        api_client = MagicMock(spec=APIClient)
        api_client.post = AsyncMock(
            side_effect=RateLimitedError(
                code="rate_limited", message="slow down", status=429
            )
        )
        svc = _make_service(log_path=tmp_path / "no_log.log", api_client=api_client)
        consent = _minimal_consent(channel="backend")
        payload = svc.collect_diagnostics(consent=consent, instances=[])

        with pytest.raises(BugReportSubmissionError):
            await svc.submit(payload=payload, consent=consent, title="T", description="D")


# ---------------------------------------------------------------------------
# Import smoke test (also checked by verify step)
# ---------------------------------------------------------------------------

def test_public_exports_importable() -> None:
    from servonaut.services.bug_report_service import (  # noqa: F401
        BugReportService,
        BugReportConsent,
        BugReportPayload,
        BugReportReceipt,
        BugReportSubmissionError,
    )
