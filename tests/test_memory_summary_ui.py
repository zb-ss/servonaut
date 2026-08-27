"""Focused TUI regressions for local and optional AI Memory summaries."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, call

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Button, Markdown, Select, Static

from servonaut.screens.memory import MemoryScreen
from servonaut.screens.memory_summary import (
    AIEnhanceConsentModal,
    MemorySummaryScreen,
)
from servonaut.services.memory.ai_summary_service import ProviderInfo
from servonaut.services.api_client import ValidationFailedError


_INSTANCE = {
    "id": "server-1",
    "name": "Example server",
    "provider": "custom",
}


def _module() -> dict[str, object]:
    return {
        "module": "os",
        "instance_id": _INSTANCE["id"],
        "observed": {"version": "1.0"},
        "declared": {},
        "probed_at": "2026-08-27T12:00:00+00:00",
        "ttl_seconds": 86400,
    }


def _memory_service(summary: str = "# Local summary\n\nLocal facts.") -> MagicMock:
    service = MagicMock()
    service.is_memory_disabled.return_value = False
    service.get_all_modules.return_value = {"os": _module()}
    service.stale_modules.return_value = []
    service.get_summary = AsyncMock(return_value=summary)
    return service


class _MemorySummaryApp(App):
    """Minimal app host exposing the services consumed by MemoryScreen."""

    def __init__(
        self,
        *,
        memory_service: MagicMock | None = None,
        ai_analysis_service: MagicMock | None = None,
        ai_summary_service: MagicMock | None = None,
        retrieval_service: MagicMock | None = None,
    ) -> None:
        super().__init__()
        self.demo_mode = False
        self.redaction_service = None
        self.memory_service = memory_service or _memory_service()
        self.memory_sync_service = None
        self.memory_retrieval_service = retrieval_service
        self.ai_analysis_service = ai_analysis_service
        self.ai_summary_service = ai_summary_service
        self.auth_service = MagicMock()
        self.auth_service.has_feature.return_value = False
        self.config_manager = MagicMock()
        self.config_manager.get.return_value = SimpleNamespace(
            memory=SimpleNamespace(ai_enhancement_prompt="Enhance faithfully.")
        )

    def on_mount(self) -> None:
        self.push_screen(MemoryScreen(dict(_INSTANCE)))


@pytest.mark.asyncio
async def test_local_view_summary_is_available_without_ai_entitlement() -> None:
    app = _MemorySummaryApp()

    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        hosted_status = app.screen.query_one("#memory-hosted-status", Static)
        enhance_button = app.screen.query_one("#btn_enhance_ai", Button)
        hosted_button = app.screen.query_one("#btn_build_ai", Button)
        assert enhance_button.parent is hosted_button.parent
        assert hosted_status.parent is not enhance_button.parent
        assert hosted_status.parent.id == "memory-container"
        inline_status = app.screen.query_one("#memory-ai-status", Static)
        inline_copy = str(inline_status.render())
        assert "Google Gemini" not in inline_copy
        await pilot.press("v")
        for _ in range(30):
            await pilot.pause(0.02)
            if isinstance(app.screen, MemorySummaryScreen):
                break

        assert isinstance(app.screen, MemorySummaryScreen)
        assert app.screen._summary.startswith("# Local summary")
        assert app.screen.query_one("#memory-summary-markdown", Markdown)
        assert (
            call("memory_ai_summary") not in app.auth_service.has_feature.call_args_list
        )


@pytest.mark.asyncio
async def test_ai_consent_modal_renders_guardrails_and_returns_selection() -> None:
    selected: list[str | None] = []

    class ModalHost(App):
        def compose(self) -> ComposeResult:
            yield Static("host")

        def on_mount(self) -> None:
            self.push_screen(
                AIEnhanceConsentModal(["openai", "ollama"]),
                selected.append,
            )

    app = ModalHost()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        disclosure = app.screen.query_one("#ai-enhance-guardrails", Static)
        assert "tools are disabled" in str(disclosure.render()).lower()
        assert "no fallback provider" in str(disclosure.render()).lower()

        app.screen.query_one("#ai-enhance-provider", Select).value = "ollama"
        await pilot.pause()
        await pilot.click("#ai-enhance-confirm")
        await pilot.pause()

    assert selected == ["ollama"]


@pytest.mark.asyncio
async def test_enhance_summary_uses_explicit_provider_and_opens_reader() -> None:
    ai_service = MagicMock()
    ai_service.available_memory_summary_providers.return_value = [
        "openai",
        "anthropic",
    ]
    ai_service.enhance_memory_summary = AsyncMock(
        return_value={"content": "# Enhanced\n\nVerified facts."}
    )
    app = _MemorySummaryApp(ai_analysis_service=ai_service)

    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        await pilot.press("A")
        await pilot.pause(0.1)
        assert isinstance(app.screen, AIEnhanceConsentModal)

        app.screen.query_one("#ai-enhance-provider", Select).value = "anthropic"
        await pilot.pause()
        await pilot.click("#ai-enhance-confirm")
        for _ in range(40):
            await pilot.pause(0.02)
            if isinstance(app.screen, MemorySummaryScreen):
                break

        assert isinstance(app.screen, MemorySummaryScreen)
        assert app.screen._summary.startswith("# Enhanced")

    ai_service.enhance_memory_summary.assert_awaited_once_with(
        "# Local summary\n\nLocal facts.",
        "anthropic",
        "Enhance faithfully.",
    )


@pytest.mark.asyncio
async def test_enhance_summary_failure_is_reported_without_fallback() -> None:
    ai_service = MagicMock()
    ai_service.available_memory_summary_providers.return_value = ["openai"]
    ai_service.enhance_memory_summary = AsyncMock(
        side_effect=ValidationFailedError(
            code="validation_failed",
            message="Request validation failed.",
            status=400,
            details={"detail": "messages[0].role system is not allowed"},
        )
    )
    app = _MemorySummaryApp(ai_analysis_service=ai_service)
    app.notify = MagicMock()

    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        await pilot.press("A")
        await pilot.pause(0.1)
        await pilot.click("#ai-enhance-confirm")
        for _ in range(30):
            await pilot.pause(0.02)
            if ai_service.enhance_memory_summary.await_count:
                break

    ai_service.enhance_memory_summary.assert_awaited_once()
    assert any(
        args.args
        and "messages[0].role system is not allowed" in str(args.args[0])
        and args.kwargs.get("severity") == "error"
        for args in app.notify.call_args_list
    )


@pytest.mark.asyncio
async def test_hosted_summary_result_is_decrypted_and_displayed() -> None:
    ai_summary_service = MagicMock()
    ai_summary_service.get_provider_info = AsyncMock(
        return_value=ProviderInfo(
            provider_name="Example AI",
            retention_days=0,
            retention_text="The provider retains this request for zero days.",
            supports_zdr=True,
        )
    )
    ai_summary_service.get_latest_summary = AsyncMock(
        return_value={"id": "old-envelope"}
    )
    ai_summary_service.request_consent_token = AsyncMock(
        return_value=SimpleNamespace(token="consent-placeholder", mode="server_60s")
    )
    ai_summary_service.dispatch_summary = AsyncMock(
        return_value=SimpleNamespace(
            status="queued",
            message="queued",
            correlation_supported=True,
            previous_summary_id="dispatch-envelope",
            poll_after_seconds=0.25,
        )
    )
    envelope = {
        "id": "new-envelope",
        "instance_id": "server-1",
        "module": "ai_summary",
    }
    ai_summary_service.wait_for_new_summary = AsyncMock(return_value=envelope)

    retrieval_service = MagicMock()
    retrieval_service.decrypt_envelope = AsyncMock(
        return_value=SimpleNamespace(
            plaintext={"summary": "# Hosted summary\n\nDecrypted result."}
        )
    )
    app = _MemorySummaryApp(
        ai_summary_service=ai_summary_service,
        retrieval_service=retrieval_service,
    )
    app._prompt_memory_passphrase = AsyncMock(return_value="placeholder-passphrase")

    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        await app.screen._do_ai_summary_flow("server-1")
        await pilot.pause(0.1)
        await pilot.click("#confirm_yes_btn")
        for _ in range(50):
            await pilot.pause(0.02)
            if isinstance(app.screen, MemorySummaryScreen):
                break

        assert isinstance(app.screen, MemorySummaryScreen)
        assert app.screen._summary.startswith("# Hosted summary")

    ai_summary_service.wait_for_new_summary.assert_awaited_once_with(
        "server-1",
        previous_envelope_id="dispatch-envelope",
        initial_poll_after_seconds=0.25,
    )
    retrieval_service.decrypt_envelope.assert_awaited_once_with(
        envelope,
        expected_instance_id="server-1",
        expected_module="ai_summary",
    )
