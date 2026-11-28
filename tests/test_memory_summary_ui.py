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


def _unlocked_memory_sync(app: App) -> None:
    """Give the host app the public unlock surface the summary flow uses."""
    app.memory_sync_service = SimpleNamespace(key_source="vault")
    app.unlock_memory_sync_for_summary = AsyncMock(return_value=True)
    app.request_memory_passphrase = AsyncMock(return_value="placeholder-passphrase")


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
    ai_summary_service.run_summary = AsyncMock(
        return_value=SimpleNamespace(
            status="queued",
            message="queued",
            correlation_supported=True,
            previous_summary_id="dispatch-envelope",
            poll_after_seconds=0.25,
            queued_at="2026-11-28T10:00:00+00:00",
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
    _unlocked_memory_sync(app)

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

    # No passphrase dialog: the key form needs none, and the screen no longer
    # reaches for the app's private prompt.
    app.request_memory_passphrase.assert_not_awaited()
    ai_summary_service.run_summary.assert_awaited_once()
    assert "passphrase" not in ai_summary_service.run_summary.await_args.kwargs
    ai_summary_service.wait_for_new_summary.assert_awaited_once_with(
        "server-1",
        previous_envelope_id="dispatch-envelope",
        initial_poll_after_seconds=0.25,
        queued_at="2026-11-28T10:00:00+00:00",
    )
    retrieval_service.decrypt_envelope.assert_awaited_once_with(
        envelope,
        expected_instance_id="server-1",
        expected_module="ai_summary",
    )


def _hosted_service(*, run_summary: AsyncMock, wait: AsyncMock | None = None) -> MagicMock:
    service = MagicMock()
    service.get_provider_info = AsyncMock(
        return_value=ProviderInfo(
            provider_name="Example AI",
            retention_days=0,
            retention_text="The provider retains this request for zero days.",
            supports_zdr=True,
        )
    )
    service.get_latest_summary = AsyncMock(return_value=None)
    service.run_summary = run_summary
    service.wait_for_new_summary = wait or AsyncMock(return_value=None)
    return service


async def _run_hosted_flow(app: App, pilot) -> list[str]:
    """Run the flow through the consent dialog; return the toast texts."""
    app.notify = MagicMock()
    await pilot.pause(0.2)
    await app.screen._do_ai_summary_flow("server-1")
    await pilot.pause(0.1)
    await pilot.click("#confirm_yes_btn")
    for _ in range(50):
        await pilot.pause(0.02)
    return [str(c.args[0]) for c in app.notify.call_args_list]


@pytest.mark.asyncio
async def test_consent_dialog_says_keys_not_passphrase_are_sent() -> None:
    service = _hosted_service(run_summary=AsyncMock())
    app = _MemorySummaryApp(ai_summary_service=service)
    _unlocked_memory_sync(app)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        await app.screen._do_ai_summary_flow("server-1")
        await pilot.pause(0.1)
        text = " ".join(str(w.render()) for w in app.screen.query(Static))
        assert (
            "Servonaut sends the keys for the memory being summarised, "
            "not your Memory Sync key or passphrase." in text
        )


def _failure_cases() -> list:
    from servonaut.services.memory.ai_summary_service import (
        HostedSummaryUnavailable,
        SummaryFailed,
    )
    from servonaut.services.memory.interfaces import VaultCustodyLocked
    from servonaut.services.memory.retrieval_service import StaleEnvelopes

    return [
        (SummaryFailed("decryption_failed"),
         "The summary could not be created (the memory could not be opened with the keys that were sent)."),
        (SummaryFailed("brand_new_code"),
         "The summary could not be created (the service reported a problem)."),
        (HostedSummaryUnavailable(),
         "Hosted summaries are not available for a key kept in the vault on this "
         "Servonaut service yet. Try again later."),
        (StaleEnvelopes(), "Memory changed while the summary was being prepared. Try again."),
        (VaultCustodyLocked("vault_locked"),
         "Your Memory Sync key is kept in your vault. Unlock or add this device to "
         "your vault to use Memory Sync here."),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("error, expected", _failure_cases())
async def test_hosted_summary_failures_show_plain_text(error, expected) -> None:
    service = _hosted_service(run_summary=AsyncMock(side_effect=error))
    app = _MemorySummaryApp(ai_summary_service=service)
    _unlocked_memory_sync(app)
    async with app.run_test(headless=True) as pilot:
        toasts = await _run_hosted_flow(app, pilot)
    assert expected in toasts
    # The raw code never reaches the user.
    assert not any("brand_new_code" in t or "decryption_failed" in t for t in toasts)


@pytest.mark.asyncio
async def test_hosted_summary_stops_when_memory_sync_stays_locked() -> None:
    service = _hosted_service(run_summary=AsyncMock())
    app = _MemorySummaryApp(ai_summary_service=service)
    _unlocked_memory_sync(app)
    app.unlock_memory_sync_for_summary = AsyncMock(return_value=False)
    async with app.run_test(headless=True) as pilot:
        await _run_hosted_flow(app, pilot)
    service.run_summary.assert_not_awaited()
    app.request_memory_passphrase.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancelled_passphrase_fallback_is_a_cancel_not_an_error() -> None:
    async def run_summary(instance_id, *, passphrase_provider, **_kw):
        await passphrase_provider()

    service = _hosted_service(run_summary=AsyncMock(side_effect=run_summary))
    app = _MemorySummaryApp(ai_summary_service=service)
    _unlocked_memory_sync(app)
    app.request_memory_passphrase = AsyncMock(side_effect=RuntimeError("cancelled"))
    async with app.run_test(headless=True) as pilot:
        toasts = await _run_hosted_flow(app, pilot)
    assert "Hosted summary cancelled." in toasts
    assert not any(t.startswith("Hosted summary failed") for t in toasts)
