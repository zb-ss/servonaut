"""Memory dialogs retain explicit consent, typed results and snapshot lifetimes."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Markdown, Select, Static

from servonaut.screens.fleet_memory import FleetScanSummaryModal
from servonaut.screens.memory_drift import DriftDiffScreen
from servonaut.screens.memory_key_change import MemberKeyChangeScreen
from servonaut.screens.memory_share import PurgeCopiesModal
from servonaut.screens.memory_summary import AIEnhanceConsentModal, MemorySummaryScreen
from servonaut.widgets.upsell_modal import UpsellModal
from servonaut.widgets.dialogs import DialogActions, DialogFrame
from servonaut.widgets.sidebar import Sidebar
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import ReflowCase, assert_layout, collapse_chat, open_case, open_chat, tab_to
from tests.test_memory_key_change_screen import NEW_FP, OLD_FP, _change
from tests.test_memory_summary_ui import _MemorySummaryApp
from tests.test_selection_copy import _Clipboard, _drag
from tests.test_selection_copy import clipboard as clipboard
from tests.test_workspace_memory_fleet_reflow import (
    CASES, _MemoryHost, _event, _fake_memory_boundaries as _fake_memory_boundaries, _opener,
)
from tests.test_workspace_pilot import _click
from tests.test_workspace_reflow import _painted

pytestmark = pytest.mark.usefixtures("navigation_open")


# Baseline native IDs must come from the original source producer, not inference.
ORIGINAL_MODAL_FOCUS: dict[str, str] | None = {
    'fleet': 'fleet-scan-failures',
    'diff': 'drift-diff-body',
    'purge': 'purge-btn-cancel',
    'ai': 'ai-enhance-provider',
}


def _modal(kind: str, app: _MemoryHost) -> ModalScreen:
    if kind == "fleet":
        return FleetScanSummaryModal(["web-1"], [], ["db-1"])
    if kind == "diff":
        return DriftDiffScreen(_event(), app.memory_retrieval_service)
    if kind == "purge":
        return PurgeCopiesModal()
    return AIEnhanceConsentModal(["ollama", "example-provider"])


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,finish,expected", [
    ("fleet", "button", None), ("fleet", "escape", None),
    ("diff", "button", None), ("diff", "escape", None),
    ("purge", "cancel", False), ("purge", "escape", False), ("purge", "confirm", True),
    ("ai", "cancel", None), ("ai", "escape", None), ("ai", "confirm", "example-provider"),
])
async def test_memory_modal_native_close_results_once(kind: str, finish: str, expected: object) -> None:
    app = _MemoryHost()
    results: list[object] = []
    async with app.run_test(size=(100, 30)) as pilot:
        origin = app.focused
        modal = _modal(kind, app)
        await app.push_screen(modal, results.append)
        await pilot.pause()
        if kind == "purge":
            assert app.focused is modal.query_one("#purge-btn-cancel")
        elif kind == "ai":
            select = modal.query_one("#ai-enhance-provider", Select)
            assert app.focused is select
            select.value = "example-provider"
            await wait_until(lambda: "Example-Provider" in modal.query_one("#ai-enhance-disclosure", Static).render().plain)
        if finish == "escape":
            await pilot.press("escape")
        else:
            button = {
                "fleet": "#btn_close", "diff": "#drift-diff-close",
                "purge": "#purge-btn-confirm" if finish == "confirm" else "#purge-btn-cancel",
                "ai": "#ai-enhance-confirm" if finish == "confirm" else "#ai-enhance-cancel",
            }[kind]
            await _click(pilot, button)
        await wait_until(lambda: bool(results))
        assert results == [expected] and app.focused is origin
        app.team_memory_service.purge_grant.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["fleet", "diff", "purge", "ai"])
async def test_memory_modal_native_initial_focus_matches_qualified_original(kind: str) -> None:
    assert ORIGINAL_MODAL_FOCUS is not None and kind in ORIGINAL_MODAL_FOCUS, "Qualify original native modal focus IDs before acceptance"
    app = _MemoryHost()
    async with app.run_test(size=(160, 50)) as pilot:
        modal = _modal(kind, app)
        await app.push_screen(modal)
        await pilot.pause()
        assert app.focused is modal.query_one("#" + ORIGINAL_MODAL_FOCUS[kind])


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["share", "catch_up"])
@pytest.mark.parametrize("cancel", [False, True])
async def test_key_change_native_ticks_fingerprints_result_survive_chat_replacement(mode: str, cancel: bool) -> None:
    app = _MemoryHost(False)
    changes = [_change(2, "Lee [literal] Ω"), _change(3, "Kim")]
    results: list[object] = []
    async with app.run_test(size=(160, 50)) as pilot:
        screen = MemberKeyChangeScreen(changes, mode=mode)
        await app.push_screen(screen, results.append)
        await pilot.pause()
        assert app.focused is screen.query_one("#keychange-btn-cancel")
        text = "\n".join(widget.render().plain for widget in screen.query(".keychange-details"))
        assert NEW_FP[:24] + "…" in text and OLD_FP[:24] + "…" in text
        assert "Lee [literal] Ω" in text
        first = screen.query_one("#keychange-check-0", Checkbox)
        await tab_to(pilot, first)
        await pilot.press("space")
        await wait_until(lambda: first.value)
        confirm = screen.query_one("#keychange-btn-confirm", Button)
        await pilot.pause()
        assert confirm.disabled is (mode == "share")
        await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        await collapse_chat(app, pilot, screen)
        assert first.value and not screen.query_one("#keychange-check-1", Checkbox).value
        if cancel:
            await _click(pilot, "#keychange-btn-cancel")
        else:
            if mode == "share":
                second = screen.query_one("#keychange-check-1", Checkbox)
                await tab_to(pilot, second)
                await pilot.press("space")
            await wait_until(lambda: not confirm.disabled)
            await _click(pilot, "#keychange-btn-confirm")
        await wait_until(lambda: bool(results))
        assert results == [None if cancel else (changes if mode == "share" else changes[:1])]
        app.team_memory_service.share_instance.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True])
async def test_drift_diff_native_loading_error_and_literal_snapshot_finish(failure: bool) -> None:
    app = _MemoryHost()
    started, release = asyncio.Event(), asyncio.Event()

    async def snapshot(instance_id: str, module: str, envelope_id: str) -> SimpleNamespace:
        started.set()
        await release.wait()
        if failure:
            raise RuntimeError("[literal] snapshot failure")
        return SimpleNamespace(plaintext={"note": "before" if envelope_id == "old-one" else "after café [literal] Ω"})

    app.memory_retrieval_service.get_snapshot.side_effect = snapshot
    async with app.run_test(size=(100, 30)) as pilot:
        screen = DriftDiffScreen(_event(), app.memory_retrieval_service)
        await app.push_screen(screen)
        try:
            await wait_until(started.is_set)
            label = screen.query_one("#drift-diff-content", Static)
            assert "Loading snapshot diff" in label.render().plain
        finally:
            release.set()
        await wait_until(lambda: "Loading snapshot diff" not in label.render().plain)
        if failure:
            assert "[literal] snapshot failure" in label.render().plain
        else:
            assert r"after caf\u00e9 [literal] \u03a9" in label.render().plain
        await _click(pilot, "#drift-diff-close")
        await wait_until(lambda: app.screen is not screen)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,theme", [("fleet", "servonaut"), ("diff", "ansi-dark"), ("purge", "servonaut-light"), ("ai", "ansi-light")])
async def test_memory_modal_named_palette_actions_remain_native_targets(kind: str, theme: str) -> None:
    app = _MemoryHost()
    app.theme = theme
    assert app.config_manager.get().theme == theme
    async with app.run_test(size=(100, 30)) as pilot:
        modal = _modal(kind, app)
        await app.push_screen(modal)
        await pilot.pause()
        frame = modal.query_one(DialogFrame)
        for button in modal.query_one(DialogActions).query(Button):
            assert frame.content_region.contains_region(button.region)
            assert modal.region.contains_region(button.region)
            assert app.get_widget_at(*button.region.center)[0] is button
            assert button.label.plain in _painted(app, button)


@pytest.mark.asyncio
@pytest.mark.parametrize("confirm", [False, True])
async def test_share_native_purge_callback_keeps_destructive_confirmation_boundary(confirm: bool) -> None:
    app = _MemoryHost(False)
    app.team_memory_service.find_live_grant.return_value = SimpleNamespace(id="grant-one", required_role="member", modules=["os"], status="active")
    if confirm:
        app.team_memory_service.purge_grant.side_effect = None
        app.team_memory_service.purge_grant.return_value = 2
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _opener("share")(app, pilot)
        button = screen.query_one("#share-btn-purge", Button)
        button.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        assert await pilot.click(button)
        await wait_until(lambda: isinstance(app.screen, PurgeCopiesModal))
        modal = app.screen
        await wait_until(lambda: modal.is_mounted and app.focused is modal.query_one("#purge-btn-cancel"))
        app.team_memory_service.purge_grant.assert_not_awaited()
        await pilot.press("shift+f6", "f2", "ctrl+g")
        assert app.screen is modal and app.focused is modal.query_one("#purge-btn-cancel")
        await _click(pilot, "#purge-btn-confirm" if confirm else "#purge-btn-cancel")
        await wait_until(lambda: app.screen is screen)
        if confirm:
            await wait_until(lambda: app.team_memory_service.purge_grant.await_count == 1)
            app.team_memory_service.purge_grant.assert_awaited_once_with("example-team", "grant-one")
        else:
            app.team_memory_service.purge_grant.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_ai_optin_real_caller_sends_only_after_exact_provider_consent(cancel: bool) -> None:
    service = MagicMock()
    service.available_memory_summary_providers.return_value = ["openai", "anthropic"]
    service.enhance_memory_summary = AsyncMock(return_value={"content": "# Enhanced\n\nFacts café Ω."})
    app = _MemorySummaryApp(ai_analysis_service=service)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        await pilot.press("A")
        await wait_until(lambda: isinstance(app.screen, AIEnhanceConsentModal))
        modal = app.screen
        field = modal.query_one("#ai-enhance-provider", Select)
        await wait_until(lambda: app.focused is field)
        field.value = "anthropic"
        await wait_until(lambda: "Anthropic" in modal.query_one("#ai-enhance-disclosure", Static).render().plain)
        assert "no fallback provider" in modal.query_one("#ai-enhance-guardrails", Static).render().plain
        service.enhance_memory_summary.assert_not_awaited()
        await _click(pilot, "#ai-enhance-cancel" if cancel else "#ai-enhance-confirm")
        if cancel:
            await wait_until(lambda: app.screen is not modal)
            service.enhance_memory_summary.assert_not_awaited()
        else:
            await wait_until(lambda: isinstance(app.screen, MemorySummaryScreen))
            await wait_until(lambda: any(
                node.is_mounted and node.source == "# Enhanced\n\nFacts café Ω."
                for node in app.screen.query(Markdown)
            ))
            assert app.screen.query_one(Markdown).source == "# Enhanced\n\nFacts café Ω."
            service.enhance_memory_summary.assert_awaited_once_with("# Local summary\n\nLocal facts.", "anthropic", "Enhance faithfully.")


@pytest.mark.asyncio
@pytest.mark.parametrize("writer_succeeds", [False, True])
async def test_memory_summary_static_selection_after_reflow_remains_literal_once(clipboard: _Clipboard, writer_succeeds: bool) -> None:
    app = _MemoryHost(False)
    clipboard.succeeds = writer_succeeds
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(CASES[2], app, pilot)
        await open_chat(app, pilot, screen)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        await collapse_chat(app, pilot, screen)
        label = screen.query_one("#memory-summary-title", Static)
        expected = "Summary café [literal] Ω"
        await _drag(pilot, label, (0, 0), (len(expected), 0))
        assert clipboard.calls == [expected]
        if not writer_succeeds:
            assert app.clipboard == expected


@pytest.mark.asyncio
async def test_long_fleet_summary_scroll_keeps_aggregate_and_close_target_literal() -> None:
    app = _MemoryHost()
    failed = [{"instance": f"web-{i} [literal] Ω", "reason": "fixture failure", "failures": []} for i in range(40)]
    async with app.run_test(size=(100, 30)) as pilot:
        modal = FleetScanSummaryModal(["db-1"], failed, ["stopped-1"])
        await app.push_screen(modal)
        await pilot.pause()
        body = modal.query_one("#fleet-scan-failures", VerticalScroll)
        close = modal.query_one("#btn_close", Button)
        assert "1 succeeded" in modal.query_one("#fleet-scan-title", Static).render().plain
        before = close.region
        await tab_to(pilot, body)
        await pilot.press("end")
        await pilot.pause()
        assert body.scroll_y > 0
        assert "stopped-1" in _painted(app, body)
        assert "web-39 [literal] Ω" in modal.query_one("#fleet-scan-body", Static).render().plain
        assert close.region == before and app.get_widget_at(*before.center)[0] is close
        await _click(pilot, "#btn_close")


@pytest.mark.asyncio
async def test_drift_native_row_opens_exact_snapshot_pair_and_closes_to_same_table() -> None:
    app = _MemoryHost(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _opener("drift")(app, pilot)
        table = screen.query_one("#drift-table")
        table.focus()
        await pilot.press("enter")
        await wait_until(lambda: isinstance(app.screen, DriftDiffScreen))
        modal = app.screen
        content_widget = modal.query_one("#drift-diff-content", Static)
        await wait_until(lambda: r"after caf\u00e9 [literal] \u03a9" in content_widget.render().plain)
        assert app.memory_retrieval_service.get_snapshot.await_args_list[0].args == ("id-web-1", "os", "old-one")
        assert app.memory_retrieval_service.get_snapshot.await_args_list[1].args == ("id-web-1", "os", "new-one")
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
        assert screen.query_one("#drift-table") is table and table.cursor_row == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["share", "drift"])
async def test_memory_entitlement_gate_keeps_native_modal_chat_barrier(kind: str) -> None:
    app = _MemoryHost(False)
    app.auth_service.has_feature.return_value = False
    app.auth_service.has_feature.side_effect = None
    async with app.run_test(size=(100, 30)) as pilot:
        if kind == "share":
            from servonaut.screens.memory_share import ShareInstanceScreen
            await app.push_screen(ShareInstanceScreen(app.instances[0]))
        else:
            from servonaut.screens.memory_drift import MemoryDriftScreen
            await app.push_screen(MemoryDriftScreen())
        await wait_until(lambda: (
            isinstance(app.screen, UpsellModal)
            and app.screen.is_mounted
            and bool(app.screen.query("#upsell-btn-close"))
        ))
        modal = app.screen
        close = modal.query_one("#upsell-btn-close", Button)
        await wait_until(lambda: app.focused is close)
        before = app.focused
        await pilot.press("f2", "ctrl+g", "shift+f6")
        assert app.screen is modal and app.focused is before
        assert not modal.query("#chat-panel")
        if kind == "share":
            app.auth_service.list_teams.assert_not_awaited()
        else:
            app.drift_service.list_drift.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
async def test_memory_child_modal_preference_resume_keeps_visible_origin(case: ReflowCase) -> None:
    app = case.app_factory(True)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await open_case(case, app, pilot)
        await open_chat(app, pilot, screen)
        modal = PurgeCopiesModal()
        await app.push_screen(modal)
        await wait_until(lambda: app.focused is modal.query_one("#purge-btn-cancel"))
        app.workspace_state.navigation_visible = False
        await pilot.press("shift+f6", "f2", "ctrl+g")
        assert app.screen is modal and app.focused is modal.query_one("#purge-btn-cancel")
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
        await pilot.pause()
        assert not screen.query_one(Sidebar).display
        assert_layout(app, screen)
        assert app.focused is not None and app.focused.visible and app.focused.region


@pytest.mark.asyncio
async def test_ai_consent_select_overlay_keeps_only_configured_provider_results() -> None:
    # No blank choice is offered; qualify the original native overlay journey.
    app = _MemoryHost()
    results: list[object] = []
    async with app.run_test(size=(100, 30)) as pilot:
        modal = AIEnhanceConsentModal(["ollama", "example-provider"])
        await app.push_screen(modal, results.append)
        field = modal.query_one("#ai-enhance-provider", Select)
        await wait_until(lambda: app.focused is field)
        await pilot.press("space", "down", "escape")
        await pilot.pause()
        assert app.screen is modal and results == []
        assert field.value in {"ollama", "example-provider"}
        chosen = str(field.value)
        await _click(pilot, "#ai-enhance-confirm")
        await wait_until(lambda: bool(results))
        assert results == [chosen]
