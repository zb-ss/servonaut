"""Security child dialogs retain results, barriers and guarded mutations."""

from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest
from textual.widgets import Button, DataTable, Input, Select, Static

from servonaut.screens.cloudtrail_browser import (
    CloudTrailBrowserScreen, FilterValueModal, _TYPE_A_VALUE,
)
from servonaut.screens.cloudwatch_browser import CloudWatchBrowserScreen
from servonaut.screens.findings import FindingDetailScreen, FindingsScreen
from servonaut.screens.ip_ban import IPBanScreen
from servonaut.screens.remediation_confirm import RemediationConfirmModal
from servonaut.services.redaction_service import RedactionService
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import ReflowCase, assert_essential_targets, assert_layout, collapse_chat, open_case, open_chat
from tests.test_findings_screen import _revertible_finding, _revert_preview
from tests.test_workspace_security_reflow import (
    CASES, TRAIL, _SecurityHost, _fake_boundaries as _fake_boundaries, _opener,
)
from tests.test_workspace_pilot import _click
from tests.test_workspace_reflow import _painted


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,value,expected", [
    ("enter", "  CaseSensitive café [literal] Ω  ", "CaseSensitive café [literal] Ω"),
    ("pointer", "  CaseSensitive café [literal] Ω  ", "CaseSensitive café [literal] Ω"),
    ("enter", "", None), ("pointer", "   ", None),
    ("cancel", "keep", None), ("escape", "keep", None),
])
async def test_typed_filter_native_focus_and_exact_result(
    mode: str, value: str, expected: str | None,
) -> None:
    app = _SecurityHost()
    results: list[str | None] = []
    async with app.run_test(size=(100, 30)) as pilot:
        origin = app.focused
        modal = FilterValueModal("event name", "ExampleEvent")
        await app.push_screen(modal, results.append)
        field = modal.query_one("#ct_value_input", Input)
        await wait_until(lambda: app.focused is field)
        assert field.placeholder == "ExampleEvent"
        field.value = value
        await pilot.pause()
        if mode in ("pointer", "cancel"):
            await _click(pilot, "#btn_ct_value_ok" if mode == "pointer" else "#btn_ct_value_cancel")
        else:
            await pilot.press("enter" if mode == "enter" else "escape")
        await wait_until(lambda: bool(results))
        assert results == [expected] and app.focused is origin
        app.cloudtrail_service.lookup_page.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_real_cloudtrail_typed_filter_callback_preserves_exact_query(cancel: bool) -> None:
    app = _SecurityHost(False)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _opener("trail")(app, pilot)
        assert isinstance(screen, CloudTrailBrowserScreen)
        picker = screen.query_one("#ct_select_event_name", Select)
        before = app.cloudtrail_service.lookup_page.await_count
        picker.value = _TYPE_A_VALUE
        # The screen is pushed before its input has finished mounting.
        await wait_until(lambda: (
            isinstance(app.screen, FilterValueModal)
            and app.screen.is_mounted
            and bool(app.screen.query("#ct_value_input"))
        ))
        field = app.screen.query_one("#ct_value_input", Input)
        await wait_until(lambda: app.focused is field)
        await pilot.press("shift+f6", "f2", "ctrl+g")
        assert isinstance(app.screen, FilterValueModal) and app.focused is field
        if cancel:
            await pilot.press("escape")
        else:
            field.value = "  CaseSensitiveΩ  "
            await pilot.press("enter")
        await wait_until(lambda: app.screen is screen)
        if cancel:
            assert picker.value is Select.NULL
            assert app.cloudtrail_service.lookup_page.await_count == before
        else:
            await wait_until(lambda: app.cloudtrail_service.lookup_page.await_count == before + 1)
            assert app.cloudtrail_service.lookup_page.await_args.kwargs["event_name"] == "CaseSensitiveΩ"
            assert picker.value == "CaseSensitiveΩ"
        assert not screen.query_one(Sidebar).navigation_mode


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
async def test_security_modal_barrier_and_workspace_preference_resume(case: ReflowCase) -> None:
    app = case.app_factory(True)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await open_case(case, app, pilot)
        panel = await open_chat(app, pilot, screen)
        modal = FilterValueModal("value", "Example")
        await app.push_screen(modal)
        field = modal.query_one("#ct_value_input", Input)
        await wait_until(lambda: app.focused is field)
        app.workspace_state.navigation_visible = False
        await pilot.press("shift+f6", "f2", "ctrl+g")
        assert app.screen is modal and app.focused is field
        assert screen.query_one(ChatPanel) is panel
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
        await pilot.pause()
        assert not screen.query_one(Sidebar).display
        assert_layout(app, screen)
        assert app.focused is not None and app.focused.visible
        assert app.focused.region and screen.region.contains(*app.focused.region.center)


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", [False, True])
async def test_finding_detail_result_and_origin_refresh_after_real_child_return(changed: bool) -> None:
    app = _SecurityHost(False)
    if changed:
        app.findings_service.acknowledge.side_effect = None
        app.findings_service.acknowledge.return_value = {"status": "acked"}
    async with app.run_test(size=(160, 50)) as pilot:
        inbox = await _opener("inbox")(app, pilot)
        assert isinstance(inbox, FindingsScreen)
        before = app.findings_service.list_findings.await_count
        table = inbox.query_one("#findings_table", DataTable)
        table.focus()
        await pilot.press("enter")
        await wait_until(lambda: isinstance(app.screen, FindingDetailScreen))
        detail = app.screen
        if changed:
            await _click(pilot, "#btn_finding_ack")
            await wait_until(lambda: detail._changed)
            app.findings_service.acknowledge.assert_awaited_once_with("fnd_01abc")
        await pilot.press("escape")
        await wait_until(lambda: app.screen is inbox)
        if changed:
            await wait_until(lambda: app.findings_service.list_findings.await_count == before + 1)
        else:
            assert app.findings_service.list_findings.await_count == before
        assert inbox.query_one("#findings_table") is table


@pytest.mark.asyncio
async def test_remediation_cancel_after_reflow_never_executes_signed_preview() -> None:
    app = _SecurityHost(False)
    preview = {
        "finding_id": "fnd_01abc", "action": "harden_sshd_password_auth",
        "exec_risk": "low", "reversible": True, "dry_run": False,
        "command": {"verb": "harden_sshd_password_auth", "human": "fixture command café [literal] Ω"},
        "confirm_token": "fixture-authorization", "expires_at": "2099-01-01T00:00:00Z",
    }
    app.findings_service.remediate_preview.side_effect = None
    app.findings_service.remediate_preview.return_value = preview
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _opener("detail")(app, pilot)
        await open_chat(app, pilot, screen)
        await collapse_chat(app, pilot, screen)
        await wait_until(lambda: bool(screen._remediation_buttons))
        button_id = next(iter(screen._remediation_buttons))
        await wait_until(lambda: bool(screen.query("#" + button_id)))
        button = screen.query_one("#" + button_id, Button)
        button.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        assert await pilot.click(button)
        await wait_until(lambda: isinstance(app.screen, RemediationConfirmModal))
        modal = app.screen
        field = modal.query_one("#remediation_confirm_input", Input)
        await wait_until(lambda: app.focused is field)
        assert modal.query_one("#remediation_confirm_run", Button).disabled
        assert preview["command"]["human"] in modal.query_one("#remediation_confirm_command", Static).render().plain
        await pilot.press("shift+f6", "f2", "ctrl+g")
        assert app.screen is modal and app.focused is field
        await _click(pilot, "#remediation_confirm_cancel")
        await wait_until(lambda: app.screen is screen)
        app.findings_service.remediate.assert_not_awaited()
        assert not screen._changed and not screen._remediating


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["watch", "trail"])
@pytest.mark.parametrize("failure", [False, True])
async def test_native_event_fetch_loading_and_failure_clear_busy_control(
    kind: str, failure: bool,
) -> None:
    app = _SecurityHost(False)
    started, release = asyncio.Event(), asyncio.Event()
    case = next(case for case in CASES if case.name == kind)
    async with app.run_test(size=(160, 50), notifications=True) as pilot:
        screen = await open_case(case, app, pilot)
        fetch = app.cloudwatch_service.get_log_events if kind == "watch" else app.cloudtrail_service.lookup_page
        original = fetch.return_value

        async def held(**kwargs: object) -> object:
            started.set()
            await release.wait()
            if failure:
                raise RuntimeError("[bold]fixture read failure[/bold] Ω")
            return original

        fetch.side_effect = held
        selector = "#cw_btn_fetch" if kind == "watch" else "#ct_btn_fetch"
        detail_id = "#cloudwatch_detail_text" if kind == "watch" else "#event_detail_text"
        try:
            await _click(pilot, selector)
            await wait_until(started.is_set)
            assert screen.query_one(selector, Button).disabled
            assert "Loading" in screen.query_one(detail_id, Static).render().plain
            await open_chat(app, pilot, screen)
            assert_layout(app, screen)
        finally:
            release.set()
        await wait_until(lambda: not screen.query_one(selector, Button).disabled)
        if not failure:
            assert screen._events
        else:
            expected = ("CloudWatch" if kind == "watch" else "CloudTrail") + " fetch failed: [bold]fixture read failure[/bold] Ω"
            await wait_until(lambda: any(note.message == expected for note in app._notifications))
            note = next(note for note in app._notifications if note.message == expected)
            assert note.severity == "error" and note.markup is False
            def message_painted(toast) -> bool:
                region = toast.content_region
                if region.width <= 0 or region.height <= 0 or not screen.region.contains_region(toast.region):
                    return False
                # Exclude native border/padding; preserve every message glyph
                # and interior space, trimming only right-edge ASCII cells.
                strips = screen._compositor.render_strips()
                lines = [strips[y].crop(region.x, region.right).text for y in range(region.y, region.bottom)]
                return " ".join(line.rstrip(" ") for line in lines) == expected

            await wait_until(lambda: any(message_painted(toast) for toast in screen.query("Toast")))
            toast = next(toast for toast in screen.query("Toast") if message_painted(toast))
            for y in range(toast.content_region.y, toast.content_region.bottom):
                hit = app.get_widget_at(toast.content_region.center[0], y)[0]
                assert hit is toast or toast in hit.ancestors
        await collapse_chat(app, pilot, screen)
        detail = screen.query_one(detail_id, Static)
        terminal = detail.render().plain
        assert "Loading" not in terminal
        if failure:
            # Desired terminal feedback: qualify the unchanged original first.
            assert "failure" in terminal.lower() or "failed" in terminal.lower()
            viewport = screen.query_one("#cloudwatch_detail" if kind == "watch" else "#event_detail")
            viewport.scroll_home(animate=False, immediate=True)
            await pilot.pause()
            painted = _painted(app, viewport).lower()
            assert "failure" in painted or "failed" in painted
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True])
async def test_findings_loading_or_error_preserves_active_workspace(failure: bool) -> None:
    app = _SecurityHost(False)
    service = app.findings_service
    payload = service.list_findings.return_value
    started, release = asyncio.Event(), asyncio.Event()

    async def held(**kwargs: object) -> dict:
        started.set()
        await release.wait()
        if failure:
            raise RuntimeError("fixture findings read failure")
        return payload

    service.list_findings.side_effect = held
    async with app.run_test(size=(100, 30)) as pilot:
        screen = FindingsScreen()
        await app.push_screen(screen)
        try:
            await wait_until(started.is_set)
            pill = screen.query_one("#findings_status_pill", Static)
            assert "Loading findings" in pill.render().plain
            worker = next(worker for worker in app.workers if worker.node is screen and worker.name == "findings_load")
            await open_chat(app, pilot, screen)
            assert_layout(app, screen)
        finally:
            release.set()
        await wait_until(lambda: worker.is_finished)
        if failure:
            assert "Load failed" in pill.render().plain
        else:
            assert screen.query_one("#findings_table", DataTable).row_count == 1
        assert screen._gate_state == "active" and app._exception is None


@pytest.mark.asyncio
async def test_cloudtrail_selected_bracket_payload_is_painted_literally() -> None:
    # This is an original-source paint lead, separate from ordinary fit fixtures.
    app = _SecurityHost(False)
    literal = '{"note":"[bold]literal[/bold] Ω"}'
    display_fields = {
        "event_name": "[bold]ReadResource[/bold] Ω",
        "event_time": "[bold]example-time[/bold] Ω",
        "username": "[bold]operator[/bold] Ω",
        "source_ip": "[bold]1.1.1.1[/bold] Ω",
        "resource_type": "[bold]Example::Resource[/bold] Ω",
        "resource_name": "[bold]web-1[/bold] Ω",
        "region": "[bold]example-region[/bold] Ω",
        "error_code": "[bold]Denied[/bold] Ω",
    }
    app.cloudtrail_service.lookup_page.return_value.events[0].update(display_fields, raw_event=literal)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _opener("trail")(app, pilot)
        table = screen.query_one("#cloudtrail_table", DataTable)
        table.focus()
        await pilot.press("enter")
        await pilot.pause()
        text = screen.query_one("#event_detail_text", Static).render().plain
        assert literal in text
        detail = screen.query_one("#event_detail")
        for value in display_fields.values():
            assert value in text
            row = next(index for index, line in enumerate(text.splitlines()) if value in line)
            detail.scroll_to(y=row, animate=False, immediate=True)
            await pilot.pause()
            assert value in _painted(app, detail)
        assert screen._selected_event == app.cloudtrail_service.lookup_page.return_value.events[0]
        detail.scroll_end(animate=False, immediate=True)
        await pilot.pause()
        assert literal in _painted(app, detail)


@pytest.mark.asyncio
@pytest.mark.parametrize("demo", [False, True])
async def test_cloudwatch_native_ban_handoff_keeps_real_address_under_demo(demo: bool) -> None:
    app = _SecurityHost(False)
    app.demo_mode = demo
    app.redaction_service = RedactionService() if demo else None
    app.ip_ban_service.ban_ip.side_effect = None
    app.ip_ban_service.ban_ip.return_value = {"success": False, "message": "fixture-only refusal"}
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _opener("watch")(app, pilot)
        table = screen.query_one("#cloudwatch_ips_table", DataTable)
        table.focus()
        await pilot.press("enter")
        await wait_until(lambda: screen._selected_ip_row == 0)
        await pilot.press("b")
        await wait_until(lambda: isinstance(app.screen, IPBanScreen))
        child = app.screen
        shown = app.redaction_service.redact_ip("1.1.1.1") if demo else "1.1.1.1"
        field = child.query_one("#ip_input", Input)
        await wait_until(lambda: app.focused is field)
        assert field.value == shown and child._field_binding == (shown, "1.1.1.1")
        child.query_one("#ban_config_selector", Select).value = "example-waf"
        await wait_until(lambda: child.query_one("#banned_table", DataTable).row_count == 2)
        await _click(pilot, "#btn_ban")
        await wait_until(lambda: app.ip_ban_service.ban_ip.await_count == 1)
        app.ip_ban_service.ban_ip.assert_awaited_once_with("1.1.1.1", "example-waf")
        app.ip_ban_service.unban_ip.assert_not_awaited()
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
        assert screen.query_one("#cloudwatch_ips_table") is table


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible,chat_open,cancel", [
    (False, True, "pointer"), (True, False, "escape"),
])
async def test_workspace_undo_preview_cancel_never_executes_reversal(
    navigation_visible: bool, chat_open: bool, cancel: str,
) -> None:
    app = _SecurityHost(navigation_visible)
    preview = _revert_preview()
    app.findings_service.revert_preview.side_effect = None
    app.findings_service.revert_preview.return_value = preview
    async with app.run_test(size=(160, 50)) as pilot:
        screen = FindingDetailScreen(_revertible_finding())
        await app.push_screen(screen)
        # Dynamic cards enter the DOM before their buttons have native layout.
        await wait_until(lambda: (
            bool(screen.query("#btn_finding_revert"))
            and screen.query_one("#btn_finding_revert", Button).size.width > 0
            and screen.query_one("#btn_finding_revert", Button).size.height > 0
        ))
        before = dict(screen._finding)
        panel = await open_chat(app, pilot, screen) if chat_open else None
        assert_layout(app, screen)
        assert screen.query_one(Sidebar).display is navigation_visible
        reachable = replace(CASES[4], essential_targets=("#btn_finding_revert",))
        await assert_essential_targets(reachable, app, pilot, screen)
        await _click(pilot, "#btn_finding_revert")
        await wait_until(lambda: isinstance(app.screen, RemediationConfirmModal))
        modal = app.screen
        required = (
            "#remediation_confirm_input", "#remediation_confirm_run",
            "#remediation_confirm_command", "#remediation_confirm_cancel",
        )

        def children_ready() -> bool:
            if app.screen is not modal or not modal.is_mounted:
                return False
            for selector in required:
                matches = list(modal.query(selector))
                if len(matches) != 1 or not matches[0].is_mounted:
                    return False
            return True

        await wait_until(children_ready)
        field = modal.query_one("#remediation_confirm_input", Input)
        await wait_until(lambda: app.focused is field)
        assert modal.query_one("#remediation_confirm_run", Button).disabled
        command = modal.query_one("#remediation_confirm_command", Static)
        assert preview["command"]["human"] in command.render().plain
        app.findings_service.revert_preview.assert_awaited_once_with("fnd_01abc", dry_run=False)
        app.findings_service.revert.assert_not_awaited()
        await pilot.press("shift+f6", "f2", "ctrl+g")
        assert app.screen is modal and app.focused is field
        if cancel == "pointer":
            await _click(pilot, "#remediation_confirm_cancel")
        else:
            await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
        app.findings_service.revert.assert_not_awaited()
        app.findings_service.await_revert_outcome.assert_not_awaited()
        app.findings_service.remediate.assert_not_awaited()
        assert screen._finding == before and not screen._changed and not screen._reverting
        if panel is not None:
            assert screen.query_one(ChatPanel) is panel
        assert_layout(app, screen)
