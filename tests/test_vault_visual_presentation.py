"""Vault summary and record framing keep native actions and literal metadata."""
from __future__ import annotations

import asyncio

import pytest
from textual.widgets import Button, DataTable, Static

from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.vault import VaultScreen
from tests._async_bounds import wait_until
from tests.test_vault_screen import _OnboardingService, _StyledVaultHost, _VaultStatusService
from tests.test_workspace_vault_reflow import (
    _VaultHost, inert_services as _native_vault_services,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize(
    ("trust", "label", "action"),
    [
        ("pending_confirmation", "Confirmation needed", "vault_confirm_identity"),
        ("compromised", "Recovery needed", "vault_reset"),
        ("confirmed", "Identity available", "vault_create"),
    ],
)
async def test_summary_presents_existing_next_step_without_changing_permissions(
    size: tuple[int, int], trust: str, label: str, action: str,
) -> None:
    app = _StyledVaultHost(_OnboardingService(trust=trust))
    async with app.run_test(size=size) as pilot:
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        await wait_until(lambda: screen._identity_state == "ready" and not screen._busy_work)
        await pilot.pause()

        assert str(screen.query_one("#vault_identity_state", Static).render()) == label
        primary = screen.query_one(f"#{action}", Button)
        assert primary.has_class("-next-action") and not primary.disabled
        assert screen.query_one("#vault_content").can_view_entire(primary)
        assert app.get_widget_at(*primary.content_region.center)[0] is primary
        assert str(screen.query_one("#vault_next_step", Static).render()) == f"Next: {primary.label}"
        assert "Identity fingerprint: local-fingerprint" in str(screen.query_one("#vault_status", Static).render())
        assert screen.query_one("#vault_setup", Button).disabled
        assert screen.query_one("#vault_recover", Button).disabled
        # There is one native widget per operation, including the emphasized step.
        expected = set(VaultScreen._READY_ACTIONS) | {
            "vault_refresh", "vault_setup", "vault_add_device", "vault_recover",
        }
        assert {button.id for button in screen.query("#vault_actions Button")} == expected
        table = screen.query_one("#vault_table", DataTable)
        assert table.is_mounted and not table.display
        assert screen.query_one("#vault_records_empty").has_class("-shown")


@pytest.mark.asyncio
async def test_summary_keeps_setup_and_locked_custody_distinct() -> None:
    service = _VaultStatusService(remote_identity=None)
    app = _StyledVaultHost(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        await wait_until(lambda: screen._identity_state == "first_user" and not screen._busy_work)
        assert str(screen.query_one("#vault_identity_state", Static).render()) == "Setup needed"
        assert screen.query_one("#vault_setup", Button).has_class("-next-action")

        service._unlock_error = True
        screen.action_refresh()
        await wait_until(lambda: screen._identity_state == "custody_unavailable" and not screen._busy_work)
        await pilot.pause()
        assert str(screen.query_one("#vault_identity_state", Static).render()) == "Identity locked"
        assert not screen.query("#vault_actions Button.-next-action")
        assert not screen.query_one("#vault_next_step", Static).display
        assert screen.query_one("#vault_setup", Button).disabled


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_record_heading_tracks_mode_and_preserves_literal_selected_vault(
    size: tuple[int, int],
) -> None:
    # Rich-like input must stay literal in both the native table and its new context.
    name = "Personal [bold]Ω[/bold]"
    service = _OnboardingService(vaults=[{
        "vault_id": "vault-1", "name": name, "kind": "personal",
        "my_role": "owner", "my_grant": {"version": 1}, "counts": {},
    }])
    app = _StyledVaultHost(service)
    async with app.run_test(size=size) as pilot:
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        table = screen.query_one("#vault_table", DataTable)
        await wait_until(lambda: table.row_count == 1 and not screen._busy_work)
        assert str(screen.query_one("#vault_records_heading", Static).render()) == "Vaults"
        assert str(screen.query_one("#vault_records_context", Static).render()) == "1 record"
        await pilot.pause()
        assert table.display and table.region.height >= 7

        screen.action_items()
        await wait_until(lambda: screen._table_mode == "items" and not screen._busy_work)
        await pilot.pause()
        assert screen.query_one("#vault_table", DataTable) is table
        assert str(screen.query_one("#vault_records_heading", Static).render()) == "Items"
        assert str(screen.query_one("#vault_records_context", Static).render()) == f"0 records · {name}"
        assert screen._selected_vault_id == "vault-1"
        assert table.is_mounted and not table.display


@pytest.mark.asyncio
async def test_initial_narrow_setup_keeps_the_complete_identity_summary_in_view() -> None:
    app = _VaultHost(navigation_visible=True)
    app.vault_command_service.local = None
    app.vault_command_service.remote = None
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        screen = VaultScreen()
        await app.push_screen(screen)
        await wait_until(lambda: screen._identity_state == "first_user" and not screen._busy_work)
        await pilot.pause()
        content = screen.query_one("#vault_content")
        assert content.scroll_y == 0, (content.scroll_y, content.max_scroll_y)
        for selector in ("#vault_title", "#vault_identity_state", "#vault_status", "#vault_next_step"):
            widget = screen.query_one(selector)
            assert content.can_view_entire(widget), (selector, widget.region, content.region)
        table = screen.query_one("#vault_table", DataTable)
        assert table.is_mounted
        assert not screen.query_one("#vault_records_panel").display
        assert screen.has_class("-identity-pending")
        assert {button.id for button in screen.query("#vault_actions Button") if button.display} == {
            "vault_setup", "vault_refresh",
        }
        setup = screen.query_one("#vault_setup", Button)
        assert content.can_view_entire(setup), (
            setup.region, content.scrollable_content_region,
            screen.query_one("#vault_action_scroll").scrollable_content_region,
            screen.query_one("#vault_action_scroll").scroll_y,
        )
        heading = setup.parent.parent.query_one(".vault_group_heading")
        assert content.can_view_entire(heading)
        assert not setup.disabled
        assert app.get_widget_at(*setup.content_region.center)[0] is setup


@pytest.mark.asyncio
async def test_native_sidebar_entry_with_pending_identity_keeps_setup_action_visible() -> None:
    app = _VaultHost(navigation_visible=True)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def pending_status() -> dict:
        entered.set()
        await release.wait()
        return {"remote": {"identity": None}, "local_identity": None}

    app.vault_command_service.status.side_effect = pending_status
    async with app.run_test(size=(100, 30), notifications=True) as pilot:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        await pilot.click("#section_tools Button.section-header")
        await pilot.pause()
        assert await pilot.click("#nav_vault")
        await wait_until(entered.is_set)
        screen = app.screen
        assert isinstance(screen, VaultScreen)
        await pilot.pause()
        release.set()
        await wait_until(lambda: screen._identity_state == "first_user" and not screen._busy_work)
        await pilot.wait_for_scheduled_animations()
        content = screen.query_one("#vault_content")
        for selector in ("#vault_title", "#vault_identity_state", "#vault_status", "#vault_next_step"):
            assert content.can_view_entire(screen.query_one(selector)), selector
        setup = screen.query_one("#vault_setup", Button)
        assert content.can_view_entire(setup), (app.focused, setup.region)
        table = screen.query_one("#vault_table", DataTable)
        assert table.is_mounted
        assert not screen.query_one("#vault_records_panel").display
        assert screen.has_class("-identity-pending")
        assert {button.id for button in screen.query("#vault_actions Button") if button.display} == {
            "vault_setup", "vault_refresh",
        }
        assert app.get_widget_at(*setup.content_region.center)[0] is setup
        # Startup focus and responsive layout can queue two reveals before a
        # repaint. Each must target the same absolute group position.
        actions = screen.query_one("#vault_action_scroll")
        actions.scroll_to(y=0, animate=False, immediate=True)
        await pilot.pause()
        screen.call_after_refresh(screen._reveal_summary_action, setup)
        screen.call_after_refresh(screen._reveal_summary_action, setup)
        await pilot.pause()
        assert content.can_view_entire(setup), (actions.scroll_y, setup.region)
        assert app.get_widget_at(*setup.content_region.center)[0] is setup
        refresh = screen.query_one("#vault_refresh", Button)
        for _ in range(len(screen.focus_chain) + 1):
            if app.focused is refresh:
                break
            await pilot.press("tab")
        assert app.focused is refresh
        await pilot.press("r")
        await wait_until(lambda: app.vault_command_service.status.await_count == 2 and not screen._busy_work)
        await pilot.wait_for_scheduled_animations()
        assert app.focused is refresh
        assert content.can_view_entire(refresh)
        assert app._exception is None


@pytest.mark.asyncio
async def test_ready_empty_native_sidebar_entry_shows_create_and_cancel_without_scrolling() -> None:
    """A ready identity with no vaults can reach its stated next step on arrival."""
    from servonaut.screens.vault import VaultCreateModal
    from tests.test_workspace_reflow import _painted

    service = _OnboardingService()
    app = _VaultHost(navigation_visible=True)
    app.vault_command_service = service
    async with app.run_test(size=(100, 30), notifications=True) as pilot:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        assert await pilot.click("#section_tools Button.section-header")
        await pilot.pause()
        assert await pilot.click("#nav_vault")
        await wait_until(lambda: isinstance(app.screen, VaultScreen))
        screen = app.screen
        await wait_until(lambda: screen._identity_state == "ready" and not screen._busy_work)
        await pilot.wait_for_scheduled_animations()
        content = screen.query_one("#vault_content")
        create = screen.query_one("#vault_create", Button)
        # No focus/scroll/reveal helper precedes these real arrival assertions.
        assert content.scroll_y == 0
        for selector in (
            "#vault_title", "#vault_identity_state", "#vault_status", "#vault_next_step",
            "#vault_records_heading", "#vault_records_hint", "#vault_records_empty",
        ):
            assert content.can_view_entire(screen.query_one(selector)), selector
        assert content.can_view_entire(create), (create.region, content.region)
        assert app.get_widget_at(*create.content_region.center)[0] is create
        assert " ".join(_painted(app, create).split()) == "Create vault"
        guidance = screen.query_one("#vault_records_empty", Static)
        assert " ".join(_painted(app, guidance).split()) == (
            "No vaults available. Use Create vault to review the vaults your account can create."
        )
        assert str(screen.query_one("#vault_records_context", Static).render()) == "0 records"
        table = screen.query_one("#vault_table", DataTable)
        assert table.is_mounted and not table.display and table.row_count == 0
        assert not create.disabled and create.has_class("-next-action")
        assert screen.query_one("#vault_setup", Button).disabled
        assert screen.query_one("#vault_recover", Button).disabled

        assert await pilot.click("#vault_create")
        await wait_until(lambda: isinstance(app.screen, VaultCreateModal) and app.screen.focused is not None)
        await pilot.pause()
        assert await pilot.click("#vault_create_cancel")
        await wait_until(lambda: app.screen is screen and not screen._busy_work)
        assert service.created == [] and service.vaults == []
        assert screen.query_one("#vault_table", DataTable) is table

        # Empty presentation must not reduce the useful populated-table contract.
        service.vaults = [{
            "vault_id": "vault-record-1", "name": "Personal [literal] Ω", "kind": "personal",
            "my_role": "owner", "my_grant": {"version": 1}, "counts": {},
        }]
        await pilot.press("r")
        await wait_until(lambda: table.row_count == 1 and not screen._busy_work)
        await pilot.pause()
        assert table.display and table.region.height >= 7
        assert table.get_row_at(0)[4] == "vault-record-1"
        assert not screen.query_one("#vault_records_empty").has_class("-shown")
        assert service.created == [] and app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_secondary_vault_actions_have_native_mouse_and_keyboard_disclosures(size) -> None:
    """Native disclosures expose the original guarded operations without activating them."""
    from textual.widgets import Collapsible

    service = _OnboardingService(vaults=[{
        "vault_id": "vault-record-1", "name": "Personal", "kind": "personal",
        "my_role": "owner", "my_grant": {"version": 1}, "counts": {},
    }])
    app = _StyledVaultHost(service)
    async with app.run_test(size=size) as pilot:
        screen = app.screen
        await wait_until(lambda: screen._identity_state == "ready" and not screen._busy_work)
        await pilot.pause()
        identity = screen.query_one("#vault_identity_group", Collapsible)
        maintenance = screen.query_one("#vault_maintenance_group", Collapsible)
        assert identity.collapsed and maintenance.collapsed
        assert identity.title == "Identity and devices"
        assert maintenance.title == "Exposure and key maintenance"
        title = identity.query_one("CollapsibleTitle")
        for _ in range(len(screen.focus_chain) + 1):
            if app.focused is title:
                break
            await pilot.press("tab")
        assert app.focused is title
        await pilot.wait_for_scheduled_animations()
        assert app.get_widget_at(*title.content_region.center)[0] is title
        assert await pilot.click(title)
        await wait_until(lambda: not identity.collapsed)

        title = maintenance.query_one("CollapsibleTitle")
        for _ in range(len(screen.focus_chain) + 1):
            if app.focused is title:
                break
            await pilot.press("tab")
        assert app.focused is title
        await pilot.press("enter")
        await wait_until(lambda: not maintenance.collapsed)
        target = screen.query_one("#vault_delete_keys", Button)
        for _ in range(len(screen.focus_chain) + 1):
            if app.focused is target:
                break
            await pilot.press("tab")
        assert app.focused is target and not target.disabled
        await pilot.wait_for_scheduled_animations()
        assert app.get_widget_at(*target.content_region.center)[0] is target
        assert service.created == [] and service.item_calls == 0
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30), (80, 24)])
async def test_pending_device_native_sidebar_entry_reveals_approve_above_footer(
    size: tuple[int, int],
) -> None:
    from servonaut.screens.vault import VaultSasConfirmModal
    from tests._workspace_reflow_conformance import assert_button_label_painted

    app = _VaultHost(navigation_visible=True)
    service = app.vault_command_service
    service.devices = [
        {"device_id": "active-device", "name": "QA desktop fixture", "status": "active"},
        {"device_id": "waiting-device", "name": "QA waiting workstation", "status": "pending"},
    ]
    async with app.run_test(size=size, notifications=True) as pilot:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        assert await pilot.click("#section_core Button.section-header")
        await pilot.pause()
        assert await pilot.click("#section_tools Button.section-header")
        await pilot.pause()
        assert await pilot.click("#nav_vault")
        await wait_until(lambda: isinstance(app.screen, VaultScreen))
        screen = app.screen
        await wait_until(lambda: screen._identity_state == "ready" and not screen._busy_work)
        await pilot.press("d")
        await wait_until(lambda: screen._table_mode == "devices" and not screen._busy_work)
        await pilot.wait_for_scheduled_animations()
        await pilot.pause()

        # The product must reveal the pending action; no focus, disclosure or
        # scroll helper prepares these arrival assertions.
        table = screen.query_one("#vault_table", DataTable)
        approve = screen.query_one("#vault_approve", Button)
        content = screen.query_one("#vault_content")
        actions = screen.query_one("#vault_action_scroll")
        assert table.row_count == 2 and table.cursor_row == 1
        assert table.region.height >= 7
        assert app.focused is approve
        assert not screen.query_one("#vault_identity_group").collapsed
        assert approve.region.width > 0 and approve.region.height > 0
        assert screen.region.contains_region(approve.region)
        assert content.can_view_entire(approve)
        assert actions.region.contains_region(approve.region)
        assert_button_label_painted(app, approve)
        for y in range(approve.region.y, approve.region.bottom):
            for x in range(approve.region.x, approve.region.right):
                hit = app.get_widget_at(x, y)[0]
                assert hit is approve or approve in hit.ancestors
        assert service.operations == [] and service.results == []

        assert await pilot.click("#vault_approve")
        await wait_until(lambda: isinstance(app.screen, VaultSasConfirmModal))
        await pilot.pause()
        assert await pilot.click("#vault_sas_no")
        await wait_until(lambda: app.screen is screen and not screen._busy_work)
        assert service.approve_device.await_count == 1
        assert service.approve_device.call_args.kwargs["device_id"] == "waiting-device"
        assert service.results == [("sas", False)]
        assert service.operations == [] and table.cursor_row == 1
        assert service.devices[1]["status"] == "pending"
        assert app._exception is None
