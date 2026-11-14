"""Initial review Enter must not choose host-key trust or arm binding."""

from __future__ import annotations

from dataclasses import replace
import json

import pytest
from textual.containers import VerticalScroll
from textual.widgets import Button, Checkbox, Input

from servonaut.screens import vault_auto_bind
from servonaut.screens.vault_auto_bind import VaultAutoBindReviewModal
from tests._async_bounds import wait_until
from tests.test_basic_dialogs import BasicDialogHost
from tests.test_vault_dialog_presentation import _review_rows
from tests.test_workspace_vault_reflow import inert_services  # noqa: F401

pytestmark = pytest.mark.usefixtures("navigation_open")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("long", [False, True], ids=["one-row", "forty-rows"])
@pytest.mark.parametrize("verified", [False, True], ids=["unverified", "verified"])
async def test_initial_enter_keeps_review_choices_and_bind_state_unchanged(
    size: tuple[int, int], long: bool, verified: bool, record_property,
) -> None:
    rows = [replace(
        row, verified=verified,
        verification_source="Verified example host keys" if verified else row.verification_source,
    ) for row in _review_rows(long)]
    modal = VaultAutoBindReviewModal(
        rows, server_name_fn=lambda row: str(row.instance["name"]), scrub_fn=str,
        team="example", team_name="Example team",
    )
    app = BasicDialogHost()
    results: list[bool] = []
    async with app.run_test(size=size) as pilot:
        caller = app.screen
        origin = caller.query_one("#origin", Input)
        assert app.focused is origin
        caller_stack = tuple(app.screen_stack)
        await app.push_screen(modal, callback=results.append)
        await pilot.pause()
        body = modal.query_one("#auto_bind_review_scroll", VerticalScroll)
        checkbox = modal.query_one("#vault_auto_bind_review_use_trusted", Checkbox)
        bind = modal.query_one("#vault_auto_bind_review_confirm", Button)
        initial_focus = app.focused
        initial_values = tuple((control.id, control.value) for control in modal.query(Checkbox))
        initial_disabled = bind.disabled
        modal_stack = tuple(app.screen_stack)
        assert checkbox.value is verified and bind.disabled is (not verified)
        assert results == [] and modal_stack == caller_stack + (modal,)

        # First interaction after mount: no focus(), Tab, click or choice setup.
        await pilot.press("enter")
        await pilot.pause()
        entered_values = tuple((control.id, control.value) for control in modal.query(Checkbox))
        entered_disabled = bind.disabled
        entered_results = list(results)
        entered_stack = tuple(app.screen_stack)
        entered_focus = app.focused
        record_property("untouched_review_enter", json.dumps({
            "verified": verified, "rows": len(rows), "size": size,
            "initial_focus_id": getattr(initial_focus, "id", None),
            "initial_focus_class": type(initial_focus).__name__,
            "after_enter_focus_id": getattr(entered_focus, "id", None),
            "initial_values": initial_values, "after_enter_values": entered_values,
            "initial_bind_disabled": initial_disabled, "after_enter_bind_disabled": entered_disabled,
            "after_enter_callbacks": entered_results,
            "initial_stack_depth": len(modal_stack), "after_enter_stack_depth": len(entered_stack),
        }, sort_keys=True))
        if app.screen is modal:
            await pilot.press("escape")
            await wait_until(lambda: app.screen is caller and not modal.is_attached)

        assert results == [False] and tuple(app.screen_stack) == caller_stack
        assert app.focused is origin
        assert initial_focus is body and initial_focus.id == "auto_bind_review_scroll"
        assert entered_focus is body
        assert entered_values == initial_values and entered_disabled is initial_disabled
        assert entered_results == [] and entered_stack == modal_stack
        assert app._exception is None
        for name in ("plan_auto_bind", "apply_auto_bind", "fetch_host_keys_for_rows"):
            getattr(vault_auto_bind, name).assert_not_called()
