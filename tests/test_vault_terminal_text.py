"""Names and values from the service or from teammates never reach the terminal raw.

An escape sequence in a vault, device, member or exposure field could set the
window title, write the clipboard, add a hyperlink or paint over other cells.
The Vault screen shows such text with its control characters removed.
"""

from __future__ import annotations

from typing import Any

import pytest
from textual.widgets import DataTable, Static

from servonaut.screens.vault import VaultMemberApprovalModal
from servonaut.services.vault.display import terminal_safe
from tests._async_bounds import wait_until
from tests._vault_target_harness import FakeVaultService, VaultHost, move_cursor, press, ready, vault_screen

pytestmark = pytest.mark.asyncio

LINK = "\x1b]8;;http://e.invalid\x1b\\"
CLIPBOARD = "\x1b]52;c;ZWNobyBoaQ==\x07"
TITLE = "\x1b]0;PWNED\x07"
CSI = "\x1b[8m"
C1 = "\x9b8m"
BIDI = "‮"
HOSTILE = f"osc{LINK}link{CLIPBOARD}{TITLE}{CSI}{C1}{BIDI}tail"
# The compositor writes its own colour codes (ESC [ ... m), so look for the
# sequences a name could add: OSC (titles, clipboard, links), C1, BEL, conceal.
FORBIDDEN = ("\x1b]", "\x1b\\", "\x1b[8m", "\x9b", "\x07", BIDI)


def _output(app: Any) -> str:
    """Everything the compositor would write to the terminal for the whole screen."""
    update = app.screen._compositor.render_update(full=True)
    return update.render_segments(app.console)


def _assert_clean(app: Any) -> None:
    out = _output(app)
    for sequence in FORBIDDEN:
        assert sequence not in out, f"{sequence!r} reached the terminal output"


async def _with(service: FakeVaultService, steps: Any) -> Any:
    app = VaultHost(service)
    async with app.run_test(size=(180, 50)) as pilot:
        await ready(app, pilot)
        return await steps(app, pilot)


def test_terminal_safe_removes_every_control_and_keeps_the_words() -> None:
    shown = terminal_safe(HOSTILE)
    assert not any(char in shown for char in "\x1b\x9b\x07" + BIDI)
    assert shown.startswith("osc") and shown.endswith("tail") and "link" in shown


async def test_vault_names_and_kinds_are_clean_in_the_vault_list() -> None:
    async def steps(app: Any, pilot: Any) -> str:
        _assert_clean(app)
        return vault_screen(app).query_one("#vault_table", DataTable).get_row_at(0)[0]

    cell = await _with(FakeVaultService(names={"A": HOSTILE}), steps)
    assert "osc" in str(cell) and "tail" in str(cell)


async def test_item_fields_are_clean() -> None:
    async def steps(app: Any, pilot: Any) -> None:
        await move_cursor(app, pilot, 0)
        await press(app, pilot, "vault_items")
        _assert_clean(app)

    await _with(FakeVaultService(item_fingerprint=HOSTILE), steps)


async def test_device_fields_are_clean() -> None:
    async def steps(app: Any, pilot: Any) -> None:
        await press(app, pilot, "vault_devices")
        _assert_clean(app)

    await _with(FakeVaultService(device_names=[HOSTILE, HOSTILE, HOSTILE], platform=HOSTILE), steps)


async def test_member_fields_are_clean() -> None:
    members = [{"user_id": "u-1", "display_name": HOSTILE, "role": HOSTILE, "status": HOSTILE,
                "identity": {"fingerprint": HOSTILE}}]

    async def steps(app: Any, pilot: Any) -> None:
        await move_cursor(app, pilot, 0)
        await press(app, pilot, "vault_roster")
        _assert_clean(app)

    await _with(FakeVaultService(members=members), steps)


async def test_exposure_fields_are_clean() -> None:
    async def steps(app: Any, pilot: Any) -> None:
        await move_cursor(app, pilot, 0)
        await press(app, pilot, "vault_items")
        await press(app, pilot, "vault_exposures")
        assert vault_screen(app)._table_mode == "exposures"
        _assert_clean(app)

    await _with(FakeVaultService(exposure_subject=HOSTILE), steps)


async def test_status_lines_and_toasts_are_clean() -> None:
    async def steps(app: Any, pilot: Any) -> None:
        screen = vault_screen(app)
        screen._status(f"Something went wrong: {HOSTILE}")
        await pilot.pause()
        _assert_clean(app)
        screen.app.notify(screen.scrub_for_display(f"toast {HOSTILE}"), markup=False)
        await pilot.pause(0.2)
        _assert_clean(app)
        assert "osc" in screen.query_one("#vault_status", Static).visual.plain

    await _with(FakeVaultService(), steps)


async def test_status_text_keeps_its_line_breaks() -> None:
    async def steps(app: Any, pilot: Any) -> str:
        screen = vault_screen(app)
        return screen.scrub_for_display("first\nsecond\tcolumn")

    assert await _with(FakeVaultService(), steps) == "first\nsecond\tcolumn"


async def test_member_approval_dialog_is_clean() -> None:
    members = [{"user_id": "u-2", "display_name": HOSTILE, "role": HOSTILE, "status": "pending",
                "identity": {"fingerprint": "SHA256:m"}}]

    class Service(FakeVaultService):
        async def process_grants(self, *, vault_id: str, approval: Any, **kw: Any) -> list:
            await approval({"user_id": "u-2", "display_name": HOSTILE, "email": f"x{CSI}@example.invalid",
                            "role": HOSTILE}, "11111 22222 33333", False)
            return []

    async def steps(app: Any, pilot: Any) -> str:
        await move_cursor(app, pilot, 1)
        await press(app, pilot, "vault_roster")
        await press(app, pilot, "vault_grants")
        await wait_until(lambda: isinstance(app.screen, VaultMemberApprovalModal))
        await pilot.pause(0.2)
        _assert_clean(app)
        return " ".join(s.visual.plain for s in app.screen.query(Static))

    shown = await _with(Service(members=members), steps)
    assert "osc" in shown and "tail" in shown


async def test_revealed_value_is_clean_but_keeps_its_lines() -> None:
    class Service(FakeVaultService):
        async def show_item(self, *, vault_id: str, item_id: str, reveal: bool, **kw: Any) -> dict:
            return {"item_id": item_id, "plaintext": {"value": f"line one\nline two {HOSTILE}"}}

    async def steps(app: Any, pilot: Any) -> str:
        from tests.test_vault_row_actions import _confirm_typed
        await move_cursor(app, pilot, 0)
        await press(app, pilot, "vault_items")
        vault_screen(app).action_reveal()
        await _confirm_typed(app, pilot, "REVEAL")
        await wait_until(lambda: app.screen.query("#vault_revealed_value"))
        await pilot.pause(0.2)
        _assert_clean(app)
        return app.screen.query_one("#vault_revealed_value", Static).visual.plain

    shown = await _with(Service(), steps)
    assert shown.startswith("line one\nline two osc")


def test_failure_reasons_from_the_service_have_no_controls() -> None:
    from servonaut.services.vault.errors import VaultUserError, vault_failure_reason

    reason = vault_failure_reason(VaultUserError(f"refused {HOSTILE}"))
    assert reason.startswith("refused osc") and not any(char in reason for char in "\x1b\x9b\x07" + BIDI)


def test_the_auto_bind_screen_scrubs_controls_from_names() -> None:
    from types import SimpleNamespace

    from servonaut.screens.vault_auto_bind import VaultAutoBindScreen

    screen = VaultAutoBindScreen.__new__(VaultAutoBindScreen)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(VaultAutoBindScreen, "app", SimpleNamespace(demo_mode=False), raising=False)
        shown = screen.scrub_for_display(HOSTILE)
    assert shown.startswith("osc") and not any(char in shown for char in "\x1b\x9b\x07" + BIDI)
