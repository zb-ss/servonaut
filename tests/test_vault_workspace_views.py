"""The Vault screen's view switch and inspector keep every action, gate and name as before."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from textual.events import Click
from textual.widgets import Button, DataTable, Static

from servonaut.screens.vault import VaultScreen
from servonaut.widgets.action_button import ActionButton
from tests._async_bounds import wait_until
from tests.test_vault_screen import _StyledVaultHost, _VaultHost, _VaultStatusService

_PERSONAL = "11111111-1111-4111-8111-111111111111"
_TEAM = "22222222-2222-4222-8222-222222222222"
# An OpenSSH SHA256 fingerprint is "SHA256:" and 43 characters; ids are UUIDs.
_FINGERPRINT = "SHA256:" + "q" * 43
_ITEM_1 = "33333333-3333-4333-8333-333333333333"
_HOSTILE = "[bold red]Mallory[/bold red] [link=https://example.invalid]x"

_VIEW_BUTTONS = ("vault_vaults", "vault_items", "vault_devices", "vault_roster", "vault_exposures")
_DANGER_BUTTONS = (
    "vault_rotate", "vault_recovery_rotate", "vault_reset", "vault_delete_keys",
)


class _Service:
    """A ready vault identity with a personal and a team vault, a pending device and an exposure."""

    def __init__(self, *, local: bool = True, hostile: bool = False) -> None:
        self.local = local
        self.hostile = hostile
        self.calls: list[str] = []

    async def status(self):
        if not self.local:
            return {"remote": {"identity": None}}
        return {
            "remote": {"identity": {"identity_id": "i", "trust_status": "confirmed"}},
            "local_identity": "local-fingerprint", "fingerprint": "local-fingerprint",
        }

    def can_create_personal_vault(self):
        return False

    async def list_vaults(self):
        return [
            {"vault_id": _PERSONAL, "kind": "personal", "name": _HOSTILE if self.hostile else "Personal",
             "my_role": "owner", "my_grant": {"version": 1}, "counts": {"items": 2, "open_exposures": 1}},
            {"vault_id": _TEAM, "kind": "team", "name": "Platform team", "my_role": "admin",
             "my_grant": {"version": 1}, "counts": {"items": 0, "open_exposures": 0}},
        ]

    async def list_items(self, **_kwargs):
        self.calls.append("list_items")
        return {"data": [
            {"item_id": _ITEM_1, "type": "ssh_key", "revision": 3, "public_fingerprint": _FINGERPRINT},
            {"item_id": "k2", "type": "ssh_key", "revision": 1, "public_fingerprint": "SHA256:" + "d" * 43},
        ]}

    async def ssh_key_choices(self, **_kwargs):
        return [
            {"item_id": _ITEM_1, "name": _HOSTILE if self.hostile else "Deploy key for web-1"},
            {"item_id": "k2", "name": "Backup key"},
        ]

    async def list_devices(self):
        self.calls.append("list_devices")
        return [
            {"device_id": "d-1", "name": "work laptop", "platform": "linux", "status": "active"},
            {"device_id": "d-2", "name": _HOSTILE if self.hostile else "build workstation",
             "platform": "linux", "status": "pending"},
        ]

    async def get_vault(self, *, vault_id, **_kwargs):
        self.calls.append(f"get_vault:{vault_id}")
        return {"roster": [
            {"user_id": "u-1", "display_name": "Alex Doe", "role": "owner", "status": "active",
             "identity": {"fingerprint": "SHA256:owner"}},
            {"user_id": "u-2", "display_name": _HOSTILE if self.hostile else "Sam Roe", "role": "member",
             "status": "pending", "identity": {"fingerprint": "SHA256:member"}},
        ]}

    async def process_grants(self, *, vault_id, approval):
        self.calls.append(f"process_grants:{vault_id}")
        return []

    async def rotate(self, *, vault_id):
        self.calls.append(f"rotate:{vault_id}")
        return {}

    async def list_exposures(self, *, vault_id, **_kwargs):
        self.calls.append(f"list_exposures:{vault_id}")
        return {"data": [
            {"exposure_id": "e-1", "item_id": "k1", "subject": "Deploy key for web-1",
             "reason": "shared in chat", "key_replaced": False},
        ]}


def _settled(screen: VaultScreen) -> bool:
    return screen._identity_state != "loading" and not screen._busy_work


async def _ready(app, view: str | None = None) -> VaultScreen:
    screen = app.screen
    assert isinstance(screen, VaultScreen)
    await wait_until(lambda: _settled(screen) and screen.query_one("#vault_table", DataTable).row_count == 2)
    return screen


def _facts(screen: VaultScreen) -> str:
    return screen.query_one("#vault_inspector_facts", Static).render().plain


def _active(screen: VaultScreen) -> list[str]:
    return [b.id for b in screen.query("#vault_views ActionButton") if b.has_class("-current-view")]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("button_id", "key", "mode"),
    [
        ("vault_items", "i", "items"),
        ("vault_devices", "d", "devices"),
        ("vault_roster", "m", "roster"),
        ("vault_exposures", "e", "exposures"),
    ],
)
async def test_each_view_opens_by_click_and_by_key_with_the_same_handler(button_id, key, mode) -> None:
    app = _StyledVaultHost(_Service())
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(app)
        assert _active(screen) == ["vault_vaults"]
        await _clickable(app, pilot, screen, button_id)
        assert await pilot.click(f"#{button_id}")
        await wait_until(lambda: screen._table_mode == mode and not screen._busy_work)
        await wait_until(lambda: _active(screen) == [button_id])

        await _clickable(app, pilot, screen, "vault_vaults")
        assert await pilot.click("#vault_vaults")
        await wait_until(lambda: screen._table_mode == "vaults")
        assert _active(screen) == ["vault_vaults"]
        screen.query_one("#vault_table", DataTable).focus()
        await pilot.press(key)
        await wait_until(lambda: screen._table_mode == mode and not screen._busy_work)
        assert _active(screen) == [button_id]
        assert app._exception is None


@pytest.mark.asyncio
async def test_a_view_shows_its_count_once_it_has_been_opened() -> None:
    app = _StyledVaultHost(_Service())
    async with app.run_test(size=(160, 50)):
        screen = await _ready(app)
        label = lambda button_id: screen.query_one(f"#{button_id}", ActionButton).words
        assert label("vault_vaults") == "Vaults (2)"
        assert label("vault_devices") == "Devices"
        screen.action_devices()
        await wait_until(lambda: screen._table_mode == "devices" and not screen._busy_work)
        assert label("vault_devices") == "Devices (2)"


@pytest.mark.asyncio
async def test_the_view_switch_is_gated_like_the_buttons_it_replaced() -> None:
    app = _StyledVaultHost(_Service(local=False))
    async with app.run_test(size=(160, 50)):
        screen = app.screen
        await wait_until(lambda: screen._identity_state == "first_user" and not screen._busy_work)
        assert not screen.query_one("#vault_views").display or screen.has_class("-identity-pending")
        assert all(screen.query_one(f"#{button_id}", Button).disabled for button_id in _VIEW_BUTTONS)
        assert all(screen.query_one(f"#{button_id}", Button).disabled for button_id in _DANGER_BUTTONS)
        screen.action_devices()
        screen.action_vaults()
        assert screen._table_mode == "vaults"


@pytest.mark.asyncio
async def test_the_view_switch_is_held_while_work_runs() -> None:
    app = _StyledVaultHost(_Service())
    async with app.run_test(size=(160, 50)):
        screen = await _ready(app)
        async with screen._busy("Working…"):
            assert all(screen.query_one(f"#{button_id}", Button).disabled for button_id in _VIEW_BUTTONS)
        assert all(not screen.query_one(f"#{button_id}", Button).disabled for button_id in _VIEW_BUTTONS)


@pytest.mark.asyncio
async def test_every_action_button_runs_the_handler_it_always_did() -> None:
    app = _StyledVaultHost(_Service())
    handlers = {
        "vault_refresh": "action_refresh", "vault_vaults": "action_vaults", "vault_items": "action_items",
        "vault_devices": "action_devices", "vault_roster": "action_roster", "vault_exposures": "action_exposures",
        "vault_setup": "action_setup", "vault_add_device": "action_add_device", "vault_recover": "action_recover",
        "vault_create": "action_create", "vault_import": "action_import", "vault_auto_bind": "action_auto_bind",
        "vault_reveal": "action_reveal", "vault_rename_key": "action_rename_key",
        "vault_confirm_identity": "action_confirm_identity", "vault_approve": "action_approve",
        "vault_grants": "action_grants", "vault_resolve_exposure": "action_resolve_exposure",
        "vault_rotate_exposure": "action_rotate_exposure", "vault_rotate": "action_rotate",
        "vault_recovery_rotate": "action_recovery_rotate", "vault_reset": "action_reset",
        "vault_delete_key": "action_delete_key", "vault_delete_keys": "action_delete_keys",
        "vault_cancel_wait": "action_stop_waiting",
    }
    async with app.run_test(size=(160, 50)):
        screen = await _ready(app)
        for button_id, handler in handlers.items():
            mock = MagicMock()
            setattr(screen, handler, mock)
            button = screen.query_one(f"#{button_id}", Button)
            screen.on_button_pressed(Button.Pressed(button))
            mock.assert_called_once_with()
            delattr(screen, handler)


@pytest.mark.asyncio
async def test_switching_views_keeps_acting_on_the_vault_being_looked_at() -> None:
    service = _Service()
    app = _StyledVaultHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(app)
        screen.action_items()
        await wait_until(lambda: screen._table_mode == "items" and not screen._busy_work)
        # The cursor now points into the items table: row 1 must not pick the team vault.
        screen.query_one("#vault_table", DataTable).move_cursor(row=1)
        await pilot.pause()
        screen.action_roster()
        await wait_until(lambda: screen._table_mode == "roster" and not screen._busy_work)
        screen.action_exposures()
        await wait_until(lambda: screen._table_mode == "exposures" and not screen._busy_work)
        assert service.calls[-2:] == [f"get_vault:{_PERSONAL}", f"list_exposures:{_PERSONAL}"]

        screen.action_vaults()
        screen.query_one("#vault_table", DataTable).move_cursor(row=1)
        await pilot.pause()
        screen.action_exposures()
        await wait_until(lambda: f"list_exposures:{_TEAM}" in service.calls)


async def _clickable(app, pilot, screen: VaultScreen, button_id: str) -> None:
    """Wait until layout and focus scrolling are done and the button is what a click would hit."""
    button = screen.query_one(f"#{button_id}")
    await wait_until(lambda: not screen._busy_work and button.region.width > 0
                     and app.get_widget_at(*button.region.center)[0] is button)
    # Queued focus reveals scroll once more; let them run before a click lands.
    await pilot.pause()


async def _view(screen: VaultScreen, action, mode: str) -> None:
    action()
    await wait_until(lambda: screen._table_mode == mode and not screen._busy_work)


@pytest.mark.asyncio
async def test_devices_view_keeps_acting_on_the_vault_chosen_before_it() -> None:
    service = _Service()
    app = _StyledVaultHost(service)
    async with app.run_test(size=(160, 50)):
        screen = await _ready(app)
        await _view(screen, screen.action_devices, "devices")
        # Device row 1 is where the pending device sits; it must not pick the second vault.
        assert screen.query_one("#vault_table", DataTable).cursor_row == 1
        assert screen._selected_vault()["vault_id"] == _PERSONAL
        screen.action_grants()
        await wait_until(lambda: f"process_grants:{_PERSONAL}" in service.calls)
        await wait_until(lambda: not screen._busy_work)
        await _view(screen, screen.action_items, "items")
        assert service.calls[-1] == "list_items"
        assert screen._selected_vault_id == _PERSONAL


@pytest.mark.asyncio
async def test_members_of_a_vault_are_the_target_of_grants_and_rotate() -> None:
    service = _Service()
    app = _StyledVaultHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(app)
        screen.query_one("#vault_table", DataTable).move_cursor(row=1)
        await wait_until(lambda: screen._selected_vault_id == _TEAM)
        await _view(screen, screen.action_roster, "roster")
        screen.query_one("#vault_table", DataTable).move_cursor(row=0)
        await pilot.pause()
        assert screen._selected_vault()["vault_id"] == _TEAM
        screen.action_grants()
        await wait_until(lambda: f"process_grants:{_TEAM}" in service.calls)
        await wait_until(lambda: not screen._busy_work)
        # The vault list returns to the vault that was chosen, not to row 0.
        screen.action_vaults()
        await wait_until(lambda: screen.query_one("#vault_table", DataTable).cursor_row == 1)
        assert screen._selected_vault()["vault_id"] == _TEAM


@pytest.mark.asyncio
async def test_row_actions_only_act_in_the_view_that_lists_their_rows() -> None:
    service = _Service()
    app = _StyledVaultHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(app)
        await _view(screen, screen.action_items, "items")
        await _view(screen, screen.action_devices, "devices")
        screen.query_one("#vault_table", DataTable).move_cursor(row=0)
        assert screen._selected_item() is None
        screen.action_reveal()
        await pilot.pause()
        assert type(app.screen) is VaultScreen  # no reveal confirmation opened
        await _view(screen, screen.action_items, "items")
        screen.action_approve()
        await pilot.pause()
        assert type(app.screen) is VaultScreen
        assert screen._selected_exposure() is None and screen._selected_item() is not None


@pytest.mark.asyncio
async def test_the_keys_still_open_what_they_opened() -> None:
    app = _StyledVaultHost(_Service())
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(app)
        screen.query_one("#vault_table", DataTable).focus()
        bound = {binding.key: binding.action for binding in VaultScreen.BINDINGS}
        assert bound["r"] == "refresh" and bound["v"] == "reveal" and bound["e"] == "exposures"
        assert bound["d"] == "devices" and bound["g"] == "grants" and bound["escape"] == "back"
        assert {bound["l"], bound["i"], bound["m"]} == {"vaults", "items", "roster"}
        await pilot.press("i")
        await wait_until(lambda: screen._table_mode == "items" and not screen._busy_work)


@pytest.mark.asyncio
async def test_the_inspector_follows_the_selected_row() -> None:
    app = _StyledVaultHost(_Service())
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(app)
        heading = screen.query_one("#vault_inspector_heading", Static)
        assert heading.render().plain == "SELECTED VAULT"
        assert "Personal" in _facts(screen) and _PERSONAL in _facts(screen)
        screen.query_one("#vault_table", DataTable).move_cursor(row=1)
        await wait_until(lambda: "Platform team" in _facts(screen) and "team" in _facts(screen))

        screen.action_devices()
        await wait_until(lambda: screen._table_mode == "devices" and not screen._busy_work)
        assert heading.render().plain == "SELECTED DEVICE"
        assert "build workstation" in _facts(screen) and "pending" in _facts(screen)
        screen.query_one("#vault_table", DataTable).move_cursor(row=0)
        await wait_until(lambda: "work laptop" in _facts(screen) and "d-1" in _facts(screen))


@pytest.mark.asyncio
async def test_names_from_the_service_and_teammates_are_shown_literally() -> None:
    app = _StyledVaultHost(_Service(hostile=True))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(app)
        assert _HOSTILE in _facts(screen)
        for action, mode in (
            (screen.action_items, "items"), (screen.action_devices, "devices"), (screen.action_roster, "roster"),
        ):
            action()
            await wait_until(lambda: screen._table_mode == mode and not screen._busy_work)
            screen.query_one("#vault_table", DataTable).move_cursor(row=0 if mode == "items" else 1)
            await wait_until(lambda: _HOSTILE in _facts(screen))
        assert app._exception is None


@pytest.mark.asyncio
async def test_demo_mode_redacts_the_inspector_and_repaints_it_without_fetching() -> None:
    class Redactor:
        def scrub_stream(self, text: str) -> str:
            return text.replace("Personal", "redacted").replace(_PERSONAL, "redacted-id")

    service = _Service()
    app = _StyledVaultHost(service)
    app.demo_mode = False
    app.redaction_service = Redactor()
    async with app.run_test(size=(160, 50)):
        screen = await _ready(app)
        assert "Personal" in _facts(screen)
        app.demo_mode = True
        screen.refresh_after_demo_toggle()
        assert "Personal" not in _facts(screen) and _PERSONAL not in _facts(screen)
        assert "redacted" in _facts(screen)
        assert service.calls == []


@pytest.mark.asyncio
async def test_a_pending_device_makes_approve_the_primary_action() -> None:
    app = _StyledVaultHost(_Service())
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(app)
        approve = screen.query_one("#vault_approve", ActionButton)
        assert approve.variant == "default"
        screen.action_devices()
        await wait_until(lambda: screen._table_mode == "devices" and not screen._busy_work)
        await wait_until(lambda: approve.variant == "primary")
        screen.query_one("#vault_table", DataTable).move_cursor(row=0)
        await wait_until(lambda: approve.variant == "default")


@pytest.mark.asyncio
async def test_the_suggested_identity_step_is_primary_and_leads_the_inspector() -> None:
    from tests.test_vault_screen import _OnboardingService

    app = _StyledVaultHost(_OnboardingService(trust="pending_confirmation"))
    async with app.run_test(size=(160, 50)):
        screen = app.screen
        await wait_until(lambda: screen._identity_state == "ready" and not screen._busy_work)
        confirm = screen.query_one("#vault_confirm_identity", ActionButton)
        assert confirm.variant == "primary" and confirm.has_class("-next-action")
        groups = [child.id for child in screen.query_one("#vault_actions").children]
        assert groups[0] == "vault_identity_group"


@pytest.mark.asyncio
async def test_destructive_actions_use_the_error_role_in_a_separate_group() -> None:
    app = _StyledVaultHost(_Service())
    async with app.run_test(size=(160, 50)):
        screen = await _ready(app)
        group = screen.query_one("#vault_danger_group")
        for button_id in _DANGER_BUTTONS:
            button = screen.query_one(f"#{button_id}", ActionButton)
            assert button.variant == "error" and group in button.ancestors, button_id
        delete = screen.query_one("#vault_delete_key", ActionButton)
        assert delete.variant == "error" and screen.query_one("#vault_keys_group") in delete.ancestors
        assert screen.query_one("#vault_rotate_exposure", ActionButton).variant == "warning"
        assert screen.query_one("#vault_cancel_wait", ActionButton).variant == "error"
        for button in screen.query(ActionButton):
            if button.id not in _DANGER_BUTTONS:
                assert group not in button.ancestors, button.id


@pytest.mark.asyncio
async def test_the_last_view_is_remembered_for_the_session() -> None:
    service = _Service()
    app = _StyledVaultHost(service)
    async with app.run_test(size=(160, 50)):
        screen = await _ready(app)
        screen.action_devices()
        await wait_until(lambda: screen._table_mode == "devices" and not screen._busy_work)
        app.pop_screen()
        service.calls.clear()
        reopened = VaultScreen()
        await app.push_screen(reopened)
        await wait_until(lambda: reopened._table_mode == "devices" and not reopened._busy_work)
        assert _active(reopened) == ["vault_devices"]


@pytest.mark.asyncio
async def test_a_remembered_view_is_not_reopened_while_the_identity_is_not_ready() -> None:
    service = _Service(local=False)
    app = _StyledVaultHost(service)
    app.vault_last_view = "vault_devices"
    async with app.run_test(size=(160, 50)):
        screen = app.screen
        await wait_until(lambda: screen._identity_state == "first_user" and not screen._busy_work)
        await screen.workers.wait_for_complete()
        assert screen._table_mode == "vaults" and service.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (120, 40), (100, 30), (90, 30)])
async def test_no_action_or_view_is_clipped_at_any_width(size) -> None:
    from tests._workspace_reflow_conformance import assert_button_label_painted

    app = _StyledVaultHost(_Service())
    async with app.run_test(size=size) as pilot:
        screen = await _ready(app)
        views = screen.query_one("#vault_views")
        for button in views.query(ActionButton):
            assert button.region.width > 0 and views.region.contains_region(button.region), button.id
            assert_button_label_painted(app, button)
        for button in screen.query("#vault_actions ActionButton"):
            if not button.display or not button.parent.parent.display:
                continue  # Setup, Add device and Recover wait for a state that needs them
            button.scroll_visible(animate=False, immediate=True)
            await pilot.pause()
            assert button.region.width > 0, button.id
            assert screen.query_one("#vault_action_scroll").region.contains_region(button.region), button.id
            assert_button_label_painted(app, button)


@pytest.mark.asyncio
async def test_terminal_escape_sequences_in_names_never_reach_the_terminal() -> None:
    from rich.console import Console

    hostile = "osc\x1b]8;;http://example.invalid\x1b\\link \x1b]52;c;eA==\x07 \x1b]0;title\x07end"

    class Hostile(_Service):
        async def list_vaults(self):
            rows = await super().list_vaults()
            rows[0]["name"] = hostile
            return rows

        async def list_devices(self):
            return [{"device_id": "d-1", "name": hostile, "platform": hostile, "status": "pending"}]

        async def get_vault(self, **_kwargs):
            return {"roster": [{"user_id": "u", "display_name": hostile, "role": hostile, "status": hostile,
                                "identity": {"fingerprint": hostile}}]}

        async def list_exposures(self, **_kwargs):
            return {"data": [{"exposure_id": "e", "item_id": "k1", "subject": hostile, "reason": hostile}]}

    app = _StyledVaultHost(Hostile())
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(app)
        for action, mode in (
            (screen.action_items, "items"), (screen.action_devices, "devices"),
            (screen.action_roster, "roster"), (screen.action_exposures, "exposures"),
            (screen.action_vaults, "vaults"),
        ):
            action()
            await wait_until(lambda: screen._table_mode == mode and not screen._busy_work)
            await pilot.pause()
            output = screen._compositor.render_update(full=True).render_segments(Console(width=160))
            assert "\x1b]" not in output and "example.invalid\x1b" not in output, mode
            assert "\x1b]8" not in _facts(screen) and "\x07" not in _facts(screen), mode


@pytest.mark.asyncio
async def test_clicking_the_open_view_reloads_it_like_its_key() -> None:
    service = _Service()
    app = _StyledVaultHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(app)
        await _view(screen, screen.action_devices, "devices")
        before = service.calls.count("list_devices")
        await _clickable(app, pilot, screen, "vault_devices")
        assert await pilot.click("#vault_devices")
        await wait_until(lambda: service.calls.count("list_devices") == before + 1)
        assert _active(screen) == ["vault_devices"]


@pytest.mark.asyncio
async def test_the_pending_device_step_is_named_next_and_a_scoped_view_reopens_on_its_vault() -> None:
    service = _Service()
    app = _StyledVaultHost(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready(app)
        await _view(screen, screen.action_devices, "devices")
        step = screen.query_one("#vault_next_step", Static)
        await wait_until(lambda: step.has_class("-shown"))
        assert step.render().plain == "Next: Approve device"

        screen.action_vaults()
        await wait_until(lambda: screen._table_mode == "vaults")
        screen.query_one("#vault_table", DataTable).move_cursor(row=1)
        await wait_until(lambda: screen._selected_vault_id == _TEAM)
        await _view(screen, screen.action_items, "items")
        app.pop_screen()
        service.calls.clear()
        reopened = VaultScreen()
        await app.push_screen(reopened)
        await wait_until(lambda: reopened._table_mode == "items" and not reopened._busy_work)
        assert reopened._selected_vault_id == _TEAM


@pytest.mark.asyncio
async def test_a_narrow_screen_still_names_the_selected_device_above_the_actions() -> None:
    app = _StyledVaultHost(_Service())
    async with app.run_test(size=(100, 30)):
        screen = await _ready(app)
        await _view(screen, screen.action_devices, "devices")
        facts = screen.query_one("#vault_inspector_facts", Static)
        shelf = screen.query_one("#vault_action_scroll")
        await wait_until(lambda: "build workstation" in facts.render().plain)
        await wait_until(lambda: shelf.region.contains_region(facts.region) and facts.region.height == 1)
        approve = screen.query_one("#vault_approve")
        assert shelf.region.contains_region(approve.region) or approve.region.y >= facts.region.bottom


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_a_real_length_fingerprint_and_item_id_are_never_cut(size) -> None:
    app = _StyledVaultHost(_Service())
    async with app.run_test(size=size):
        screen = await _ready(app)
        await _view(screen, screen.action_items, "items")
        facts = screen.query_one("#vault_inspector_facts", Static)
        await wait_until(lambda: _FINGERPRINT in facts.render().plain.replace("\n", ""))
        assert _ITEM_1 in facts.render().plain
        if size[0] > 110:
            needed = facts.visual.get_height(facts.styles, facts.size.width)
            await wait_until(lambda: facts.size.height >= needed)
        else:
            # Narrow: the pinned line is the name; the full facts are in the table row.
            assert facts.size.height == 1


@pytest.mark.asyncio
async def test_the_narrow_device_view_keeps_the_group_heading_above_its_actions() -> None:
    app = _StyledVaultHost(_Service())
    async with app.run_test(size=(100, 30)):
        screen = await _ready(app)
        await _view(screen, screen.action_devices, "devices")
        shelf = screen.query_one("#vault_action_scroll")
        group = screen.query_one("#vault_identity_group")
        heading = group.query_one(".vault_group_heading")
        approve = screen.query_one("#vault_approve")
        await wait_until(lambda: shelf.region.contains_region(heading.region)
                         and shelf.region.contains_region(approve.region))
        facts = screen.query_one("#vault_inspector_facts", Static)
        assert heading.region.y >= facts.region.bottom
