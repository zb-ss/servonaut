"""Team and shared-server pickers in the vault dialogs.

The dialogs used to ask for a team slug and server IDs as free text; they now
offer the user's teams and each team's shared servers as select boxes.
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional

import pytest
from textual.app import App
from textual.widget import Widget
from textual.widgets import Button, Input, Select, SelectionList, Static

from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.vault import (
    VaultExposureActionModal,
    VaultImportedReferenceModal,
    VaultImportedTeamBindingModal,
    VaultScreen,
    VaultSharedServerPicker,
)
from servonaut.services.api_client import APIError
from servonaut.styles import CSS_FILES
from servonaut.widgets.busy_indicator import BusyIndicator
from tests._async_bounds import wait_until

_TEAMS = [{"slug": "ops", "label": "Operations (ops)"}, {"slug": "web", "label": "Web [prod] (web)"}]
_SERVERS = {
    "ops": [{"server_id": "srv-ops-1", "label": "db-1 (10.0.0.1)"}, {"server_id": "srv-ops-2", "label": "db-2 (10.0.0.2)"}],
    "web": [{"server_id": "srv-web-1", "label": "web-1 (10.0.1.1)"}, {"server_id": "srv-web-2", "label": "web-2 (10.0.1.2)"}],
}

_NO_SERVERS = "No shared servers in this team: share one from Team Management."


class _PickerService:
    """Answers the picker calls the way the vault command service does."""

    def __init__(self, *, teams=None, servers=None, team_error=None, server_errors=None) -> None:
        self.teams = list(_TEAMS if teams is None else teams)
        self.servers = dict(_SERVERS if servers is None else servers)
        self.team_error = team_error
        self.server_errors = dict(server_errors or {})
        self.server_calls: list[str] = []
        self.release: dict[str, asyncio.Event] = {}

    async def team_choices(self):
        if self.team_error is not None:
            raise self.team_error
        return list(self.teams)

    async def shared_server_choices(self, *, team: str):
        self.server_calls.append(team)
        if team in self.release:
            await self.release[team].wait()
        if team in self.server_errors:
            raise self.server_errors[team]
        return list(self.servers.get(team, []))


class _ModalHost(App):
    """Push one dialog and record what it dismisses with."""

    def __init__(self, modal) -> None:
        super().__init__()
        self._modal = modal
        self.results: list[Any] = []

    def on_mount(self) -> None:
        self.push_screen(self._modal, self.results.append)


class _StyledModalHost(_ModalHost):
    """Load product styles so the dialog geometry is tested as users see it."""

    CSS_PATH = CSS_FILES


def _option_values(select: Select) -> list[str]:
    # Select keeps its options privately; the blank prompt row is not an option.
    return [value for _prompt, value in select._options if value is not Select.NULL]


def _option_labels(select: Select) -> list[str]:
    return [str(prompt) for prompt, value in select._options if value is not Select.NULL]


def _list_values(servers: SelectionList) -> list[str]:
    return [servers.get_option_at_index(index).value for index in range(servers.option_count)]


def _message(screen, message_id: str) -> Optional[str]:
    note = screen.query_one(f"#{message_id}", Static)
    return str(note.render()) if note.display else None


def _loading(screen) -> Optional[str]:
    """What the dialog's team/server picker is waiting for, if anything."""
    busy = screen.query_one(VaultSharedServerPicker).query_one(BusyIndicator)
    return busy.message if busy.is_active else None


def _assert_not_clipped(screen, container_id: str) -> None:
    """Every shown part of the dialog fits on screen without scrolling."""
    container = screen.query_one(f"#{container_id}", Widget)
    assert container.max_scroll_y == 0
    assert screen.region.contains_region(container.region)
    for widget in container.query("*"):
        if widget.display and widget.region.area and widget.parent is not None:
            if not any(ancestor.has_class("-expanded") for ancestor in widget.ancestors_with_self):
                assert container.region.contains_region(widget.region), widget


async def _teams_loaded(app: App, pilot, modal_type: type, prefix: str):
    """Wait until the dialog is up and its team list has loaded or said why not."""
    await wait_until(lambda: isinstance(app.screen, modal_type) and bool(app.screen.query(f"#{prefix}_team")))
    screen = app.screen
    team = screen.query_one(f"#{prefix}_team", Select)
    await wait_until(lambda: not team.disabled or _loading(screen) is None)
    await pilot.pause()
    return screen


# --- Import: bind an imported key to a team server ---------------------------


async def _import_modal_loaded(app: App, pilot) -> VaultImportedTeamBindingModal:
    return await _teams_loaded(app, pilot, VaultImportedTeamBindingModal, "vault_import_bind")


@pytest.mark.asyncio
async def test_import_binding_offers_teams_then_that_teams_servers_and_returns_the_choice() -> None:
    service = _PickerService()
    app = _ModalHost(VaultImportedTeamBindingModal(service))

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _import_modal_loaded(app, pilot)
        team = screen.query_one("#vault_import_bind_team", Select)
        server = screen.query_one("#vault_import_bind_server", Select)
        review = screen.query_one("#vault_import_bind_target_continue", Button)

        assert _option_values(team) == ["ops", "web"]
        # Labels are plain text: a bracket in a team name is not markup.
        assert _option_labels(team) == ["Operations (ops)", "Web [prod] (web)"]
        assert team.has_focus
        assert server.disabled and review.disabled
        assert service.server_calls == []

        team.value = "web"
        await wait_until(lambda: not server.disabled)
        assert service.server_calls == ["web"]
        assert _option_values(server) == ["srv-web-1", "srv-web-2"]
        assert server.is_blank() and review.disabled

        server.value = "srv-web-2"
        await wait_until(lambda: not review.disabled)
        screen.query_one("#vault_import_bind_login", Input).value = " deploy "
        await pilot.pause()  # let the layout settle so the click lands on the button
        assert await pilot.click("#vault_import_bind_target_continue")
        await wait_until(lambda: bool(app.results))

    assert app.results == [{"team": "web", "server_id": "srv-web-2", "login": "deploy"}]


@pytest.mark.asyncio
async def test_import_binding_can_be_chosen_from_the_keyboard() -> None:
    app = _ModalHost(VaultImportedTeamBindingModal(_PickerService()))

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _import_modal_loaded(app, pilot)
        server = screen.query_one("#vault_import_bind_server", Select)
        assert screen.query_one("#vault_import_bind_team", Select).has_focus

        await pilot.press("enter", "down", "enter")  # open, first team, choose
        await wait_until(lambda: not server.disabled and server.has_focus)
        await pilot.press("enter", "down", "down", "enter")  # open, second server, choose
        await wait_until(lambda: server.value == "srv-ops-2")
        screen.query_one("#vault_import_bind_target_continue", Button).press()
        await wait_until(lambda: bool(app.results))

    assert app.results == [{"team": "ops", "server_id": "srv-ops-2", "login": ""}]


@pytest.mark.asyncio
async def test_import_binding_changing_the_team_reloads_its_servers() -> None:
    service = _PickerService()
    app = _ModalHost(VaultImportedTeamBindingModal(service))

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _import_modal_loaded(app, pilot)
        team = screen.query_one("#vault_import_bind_team", Select)
        server = screen.query_one("#vault_import_bind_server", Select)
        review = screen.query_one("#vault_import_bind_target_continue", Button)

        team.value = "ops"
        await wait_until(lambda: _option_values(server) == ["srv-ops-1", "srv-ops-2"])
        server.value = "srv-ops-1"
        await wait_until(lambda: not review.disabled)

        team.value = "web"
        # The earlier team's server never counts for the new team, not even
        # before the picker has handled the change.
        assert screen.query_one(VaultSharedServerPicker).server_ids == []
        await wait_until(lambda: _option_values(server) == ["srv-web-1", "srv-web-2"])
        await wait_until(lambda: review.disabled)
        assert server.is_blank()
        assert service.server_calls == ["ops", "web"]

        # A confirm that slips through before the button greys out does not cancel.
        screen.post_message(Button.Pressed(review))
        await pilot.pause()
        assert app.screen is screen and app.results == []


@pytest.mark.asyncio
async def test_import_binding_ignores_servers_of_a_team_the_user_left() -> None:
    service = _PickerService()
    service.release["ops"] = asyncio.Event()
    app = _ModalHost(VaultImportedTeamBindingModal(service))

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _import_modal_loaded(app, pilot)
        team = screen.query_one("#vault_import_bind_team", Select)
        server = screen.query_one("#vault_import_bind_server", Select)

        team.value = "ops"
        await wait_until(lambda: service.server_calls == ["ops"])
        assert _loading(screen) == "Loading this team's shared servers…"
        assert _message(screen, "vault_import_bind_message") is None
        assert server.disabled
        team.value = "web"
        await wait_until(lambda: _option_values(server) == ["srv-web-1", "srv-web-2"])
        service.release["ops"].set()
        await pilot.pause()

        assert _option_values(server) == ["srv-web-1", "srv-web-2"]


@pytest.mark.asyncio
async def test_import_binding_preselects_a_single_team_and_server() -> None:
    service = _PickerService(teams=[_TEAMS[0]], servers={"ops": [_SERVERS["ops"][0]]})
    app = _ModalHost(VaultImportedTeamBindingModal(service))

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _import_modal_loaded(app, pilot)
        review = screen.query_one("#vault_import_bind_target_continue", Button)
        await wait_until(lambda: not review.disabled)

        assert screen.query_one("#vault_import_bind_team", Select).value == "ops"
        assert screen.query_one("#vault_import_bind_server", Select).value == "srv-ops-1"
        assert screen.query_one("#vault_import_bind_server", Select).has_focus
        review.press()
        await wait_until(lambda: bool(app.results))

    assert app.results == [{"team": "ops", "server_id": "srv-ops-1", "login": ""}]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("service", "pick_team", "expected"),
    [
        (_PickerService(teams=[]), None, "No teams yet: create or join one from Team Management."),
        (
            _PickerService(team_error=APIError(code="server_error", message="server text", status=503)),
            None,
            "Could not load your teams (HTTP 503, server_error).",
        ),
        (_PickerService(servers={"ops": []}), "ops", _NO_SERVERS),
        (
            _PickerService(server_errors={"ops": APIError(code="server_error", message="server text", status=503)}),
            "ops",
            "Could not load this team's servers (HTTP 503, server_error).",
        ),
    ],
    ids=["no-teams", "teams-fail", "no-servers", "servers-fail"],
)
async def test_import_binding_explains_an_empty_or_failed_list_and_can_be_cancelled(service, pick_team, expected) -> None:
    app = _ModalHost(VaultImportedTeamBindingModal(service))

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _import_modal_loaded(app, pilot)
        if pick_team:
            screen.query_one("#vault_import_bind_team", Select).value = pick_team
        await wait_until(lambda: _message(screen, "vault_import_bind_message") == expected)

        assert "server text" not in expected
        assert screen.query_one("#vault_import_bind_server", Select).disabled
        assert screen.query_one("#vault_import_bind_target_continue", Button).disabled
        await pilot.pause()  # let the layout settle so the click lands on the button
        assert await pilot.click("#vault_import_bind_target_cancel")
        await wait_until(lambda: bool(app.results))

    assert app.results == [None]


@pytest.mark.asyncio
async def test_demo_mode_redacts_picker_labels_but_returns_the_real_ids() -> None:
    class Redactor:
        def scrub_stream(self, text: str) -> str:
            return "redacted"

    app = _ModalHost(VaultImportedTeamBindingModal(_PickerService()))
    app.demo_mode = True
    app.redaction_service = Redactor()

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _import_modal_loaded(app, pilot)
        team = screen.query_one("#vault_import_bind_team", Select)
        server = screen.query_one("#vault_import_bind_server", Select)
        team.value = "ops"
        await wait_until(lambda: not server.disabled)

        assert _option_labels(team) == ["redacted", "redacted"]
        assert _option_labels(server) == ["redacted", "redacted"]
        server.value = "srv-ops-1"
        review = screen.query_one("#vault_import_bind_target_continue", Button)
        await wait_until(lambda: not review.disabled)
        review.press()
        await wait_until(lambda: bool(app.results))

    assert app.results == [{"team": "ops", "server_id": "srv-ops-1", "login": ""}]


@pytest.mark.asyncio
async def test_import_binding_escape_cancels_while_teams_are_loading() -> None:
    class SlowService(_PickerService):
        async def team_choices(self):
            await asyncio.Event().wait()

    app = _ModalHost(VaultImportedTeamBindingModal(SlowService()))

    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: isinstance(app.screen, VaultImportedTeamBindingModal))
        await pilot.pause()
        screen = app.screen
        assert screen.query_one("#vault_import_bind_team", Select).disabled
        assert _loading(screen) == "Loading your teams…"
        await pilot.press("escape")
        await wait_until(lambda: bool(app.results))

    assert app.results == [None]


# --- Exposures: rotate an exposed key / resolve an exposure -----------------


async def _rotation_modal_loaded(app: App, pilot) -> VaultExposureActionModal:
    return await _teams_loaded(app, pilot, VaultExposureActionModal, "vault_exposure")


@pytest.mark.asyncio
async def test_rotation_offers_a_teams_servers_as_a_checklist_and_returns_the_ids() -> None:
    service = _PickerService()
    app = _ModalHost(VaultExposureActionModal(rotation=True, service=service))

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _rotation_modal_loaded(app, pilot)
        team = screen.query_one("#vault_exposure_team", Select)
        servers = screen.query_one("#vault_exposure_servers", SelectionList)
        confirm = screen.query_one("#vault_exposure_confirm", Button)

        assert _option_values(team) == ["ops", "web"]
        assert not servers.display and confirm.disabled

        team.value = "ops"
        await wait_until(lambda: servers.display and servers.option_count == 2)
        assert _list_values(servers) == ["srv-ops-1", "srv-ops-2"]
        assert servers.selected == [] and confirm.disabled

        servers.select("srv-ops-2")
        servers.select("srv-ops-1")
        await wait_until(lambda: not confirm.disabled)
        await pilot.pause()  # let the layout settle so the click lands on the button
        assert await pilot.click("#vault_exposure_confirm")
        await wait_until(lambda: bool(app.results))

    [values] = app.results
    assert values["team"] == "ops"
    assert sorted(values["servers"].split(",")) == ["srv-ops-1", "srv-ops-2"]


@pytest.mark.asyncio
async def test_rotation_changing_the_team_replaces_the_server_checklist() -> None:
    service = _PickerService()
    app = _ModalHost(VaultExposureActionModal(rotation=True, service=service))

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _rotation_modal_loaded(app, pilot)
        team = screen.query_one("#vault_exposure_team", Select)
        servers = screen.query_one("#vault_exposure_servers", SelectionList)
        confirm = screen.query_one("#vault_exposure_confirm", Button)

        team.value = "ops"
        await wait_until(lambda: servers.option_count == 2)
        servers.select_all()
        await wait_until(lambda: not confirm.disabled)

        team.value = "web"
        await wait_until(lambda: _list_values(servers) == ["srv-web-1", "srv-web-2"])
        await wait_until(lambda: confirm.disabled)
        assert servers.selected == []
        assert service.server_calls == ["ops", "web"]


@pytest.mark.asyncio
async def test_rotation_checks_the_only_server_of_the_only_team() -> None:
    service = _PickerService(teams=[_TEAMS[1]], servers={"web": [_SERVERS["web"][0]]})
    app = _ModalHost(VaultExposureActionModal(rotation=True, service=service))

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _rotation_modal_loaded(app, pilot)
        confirm = screen.query_one("#vault_exposure_confirm", Button)
        await wait_until(lambda: not confirm.disabled)

        assert screen.query_one("#vault_exposure_team", Select).value == "web"
        assert screen.query_one("#vault_exposure_servers", SelectionList).selected == ["srv-web-1"]
        confirm.press()
        await wait_until(lambda: bool(app.results))

    assert app.results == [{"team": "web", "servers": "srv-web-1"}]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("service", "pick_team", "expected"),
    [
        (_PickerService(teams=[]), None, "No teams yet: create or join one from Team Management."),
        (_PickerService(servers={"ops": []}), "ops", _NO_SERVERS),
        (
            _PickerService(server_errors={"web": RuntimeError("boom")}),
            "web",
            "Could not load this team's servers (RuntimeError).",
        ),
        (None, None, "Vault services are unavailable in this session."),
    ],
    ids=["no-teams", "no-servers", "servers-fail", "no-service"],
)
async def test_rotation_explains_an_empty_or_failed_list_and_can_be_cancelled(service, pick_team, expected) -> None:
    app = _ModalHost(VaultExposureActionModal(rotation=True, service=service))

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _rotation_modal_loaded(app, pilot)
        if pick_team:
            screen.query_one("#vault_exposure_team", Select).value = pick_team
        await wait_until(lambda: _message(screen, "vault_exposure_message") == expected)

        assert not screen.query_one("#vault_exposure_servers", SelectionList).display
        assert screen.query_one("#vault_exposure_confirm", Button).disabled
        await pilot.pause()  # let the layout settle so the click lands on the button
        assert await pilot.click("#vault_exposure_cancel")
        await wait_until(lambda: bool(app.results))

    assert app.results == [None]


@pytest.mark.asyncio
async def test_resolution_is_one_of_the_three_outcomes_with_readable_labels() -> None:
    app = _ModalHost(VaultExposureActionModal(rotation=False))

    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: isinstance(app.screen, VaultExposureActionModal))
        await pilot.pause()
        screen = app.screen
        resolution = screen.query_one("#vault_exposure_resolution", Select)
        confirm = screen.query_one("#vault_exposure_confirm", Button)

        assert _option_values(resolution) == ["rotated", "accepted_risk", "not_deployed"]
        assert all("_" not in label for label in _option_labels(resolution))
        assert resolution.has_focus and resolution.is_blank() and confirm.disabled

        resolution.value = "accepted_risk"
        await wait_until(lambda: not confirm.disabled)
        screen.query_one("#vault_exposure_note", Input).value = "isolated lab host "
        await pilot.pause()  # let the layout settle so the click lands on the button
        assert await pilot.click("#vault_exposure_confirm")
        await wait_until(lambda: bool(app.results))

    assert app.results == [{"resolution": "accepted_risk", "note": "isolated lab host"}]


# --- Demo mode switched while a dialog is open --------------------------------


class _Redactor:
    def scrub_stream(self, _text: str) -> str:
        return "redacted"


def _demo_host(modal) -> _ModalHost:
    app = _ModalHost(modal)
    app.demo_mode = False
    app.redaction_service = _Redactor()
    return app


async def _toggle_demo(app: _ModalHost, pilot, on: bool) -> None:
    app.demo_mode = on
    app.screen.refresh_after_demo_toggle()
    for _ in range(3):  # let the redraw's own change events be handled
        await pilot.pause()


def _list_labels(servers: SelectionList) -> list[str]:
    return [str(servers.get_option_at_index(index).prompt) for index in range(servers.option_count)]


@pytest.mark.asyncio
async def test_demo_toggle_redraws_the_import_pickers_and_keeps_the_choice() -> None:
    service = _PickerService()
    app = _demo_host(VaultImportedTeamBindingModal(service))

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _import_modal_loaded(app, pilot)
        team = screen.query_one("#vault_import_bind_team", Select)
        server = screen.query_one("#vault_import_bind_server", Select)
        review = screen.query_one("#vault_import_bind_target_continue", Button)
        team.value = "ops"
        await wait_until(lambda: not server.disabled)
        server.value = "srv-ops-2"
        await wait_until(lambda: not review.disabled)

        await _toggle_demo(app, pilot, True)
        assert _option_labels(team) == ["redacted", "redacted"]
        assert _option_labels(server) == ["redacted", "redacted"]
        assert (team.value, server.value) == ("ops", "srv-ops-2")
        # Redrawing the team list is not a team change: the servers are not reloaded.
        assert service.server_calls == ["ops"]
        assert not review.disabled

        await _toggle_demo(app, pilot, False)
        assert _option_labels(team) == ["Operations (ops)", "Web [prod] (web)"]
        assert _option_labels(server) == ["db-1 (10.0.0.1)", "db-2 (10.0.0.2)"]
        assert service.server_calls == ["ops"]
        review.press()
        await wait_until(lambda: bool(app.results))

    assert app.results == [{"team": "ops", "server_id": "srv-ops-2", "login": ""}]


@pytest.mark.asyncio
async def test_demo_toggle_redraws_the_rotation_checklist_and_keeps_the_ticks() -> None:
    service = _PickerService()
    app = _demo_host(VaultExposureActionModal(rotation=True, service=service))

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _rotation_modal_loaded(app, pilot)
        screen.query_one("#vault_exposure_team", Select).value = "web"
        servers = screen.query_one("#vault_exposure_servers", SelectionList)
        await wait_until(lambda: servers.option_count == 2)
        servers.select("srv-web-2")

        await _toggle_demo(app, pilot, True)
        assert _list_labels(servers) == ["redacted", "redacted"]
        assert servers.selected == ["srv-web-2"]
        assert service.server_calls == ["web"]

        await _toggle_demo(app, pilot, False)
        assert _list_labels(servers) == ["web-1 (10.0.1.1)", "web-2 (10.0.1.2)"]
        screen.query_one("#vault_exposure_confirm", Button).press()
        await wait_until(lambda: bool(app.results))

    assert app.results == [{"team": "web", "servers": "srv-web-2"}]


@pytest.mark.asyncio
async def test_demo_toggle_redraws_the_picker_message() -> None:
    app = _demo_host(VaultExposureActionModal(rotation=True, service=_PickerService(servers={"ops": []})))

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _rotation_modal_loaded(app, pilot)
        screen.query_one("#vault_exposure_team", Select).value = "ops"
        await wait_until(lambda: _message(screen, "vault_exposure_message") == _NO_SERVERS)

        await _toggle_demo(app, pilot, True)
        assert _message(screen, "vault_exposure_message") == "redacted"
        await _toggle_demo(app, pilot, False)
        assert _message(screen, "vault_exposure_message") == _NO_SERVERS


# --- The vault screen hands the choices to the service unchanged -------------


class _ScreenService(_PickerService):
    """A ready vault identity with one open SSH-key exposure."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.rotations: list[dict] = []
        self.bindings: list[dict] = []

    async def status(self):
        return {"remote": {"identity": {"identity_id": "i"}}, "local_identity": "local-fingerprint"}

    async def list_vaults(self):
        return [{"vault_id": "vault-1", "kind": "team", "name": "Ops", "my_grant": {"version": 1}, "counts": {}}]

    async def list_exposures(self, *, vault_id):
        return {"data": [{"exposure_id": "e-1", "item_id": "item-1", "subject": "member", "reason": "member_removed"}]}

    async def rotate_ssh_key(self, **kwargs):
        self.rotations.append(kwargs)
        return {"rotated": True, "hosts": []}

    async def bind_imported_bitwarden_ref(self, **kwargs):
        self.bindings.append(kwargs)
        return {"verified": True, "legacy_cleared": kwargs["clear_legacy"]}


class _VaultHost(App):
    def __init__(self, service) -> None:
        self.vault_command_service = service
        super().__init__()

    def on_mount(self) -> None:
        self.push_screen(VaultScreen())


async def _ready_vault_screen(app: _VaultHost) -> VaultScreen:
    await wait_until(lambda: isinstance(app.screen, VaultScreen)
                     and "Identity fingerprint" in str(app.screen.query_one("#vault_status", Static).render()))
    return app.screen


async def _answer_confirmation(app: App, pilot, accept: bool) -> None:
    """Answer the typed confirmation once it has mounted, like a user would."""
    await wait_until(lambda: isinstance(app.screen, ConfirmActionScreen) and bool(app.screen.query("#confirm_input")))
    await pilot.pause()
    app.screen.dismiss(accept)


@pytest.mark.asyncio
async def test_vault_screen_rotates_on_the_picked_servers() -> None:
    service = _ScreenService()
    app = _VaultHost(service)

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready_vault_screen(app)
        screen._selected_vault_id = "vault-1"
        await screen._load_exposures()
        screen.action_rotate_exposure()
        modal = await _rotation_modal_loaded(app, pilot)
        modal.query_one("#vault_exposure_team", Select).value = "ops"
        servers = modal.query_one("#vault_exposure_servers", SelectionList)
        await wait_until(lambda: servers.option_count == 2)
        servers.select_all()
        await wait_until(lambda: not modal.query_one("#vault_exposure_confirm", Button).disabled)
        modal.query_one("#vault_exposure_confirm", Button).press()
        await _answer_confirmation(app, pilot, True)
        await wait_until(lambda: bool(service.rotations))

    [rotation] = service.rotations
    assert rotation["vault_id"] == "vault-1" and rotation["item_id"] == "item-1" and rotation["team"] == "ops"
    assert sorted(rotation["servers"]) == ["srv-ops-1", "srv-ops-2"]


@pytest.mark.asyncio
async def test_vault_screen_binds_an_imported_key_to_the_picked_server() -> None:
    service = _ScreenService()
    app = _VaultHost(service)

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _ready_vault_screen(app)
        reference = {"source": "bitwarden", "vault_item_id": "item-9", "source_ref": "bw-9"}
        offer = screen.run_worker(screen._offer_imported_bitwarden_binding("vault-1", [reference]), group="vault")
        await wait_until(lambda: isinstance(app.screen, VaultImportedReferenceModal))
        await pilot.pause()
        app.screen.query_one("#vault_import_bind_continue", Button).press()
        modal = await _import_modal_loaded(app, pilot)
        modal.query_one("#vault_import_bind_team", Select).value = "web"
        server = modal.query_one("#vault_import_bind_server", Select)
        await wait_until(lambda: not server.disabled)
        server.value = "srv-web-1"
        modal.query_one("#vault_import_bind_login", Input).value = "deploy"
        await wait_until(lambda: not modal.query_one("#vault_import_bind_target_continue", Button).disabled)
        modal.query_one("#vault_import_bind_target_continue", Button).press()
        await _answer_confirmation(app, pilot, True)
        await wait_until(lambda: bool(service.bindings))
        await _answer_confirmation(app, pilot, False)  # keep the legacy reference
        await asyncio.wait_for(offer.wait(), timeout=10)

    assert service.bindings == [{
        "vault_id": "vault-1", "item_id": "item-9", "team": "web", "server_id": "srv-web-1",
        "source_ref": "bw-9", "login": "deploy", "clear_legacy": False,
    }]


# --- Layout at 100x30 ---------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("make_modal", "container_id", "pick", "message_id"),
    [
        (lambda: VaultImportedTeamBindingModal(_PickerService()), "vault_import_bind_target_modal", None, None),
        (lambda: VaultImportedTeamBindingModal(_PickerService(servers={"web": []})), "vault_import_bind_target_modal",
         ("vault_import_bind_team", "web"), "vault_import_bind_message"),
        (lambda: VaultImportedTeamBindingModal(_PickerService(server_errors={"web": APIError(
            code="server_error", message="server text", status=503)})), "vault_import_bind_target_modal",
         ("vault_import_bind_team", "web"), "vault_import_bind_message"),
        (lambda: VaultExposureActionModal(rotation=True, service=_PickerService(servers={"web": [
            {"server_id": f"srv-{index}", "label": f"web-{index} (10.0.1.{index})"} for index in range(12)]})),
         "vault_exposure_modal", ("vault_exposure_team", "web"), None),
        (lambda: VaultExposureActionModal(rotation=True, service=_PickerService(servers={"web": []})),
         "vault_exposure_modal", ("vault_exposure_team", "web"), "vault_exposure_message"),
        (lambda: VaultExposureActionModal(rotation=False), "vault_exposure_modal", None, None),
    ],
    ids=["import", "import-no-servers", "import-servers-fail", "rotation-long-list", "rotation-no-servers", "resolve"],
)
async def test_dialogs_fit_a_100x30_terminal(make_modal, container_id, pick, message_id) -> None:
    app = _StyledModalHost(make_modal())

    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: app.screen is not app.screen_stack[0])
        screen = app.screen
        if pick:
            widget_id, value = pick
            team = screen.query_one(f"#{widget_id}", Select)
            await wait_until(lambda: not team.disabled)
            team.value = value
            if message_id:
                await wait_until(lambda: _loading(screen) is None and _message(screen, message_id) is not None)
            else:
                await wait_until(lambda: screen.query_one("#vault_exposure_servers", SelectionList).option_count == 12)
        await pilot.pause()

        _assert_not_clipped(screen, container_id)
        for button in screen.query(Button):
            assert button.region.height == 3, button
        for select in screen.query(Select):
            assert select.region.width >= 60, select


@pytest.mark.asyncio
async def test_the_loading_line_stays_while_the_newest_server_load_runs() -> None:
    """Choose a team, clear it, choose it again: the older load must not end the newer one's line."""
    service = _PickerService()
    service.release["ops"] = asyncio.Event()
    app = _ModalHost(VaultImportedTeamBindingModal(service))

    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _import_modal_loaded(app, pilot)
        team = screen.query_one("#vault_import_bind_team", Select)

        team.value = "ops"
        await wait_until(lambda: service.server_calls == ["ops"])
        team.clear()
        await wait_until(lambda: _loading(screen) is None)
        team.value = "ops"
        await wait_until(lambda: service.server_calls == ["ops", "ops"])
        for _ in range(5):
            await pilot.pause()
        assert _loading(screen) == "Loading this team's shared servers…"

        service.release["ops"].set()
        await wait_until(lambda: _loading(screen) is None)
