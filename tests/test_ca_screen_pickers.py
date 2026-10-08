"""The SSH Certificates screen offers teams, servers and break-glass keys as pickers."""
from __future__ import annotations

import asyncio
import copy
from typing import Any

import pytest
from textual.app import App
from textual.pilot import Pilot
from textual.screen import Screen
from textual.widgets import Button, OptionList, Select, Static

from servonaut.screens.ca import _EVERY_ENROLLED_SERVER, CaScreen
from servonaut.services.api_client import APIError, FeatureDisabledError
from servonaut.services.vault.errors import SSH_CA_COMING_SOON, VaultUserError
from servonaut.styles import CSS_FILES
from tests._async_bounds import wait_until

_TEAMS = [{"slug": "ops", "label": "Ops (ops)"}, {"slug": "platform", "label": "Platform (platform)"}]
_SERVERS = {
    "ops": [{"server_id": "srv-web", "label": "web-1 (web-1)"}, {"server_id": "srv-db", "label": "db-1"}],
    "platform": [{"server_id": "srv-build", "label": "build-1"}],
}
_ITEMS = {
    "vault-ops": [
        {"item_id": "bg-1", "type": "break_glass", "public_fingerprint": "SHA256:breakglass-one"},
        {"item_id": "bg-old", "type": "break_glass", "public_fingerprint": "SHA256:retired", "deleted": True},
        {"item_id": "key-1", "type": "ssh_key", "public_fingerprint": "SHA256:deploy-key"},
    ],
}
_EVERY = "All enrolled servers (KRL delivery and scan only)"
_CA_ACTIONS = ("#ca_audit", "#ca_enroll", "#ca_krl", "#ca_break_glass_scan")
_WARNING = {"severity": "warning", "markup": False}


class _PickerService:
    """The VaultCommandService surface the CA screen reads, with every call recorded.

    A call named in ``gates`` waits for that event after it is recorded, the
    way a slow service or a host write still in progress would.
    """

    def __init__(
        self, *, teams: list[dict[str, str]] | None = None, servers: dict[str, list[dict[str, str]]] | None = None,
    ) -> None:
        self.teams = copy.deepcopy(_TEAMS if teams is None else teams)
        self.servers = copy.deepcopy(_SERVERS if servers is None else servers)
        self.vaults = {"ops": [{"vault_id": "vault-ops", "label": "Ops vault (team ops)"}]}
        self.items = copy.deepcopy(_ITEMS)
        self.failures: dict[str, Exception] = {}
        self.gates: dict[str, asyncio.Event] = {}
        self.switched_off: set[str] = set()
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.finished: list[str] = []

    async def _answer(self, name: str, **kwargs: Any) -> None:
        self.calls.append((name, kwargs))
        if name in self.gates:
            await self.gates[name].wait()
        if name in self.failures:
            raise self.failures[name]
        self.finished.append(name)

    def calls_to(self, name: str) -> list[dict[str, Any]]:
        return [kwargs for called, kwargs in self.calls if called == name]

    async def team_choices(self) -> list[dict[str, str]]:
        await self._answer("team_choices")
        return self.teams

    async def shared_server_choices(self, *, team: str) -> list[dict[str, str]]:
        await self._answer("shared_server_choices", team=team)
        return self.servers.get(team, [])

    async def vault_choices(self, *, team: str | None = None) -> list[dict[str, str]]:
        await self._answer("vault_choices", team=team)
        return self.vaults.get(team or "", [])

    async def list_items(self, *, vault_id: str, include_deleted: bool = False) -> dict[str, Any]:
        await self._answer("list_items", vault_id=vault_id)
        return {"data": self.items.get(vault_id, []), "meta": {"next_cursor": None}}

    async def ca_status(self, *, team: str) -> dict[str, Any]:
        await self._answer("ca_status", team=team)
        if team in self.switched_off:
            raise FeatureDisabledError(
                code="feature_disabled", message="server text", status=503, details={"feature": "ssh_ca"},
            )
        return {"team": team, "enabled": True}

    async def ca_audit(self, *, team: str) -> dict[str, Any]:
        await self._answer("ca_audit", team=team)
        return {"ok": True}

    async def ca_enroll(self, *, team: str, server: str, break_glass_item_id: str | None, confirmation: Any):
        await self._answer("ca_enroll", team=team, server=server, break_glass_item_id=break_glass_item_id)
        return {"status": "enrolled"}

    async def ca_deliver_krl(self, *, team: str, servers: list[str]):
        await self._answer("ca_deliver_krl", team=team, servers=servers)
        return {"results": []}

    async def ca_break_glass_scan(self, *, team: str, servers: list[str] | None = None):
        await self._answer("ca_break_glass_scan", team=team, servers=servers)
        return {"reported": 0}


class _Host(App):
    def __init__(self, service: Any) -> None:
        super().__init__()
        self.vault_command_service = service
        self.notes: list[tuple[str, dict[str, Any]]] = []

    def notify(self, message: str, **kwargs: Any) -> None:
        self.notes.append((message, kwargs))

    def on_mount(self) -> None:
        self.push_screen(CaScreen())


class _StyledHost(_Host):
    CSS_PATH = CSS_FILES


def _picker(screen: Screen, picker_id: str) -> Select:
    return screen.query_one(f"#{picker_id}", Select)


def _labels(select: Select) -> list[str]:
    """The options a picker offers, without its blank entry."""
    overlay = select.query_one(OptionList)
    return [str(overlay.get_option_at_index(index).prompt) for index in range(1, overlay.option_count)]


def _text(screen: Screen, widget_id: str) -> str:
    return str(screen.query_one(f"#{widget_id}", Static).render())


async def _teams_loaded(screen: Screen) -> Select:
    team = _picker(screen, "ca_team")
    await wait_until(lambda: "Loading" not in team.prompt)
    return team


async def _team_settled(pilot: Pilot, screen: Screen) -> None:
    """Wait until the chosen team's server and break-glass pickers are filled."""
    pickers = [_picker(screen, "ca_server"), _picker(screen, "ca_break_glass")]
    await wait_until(lambda: not any("Loading" in picker.prompt for picker in pickers))
    await pilot.pause()  # a guidance line may have moved the buttons


async def _choose_team(pilot: Pilot, service: _PickerService, screen: Screen, slug: str) -> None:
    """Choose another team and wait for its status, servers and break-glass keys."""
    before = len(service.calls_to("ca_status"))
    (await _teams_loaded(screen)).value = slug
    await wait_until(lambda: len(service.calls_to("ca_status")) > before)
    await _team_settled(pilot, screen)


async def _click(pilot: Pilot, selector: str) -> None:
    """Click a button once its last press has finished: a button ignores clicks while it animates one."""
    button = pilot.app.screen.query_one(selector, Button)
    await wait_until(lambda: not button.has_class("-active"))
    await pilot.click(selector)


async def _press(pilot: Pilot, service: _PickerService, button: str, call: str) -> dict[str, Any]:
    """Click an enabled button, wait for the service call and for the action to end."""
    widget = pilot.app.screen.query_one(button, Button)
    await wait_until(lambda: not widget.disabled)
    before = len(service.calls_to(call))
    await _click(pilot, button)
    await wait_until(lambda: len(service.calls_to(call)) > before)
    await wait_until(lambda: not widget.disabled)
    return service.calls_to(call)[-1]


async def _refused(pilot: Pilot, screen: Screen, button: str, message: str) -> None:
    """Deliver a press the way a click queued before the button was disabled arrives, and expect *message*."""
    app = pilot.app
    before = len(app.notes)
    screen.post_message(Button.Pressed(screen.query_one(button, Button)))
    await wait_until(lambda: len(app.notes) > before)
    assert app.notes[-1] == (message, _WARNING)


def _ca_actions_disabled(screen: Screen) -> list[bool]:
    return [screen.query_one(selector, Button).disabled for selector in _CA_ACTIONS]


@pytest.mark.asyncio
async def test_teams_load_and_choosing_one_loads_its_status_servers_and_break_glass_keys() -> None:
    service = _PickerService()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        team = await _teams_loaded(screen)
        assert _labels(team) == ["Ops (ops)", "Platform (platform)"]
        assert team.is_blank() and not team.disabled  # two teams: the user chooses
        assert _picker(screen, "ca_server").disabled
        assert _ca_actions_disabled(screen) == [True, True, True, True]
        assert service.calls_to("ca_status") == []

        await _choose_team(pilot, service, screen, "ops")

        server, break_glass = _picker(screen, "ca_server"), _picker(screen, "ca_break_glass")
        assert service.calls_to("ca_status") == [{"team": "ops"}]
        assert service.calls_to("shared_server_choices") == [{"team": "ops"}]
        assert _labels(server) == [_EVERY, "web-1 (web-1)", "db-1"]
        assert server.is_blank() and server.prompt == "Choose a server" and not server.disabled
        # Only live break-glass items, by fingerprint: not deleted ones, not SSH keys.
        assert _labels(break_glass) == ["Break-glass key SHA256:breakglass-one"]
        assert break_glass.is_blank() and break_glass.prompt == "No break-glass key"
        assert service.calls_to("list_items") == [{"vault_id": "vault-ops"}]
        assert not screen.query_one("#ca_hint", Static).display
        assert _ca_actions_disabled(screen) == [False, False, False, False]


@pytest.mark.asyncio
async def test_a_single_team_is_chosen_for_the_user() -> None:
    service = _PickerService(teams=[_TEAMS[0]])
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await wait_until(lambda: "team: ops" in _text(screen, "ca_status"))
        await _team_settled(pilot, screen)
        assert _picker(screen, "ca_team").value == "ops"
        assert service.calls_to("ca_status") == [{"team": "ops"}]
        assert _labels(_picker(screen, "ca_server")) == [_EVERY, "web-1 (web-1)", "db-1"]


@pytest.mark.asyncio
async def test_a_blank_server_choice_never_means_every_server() -> None:
    service = _PickerService()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")

        for button in ("#ca_krl", "#ca_break_glass_scan"):
            await _click(pilot, button)
            await wait_until(lambda: bool(app.notes))
            assert app.notes.pop() == ("Choose a server, or all enrolled servers, first.", _WARNING)
        await _click(pilot, "#ca_enroll")
        await wait_until(lambda: bool(app.notes))
        assert app.notes.pop() == ("Choose a server to enroll first.", _WARNING)
        assert not {"ca_deliver_krl", "ca_break_glass_scan", "ca_enroll"} & {name for name, _ in service.calls}


@pytest.mark.asyncio
async def test_every_enrolled_server_is_an_explicit_choice_for_krl_and_scan_but_not_enrollment() -> None:
    service = _PickerService()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        _picker(screen, "ca_server").value = _EVERY_ENROLLED_SERVER
        await pilot.pause()

        assert await _press(pilot, service, "#ca_krl", "ca_deliver_krl") == {"team": "ops", "servers": []}
        assert await _press(pilot, service, "#ca_break_glass_scan", "ca_break_glass_scan") == {
            "team": "ops", "servers": None,
        }
        await _click(pilot, "#ca_enroll")
        await wait_until(lambda: bool(app.notes))
        assert app.notes == [("Choose a server to enroll first.", _WARNING)]
        assert service.calls_to("ca_enroll") == []


@pytest.mark.asyncio
async def test_actions_use_the_selected_server_id() -> None:
    service = _PickerService()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        _picker(screen, "ca_server").value = "srv-db"
        await pilot.pause()

        assert await _press(pilot, service, "#ca_enroll", "ca_enroll") == {
            "team": "ops", "server": "srv-db", "break_glass_item_id": None,
        }
        assert await _press(pilot, service, "#ca_krl", "ca_deliver_krl") == {"team": "ops", "servers": ["srv-db"]}
        assert await _press(pilot, service, "#ca_break_glass_scan", "ca_break_glass_scan") == {
            "team": "ops", "servers": ["srv-db"],
        }


@pytest.mark.asyncio
async def test_enrollment_takes_the_chosen_break_glass_key_or_none() -> None:
    service = _PickerService()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        _picker(screen, "ca_server").value = "srv-web"
        break_glass = _picker(screen, "ca_break_glass")

        break_glass.value = "bg-1"
        await pilot.pause()
        assert (await _press(pilot, service, "#ca_enroll", "ca_enroll"))["break_glass_item_id"] == "bg-1"

        break_glass.clear()  # the "No break-glass key" choice
        await pilot.pause()
        assert (await _press(pilot, service, "#ca_enroll", "ca_enroll"))["break_glass_item_id"] is None


@pytest.mark.asyncio
async def test_refresh_reloads_the_pickers_and_keeps_the_choices() -> None:
    service = _PickerService()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        _picker(screen, "ca_server").value = "srv-db"
        _picker(screen, "ca_break_glass").value = "bg-1"
        service.servers["ops"].append({"server_id": "srv-new", "label": "new-1"})

        await pilot.press("r")
        await wait_until(lambda: len(service.calls_to("shared_server_choices")) == 2)
        await _team_settled(pilot, screen)

        assert len(service.calls_to("ca_status")) == 2
        assert "new-1" in _labels(_picker(screen, "ca_server"))
        assert _picker(screen, "ca_server").value == "srv-db"
        assert _picker(screen, "ca_break_glass").value == "bg-1"

        _picker(screen, "ca_server").value = _EVERY_ENROLLED_SERVER
        await pilot.press("r")
        await wait_until(lambda: len(service.calls_to("shared_server_choices")) == 3)
        await _team_settled(pilot, screen)
        assert _picker(screen, "ca_server").value is _EVERY_ENROLLED_SERVER


@pytest.mark.asyncio
async def test_krl_during_a_refresh_never_reaches_every_server() -> None:
    service = _PickerService()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        _picker(screen, "ca_server").value = "srv-db"
        service.gates["shared_server_choices"] = asyncio.Event()

        await pilot.press("r")
        await wait_until(lambda: len(service.calls_to("shared_server_choices")) == 2)
        # While the list reloads, the server picker is empty and the server actions wait.
        assert _picker(screen, "ca_server").is_blank()
        assert _ca_actions_disabled(screen) == [False, True, True, True]
        await pilot.click("#ca_krl")
        await _refused(pilot, screen, "#ca_krl", "Wait for this team's servers to load.")
        await _refused(pilot, screen, "#ca_break_glass_scan", "Wait for this team's servers to load.")
        await _refused(pilot, screen, "#ca_enroll", "Wait for this team's servers to load.")
        assert service.calls_to("ca_deliver_krl") == [] and service.calls_to("ca_break_glass_scan") == []

        service.gates["shared_server_choices"].set()
        await _team_settled(pilot, screen)
        assert _picker(screen, "ca_server").value == "srv-db"
        assert await _press(pilot, service, "#ca_krl", "ca_deliver_krl") == {"team": "ops", "servers": ["srv-db"]}


@pytest.mark.asyncio
async def test_enrollment_waits_for_the_break_glass_keys_to_reload() -> None:
    service = _PickerService()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        _picker(screen, "ca_server").value = "srv-web"
        _picker(screen, "ca_break_glass").value = "bg-1"
        service.gates["list_items"] = asyncio.Event()

        await pilot.press("r")
        await wait_until(lambda: len(service.calls_to("list_items")) == 2)
        await wait_until(lambda: _picker(screen, "ca_server").value == "srv-web")
        # The chosen break-glass key is not dropped by an enrollment started mid-reload.
        assert screen.query_one("#ca_enroll", Button).disabled
        assert not screen.query_one("#ca_krl", Button).disabled
        await _refused(pilot, screen, "#ca_enroll", "Wait for this team's break-glass keys to load.")

        service.gates["list_items"].set()
        await _team_settled(pilot, screen)
        assert (await _press(pilot, service, "#ca_enroll", "ca_enroll"))["break_glass_item_id"] == "bg-1"


@pytest.mark.asyncio
async def test_a_second_action_neither_starts_nor_cancels_a_running_enrollment() -> None:
    service = _PickerService()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        _picker(screen, "ca_server").value = "srv-web"
        service.gates["ca_enroll"] = asyncio.Event()
        await pilot.pause()

        await _click(pilot, "#ca_enroll")
        await wait_until(lambda: len(service.calls_to("ca_enroll")) == 1)  # writing to the host
        assert _ca_actions_disabled(screen) == [True, True, True, True]
        await _refused(pilot, screen, "#ca_audit", "Another CA action is still running.")
        await _refused(pilot, screen, "#ca_krl", "Another CA action is still running.")
        await _click(pilot, "#ca_refresh")  # Refresh still works and does not cancel it
        await wait_until(lambda: len(service.calls_to("ca_status")) == 2)
        await _team_settled(pilot, screen)
        assert service.calls_to("ca_audit") == [] and service.calls_to("ca_deliver_krl") == []
        await pilot.press("escape")  # leaving the screen would cancel the enrollment
        await pilot.pause()
        assert app.screen is screen

        service.gates["ca_enroll"].set()
        await wait_until(lambda: "enrolled" in _text(screen, "ca_status"))
        assert "ca_enroll" in service.finished
        await wait_until(lambda: _ca_actions_disabled(screen) == [False, False, False, False])


@pytest.mark.asyncio
async def test_choosing_another_team_does_not_cancel_a_running_action() -> None:
    service = _PickerService()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        _picker(screen, "ca_server").value = _EVERY_ENROLLED_SERVER
        service.gates["ca_deliver_krl"] = asyncio.Event()
        await pilot.pause()

        await _click(pilot, "#ca_krl")
        await wait_until(lambda: len(service.calls_to("ca_deliver_krl")) == 1)
        await _choose_team(pilot, service, screen, "platform")
        assert _ca_actions_disabled(screen) == [True, True, True, True]  # the delivery still runs

        service.gates["ca_deliver_krl"].set()
        await wait_until(lambda: "ca_deliver_krl" in service.finished)
        await wait_until(lambda: _ca_actions_disabled(screen) == [False, False, False, False])


@pytest.mark.asyncio
async def test_coming_soon_holds_back_actions_until_another_team_is_chosen() -> None:
    service = _PickerService()
    service.switched_off.add("ops")
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        assert _text(screen, "ca_status") == SSH_CA_COMING_SOON
        assert _ca_actions_disabled(screen) == [True, True, True, True]
        assert app.notes == []

        await _press(pilot, service, "#ca_refresh", "ca_status")  # the same team: still held back
        await _team_settled(pilot, screen)
        assert _ca_actions_disabled(screen) == [True, True, True, True]

        await _choose_team(pilot, service, screen, "platform")
        assert _ca_actions_disabled(screen) == [False, False, False, False]
        assert _labels(_picker(screen, "ca_server")) == [_EVERY, "build-1"]

        await _choose_team(pilot, service, screen, "ops")
        assert _ca_actions_disabled(screen) == [True, True, True, True]
        _picker(screen, "ca_team").clear()
        await wait_until(lambda: _text(screen, "ca_status") == "Choose a team to inspect its CA status.")
        assert screen._switched_off_team is None
        assert _ca_actions_disabled(screen) == [True, True, True, True]  # no team chosen
        assert _picker(screen, "ca_server").disabled and _picker(screen, "ca_server").prompt == "Choose a team first"


@pytest.mark.asyncio
async def test_no_teams_explains_where_to_join_one_and_refresh_lists_them_again() -> None:
    service = _PickerService(teams=[])
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        team = await _teams_loaded(screen)
        assert team.disabled and team.prompt == "No teams"
        assert "create or join one from Team Management" in _text(screen, "ca_hint")

        service.teams = list(_TEAMS)
        await pilot.press("r")
        await wait_until(lambda: not team.disabled)
        assert _labels(team) == ["Ops (ops)", "Platform (platform)"]
        assert "Team Management" not in _text(screen, "ca_hint")


@pytest.mark.asyncio
async def test_a_failed_team_list_says_why_and_refresh_retries() -> None:
    service = _PickerService()
    service.failures["team_choices"] = APIError(code="server_error", message="server text", status=503)
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        team = await _teams_loaded(screen)
        assert team.disabled and team.prompt == "Teams unavailable"
        assert _text(screen, "ca_hint") == "Could not load your teams (HTTP 503, server_error). Refresh to try again."
        assert app.notes == []

        del service.failures["team_choices"]
        await _click(pilot, "#ca_refresh")
        await wait_until(lambda: not team.disabled)
        assert len(service.calls_to("team_choices")) == 2


@pytest.mark.asyncio
async def test_a_team_without_shared_servers_points_to_team_management() -> None:
    service = _PickerService(servers={"ops": []})
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        server = _picker(screen, "ca_server")
        assert server.disabled and server.prompt == "No shared servers"
        assert _labels(server) == []  # nothing to deliver to, not even "every enrolled server"
        hint = "No shared servers in this team yet: share one from Team Management."
        assert _text(screen, "ca_hint") == hint
        assert _ca_actions_disabled(screen) == [False, True, True, True]
        await _refused(pilot, screen, "#ca_krl", hint)
        assert service.calls_to("ca_deliver_krl") == []


@pytest.mark.asyncio
async def test_failed_server_and_break_glass_loads_say_why_without_markup() -> None:
    service = _PickerService()
    service.failures["shared_server_choices"] = VaultUserError("team [b]ops[/b] is not readable")
    service.failures["list_items"] = APIError(code="vault_locked", message="server text", status=423)
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        server, break_glass = _picker(screen, "ca_server"), _picker(screen, "ca_break_glass")
        assert server.disabled and server.prompt == "Servers unavailable"
        assert break_glass.disabled and break_glass.prompt == "No break-glass key"
        assert _text(screen, "ca_hint").splitlines() == [
            "Could not load this team's servers (team [b]ops[/b] is not readable). Refresh to try again.",
            "Could not load break-glass keys (HTTP 423, vault_locked).",
        ]
        assert app.notes == []
        # A failed server list is never read as "every server".
        assert _ca_actions_disabled(screen) == [False, True, True, True]
        await _refused(pilot, screen, "#ca_krl", "This team's servers did not load: Refresh to try again.")
        await _refused(pilot, screen, "#ca_break_glass_scan", "This team's servers did not load: Refresh to try again.")
        assert service.calls_to("ca_deliver_krl") == [] and service.calls_to("ca_break_glass_scan") == []


@pytest.mark.asyncio
async def test_a_failed_break_glass_list_still_allows_enrollment_without_one() -> None:
    service = _PickerService()
    service.failures["list_items"] = APIError(code="vault_locked", message="server text", status=423)
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        _picker(screen, "ca_server").value = "srv-web"
        await pilot.pause()
        assert (await _press(pilot, service, "#ca_enroll", "ca_enroll"))["break_glass_item_id"] is None


@pytest.mark.asyncio
async def test_a_team_without_break_glass_keys_says_so() -> None:
    service = _PickerService()
    service.items = {}
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        break_glass = _picker(screen, "ca_break_glass")
        assert break_glass.disabled and break_glass.prompt == "No break-glass keys in this team"
        assert not screen.query_one("#ca_hint", Static).display
        assert not screen.query_one("#ca_enroll", Button).disabled


@pytest.mark.asyncio
async def test_labels_are_shown_literally_and_redacted_in_demo_mode() -> None:
    class Redactor:
        def scrub_stream(self, text: str) -> str:
            return text.replace("web-1", "host-redacted")

    service = _PickerService(teams=[{"slug": "ops", "label": "[bold]Ops[/bold] (ops)"}, _TEAMS[1]])
    app = _Host(service)
    app.redaction_service = Redactor()
    app.demo_mode = False
    async with app.run_test(size=(160, 50)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        server = _picker(screen, "ca_server")
        server.value = "srv-web"
        assert _labels(_picker(screen, "ca_team")) == ["[bold]Ops[/bold] (ops)", "Platform (platform)"]

        app.demo_mode = True
        screen.refresh_after_demo_toggle()
        await pilot.pause()
        assert _labels(server) == [_EVERY, "host-redacted (host-redacted)", "db-1"]
        assert server.value == "srv-web"
        assert _picker(screen, "ca_team").value == "ops"
        assert service.calls_to("ca_status") == [{"team": "ops"}]  # relabelling reloads nothing


@pytest.mark.asyncio
async def test_pickers_fit_and_actions_stay_reachable_at_100x30() -> None:
    service = _PickerService()
    app = _StyledHost(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = app.screen
        await _choose_team(pilot, service, screen, "ops")
        content = screen.query_one("#ca_content")
        # The team picker takes focus once loaded; the pickers stay in view, not scrolled past.
        assert app.focused is _picker(screen, "ca_team")
        assert content.scroll_y == 0
        for picker_id in ("ca_team", "ca_server", "ca_break_glass"):
            picker = _picker(screen, picker_id)
            assert picker.region.width > 20
            assert content.region.x <= picker.region.x and picker.region.right <= content.region.right
            assert picker.region.height == 3

        scan = screen.query_one("#ca_break_glass_scan")
        content.scroll_to_widget(scan, animate=False)
        await pilot.pause()
        assert scan.region.bottom <= content.region.bottom
