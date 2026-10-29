"""Use Vault Key distinguishes a personal key from each sharing team's key."""
from __future__ import annotations

from base64 import b64encode
from types import MappingProxyType, SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from textual.app import App
from textual.widgets import Button, Input, OptionList, Select, Static

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens import server_actions
from servonaut.screens._demo_resolve import replace_instances
from servonaut.screens.server_actions import ServerActionsScreen, VaultBindingModal
from servonaut.services.redaction_service import RedactionService
from servonaut.services.shared_servers import shared_row
from servonaut.services.vault import crypto
from servonaut.styles import CSS_FILES
from tests.test_vault_bind_picker import KEY_ITEM, PERSONAL_VAULT, TEAM_VAULT, _Service, _host_key, _settle


def _own() -> dict:
    return {"id": "i-1", "name": "web-1", "public_ip": "9.9.9.9", "username": "deploy"}


def _shared(slug: str = "team-a", role: str = "owner", **changes: Any) -> dict:
    return shared_row(
        {"id": f"shared-{slug}", "hostname": "9.9.9.9", "username": "deploy", **changes},
        {"slug": slug, "name": slug, "role": role},
    )


def _signed_binding(server: str = "shared-team-a") -> dict[str, Any]:
    """A synthetic API binding with a real signature over its fixture fields."""
    binding = {
        "source": "servonaut_vault", "valid": True,
        "target": f"shared_server:{server}",
        "vault_id": TEAM_VAULT, "vault_item_id": KEY_ITEM,
        "hostname": "9.9.9.9", "port": 22, "login_user": "deploy",
        "public_fingerprint": crypto.ssh_public_fingerprint(_host_key()),
        "host_keys": [_host_key()], "binding_revision": 1,
        "binder_identity_id": KEY_ITEM,
    }
    message = crypto.binding_message(
        "team:1", binding["target"], binding["hostname"], binding["port"],
        binding["login_user"], binding["vault_id"], binding["vault_item_id"],
        binding["public_fingerprint"], binding["host_keys"],
        binding["binding_revision"], binding["binder_identity_id"],
    )
    binding["signature"] = b64encode(Ed25519PrivateKey.generate().sign(message)).decode("ascii")
    return binding


class _BindingService(_Service):
    def __init__(self) -> None:
        super().__init__()
        self.keys[TEAM_VAULT] = self.keys[TEAM_VAULT][:1]
        self.store = SimpleNamespace(identity=object())
        self.personal_binding = AsyncMock(return_value=None)
        self.bind = AsyncMock(side_effect=lambda **values: _signed_binding(values["server"]))
        self.bind_personal = AsyncMock(return_value={"source": "servonaut_vault"})

    def ssh_destination(self, instance: dict) -> tuple[str, int]:
        return instance["public_ip"], instance.get("port", 22)


class _Host(App):
    CSS_PATH = CSS_FILES

    def __init__(self, rows: list[dict], *, target: int = 0, demo: bool = False) -> None:
        super().__init__()
        self.demo_mode = demo
        self.redaction_service = RedactionService() if demo else None
        self.config_manager = SimpleNamespace(get=lambda: AppConfig())
        self.connection_service = MagicMock()
        self.connection_service.resolve_profile.return_value = None
        self.vault_command_service = _BindingService()
        self.vault_lease_cache = MagicMock()
        self.instances = []
        self._demo_known_cache = None
        replace_instances(self, None, rows)
        self.actions = ServerActionsScreen(self.instances[target])
        self.notices: list[tuple[str, dict]] = []

    def on_mount(self) -> None:
        self.push_screen(self.actions)

    def connection_instance(self, instance: dict) -> dict:
        return ServonautApp.connection_instance(self, instance)

    def redact_display_text(self, text: str) -> str:
        return ServonautApp.redact_display_text(self, text)

    def _demo_known_identifiers(self) -> Any:
        return ServonautApp._demo_known_identifiers(self)

    def notify(self, message: str, **kwargs: Any) -> None:
        self.notices.append((message, kwargs))


async def _start(pilot: Any) -> None:
    await _settle(pilot, lambda: pilot.app.screen is pilot.app.actions)
    pilot.app.actions.query_one("#btn_use_vault_key", Button).press()
    await _settle(pilot, lambda: pilot.app.screen is not pilot.app.actions and pilot.app.screen.is_mounted)
    await pilot.pause()


async def _choose_scope(pilot: Any, index: int) -> None:
    assert type(pilot.app.screen).__name__ == "VaultBindingScopeModal"
    choices = pilot.app.screen.query_one("#vault_scope_choices", OptionList)
    choices.highlighted = index
    choices.focus()
    await pilot.press("enter")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("personal", [False, True])
async def test_own_shared_server_binds_the_scope_chosen_by_the_user(
    size: tuple[int, int], personal: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(server_actions, "trusted_host_keys", lambda *_args: [])
    app = _Host([_own(), _shared(), _shared("team-b", "admin")])
    async with app.run_test(size=size) as pilot:
        await _start(pilot)
        choices = app.screen.query_one(OptionList)
        assert choices.option_count == 3
        assert [choices.get_option_at_index(i).prompt.plain.splitlines()[0] for i in range(3)] == [
            "Everyone in team team-a", "Everyone in team team-b", "Just me",
        ]
        assert choices.highlighted == 2  # Enter alone never changes a team's key.
        modal = app.screen.query_one("#vault_scope_modal")
        assert app.screen.region.contains_region(modal.region)
        assert modal.region.contains_region(app.screen.query_one("#vault_scope_cancel").region)
        await _choose_scope(pilot, 2 if personal else 1)
        await _settle(pilot, lambda: isinstance(app.screen, VaultBindingModal))
        binding_modal = app.screen
        await _settle(pilot, lambda: app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM)
        service = app.vault_command_service
        assert service.vault_calls == [None if personal else "team-b"]
        assert binding_modal._instance["id"] == ("i-1" if personal else "shared-team-b")
        vault = app.screen.query_one("#vault_bind_vault", Select)
        assert vault.value == (PERSONAL_VAULT if personal else TEAM_VAULT)
        assert len(binding_modal._vault_choices) == (2 if personal else 1)
        app.screen.query_one("#vault_bind_host_keys", Input).value = _host_key()
        # The footer is reachable even at 100x30.
        confirm = app.screen.query_one("#vault_bind_confirm", Button)
        await pilot.pause()
        assert app.screen.region.contains_region(confirm.region)
        assert await pilot.click("#vault_bind_confirm")
        await _settle(pilot, lambda: bool(app.notices))
        assert app.screen is app.actions
        if personal:
            service.bind.assert_not_awaited()
            assert service.bind_personal.await_args.kwargs["instance_id"] == "i-1"
            assert "Your key" in app.actions._credential_source_line()
            assert "credential_binding" not in app.instances[2]
            assert "Your key" in app.notices[-1][0]
        else:
            service.bind_personal.assert_not_awaited()
            assert service.bind.await_args.kwargs["team"] == "team-b"
            assert service.bind.await_args.kwargs["server"] == "shared-team-b"
            assert app.actions._binding_source() is None  # This did not create a personal binding.
            assert "Team key for team-b" in app.actions._credential_source_line()
            assert "credential_binding" not in app.instances[0]
            assert "credential_binding" not in app.instances[1]
            assert app.instances[2]["credential_binding"]["source"] == "servonaut_vault"
            assert app._instances_pristine[2]["credential_binding"]["source"] == "servonaut_vault"
            assert "Team key for team-b" in app.notices[-1][0]
            assert {call.args[0]["id"] for call in app.vault_lease_cache.forget.call_args_list} == {
                "i-1", "shared-team-b",
            }
            await app.actions._refresh_vault_binding()
            assert "Team key for team-b" in str(app.screen.query_one("#server_info", Static).render())
        assert app.notices[-1][1]["markup"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("shared", [False, True])
async def test_unshared_own_and_direct_team_rows_skip_the_scope_picker(shared: bool) -> None:
    row = _shared() if shared else _own()
    app = _Host([row])
    async with app.run_test(size=(100, 30)) as pilot:
        await _start(pilot)
        assert isinstance(app.screen, VaultBindingModal)
        assert app.screen._instance["id"] == row["id"]
        await _settle(pilot, lambda: bool(app.vault_command_service.vault_calls))
        assert app.vault_command_service.vault_calls == ["team-a" if shared else None]
        await pilot.press("escape")
        await _settle(pilot, lambda: app.screen is app.actions)
        app.vault_command_service.bind.assert_not_awaited()
        app.vault_command_service.bind_personal.assert_not_awaited()


@pytest.mark.asyncio
async def test_scope_lists_each_team_once_and_disables_non_admin_roles() -> None:
    rows = [_own(), _shared(), _shared(), _shared("team-b", "admin")]
    rows += [_shared(f"team-{index}", role) for index, role in enumerate(["member", "viewer", "", "unknown"])]
    rows += [_shared("unrelated", hostname="8.8.8.8")]
    app = _Host(rows)
    async with app.run_test(size=(100, 30)) as pilot:
        await _start(pilot)
        assert type(app.screen).__name__ == "VaultBindingScopeModal"
        choices = app.screen.query_one(OptionList)
        assert choices.option_count == 7
        for index in range(6):
            option = choices.get_option_at_index(index)
            assert option.disabled is (index >= 2)
            if option.disabled:
                assert "Only a team owner or admin" in option.prompt.plain
        # A disabled option cannot dispatch a binding, even when highlighted programmatically.
        await _choose_scope(pilot, 2)
        assert type(app.screen).__name__ == "VaultBindingScopeModal"
        assert not app.vault_command_service.vault_calls
        await _choose_scope(pilot, 6)
        await _settle(pilot, lambda: isinstance(app.screen, VaultBindingModal))


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", ["escape", "button"])
async def test_cancelling_scope_never_opens_the_key_picker(cancel: str) -> None:
    app = _Host([_own(), _shared()])
    async with app.run_test() as pilot:
        await _start(pilot)
        assert type(app.screen).__name__ == "VaultBindingScopeModal"
        if cancel == "escape":
            await pilot.press("escape")
        else:
            assert await pilot.click("#vault_scope_cancel")
        await _settle(pilot, lambda: app.screen is app.actions)
        assert not app.vault_command_service.vault_calls


@pytest.mark.asyncio
@pytest.mark.parametrize("after_key_picker", [False, True])
async def test_scope_permission_is_rechecked_before_opening_and_saving(after_key_picker: bool) -> None:
    app = _Host([_own(), _shared()])
    async with app.run_test() as pilot:
        await _start(pilot)
        if after_key_picker:
            await _choose_scope(pilot, 0)
            await _settle(pilot, lambda: isinstance(app.screen, VaultBindingModal))
            await _settle(pilot, lambda: app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM)
        app.instances[1]["team_role"] = "member"
        if after_key_picker:
            app.screen.query_one("#vault_bind_confirm", Button).press()
        else:
            await _choose_scope(pilot, 0)
        await _settle(pilot, lambda: bool(app.notices))
        app.vault_command_service.bind.assert_not_awaited()
        app.vault_command_service.bind_personal.assert_not_awaited()
        assert "Only a team owner or admin" in app.notices[-1][0]


@pytest.mark.asyncio
async def test_team_names_are_literal_and_redraw_in_demo_mode() -> None:
    name = 'team-[@click="screen.dismiss()"]a[/]'
    row = _shared()
    row["team_name"] = name
    app = _Host([_own(), row])

    class Redactor:
        def scrub_stream(self, text: str) -> str:
            return text.replace(name, "<team>")

    async with app.run_test() as pilot:
        await _start(pilot)
        assert type(app.screen).__name__ == "VaultBindingScopeModal"
        choices = app.screen.query_one(OptionList)
        assert name in choices.get_option_at_index(0).prompt.plain
        app.demo_mode, app.redaction_service = True, Redactor()
        app.screen.refresh_after_demo_toggle()
        assert name not in choices.get_option_at_index(0).prompt.plain
        assert "Everyone in team <team>" in choices.get_option_at_index(0).prompt.plain
        app.demo_mode = False
        app.screen.refresh_after_demo_toggle()
        assert name in choices.get_option_at_index(0).prompt.plain


@pytest.mark.asyncio
async def test_team_binding_status_keeps_the_existing_personal_key() -> None:
    app = _Host([_own(), _shared()])
    team_binding = _signed_binding()
    app.vault_command_service.bind = AsyncMock(return_value=team_binding)
    # The own binding already has the team's key and login: nothing to offer.
    app.vault_command_service.personal_binding.return_value = {
        "source": "servonaut_vault", "login_user": "deploy",
        "public_fingerprint": team_binding["public_fingerprint"],
    }
    async with app.run_test() as pilot:
        await _start(pilot)
        await _choose_scope(pilot, 0)
        await _settle(pilot, lambda: isinstance(app.screen, VaultBindingModal))
        await _settle(pilot, lambda: app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM)
        app.screen.query_one("#vault_bind_confirm", Button).press()
        await _settle(pilot, lambda: bool(app.notices))
        await app.actions._refresh_vault_binding()
        line = app.actions._credential_source_line()
        assert "Your key" in line and "Team key for team-a" in line
        assert "You keep connecting with your key" in app.notices[-1][0]
        app.vault_command_service.bind_personal.assert_not_awaited()


@pytest.mark.asyncio
async def test_demo_scope_uses_real_ids_and_keeps_names_hidden_after_binding() -> None:
    app = _Host([{**_own(), "id": "i-00000000000000001"}, _shared(id="2001")], demo=True)
    async with app.run_test(size=(100, 30)) as pilot:
        await _start(pilot)
        assert type(app.screen).__name__ == "VaultBindingScopeModal"
        prompt = app.screen.query_one(OptionList).get_option_at_index(0).prompt.plain
        assert "team-a" not in prompt
        await _choose_scope(pilot, 0)
        await _settle(pilot, lambda: isinstance(app.screen, VaultBindingModal))
        await _settle(pilot, lambda: app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM)
        app.screen.query_one("#vault_bind_confirm", Button).press()
        await _settle(pilot, lambda: bool(app.notices))
        call = app.vault_command_service.bind.await_args
        assert call.kwargs["team"] == "team-a" and call.kwargs["server"] == "2001"
        assert "team-a" not in app.notices[-1][0]
        assert "team-a" not in app.actions._credential_source_line()
        assert "team-a" not in app.actions._shared_with_line()
        assert app._instances_pristine[1]["credential_binding"]["source"] == "servonaut_vault"
        assert app.instances[1]["id"] != "2001"
        ServonautApp._restore_instances_in_place(app)
        app.demo_mode = False
        assert "Team key for team-a" in app.actions._credential_source_line()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_many_sharing_teams_scroll_and_leave_cancel_and_personal_choice_reachable(
    size: tuple[int, int],
) -> None:
    app = _Host([_own(), *[_shared(f"team-{index}") for index in range(15)]])
    async with app.run_test(size=size) as pilot:
        await _start(pilot)
        assert type(app.screen).__name__ == "VaultBindingScopeModal"
        modal = app.screen.query_one("#vault_scope_modal")
        choices = app.screen.query_one(OptionList)
        assert choices.option_count == 16
        assert choices.highlighted == 15
        assert app.screen.region.contains_region(modal.region)
        assert modal.region.contains_region(app.screen.query_one("#vault_scope_cancel").region)
        await pilot.press("enter")
        await _settle(pilot, lambda: isinstance(app.screen, VaultBindingModal))
        assert app.screen._team is None


@pytest.mark.asyncio
async def test_replaced_shared_record_cannot_receive_a_stale_binding() -> None:
    app = _Host([_own(), _shared()])
    async with app.run_test() as pilot:
        await _start(pilot)
        await _choose_scope(pilot, 0)
        await _settle(pilot, lambda: isinstance(app.screen, VaultBindingModal))
        await _settle(pilot, lambda: app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM)
        app.instances[1]["id"] = "replacement-server"
        app.screen.query_one("#vault_bind_confirm", Button).press()
        await _settle(pilot, lambda: bool(app.notices))
        app.vault_command_service.bind.assert_not_awaited()
        assert "no longer available" in app.notices[-1][0]


@pytest.mark.asyncio
async def test_direct_team_binding_updates_the_team_status_without_a_scope_picker() -> None:
    app = _Host([_shared()])
    async with app.run_test(size=(100, 30)) as pilot:
        await _start(pilot)
        assert isinstance(app.screen, VaultBindingModal)
        await _settle(pilot, lambda: app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM)
        app.screen.query_one("#vault_bind_confirm", Button).press()
        await _settle(pilot, lambda: bool(app.notices))
        call = app.vault_command_service.bind.await_args
        assert call.kwargs["team"] == "team-a" and call.kwargs["server"] == "shared-team-a"
        assert "Team key for team-a" in app.actions._credential_source_line()
        assert "Your key" not in app.actions._credential_source_line()


@pytest.mark.asyncio
async def test_late_personal_lookup_cannot_replace_a_binding_saved_on_this_screen() -> None:
    app = _Host([_own()])
    async with app.run_test() as pilot:
        await _settle(pilot, lambda: app.screen is app.actions)

        async def lookup() -> str:
            app.actions._vault_binding_source = "servonaut_vault"
            return "bitwarden"

        app.actions._lookup_vault_binding_source = lookup
        await app.actions._refresh_vault_binding()
        assert app.actions._binding_source() == "servonaut_vault"


@pytest.mark.asyncio
@pytest.mark.parametrize("reorder", [False, True])
async def test_filtering_or_reordering_options_cannot_change_the_chosen_scope(reorder: bool) -> None:
    app = _Host([_own(), _shared(), _shared("team-b", "viewer"), _shared("team-c", "admin")])
    async with app.run_test() as pilot:
        await _start(pilot)
        assert type(app.screen).__name__ == "VaultBindingScopeModal"
        choices = app.screen.query_one(OptionList)
        options = [choices.get_option_at_index(index) for index in range(4)]
        shown = list(reversed(options)) if reorder else options[1:]
        choices.clear_options().add_options(shown)
        await _choose_scope(pilot, 0)
        if not reorder:
            # The filtered list starts with a disabled team: no scope is dispatched.
            assert type(app.screen).__name__ == "VaultBindingScopeModal"
            assert not app.vault_command_service.vault_calls
            await _choose_scope(pilot, 1)
        await _settle(pilot, lambda: isinstance(app.screen, VaultBindingModal))
        assert app.screen._team == (None if reorder else "team-c")


@pytest.mark.asyncio
@pytest.mark.parametrize("direct", [False, True])
@pytest.mark.parametrize("reply_kind", [
    "bare", "wrapped", "mapping", "receipt", "unsigned", "no_source",
    "wrong_source", "invalid", "truthy_valid", "empty_signature", "non_mapping",
])
async def test_team_binding_reply_cannot_replace_cached_credentials_with_an_unusable_receipt(
    direct: bool, reply_kind: str,
) -> None:
    previous, incoming = _signed_binding(), _signed_binding()
    usable = reply_kind in ("bare", "wrapped", "mapping")
    reply: Any = incoming
    if reply_kind == "wrapped":
        reply = {"credential_binding": incoming, "ok": True}
    elif reply_kind == "mapping":
        reply = MappingProxyType(incoming)
    elif reply_kind == "receipt":
        reply = {"ok": True}
    elif reply_kind == "unsigned":
        incoming.pop("signature")
    elif reply_kind == "no_source":
        incoming.pop("source")
    elif reply_kind == "wrong_source":
        incoming["source"] = "bitwarden"
    elif reply_kind == "invalid":
        incoming["valid"] = False
    elif reply_kind == "truthy_valid":
        incoming["valid"] = 1  # A truthy JSON number is not a validated binding.
    elif reply_kind == "empty_signature":
        incoming["signature"] = ""
    elif reply_kind == "non_mapping":
        reply = None
    app = _Host([_own(), _shared(credential_binding=previous)], target=1 if direct else 0)
    app.vault_command_service.bind.side_effect = None
    app.vault_command_service.bind.return_value = reply
    async with app.run_test(size=(100, 30)) as pilot:
        await _start(pilot)
        if not direct:
            await _choose_scope(pilot, 0)
        await _settle(pilot, lambda: isinstance(app.screen, VaultBindingModal))
        await _settle(pilot, lambda: app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM)
        app.screen.query_one("#vault_bind_confirm", Button).press()
        await _settle(pilot, lambda: bool(app.notices))
        expected = incoming if usable else previous
        assert app.instances[1]["credential_binding"] == expected
        assert app._instances_pristine[1]["credential_binding"] == expected
        if direct:
            assert app.actions._instance["credential_binding"] == expected
        assert "credential_binding" not in app.instances[0]
        assert app.notices[-1][0].startswith("Vault key bound. Team key for team-a:")
        app.vault_command_service.bind.assert_awaited_once()


@pytest.mark.asyncio
async def test_scope_dialog_warns_when_replacing_existing_team_key() -> None:
    # team-a has no previous binding; team-b has an existing vault binding
    rows = [
        _own(),
        _shared("team-a", "admin"),
        _shared("team-b", "admin", credential_binding=_signed_binding("shared-team-b")),
    ]
    app = _Host(rows)
    async with app.run_test(size=(100, 30)) as pilot:
        await _start(pilot)
        assert type(app.screen).__name__ == "VaultBindingScopeModal"
        choices = app.screen.query_one(OptionList)
        assert choices.option_count == 3  # team-a, team-b, Just me

        opt_a = choices.get_option_at_index(0)
        assert "Team members connect to this server with this key." in opt_a.prompt.plain
        assert "Replaces the key" not in opt_a.prompt.plain

        opt_b = choices.get_option_at_index(1)
        assert "Replaces the key everyone in team-b uses now." in opt_b.prompt.plain
        assert "Team members connect to this server with this key." not in opt_b.prompt.plain



async def _bind_team_key(pilot: Any) -> None:
    app = pilot.app
    await _start(pilot)
    await _choose_scope(pilot, 0)
    await _settle(pilot, lambda: isinstance(app.screen, VaultBindingModal))
    await _settle(pilot, lambda: app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM)
    app.screen.query_one("#vault_bind_confirm", Button).press()


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("update", [False, True])
async def test_a_team_key_on_your_own_server_offers_to_update_your_own_binding(
    size: tuple[int, int], update: bool,
) -> None:
    # Regression: the team key's new login changed nothing for the owner,
    # whose own row kept connecting with their personal binding's old login.
    from servonaut.screens.server_actions import OwnKeyUpdateModal

    app = _Host([_own(), _shared()])
    service = app.vault_command_service
    team_binding = _signed_binding()
    service.bind = AsyncMock(return_value=team_binding)
    service.personal_binding.return_value = {
        "source": "servonaut_vault", "login_user": "ec2-user", "public_fingerprint": "SHA256:old",
    }
    async with app.run_test(size=size) as pilot:
        await _bind_team_key(pilot)
        await _settle(pilot, lambda: isinstance(app.screen, OwnKeyUpdateModal))
        modal = app.screen
        await _settle(pilot, lambda: bool(modal.query("#own_key_keep")) and app.focused is not None)
        body = str(modal.query_one("#own_key_body", Static).render())
        assert "as ec2-user" in body and "logs in as deploy" in body
        # Keep is the default: Enter never changes the user's own key.
        assert app.focused is modal.query_one("#own_key_keep", Button)
        assert modal.query_one("#own_key_update", Button).region.bottom <= size[1]
        modal.query_one("#own_key_update" if update else "#own_key_keep", Button).press()
        await _settle(pilot, lambda: bool(app.notices))

    if update:
        service.bind_personal.assert_awaited_once()
        sent = service.bind_personal.await_args.kwargs
        assert (sent["vault_id"], sent["item_id"], sent["login"]) == (TEAM_VAULT, KEY_ITEM, "deploy")
        assert (sent["provider"], sent["instance_id"], sent["hostname"]) == ("aws", "i-1", "9.9.9.9")
        assert sent["host_keys"] == team_binding["host_keys"]
        assert "Your own key now uses the team's key, as deploy." in app.notices[-1][0]
    else:
        service.bind_personal.assert_not_awaited()
        assert "You still connect with your own key, as ec2-user." in app.notices[-1][0]


@pytest.mark.asyncio
async def test_escape_keeps_your_own_binding() -> None:
    from servonaut.screens.server_actions import OwnKeyUpdateModal

    app = _Host([_own(), _shared()])
    app.vault_command_service.personal_binding.return_value = {
        "source": "servonaut_vault", "login_user": "ec2-user", "public_fingerprint": "SHA256:old",
    }
    async with app.run_test() as pilot:
        await _bind_team_key(pilot)
        await _settle(pilot, lambda: isinstance(app.screen, OwnKeyUpdateModal))
        await _settle(pilot, lambda: bool(app.screen.query("#own_key_keep")))
        await pilot.press("escape")
        await _settle(pilot, lambda: bool(app.notices))

    app.vault_command_service.bind_personal.assert_not_awaited()
    assert "You still connect with your own key, as ec2-user." in app.notices[-1][0]
