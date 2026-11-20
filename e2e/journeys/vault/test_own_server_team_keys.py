"""A user's own server may use a key of a team vault they own or administer.

The service announces the rule as the vault capability ``own_server_team_keys``;
without it (an older service) only personal-vault keys work on own servers.
These journeys run a real vault service against the hermetic FakeCloud, which
enforces the same rule on the binding PUT.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from textual.app import App
from textual.widgets import Button, Input, OptionList, Select

from e2e.harness import fleet
from e2e.harness.fake_cloud.routes_vault import SERVER_ID, TEAM_SLUG
from e2e.harness.waits import wait_for_async
from e2e.journeys.vault.test_cli_vault import _VAULT_TEAM
from e2e.journeys.vault.test_native_import import _native_service
from e2e.journeys.vault.test_vault_key_names import _ed25519_key_pair, _host_key
from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens import server_actions
from servonaut.screens._demo_resolve import replace_instances
from servonaut.screens.server_actions import (
    OwnKeyUpdateModal,
    ServerActionsScreen,
    VaultBindingModal,
)
from servonaut.services.api_client import APIError
from servonaut.services.shared_servers import shared_row
from servonaut.services.vault import command_service as command_service_module
from servonaut.services.vault.errors import VaultUserError

pytestmark = [pytest.mark.e2e_pr]

CAPABILITY = "own_server_team_keys"
PERSONAL_ONLY = "this Servonaut service only lets your own servers use keys from your personal vault"
NOT_MANAGED = "your own servers can use keys from your personal vault, or from a team vault you own or administer"
TEAM_KEY_REFUSED = (
    "the Servonaut service refused this key for your server: it may have been deleted, "
    "or you no longer own or administer its team vault"
)
BINDING_PATH = "/api/v1/me/instances/aws/{}/credential-binding"
OWN_ROW = {**fleet.EDGE_1.cache_row(), "username": "ubuntu"}
OWN_ID = fleet.EDGE_1.instance_id
OWN_ADDRESS = fleet.EDGE_1.public_ip


async def _vaults(service: Any, fake_cloud: Any) -> tuple[dict, dict]:
    fake_cloud.account.configure(teams=[_VAULT_TEAM])
    personal = await service.create_vault(team=None, name="Personal vault", grant_policy="auto")
    team = await service.create_vault(team=TEAM_SLUG, name="Team vault", grant_policy="auto")
    return personal, team


async def _import(service: Any, vault_id: str, name: str) -> str:
    private, _public = _ed25519_key_pair()
    imported = await service.import_keys(
        source="ssh", vault_id=vault_id, path=f"/fake/{name}.pem", private_key=private.encode("utf-8"), name=name,
    )
    return imported["item_id"]


def _user_id(service: Any) -> int:
    return service.auth.user_id


async def _bind(service: Any, vault_id: str, item_id: str, *, login: str = "ubuntu") -> dict:
    return await service.bind_personal(
        vault_id=vault_id, item_id=item_id, provider="aws", instance_id=OWN_ID,
        hostname=OWN_ADDRESS, port=22, login=login, host_keys=[_host_key()],
    )


def _puts(fake_cloud: Any) -> list[dict]:
    return fake_cloud.requests(path=BINDING_PATH.format(OWN_ID), method="PUT")


def _stored_binding_vault(fake_cloud: Any) -> str | None:
    binding = fake_cloud.vault._bindings.get(("aws", OWN_ID))
    return None if binding is None else binding.get("vault_id")


# Journey 1: the vault list of the bind dialog.

class _DialogHost(App):
    def __init__(self, service: Any, instance: dict) -> None:
        super().__init__()
        self.service, self.instance = service, instance

    def on_mount(self) -> None:
        self.push_screen(VaultBindingModal(self.service, self.instance))


async def _offered_vaults(service: Any, instance: dict) -> list[str]:
    app = _DialogHost(service, instance)
    async with app.run_test(size=(160, 50)):
        select = await wait_for_async(
            lambda: (
                app.screen.query_one("#vault_bind_vault", Select)
                if isinstance(app.screen, VaultBindingModal) and app.screen.query("#vault_bind_vault")
                and not app.screen.query_one("#vault_bind_vault", Select).disabled else None
            ),
            desc="the vault list",
        )
        offered = [value for _prompt, value in select._options if isinstance(value, str)]
        # A single obvious vault is chosen at once and its keys start loading: let that
        # finish, or leaving would tear the dialog down under it.
        dialog = app.screen
        await wait_for_async(
            lambda: all(worker.is_finished for worker in dialog.workers), desc="the dialog's key loading",
        )
        return offered


@pytest.mark.asyncio
async def test_the_bind_dialog_lists_team_vaults_only_for_owners_and_admins_of_a_capable_service(
    fake_cloud: Any, account_home: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = account_home("own-team-keys-dialog")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    personal, team = await _vaults(service, fake_cloud)
    personal_id, team_id = personal["vault_id"], team["vault_id"]
    shared = shared_row(
        fake_cloud.account.shared_servers(TEAM_SLUG)[0], {"slug": TEAM_SLUG, "name": "Example team", "role": "owner"},
    )

    # An older service: only the personal vault, though the shared server still gets its team's.
    assert await _offered_vaults(service, dict(OWN_ROW)) == [personal_id]
    assert await _offered_vaults(service, shared) == [team_id]

    fake_cloud.vault.set_capabilities([CAPABILITY])
    assert await _offered_vaults(service, dict(OWN_ROW)) == [personal_id, team_id]

    # A member of the team vault no longer qualifies.
    fake_cloud.vault.set_member_role(team_id, _user_id(service), "member")
    assert await _offered_vaults(service, dict(OWN_ROW)) == [personal_id]


# Journey 2: `servonaut vault bind-personal` is bind_personal.

@pytest.mark.asyncio
async def test_bind_personal_uses_a_team_key_only_on_a_capable_service_for_owners_and_admins(
    fake_cloud: Any, account_home: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = account_home("own-team-keys-bind")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    _personal, team = await _vaults(service, fake_cloud)
    team_id = team["vault_id"]
    item_id = await _import(service, team_id, "team-key")

    # (a) An older service: refused before anything is sent.
    with pytest.raises(VaultUserError) as refused:
        await _bind(service, team_id, item_id)
    assert str(refused.value) == PERSONAL_ONLY
    assert _puts(fake_cloud) == []

    # (b) Capable service, team owner: bound to the team vault's key.
    fake_cloud.vault.set_capabilities([CAPABILITY])
    await _bind(service, team_id, item_id)
    assert _stored_binding_vault(fake_cloud) == team_id
    assert len(_puts(fake_cloud)) == 1

    # (c) A member: refused before anything is sent.
    fake_cloud.vault.set_member_role(team_id, _user_id(service), "member")
    sent = len(_puts(fake_cloud))
    with pytest.raises(VaultUserError) as refused:
        await _bind(service, team_id, item_id)
    assert str(refused.value) == NOT_MANAGED
    assert len(_puts(fake_cloud)) == sent


@pytest.mark.asyncio
async def test_a_wire_refusal_of_a_team_key_is_explained_without_the_service_text(
    fake_cloud: Any, account_home: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = account_home("own-team-keys-wire")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    _personal, team = await _vaults(service, fake_cloud)
    item_id = await _import(service, team["vault_id"], "team-key")
    # A client that skipped the pre-check: the service's 422 is what stops it.
    monkeypatch.setattr(service, "own_server_key_refusal", lambda _vault: None)

    with pytest.raises(VaultUserError) as refused:
        await _bind(service, team["vault_id"], item_id)

    assert not isinstance(refused.value, APIError)
    assert str(refused.value) == TEAM_KEY_REFUSED
    [put] = _puts(fake_cloud)
    assert put["status"] == 422
    assert _stored_binding_vault(fake_cloud) is None


# Journey 3: 'Update mine' after a team key is set on the user's own server.

class _ActionsHost(App):
    def __init__(self, service: Any, rows: list[dict]) -> None:
        super().__init__()
        self.config_manager = SimpleNamespace(get=lambda: AppConfig())
        self.connection_service = MagicMock()
        self.connection_service.resolve_profile.return_value = None
        self.vault_command_service = service
        self.vault_lease_cache = SimpleNamespace(forget=lambda _row: None)
        self.instances = []
        self._demo_known_cache = None
        self.demo_mode = False
        self.redaction_service = None
        replace_instances(self, None, rows)
        self.actions = ServerActionsScreen(self.instances[0])
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


async def _set_team_key(app: _ActionsHost, team_item: str, before_bind: Any = None) -> None:
    """Drive Use Vault Key: the team scope, its key, a verified host key, Bind."""
    await wait_for_async(lambda: app.screen is app.actions, desc="the server actions")
    app.actions.query_one("#btn_use_vault_key", Button).press()
    scope = await wait_for_async(
        lambda: app.screen if type(app.screen).__name__ == "VaultBindingScopeModal"
        and app.screen.query("#vault_scope_choices") else None,
        desc="the scope picker",
    )
    choices = scope.query_one("#vault_scope_choices", OptionList)
    choices.highlighted = 0
    choices.focus()
    scope.query_one("#vault_scope_choices", OptionList).action_select()
    dialog = await wait_for_async(
        lambda: app.screen if isinstance(app.screen, VaultBindingModal)
        and app.screen.query("#vault_bind_item") else None,
        desc="the key dialog",
    )
    select = dialog.query_one("#vault_bind_item", Select)
    await wait_for_async(lambda: select.value == team_item, desc="the team key to be selected")
    dialog.query_one("#vault_bind_host_keys", Input).value = _host_key()
    if before_bind is not None:
        before_bind()
    confirm = dialog.query_one("#vault_bind_confirm", Button)
    await wait_for_async(lambda: not confirm.disabled, desc="the Bind button")
    confirm.press()


async def _update_mine_world(
    fake_cloud: Any, service: Any, monkeypatch: pytest.MonkeyPatch,
) -> tuple[_ActionsHost, dict, dict, str, str]:
    """An own server bound to a personal key, shared by the team, whose vault holds one key."""
    monkeypatch.setattr(server_actions, "trusted_host_keys", lambda *_args: [])
    personal, team = await _vaults(service, fake_cloud)
    personal_key = await _import(service, personal["vault_id"], "personal-key")
    team_key = await _import(service, team["vault_id"], "team-key")
    await _bind(service, personal["vault_id"], personal_key, login="ec2-user")
    fake_cloud.account.place_shared_server(
        TEAM_SLUG, SERVER_ID, name=OWN_ROW["name"], hostname=OWN_ADDRESS, login_user="deploy",
    )
    shared = shared_row(
        fake_cloud.account.shared_servers(TEAM_SLUG)[0], {"slug": TEAM_SLUG, "name": "Example team", "role": "owner"},
    )
    return _ActionsHost(service, [dict(OWN_ROW), shared]), personal, team, personal_key, team_key


@pytest.mark.asyncio
async def test_update_mine_is_offered_for_a_team_vault_the_user_may_use_on_own_servers(
    fake_cloud: Any, account_home: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = account_home("own-team-keys-update")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    fake_cloud.vault.set_capabilities([CAPABILITY])
    app, _personal, team, _personal_key, team_key = await _update_mine_world(fake_cloud, service, monkeypatch)

    async with app.run_test(size=(160, 50)):
        await _set_team_key(app, team_key)
        modal = await wait_for_async(
            lambda: app.screen if isinstance(app.screen, OwnKeyUpdateModal) and app.screen.query("#own_key_update")
            else None,
            desc="the Update mine offer",
        )
        modal.query_one("#own_key_update", Button).press()
        await wait_for_async(
            lambda: any("Your own key now uses the team's key" in message for message, _ in app.notices),
            desc="the update outcome",
        )

    assert _stored_binding_vault(fake_cloud) == team["vault_id"]
    assert app.notices[-1][1].get("markup") is False


@pytest.mark.asyncio
async def test_update_mine_is_not_offered_when_the_service_does_not_allow_it(
    fake_cloud: Any, account_home: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = account_home("own-team-keys-no-capability")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    app, personal, _team, _personal_key, team_key = await _update_mine_world(fake_cloud, service, monkeypatch)
    sent_before = len(_puts(fake_cloud))

    async with app.run_test(size=(160, 50)):
        await _set_team_key(app, team_key)
        await wait_for_async(
            lambda: any("You still connect with your own key" in message for message, _ in app.notices),
            desc="the outcome",
        )
        assert not isinstance(app.screen, OwnKeyUpdateModal)

    message, kwargs = app.notices[-1]
    assert "You still connect with your own key, as ec2-user." in message
    assert f"Updating it to the team's key was not offered: {PERSONAL_ONLY}." in message
    assert kwargs.get("markup") is False
    assert _stored_binding_vault(fake_cloud) == personal["vault_id"]
    assert len(_puts(fake_cloud)) == sent_before


@pytest.mark.asyncio
async def test_update_mine_is_not_offered_when_the_user_lost_the_vault_role_meanwhile(
    fake_cloud: Any, account_home: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The fake lets a member's team-server bind through, so the dialog's role change
    # lands between the dialog and the confirmation: only the own-server update is refused.
    sandbox = account_home("own-team-keys-member")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    fake_cloud.vault.set_capabilities([CAPABILITY])
    app, personal, team, _personal_key, team_key = await _update_mine_world(fake_cloud, service, monkeypatch)

    async with app.run_test(size=(160, 50)):
        await _set_team_key(
            app, team_key, before_bind=lambda: fake_cloud.vault.set_member_role(team["vault_id"], _user_id(service), "member"),
        )
        await wait_for_async(
            lambda: any("You still connect with your own key" in message for message, _ in app.notices),
            desc="the outcome",
        )
        assert not isinstance(app.screen, OwnKeyUpdateModal)

    # The team's key is bound; only the update of the user's own binding is not offered.
    assert _stored_binding_vault(fake_cloud) == personal["vault_id"]
    message, kwargs = app.notices[-1]
    assert "You still connect with your own key, as ec2-user." in message
    assert f"Updating it to the team's key was not offered: {NOT_MANAGED}." in message
    assert kwargs.get("markup") is False


# Journey 4: a team key lost with the user's role.

class _StubAgent:
    """The hermetic suite cannot start an SSH agent; a lease only needs one to hold the key."""

    def __init__(self, directory: Path) -> None:
        self.socket_path = directory / "agent.sock"

    def add_private_key(self, _private: bytes, *, ttl_seconds: int) -> None:
        return None

    def close(self) -> None:
        return None


def _stub_agent(monkeypatch: pytest.MonkeyPatch, sandbox_home: Path) -> None:
    # A lease writes its pin file under the home directory: keep it in a private one inside the sandbox.
    home = sandbox_home / "lease-home"
    home.mkdir(mode=0o700)
    (home / ".servonaut").mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(
        command_service_module.PrivateSshAgent, "start", classmethod(lambda _cls, directory=None: _StubAgent(home)),
    )


@pytest.mark.asyncio
async def test_an_own_server_falls_back_to_no_vault_key_once_its_team_vault_is_lost(
    fake_cloud: Any, account_home: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = account_home("own-team-keys-lost")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    _stub_agent(monkeypatch, sandbox.home)
    fake_cloud.vault.set_capabilities([CAPABILITY])
    _personal, team = await _vaults(service, fake_cloud)
    team_id = team["vault_id"]
    item_id = await _import(service, team_id, "team-key")
    await _bind(service, team_id, item_id)
    instance = dict(OWN_ROW)

    lease = await service.resolve_ssh(instance)
    assert lease is not None
    lease.close()
    assert await service.credential_team(instance) == TEAM_SLUG
    gets_before = len(fake_cloud.requests(path=BINDING_PATH.format(OWN_ID), method="GET"))

    # Losing the right: the service deletes the binding and the vault is no longer readable.
    dropped = fake_cloud.vault.set_member_role(team_id, _user_id(service), None)
    assert dropped == 1
    assert await service.resolve_ssh(instance) is None
    assert service.take_lost_team_key(instance) is True
    assert service.take_lost_team_key(instance) is False
    gets = fake_cloud.requests(path=BINDING_PATH.format(OWN_ID), method="GET")[gets_before:]
    assert [entry["status"] for entry in gets] == [404]
    assert await service.credential_team(instance) is None


@pytest.mark.asyncio
async def test_a_refused_team_vault_still_fails_the_connection_while_the_binding_stands(
    fake_cloud: Any, account_home: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = account_home("own-team-keys-still-bound")
    service = _native_service(fake_cloud, sandbox.home, monkeypatch)
    _stub_agent(monkeypatch, sandbox.home)
    fake_cloud.vault.set_capabilities([CAPABILITY])
    _personal, team = await _vaults(service, fake_cloud)
    team_id = team["vault_id"]
    item_id = await _import(service, team_id, "team-key")
    await _bind(service, team_id, item_id)
    instance = dict(OWN_ROW)
    lease = await service.resolve_ssh(instance)
    assert lease is not None
    lease.close()

    # The vault becomes unreadable, but the binding is put back: it still stands.
    binding = dict(fake_cloud.vault._bindings[("aws", OWN_ID)])
    fake_cloud.vault.set_member_role(team_id, _user_id(service), None)
    fake_cloud.vault._bindings[("aws", OWN_ID)] = binding

    with pytest.raises(APIError) as failure:
        await service.resolve_ssh(instance)
    assert failure.value.status in (403, 404)
    assert service.take_lost_team_key(instance) is False

