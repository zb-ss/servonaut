"""The Use Vault Key dialog offers the user's vaults and SSH keys to pick from."""
from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from textual.app import App
from textual.widgets import Button, Checkbox, Input, Select, Static

from servonaut.screens import server_actions
from servonaut.screens.server_actions import VaultBindingModal

PERSONAL_VAULT = "11111111-1111-4111-8111-111111111111"
TEAM_VAULT = "33333333-3333-4333-8333-333333333333"
KEY_ITEM = "22222222-2222-4222-8222-222222222222"
OTHER_ITEM = "44444444-4444-4444-8444-444444444444"


def _host_key() -> str:
    return Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()


class _Service:
    def __init__(self, *, vaults=None, keys=None, fail_keys: bool = False) -> None:
        self.vaults = vaults if vaults is not None else [
            {"vault_id": PERSONAL_VAULT, "label": "Personal (your personal vault)", "kind": "personal"},
            {"vault_id": TEAM_VAULT, "label": "Team vault (team ops)", "kind": "team"},
        ]
        self.keys = keys if keys is not None else {
            PERSONAL_VAULT: [{"item_id": KEY_ITEM, "label": "web1_ed25519 · SHA256:abc"}],
            TEAM_VAULT: [{"item_id": KEY_ITEM, "label": "deploy · SHA256:def"},
                         {"item_id": OTHER_ITEM, "label": "backup · SHA256:ghi"}],
        }
        self.fail_keys = fail_keys
        self.vault_calls: list[Any] = []

    async def vault_choices(self, *, team=None):
        self.vault_calls.append(team)
        return [vault for vault in self.vaults if team is None or vault.get("kind") == "team"]

    async def ssh_key_choices(self, *, vault_id):
        if self.fail_keys:
            raise RuntimeError("boom")
        return self.keys.get(vault_id, [])


class _Host(App):
    def __init__(self, service: _Service, instance: dict) -> None:
        super().__init__()
        self.service, self.instance = service, instance
        self.result: Any = "pending"

    def on_mount(self) -> None:
        self.push_screen(VaultBindingModal(self.service, self.instance), callback=self._done)

    def _done(self, value: Any) -> None:
        self.result = value


async def _settle(pilot, condition, attempts: int = 50) -> None:
    for _ in range(attempts):
        if condition():
            return
        await pilot.pause(0.02)
    raise AssertionError("condition never held")


@pytest.mark.asyncio
async def test_a_shared_server_offers_its_team_vault_and_its_keys() -> None:
    service = _Service()
    app = _Host(service, {"id": "s1", "is_shared": True, "team_slug": "ops", "username": "deploy"})
    async with app.run_test(size=(160, 50)) as pilot:
        keys = lambda: app.screen.query_one("#vault_bind_item", Select)  # noqa: E731
        await _settle(pilot, lambda: not keys().disabled)
        assert service.vault_calls == ["ops"]
        assert app.screen.query_one("#vault_bind_vault", Select).value == TEAM_VAULT  # the only one
        assert [str(label) for label, _ in keys()._options if str(label)] == [
            "deploy · SHA256:def", "backup · SHA256:ghi"]
        keys().value = OTHER_ITEM
        await pilot.pause()
        app.screen.query_one("#vault_bind_confirm", Button).press()
        await _settle(pilot, lambda: app.result != "pending")

    assert app.result == {"team": "ops", "vault_id": TEAM_VAULT, "item_id": OTHER_ITEM,
                          "login": "deploy", "host_keys": ""}


@pytest.mark.asyncio
async def test_a_personal_server_pins_the_host_keys_this_machine_trusts(monkeypatch) -> None:
    trusted = _host_key()
    monkeypatch.setattr(server_actions, "trusted_host_keys", lambda instance, host, port: [trusted])
    app = _Host(_Service(), {"id": "i-1", "hostname": "198.51.100.7", "port": 22, "username": "ec2-user"})
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot, lambda: app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM)
        await _settle(pilot, lambda: not app.screen.query_one("#vault_bind_use_trusted", Checkbox).disabled)
        assert app.screen.query_one("#vault_bind_vault", Select).value == PERSONAL_VAULT
        assert "SHA256:" in str(app.screen.query_one("#vault_bind_trusted", Static).render())
        box = app.screen.query_one("#vault_bind_use_trusted", Checkbox)
        assert box.value is False  # pinning takes the user's word that they checked
        app.screen.query_one("#vault_bind_confirm", Button).press()
        await pilot.pause()
        assert app.result == "pending"
        box.value = True
        app.screen.query_one("#vault_bind_confirm", Button).press()
        await _settle(pilot, lambda: app.result != "pending")

    assert app.result["team"] == "" and app.result["item_id"] == KEY_ITEM
    assert app.result["host_keys"] == trusted and app.result["login"] == "ec2-user"


@pytest.mark.asyncio
async def test_a_personal_server_without_trusted_or_pasted_keys_is_not_bound(monkeypatch) -> None:
    monkeypatch.setattr(server_actions, "trusted_host_keys", lambda instance, host, port: [])
    app = _Host(_Service(), {"id": "i-1", "hostname": "198.51.100.7", "username": "ec2-user"})
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot, lambda: app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM)
        await _settle(pilot, lambda: "does not trust" in str(app.screen.query_one("#vault_bind_trusted", Static).render()))
        app.screen.query_one("#vault_bind_confirm", Button).press()
        await pilot.pause()
        assert app.result == "pending"
        assert "needs its host keys pinned" in str(app.screen.query_one("#vault_bind_message", Static).render())

        pasted = _host_key()
        app.screen.query_one("#vault_bind_host_keys", Input).value = pasted
        app.screen.query_one("#vault_bind_confirm", Button).press()
        await _settle(pilot, lambda: app.result != "pending")

    assert app.result["host_keys"] == pasted


@pytest.mark.asyncio
async def test_no_vault_or_a_failed_key_load_says_what_to_do() -> None:
    app = _Host(_Service(vaults=[]), {"id": "s1", "is_shared": True, "team_slug": "ops"})
    async with app.run_test(size=(160, 50)) as pilot:
        message = lambda: str(app.screen.query_one("#vault_bind_message", Static).render())  # noqa: E731
        await _settle(pilot, lambda: "no vault you can read" in message())
        app.screen.query_one("#vault_bind_confirm", Button).press()
        await pilot.pause()
        assert app.result == "pending" and "Choose a vault and an SSH key" in message()
        app.screen.query_one("#vault_bind_cancel", Button).press()
        await _settle(pilot, lambda: app.result != "pending")
    assert app.result is None

    app = _Host(_Service(fail_keys=True), {"id": "s1", "is_shared": True, "team_slug": "ops"})
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot, lambda: "Could not load the SSH keys" in str(
            app.screen.query_one("#vault_bind_message", Static).render()))


@pytest.mark.asyncio
async def test_the_dialog_fits_a_narrow_terminal_with_the_choices_in_view(monkeypatch) -> None:
    monkeypatch.setattr(server_actions, "trusted_host_keys", lambda instance, host, port: [_host_key()] * 3)
    app = _Host(_Service(), {"id": "i-1", "hostname": "198.51.100.7", "username": "ec2-user"})
    async with app.run_test(size=(100, 30)) as pilot:
        await _settle(pilot, lambda: app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM)
        await pilot.pause()
        modal = app.screen.query_one("#vault_bind_modal").region
        for selector in ("#vault_bind_vault", "#vault_bind_item"):
            region = app.screen.query_one(selector).region
            assert region.width > 0 and modal.contains_region(region), (selector, region, modal)
        assert app.focused is app.screen.query_one("#vault_bind_item", Select)  # never Bind


@pytest.mark.asyncio
async def test_names_with_markup_are_shown_as_written_and_cannot_act() -> None:
    hostile = '[@click="screen.dismiss({\'vault_id\': \'x\'})"]Production deploy key[/]'
    service = _Service(vaults=[{"vault_id": TEAM_VAULT, "label": hostile, "kind": "team"}],
                       keys={TEAM_VAULT: [{"item_id": KEY_ITEM, "label": "backup [prod] [/]"}]})
    app = _Host(service, {"id": "s1", "is_shared": True, "team_slug": "ops"})
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot, lambda: app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM)
        labels = [str(label) for label, _ in app.screen.query_one("#vault_bind_item", Select)._options if str(label)]
        assert labels == ["backup [prod] [/]"]
        await pilot.click("#vault_bind_vault", offset=(4, 1))  # on the label text, not the border
        await pilot.pause()
        assert app.result == "pending"  # a click on the name ran nothing


@pytest.mark.asyncio
async def test_bind_takes_only_the_vault_and_key_the_lists_offered() -> None:
    app = _Host(_Service(), {"id": "s1", "is_shared": True, "team_slug": "ops"})
    async with app.run_test(size=(160, 50)) as pilot:
        keys = app.screen.query_one("#vault_bind_item", Select)
        await _settle(pilot, lambda: not keys.disabled)
        keys.value = KEY_ITEM
        app.screen._key_choices = [{"item_id": OTHER_ITEM, "label": "other"}]  # the list moved on
        app.screen.query_one("#vault_bind_confirm", Button).press()
        await pilot.pause()
        assert app.result == "pending"


@pytest.mark.asyncio
async def test_escape_cancels_and_a_personal_server_needs_a_login(monkeypatch) -> None:
    monkeypatch.setattr(server_actions, "trusted_host_keys", lambda instance, host, port: [])
    app = _Host(_Service(), {"id": "i-1", "hostname": "198.51.100.7"})
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot, lambda: app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM)
        app.screen.query_one("#vault_bind_host_keys", Input).value = _host_key()
        app.screen.query_one("#vault_bind_confirm", Button).press()
        await pilot.pause()
        assert app.result == "pending"
        assert "login user" in str(app.screen.query_one("#vault_bind_message", Static).render())
        await pilot.press("escape")
        await _settle(pilot, lambda: app.result != "pending")
    assert app.result is None


@pytest.mark.asyncio
async def test_demo_mode_hides_vault_key_and_host_names_and_redraws_on_toggle(monkeypatch) -> None:
    monkeypatch.setattr(server_actions, "trusted_host_keys", lambda instance, host, port: [_host_key()])

    class Redactor:
        def scrub_stream(self, text: str) -> str:
            return text.replace("web1_ed25519", "<key>").replace("Personal", "<vault>").replace("198.51.100.7", "<host>")

    app = _Host(_Service(), {"id": "i-1", "hostname": "198.51.100.7", "username": "ec2-user"})
    app.redaction_service = Redactor()
    app.demo_mode = True
    async with app.run_test(size=(160, 50)) as pilot:
        await _settle(pilot, lambda: app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM)
        await _settle(pilot, lambda: "<host>" in str(app.screen.query_one("#vault_bind_trusted", Static).render()))
        labels = lambda selector: [str(label) for label, _ in app.screen.query_one(selector, Select)._options]  # noqa: E731
        assert any("<key>" in label for label in labels("#vault_bind_item"))
        assert not any("web1_ed25519" in label for label in labels("#vault_bind_item"))

        app.demo_mode = False
        app.screen.refresh_after_demo_toggle()
        await pilot.pause()
        assert any("web1_ed25519" in label for label in labels("#vault_bind_item"))
        assert app.screen.query_one("#vault_bind_item", Select).value == KEY_ITEM  # choice kept
        assert "198.51.100.7" in str(app.screen.query_one("#vault_bind_trusted", Static).render())


@pytest.mark.asyncio
async def test_a_failed_key_load_can_be_retried_by_choosing_the_vault_again() -> None:
    service = _Service(fail_keys=True)
    app = _Host(service, {"id": "s1", "is_shared": True, "team_slug": "ops"})
    async with app.run_test(size=(160, 50)) as pilot:
        message = lambda: str(app.screen.query_one("#vault_bind_message", Static).render())  # noqa: E731
        await _settle(pilot, lambda: "Choose the vault again to retry" in message())
        vault = app.screen.query_one("#vault_bind_vault", Select)
        service.fail_keys = False
        vault.value = TEAM_VAULT  # the only vault, chosen again
        await _settle(pilot, lambda: not app.screen.query_one("#vault_bind_item", Select).disabled)
