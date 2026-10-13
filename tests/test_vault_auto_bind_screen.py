"""The Auto-bind screen reviews and binds vault keys named like the servers."""
from __future__ import annotations

from typing import Any

import pytest
from textual.app import App
from textual.widgets import Button, Checkbox, DataTable, Static

from servonaut.screens import vault_auto_bind
from servonaut.screens.vault_auto_bind import VaultAutoBindScreen
from servonaut.services.vault.errors import VaultUserError
from servonaut.styles import CSS_FILES
from tests._async_bounds import wait_until

PERSONAL_VAULT = "11111111-1111-4111-8111-111111111111"
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

SERVERS = [
    {"id": "i-web1", "name": "web-1", "key_name": "web-1", "public_ip": "198.51.100.1"},
    {"id": "i-web2", "name": "web-2", "public_ip": "198.51.100.2"},
    {"id": "i-db", "name": "db-1", "public_ip": "198.51.100.3"},
    {"id": "i-bound", "name": "cache-1", "public_ip": "198.51.100.4"},
]


class _Service:
    def __init__(self, *, keys=None, vaults=None, fail_bind=()) -> None:
        self.keys = keys if keys is not None else [
            {"item_id": "k1", "label": "web-1 · SHA256:a", "name": "web-1.pem", "fingerprint": "SHA256:a"},
            {"item_id": "k2", "label": "web-2 · SHA256:b", "name": "web-2", "fingerprint": "SHA256:b"},
            {"item_id": "k4", "label": "cache-1 · SHA256:d", "name": "cache-1", "fingerprint": "SHA256:d"},
        ]
        self.vaults = vaults if vaults is not None else [
            {"vault_id": PERSONAL_VAULT, "label": "Personal", "kind": "personal"},
        ]
        self.fail_bind = set(fail_bind)
        self.binds: list[dict[str, Any]] = []
        self.key_calls: list[dict[str, Any]] = []

    async def vault_choices(self, *, team=None):
        return self.vaults

    async def ssh_key_choices(self, **kwargs):
        self.key_calls.append(kwargs)
        return self.keys

    def ssh_destination(self, instance):
        return instance.get("public_ip"), 22

    def ssh_login(self, instance):
        return "ubuntu"

    async def personal_binding(self, instance):
        return {"source": "servonaut_vault"} if instance["id"] == "i-bound" else None

    async def bind_personal(self, **kwargs):
        if kwargs["instance_id"] in self.fail_bind:
            raise VaultUserError("this server already has a vault key")
        self.binds.append(kwargs)
        return {"source": "servonaut_vault"}


class _Host(App):
    CSS_PATH = CSS_FILES

    def __init__(self, service: _Service, instances=None) -> None:
        self.vault_command_service = service
        self.vault_available = True
        self.instances = list(SERVERS if instances is None else instances)
        super().__init__()

    def on_mount(self) -> None:
        self.push_screen(VaultAutoBindScreen())


@pytest.fixture(autouse=True)
def _trusted(monkeypatch):
    """This computer trusts a host key for every server but web-2."""
    monkeypatch.setattr(
        vault_auto_bind, "plan_auto_bind",
        _with_host_keys(vault_auto_bind.plan_auto_bind, {"i-web1": [HOST_KEY], "i-bound": [HOST_KEY]}),
    )


def _with_host_keys(plan, trusted):
    async def planned(service, instances, keys):
        return await plan(service, instances, keys, host_keys_for=lambda instance, host, port: trusted.get(instance["id"], []))
    return planned


def _rows(app) -> list[tuple[str, ...]]:
    table = app.screen.query_one("#auto_bind_table", DataTable)
    return [tuple(str(cell) for cell in table.get_row(key)) for key in table.rows]


def _status(app) -> str:
    return str(app.screen.query_one("#auto_bind_status", Static).render())


@pytest.mark.asyncio
async def test_the_review_lists_each_server_with_its_key_or_why_not() -> None:
    service = _Service()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app))
        rows = _rows(app)
        assert rows[0] == ("[x]", "web-1", "ready", "web-1.pem", "key pair", "ubuntu", "198.51.100.1")
        statuses = {row[1]: row[2] for row in rows}
        assert statuses == {
            "web-1": "ready", "cache-1": "has a vault key", "web-2": "no trusted host key", "db-1": "no matching key",
        }
        # Every key name is read, not just the first page of them.
        assert service.key_calls == [{"vault_id": PERSONAL_VAULT, "name_limit": None}]
        assert "1 of 4 servers can get a vault key" in _status(app)
        detail = str(app.screen.query_one("#auto_bind_detail", Static).render())
        assert "web-1: Ready to bind" in detail and "SHA256:" in detail
        # Another row's full reason shows when it is highlighted.
        app.screen.query_one("#auto_bind_table", DataTable).move_cursor(row=2)
        await wait_until(lambda: "connect once with SSH" in str(app.screen.query_one("#auto_bind_detail", Static).render()))


@pytest.mark.asyncio
async def test_nothing_is_bound_until_the_fingerprints_are_confirmed() -> None:
    service = _Service()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app))
        apply = app.screen.query_one("#auto_bind_apply", Button)
        assert str(apply.label) == "Bind selected (1)" and not apply.disabled

        apply.press()
        await pilot.pause()
        assert service.binds == []
        assert "tick the box" in _status(app)

        app.screen.query_one("#auto_bind_trust", Checkbox).value = True
        apply.press()
        await wait_until(lambda: "Bound vault keys to 1 of 1" in _status(app))

    (bound,) = service.binds
    assert (bound["instance_id"], bound["item_id"], bound["hostname"], bound["login"]) == ("i-web1", "k1", "198.51.100.1", "ubuntu")
    assert bound["host_keys"] == [HOST_KEY] and bound["replace_existing"] is False


@pytest.mark.asyncio
async def test_a_row_can_be_left_out_and_a_failure_shows_on_its_row() -> None:
    service = _Service(fail_bind={"i-web1"})
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: _rows(app))
        table = app.screen.query_one("#auto_bind_table", DataTable)
        table.focus()
        table.move_cursor(row=0)
        await pilot.press("space")
        await wait_until(lambda: _rows(app)[0][0] == "[ ]")
        assert app.screen.query_one("#auto_bind_apply", Button).disabled
        await pilot.press("space")
        await wait_until(lambda: _rows(app)[0][0] == "[x]")

        app.screen.query_one("#auto_bind_trust", Checkbox).value = True
        app.screen.query_one("#auto_bind_apply", Button).press()
        await wait_until(lambda: "failed" in _status(app))
        assert _rows(app)[0][2] == "binding failed"
        assert "Binding failed (this server already has a vault key)" in str(
            app.screen.query_one("#auto_bind_detail", Static).render()
        )


@pytest.mark.asyncio
async def test_without_a_personal_vault_or_keys_it_says_what_to_do() -> None:
    app = _Host(_Service(vaults=[{"vault_id": "t", "label": "Ops", "kind": "team"}]))
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: "no personal vault" in _status(app))
        assert app.screen.query_one("#auto_bind_apply", Button).disabled

    app = _Host(_Service(keys=[]))
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: "no SSH key yet" in _status(app))


@pytest.mark.asyncio
async def test_team_servers_are_not_offered() -> None:
    shared = {"id": "s1", "name": "web-1", "is_shared": True, "hostname": "web.example.test"}
    app = _Host(_Service(), instances=[shared])
    async with app.run_test(size=(160, 50)) as pilot:
        await wait_until(lambda: "no servers of your own" in _status(app))


@pytest.mark.asyncio
async def test_the_review_fits_a_narrow_terminal() -> None:
    app = _Host(_Service())
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(lambda: _rows(app))
        await pilot.pause()
        screen = app.screen.region
        for selector in ("#auto_bind_table", "#auto_bind_trust", "#auto_bind_apply", "#auto_bind_back"):
            region = app.screen.query_one(selector).region
            assert region.width > 0 and region.height > 0 and screen.contains_region(region), (selector, region)
