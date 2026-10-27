"""Vault item names, rename and delete through the native Vault screen."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from textual.app import App
from textual.widgets import Button, DataTable, Input, Static

from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.vault import VaultRenameKeyModal, VaultScreen
from servonaut.screens.vault_import_modal import VaultImportModal
from servonaut.services.bw_session_service import BwItemSummary
from servonaut.services.vault.errors import VaultKeyInUse, VaultUserError
from servonaut.styles import CSS_FILES
from tests._async_bounds import wait_until

VAULT = "11111111-1111-4111-8111-111111111111"


class _Service:
    def __init__(
        self,
        *,
        items=None,
        names=None,
        usage=None,
        names_error: Exception | None = None,
        rename_error: Exception | None = None,
        delete_error: Exception | None = None,
    ) -> None:
        self.items = list(items if items is not None else [
            {"item_id": "k1", "type": "ssh_key", "revision": 1, "public_fingerprint": "SHA256:one"},
        ])
        self.names = list(names if names is not None else [
            {"item_id": "k1", "label": "old", "name": "old", "fingerprint": "SHA256:one"},
        ])
        self.usage = usage if usage is not None else {
            "team_servers": [], "own_servers": [], "unchecked": [], "checked": 0,
        }
        self.names_error = names_error
        self.rename_error = rename_error
        self.delete_error = delete_error
        self.rename_calls: list[dict] = []
        self.delete_calls: list[dict] = []
        self.usage_calls: list[dict] = []

    async def status(self):
        return {
            "remote": {"identity": {"identity_id": "i", "trust_status": "confirmed"}},
            "local_identity": "local-fingerprint",
            "fingerprint": "local-fingerprint",
        }

    async def list_vaults(self):
        return [{"vault_id": VAULT, "kind": "personal", "name": "Personal", "my_role": "owner",
                 "my_grant": {"version": 1}, "counts": {"items": len(self.items), "open_exposures": 0}}]

    async def list_items(self, **_kwargs):
        return {"data": [dict(row) for row in self.items]}

    async def ssh_key_choices(self, *, vault_id, name_limit=None):
        assert vault_id == VAULT
        if self.names_error is not None:
            raise self.names_error
        return [dict(row) for row in self.names]

    async def rename_ssh_key(self, *, vault_id, item_id, name):
        self.rename_calls.append({"vault_id": vault_id, "item_id": item_id, "name": name})
        if self.rename_error is not None:
            raise self.rename_error
        for item in self.items:
            if item["item_id"] == item_id:
                item["revision"] += 1
        for row in self.names:
            if row["item_id"] == item_id:
                row["name"] = name
                row["label"] = name
        return {"item_id": item_id, "name": name, "revision": 2}

    async def ssh_key_usage(self, *, vault_id, item_id, servers):
        self.usage_calls.append({"vault_id": vault_id, "item_id": item_id, "servers": servers})
        return dict(self.usage)

    async def delete_ssh_key(self, *, vault_id, item_id, servers):
        self.delete_calls.append({"vault_id": vault_id, "item_id": item_id, "servers": servers})
        if self.delete_error is not None:
            raise self.delete_error
        self.items = [row for row in self.items if row["item_id"] != item_id]
        self.names = [row for row in self.names if row["item_id"] != item_id]
        return {"item_id": item_id, "deleted": True}


class _Host(App):
    CSS_PATH = CSS_FILES

    def __init__(self, service: _Service, instances=None) -> None:
        self.vault_command_service = service
        self.vault_available = True
        self.instances = list(instances or [])
        self.notes: list[tuple[str, dict]] = []
        super().__init__()

    def on_mount(self) -> None:
        self.push_screen(VaultScreen())

    def notify(self, message, **kwargs):
        self.notes.append((str(message), dict(kwargs)))
        return super().notify(message, **kwargs)


async def _loaded(app: App, pilot) -> VaultScreen:
    screen = app.screen
    assert isinstance(screen, VaultScreen)
    await wait_until(lambda: "Identity fingerprint" in str(screen.query_one("#vault_status", Static).render()))
    screen._selected_vault_id = VAULT
    await screen._load_items()
    await pilot.pause()
    assert screen._table_mode == "items"
    return screen


def _confirm_open(app: App) -> bool:
    return (isinstance(app.screen, ConfirmActionScreen)
            and bool(app.screen.query("#btn_confirm"))
            and app.screen.query_one("#btn_confirm").region.area > 0)


def _rename_open(app: App) -> bool:
    return (isinstance(app.screen, VaultRenameKeyModal)
            and bool(app.screen.query("#vault_rename_key_save"))
            and app.screen.query_one("#vault_rename_key_save").region.area > 0)


def _row(screen: VaultScreen, index: int = 0) -> list[str]:
    table = screen.query_one("#vault_table", DataTable)
    return [str(cell) for cell in table.get_row_at(index)]


def test_item_names_are_the_first_column_and_are_plain_text() -> None:
    hostile = "prod [bold]key[/bold]"
    service = _Service(
        items=[
            {"item_id": "k1", "type": "ssh_key", "revision": 1, "public_fingerprint": "SHA256:one"},
            {"item_id": "k2", "type": "ssh_key", "revision": 1, "public_fingerprint": "SHA256:two"},
            {"item_id": "k3", "type": "note", "revision": 1, "public_fingerprint": ""},
        ],
        names=[
            {"item_id": "k1", "name": hostile, "fingerprint": "SHA256:one"},
            {"item_id": "k2", "name": None, "fingerprint": "SHA256:two"},
        ],
    )

    async def run() -> None:
        app = _Host(service)
        async with app.run_test(size=(160, 50)) as pilot:
            screen = await _loaded(app, pilot)
            first = _row(screen, 0)
            assert first[0] == "prod \\[bold]key\\[/bold]"
            assert first[1] == "ssh_key" and first[3] == "SHA256:one"
            assert _row(screen, 1)[0] == "(name unknown)"
            assert _row(screen, 2)[0] == ""

    asyncio.run(run())


@pytest.mark.asyncio
async def test_rename_updates_the_name_column_and_says_what_it_saved() -> None:
    service = _Service()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        screen.query_one("#vault_rename_key", Button).press()
        await wait_until(lambda: _rename_open(app))
        modal = app.screen
        assert modal.query_one("#vault_rename_key_input", Input).value == "old"
        modal.query_one("#vault_rename_key_input", Input).value = "new name"
        modal.query_one("#vault_rename_key_save", Button).press()

        await wait_until(lambda: service.rename_calls)
        await wait_until(lambda: app.screen is screen and _row(screen, 0)[0] == "new name")
        assert service.rename_calls == [{"vault_id": VAULT, "item_id": "k1", "name": "new name"}]
        assert ("Renamed to new name.", {"markup": False}) in app.notes


@pytest.mark.asyncio
async def test_rename_shows_a_service_refusal_verbatim() -> None:
    detail = "vault key name must contain 1 to 200 characters"
    service = _Service(rename_error=VaultUserError(detail))
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_rename_key()
        await wait_until(lambda: _rename_open(app))
        modal = app.screen
        modal.query_one("#vault_rename_key_input", Input).value = "bad"
        modal.query_one("#vault_rename_key_save", Button).press()

        await wait_until(lambda: any(detail in message for message, _options in app.notes))
        assert app.screen is screen
        assert any(detail in message and options.get("markup") is False for message, options in app.notes)


@pytest.mark.asyncio
async def test_rename_refuses_an_item_that_is_not_an_ssh_key() -> None:
    service = _Service(
        items=[
            {"item_id": "k1", "type": "ssh_key", "revision": 1, "public_fingerprint": "SHA256:one"},
            {"item_id": "k3", "type": "note", "revision": 1, "public_fingerprint": ""},
        ],
    )
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        screen.query_one("#vault_table", DataTable).move_cursor(row=1)
        screen.action_rename_key()
        await pilot.pause()

        assert not isinstance(app.screen, VaultRenameKeyModal)
        assert any("Select an SSH key item first." == message for message, _options in app.notes)
        assert service.rename_calls == []


@pytest.mark.asyncio
async def test_delete_refuses_while_a_server_uses_or_could_not_be_checked() -> None:
    service = _Service(usage={
        "team_servers": ["web-1"], "own_servers": ["db-1"], "unchecked": ["cache-1"], "checked": 1,
    })
    app = _Host(service, instances=[{"id": "i-web1", "is_shared": True}])
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        await wait_until(lambda: service.usage_calls)

        await wait_until(lambda: any("still used by" in message for message, _options in app.notes))
        notice = next(message for message, _options in app.notes if "still used by" in message)
        assert "web-1" in notice and "db-1" in notice and "cache-1" in notice
        assert "another vault key first" in notice
        assert "Team servers: web-1" in notice and "Your servers: db-1" in notice
        assert "Could not check: cache-1" in notice
        assert not isinstance(app.screen, ConfirmActionScreen)
        assert service.delete_calls == []
        assert service.usage_calls == [{"vault_id": VAULT, "item_id": "k1",
                                        "servers": [{"id": "i-web1", "is_shared": True}]}]


@pytest.mark.asyncio
async def test_delete_can_be_cancelled_without_removing_the_key() -> None:
    service = _Service()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        await wait_until(lambda: _confirm_open(app))
        app.screen.query_one("#btn_cancel", Button).press()
        await wait_until(lambda: app.screen is screen)
        await pilot.pause()

        assert service.delete_calls == []
        assert _row(screen, 0)[0] == "old"


@pytest.mark.asyncio
async def test_delete_confirms_and_passes_every_server_for_the_service_to_filter() -> None:
    service = _Service()
    instances = [{"id": "i-web1", "is_shared": True}, {"id": "i-own", "is_shared": False}]
    app = _Host(service, instances=instances)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        screen.query_one("#vault_delete_key", Button).press()
        await wait_until(lambda: _confirm_open(app))
        app.screen.query_one("#confirm_input", Input).value = "DELETE"
        await pilot.pause()
        app.screen.query_one("#btn_confirm", Button).press()

        await wait_until(lambda: service.delete_calls)
        await wait_until(lambda: screen.query_one("#vault_table", DataTable).row_count == 0)
        assert service.delete_calls == [{"vault_id": VAULT, "item_id": "k1", "servers": instances}]
        assert any(message == "Vault key deleted." and options.get("markup") is False
                   for message, options in app.notes)


@pytest.mark.asyncio
async def test_delete_still_names_servers_when_the_key_became_used_meanwhile() -> None:
    service = _Service(delete_error=VaultKeyInUse(team_servers=["web-1"], own_servers=[], unchecked=["cache-1"]))
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        await wait_until(lambda: _confirm_open(app))
        app.screen.query_one("#confirm_input", Input).value = "DELETE"
        await pilot.pause()
        app.screen.query_one("#btn_confirm", Button).press()

        await wait_until(lambda: any("web-1" in message and "still used by" in message for message, _options in app.notes))
        notice = next(message for message, _options in app.notes if "web-1" in message)
        assert "Could not check: cache-1" in notice and "another vault key first" in notice
        assert screen.query_one("#vault_table", DataTable).row_count == 1


def test_bitwarden_import_passes_the_item_name(tmp_path: Path) -> None:
    service = MagicMock()
    service.import_keys = AsyncMock(return_value={"item_id": "vault-item-1"})
    resolver = MagicMock()
    resolver.resolve_ssh_key.return_value = "fixture-private"
    modal = VaultImportModal(service, "vault-1", tmp_path, resolver=resolver)
    modal._source = "bitwarden"
    modal._bw_items = [BwItemSummary(id="item-uuid-1", name="Production key", type=5, has_ssh_key=True)]
    modal._list = MagicMock(return_value=type("_List", (), {"selected": [0]})())
    modal.dismiss = MagicMock()

    async def run() -> None:
        with patch("servonaut.screens.vault_import_modal.asyncio.to_thread",
                   new=lambda function, *args, **kwargs: _immediate(function, *args, **kwargs)):
            await modal._import_selected()

    asyncio.run(run())
    call = service.import_keys.await_args.kwargs
    assert call["source"] == "bitwarden"
    assert call["source_ref"] == "item-uuid-1"
    assert call["name"] == "Production key"


async def _immediate(function, *args, **kwargs):
    return function(*args, **kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_long_name_is_short_in_table_but_prefills_the_whole_name(size) -> None:
    name = "x" * 120
    app = _Host(_Service(names=[{"item_id": "k1", "name": name}]))
    async with app.run_test(size=size) as pilot:
        screen = await _loaded(app, pilot)
        assert _row(screen)[0] == "x" * 60 + "…"
        assert screen._key_names["k1"] == name
        for selector in ("#vault_rename_key", "#vault_delete_key"):
            button = screen.query_one(selector, Button)
            button.focus()
            await wait_until(lambda: app.screen.region.contains_region(button.region))
            assert button.region.right <= screen.query_one("#vault_content").region.right
        screen.action_rename_key()
        await wait_until(lambda: _rename_open(app))
        assert app.screen.query_one("#vault_rename_key_input", Input).value == name
        for selector in ("#vault_rename_key_save", "#vault_rename_key_cancel"):
            assert app.screen.region.contains_region(app.screen.query_one(selector).region)
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)


@pytest.mark.asyncio
async def test_name_load_failure_keeps_metadata_and_allows_unknown_key_actions() -> None:
    service = _Service(names_error=ValueError("private name detail"))
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        assert _row(screen)[0] == "(name unknown)"
        status = str(screen.query_one("#vault_status", Static).render())
        assert "names could not be read (ValueError)" in status
        assert "private name detail" not in status
        screen.action_rename_key()
        await wait_until(lambda: _rename_open(app))
        assert app.screen.query_one("#vault_rename_key_input", Input).value == ""
        app.screen.query_one("#vault_rename_key_cancel", Button).press()
        await wait_until(lambda: app.screen is screen)
        screen.action_delete_key()
        await wait_until(lambda: _confirm_open(app))
        assert "(name unknown)" in app.screen._consequences[0]
        app.screen.query_one("#btn_cancel", Button).press()
        await wait_until(lambda: app.screen is screen)
        assert not service.rename_calls and not service.delete_calls


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["action_rename_key", "action_delete_key"])
async def test_ssh_eligibility_uses_the_row_type_even_when_a_name_is_cached(action) -> None:
    service = _Service(items=[{"item_id": "k1", "type": "secret", "revision": 1}])
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        assert _row(screen)[0] == ""
        getattr(screen, action)()
        await wait_until(lambda: any("Select an SSH key item first." == msg for msg, _ in app.notes))
        assert app.screen is screen
        assert not service.rename_calls and not service.usage_calls


@pytest.mark.asyncio
async def test_unchecked_only_refusal_has_retry_guidance_and_safe_grouped_names() -> None:
    app = _Host(_Service(usage={"team_servers": [], "own_servers": [], "unchecked": ["web-1\u202e\n[bold]"], "checked": 0}))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        await wait_until(lambda: any("could not check whether" in msg for msg, _ in app.notes))
        notice, options = next((msg, opts) for msg, opts in app.notes if "could not check whether" in msg)
        assert "Could not check: web-1[bold]" in notice
        assert "try again when they can be reached" in notice
        assert "\u202e" not in notice
        assert options["markup"] is False
        assert app.screen is screen


@pytest.mark.asyncio
async def test_confirmation_uses_fresh_usage_labels_and_describes_consequences() -> None:
    service = _Service(usage={"team_servers": [], "own_servers": [], "unchecked": [], "checked": 0,
                             "name": "fresh [bold]key[/bold]\u202e", "fingerprint": "SHA256:fresh"})
    app = _Host(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        await wait_until(lambda: _confirm_open(app))
        modal = app.screen
        assert modal._description.startswith("Delete the vault key ") and modal._description.endswith("?")
        assert modal._consequences == [
            "remove the key fresh \\[bold]key\\[/bold] (SHA256:fresh) from this vault",
            "not remove it from servers: those that accept it keep accepting it until it is removed from their authorized_keys",
        ]
        assert modal.query_one("#btn_confirm", Button).disabled
        app.screen.query_one("#confirm_input", Input).value = "delete"
        await pilot.pause()
        assert modal.query_one("#btn_confirm", Button).disabled
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
        assert not service.delete_calls


@pytest.mark.asyncio
@pytest.mark.parametrize("value, feedback", [(" ", "Name is required."), ("x" * 201, "Name must be at most 200 characters.")])
async def test_rename_inline_validation_then_enter_saves_cleaned_name(value, feedback) -> None:
    service = _Service()
    app = _Host(service)
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_rename_key()
        await wait_until(lambda: _rename_open(app))
        modal = app.screen
        field = modal.query_one("#vault_rename_key_input", Input)
        field.value = value
        field.focus()
        await pilot.press("enter")
        await wait_until(lambda: feedback in str(modal.query_one("#vault_rename_key_feedback", Static).render()))
        assert app.screen is modal and not service.rename_calls
        field.value = "  new key  "
        await pilot.press("enter")
        await wait_until(lambda: bool(service.rename_calls))
        assert service.rename_calls[0]["name"] == "new key"
        await wait_until(lambda: app.screen is screen)


@pytest.mark.asyncio
async def test_actions_stay_disabled_while_names_are_still_loading() -> None:
    service = _Service()
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        started, release = asyncio.Event(), asyncio.Event()
        async def delayed_names(**_kwargs):
            started.set()
            await release.wait()
            return service.names
        service.ssh_key_choices = delayed_names
        loading = asyncio.create_task(screen._load_items())
        try:
            await asyncio.wait_for(started.wait(), timeout=2)
            for selector in ("#vault_rename_key", "#vault_delete_key"):
                assert screen.query_one(selector, Button).disabled
            screen.action_rename_key()
            screen.action_delete_key()
            assert app.screen is screen and not service.rename_calls and not service.usage_calls
        finally:
            release.set()
            await loading
        assert not screen.query_one("#vault_rename_key", Button).disabled


@pytest.mark.asyncio
async def test_untrusted_rename_exception_text_is_not_displayed() -> None:
    service = _Service(rename_error=ValueError("private exception detail"))
    app = _Host(service)
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_rename_key()
        await wait_until(lambda: _rename_open(app))
        app.screen.query_one("#vault_rename_key_save", Button).press()
        await wait_until(lambda: any("Could not rename" in msg for msg, _ in app.notes))
        assert not any("private exception detail" in msg for msg, _ in app.notes)
        assert any("(ValueError)" in msg and opts.get("markup") is False for msg, opts in app.notes)


@pytest.mark.asyncio
async def test_grouped_refusal_names_are_scrubbed_in_demo_mode() -> None:
    app = _Host(_Service())
    app.demo_mode = True
    app.redaction_service = MagicMock()
    app.redaction_service.scrub_stream.side_effect = lambda text: text.replace("web-1", "server-1")
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _loaded(app, pilot)
        screen._notify_key_in_use(VaultKeyInUse(team_servers=["web-1"], own_servers=[], unchecked=[]))
        notice, options = app.notes[-1]
        assert "Team servers: server-1" in notice and "web-1" not in notice
        assert options["markup"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["key [old", "\x1b[31mred-key", "x\\[y", "trailing\\"])
async def test_delete_confirmation_shows_hostile_key_name_without_markup_crash(name: str) -> None:
    from textual.markup import to_content
    from servonaut.services.vault.display import terminal_safe

    usage = {"team_servers": [], "own_servers": [], "unchecked": [], "checked": 0,
             "name": name, "fingerprint": "SHA256:fixture"}
    app = _Host(_Service(names=[{"item_id": "k1", "name": name}], usage=usage))
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _loaded(app, pilot)
        screen.action_delete_key()
        await wait_until(lambda: _confirm_open(app))
        modal = app.screen
        assert to_content(modal._description).plain == f"Delete the vault key {terminal_safe(name)}?"
        bullet = "[$text-error]  • " + modal._consequences[0] + "[/$text-error]"
        assert to_content(bullet).plain == f"  • remove the key {terminal_safe(name)} (SHA256:fixture) from this vault"
        await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
