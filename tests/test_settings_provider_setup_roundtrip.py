"""Settings account forms return without losing scalar or chat drafts."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock, create_autospec

import pytest
from textual.widgets import Button, DataTable, Input, Static, TextArea
from textual.widgets.text_area import Selection

from servonaut.config.manager import ConfigManager
from servonaut.config.accounts import AccountRef, PROVIDERS, all_account_refs
from servonaut.config.schema import HetznerAccount, OVHAccount
from servonaut.screens import hetzner_setup, ovh_setup
from servonaut.screens.settings.accounts import (
    rebuild_accounts as _real_rebuild, reload_provider_fleet as _real_reload,
)
from servonaut.services.hetzner_service import HetznerService
from servonaut.services.ovh_service import OVHService
from servonaut.services.object_storage_regions import HETZNER_S3_DEFAULT_REGION, OVH_S3_DEFAULT_REGION
from servonaut.widgets.chat_panel import ChatPanel
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import collapse_chat, open_chat
from tests.test_settings_accounts_panels import FakeInventory
from tests.test_settings_provider_presentation import (
    EDIT, _app, _no_external_work, _press, _ready, _type, manager,
)
from tests.test_settings_presentation import _tab_to
from tests.test_workspace_provider_setup import IDS, SCREENS, _inert_boundaries

pytestmark = pytest.mark.usefixtures("navigation_open")


DRAFT = 'Keep this provider discussion\nSecond line café Ω'
NEW_USERNAME = 'journey-user'
NEW_TOKEN = 'example-updated-project-token'
NEW_SECRET = 'example-updated-account-secret'
REGIONS = {'hetzner': HETZNER_S3_DEFAULT_REGION, 'ovh': OVH_S3_DEFAULT_REGION}
MODULES = {'hetzner': hetzner_setup, 'ovh': ovh_setup}


class _ConfiguredRegistry:
    """Expose seeded usable accounts and the one fake inventory, without SDKs."""

    def __init__(self, manager: ConfigManager, provider: str, inventory: FakeInventory) -> None:
        self._manager = manager
        self._inventories = {provider: inventory}
        self.unavailable: dict[str, str] = {}

    def accounts(self, provider: str) -> list[AccountRef]:
        if provider not in PROVIDERS:
            raise ValueError(provider)
        config = self._manager.get()
        if not getattr(config, provider).enabled:
            return []
        return [ref for ref in all_account_refs(config) if ref.provider == provider]

    def fleet(self, provider: str) -> FakeInventory | None:
        if provider not in PROVIDERS:
            raise ValueError(provider)
        return self._inventories.get(provider)


def _seed_valid_config(manager: ConfigManager) -> None:
    config = manager.get()
    config.theme = 'servonaut'
    for kind in ('hetzner', 'ovh'):
        block = getattr(config, kind)
        block.enabled = True
        block.object_storage.region = REGIONS[kind]
        for account in block.accounts:
            account.object_storage.region = REGIONS[kind]
    manager.save(config)


def _expected_account(kind, route, config, label):
    if route == 'edit':
        previous = deepcopy(getattr(config, kind).accounts[0])
    else:
        previous = HetznerAccount() if kind == 'hetzner' else OVHAccount()
        previous.object_storage.region = REGIONS[kind]
    if kind == 'hetzner':
        return replace(previous, label=label, api_token=NEW_TOKEN, default_username=NEW_USERNAME)
    if route == 'edit':
        return replace(previous, label=label, client_secret=NEW_SECRET, default_username=NEW_USERNAME)
    return replace(previous, label=label, application_key='example-added-key',
                   application_secret=NEW_SECRET, consumer_key='example-added-consumer',
                   default_username=NEW_USERNAME)


def _isolated_inventory(app, kind, monkeypatch, label):
    fresh = {'id': kind + '-saved', 'name': 'saved-web', 'account': label,
             'is_' + kind: True, 'state': 'running'}
    inventory = FakeInventory([fresh])
    fetch = AsyncMock(wraps=inventory.fetch_instances_cached)
    monkeypatch.setattr(inventory, 'fetch_instances_cached', fetch)
    app.accounts = _ConfiguredRegistry(app.config_manager, kind, inventory)
    # The registry service boundary is fake; the UI's real rebuild/reload helpers run.
    monkeypatch.setattr(app, 'rebuild_accounts', Mock())
    app.instances = [
        {'id': 'local-keep', 'name': 'local-web', 'is_custom': True},
        {'id': kind + '-stale', 'name': 'stale-web', 'is_' + kind: True},
    ]
    app._instances_pristine = deepcopy(app.instances)
    module = MODULES[kind]
    rebuild = Mock(wraps=_real_rebuild)
    reload = AsyncMock(wraps=_real_reload)
    monkeypatch.setattr(module, 'rebuild_accounts', rebuild)
    monkeypatch.setattr(module, 'reload_provider_fleet', reload)
    return inventory, fetch, rebuild, reload, deepcopy(fresh)


def _provider_client(kind, monkeypatch):
    cls = HetznerService if kind == 'hetzner' else OVHService
    service = create_autospec(cls, instance=True, spec_set=True)
    service.test_connection.return_value = (
        {'ok': True, 'project': 'local-project'} if kind == 'hetzner'
        else {'success': True, 'account': 'local-account', 'message': ''}
    )
    if kind == 'hetzner':
        service.list_ssh_keys.return_value = []
    factory = Mock(return_value=service)
    monkeypatch.setattr('servonaut.services.' + kind + '_service.' + cls.__name__, factory)
    return service, factory


async def _fill_account(app, pilot, screen, kind, route, label):
    await _type(app, pilot, screen.query_one('#' + kind + '_input_label', Input), label)
    await _type(app, pilot, screen.query_one(IDS[kind].username, Input), NEW_USERNAME)
    if kind == 'hetzner':
        await _type(app, pilot, screen.query_one(IDS[kind].token, Input), NEW_TOKEN)
    elif route == 'edit':
        await _type(app, pilot, screen.query_one('#ovh_input_client_secret', Input), NEW_SECRET)
    else:
        for field, value in (('app_key', 'example-added-key'), ('app_secret', NEW_SECRET),
                             ('consumer_key', 'example-added-consumer')):
            await _type(app, pilot, screen.query_one('#ovh_input_' + field, Input), value)


async def _activate(pilot, screen, selector):
    button = screen.query_one(selector, Button)
    await _tab_to(pilot, button)
    assert pilot.app.focused is button
    await pilot.press('enter')


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ('hetzner', 'ovh'))
@pytest.mark.parametrize('route', ('add', 'edit'))
async def test_settings_provider_test_save_return_keeps_unsaved_parent_state(
    manager: ConfigManager, monkeypatch, tmp_path: Path, record_property, kind, route,
) -> None:
    _seed_valid_config(manager)
    expected = deepcopy(asdict(manager.get()))
    label = route + '-' + kind
    account = _expected_account(kind, route, manager.get(), label)
    if route == 'add':
        expected[kind]['accounts'].append(asdict(account))
    else:
        expected[kind]['accounts'][0] = asdict(account)
    app = _app(manager, kind, navigation_visible=False)
    inventory, fetch, rebuild, reload, fresh = _isolated_inventory(app, kind, monkeypatch, label)
    service, factory = _provider_client(kind, monkeypatch)
    save = Mock(wraps=manager.save)
    update = Mock(wraps=manager.update)
    monkeypatch.setattr(manager, 'save', save)
    monkeypatch.setattr(manager, 'update', update)
    facts = {'provider': kind, 'route': route, 'new_label': label}
    try:
        async with app.run_test(size=(100, 30)) as pilot:
            panel = await _ready(app, pilot)
            parent = app.screen
            scalar_id, _, value, _, _ = EDIT[kind]
            scalar = panel.query_one('#' + scalar_id, Input)
            await _type(app, pilot, scalar, value)
            await pilot.press('home', 'right', 'shift+right')
            await wait_until(panel.is_dirty)
            table = panel.query_one('#' + kind + '_accounts_table', DataTable)
            table.move_cursor(row=0)
            await _tab_to(pilot, table)
            if route == 'edit':
                await pilot.press('down')
                await wait_until(lambda: table.cursor_row == 1)
            scalar_state = scalar.value, scalar.cursor_position, scalar.selection
            values = panel.current_values()
            chat = await open_chat(app, pilot, parent)
            editor = chat.query_one('#chat-input', TextArea)
            editor.load_text(DRAFT)
            editor.selection = Selection((0, 5), (1, 6))
            await pilot.pause()
            chat_state = editor.document, editor.text, editor.selection, editor.scroll_offset
            await collapse_chat(app, pilot, parent)
            assert scalar_state == (scalar.value, scalar.cursor_position, scalar.selection)
            fleet_before, local_holder = deepcopy(app.instances), app.instances[0]
            generation = app._fleet_generation
            persisted = (tmp_path / 'config.json').read_bytes()
            resumed = Mock(wraps=panel.refresh_external_state)
            monkeypatch.setattr(panel, 'refresh_external_state', resumed)
            await _press(app, pilot, '#btn_' + kind + '_account_' + route)
            await wait_until(lambda: isinstance(app.screen, SCREENS[kind]))
            child = app.screen
            await wait_until(lambda: bool(child.query('#' + kind + '_input_label')))
            assert child._account_mode and child._add_extra is (route == 'add')
            assert child._extra_index == (0 if route == 'edit' else None)
            assert app.screen_stack[-2] is parent and not child.query(ChatPanel)
            installer_name = '_install_hcloud_if_needed' if kind == 'hetzner' else '_install_ovh_if_needed'
            install = AsyncMock(return_value=True)
            monkeypatch.setattr(child, installer_name, install)
            await _fill_account(app, pilot, child, kind, route, label)
            await _activate(pilot, child, IDS[kind].test)
            await wait_until(lambda: service.test_connection.await_count == 1 and
                             'Connection successful!' in child.query_one(IDS[kind].result, Static).render().plain)
            await wait_until(lambda: all(w.is_finished for w in app.workers if w.name == kind + '_test'))
            save.assert_not_called()
            update.assert_not_called()
            rebuild.assert_not_called()
            reload.assert_not_awaited()
            assert inventory.fetches == 0 and app.instances == fleet_before
            assert (tmp_path / 'config.json').read_bytes() == persisted
            await _activate(pilot, child, IDS[kind].save)
            await wait_until(lambda: app.screen is parent and not child.is_attached and resumed.called)
            assert parent._current_panel() is panel
            assert panel.query_one('#' + scalar_id) is scalar
            assert panel.current_values() == values and panel.is_dirty()
            assert scalar_state == (scalar.value, scalar.cursor_position, scalar.selection)
            assert asdict(manager.get()) == expected
            assert asdict(ConfigManager(config_path=tmp_path / 'config.json').load()) == expected
            save.assert_called_once_with(manager.get())
            update.assert_not_called()
            rebuild.assert_called_once_with(app)
            app.rebuild_accounts.assert_called_once_with()
            reload.assert_awaited_once_with(app, kind)
            fetch.assert_awaited_once_with(force_refresh=True)
            assert inventory.fetches == 1 and app._fleet_generation == generation + 1
            assert app.instances[0] is local_holder and app.instances == [fleet_before[0], fresh]
            assert inventory.rows == [fresh]
            assert service.test_connection.await_count == 2 and factory.call_count == 2
            assert install.await_count == 2
            for call in factory.call_args_list:
                (config,), options = call.args, call.kwargs
                assert options == ({'allow_ambient_token': False} if kind == 'hetzner'
                                   else {'allow_ambient_config': False})
                if kind == 'hetzner':
                    assert config.enabled and config.api_token == NEW_TOKEN
                else:
                    assert not config.enabled and config.endpoint == account.endpoint
                    assert config.client_id == account.client_id and config.client_secret == account.client_secret
                    assert (config.application_key, config.application_secret, config.consumer_key) == (
                        account.application_key, account.application_secret, account.consumer_key)
            if kind == 'hetzner':
                assert service.list_ssh_keys.await_count == 2
            labels = [str(table.get_row_at(i)[0]) for i in range(table.row_count)]
            assert label in labels and table.row_count == len(expected[kind]['accounts']) + 1
            assert parent.query_one(ChatPanel) is chat and chat.is_attached and chat._collapsed
            assert chat_state == (editor.document, editor.text, editor.selection, editor.scroll_offset)
            restored = await open_chat(app, pilot, parent)
            assert restored is chat
            assert chat_state == (editor.document, editor.text, editor.selection, editor.scroll_offset)
            await collapse_chat(app, pilot, parent)
            resumed.assert_called_once_with()
            assert panel.current_values() == values and panel.is_dirty() and app._exception is None
            facts.update({'config_saves': save.call_count, 'registry_rebuilds': app.rebuild_accounts.call_count,
                          'forced_fetches': fetch.await_count, 'parent_resumes': resumed.call_count,
                          'connection_tests': service.test_connection.await_count, 'draft_retained': True})
    finally:
        record_property('settings-provider-roundtrip', json.dumps(facts, sort_keys=True))
