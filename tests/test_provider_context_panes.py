"""Selection panes show a provider-chosen name as typed, never as markup."""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from textual.app import App
from textual.widgets import Static

from servonaut.app import ServonautApp
from servonaut.screens.hetzner_ssh_keys import HetznerSSHKeysScreen
from servonaut.screens.ovh_ip_management import OVHIPManagementScreen
from servonaut.screens.ovh_snapshots import OVHSnapshotsScreen
from servonaut.screens.ovh_ssh_keys import OVHSSHKeysScreen
from servonaut.styles.themes import SERVONAUT_THEMES

CLICK_NAME = "[@click=app.quit]key-1[/]"
LINK_NAME = "[link=x"


class _Host(ServonautApp):
    demo_mode = False
    redaction_service = None

    def __init__(self, pane_id: str) -> None:
        App.__init__(self)
        self.user_themes = {}
        for theme in SERVONAUT_THEMES:
            self.register_theme(theme)
        self.theme = "servonaut"
        self.quit_requested = False
        self._pane_id = pane_id

    def compose(self):
        yield Static("", id=self._pane_id)

    def on_mount(self, event: Any) -> None:
        event.prevent_default()

    async def action_quit(self) -> None:
        self.quit_requested = True


def _hetzner(app, name):
    fake = SimpleNamespace(query_one=app.query_one, app=app, _selected_key=lambda: {"name": name, "id": 7})
    return lambda: HetznerSSHKeysScreen._update_selected_context(fake)


def _ovh_keys(app, name):
    fake = SimpleNamespace(query_one=app.query_one, app=app, _selected_key=lambda: {"name": name, "id": 7})
    return lambda: OVHSSHKeysScreen._update_selected_context(fake)


def _snapshots(app, name):
    from textual.widgets import DataTable

    table = DataTable(id="snapshots_table")
    fake = SimpleNamespace(
        app=app, _snapshots=[{"name": name, "id": "snap-1"}],
        query_one=lambda selector, kind=None: table if selector == "#snapshots_table" else app.query_one(selector, kind),
    )
    fake._display_snapshot_name = lambda snapshot: OVHSnapshotsScreen._display_snapshot_name(fake, snapshot)
    table.add_column("name")
    table.add_row("x")
    return lambda: OVHSnapshotsScreen._update_selected_context(fake)


def _ips(app, name):
    fake = SimpleNamespace(query_one=app.query_one, app=app, _selected_ip={"ip": name})
    return lambda: OVHIPManagementScreen._update_selected_context(fake)


PANES = [
    ("provider_key_selection", _hetzner, "7"),
    ("provider_key_selection", _ovh_keys, "7"),
    ("snapshot_selected_context", _snapshots, "snap-1"),
    ("ip_selected_context", _ips, "Selected IP"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("pane_id,build,tail", PANES, ids=["hetzner", "ovh-keys", "snapshots", "ips"])
@pytest.mark.parametrize("name", [CLICK_NAME, LINK_NAME])
async def test_a_selected_name_is_shown_as_typed_and_nothing_runs(pane_id, build, tail, name) -> None:
    app = _Host(pane_id)
    async with app.run_test(size=(100, 20)) as pilot:
        await pilot.pause(0.2)
        build(app, name)()
        await pilot.pause(0.2)
        pane = app.query_one(f"#{pane_id}", Static)
        assert name in pane.visual.plain and tail in pane.visual.plain
        await pilot.click(pane, offset=(1, 0))
        await pilot.pause(0.2)
        assert app.quit_requested is False
