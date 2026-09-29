"""Screenshot tests: the Accounts sections of the provider settings panels.

With several accounts per provider, each provider panel lists them at its
end. The accounts are written into the saved config after the fleet has
loaded, so the panels show them without the app ever trying to reach them.
Captured at both terminal sizes (see ``test_screens.py``).
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

import pytest
from textual.widgets import Button, DataTable

from servonaut.config.schema import AWSAccount, HetznerAccount, OVHAccount

from . import _harness

Scenario = Callable[[Any], Awaitable[None]]

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))


def _add_accounts(app: Any) -> None:
    """Give every provider a renamed primary and extra accounts."""
    manager = app.config_manager
    config = manager.get()
    config.aws.label = "main"
    config.aws.profile = "main-admin"
    config.aws.accounts = [
        AWSAccount(label="prod", profile="prod-admin", regions=["eu-west-1", "us-east-1"]),
        AWSAccount(label="sandbox"),  # no profile: skipped, and says why
    ]
    config.hetzner.enabled = True
    config.hetzner.api_token = "$HCLOUD_TOKEN_MAIN"
    config.hetzner.accounts = [
        HetznerAccount(label="staging", api_token="$HCLOUD_TOKEN_STAGING"),
    ]
    config.ovh.enabled = True
    config.ovh.application_key = "app-key"
    config.ovh.application_secret = "$OVH_SECRET"
    config.ovh.consumer_key = "$OVH_CONSUMER"
    config.ovh.cloud_project_ids = ["0e0e0000000000000000000000000001"]
    config.ovh.accounts = [
        OVHAccount(label="client-a", endpoint="ovh-ca", client_id="id", client_secret="$S"),
    ]
    manager.save(config)


def _accounts_of(panel_id: str, *, edit_row: int = -1) -> Scenario:
    async def scenario(pilot: Any) -> None:
        app = pilot.app
        _add_accounts(app)
        app.open_settings_screen(panel_id)
        screen = await _harness.wait_for_screen(pilot, "SettingsScreen")
        await _harness.wait_until(
            pilot,
            lambda: screen.query_one(f"#panel_{panel_id}").display,
            f"the {panel_id} settings panel",
        )
        section = screen.query_one(f"#{panel_id}_accounts")
        table = section.query_one(DataTable)
        await _harness.wait_until(pilot, lambda: table.row_count > 1, "the accounts table")
        target = section
        if edit_row >= 0:
            table.move_cursor(row=edit_row)
            section.query_one(f"#btn_{panel_id}_account_edit", Button).press()
            await pilot.pause()
            target = section.query_one(f"#{panel_id}_account_form")
        screen.query_one(f"#panel_{panel_id} .panel-body").scroll_to_widget(
            target, animate=False, top=True
        )
        await pilot.pause()

    return scenario


def _capture(screen_snapshot: Any, size: str, scenario: Scenario, *, demo: bool = False) -> None:
    async def run_before(pilot: Any) -> None:
        await _harness.wait_for_fleet(pilot)
        await scenario(pilot)
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    screen_snapshot(_harness.SnapshotApp(demo=demo), _harness.SIZES[size], run_before)


@sizes
def test_aws_accounts(screen_snapshot, size: str) -> None:
    """AWS accounts: the renamed primary, a working extra and a skipped one."""
    _capture(screen_snapshot, size, _accounts_of("aws"))


@sizes
def test_aws_account_form(screen_snapshot, size: str) -> None:
    """Editing an extra AWS account inline."""
    _capture(screen_snapshot, size, _accounts_of("aws", edit_row=1))


def test_aws_accounts_demo_mode(screen_snapshot) -> None:
    """Demo mode shows stand-ins for the account labels and profiles."""
    _capture(screen_snapshot, "160x50", _accounts_of("aws"), demo=True)


@sizes
def test_hetzner_projects(screen_snapshot, size: str) -> None:
    """Hetzner projects: whether each token is set, never its value."""
    _capture(screen_snapshot, size, _accounts_of("hetzner"))


@sizes
def test_ovh_accounts(screen_snapshot, size: str) -> None:
    """OVH accounts: endpoint, kind of credentials and projects."""
    _capture(screen_snapshot, size, _accounts_of("ovh"))
