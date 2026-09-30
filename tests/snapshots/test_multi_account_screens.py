"""Screenshot tests: the AWS account-level screens with two AWS accounts.

The seeded home gets a second AWS account ("staging", a named profile) and
the primary account is labelled "prod". Each account lists its own pinned
instances; one name exists in both, so the tables must tell them apart.
With a single account these screens are covered, unchanged, by
``test_screens.py``.
"""

from __future__ import annotations

from typing import Any, List

import pytest

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import AWSAccount

from . import _harness

sizes = pytest.mark.parametrize("size", list(_harness.SIZES))

STAGING_ROWS: List[dict] = [
    _harness._aws_row("app-1", 11, "running", "t3.micro", "eu-west-1", "10.1.1.21"),
    _harness._aws_row("worker-1", 12, "stopped", "t3.small", "eu-west-1", "10.1.2.31"),
]

# Everything the fleet table lists once both accounts have loaded.
_FLEET_SIZE = len(_harness.FLEET_NAMES) + len(STAGING_ROWS)


@pytest.fixture(autouse=True)
def two_aws_accounts(snapshot_state: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """A second AWS account, with fixed instances and no network calls."""
    from servonaut.services.accounts.aws_account import AWSAccountContext
    from servonaut.services.aws_service import AWSService

    manager = ConfigManager()
    config = manager.get()
    config.aws.label = "prod"
    config.aws.accounts = [AWSAccount(label="staging", profile="staging")]
    manager.save(config)

    async def rows_of_account(self: AWSService, force_refresh: bool = False) -> list:
        del force_refresh
        rows = STAGING_ROWS if self.account.ref.label == "staging" else _harness.AWS_ROWS
        return [dict(row) for row in rows]

    monkeypatch.setattr(AWSService, "fetch_instances_cached", rows_of_account)
    # The account id is a display detail read from STS; never call it.
    monkeypatch.setattr(AWSAccountContext, "account_id", lambda self: "")


def _run(scenario):
    async def run_before(pilot: Any) -> None:
        from servonaut.widgets.instance_table import InstanceTable

        await _harness.wait_for_screen(pilot, "InstanceListScreen")
        table = pilot.app.screen.query_one(InstanceTable)
        await _harness.wait_until(
            pilot, lambda: table.row_count == _FLEET_SIZE, "both accounts in the fleet"
        )
        await scenario(pilot)
        await pilot.pause()
        _harness.freeze_cursors(pilot.app)

    return run_before


def _capture(screen_snapshot: Any, size: str, scenario: Any) -> None:
    screen_snapshot(_harness.SnapshotApp(), _harness.SIZES[size], _run(scenario))


async def _navigate(pilot: Any, nav_id: str, screen: str) -> Any:
    from textual.widgets import Button

    pilot.app.screen.query_one(f"#{nav_id}", Button).press()
    return await _harness.wait_for_screen(pilot, screen)


async def _aws_manager(pilot: Any) -> None:
    from textual.widgets import DataTable

    screen = await _navigate(pilot, "nav_aws_manage", "AWSManagerScreen")
    table = screen.query_one("#aws_mgr_table", DataTable)
    expected = len(_harness.AWS_ROWS) + len(STAGING_ROWS)
    await _harness.wait_until(pilot, lambda: table.row_count == expected, "the EC2 table")
    # A DataTable counts rows as they are added but measures its columns
    # later; wait for the widest name, or the capture can show the table
    # before its columns fit the rows.
    widest = max(len(f"staging/{row['name']}") for row in STAGING_ROWS)
    await _harness.wait_until(
        pilot, lambda: table.ordered_columns[1].content_width >= widest, "the EC2 columns"
    )
    # A plain DataTable keeps lines drawn before its columns were measured
    # until its next refresh (the fleet's InstanceTable redraws itself);
    # draw once more so the capture shows the measured columns.
    table.refresh()
    await pilot.pause()
    pilot.app.clear_notifications()


async def _aws_create(pilot: Any) -> None:
    from textual.widgets import DataTable

    await _navigate(pilot, "nav_aws_manage", "AWSManagerScreen")
    await pilot.press("n")
    screen = await _harness.wait_for_screen(pilot, "AWSCreateScreen")
    regions = screen.query_one("#aws_regions_table", DataTable)
    await _harness.wait_until(pilot, lambda: regions.row_count == 2, "the region list")
    pilot.app.clear_notifications()


async def _cloudwatch(pilot: Any) -> None:
    await _navigate(pilot, "nav_cloudwatch", "CloudWatchBrowserScreen")
    pilot.app.clear_notifications()


async def _cloudtrail(pilot: Any) -> None:
    await _navigate(pilot, "nav_cloudtrail", "CloudTrailBrowserScreen")
    pilot.app.clear_notifications()


@sizes
def test_aws_manager_two_accounts(screen_snapshot, size: str) -> None:
    """Instances of both accounts, named ``account/name``."""
    _capture(screen_snapshot, size, _aws_manager)


def test_aws_create_two_accounts(screen_snapshot, monkeypatch: pytest.MonkeyPatch) -> None:
    """The launch wizard asks for the account before the region."""
    from servonaut.services.aws_service import AWSService

    async def regions(self: AWSService, bootstrap_region: str = "") -> list:
        del bootstrap_region
        return ["eu-west-1", "us-east-1"]

    async def nothing(self: AWSService, *args: Any, **kwargs: Any) -> list:
        return []

    monkeypatch.setattr(AWSService, "list_regions", regions)
    for name in (
        "list_amis", "list_instance_types", "list_key_pairs", "list_subnets",
        "list_security_groups",
    ):
        monkeypatch.setattr(AWSService, name, nothing)
    _capture(screen_snapshot, "160x50", _aws_create)


@sizes
def test_cloudwatch_two_accounts(screen_snapshot, size: str) -> None:
    """The account picker leads the CloudWatch filters, wide and narrow."""
    _capture(screen_snapshot, size, _cloudwatch)


@sizes
def test_cloudtrail_two_accounts(screen_snapshot, size: str) -> None:
    """The account picker leads the CloudTrail filters, wide and narrow."""
    _capture(screen_snapshot, size, _cloudtrail)
