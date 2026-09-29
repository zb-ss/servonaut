"""Journeys: work with two AWS accounts in the TUI.

The primary account uses the suite's own credentials (moto's default
account); the second account, labelled ``prod``, is a named profile that
assumes a role in another moto account, the way users reach their other
accounts. Both accounts have a server called ``web-1``.

The EC2 manager lists both accounts as ``aws/...`` and ``prod/...`` and a
stop acts in the account the server belongs to. The launch wizard launches
in the account picked first. CloudWatch, the IP ban manager and the object
storage browser read and change the picked (or configured) account only;
CloudTrail reads the trail again when the account changes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest

from e2e.harness import aws, fleet
from e2e.harness.cloudtrail_stub import cloudtrail_event
from e2e.harness.controls import choose, click_row, option_labels, table_text

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

SECOND = fleet.AWS_SECOND_ACCOUNT
REGION = "us-east-1"
# The primary account's servers, all in REGION (the accounts list only it).
PRIMARY_HOSTS = (fleet.APP_1, fleet.AWS_WEB_1)
ADDRESS = "9.9.9.9"
# The launch wizard lists every launch option for the default account, then
# again for the picked one. moto answers the instance-type list with every
# type it knows (over a thousand rows, several seconds each on a busy
# machine), so the options wait, and the journey, get more time.
LAUNCH_OPTIONS_TIMEOUT = 120.0
LAUNCH_JOURNEY_TIMEOUT = 180


def _seed_aws(moto) -> str:
    """Both accounts' servers in moto; returns the role that reaches the second."""
    moto.seed_fleet(PRIMARY_HOSTS)
    return moto.seed_account(aws.SECOND_ACCOUNT, fleet.AWS_SECOND_FLEET)


def _seed_home(seed, role: str, **config) -> None:
    """The second account's profile, a config with both accounts, their caches."""
    seed.aws_profile("base")
    seed.aws_profile(SECOND, role_arn=role, source_profile="base")
    seed.config(
        aws=seed.aws_config(
            regions=[REGION],
            default_region=REGION,
            accounts=[seed.aws_account(SECOND, regions=[REGION])],
        ),
        **config,
    )
    seed.cache(fleet.cache_rows(*PRIMARY_HOSTS), fresh=True)
    seed.cache(fleet.cache_rows(*fleet.AWS_SECOND_FLEET), fresh=True, account=SECOND)


def _seed_accounts(seed, moto, **config) -> str:
    """Both accounts, seeded; returns the role that reaches the second."""
    role = _seed_aws(moto)
    _seed_home(seed, role, **config)
    return role


def _states(moto, role: Optional[str] = None) -> dict[str, str]:
    """Instance name → state in the primary account, or in *role*'s account."""
    ec2 = moto.client_as(role, "ec2", REGION) if role else moto.client("ec2", REGION)
    states = {}
    for reservation in ec2.describe_instances()["Reservations"]:
        for instance in reservation["Instances"]:
            tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
            states[tags.get("Name", "")] = instance["State"]["Name"]
    return states


def _column(t, selector: str, index: int) -> list[str]:
    return [row[index] for row in table_text(t, selector)]


# ---------------------------------------------------------------------------
# EC2 manager and launch wizard
# ---------------------------------------------------------------------------


async def _open_manager(t) -> None:
    await t.nav("nav_aws_manage")
    await t.wait_for_screen("AWSManagerScreen")
    expected = {"aws/app-1", "aws/web-1", f"{SECOND}/web-1", f"{SECOND}/jobs-1"}
    await t.wait_until(
        lambda: set(_column(t, "#aws_mgr_table", 1)) == expected,
        desc="both accounts' instances",
    )


async def test_manager_stops_a_server_in_its_own_account(tui, seed, moto):
    role = _seed_accounts(seed, moto)
    async with tui() as t:
        await _open_manager(t)
        table = t.on_screen("#aws_mgr_table")
        await click_row(t, table, _column(t, "#aws_mgr_table", 1).index(f"{SECOND}/web-1"))
        await t.click("#btn_aws_mgr_stop")
        await t.wait_for_screen("PowerActionConfirmModal")
        await t.click("#btn_power_confirm_yes")
        await t.wait_for_toast(r"^EC2 i-[0-9a-f]+: stop sent\.$", severity="information")
        await t.wait_until(
            lambda: _states(moto, role)["web-1"] in ("stopping", "stopped"),
            desc="web-1 stopping in the second account",
        )
        # The refresh after the stop still lists both accounts.
        await t.wait_until(
            lambda: len(_column(t, "#aws_mgr_table", 1)) == 4, desc="both accounts listed"
        )

    assert _states(moto)["web-1"] == "running"


@pytest.mark.timeout(LAUNCH_JOURNEY_TIMEOUT)
async def test_launch_lands_in_the_picked_account(tui, seed, moto):
    role = _seed_accounts(seed, moto)
    name = "launched-1"
    async with tui() as t:
        await _open_manager(t)
        await t.click("#btn_aws_mgr_new")
        screen = await t.wait_for_screen("AWSCreateScreen")
        await choose(t, "#aws_create_account_select", SECOND)

        # Subnet ids differ between accounts: once the table lists the
        # second account's, the options are that account's.
        second_subnets = {
            subnet["SubnetId"]
            for subnet in moto.client_as(role, "ec2", REGION).describe_subnets()["Subnets"]
        }
        tables = ("#aws_amis_table", "#aws_types_table", "#aws_keys_table", "#aws_sg_table")

        def second_account_options() -> bool:
            subnets = set(_column(t, "#aws_subnets_table", 0))
            return bool(subnets) and subnets <= second_subnets and all(
                screen.query_one(table).row_count for table in tables
            )

        await t.wait_until(
            second_account_options,
            timeout=LAUNCH_OPTIONS_TIMEOUT,
            desc="the second account's launch options",
        )
        regions = screen.query_one("#aws_regions_table")
        assert _column(t, "#aws_regions_table", 0)[regions.cursor_row] == REGION
        await t.fill("#aws_input_name", name)
        await t.click("#btn_aws_create_submit")
        await t.wait_for_screen("ConfirmActionScreen")
        assert f" in {SECOND}, {REGION} as " in t.rendered_text(screen_only=True)
        await t.fill("#confirm_input", "launch")
        await t.click("#btn_confirm")
        await t.wait_for_toast(rf"^Instance '{name}' launching", severity="information")
        await t.wait_until(lambda: name in _states(moto, role), desc="launched in the second account")

    assert name not in _states(moto)


# ---------------------------------------------------------------------------
# CloudWatch and CloudTrail
# ---------------------------------------------------------------------------

PRIMARY_GROUP = "/e2e/primary/app"
SECOND_GROUP = "/e2e/second/app"


async def test_cloudwatch_reads_the_picked_accounts_logs(tui, seed, moto):
    role = _seed_accounts(seed, moto, cloudwatch_default_region=REGION)
    moto.seed_log_events(PRIMARY_GROUP, ["GET /primary 200"])
    moto.seed_log_events(
        SECOND_GROUP, ["GET /second 200", "GET /second 404"], region=REGION, role_arn=role
    )

    async with tui() as t:
        await t.nav("nav_cloudwatch")
        await t.wait_for_screen("CloudWatchBrowserScreen")
        groups = t.on_screen("#cw_select_log_group")
        await t.wait_until(lambda: PRIMARY_GROUP in option_labels(groups), desc="primary groups")
        assert SECOND_GROUP not in option_labels(groups)

        await choose(t, "#cw_filter_account_select", SECOND)
        await t.wait_until(lambda: SECOND_GROUP in option_labels(groups), desc="second groups")
        assert PRIMARY_GROUP not in option_labels(groups)

        await choose(t, "#cw_select_log_group", SECOND_GROUP)
        await t.click("#cw_btn_fetch")
        await t.wait_for_toast(r"^Loaded 2 events ")
        messages = _column(t, "#cloudwatch_events_table", 2)
        assert sorted(messages) == ["GET /second 200", "GET /second 404"]


async def test_cloudtrail_reads_the_trail_again_for_the_picked_account(tui, seed, moto, cloudtrail):
    _seed_accounts(seed, moto, cloudtrail_default_region=REGION)
    when = datetime.now(timezone.utc) - timedelta(minutes=5)
    cloudtrail.seed([cloudtrail_event("StopInstances", when, username="e2e-operator")], region=REGION)
    cloudtrail.seed(
        [cloudtrail_event("RebootInstances", when, username="e2e-operator")],
        region=REGION,
        account=aws.SECOND_ACCOUNT,
    )
    async with tui() as t:
        await t.nav("nav_cloudtrail")
        await t.wait_for_screen("CloudTrailBrowserScreen")
        await t.click("#ct_btn_fetch")
        await t.wait_for_toast(r"^Loaded 1 CloudTrail events\.$")
        assert _column(t, "#cloudtrail_table", 1) == ["StopInstances"]
        assert {lookup["account"] for lookup in cloudtrail.lookups()} == {aws.DEFAULT_ACCOUNT}
        before = len(cloudtrail.lookups())

        await choose(t, "#ct_filter_account_select", SECOND)
        await t.wait_until(lambda: len(cloudtrail.lookups()) > before, desc="the trail read again")
        await t.wait_until(
            lambda: _column(t, "#cloudtrail_table", 1) == ["RebootInstances"],
            desc="the second account's events shown",
        )
        assert {lookup["account"] for lookup in cloudtrail.lookups()[before:]} == {
            aws.SECOND_ACCOUNT
        }
        assert t.on_screen("#ct_filter_account").account == SECOND


# ---------------------------------------------------------------------------
# IP ban and object storage
# ---------------------------------------------------------------------------


async def test_ip_ban_config_acts_in_its_account(tui, seed, moto):
    from servonaut.config.schema import IPBanConfig

    role = _seed_aws(moto)
    ip_set = moto.seed_waf_ip_set("e2e-second-blocklist", region=REGION, role_arn=role)
    config = IPBanConfig(
        name="second-waf", method="waf", region=REGION, account=SECOND,
        ip_set_id=ip_set["Id"], ip_set_name=ip_set["Name"],
    )
    _seed_home(seed, role, ip_ban_configs=[config])

    async with tui() as t:
        await t.nav("nav_ip_ban")
        await t.wait_for_screen("IPBanScreen")
        await choose(t, "#ban_config_selector", f"second-waf (waf, {SECOND})")
        await t.wait_for_toast("No IPs currently banned in 'second-waf'")
        await t.fill("#ip_input", ADDRESS)
        await t.click("#btn_ban")
        await t.wait_for_toast(f"^Banned {ADDRESS} via WAF IP set$", severity="information")

    assert moto.waf_addresses(ip_set, region=REGION, role_arn=role) == [f"{ADDRESS}/32"]
    assert moto.client("wafv2", REGION).list_ip_sets(Scope="REGIONAL")["IPSets"] == []


async def test_object_storage_lists_the_picked_accounts_buckets(tui, seed, moto):
    role = _seed_accounts(seed, moto)
    moto.seed_bucket("e2e-primary-assets")
    moto.seed_bucket("e2e-second-assets", region=REGION, role_arn=role)

    async with tui() as t:
        await t.nav("nav_aws_s3")
        await t.wait_for_screen("ObjectStorageScreen")
        await t.wait_until(
            lambda: _column(t, "#s3_table", 1) == ["e2e-primary-assets"], desc="primary buckets"
        )
        await choose(t, "#s3_account_select", SECOND)
        await t.wait_until(
            lambda: _column(t, "#s3_table", 1) == ["e2e-second-assets"], desc="second buckets"
        )
