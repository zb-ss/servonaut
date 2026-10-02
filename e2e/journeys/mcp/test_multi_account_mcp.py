"""Journey: an MCP client with several accounts per provider.

``servonaut --mcp`` runs as a child process with two Hetzner projects, two
OVH accounts and, where AWS matters, two AWS accounts (the second one a
named profile that assumes a role in another moto account). Every provider
has a server named ``web-1`` in each of its accounts.

``list_instances`` names those servers ``<account>/<name>`` and filters by
account. Every tool that takes a server accepts ``<account>/<name>``, and a
bare shared name is refused with the candidates, leaving an audit row that
says so. Lifecycle tools act in the account that has the server, whether it
was named by a qualified reference, by the ``account`` argument, or by a
name or id only that account's inventory lists; a server no account lists
is refused rather than sent to the default account. Object storage follows
the ``account`` argument. An account label nothing uses is a validation
error.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from e2e.harness import aws, fleet
from e2e.harness.fake_providers import hetzner as fake_hetzner
from e2e.harness.fake_providers import ovh as fake_ovh
from e2e.harness.seed import HomeSeeder

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

STAGING = fleet.HETZNER_SECOND_ACCOUNT
BACKUP = fleet.OVH_SECOND_ACCOUNT
PROD = fleet.AWS_SECOND_ACCOUNT
HZ_PRIMARY = fake_hetzner.PRIMARY_LABEL
OVH_PRIMARY = fake_ovh.PRIMARY_LABEL
SHARED = fleet.SHARED_NAME
REGION = "us-east-1"
# The second OVH account lives on another API endpoint and signs in with
# its OAuth2 client, so its calls prove whose credentials were used.
BACKUP_ENDPOINT = "ovh-ca"


def _home(journey, fake_cloud, *, aws_role_arn=None, level="standard"):
    """A child home with the second accounts configured.

    Without *aws_role_arn*: two Hetzner projects and two OVH accounts, and
    AWS with its primary account only, served from a fresh cache. With it:
    AWS alone, its second account being the profile that assumes that role,
    both accounts read from the local AWS endpoint.
    """
    from servonaut.config.schema import MCPConfig

    sandbox = journey.new_sandbox()
    seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
    overrides = {"mcp": MCPConfig(guard_level=level)}
    if aws_role_arn is None:
        overrides["hetzner"] = seeder.hetzner_config(accounts=[seeder.hetzner_account(STAGING)])
        overrides["ovh"] = seeder.ovh_config(accounts=[
            seeder.ovh_account(BACKUP, endpoint=BACKUP_ENDPOINT, oauth2=True),
        ])
        seeder.cache(fleet.cache_rows(fleet.APP_1), fresh=True)
    else:
        seeder.aws_profile("base")
        seeder.aws_profile(PROD, role_arn=aws_role_arn, source_profile="base")
        overrides["aws"] = seeder.aws_config(
            regions=[REGION], accounts=[seeder.aws_account(PROD, regions=[REGION])],
        )
    seeder.config(**overrides)
    return sandbox


def _seed_providers(providers):
    fleet.seed_provider_fleet(providers)
    return fleet.seed_second_accounts(providers, ovh_endpoint=BACKUP_ENDPOINT)


def _audit(sandbox) -> list[dict]:
    path: Path = sandbox.home / ".servonaut" / "mcp_audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _names(listing: str) -> set[str]:
    """First column of every row below the dashed rule."""
    lines = listing.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("---")) + 1
    names = set()
    for line in lines[start:]:
        if not line.strip() or line.startswith("Warning"):
            break
        names.add(line.split()[0])
    return names


def _candidates(*accounts: str) -> list[str]:
    return [f"{account}/{SHARED}" for account in accounts]


async def test_list_instances_names_and_filters_accounts(mcp, journey, fake_cloud, providers):
    _seed_providers(providers)
    sandbox = _home(journey, fake_cloud)

    async with mcp(sandbox) as session:
        everything = await session.call("list_instances")
        staging = await session.call("list_instances", {"account": STAGING})
        unknown = await session.call("list_instances", {"account": "nope"})

    shown = _names(everything)
    assert set(_candidates(HZ_PRIMARY, STAGING, OVH_PRIMARY, BACKUP)) <= shown
    assert {
        f"{STAGING}/{fleet.HZ_SECOND_LB_1.name}",
        f"{HZ_PRIMARY}/{fleet.HZ_CACHE_1.name}",
        f"{BACKUP}/{fleet.OVH_SECOND_BATCH_3.name}",
        f"{OVH_PRIMARY}/{fleet.OVH_VPS_MAIL_1.display_name}",
    } <= shown
    # AWS has one account here: its names stay plain.
    assert fleet.APP_1.name in shown and f"aws/{fleet.APP_1.name}" not in shown

    assert _names(staging) == {
        f"{STAGING}/{fleet.HZ_SECOND_WEB_1.name}", f"{STAGING}/{fleet.HZ_SECOND_LB_1.name}",
    }
    assert unknown.startswith("Error: No account named 'nope'.")
    assert STAGING in unknown and BACKUP in unknown

    rows = _audit(sandbox)
    assert [(r["tool"], r["args"].get("account"), r["allowed"]) for r in rows] == [
        ("list_instances", None, True),
        ("list_instances", STAGING, True),
        ("list_instances", "nope", False),
    ]
    assert rows[-1]["reason"].startswith("validation: unknown account")


async def test_a_shared_name_is_refused_and_a_qualified_one_resolves(
    mcp, journey, fake_cloud, providers
):
    _seed_providers(providers)
    sandbox = _home(journey, fake_cloud)

    async with mcp(sandbox) as session:
        # Listing caches every account's servers, as an agent's first call does.
        await session.call("list_instances")
        ambiguous = await session.call("check_status", {"instance_id": SHARED})
        qualified = await session.call("check_status", {"instance_id": f"{STAGING}/{SHARED}"})
        backup = await session.call("check_status", {"instance_id": f"{BACKUP}/{SHARED}"})

    assert ambiguous.startswith(f"Error: '{SHARED}' matches 4 servers:")
    for reference in _candidates(HZ_PRIMARY, STAGING, OVH_PRIMARY, BACKUP):
        assert reference in ambiguous
    assert f"Instance:   {fleet.HZ_SECOND_WEB_1.server_id}" in qualified
    assert f"Instance:   {fleet.OVH_SECOND_VPS_WEB_1.service_name}" in backup

    rows = [r for r in _audit(sandbox) if r["tool"] == "check_status"]
    assert [(r["tool"], r["allowed"], r.get("reason")) for r in rows] == [
        ("check_status", False, "ambiguous_instance"),
        ("check_status", True, ""),
        ("check_status", True, ""),
    ]


async def test_hetzner_power_off_reaches_the_owning_project(mcp, journey, fake_cloud, providers):
    second, _ = _seed_providers(providers)
    sandbox = _home(journey, fake_cloud)
    web_1 = fleet.HZ_SECOND_WEB_1.server_id
    lb_1 = fleet.HZ_SECOND_LB_1.server_id

    # Nothing was listed first: each project's servers are read on demand,
    # and a power action dropping a project's cache hides none of them.
    async with mcp(sandbox) as session:
        qualified = await session.call("hetzner_power_off", {"identifier": f"{STAGING}/{SHARED}"})
        by_account = await session.call(
            "hetzner_power_off", {"identifier": SHARED, "account": STAGING},
        )
        only_there = await session.call("hetzner_power_off", {"identifier": fleet.HZ_SECOND_LB_1.name})
        ambiguous = await session.call("hetzner_power_off", {"identifier": SHARED})
        unknown = await session.call("hetzner_power_off", {"identifier": SHARED, "account": "nope"})
        nowhere = await session.call("hetzner_power_off", {"identifier": "web-9"})

    assert qualified == f"Hetzner server '{STAGING}/{SHARED}': powered off."
    assert by_account == f"Hetzner server '{SHARED}': powered off."
    assert only_there == f"Hetzner server '{fleet.HZ_SECOND_LB_1.name}': powered off."
    assert "matches 2 servers" in ambiguous
    for reference in _candidates(HZ_PRIMARY, STAGING):
        assert reference in ambiguous
    assert unknown.startswith("Error: No Hetzner account named 'nope'")
    assert nowhere.startswith(
        f"Error: No Hetzner server 'web-9' in any account ({HZ_PRIMARY}, {STAGING})."
    )

    # Three power-offs, all in the staging project; nothing in the primary one.
    assert [(e["account"], e["api_path"]) for e in providers.mutations("hetzner")] == [
        (STAGING, f"/servers/{web_1}/actions/poweroff"),
        (STAGING, f"/servers/{web_1}/actions/poweroff"),
        (STAGING, f"/servers/{lb_1}/actions/poweroff"),
    ]
    assert second.server(web_1)["status"] == "off"
    assert providers.hetzner.server(fleet.HZ_WEB_1.server_id)["status"] == "running"

    lifecycle = [r for r in _audit(sandbox) if r["tool"] == "hetzner_power_off"]
    assert [(r["args"].get("account"), r["allowed"], r.get("reason")) for r in lifecycle] == [
        (STAGING, True, ""),
        (STAGING, True, ""),
        (STAGING, True, ""),
        (None, False, "ambiguous_instance"),
        ("nope", False, lifecycle[-2].get("reason")),
        (None, False, "instance_not_found"),
    ]
    assert lifecycle[-2]["reason"].startswith("validation: unknown account")


async def test_ovh_reboot_reaches_the_owning_account(mcp, journey, fake_cloud, providers):
    _, backup = _seed_providers(providers)
    sandbox = _home(journey, fake_cloud)
    vps = fleet.OVH_SECOND_VPS_WEB_1.service_name

    async with mcp(sandbox) as session:
        await session.call("list_instances")
        qualified = await session.call(
            "ovh_reboot_instance", {"instance_id": f"{BACKUP}/{vps}", "provider_type": "vps"},
        )
        by_id = await session.call(
            "ovh_reboot_instance", {"instance_id": vps, "provider_type": "vps"},
        )

    assert qualified == f"OVH vps {BACKUP}/{vps}: reboot sent."
    assert by_id == f"OVH vps {vps}: reboot sent."
    reboots = providers.requests("ovh", method="POST", path=rf"/vps/{vps}/reboot")
    assert [(e["endpoint"], e["account"]) for e in reboots] == [
        (BACKUP_ENDPOINT, BACKUP), (BACKUP_ENDPOINT, BACKUP),
    ]
    # Apart from its OAuth2 token requests, nothing else changed anywhere.
    changes = [e for e in providers.mutations("ovh") if e not in reboots]
    assert {e["api_path"] for e in changes} <= {fake_ovh.OVH_OAUTH2_TOKEN_PATH}


async def test_aws_lifecycle_acts_in_the_owning_account(mcp, journey, fake_cloud, moto):
    primary = moto.seed_fleet([fleet.AWS_WEB_1])
    role_arn = moto.seed_role(aws.ACCOUNT_ROLE, aws.SECOND_ACCOUNT)
    second = moto.seed_fleet(fleet.AWS_SECOND_FLEET, role_arn=role_arn)
    sandbox = _home(journey, fake_cloud, aws_role_arn=role_arn)

    async with mcp(sandbox) as session:
        listed = await session.call("list_instances")
        stopped = await session.call(
            "aws_stop_instance", {"instance_id": second[SHARED], "region": REGION},
        )
        started = await session.call(
            "aws_start_instance",
            {"instance_id": f"{PROD}/{fleet.AWS_SECOND_JOBS_1.name}", "region": REGION},
        )
        ambiguous = await session.call(
            "aws_reboot_instance", {"instance_id": SHARED, "region": REGION},
        )

    assert {f"aws/{SHARED}", f"{PROD}/{SHARED}", f"{PROD}/{fleet.AWS_SECOND_JOBS_1.name}"} <= (
        _names(listed)
    )
    assert stopped == f"EC2 instance {second[SHARED]} ({REGION}): stop sent."
    assert started == f"EC2 instance {second[fleet.AWS_SECOND_JOBS_1.name]} ({REGION}): start sent."
    assert "matches 2 servers" in ambiguous

    def state(instance_id, role=None):
        ec2 = moto.client_as(role, "ec2", REGION) if role else moto.client("ec2", REGION)
        reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        return reservations[0]["Instances"][0]["State"]["Name"]

    # The second account's instances changed; the primary web-1 did not.
    assert state(second[SHARED], role_arn) in ("stopping", "stopped")
    assert state(second[fleet.AWS_SECOND_JOBS_1.name], role_arn) in ("pending", "running")
    assert state(primary[SHARED]) == "running"

    lifecycle = [r for r in _audit(sandbox) if r["tool"].startswith("aws_")]
    assert [(r["tool"], r["args"].get("account"), r["allowed"]) for r in lifecycle] == [
        ("aws_stop_instance", PROD, True),
        ("aws_start_instance", PROD, True),
        ("aws_reboot_instance", None, False),
    ]
    assert lifecycle[-1]["reason"] == "ambiguous_instance"


async def test_object_storage_follows_the_account(mcp, journey, fake_cloud, moto):
    role_arn = moto.seed_role(aws.ACCOUNT_ROLE, aws.SECOND_ACCOUNT)
    moto.seed_bucket("e2e-primary-assets")
    moto.seed_bucket("e2e-prod-assets", region=REGION, role_arn=role_arn)
    sandbox = _home(journey, fake_cloud, aws_role_arn=role_arn)

    async with mcp(sandbox) as session:
        primary = await session.call("s3_list_buckets", {"provider": "aws"})
        prod = await session.call("s3_list_buckets", {"provider": "aws", "account": PROD})
        unknown = await session.call("s3_list_buckets", {"provider": "aws", "account": "nope"})

    assert "e2e-primary-assets" in primary and "e2e-prod-assets" not in primary
    assert "e2e-prod-assets" in prod and "e2e-primary-assets" not in prod
    assert unknown.startswith("Error: No AWS account named 'nope'")
    rows = _audit(sandbox)
    assert [(r["args"].get("account"), r["allowed"]) for r in rows] == [
        (None, True), (PROD, True), ("nope", False),
    ]
