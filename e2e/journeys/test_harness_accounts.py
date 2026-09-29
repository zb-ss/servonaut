"""Self-tests for several accounts per provider in the harness.

Journeys about multiple accounts prove that each action reached the right
account, which only means something if the stand-ins keep the accounts
apart the way the real services do:

* each Hetzner project answers its own token, and an unknown token gets 401;
* each OVH account answers its own classic keys and OAuth2 client, on its
  own endpoint, in this process and in children;
* each AWS named profile reaches its own moto account even though the suite's
  environment credentials are set;
* the request logs name the account every call reached, never a credential.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from dataclasses import replace

import pytest

from e2e.harness import aws, fleet
from e2e.harness.fake_providers import hetzner as fake_hetzner
from e2e.harness.fake_providers import ovh as fake_ovh

pytestmark = [pytest.mark.e2e_pr]


def _hcloud(providers, token: str):
    from hcloud import Client

    # The product's own endpoint switch is not used here: point the SDK directly.
    return Client(token=token, api_endpoint=providers.hetzner_url)


def _ovh_client(endpoint: str, credentials, *, oauth2: bool):
    import ovh

    if oauth2:
        return ovh.Client(
            endpoint=endpoint,
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
        )
    return ovh.Client(
        endpoint=endpoint,
        application_key=credentials.application_key,
        application_secret=credentials.application_secret,
        consumer_key=credentials.consumer_key,
    )


def _names(hosts) -> set[str]:
    return {host.name for host in hosts}


# ---------------------------------------------------------------------------
# Hetzner
# ---------------------------------------------------------------------------


def test_hetzner_projects_answer_their_own_token(providers):
    from hcloud import APIException
    from hcloud.images import Image
    from hcloud.server_types import ServerType

    fleet.seed_provider_fleet(providers, ovh=False)
    second, _ = fleet.seed_second_accounts(providers, ovh=False)
    primary = _hcloud(providers, fake_hetzner.PRIMARY_TOKEN)
    other = _hcloud(providers, fake_hetzner.token_for(fleet.HETZNER_SECOND_ACCOUNT))

    primary_names = _names(fleet.HETZNER_FLEET) | {fleet.SHARED_NAME}
    assert {s.name for s in primary.servers.get_all()} == primary_names
    assert {s.name for s in other.servers.get_all()} == _names(fleet.HETZNER_SECOND_FLEET)
    with pytest.raises(APIException) as refused:
        _hcloud(providers, "hz-unknown-token").servers.get_all()
    assert refused.value.code == "unauthorized"

    # Ids stay unique across projects, as they are on Hetzner.
    created = [
        client.servers.create(
            name="web-2", server_type=ServerType(name="cx23"), image=Image(name="debian-12")
        ).server.id
        for client in (primary, other)
    ]
    assert len(set(created)) == 2
    assert providers.hetzner.server_named("web-2")["id"] == created[0]
    assert second.server_named("web-2")["id"] == created[1]

    # A failure set on one project leaves the other one working.
    second.fail_with = "unauthorized"
    with pytest.raises(APIException):
        other.servers.get_all()
    assert primary.servers.get_all()

    listings = providers.requests("hetzner", method="GET", path="/servers")
    assert [(e["account"], e["status"]) for e in listings] == [
        (fake_hetzner.PRIMARY_LABEL, 200),
        (fleet.HETZNER_SECOND_ACCOUNT, 200),
        (None, 401),
        (fleet.HETZNER_SECOND_ACCOUNT, 401),
        (fake_hetzner.PRIMARY_LABEL, 200),
    ]
    assert providers.requests("hetzner", method="POST", account=fleet.HETZNER_SECOND_ACCOUNT)
    logged = json.dumps(providers.requests())
    assert fake_hetzner.PRIMARY_TOKEN not in logged and "hz-unknown-token" not in logged


def test_hetzner_projects_are_forgotten_on_reset(providers):
    providers.add_hetzner_project(fleet.HETZNER_SECOND_ACCOUNT)
    with pytest.raises(ValueError):
        providers.add_hetzner_project(fleet.HETZNER_SECOND_ACCOUNT)
    providers.hetzner.label = "renamed"
    providers.reset()
    assert providers.hetzner.label == fake_hetzner.PRIMARY_LABEL
    with pytest.raises(KeyError):
        providers.hetzner_projects.get(fleet.HETZNER_SECOND_ACCOUNT)
    second_token = fake_hetzner.token_for(fleet.HETZNER_SECOND_ACCOUNT)
    assert providers.hetzner_projects.for_token(second_token) is None


# ---------------------------------------------------------------------------
# OVH
# ---------------------------------------------------------------------------


def test_ovh_accounts_answer_their_own_credentials(providers):
    import ovh

    fleet.seed_provider_fleet(providers, hetzner=False)
    _, second = fleet.seed_second_accounts(providers, hetzner=False, ovh_endpoint="ovh-ca")
    keys = fake_ovh.credentials_for(fleet.OVH_SECOND_ACCOUNT)
    primary = _ovh_client("ovh-eu", fake_ovh.PRIMARY_CREDENTIALS, oauth2=False)
    classic = _ovh_client("ovh-ca", keys, oauth2=False)
    oauth2 = _ovh_client("ovh-ca", keys, oauth2=True)

    primary_vps = sorted(h.service_name for h in (*fleet.OVH_VPS_FLEET, fleet.OVH_VPS_WEB_1))
    second_vps = sorted(h.service_name for h in fleet.OVH_SECOND_VPS_FLEET)
    assert primary.get("/vps") == primary_vps
    assert primary.get("/me")["nichandle"] == fake_ovh.NIC_HANDLE
    for client in (classic, oauth2):
        assert client.get("/vps") == second_vps
        assert client.get("/cloud/project") == [fleet.OVH_SECOND_PROJECT_ID]
        assert client.get("/me")["nichandle"] == second.nic_handle != fake_ovh.NIC_HANDLE

    # Credentials only work on their own account's endpoint, and must match.
    with pytest.raises(ovh.exceptions.InvalidKey):
        _ovh_client("ovh-eu", keys, oauth2=False).get("/vps")
    with pytest.raises(ovh.exceptions.InvalidCredential):
        _ovh_client("ovh-ca", replace(keys, consumer_key="ck-unknown"), oauth2=False).get("/vps")
    with pytest.raises(ovh.exceptions.BadParametersError, match="Invalid signature"):
        _ovh_client("ovh-ca", replace(keys, application_secret="as-unknown"), oauth2=False).get(
            "/vps"
        )
    with pytest.raises(ovh.exceptions.OAuth2FailureError):
        _ovh_client("ovh-ca", replace(keys, client_secret="cs-unknown"), oauth2=True).get("/vps")

    # One account failing leaves the other one working.
    second.fail_with = "INVALID_CREDENTIAL"
    with pytest.raises(ovh.exceptions.InvalidCredential):
        classic.get("/vps")
    assert primary.get("/vps") == primary_vps

    listings = providers.requests("ovh", method="GET", path="/vps")
    assert [(e["endpoint"], e["account"], e["status"]) for e in listings] == [
        ("ovh-eu", fake_ovh.PRIMARY_LABEL, 200),
        ("ovh-ca", fleet.OVH_SECOND_ACCOUNT, 200),
        ("ovh-ca", fleet.OVH_SECOND_ACCOUNT, 200),
        ("ovh-eu", None, 403),
        ("ovh-ca", None, 403),
        ("ovh-ca", None, 400),
        ("ovh-ca", fleet.OVH_SECOND_ACCOUNT, 403),
        ("ovh-eu", fake_ovh.PRIMARY_LABEL, 200),
    ]
    tokens = providers.requests("ovh", path=fake_ovh.OVH_OAUTH2_TOKEN_PATH)
    assert [(e["endpoint"], e["account"], e["status"]) for e in tokens] == [
        ("ovh-ca", fleet.OVH_SECOND_ACCOUNT, 200),
        ("ovh-ca", None, 401),
    ]
    logged = json.dumps(providers.requests())
    for secret in (keys.consumer_key, keys.client_secret, "cs-unknown"):
        assert secret not in logged


def test_ovh_oauth2_reaches_the_fake_from_a_child(journey, providers):
    fleet.seed_second_accounts(providers, hetzner=False, ovh_endpoint="ovh-ca")
    keys = fake_ovh.credentials_for(fleet.OVH_SECOND_ACCOUNT)
    code = (
        "import json, ovh\n"
        f"client = ovh.Client(endpoint='ovh-ca', client_id={keys.client_id!r},\n"
        f"                    client_secret={keys.client_secret!r})\n"
        "print(json.dumps(client.get('/vps')))\n"
    )
    sandbox = journey.new_sandbox(f"ovh-child-{uuid.uuid4().hex[:8]}")
    completed = subprocess.run(
        [sys.executable, "-c", code],
        env=journey.child_env(sandbox),
        cwd=sandbox.base,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == [h.service_name for h in fleet.OVH_SECOND_VPS_FLEET]
    calls = providers.requests("ovh", account=fleet.OVH_SECOND_ACCOUNT)
    assert [(e["endpoint"], e["api_path"]) for e in calls] == [
        ("ovh-ca", fake_ovh.OVH_OAUTH2_TOKEN_PATH),
        ("ovh-ca", "/vps"),
    ]


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------


def _session_view(profile):
    import boto3

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    account = session.client("sts").get_caller_identity()["Account"]
    reservations = session.client("ec2", region_name="us-east-1").describe_instances()
    names = {
        tag["Value"]
        for reservation in reservations["Reservations"]
        for instance in reservation["Instances"]
        for tag in instance.get("Tags", [])
        if tag["Key"] == "Name"
    }
    return session.get_credentials().access_key, account, names


def test_aws_profiles_reach_their_own_accounts(seed, moto):
    from e2e.harness.seed import aws_access_key

    primary_hosts = (*fleet.AWS_FLEET, fleet.AWS_WEB_1)
    moto.seed_fleet(primary_hosts)
    role_arn = moto.seed_account(aws.SECOND_ACCOUNT, fleet.AWS_SECOND_FLEET)
    seed.aws_profile("base")
    seed.aws_profile(fleet.AWS_SECOND_ACCOUNT, role_arn=role_arn, source_profile="base")
    # The suite's environment credentials stay set throughout.
    assert os.environ["AWS_ACCESS_KEY_ID"] == "testing"
    assert "AWS_PROFILE" not in os.environ

    primary_names = {h.name for h in primary_hosts if h.region == "us-east-1"}
    second_names = _names(fleet.AWS_SECOND_FLEET)
    assert primary_names & second_names == {fleet.SHARED_NAME}
    assert _session_view(None) == ("testing", aws.DEFAULT_ACCOUNT, primary_names)
    # A profile named explicitly replaces the environment credentials.
    assert _session_view("base") == (aws_access_key("base"), aws.DEFAULT_ACCOUNT, primary_names)
    key, account, names = _session_view(fleet.AWS_SECOND_ACCOUNT)
    assert key not in ("testing", aws_access_key("base"))
    assert (account, names) == (aws.SECOND_ACCOUNT, second_names)
    assert set(moto.describe_names(role_arn=role_arn)) == second_names

    with pytest.raises(ValueError):
        seed.aws_profile("orphan", role_arn=role_arn, source_profile="missing")


# ---------------------------------------------------------------------------
# The product reads every seeded account
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_seeded_accounts_load_through_the_product(seed, providers, moto):
    from servonaut.config.manager import ConfigManager
    from servonaut.services.accounts import AccountRegistry
    from servonaut.utils.instance_resolver import display_name

    fleet.seed_provider_fleet(providers)
    fleet.seed_second_accounts(providers, ovh_endpoint="ovh-ca")
    moto.seed_fleet((*fleet.AWS_FLEET, fleet.AWS_WEB_1))
    role_arn = moto.seed_account(aws.SECOND_ACCOUNT, fleet.AWS_SECOND_FLEET)
    seed.aws_profile("base")
    seed.aws_profile(fleet.AWS_SECOND_ACCOUNT, role_arn=role_arn, source_profile="base")
    seed.config(
        aws=seed.aws_config(
            regions=["us-east-1"],
            accounts=[seed.aws_account(fleet.AWS_SECOND_ACCOUNT, regions=["us-east-1"])],
        ),
        hetzner=seed.hetzner_config(
            accounts=[seed.hetzner_account(fleet.HETZNER_SECOND_ACCOUNT)]
        ),
        ovh=seed.ovh_config(
            accounts=[seed.ovh_account(fleet.OVH_SECOND_ACCOUNT, endpoint="ovh-ca", oauth2=True)]
        ),
    )
    registry = AccountRegistry(ConfigManager(config_path=seed.config_path).load())
    assert registry.problems == [] and registry.unavailable == {}

    shown = {}
    for provider in ("aws", "hetzner", "ovh"):
        inventory = registry.fleet(provider)
        rows = await inventory.fetch_instances_cached(force_refresh=True)
        assert inventory.last_fetch_error is None, (provider, inventory.last_fetch_error)
        shown[provider] = {display_name(row) for row in rows}

    assert {"aws/web-1", "prod/web-1", "prod/jobs-1"} <= shown["aws"]
    assert {"hetzner/web-1", "staging/web-1", "staging/lb-1"} <= shown["hetzner"]
    assert {"ovh/web-1", "backup/web-1", "backup/batch-3"} <= shown["ovh"]
    assert providers.requests("hetzner", account=fleet.HETZNER_SECOND_ACCOUNT, path="/servers")
    ovh_calls = providers.requests("ovh", account=fleet.OVH_SECOND_ACCOUNT)
    assert {e["endpoint"] for e in ovh_calls} == {"ovh-ca"}
    assert ovh_calls[0]["api_path"] == fake_ovh.OVH_OAUTH2_TOKEN_PATH


@pytest.mark.asyncio
async def test_fleet_rows_are_selected_by_what_the_table_shows(tui, seed, providers):
    fleet.seed_provider_fleet(providers, ovh=False)
    fleet.seed_second_accounts(providers, ovh=False)
    seed.config(
        hetzner=seed.hetzner_config(accounts=[seed.hetzner_account(fleet.HETZNER_SECOND_ACCOUNT)])
    )
    seed.cache(fleet.cache_rows(fleet.APP_1), fresh=True)
    second = f"{fleet.HETZNER_SECOND_ACCOUNT}/{fleet.SHARED_NAME}"
    primary = f"{fake_hetzner.PRIMARY_LABEL}/{fleet.SHARED_NAME}"

    async with tui() as t:
        selected = await t.wait_and_select_instance(second)
        assert (selected["account"], selected["name"]) == (
            fleet.HETZNER_SECOND_ACCOUNT, fleet.SHARED_NAME
        )
        selected = await t.select_instance(primary)
        assert selected["id"] == str(fleet.HZ_WEB_1.server_id)
        # A provider with one account keeps showing, and selecting, plain names.
        assert (await t.select_instance(fleet.APP_1.name))["id"] == fleet.APP_1.instance_id
        with pytest.raises(AssertionError, match="is not in the fleet table"):
            await t.select_instance(fleet.SHARED_NAME)
