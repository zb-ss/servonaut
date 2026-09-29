"""MCP tools across several accounts per provider."""
from __future__ import annotations

import asyncio
import inspect
from unittest.mock import MagicMock

import pytest

from servonaut.mcp.guards import GuardLevel
from servonaut.mcp.tool_schemas import TOOL_SCHEMAS
from servonaut.mcp.tools import ServonautTools
from tests._account_fixtures import audit_rows, build_registry, make_tools


def _run(coro):
    return asyncio.run(coro)


def _hetzner(id_, name, **extra):
    return {"id": id_, "name": name, "state": "running", "region": "fsn1",
            "public_ip": "9.9.9.9", "is_hetzner": True, **extra}


WEB_PRIMARY = _hetzner("1", "web-1")
WEB_STAGING = _hetzner("2", "web-1")
WORKER = _hetzner("4", "worker")


@pytest.fixture
def two_projects(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "api", "state": "running", "region": "eu-west-1"}]},
        hetzner={"hetzner": [WEB_PRIMARY], "staging": [WEB_STAGING, WORKER]},
    )
    return make_tools(registry), services


# ---------------------------------------------------------------------------
# list_instances
# ---------------------------------------------------------------------------


def test_list_instances_qualifies_names_of_a_multi_account_provider(two_projects):
    tools, _ = two_projects
    out = _run(tools.list_instances())
    assert "hetzner/web-1" in out and "staging/web-1" in out and "staging/worker" in out
    # AWS has one account: its names stay plain.
    assert "aws/api" not in out and "api" in out


def test_list_instances_single_account_output_is_unchanged(monkeypatch):
    registry, _ = build_registry(monkeypatch, hetzner={"hetzner": [WEB_PRIMARY]})
    tools = make_tools(registry)
    out = _run(tools.list_instances())
    assert "hetzner/web-1" not in out
    row = next(line for line in out.splitlines() if "web-1" in line)
    assert row.startswith("web-1 ")


def test_list_instances_account_filter(two_projects):
    tools, services = two_projects
    out = _run(tools.list_instances(account="staging"))
    assert "staging/web-1" in out and "staging/worker" in out
    assert "hetzner/web-1" not in out and "api" not in out
    # Only Hetzner was read.
    assert services[("aws", "aws")].fetches == 0
    name, args, allowed, _ = audit_rows(tools)[-1]
    assert (name, args["account"], allowed) == ("list_instances", "staging", True)


def test_list_instances_custom_filter(monkeypatch):
    registry, _ = build_registry(monkeypatch)
    tools = make_tools(registry, custom=[{"id": "custom-a", "name": "box", "is_custom": True}])
    out = _run(tools.list_instances(account="custom"))
    assert "box" in out


def test_list_instances_unknown_account_is_a_validation_error(two_projects):
    tools, _ = two_projects
    out = _run(tools.list_instances(account="nope"))
    assert out.startswith("Error: No account named 'nope'")
    assert "staging" in out
    name, args, allowed, reason = audit_rows(tools)[-1]
    assert (name, allowed) == ("list_instances", False)
    assert reason.startswith("validation: unknown account")


def test_list_instances_warns_per_account(two_projects):
    tools, services = two_projects
    services[("hetzner", "staging")].last_fetch_error = "token refused"
    out = _run(tools.list_instances())
    assert "Hetzner inventory was only partly refreshed. staging: token refused" in out


# ---------------------------------------------------------------------------
# Instance references in instance-level tools
# ---------------------------------------------------------------------------


def test_check_status_accepts_a_qualified_reference(two_projects):
    tools, _ = two_projects
    out = _run(tools.check_status("staging/web-1"))
    assert "Instance:   2" in out


def test_ambiguous_reference_is_refused_with_candidates(two_projects):
    tools, _ = two_projects
    out = _run(tools.check_status("web-1"))
    assert out.startswith("Error: 'web-1' matches 2 servers")
    assert "hetzner/web-1" in out and "staging/web-1" in out
    assert audit_rows(tools)[-1] == (
        "check_status", {"instance_id": "web-1"}, False, "ambiguous_instance",
    )


def test_run_command_never_takes_a_name_as_unique_before_listing_it(monkeypatch):
    """AWS web-1 matches first; Hetzner was never listed and has one too."""
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "web-1", "region": "eu-west-1"}]},
        hetzner={"hetzner": [WEB_PRIMARY]},
    )
    services[("hetzner", "hetzner")].cached = None
    tools = make_tools(registry)
    ran = MagicMock()
    monkeypatch.setattr(tools, "_run_command_via_ssh", ran)
    out = _run(tools.run_command("web-1", "uptime"))
    assert "matches 2 servers" in out and "hetzner/web-1" in out
    ran.assert_not_called()


def test_ambiguous_reference_on_run_command_never_runs(two_projects, monkeypatch):
    tools, _ = two_projects
    ran = MagicMock()
    monkeypatch.setattr(tools, "_run_command_via_ssh", ran)
    out = _run(tools.run_command("web-1", "uptime"))
    assert "matches 2 servers" in out
    ran.assert_not_called()
    assert audit_rows(tools)[-1][3] == "ambiguous_instance"


# ---------------------------------------------------------------------------
# Lifecycle tools
# ---------------------------------------------------------------------------


def test_hetzner_power_on_finds_the_owning_project(two_projects):
    tools, services = two_projects
    out = _run(tools.hetzner_power_on("worker"))
    assert out == "Hetzner server 'worker': started."
    assert services[("hetzner", "staging")].called("power_on") == [("worker",)]
    assert services[("hetzner", "hetzner")].called("power_on") == []
    name, args, allowed, _ = audit_rows(tools)[-1]
    assert args == {"identifier": "worker", "account": "staging"} and allowed


def test_hetzner_power_on_qualified(two_projects):
    tools, services = two_projects
    _run(tools.hetzner_reboot("staging/web-1"))
    assert services[("hetzner", "staging")].called("reboot") == [("web-1",)]


def test_hetzner_name_in_two_projects_is_refused(two_projects):
    tools, services = two_projects
    out = _run(tools.hetzner_delete_server("web-1"))
    assert "matches 2 servers" in out and "staging/web-1" in out
    assert all(not s.called("delete_server") for s in services.values())
    assert audit_rows(tools)[-1][3] == "ambiguous_instance"


def test_hetzner_explicit_account(two_projects):
    tools, services = two_projects
    _run(tools.hetzner_power_off("web-1", account="staging"))
    assert services[("hetzner", "staging")].called("power_off") == [("web-1",)]


def test_hetzner_unknown_account(two_projects):
    tools, services = two_projects
    out = _run(tools.hetzner_shutdown("web-1", account="nope"))
    assert out.startswith("Error: No Hetzner account named 'nope'")
    assert audit_rows(tools)[-1][3].startswith("validation: unknown account")


def test_hetzner_single_account_audit_row_is_unchanged(monkeypatch):
    registry, services = build_registry(monkeypatch, hetzner={"hetzner": [WEB_PRIMARY]})
    tools = make_tools(registry)
    _run(tools.hetzner_power_on("web-1"))
    assert services[("hetzner", "hetzner")].called("power_on") == [("web-1",)]
    assert audit_rows(tools)[-1][1] == {"identifier": "web-1"}


def test_a_power_action_that_drops_a_cache_does_not_hide_its_servers(two_projects):
    """Hetzner drops a project's cache after a power action; the next call
    must still see that project's servers, and refuse the shared name."""
    tools, services = two_projects
    staging = services[("hetzner", "staging")]
    staging.invalidates_cache = True
    _run(tools.hetzner_power_off("staging/web-1"))
    assert staging.cached is None

    out = _run(tools.hetzner_power_off("worker"))
    assert out == "Hetzner server 'worker': powered off."
    refused = _run(tools.hetzner_power_off("web-1"))
    assert "matches 2 servers" in refused
    assert services[("hetzner", "hetzner")].called("power_off") == []
    assert staging.called("power_off") == [("web-1",), ("worker",)]


def test_a_project_never_listed_is_read_before_acting(two_projects):
    tools, services = two_projects
    services[("hetzner", "staging")].cached = None
    _run(tools.hetzner_reboot("worker"))
    assert services[("hetzner", "staging")].called("reboot") == [("worker",)]


def test_a_server_no_project_lists_is_refused(two_projects):
    tools, services = two_projects
    out = _run(tools.hetzner_delete_server("ghost"))
    assert out.startswith("Error: No Hetzner server 'ghost' in any account (hetzner, staging).")
    assert "account=<label>" in out and "'staging/ghost'" in out
    assert all(not s.called("delete_server") for s in services.values())
    assert audit_rows(tools)[-1][2:] == (False, "instance_not_found")
    # Naming the project still passes the reference to it.
    _run(tools.hetzner_delete_server("ghost", account="staging"))
    assert services[("hetzner", "staging")].called("delete_server") == [("ghost",)]


def test_single_project_unlisted_server_still_goes_to_it(monkeypatch):
    registry, services = build_registry(monkeypatch, hetzner={"hetzner": [WEB_PRIMARY]})
    tools = make_tools(registry)
    _run(tools.hetzner_power_on("ghost"))
    assert services[("hetzner", "hetzner")].called("power_on") == [("ghost",)]


def test_aws_lifecycle_uses_the_account_that_lists_the_instance(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        aws={"aws": [{"id": "i-1", "name": "api"}], "prod": [{"id": "i-2", "name": "db"}]},
    )
    tools = make_tools(registry)
    _run(tools.aws_stop_instance("i-2", "eu-west-1"))
    _run(tools.aws_start_instance("prod/db", "eu-west-1"))
    prod = services[("aws", "prod")]
    assert prod.called("stop_instance") == [("i-2", "eu-west-1")]
    assert prod.called("start_instance") == [("i-2", "eu-west-1")]
    assert services[("aws", "aws")].calls == []


def test_ovh_lifecycle_with_a_qualified_cloud_id(monkeypatch):
    registry, services = build_registry(
        monkeypatch,
        ovh={"ovh": [], "eu2": [{"id": "proj1/inst-1", "name": "api", "is_ovh": True}]},
    )
    tools = make_tools(registry)
    _run(tools.ovh_reboot_instance("eu2/proj1/inst-1", "cloud"))
    assert services[("ovh", "eu2")].called("reboot_instance") == [("proj1/inst-1", "cloud")]


def test_ovh_delete_instance_in_the_owning_account(monkeypatch):
    registry, _ = build_registry(
        monkeypatch,
        ovh={"ovh": [], "eu2": [{"id": "proj1/inst-1", "name": "api", "is_ovh": True}]},
    )
    tools = make_tools(registry)
    cloud = MagicMock()

    async def _delete(project_id, instance_id):
        cloud.deleted = (project_id, instance_id)

    cloud.delete_instance = _delete
    registry.ovh_services("eu2").cloud = cloud
    out = _run(tools.ovh_delete_instance("proj1", "inst-1"))
    assert out == "Deleted OVH instance proj1/inst-1."
    assert cloud.deleted == ("proj1", "inst-1")


# ---------------------------------------------------------------------------
# Account-scoped tools
# ---------------------------------------------------------------------------


def test_hetzner_account_level_tools_use_the_named_project(two_projects):
    tools, services = two_projects
    services[("hetzner", "staging")].returns["list_ssh_keys"] = [
        {"name": "deploy", "id": 7, "fingerprint": "aa"},
    ]
    out = _run(tools.hetzner_list_ssh_keys(account="staging"))
    assert "deploy" in out
    assert services[("hetzner", "hetzner")].called("list_ssh_keys") == []


def test_hetzner_list_servers_lists_every_project_unless_one_is_named(two_projects):
    tools, _ = two_projects
    everything = _run(tools.hetzner_list_servers())
    assert "hetzner/web-1" in everything and "staging/worker" in everything
    staging = _run(tools.hetzner_list_servers(account="staging"))
    assert "worker" in staging and "hetzner/web-1" not in staging


def test_aws_list_tools_use_the_named_account(monkeypatch):
    registry, services = build_registry(monkeypatch, aws={"aws": [], "prod": []})
    services[("aws", "prod")].returns["list_regions"] = ["eu-central-1"]
    tools = make_tools(registry)
    out = _run(tools.aws_list_regions(account="prod"))
    assert "eu-central-1" in out
    assert services[("aws", "aws")].calls == []
    assert audit_rows(tools)[-1][1]["account"] == "prod"


def test_cloudtrail_and_cloudwatch_use_the_named_account(monkeypatch):
    registry, _ = build_registry(monkeypatch, aws={"aws": [], "prod": []})
    tools = make_tools(registry)
    trail = MagicMock()

    async def _lookup(**kwargs):
        return []

    trail.lookup_events = _lookup
    registry.aws_services("prod").cloudtrail = trail
    out = _run(tools.cloudtrail_lookup_events(account="prod"))
    assert out == "No CloudTrail events matched the given filters."
    out = _run(tools.cloudwatch_list_log_groups(account="nope"))
    assert out.startswith("Error: No AWS account named 'nope'")


def test_ovh_account_level_tools_use_the_named_account(monkeypatch):
    registry, _ = build_registry(monkeypatch, ovh={"ovh": [], "eu2": []})
    tools = make_tools(registry)
    ip_service = MagicMock()

    async def _ips():
        return [{"ip": "1.1.1.1/32", "type": "failover"}]

    ip_service.list_ips = _ips
    registry.ovh_services("eu2").ip = ip_service
    assert "1.1.1.1/32" in _run(tools.ovh_list_ips(account="eu2"))


def _staging_storage(registry):
    from servonaut.config.schema import ObjectStorageConfig

    registry.config.hetzner.accounts[0].object_storage = ObjectStorageConfig(
        access_key="AKEXAMPLE", secret_key="secret", region="fsn1",
    )


def test_s3_tools_use_the_named_accounts_storage(monkeypatch):
    registry, _ = build_registry(monkeypatch, hetzner={"hetzner": [], "staging": []})
    _staging_storage(registry)
    tools = make_tools(registry)
    storage = registry.object_storage("hetzner", "staging")

    async def _buckets():
        return [{"name": "staging-assets", "creation_date": "2026-01-01"}]

    monkeypatch.setattr(storage, "list_buckets", _buckets)
    out = _run(tools.s3_list_buckets("hetzner", account="staging"))
    assert "staging-assets" in out
    assert audit_rows(tools)[-1][1] == {"provider": "hetzner", "account": "staging"}
    refused = _run(tools.s3_list_buckets("hetzner", account="prod"))
    assert refused.startswith("Error: No Hetzner account named 'prod'")
    assert audit_rows(tools)[-1][3].startswith("validation: unknown account")


def test_s3_storage_of_an_account_without_compute_credentials(monkeypatch):
    """Object storage keys work even when the project's API token does not."""
    registry, _ = build_registry(monkeypatch, hetzner={"hetzner": [], "staging": []})
    _staging_storage(registry)
    registry.config.hetzner.accounts[0].api_token = ""
    registry.rebuild(registry.config)
    assert [ref.label for ref in registry.accounts("hetzner")] == ["hetzner"]
    tools = make_tools(registry)
    storage = registry.object_storage("hetzner", "staging")
    assert storage is not None

    async def _buckets():
        return [{"name": "archive", "creation_date": "2026-01-01"}]

    monkeypatch.setattr(storage, "list_buckets", _buckets)
    assert "archive" in _run(tools.s3_list_buckets("hetzner", account="staging"))


def test_aws_call_label_and_account_id(monkeypatch):
    registry, _ = build_registry(
        monkeypatch, aws={"aws": [], "prod": []}, account_ids={"prod": "111122223333"},
    )
    tools = make_tools(registry)
    used = []

    class _Factory:
        def __init__(self, label):
            self.label = label

        def client(self, service, region="", account="", mutate=False):
            used.append((self.label, account))
            client = MagicMock()
            client.can_paginate.return_value = False
            client.describe_vpcs.return_value = {"Vpcs": []}
            return client

    monkeypatch.setattr(
        registry, "aws_client_factory", lambda label=None: _Factory(label or "aws"),
    )
    monkeypatch.setattr(tools, "_get_aws_factory", lambda: _Factory("default"))

    _run(tools.aws_call("ec2", "describe_vpcs", account="prod"))
    _run(tools.aws_call("ec2", "describe_vpcs", account="111122223333"))
    _run(tools.aws_call("ec2", "describe_vpcs", account="999999999999"))
    _run(tools.aws_call("ec2", "describe_vpcs"))
    assert used == [
        ("prod", ""), ("prod", "111122223333"),
        ("default", "999999999999"), ("default", ""),
    ]
    out = _run(tools.aws_call("ec2", "describe_vpcs", account="nope"))
    assert out.startswith("Error: No AWS account named 'nope'")


def _ip_ban_service(tools, registry):
    from servonaut.services.ip_ban_service import IPBanService

    return IPBanService(tools._config_manager, accounts=registry)


def test_ip_ban_configs_filtered_by_account(monkeypatch):
    from servonaut.config.schema import IPBanConfig

    registry, _ = build_registry(monkeypatch, aws={"aws": [], "prod": []})
    registry.config.ip_ban_configs = [
        IPBanConfig(name="main-waf", method="waf", ip_set_name="a"),
        IPBanConfig(name="prod-sg", method="security_group", security_group_id="sg-1",
                    account="prod"),
    ]
    tools = make_tools(registry)
    tools._ip_ban_service = _ip_ban_service(tools, registry)
    out = _run(tools.ip_ban_list_configs(account="prod"))
    assert "prod-sg" in out and "main-waf" not in out
    everything = _run(tools.ip_ban_list_configs())
    assert "Account" in everything and "prod-sg" in everything
    mismatch = _run(tools.ip_ban_list_banned("main-waf", account="prod"))
    assert "acts in AWS account 'aws'" in mismatch
    assert audit_rows(tools)[-1][3] == "validation: account_mismatch"


def _block_ip_tools(monkeypatch, site_account):
    """Tools with two AWS accounts, a ban config in each, and no WebACL."""
    from servonaut.config.schema import IPBanConfig

    registry, _ = build_registry(monkeypatch, aws={"aws": [], "prod": []})
    registry.config.ip_ban_configs = [
        IPBanConfig(name="waf-a", method="waf", ip_set_name="a"),
        IPBanConfig(name="waf-prod", method="waf", ip_set_name="p", account="prod"),
    ]
    tools = make_tools(registry)
    service = _ip_ban_service(tools, registry)
    banned = []

    async def _ban(ip, config_name):
        banned.append(config_name)
        return {"success": True, "message": "banned"}

    service.ban_ip = _ban
    tools._ip_ban_service = service
    acl = {"error": "no WebACL found"}
    if site_account is not None:
        acl["account"] = site_account

    async def _resolve(site, region="", account=""):
        return dict(acl)

    monkeypatch.setattr(tools, "_resolve_webacl", _resolve)
    return tools, banned


def test_block_ip_uses_a_ban_config_of_the_sites_account(monkeypatch):
    tools, banned = _block_ip_tools(monkeypatch, site_account="prod")
    out = _run(tools.block_ip("9.9.9.9", site="prod/shop"))
    assert "config 'waf-prod'" in out and banned == ["waf-prod"]


def test_block_ip_never_guesses_the_sites_account(monkeypatch):
    tools, banned = _block_ip_tools(monkeypatch, site_account=None)
    out = _run(tools.block_ip("9.9.9.9", site="gone-1"))
    assert "layer_used: host" in out and "AWS account is unknown" in out
    assert banned == []


def test_webacl_site_account_is_only_named_when_known(monkeypatch):
    from unittest.mock import patch

    registry, _ = build_registry(
        monkeypatch,
        aws={"aws": [], "prod": [{"id": "i-2", "name": "shop", "region": "eu-west-1"}]},
    )
    tools = make_tools(registry)

    class _Ingress:
        def __init__(self, account=None):
            pass

        async def describe(self, *args):
            return {"load_balancers": []}

    with patch("servonaut.services.ingress_path_service.IngressPathService", _Ingress):
        found = _run(tools._resolve_webacl("prod/shop"))
        missing = _run(tools._resolve_webacl("gone-1"))
        named = _run(tools._resolve_webacl("gone-1", account="prod"))
    assert found["account"] == "prod" and "error" in found
    assert "account" not in missing
    assert named["account"] == "prod"


def test_fleet_health_snapshot_account_filter(two_projects, monkeypatch):
    tools, _ = two_projects
    probed = []

    async def _exec(instance, command, timeout=60, audit_extras=None):
        probed.append(instance["id"])
        return "", ""

    monkeypatch.setattr(tools, "_exec_ssh", _exec)
    _run(tools.fleet_health_snapshot(account="staging"))
    assert sorted(probed) == ["2", "4"]


# ---------------------------------------------------------------------------
# Rebinding and wiring
# ---------------------------------------------------------------------------


def test_bind_accounts_rebinds_every_default_service(monkeypatch):
    registry, services = build_registry(monkeypatch, hetzner={"hetzner": []}, ovh={"ovh": []})
    tools = make_tools(registry)
    assert tools._hetzner_service is services[("hetzner", "hetzner")]
    assert tools._ovh_service is services[("ovh", "ovh")]
    assert tools._ovh_ip_service is registry.ovh_services().ip

    other, other_services = build_registry(monkeypatch, hetzner={"prod-h": []})
    tools.bind_accounts(other)
    assert tools.account_registry is other
    assert tools._hetzner_service is other_services[("hetzner", "prod-h")]
    assert tools._ovh_service is None and tools._ovh_ip_service is None


def test_account_argument_without_a_registry_accepts_only_the_primary():
    from servonaut.config.schema import AppConfig
    from tests.test_hetzner_tools import _make_tools

    tools = _make_tools(guard_level=GuardLevel.DANGEROUS, hetzner_service=MagicMock())
    tools._config_manager.get.return_value = AppConfig()

    async def _keys():
        return []

    tools._hetzner_service.list_ssh_keys = _keys
    assert "No SSH keys" in _run(tools.hetzner_list_ssh_keys(account="hetzner"))
    assert "No Hetzner account named 'x'" in _run(tools.hetzner_list_ssh_keys(account="x"))


def test_every_account_scoped_tool_accepts_account():
    """Schemas and handlers agree on the new argument."""
    for name, spec in TOOL_SCHEMAS.items():
        properties = spec["schema"].get("properties", {})
        handler = getattr(ServonautTools, name)
        params = inspect.signature(handler).parameters
        assert set(properties) <= set(params), name
        if "account" in params:
            assert properties["account"]["type"] == "string", name


def test_build_headless_tools_serves_the_registry(monkeypatch, tmp_path):
    from servonaut.mcp.server import build_headless_tools

    registry_config = build_registry(
        monkeypatch, hetzner={"hetzner": [], "staging": []},
    )[0].config
    config_manager = MagicMock()
    config_manager.get.return_value = registry_config
    registry_config.mcp.audit_path = str(tmp_path / "audit.jsonl")
    tools = build_headless_tools(config_manager)
    registry = tools.account_registry
    assert [ref.label for ref in registry.accounts("hetzner")] == ["hetzner", "staging"]
    assert tools._hetzner_service is registry.default_service("hetzner")
    assert tools._aws_service is registry.default_service("aws")
    assert tools._cloudwatch_service is registry.aws_services().cloudwatch
