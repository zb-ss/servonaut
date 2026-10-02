"""CLI commands across several accounts per provider."""
from __future__ import annotations

import argparse
import asyncio
import io
import json
import time
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.cli import hetzner as cli_hetzner
from servonaut.services.accounts import ACCOUNT_KEY, QUALIFIED_KEY
from servonaut.services.accounts.headless import CachedFleet
from tests._account_fixtures import build_registry


def _hetzner(id_, name, **extra):
    return {"id": id_, "name": name, "type": "cx22", "state": "running",
            "public_ip": "9.9.9.9", "region": "fsn1", "is_hetzner": True, **extra}


PROJECTS = {
    "hetzner": [_hetzner("1", "web-1")],
    "staging": [_hetzner("2", "web-1"), _hetzner("4", "worker")],
}


def _tagged_fleet(monkeypatch):
    registry, services = build_registry(monkeypatch, hetzner=PROJECTS)
    custom = MagicMock()
    custom.list_as_instances.return_value = []
    return CachedFleet.from_registry(registry, custom), registry, services


# ---------------------------------------------------------------------------
# servonaut ssh
# ---------------------------------------------------------------------------


def test_ssh_shared_name_lists_qualified_candidates(monkeypatch, capsys):
    from servonaut.cli import ssh as ssh_mod

    fleet, _, _ = _tagged_fleet(monkeypatch)
    headless = (MagicMock(), MagicMock(is_authenticated=False), None, None, None,
                MagicMock(), MagicMock())
    with patch.object(ssh_mod, "_init_headless_services", return_value=headless), \
         patch.object(ssh_mod, "_load_instances", return_value=fleet.instances()):
        rc = ssh_mod.handle_ssh_command(
            argparse.Namespace(instance="web-1", user=None, port=None, remote_command=[]),
        )
    err = capsys.readouterr().err
    assert rc == ssh_mod._EXIT_AMBIGUOUS
    assert "hetzner/web-1 (1, Hetzner)" in err and "staging/web-1 (2, Hetzner)" in err


# Two servers of one project sharing a name (an image rolled out twice).
TWIN_WORKERS = {
    "hetzner": [_hetzner("1", "web-1")],
    "staging": [_hetzner("4", "worker"), _hetzner("5", "worker")],
}


def test_ssh_suggests_ids_for_servers_of_one_account_sharing_a_name(monkeypatch, capsys):
    from servonaut.cli import ssh as ssh_mod

    registry, _ = build_registry(monkeypatch, hetzner=TWIN_WORKERS)
    custom = MagicMock()
    custom.list_as_instances.return_value = []
    rows = CachedFleet.from_registry(registry, custom).instances()
    headless = (registry.config, MagicMock(is_authenticated=False), None, None, None,
                MagicMock(), MagicMock())
    with patch.object(ssh_mod, "_init_headless_services", return_value=headless), \
         patch.object(ssh_mod, "_load_instances", return_value=rows):
        rc = ssh_mod.handle_ssh_command(
            argparse.Namespace(instance="staging/worker", user=None, port=None, remote_command=[]),
        )
    err = capsys.readouterr().err
    assert rc == ssh_mod._EXIT_AMBIGUOUS
    assert "1. 4 (Hetzner)" in err and "2. 5 (Hetzner)" in err
    assert "staging/worker (" not in err


def test_ssh_finds_a_qualified_reference(monkeypatch):
    from servonaut.cli import ssh as ssh_mod

    fleet, _, _ = _tagged_fleet(monkeypatch)
    assert [r["id"] for r in ssh_mod._find_instance(fleet.instances(), "staging/web-1")] == ["2"]


def test_ssh_loader_reads_every_account(monkeypatch):
    from servonaut.cli import ssh as ssh_mod

    registry, _ = build_registry(monkeypatch, hetzner=PROJECTS)
    custom = MagicMock()
    custom.list_as_instances.return_value = []
    rows = asyncio.run(ssh_mod._load_instances(custom, registry.config, "web-1"))
    ids = [r["id"] for r in rows]
    assert ids == ["1", "2", "4"]


# ---------------------------------------------------------------------------
# A project never listed on this machine: read once for name lookups
# ---------------------------------------------------------------------------


@pytest.fixture
def staging_never_listed(monkeypatch):
    """Project staging holds web-1 too, but has no cache: it was never listed here."""
    registry, services = build_registry(monkeypatch, hetzner=PROJECTS)
    services[("hetzner", "staging")].cached = None
    # Every command builds its fleet from the config; serve this registry's.
    monkeypatch.setattr(CachedFleet, "from_config", classmethod(
        lambda cls, config, custom, config_manager=None: cls.from_registry(registry, custom),
    ))
    return registry, services


def _failing(service, message):
    async def refused(force_refresh=False):
        raise RuntimeError(message)

    service.fetch_instances_cached = refused


STAGING_NOT_LISTED = (
    "Note: Hetzner project 'staging' could not be listed (401 Unauthorized); "
    "its servers were not checked for 'web-1'"
)


def test_ssh_refuses_a_name_a_never_listed_project_shares(staging_never_listed, capsys):
    from servonaut.cli import ssh as ssh_mod

    registry, services = staging_never_listed
    headless = (registry.config, MagicMock(is_authenticated=False), None, None, None,
                MagicMock(), MagicMock())
    with patch.object(ssh_mod, "_init_headless_services", return_value=headless):
        rc = ssh_mod.handle_ssh_command(
            argparse.Namespace(instance="web-1", user=None, port=None, remote_command=[]),
        )
    err = capsys.readouterr().err
    assert rc == ssh_mod._EXIT_AMBIGUOUS
    assert "hetzner/web-1 (1, Hetzner)" in err and "staging/web-1 (2, Hetzner)" in err
    assert services[("hetzner", "staging")].fetches == 1


def test_ssh_notes_a_project_that_cannot_be_listed(staging_never_listed, capsys):
    from servonaut.cli import ssh as ssh_mod

    registry, services = staging_never_listed
    _failing(services[("hetzner", "staging")], "401 Unauthorized")
    custom = MagicMock()
    custom.list_as_instances.return_value = []

    rows = asyncio.run(ssh_mod._load_instances(custom, registry.config, "web-1"))

    assert [row["id"] for row in ssh_mod._find_instance(rows, "web-1")] == ["1"]
    assert capsys.readouterr().err.strip() == STAGING_NOT_LISTED


def test_ssh_by_id_reads_no_project(staging_never_listed):
    from servonaut.cli import ssh as ssh_mod

    registry, services = staging_never_listed
    custom = MagicMock()
    custom.list_as_instances.return_value = []
    asyncio.run(ssh_mod._load_instances(custom, registry.config, "1"))
    asyncio.run(ssh_mod._load_instances(custom, registry.config, "hetzner/web-1"))
    assert all(service.fetches == 0 for service in services.values())


def test_servers_verify_refuses_a_name_a_never_listed_project_shares(
    staging_never_listed, monkeypatch, capsys,
):
    from servonaut.cli import servers as cli_servers

    registry, services = staging_never_listed
    config_manager = MagicMock()
    config_manager.get.return_value = registry.config
    custom = MagicMock()
    custom.list_as_instances.return_value = []
    services_tuple = (config_manager, MagicMock(is_authenticated=True), MagicMock(),
                      MagicMock(), MagicMock(), custom)
    monkeypatch.setattr(cli_servers, "_init_headless_services", lambda: services_tuple)
    rc = cli_servers.handle_servers_command(argparse.Namespace(
        servers_command="verify", instance="web-1", host=None, user=None,
        port=None, timeout=5,
    ))
    err = capsys.readouterr().err
    assert rc == cli_servers._EXIT_FATAL
    assert "hetzner/web-1" in err and "staging/web-1" in err
    assert services[("hetzner", "staging")].fetches == 1


@pytest.mark.parametrize("use_json", [False, True])
def test_memory_refuses_a_name_a_never_listed_project_shares(staging_never_listed, monkeypatch,
                                                             capsys, use_json):
    from servonaut.cli import memory as mem_mod

    registry, services = staging_never_listed
    custom = MagicMock()
    custom.list_as_instances.return_value = []
    fleet = CachedFleet.from_registry(registry, custom)
    monkeypatch.setattr(
        mem_mod, "_init_headless_services", lambda: (registry.config, MagicMock(), fleet),
    )
    monkeypatch.setattr(mem_mod, "_init_headless_sync_services", lambda *a: (None, None))
    rc = mem_mod.run_memory(
        argparse.Namespace(memory_command="show", instance="web-1", json=use_json),
    )
    out = capsys.readouterr()
    assert rc == mem_mod._EXIT_USAGE_ERROR
    if use_json:
        assert json.loads(out.out)["error"]["candidates"] == ["hetzner/web-1", "staging/web-1"]
    else:
        assert "hetzner/web-1" in out.err and "staging/web-1" in out.err
    assert services[("hetzner", "staging")].fetches == 1


def test_memory_notes_a_project_that_cannot_be_listed(staging_never_listed, capsys):
    from servonaut.cli import memory as mem_mod

    registry, services = staging_never_listed
    _failing(services[("hetzner", "staging")], "401 Unauthorized")
    custom = MagicMock()
    custom.list_as_instances.return_value = []
    fleet = CachedFleet.from_registry(registry, custom)

    inst = mem_mod._resolve_or_exit(argparse.Namespace(instance="web-1"), fleet, use_json=True)

    assert inst["id"] == "1"
    out = capsys.readouterr()
    assert out.err.strip() == STAGING_NOT_LISTED and out.out == ""


def _slow_staging(services, count=5, seconds=1.0):
    """staging's listing: *count* blocking requests of *seconds* each (threads)."""
    staging = services[("hetzner", "staging")]

    def requests():
        for _ in range(count):
            time.sleep(seconds)

    async def listing(force_refresh=False):
        # One blocking call, as an SDK pages: cancelling cannot stop it.
        await asyncio.to_thread(requests)
        return [dict(row) for row in staging.rows]

    staging.fetch_instances_cached = listing


def _within_budget(run) -> float:
    begin = time.monotonic()
    run()
    return time.monotonic() - begin


@pytest.mark.parametrize("command", ["ssh", "servers verify", "memory"])
def test_each_command_returns_within_the_budget(staging_never_listed, monkeypatch, capsys,
                                                command):
    """A project whose API answers slowly, request after request, costs the budget only."""
    from servonaut.cli import memory as mem_mod
    from servonaut.cli import servers as cli_servers
    from servonaut.cli import ssh as ssh_mod

    registry, services = staging_never_listed
    _slow_staging(services)
    registry.config.account_check_timeout_seconds = 1.5
    custom = MagicMock()
    custom.list_as_instances.return_value = []
    runs = {
        "ssh": lambda: asyncio.run(ssh_mod._load_instances(custom, registry.config, "web-1")),
        "servers verify": lambda: asyncio.run(
            cli_servers._load_all_instances(registry.config, custom, "web-1"),
        ),
        "memory": lambda: mem_mod._resolve_or_exit(
            argparse.Namespace(instance="worker"), CachedFleet.from_registry(registry, custom),
        ),
    }

    elapsed = _within_budget(runs[command])

    assert elapsed < 1.5 + 0.7, elapsed
    assert "could not be listed (timed out after 1.5 s)" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# servonaut servers verify
# ---------------------------------------------------------------------------


def test_servers_verify_refuses_a_shared_name(monkeypatch, capsys):
    from servonaut.cli import servers as cli_servers

    fleet, _, _ = _tagged_fleet(monkeypatch)
    services = (MagicMock(), MagicMock(is_authenticated=True), MagicMock(),
                MagicMock(), MagicMock(), MagicMock())
    monkeypatch.setattr(cli_servers, "_init_headless_services", lambda: services)
    with patch("servonaut.cli.servers._load_all_instances", return_value=fleet.instances()):
        rc = cli_servers.handle_servers_command(argparse.Namespace(
            servers_command="verify", instance="web-1", host=None, user=None,
            port=None, timeout=5,
        ))
    assert rc == cli_servers._EXIT_FATAL
    assert "staging/web-1" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# OVH logins: each account's username and key
# ---------------------------------------------------------------------------


def _ovh(id_, name):
    return {"id": id_, "name": name, "type": "vps-starter", "state": "running",
            "public_ip": "8.8.4.4", "region": "gra", "provider": "ovh",
            "provider_type": "vps", "is_ovh": True}


@pytest.fixture
def ovh_logins(monkeypatch, tmp_path):
    """Two OVH accounts that each log in with their own user and key."""
    registry, _ = build_registry(monkeypatch, ovh={
        "ovh": [_ovh("vps-a.vps.ovh.net", "web-1")],
        "backup": [_ovh("vps-b.vps.ovh.net", "web-1")],
    })
    keys = {label: tmp_path / f"{label}_ed25519" for label in ("ovh", "backup")}
    for key in keys.values():
        key.write_text("private key")
    config = registry.config
    config.ovh.default_username, config.ovh.default_ssh_key = "ubuntu", str(keys["ovh"])
    backup = config.ovh.accounts[0]
    backup.default_username, backup.default_ssh_key = "debian", str(keys["backup"])
    custom = MagicMock()
    custom.list_as_instances.return_value = []
    return config, CachedFleet.from_registry(registry, custom).instances(), keys


@pytest.mark.parametrize("reference, user, expected_user, account", [
    ("backup/web-1", None, "debian", "backup"),
    ("ovh/web-1", None, "ubuntu", "ovh"),
    ("backup/web-1", "root", "root", "backup"),
])
def test_ssh_logs_in_to_an_ovh_server_as_its_account_says(
    ovh_logins, reference, user, expected_user, account,
):
    from servonaut.cli import ssh as ssh_mod

    config, rows, keys = ovh_logins
    ssh_service = MagicMock()
    ssh_service.build_ssh_command.return_value = ["ssh"]
    headless = (config, MagicMock(is_authenticated=False), None, None, None,
                ssh_service, MagicMock())
    with patch.object(ssh_mod, "_init_headless_services", return_value=headless), \
         patch.object(ssh_mod, "_load_instances", return_value=rows), \
         patch.object(ssh_mod.subprocess, "run", return_value=MagicMock(returncode=0)):
        rc = ssh_mod.handle_ssh_command(argparse.Namespace(
            instance=reference, user=user, port=None, remote_command=[],
        ))
    assert rc == 0
    call = ssh_service.build_ssh_command.call_args.kwargs
    assert (call["username"], call["key_path"]) == (expected_user, str(keys[account]))


def test_servers_verify_probes_an_ovh_server_as_its_accounts_user(ovh_logins, monkeypatch):
    from servonaut.cli import servers as cli_servers

    config, rows, _ = ovh_logins
    config_manager = MagicMock()
    config_manager.get.return_value = config
    services = (config_manager, MagicMock(is_authenticated=True), MagicMock(),
                MagicMock(), MagicMock(), MagicMock())
    monkeypatch.setattr(cli_servers, "_init_headless_services", lambda: services)
    probe = AsyncMock(return_value=None)
    monkeypatch.setattr(cli_servers, "_probe_personal", probe)
    with patch("servonaut.cli.servers._load_all_instances", return_value=rows):
        cli_servers.handle_servers_command(argparse.Namespace(
            servers_command="verify", instance="backup/web-1", host=None, user=None,
            port=None, timeout=5,
        ))
    _bw, _resolver, instance, host, user = probe.call_args.args[:5]
    assert (instance["id"], host, user) == ("vps-b.vps.ovh.net", "8.8.4.4", "debian")


def test_only_ovh_rows_take_an_account_login(ovh_logins):
    from servonaut.services.accounts.headless import with_ovh_login

    config, rows, _ = ovh_logins
    hetzner = _hetzner("1", "web-1")
    assert with_ovh_login(hetzner, config) is hetzner
    named = dict(rows[1], username="admin")
    assert with_ovh_login(named, config)["username"] == "admin"
    assert "username" not in rows[1]


# ---------------------------------------------------------------------------
# servonaut memory
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("use_json", [False, True])
def test_memory_shared_name_exits_with_candidates(monkeypatch, capsys, use_json):
    from servonaut.cli import memory as mem_mod

    fleet, registry, _ = _tagged_fleet(monkeypatch)
    monkeypatch.setattr(
        mem_mod, "_init_headless_services", lambda: (registry.config, MagicMock(), fleet),
    )
    monkeypatch.setattr(mem_mod, "_init_headless_sync_services", lambda *a: (None, None))
    args = argparse.Namespace(memory_command="show", instance="web-1", json=use_json)
    rc = mem_mod.run_memory(args)
    out = capsys.readouterr()
    assert rc == mem_mod._EXIT_USAGE_ERROR
    if use_json:
        error = json.loads(out.out)["error"]
        assert error["code"] == "ambiguous"
        assert error["candidates"] == ["hetzner/web-1", "staging/web-1"]
    else:
        assert "staging/web-1" in out.err


def test_memory_json_candidates_are_distinct_references(monkeypatch, capsys):
    from servonaut.cli import memory as mem_mod

    registry, _ = build_registry(monkeypatch, hetzner=TWIN_WORKERS)
    custom = MagicMock()
    custom.list_as_instances.return_value = []
    fleet = CachedFleet.from_registry(registry, custom)
    monkeypatch.setattr(
        mem_mod, "_init_headless_services", lambda: (registry.config, MagicMock(), fleet),
    )
    monkeypatch.setattr(mem_mod, "_init_headless_sync_services", lambda *a: (None, None))
    rc = mem_mod.run_memory(
        argparse.Namespace(memory_command="show", instance="worker", json=True),
    )
    assert rc == mem_mod._EXIT_USAGE_ERROR
    assert json.loads(capsys.readouterr().out)["error"]["candidates"] == ["4", "5"]


# ---------------------------------------------------------------------------
# servonaut db setup
# ---------------------------------------------------------------------------


def test_db_setup_tools_serve_every_account(monkeypatch):
    from servonaut.cli import db as cli_db

    registry, services = build_registry(monkeypatch, hetzner=PROJECTS)
    config_manager = MagicMock()
    config_manager.get.return_value = registry.config
    monkeypatch.setattr("servonaut.config.manager.ConfigManager", lambda: config_manager)
    tools, _ = cli_db._build_tools()
    labels = [ref.label for ref in tools.account_registry.accounts("hetzner")]
    assert labels == ["hetzner", "staging"]
    assert tools._hetzner_service is tools.account_registry.default_service("hetzner")


# ---------------------------------------------------------------------------
# servonaut hetzner --account
# ---------------------------------------------------------------------------


def _parser():
    parser = argparse.ArgumentParser(prog="servonaut")
    cli_hetzner.add_hetzner_parser(parser.add_subparsers(dest="subcommand"))
    return parser


def _cli(argv, stdin=None):
    args = _parser().parse_args(["hetzner", *argv])
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        if stdin is not None:
            with patch("builtins.input", side_effect=stdin):
                rc = cli_hetzner.handle_hetzner_command(args)
        else:
            rc = cli_hetzner.handle_hetzner_command(args)
    return rc, out.getvalue(), err.getvalue()


@pytest.fixture
def projects(monkeypatch):
    registry, services = build_registry(monkeypatch, hetzner=PROJECTS)
    monkeypatch.setattr(cli_hetzner, "_hetzner_registry", lambda: registry)
    return registry, services


def test_every_subcommand_takes_account():
    parser = _parser()
    for argv in (["list"], ["create", "web-9"], ["destroy", "web-1"],
                 ["ssh-keys", "list"], ["ssh-keys", "add", "k", "--public-key", "ssh-ed25519 X"],
                 ["server-types"], ["test-connection"]):
        args = parser.parse_args(["hetzner", *argv, "--account", "staging"])
        assert args.account == "staging", argv


def test_list_shows_every_project_with_an_account_column(projects):
    rc, out, _ = _cli(["list"])
    assert rc == 0
    assert "Account" in out
    assert "hetzner/web-1" in out and "staging/web-1" in out and "staging/worker" in out


def test_list_json_rows_carry_their_account(projects):
    rc, out, _ = _cli(["list", "--json"])
    rows = json.loads(out)
    assert [(r["id"], r[ACCOUNT_KEY]) for r in rows] == [
        ("1", "hetzner"), ("2", "staging"), ("4", "staging"),
    ]
    assert all(QUALIFIED_KEY not in r for r in rows)


def test_list_one_project(projects):
    rc, out, _ = _cli(["list", "--account", "staging", "--json"])
    assert [r["id"] for r in json.loads(out)] == ["2", "4"]
    _, services = projects
    assert services[("hetzner", "hetzner")].fetches == 0


def test_list_unknown_project(projects):
    rc, _, err = _cli(["list", "--account", "nope"])
    assert rc == cli_hetzner._EXIT_VALIDATION
    assert "No Hetzner account named 'nope'" in err and "staging" in err


def test_single_project_list_is_unchanged(monkeypatch):
    registry, _ = build_registry(monkeypatch, hetzner={"hetzner": [_hetzner("1", "web-1")]})
    monkeypatch.setattr(cli_hetzner, "_hetzner_registry", lambda: registry)
    rc, out, _ = _cli(["list"])
    assert "Account" not in out and "hetzner/web-1" not in out
    assert "  web-1 " in out


def test_destroy_in_the_project_that_lists_the_server(projects):
    _, services = projects
    rc, out, _ = _cli(["destroy", "worker"], stdin=["worker"])
    assert rc == 0
    assert "(project staging)" in out
    assert services[("hetzner", "staging")].called("delete_server") == [("worker",)]


def test_destroy_qualified(projects):
    _, services = projects
    rc, _, _ = _cli(["destroy", "staging/web-1", "--yes"])
    assert rc == 0
    assert services[("hetzner", "staging")].called("delete_server") == [("web-1",)]
    assert services[("hetzner", "hetzner")].called("delete_server") == []


def test_destroy_a_name_two_projects_use_is_refused(projects):
    _, services = projects
    rc, _, err = _cli(["destroy", "web-1", "--yes"])
    assert rc == cli_hetzner._EXIT_VALIDATION
    assert "hetzner/web-1" in err and "staging/web-1" in err
    assert all(not s.called("delete_server") for s in services.values())


def test_account_level_subcommands_use_the_named_project(projects):
    _, services = projects
    services[("hetzner", "staging")].returns["list_ssh_keys"] = [
        {"name": "deploy", "id": 7, "fingerprint": "aa"},
    ]
    rc, out, _ = _cli(["ssh-keys", "list", "--account", "staging"])
    assert rc == 0 and "deploy" in out
    assert services[("hetzner", "hetzner")].called("list_ssh_keys") == []


def test_unknown_account_without_configured_projects(monkeypatch, capsys):
    monkeypatch.setattr(cli_hetzner, "_hetzner_registry", lambda: None)
    args = _parser().parse_args(["hetzner", "server-types", "--account", "staging"])
    # Like "not configured", the service builder exits with its code.
    with pytest.raises(SystemExit) as exit_info:
        cli_hetzner.handle_hetzner_command(args)
    assert exit_info.value.code == cli_hetzner._EXIT_VALIDATION
    assert "No Hetzner account named 'staging'" in capsys.readouterr().err


def test_destroy_a_server_no_project_lists_is_refused(projects):
    _, services = projects
    rc, _, err = _cli(["destroy", "ghost", "--yes"])
    assert rc == cli_hetzner._EXIT_GENERIC_ERROR
    assert "No Hetzner server 'ghost' in any account (hetzner, staging)." in err
    assert "--account" in err
    assert all(not s.called("delete_server") for s in services.values())


# ---------------------------------------------------------------------------
# The primary project cannot be used, the second one can
# ---------------------------------------------------------------------------


@pytest.fixture
def primary_down(monkeypatch):
    registry, services = build_registry(monkeypatch, hetzner=PROJECTS, unusable={"hetzner"})
    monkeypatch.setattr(cli_hetzner, "_hetzner_registry", lambda: registry)
    return registry, services


def test_a_subcommand_without_account_gets_the_registrys_reason(primary_down, capsys):
    args = _parser().parse_args(["hetzner", "server-types"])
    with pytest.raises(SystemExit) as exit_info:
        cli_hetzner.handle_hetzner_command(args)
    assert exit_info.value.code == cli_hetzner._EXIT_VALIDATION
    err = capsys.readouterr().err
    assert "The primary Hetzner account 'hetzner' is not available" in err
    assert "staging" in err


def test_the_second_project_still_serves_while_the_primary_is_down(primary_down):
    _, services = primary_down
    services[("hetzner", "staging")].returns["list_server_types"] = []
    rc, _, _ = _cli(["server-types", "--account", "staging"])
    assert rc == 0
    rc, out, err = _cli(["list"])
    assert rc == 0
    assert "staging/worker" in out
    assert "Warning: some projects were not listed: hetzner: not available" in err
    rc, _, _ = _cli(["destroy", "worker", "--yes"])
    assert rc == 0
    assert services[("hetzner", "staging")].called("delete_server") == [("worker",)]


# ---------------------------------------------------------------------------
# A reference to a project that cannot connect
# ---------------------------------------------------------------------------

STAGING_DOWN = (
    "Hetzner account 'staging' is not available: No Hetzner Cloud API token configured"
)


@pytest.fixture
def staging_down(monkeypatch):
    registry, services = build_registry(monkeypatch, hetzner=PROJECTS, unusable={"staging"})
    monkeypatch.setattr(cli_hetzner, "_hetzner_registry", lambda: registry)
    custom = MagicMock()
    custom.list_as_instances.return_value = []
    return registry, CachedFleet.from_registry(registry, custom)


def test_ssh_to_a_project_that_cannot_connect_says_why(staging_down, capsys):
    from servonaut.cli import ssh as ssh_mod

    registry, fleet = staging_down
    headless = (registry.config, MagicMock(is_authenticated=False), None, None, None,
                MagicMock(), MagicMock())
    with patch.object(ssh_mod, "_init_headless_services", return_value=headless), \
         patch.object(ssh_mod, "_load_instances", return_value=fleet.instances()):
        rc = ssh_mod.handle_ssh_command(argparse.Namespace(
            instance="staging/web-1", user=None, port=None, remote_command=[],
        ))
    assert rc == ssh_mod._EXIT_NOT_FOUND
    assert STAGING_DOWN in capsys.readouterr().err


def test_servers_verify_on_a_project_that_cannot_connect_says_why(staging_down, monkeypatch,
                                                                   capsys):
    from servonaut.cli import servers as cli_servers

    registry, fleet = staging_down
    config_manager = MagicMock()
    config_manager.get.return_value = registry.config
    services = (config_manager, MagicMock(is_authenticated=True), MagicMock(),
                MagicMock(), MagicMock(), MagicMock())
    monkeypatch.setattr(cli_servers, "_init_headless_services", lambda: services)
    with patch("servonaut.cli.servers._load_all_instances", return_value=fleet.instances()):
        rc = cli_servers.handle_servers_command(argparse.Namespace(
            servers_command="verify", instance="staging/web-1", host=None, user=None,
            port=None, timeout=5,
        ))
    assert rc == cli_servers._EXIT_FATAL
    assert STAGING_DOWN in capsys.readouterr().err


@pytest.mark.parametrize("use_json", [False, True])
def test_memory_on_a_project_that_cannot_connect_says_why(staging_down, monkeypatch, capsys,
                                                          use_json):
    from servonaut.cli import memory as mem_mod

    registry, fleet = staging_down
    monkeypatch.setattr(
        mem_mod, "_init_headless_services", lambda: (registry.config, MagicMock(), fleet),
    )
    monkeypatch.setattr(mem_mod, "_init_headless_sync_services", lambda *a: (None, None))
    rc = mem_mod.run_memory(
        argparse.Namespace(memory_command="show", instance="staging/web-1", json=use_json),
    )
    out = capsys.readouterr()
    assert rc == mem_mod._EXIT_NOT_FOUND
    if use_json:
        error = json.loads(out.out)["error"]
        assert (error["code"], error["message"]) == ("account_unavailable", STAGING_DOWN)
    else:
        assert STAGING_DOWN in out.err


@pytest.mark.parametrize("argv", [
    ["list", "--account", "staging"],
    ["destroy", "staging/web-1", "--yes"],
])
def test_hetzner_commands_on_a_project_that_cannot_connect_say_why(staging_down, argv, capsys):
    try:
        rc, _, err = _cli(argv)
    except SystemExit as exit_info:
        rc, err = exit_info.code, capsys.readouterr().err
    assert rc == cli_hetzner._EXIT_VALIDATION
    assert STAGING_DOWN in err
