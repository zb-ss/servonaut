"""CLI commands across several accounts per provider."""
from __future__ import annotations

import argparse
import io
import json
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


def test_ssh_finds_a_qualified_reference(monkeypatch):
    from servonaut.cli import ssh as ssh_mod

    fleet, _, _ = _tagged_fleet(monkeypatch)
    assert [r["id"] for r in ssh_mod._find_instance(fleet.instances(), "staging/web-1")] == ["2"]


def test_ssh_loader_reads_every_account(monkeypatch):
    from servonaut.cli import ssh as ssh_mod

    registry, _ = build_registry(monkeypatch, hetzner=PROJECTS)
    custom = MagicMock()
    custom.list_as_instances.return_value = []
    ids = [r["id"] for r in ssh_mod._load_instances(custom, registry.config)]
    assert ids == ["1", "2", "4"]


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
