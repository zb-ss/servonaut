"""CLI boundaries for naming and safely removing vault SSH keys."""
from __future__ import annotations

import argparse
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.cli import vault
from servonaut.services.vault.errors import VaultUserError

VAULT_ID = "11111111-1111-4111-8111-111111111111"  # synthetic fixture  leak-guard:allow


def _run(*argv: str) -> int:
    parser = argparse.ArgumentParser()
    vault.add_vault_parser(parser.add_subparsers(dest="subcommand"))
    return vault.handle_vault_command(parser.parse_args(["vault", *argv]))


@pytest.fixture
def service(monkeypatch):
    service = SimpleNamespace(
        list_items=AsyncMock(return_value={"data": [
            {"item_id": "key", "type": "ssh_key", "revision": 1},
            {"item_id": "token", "type": "secret", "revision": 1},
        ], "meta": {"next_cursor": None}}),
        ssh_key_choices=AsyncMock(return_value=[{"item_id": "key", "name": "web-1\u202e\n", "fingerprint": "SHA256:key"}]),
        ssh_key_usage=AsyncMock(return_value={"team_servers": [], "own_servers": [], "unchecked": [], "checked": 1,
                                              "name": "web-1\u202e\n", "fingerprint": "SHA256:key"}),
        delete_ssh_key=AsyncMock(return_value={"item_id": "key", "deleted": True}),
        rename_ssh_key=AsyncMock(return_value={"item_id": "key", "name": "app-1", "revision": 2}),
        import_keys=AsyncMock(return_value={"item_id": "key"}), close=MagicMock(),
    )
    monkeypatch.setattr(vault, "_services", lambda: service)
    monkeypatch.setattr(vault, "_auto_bind_servers", lambda: [{"id": "i-1", "name": "web-1"}])
    return service


@pytest.mark.parametrize("override, expected", [(None, "ops-key"), ("custom", "custom")])
def test_bitwarden_import_passes_the_item_name_or_override(service, monkeypatch, capsys, override, expected) -> None:
    resolve = MagicMock(return_value=("opaque", "ops-key"))
    monkeypatch.setattr("servonaut.services.bw_resolver.BwResolver.resolve_ssh_item", resolve)
    captured = {}
    async def imported(**kwargs):
        captured.update({**kwargs, "private_key": bytes(kwargs["private_key"])})
        return {"item_id": "key"}
    service.import_keys.side_effect = imported
    extra = ["--name", override] if override is not None else []
    assert _run("import", "bitwarden", "--vault", VAULT_ID, "--item", "bw-item", *extra) == 0
    assert captured["name"] == expected
    assert captured["private_key"] == b"opaque"
    assert captured["source_ref"] == "bw-item"
    resolve.assert_called_once_with("bw-item")
    assert "opaque" not in capsys.readouterr().out


def test_file_import_passes_the_optional_name(service, monkeypatch) -> None:
    monkeypatch.setattr(vault, "_read_import_key", lambda _: bytearray(b"opaque"))
    assert _run("import", "ssh", "--vault", VAULT_ID, "--path", "web.pem", "--name", "web-1") == 0
    assert service.import_keys.call_args.kwargs["name"] == "web-1"


def test_items_without_names_stays_metadata_only(service, capsys) -> None:
    assert _run("items", "--vault", VAULT_ID, "--json") == 0
    assert "name" not in json.loads(capsys.readouterr().out)["data"][0]
    service.ssh_key_choices.assert_not_awaited()


def test_items_names_are_local_and_terminal_safe(service, capsys) -> None:
    assert _run("items", "--vault", VAULT_ID, "--names", "--json") == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["data"][0]["name"] == "web-1"
    assert "name" not in listed["data"][1]
    service.ssh_key_choices.assert_awaited_once_with(vault_id=VAULT_ID, name_limit=None)


def test_rename_dispatches_and_returns_revision(service, capsys) -> None:
    assert _run("rename", "key", "--vault", VAULT_ID, "--name", "app-1", "--json") == 0
    service.rename_ssh_key.assert_awaited_once_with(vault_id=VAULT_ID, item_id="key", name="app-1")
    assert json.loads(capsys.readouterr().out) == {"item_id": "key", "name": "app-1", "revision": 2}


def test_delete_yes_checks_servers_and_explains_what_remains(service, capsys) -> None:
    assert _run("delete", "key", "--vault", VAULT_ID, "--yes", "--json") == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == {"item_id": "key", "deleted": True}
    assert "Vault key: web-1 (SHA256:key)" in output.err
    assert "vault only" in output.err and "authorized_keys" in output.err
    assert "\u202e" not in output.err
    service.ssh_key_choices.assert_not_awaited()
    service.delete_ssh_key.assert_awaited_once_with(
        vault_id=VAULT_ID, item_id="key", servers=[{"id": "i-1", "name": "web-1"}],
    )


@pytest.mark.parametrize("interactive, answer, expected", [(False, "", 5), (True, "n\n", 5), (True, "y\n", 0)])
def test_delete_requires_explicit_confirmation(service, monkeypatch, capsys, interactive, answer, expected) -> None:
    monkeypatch.setattr(vault.sys.stdin, "isatty", lambda: interactive)
    monkeypatch.setattr(vault.sys.stdin, "readline", lambda: answer)
    assert _run("delete", "key", "--vault", VAULT_ID) == expected
    assert service.delete_ssh_key.await_count == (1 if expected == 0 else 0)
    if not interactive:
        assert "Refusing in a non-interactive shell without --yes" in capsys.readouterr().err


@pytest.mark.parametrize("field, label", [("team_servers", "Team servers"), ("own_servers", "Your servers"), ("unchecked", "Could not check")])
def test_delete_refuses_and_names_in_use_or_unchecked_servers(service, capsys, field, label) -> None:
    service.ssh_key_usage.return_value[field] = ["db-1\x1b\u202e\n"]
    assert _run("delete", "key", "--vault", VAULT_ID, "--yes") == 1
    error = capsys.readouterr().err
    assert f"{label}: db-1" in error
    assert ("hosts do not need to be running" if field == "unchecked" else "another vault key") in error
    assert "\x1b" not in error and "\u202e" not in error
    service.delete_ssh_key.assert_not_awaited()


def test_delete_rechecks_can_refuse_a_new_binding_after_confirmation(service, capsys) -> None:
    from servonaut.services.vault.errors import VaultKeyInUse

    service.delete_ssh_key.side_effect = VaultKeyInUse(team_servers=["web-2"], own_servers=[], unchecked=[])
    assert _run("delete", "key", "--vault", VAULT_ID, "--yes") == 1
    assert "Team servers: web-2" in capsys.readouterr().err


def test_delete_reports_exposure_refusal(service, capsys) -> None:
    service.delete_ssh_key.side_effect = VaultUserError("resolve or rotate its open exposures first")
    assert _run("delete", "key", "--vault", VAULT_ID, "--yes") == 1
    assert "resolve or rotate its open exposures first" in capsys.readouterr().err


def test_delete_refuses_an_item_that_is_not_an_active_key(service, capsys) -> None:
    service.ssh_key_usage.side_effect = VaultUserError("this item is not an active SSH key in the vault")
    assert _run("delete", "token", "--vault", VAULT_ID, "--yes") == 1
    assert "not an active SSH key" in capsys.readouterr().err
    service.delete_ssh_key.assert_not_awaited()


def test_rename_human_output_is_a_terminal_safe_sentence(service, capsys) -> None:
    service.rename_ssh_key.return_value["name"] = "app-1\u202e\n"
    assert _run("rename", "key", "--vault", VAULT_ID, "--name", "app-1") == 0
    assert capsys.readouterr().out == "Renamed the key to app-1.\n"


def test_items_with_an_unavailable_name_shows_null(service, capsys) -> None:
    service.ssh_key_choices.return_value = []
    assert _run("items", "--vault", VAULT_ID, "--names", "--json") == 0
    assert json.loads(capsys.readouterr().out)["data"][0]["name"] is None


def test_bitwarden_import_reports_unreadable_material_without_raw_exception(service, monkeypatch, capsys) -> None:
    from servonaut.services.vault.command_service import VaultCommandService

    core = VaultCommandService.__new__(VaultCommandService)
    core.items = SimpleNamespace(write_item=AsyncMock())
    service.import_keys = core.import_keys
    monkeypatch.setattr("servonaut.services.bw_resolver.BwResolver.resolve_ssh_item",
                        MagicMock(return_value=("unreadable key material", "web-1")))
    assert _run("import", "bitwarden", "--vault", VAULT_ID, "--item", "bw-item") == 1
    output = capsys.readouterr()
    assert "this is not an SSH private key Servonaut can read: it must be an OpenSSH private key, unlocked or with its passphrase" in output.err
    assert "ValueError" not in output.err
    assert "unreadable key material" not in output.out + output.err
    core.items.write_item.assert_not_awaited()


_UUID = "22222222-2222-4222-8222-222222222222"  # synthetic fixture  leak-guard:allow


def _in_use(service, *, can_unbind: bool, **fields) -> None:
    usage = service.ssh_key_usage.return_value
    usage.update({"team_servers": ["site-1"], "team_server_ids": ["s1"], "own_servers": [], "unchecked": [],
                  "can_unbind": can_unbind, **fields})


@pytest.mark.parametrize("can_unbind", [True, False])
def test_delete_in_use_without_unbind_prints_usage_and_hint_only_when_possible(service, capsys, can_unbind) -> None:
    _in_use(service, can_unbind=can_unbind, other_members={"members": 2, "servers": 3})
    assert _run("delete", "key", "--vault", VAULT_ID, "--yes") == 1
    error = capsys.readouterr().err
    assert "Team servers: site-1" in error
    assert "Other members: 3 server(s) of 2 member(s)" in error
    assert ("Pass --unbind" in error) is can_unbind
    service.delete_ssh_key.assert_not_awaited()


def test_delete_unbind_passes_the_flag_when_available(service, capsys) -> None:
    _in_use(service, can_unbind=True)
    assert _run("delete", "key", "--vault", VAULT_ID, "--unbind", "--yes") == 0
    shown = {"team_servers": ["site-1"], "own_servers": [], "unchecked": [], "unchecked_targets": [],
             "team_server_ids": ["s1"], "own_targets": [], "other_members": {"members": 0, "servers": 0},
             "can_unbind": True}
    service.delete_ssh_key.assert_awaited_once_with(
        vault_id=VAULT_ID, item_id="key", servers=[{"id": "i-1", "name": "web-1"}], unbind=True,
        confirmed_usage=shown,
    )
    error = capsys.readouterr().err
    assert "Team servers: site-1" in error and "for every member" in error


def test_delete_unbind_unavailable_refuses_without_delete(service, capsys) -> None:
    _in_use(service, can_unbind=False)
    assert _run("delete", "key", "--vault", VAULT_ID, "--unbind", "--yes") == 1
    error = capsys.readouterr().err
    assert "unbinding while deleting is not available" in error
    # The servers to move are listed before the error.
    assert error.index("Team servers: site-1") < error.index("unbinding while deleting is not available")
    service.delete_ssh_key.assert_not_awaited()


@pytest.mark.parametrize("can_unbind", [True, False])
def test_delete_unbind_on_an_unused_key_is_a_plain_delete(service, can_unbind) -> None:
    service.ssh_key_usage.return_value["can_unbind"] = can_unbind
    assert _run("delete", "key", "--vault", VAULT_ID, "--unbind", "--yes") == 0
    service.delete_ssh_key.assert_awaited_once_with(
        vault_id=VAULT_ID, item_id="key", servers=[{"id": "i-1", "name": "web-1"}],
    )


def _bound_since_review(service, *, can_unbind: bool = True) -> None:
    from servonaut.services.vault.errors import VaultKeyInUse

    refusal = VaultKeyInUse(team_servers=["site-1"], own_servers=[], unchecked=[], can_unbind=can_unbind)
    service.delete_ssh_key.side_effect = [refusal, {"item_id": "key", "deleted": True}]


def test_delete_unbind_retries_after_a_refusal_once_confirmed(service, capsys) -> None:
    _bound_since_review(service)
    assert _run("delete", "key", "--vault", VAULT_ID, "--unbind", "--yes") == 0
    calls = service.delete_ssh_key.await_args_list
    assert ["unbind" in call.kwargs for call in calls] == [False, True]
    error = capsys.readouterr().err
    assert "Team servers: site-1" in error and "for every member" in error


def test_delete_unbind_retry_asks_before_unbinding(service, monkeypatch, capsys) -> None:
    _bound_since_review(service)
    answers = iter(["y\n", "n\n"])
    monkeypatch.setattr(vault.sys, "stdin", SimpleNamespace(isatty=lambda: True, readline=lambda: next(answers)))
    assert _run("delete", "key", "--vault", VAULT_ID, "--unbind") == 5
    assert service.delete_ssh_key.await_count == 1
    assert "Unbind this key everywhere and delete it [y/N]" in capsys.readouterr().err


def test_delete_with_the_flag_given_never_hints_to_pass_it(service, capsys) -> None:
    _bound_since_review(service, can_unbind=False)
    assert _run("delete", "key", "--vault", VAULT_ID, "--unbind", "--yes") == 1
    assert "Pass --unbind" not in capsys.readouterr().err


def test_delete_unbind_still_refuses_unchecked_servers(service, capsys) -> None:
    _in_use(service, can_unbind=True, team_servers=[], unchecked=["db-1"])
    assert _run("delete", "key", "--vault", VAULT_ID, "--unbind", "--yes") == 1
    assert "Could not check: db-1" in capsys.readouterr().err
    service.delete_ssh_key.assert_not_awaited()


def test_delete_unbind_needs_confirmation_non_interactively(service, monkeypatch, capsys) -> None:
    _in_use(service, can_unbind=True)
    monkeypatch.setattr(vault.sys.stdin, "isatty", lambda: False)
    assert _run("delete", "key", "--vault", VAULT_ID, "--unbind") == 5
    assert "Refusing in a non-interactive shell without --yes" in capsys.readouterr().err
    service.delete_ssh_key.assert_not_awaited()


def _duplicate():
    from servonaut.services.vault.errors import VaultDuplicateKey

    return VaultDuplicateKey(existing_item_id=_UUID, existing_name="key-1", fingerprint="SHA256:key")


@pytest.mark.parametrize("source", ["ssh", "bitwarden"])
def test_duplicate_import_is_skipped_with_exit_zero(service, monkeypatch, capsys, caplog, source) -> None:
    buffers = []
    monkeypatch.setattr(vault, "_read_import_key", lambda _: buffers.append(bytearray(b"opaque")) or buffers[0])
    monkeypatch.setattr("servonaut.services.bw_resolver.BwResolver.resolve_ssh_item",
                        MagicMock(return_value=("opaque", "key-1")))
    service.import_keys.side_effect = _duplicate()
    argv = ["import", "ssh", "--vault", VAULT_ID, "--path", "k.pem"] if source == "ssh" else [
        "import", "bitwarden", "--vault", VAULT_ID, "--item", "bw-item"]
    with caplog.at_level("INFO", logger=vault.logger.name):
        assert _run(*argv, "--json") == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == {
        "imported": False, "skipped": "already_in_vault", "item_id": _UUID,
        "existing_item_id": _UUID, "existing_name": "key-1",
    }
    assert "this key is already in this vault as key-1; nothing was imported" in output.err
    lines = [r.getMessage() for r in caplog.records if "Vault key import" in r.getMessage()]
    assert lines == [f"Vault key import ({source}) into vault {VAULT_ID}: 0 imported, 1 already in the vault, 0 failed"]
    if buffers:
        assert bytes(buffers[0]) != b"opaque"


def test_import_failure_is_non_zero_and_logged_once(service, monkeypatch, caplog) -> None:
    monkeypatch.setattr(vault, "_read_import_key", lambda _: bytearray(b"opaque"))
    service.import_keys.side_effect = RuntimeError("boom")
    with caplog.at_level("INFO", logger=vault.logger.name):
        assert _run("import", "ssh", "--vault", VAULT_ID, "--path", "k.pem") == 1
    lines = [r.getMessage() for r in caplog.records if "Vault key import" in r.getMessage()]
    assert lines == [f"Vault key import (ssh) into vault {VAULT_ID}: 0 imported, 0 already in the vault, 1 failed"]


def test_successful_import_logs_one_line(service, monkeypatch, caplog) -> None:
    monkeypatch.setattr(vault, "_read_import_key", lambda _: bytearray(b"opaque"))
    with caplog.at_level("INFO", logger=vault.logger.name):
        assert _run("import", "ssh", "--vault", VAULT_ID, "--path", "k.pem") == 0
    lines = [r.getMessage() for r in caplog.records if "Vault key import" in r.getMessage()]
    assert lines == [f"Vault key import (ssh) into vault {VAULT_ID}: 1 imported, 0 already in the vault, 0 failed"]


def test_a_stored_key_reports_imported_true_in_json(service, monkeypatch, capsys) -> None:
    monkeypatch.setattr("servonaut.services.bw_resolver.BwResolver.resolve_ssh_item",
                        MagicMock(return_value=("opaque", "key-1")))
    assert _run("import", "bitwarden", "--vault", VAULT_ID, "--item", "bw-item", "--json") == 0
    assert json.loads(capsys.readouterr().out) == {"item_id": "key", "imported": True}


def test_the_retry_after_a_refusal_confirms_what_the_refusal_showed(service) -> None:
    from servonaut.services.vault.errors import VaultKeyInUse

    refusal = VaultKeyInUse(
        team_servers=["site-1"], own_servers=["web-1"], unchecked=[], can_unbind=True,
        other_members=1, other_servers=2, team_server_ids=["s1"], own_targets=[["aws", "i-1"]],
    )
    service.delete_ssh_key.side_effect = [refusal, {"item_id": "key", "deleted": True}]
    assert _run("delete", "key", "--vault", VAULT_ID, "--unbind", "--yes") == 0
    confirmed = service.delete_ssh_key.await_args_list[1].kwargs["confirmed_usage"]
    assert confirmed["team_server_ids"] == ["s1"] and confirmed["own_targets"] == [["aws", "i-1"]]
    assert confirmed["other_members"] == {"members": 1, "servers": 2}
