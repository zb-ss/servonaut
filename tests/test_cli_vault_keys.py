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
    assert ("try again when they can be reached" if field == "unchecked" else "another vault key") in error
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
