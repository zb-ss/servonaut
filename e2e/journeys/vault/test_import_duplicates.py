"""A vault never stores the same SSH key twice; the same key in another vault stays allowed."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from e2e.harness.fake_cloud.routes_vault import TEAM_ID
from e2e.journeys.vault.test_cli_vault import (
    _assert_only_getpass_tty_access,
    _configure_test_custody,
    _setup_with_recovery_confirmation,
)
from e2e.journeys.vault.test_vault_key_names import _ed25519_key_pair, _native_service
from servonaut.services.vault.errors import VaultDuplicateKey

pytestmark = [pytest.mark.e2e_pr]


def _json(result) -> dict:
    assert result.returncode == 0, result.describe()
    return json.loads(result.stdout)


def _write_key(path: Path) -> Path:
    path.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption(),
    ))
    path.chmod(0o600)
    return path


def _live(fake_cloud: Any, vault_id: str) -> list[dict[str, Any]]:
    return [item for item in fake_cloud.vault._items[vault_id].values() if not item.get("deleted_at")]


@pytest.mark.parametrize("capabilities", [None, ["duplicate_item"]], ids=["old-service", "duplicate-item"])
def test_cli_import_skips_a_key_the_vault_already_holds(
    journey, fake_cloud, cli, account_home, servonaut_cmd, capabilities,
):
    fake_cloud.vault.set_capabilities(capabilities)
    _configure_test_custody(journey)
    home = account_home("import-duplicate-cli")
    setup, _ = _setup_with_recovery_confirmation(journey, home, servonaut_cmd)
    assert setup.returncode == 0, setup.text
    _assert_only_getpass_tty_access(journey)
    vault_id = _json(cli(home, "vault", "create", "--name", "Personal", "--json"))["vault_id"]
    key_path = _write_key(home.home / "first.pem")

    first = _json(cli(home, "vault", "import", "ssh", "--vault", vault_id, "--path", str(key_path),
                      "--name", "stored-key", "--json"))
    again = cli(home, "vault", "import", "ssh", "--vault", vault_id, "--path", str(key_path),
                "--name", "other-name", "--json")

    assert again.returncode == 0, again.describe()
    assert "already in this vault as stored-key" in again.stderr
    assert "Traceback" not in again.stderr
    result = json.loads(again.stdout)
    assert result["imported"] is False
    assert first["imported"] is True
    assert result["item_id"] == result["existing_item_id"] == first["item_id"]
    listed = _json(cli(home, "vault", "items", "--vault", vault_id, "--json"))
    assert [row["item_id"] for row in listed["data"]] == [first["item_id"]]

    other_path = _write_key(home.home / "second.pem")
    _json(cli(home, "vault", "import", "ssh", "--vault", vault_id, "--path", str(other_path),
              "--name", "new-key", "--json"))
    listed = _json(cli(home, "vault", "items", "--vault", vault_id, "--json"))
    assert len(listed["data"]) == 2


@pytest.mark.asyncio
async def test_the_same_key_is_refused_twice_in_one_vault_but_allowed_in_another(
    fake_cloud, account_home, monkeypatch,
):
    fake_cloud.configure(plan="teams")
    fake_cloud.account.configure(teams=[])
    fake_cloud.vault.set_capabilities(["duplicate_item"])
    home = account_home("import-duplicate-service").home
    service = _native_service(fake_cloud, home, monkeypatch)
    team = fake_cloud.account.create_team(name="Example team", owner_user_id=service.auth.user_id, team_id=TEAM_ID)
    personal = (await service.create_vault(team=None, name="Personal", grant_policy="auto"))["vault_id"]
    shared = (await service.create_vault(team=team["slug"], name="Shared", grant_policy="auto"))["vault_id"]
    private_key, _ = _ed25519_key_pair()

    first = await service.import_keys(source="ssh", vault_id=personal, private_key=private_key.encode(), name="stored-key")
    await service.import_keys(source="ssh", vault_id=shared, private_key=private_key.encode(), name="stored-key")
    with pytest.raises(VaultDuplicateKey) as refused:
        await service.import_keys(source="ssh", vault_id=personal, private_key=private_key.encode(), name="new-key")

    assert refused.value.existing_item_id == first["item_id"]
    assert refused.value.existing_name == "stored-key"
    assert len(_live(fake_cloud, personal)) == 1
    assert len(_live(fake_cloud, shared)) == 1

    await service.delete_ssh_key(vault_id=personal, item_id=first["item_id"], servers=[])
    again = await service.import_keys(source="ssh", vault_id=personal, private_key=private_key.encode(), name="new-key")
    assert again["item_id"] != first["item_id"]
    assert len(_live(fake_cloud, personal)) == 1


@pytest.mark.asyncio
async def test_a_service_duplicate_refusal_is_raised_as_a_duplicate_key(
    fake_cloud, account_home, monkeypatch,
):
    fake_cloud.vault.set_capabilities(["duplicate_item"])
    home = account_home("import-duplicate-409").home
    service = _native_service(fake_cloud, home, monkeypatch)
    vault_id = (await service.create_vault(team=None, name="Personal", grant_policy="auto"))["vault_id"]
    private_key, _ = _ed25519_key_pair()
    first = await service.import_keys(source="ssh", vault_id=vault_id, private_key=private_key.encode(), name="stored-key")

    real_list_items = service.list_items
    missed = {"done": False}

    async def listing_that_misses_once(**kwargs: Any) -> dict[str, Any]:
        if not missed["done"]:
            missed["done"] = True
            return {"data": [], "meta": {}}
        return await real_list_items(**kwargs)

    monkeypatch.setattr(service, "list_items", listing_that_misses_once)
    with pytest.raises(VaultDuplicateKey) as refused:
        await service.import_keys(source="ssh", vault_id=vault_id, private_key=private_key.encode(), name="new-key")

    assert missed["done"] is True
    assert refused.value.existing_item_id == first["item_id"]
    assert len(_live(fake_cloud, vault_id)) == 1
