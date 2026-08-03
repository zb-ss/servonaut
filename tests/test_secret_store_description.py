"""Naming the secret-store backend in user- and agent-facing messages.

The active provider is resolved at boot from the operator's secrets config,
so an identical ``db_setup_save`` call lands in Bitwarden Secrets Manager for
one operator and in a local file for another. Messages that said only "the
secret store" left agents unable to tell which — and one reported that a
credential had never reached Bitwarden when it had.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from servonaut.config.schema import AppConfig, DBProfile
from servonaut.mcp.guards import CommandGuard
from servonaut.mcp.tools import ServonautTools
from servonaut.services.bitwarden_provider import BitwardenProvider
from servonaut.services.db_credential_scanner import DBCandidate
from servonaut.services.secret_provider import LocalProvider
from servonaut.services.secrets_status import describe_secret_store

_PW = "s3cr3t-store-naming-pw"
_PROJECT_ID = "11111111-2222-4333-8444-555555555555"


def _tools(cfg: AppConfig, secret_provider):
    """ServonautTools whose config_manager.update mutates the config."""
    cm = MagicMock()
    cm.get.return_value = cfg

    def _update(**kwargs):
        for k, v in kwargs.items():
            setattr(cfg, k, v)
    cm.update.side_effect = _update

    return ServonautTools(
        config_manager=cm, aws_service=MagicMock(),
        custom_server_service=MagicMock(), cache_service=MagicMock(),
        ssh_service=MagicMock(), connection_service=MagicMock(),
        scp_service=MagicMock(), guard=CommandGuard(cfg.mcp),
        audit=MagicMock(), secret_provider=secret_provider,
    )


def _bitwarden_provider(project_id: str = _PROJECT_ID) -> BitwardenProvider:
    """A real BitwardenProvider — constructing it touches no network/bws."""
    return BitwardenProvider(project_id=project_id)


# ---------------------------------------------------------------------------
# describe_secret_store — the pure describer
# ---------------------------------------------------------------------------


def test_describes_bitwarden_with_project_id():
    out = describe_secret_store(_bitwarden_provider())
    assert out == f"Bitwarden Secrets Manager (project {_PROJECT_ID})"


def test_describes_local_provider_with_path(tmp_path: Path):
    provider = LocalProvider(tmp_path / "secrets.json", _allow_any_path=True)
    out = describe_secret_store(provider)
    assert "local secret store" in out
    assert str(tmp_path / "secrets.json") in out


def test_describes_absent_provider():
    assert describe_secret_store(None) == "no active secret store"


def test_unknown_provider_degrades_to_generic_phrasing():
    """Duck-typed, so a test double or a future provider never raises."""
    assert describe_secret_store(MagicMock()) == "your active secret store"

    class _FutureProvider:
        provider_name = "vault"

    assert describe_secret_store(_FutureProvider()) == "your active secret store"


def test_bitwarden_without_readable_project_id_still_names_the_product():
    """Defensive: a provider-shaped object with no usable id is still Bitwarden."""
    stub = MagicMock()
    stub.provider_name = "bitwarden"
    stub.project_id = None
    assert describe_secret_store(stub) == "Bitwarden Secrets Manager"


# ---------------------------------------------------------------------------
# Tool surface — the three messages that mention the store
# ---------------------------------------------------------------------------


def test_db_setup_save_names_the_backend_it_wrote_to():
    cfg = AppConfig()
    provider = _bitwarden_provider()
    provider.set_secret = AsyncMock()  # don't shell out to bws
    t = _tools(cfg, provider)
    t._db_staging["tok"] = DBCandidate(
        "mysql", "127.0.0.1", 3306, "app", _PW, "appdb", "/var/www/html/.env")

    out = asyncio.run(t.db_setup_save("tok", instance_id="web"))

    assert "Bitwarden Secrets Manager" in out
    assert _PROJECT_ID in out
    assert "'db/web'" in out          # the key name is still reported
    assert _PW not in out             # ...but never the password


def test_db_setup_save_names_the_local_file_when_local_is_active(tmp_path: Path):
    cfg = AppConfig()
    provider = LocalProvider(tmp_path / "secrets.json", _allow_any_path=True)
    t = _tools(cfg, provider)
    t._db_staging["tok"] = DBCandidate(
        "mysql", "127.0.0.1", 3306, "app", _PW, "appdb", "/var/www/html/.env")

    out = asyncio.run(t.db_setup_save("tok", instance_id="web"))

    assert str(tmp_path / "secrets.json") in out
    assert "Bitwarden" not in out
    assert _PW not in out


def test_secret_not_found_error_names_the_store_it_searched():
    cfg = AppConfig()
    cfg.db_profiles = [DBProfile(
        instance="web", engine="mysql", host="127.0.0.1", port=3306,
        user="app", password_secret="db/web", database="appdb",
    )]
    provider = _bitwarden_provider()
    provider.get_secret = AsyncMock(return_value=None)  # absent from the vault
    t = _tools(cfg, provider)
    t._find_instance = AsyncMock(return_value={"id": "web", "name": "web"})

    _, _, _, err = asyncio.run(t._resolve_db("web", "db_processlist", {}))

    assert "not found in Bitwarden Secrets Manager" in err
    assert _PROJECT_ID in err


def test_db_setup_remove_names_the_store_it_deleted_from():
    cfg = AppConfig()
    cfg.db_profiles = [DBProfile(
        instance="web", engine="mysql", host="127.0.0.1", port=3306,
        user="app", password_secret="db/web", database="appdb",
    )]
    provider = _bitwarden_provider()
    provider.delete_secret = AsyncMock(return_value=True)
    t = _tools(cfg, provider)

    out = asyncio.run(t.db_setup_remove("web"))

    assert "deleted from Bitwarden Secrets Manager" in out
    assert _PROJECT_ID in out
