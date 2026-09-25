"""db_setup_save files credentials under the scanned instance, not the DB host.

Apps on different servers commonly point at ``DB_HOST=localhost``. Keying the
profile and its secret by the DB host made every such server share (and
overwrite) one ``db/localhost/<site>`` secret. The staging token remembers
which instance was scanned; the DB host stays the connection target only.
"""
from __future__ import annotations

import argparse
import asyncio
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.config.schema import AppConfig
from servonaut.mcp.guards import CommandGuard
from servonaut.mcp.tools import ServonautTools
from servonaut.services.db_credential_scanner import DBCandidate

_INSTANCES: Dict[str, Dict[str, Any]] = {
    "i-aaa": {"id": "i-aaa", "name": "web-1"},
    "i-bbb": {"id": "i-bbb", "name": "web-2"},
}


def _dump(password: str) -> str:
    return (
        "===FILE:/var/www/shop.example.com/.env===\n"
        "DB_CONNECTION=mysql\nDB_HOST=localhost\nDB_PORT=3306\n"
        f"DB_USERNAME=app\nDB_PASSWORD={password}\nDB_DATABASE=shop\n"
    )


def _tools(cfg: AppConfig) -> ServonautTools:
    cm = MagicMock()
    cm.get.return_value = cfg

    def _update(**kwargs):
        for key, value in kwargs.items():
            setattr(cfg, key, value)

    cm.update.side_effect = _update
    secret_provider = MagicMock()
    secret_provider.set_secret = AsyncMock()
    tools = ServonautTools(
        config_manager=cm, aws_service=MagicMock(),
        custom_server_service=MagicMock(), cache_service=MagicMock(),
        ssh_service=MagicMock(), connection_service=MagicMock(),
        scp_service=MagicMock(), guard=CommandGuard(cfg.mcp),
        audit=MagicMock(), secret_provider=secret_provider,
    )

    async def _find_instance(instance_id: str):
        return _INSTANCES.get(instance_id)

    tools._find_instance = _find_instance  # type: ignore[method-assign]
    return tools


def _scan_and_save(tools: ServonautTools, instance_id: str, password: str) -> str:
    """Scan *instance_id* (its app uses localhost) and save WITHOUT instance_id."""
    async def _exec_ssh(instance, command, **_kwargs):
        return _dump(password), ""

    tools._exec_ssh = _exec_ssh  # type: ignore[method-assign]
    asyncio.run(tools.db_setup_scan(instance_id))
    (token,) = [t for t, i in tools._db_staging_instance.items() if i == instance_id]
    return asyncio.run(tools.db_setup_save(token))


def test_two_servers_with_local_databases_get_distinct_secrets():
    cfg = AppConfig()
    tools = _tools(cfg)

    _scan_and_save(tools, "i-aaa", "pw-one-aaaa")
    _scan_and_save(tools, "i-bbb", "pw-two-bbbb")

    stored = {c.args[0]: c.args[1] for c in tools._secret_provider.set_secret.call_args_list}
    assert stored == {
        "db/i-aaa/shop.example.com": "pw-one-aaaa",
        "db/i-bbb/shop.example.com": "pw-two-bbbb",
    }
    by_instance = {p.instance: p for p in cfg.db_profiles}
    assert set(by_instance) == {"i-aaa", "i-bbb"}
    # The DB host is still the connection target.
    assert all(p.host == "localhost" for p in cfg.db_profiles)
    # The read tools' per-instance lookup finds each server's own secret.
    assert cfg.db_profile_for("i-aaa", "web-1").password_secret == "db/i-aaa/shop.example.com"
    assert cfg.db_profile_for("i-bbb", "web-2").password_secret == "db/i-bbb/shop.example.com"


def test_explicit_instance_id_still_wins():
    cfg = AppConfig()
    tools = _tools(cfg)

    async def _exec_ssh(instance, command, **_kwargs):
        return _dump("pw-explicit-1"), ""

    tools._exec_ssh = _exec_ssh  # type: ignore[method-assign]
    asyncio.run(tools.db_setup_scan("i-aaa"))
    (token,) = tools._db_staging
    out = asyncio.run(tools.db_setup_save(token, instance_id="web-1"))

    assert "Saved db_profile for web-1" in out
    assert cfg.db_profiles[0].instance == "web-1"
    assert cfg.db_profiles[0].password_secret == "db/web-1/shop.example.com"
    assert tools._db_staging_instance == {}  # consumed with the token


def test_unscanned_token_without_instance_is_refused():
    """No scanned instance and no instance_id: refuse rather than guess a key."""
    cfg = AppConfig()
    tools = _tools(cfg)
    tools._db_staging["tok"] = DBCandidate(
        "mysql", "localhost", 3306, "app", "pw-orphan-1", "shop",
        "/var/www/shop.example.com/.env",
    )

    out = asyncio.run(tools.db_setup_save("tok"))

    assert "instance_id" in out
    tools._secret_provider.set_secret.assert_not_called()
    assert cfg.db_profiles == []
    assert "tok" in tools._db_staging  # still available for a retry


def test_cli_db_setup_attaches_to_the_named_instance():
    """``servonaut db setup <instance>`` passes the instance explicitly."""
    from servonaut.cli import db as cli_db

    tools = MagicMock()
    tools.db_setup_scan = AsyncMock(return_value="token=dbstg_x ...")
    tools.db_setup_save = AsyncMock(return_value="Saved db_profile for web-1")
    args = argparse.Namespace(instance="web-1", search_path="", source="auto")

    with patch.object(cli_db, "_build_tools", return_value=(tools, MagicMock())), \
         patch("builtins.input", side_effect=["dbstg_x", "y"]):
        assert asyncio.run(cli_db._run_setup(args)) == 0

    tools.db_setup_save.assert_awaited_once_with("dbstg_x", instance_id="web-1")
