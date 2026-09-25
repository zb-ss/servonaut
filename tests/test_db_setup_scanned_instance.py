"""db_setup_save keys every DB profile by the canonical instance id.

Apps on different servers commonly point at ``DB_HOST=localhost``. Keying the
profile and its secret by the DB host made every such server share (and
overwrite) one ``db/localhost/<site>`` secret. The staging token remembers
which instance was scanned; an explicit ``instance_id`` (id or name) is
resolved to the same canonical id, so one site never gets two profiles. The
DB host stays the connection target only.
"""
from __future__ import annotations

import argparse
import asyncio
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

from servonaut.config.schema import AppConfig, DBProfile
from servonaut.mcp.guards import CommandGuard
from servonaut.mcp.tools import ServonautTools
from servonaut.services.db_credential_scanner import DBCandidate

_INSTANCES: List[Dict[str, Any]] = [
    {"id": "i-aaa", "name": "web-1"},
    {"id": "i-bbb", "name": "web-2"},
]
_SITE_SOURCE = "/var/www/shop.example.com/" + ".env"


def _dump(password: str) -> str:
    return (
        f"===FILE:{_SITE_SOURCE}===\n"
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
    secret_provider.delete_secret = AsyncMock(return_value=True)
    tools = ServonautTools(
        config_manager=cm, aws_service=MagicMock(),
        custom_server_service=MagicMock(), cache_service=MagicMock(),
        ssh_service=MagicMock(), connection_service=MagicMock(),
        scp_service=MagicMock(), guard=CommandGuard(cfg.mcp),
        audit=MagicMock(), secret_provider=secret_provider,
    )

    async def _find_instance(key: str) -> Optional[Dict[str, Any]]:
        needle = key.lower()
        for inst in _INSTANCES:
            if needle in (inst["id"].lower(), inst["name"].lower()):
                return inst
        return None

    tools._find_instance = _find_instance  # type: ignore[method-assign]
    return tools


def _scan(tools: ServonautTools, instance: str, password: str) -> str:
    """Scan *instance* (its app uses localhost); return the staged token."""
    async def _exec_ssh(inst, command, **_kwargs):
        return _dump(password), ""

    tools._exec_ssh = _exec_ssh  # type: ignore[method-assign]
    before = set(tools._db_staging)
    asyncio.run(tools.db_setup_scan(instance))
    (token,) = set(tools._db_staging) - before
    return token


def _stored(tools: ServonautTools) -> Dict[str, str]:
    return {c.args[0]: c.args[1] for c in tools._secret_provider.set_secret.call_args_list}


def test_two_servers_with_local_databases_get_distinct_secrets():
    cfg = AppConfig()
    tools = _tools(cfg)

    asyncio.run(tools.db_setup_save(_scan(tools, "i-aaa", "pw-one-aaaa")))
    asyncio.run(tools.db_setup_save(_scan(tools, "i-bbb", "pw-two-bbbb")))

    assert _stored(tools) == {
        "db/i-aaa/shop.example.com": "pw-one-aaaa",
        "db/i-bbb/shop.example.com": "pw-two-bbbb",
    }
    assert {p.instance for p in cfg.db_profiles} == {"i-aaa", "i-bbb"}
    # The DB host is still the connection target.
    assert all(p.host == "localhost" for p in cfg.db_profiles)
    # The read tools' per-instance lookup finds each server's own secret.
    assert cfg.db_profile_for("i-aaa", "web-1").password_secret == "db/i-aaa/shop.example.com"
    assert cfg.db_profile_for("i-bbb", "web-2").password_secret == "db/i-bbb/shop.example.com"


def test_explicit_name_is_stored_as_the_canonical_id():
    cfg = AppConfig()
    tools = _tools(cfg)

    out = asyncio.run(tools.db_setup_save(
        _scan(tools, "web-1", "pw-explicit-1"), instance_id="web-1",
    ))

    assert out.startswith("Saved db_profile for web-1 (i-aaa)")
    assert "WARNING" not in out
    assert cfg.db_profiles[0].instance == "i-aaa"
    assert cfg.db_profiles[0].password_secret == "db/i-aaa/shop.example.com"
    assert len(tools._db_staging) == 0  # token consumed


def test_name_then_id_saves_of_one_site_leave_one_profile():
    cfg = AppConfig()
    tools = _tools(cfg)

    asyncio.run(tools.db_setup_save(_scan(tools, "i-aaa", "pw-first-11"), instance_id="web-1"))
    asyncio.run(tools.db_setup_save(_scan(tools, "i-aaa", "pw-second-2"), instance_id="i-aaa"))

    assert len(cfg.db_profiles) == 1
    assert cfg.db_profiles[0].instance == "i-aaa"
    # One label per instance means the label lookup is unambiguous.
    assert cfg.db_profile_by_label("i-aaa", "shop", "web-1") is cfg.db_profiles[0]


def test_resave_replaces_a_legacy_name_keyed_profile():
    """A profile an earlier release stored under the NAME is replaced, not duplicated."""
    cfg = AppConfig(db_profiles=[DBProfile(
        instance="web-1", engine="mysql", host="localhost", user="app",
        password_secret="db/web-1/shop.example.com", label="shop.example.com",
    )])
    tools = _tools(cfg)

    out = asyncio.run(tools.db_setup_save(_scan(tools, "i-aaa", "pw-rescan-3")))

    assert len(cfg.db_profiles) == 1
    assert cfg.db_profiles[0].instance == "i-aaa"
    assert cfg.db_profile_by_label("i-aaa", "shop", "web-1") is cfg.db_profiles[0]
    # The superseded secret is named, not silently deleted.
    assert "'db/web-1/shop.example.com'" in out and "no longer used" in out


def test_explicit_instance_that_differs_from_the_scan_warns():
    cfg = AppConfig()
    tools = _tools(cfg)

    out = asyncio.run(tools.db_setup_save(
        _scan(tools, "i-aaa", "pw-mismatch-4"), instance_id="web-2",
    ))

    assert out.startswith("Saved")
    assert "WARNING: these credentials were scanned on web-1 (i-aaa)" in out
    assert "db_setup_remove(instance_id='i-bbb', app='shop.example.com')" in out
    assert cfg.db_profiles[0].instance == "i-bbb"
    audit_kwargs = tools._audit.log.call_args.kwargs
    assert audit_kwargs.get("instance_mismatch") is True


def test_unknown_explicit_instance_is_refused():
    cfg = AppConfig()
    tools = _tools(cfg)
    token = _scan(tools, "i-aaa", "pw-unknown-5")

    out = asyncio.run(tools.db_setup_save(token, instance_id="does-not-exist"))

    assert out == "Instance not found: does-not-exist"
    tools._secret_provider.set_secret.assert_not_called()
    assert cfg.db_profiles == []
    assert token in tools._db_staging  # still available for a retry


def test_unscanned_token_without_instance_is_refused():
    """No scanned instance and no instance_id: refuse rather than guess a key."""
    cfg = AppConfig()
    tools = _tools(cfg)
    tools._db_staging["tok"] = DBCandidate(
        "mysql", "localhost", 3306, "app", "pw-orphan-1", "shop", _SITE_SOURCE,
    )

    out = asyncio.run(tools.db_setup_save("tok"))

    assert "instance_id" in out
    tools._secret_provider.set_secret.assert_not_called()
    assert cfg.db_profiles == []
    assert "tok" in tools._db_staging


def test_remove_by_name_finds_id_keyed_profile_and_vice_versa():
    cfg = AppConfig(db_profiles=[
        DBProfile(instance="i-aaa", password_secret="db/i-aaa"),
        DBProfile(instance="web-2", password_secret="db/web-2"),  # legacy, name-keyed
    ])
    tools = _tools(cfg)

    assert "Removed" in asyncio.run(tools.db_setup_remove("web-1"))
    assert "Removed" in asyncio.run(tools.db_setup_remove("i-bbb"))
    assert cfg.db_profiles == []


def test_remove_still_works_for_an_instance_that_no_longer_resolves():
    cfg = AppConfig(db_profiles=[DBProfile(instance="old-box", password_secret="db/old-box")])
    tools = _tools(cfg)

    assert "Removed" in asyncio.run(tools.db_setup_remove("old-box"))
    assert cfg.db_profiles == []


def test_cli_db_setup_passes_the_named_instance():
    """``servonaut db setup <instance>`` passes what the user typed; the tool
    resolves it to the canonical id (covered above)."""
    from servonaut.cli import db as cli_db

    tools = MagicMock()
    tools.db_setup_scan = AsyncMock(return_value="token=dbstg_x ...")
    tools.db_setup_save = AsyncMock(return_value="Saved db_profile for web-1 (i-aaa)")
    args = argparse.Namespace(instance="web-1", search_path="", source="auto")

    with patch.object(cli_db, "_build_tools", return_value=(tools, MagicMock())), \
         patch("builtins.input", side_effect=["dbstg_x", "y"]):
        assert asyncio.run(cli_db._run_setup(args)) == 0

    tools.db_setup_save.assert_awaited_once_with("dbstg_x", instance_id="web-1")
