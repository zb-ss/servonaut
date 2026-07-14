"""Tests for the human scan→store surface — Layer B2.

Covers the structured :meth:`ServonautTools.db_scan_stage` (the sibling of
``db_setup_scan`` the TUI drives) and the full round-trip:

    db_scan_stage  →  db_setup_save  →  _resolve_db (what db_processlist uses)

proving the stored credential resolves BY NAME afterward — the whole point
of the vault (no re-SSH to read). The plaintext password must never appear
in any structured preview.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import AppConfig, DBProfile
from servonaut.mcp.guards import CommandGuard
from servonaut.mcp.tools import ServonautTools

_SECRET_PW = "s3cr3t-passw0rd-xyz"


def _async_return(value):
    async def _inner(*a, **k):
        return value
    return _inner


class _DictProvider:
    """Minimal in-memory SecretProvider for round-trip resolution."""

    provider_name = "local"

    def __init__(self):
        self._store = {}

    async def set_secret(self, name, value):
        self._store[name] = value

    async def get_secret(self, name):
        return self._store.get(name)

    async def delete_secret(self, name):
        return self._store.pop(name, None) is not None

    async def list_secrets(self):
        return sorted(self._store)


def _tools(secret_provider=None):
    cfg = AppConfig()
    cm = MagicMock()
    cm.get.return_value = cfg

    def _update(**kw):
        for k, v in kw.items():
            setattr(cfg, k, v)

    cm.update.side_effect = _update
    return ServonautTools(
        config_manager=cm,
        aws_service=MagicMock(),
        custom_server_service=MagicMock(),
        cache_service=MagicMock(),
        ssh_service=MagicMock(),
        connection_service=MagicMock(),
        scp_service=MagicMock(),
        guard=CommandGuard(cfg.mcp),
        audit=MagicMock(),
        secret_provider=secret_provider,
    )


_DUMP = (
    "===FILE:/var/www/app/.env===\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\n"
    f"DB_PORT=3306\nDB_USERNAME=app\nDB_PASSWORD={_SECRET_PW}\nDB_DATABASE=appdb\n"
)


class TestDbScanStage:
    def test_returns_structured_previews_without_plaintext(self):
        t = _tools()
        t._find_instance = _async_return({"id": "i-1", "name": "web"})  # type: ignore
        t._exec_ssh = _async_return((_DUMP, ""))  # type: ignore
        result = asyncio.run(t.db_scan_stage("i-1"))

        assert result["error"] is None
        cands = result["candidates"]
        assert len(cands) == 1
        c = cands[0]
        # Structured preview carries the token + masked password, never plaintext.
        assert c["token"].startswith("dbstg_")
        assert c["password_preview"].startswith("****")
        assert _SECRET_PW not in str(result)
        # ...but the plaintext IS staged server-side for the commit step.
        assert t._db_staging[c["token"]].password == _SECRET_PW

    def test_no_candidates_returns_empty_not_error(self):
        t = _tools()
        t._find_instance = _async_return({"id": "i-1", "name": "web"})  # type: ignore
        t._exec_ssh = _async_return(("", ""))  # type: ignore
        result = asyncio.run(t.db_scan_stage("i-1"))
        assert result["error"] is None
        assert result["candidates"] == []

    def test_instance_not_found(self):
        t = _tools()
        t._find_instance = _async_return(None)  # type: ignore
        result = asyncio.run(t.db_scan_stage("nope"))
        assert "not found" in result["error"].lower()
        assert result["candidates"] == []

    def test_ssh_source_error_surfaces(self):
        t = _tools()
        t._find_instance = _async_return({"id": "i-1", "name": "web"})  # type: ignore

        async def _boom(*a, **k):
            raise RuntimeError("connection refused")

        t._exec_ssh = _boom  # type: ignore
        result = asyncio.run(t.db_scan_stage("i-1", source="ssh"))
        assert result["error"].startswith("ssh_error")
        assert result["candidates"] == []


class TestRoundTripResolveByName:
    def test_scan_stage_save_then_resolve_by_name(self):
        provider = _DictProvider()
        t = _tools(secret_provider=provider)
        t._find_instance = _async_return({"id": "i-1", "name": "web"})  # type: ignore
        t._exec_ssh = _async_return((_DUMP, ""))  # type: ignore

        # 1. Scan → structured candidate + token.
        scan = asyncio.run(t.db_scan_stage("web"))
        token = scan["candidates"][0]["token"]

        # 2. Store the chosen candidate in the vault (same path as db_setup_save).
        save = asyncio.run(t.db_setup_save(token, instance_id="web"))
        assert save.startswith("Saved")
        # The secret landed under the db/<instance> convention.
        assert asyncio.run(provider.get_secret("db/web")) == _SECRET_PW

        # 3. db_processlist's resolver now finds the credential BY NAME —
        #    no re-scan, no SSH-to-read.
        instance, profile, password, err = asyncio.run(
            t._resolve_db("web", "db_processlist", {})
        )
        assert err == ""
        assert isinstance(profile, DBProfile)
        assert profile.password_secret == "db/web"
        assert password == _SECRET_PW  # resolved from the store by name
