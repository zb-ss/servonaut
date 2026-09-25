"""Staged DB credentials expire and are capped.

db_setup_scan holds plaintext DB passwords in memory until db_setup_save
commits them; these tests pin how long and how many.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import AppConfig
from servonaut.mcp.db_staging import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_TTL_SECONDS,
    DBCredentialStaging,
)
from servonaut.mcp.guards import CommandGuard
from servonaut.mcp.tools import ServonautTools
from servonaut.services.db_credential_scanner import DBCandidate


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _cand(password: str = "pw-staged-1") -> DBCandidate:
    return DBCandidate("mysql", "localhost", 3306, "app", password, "shop")


class TestExpiry:
    def test_token_expires_after_ttl(self):
        clock = _Clock()
        store = DBCredentialStaging(ttl_seconds=900, clock=clock)
        token = store.stage(_cand(), instance_id="i-aaa", instance_name="web-1")

        clock.now += 899
        assert store.entry(token).instance_id == "i-aaa"

        clock.now += 2
        assert store.entry(token) is None
        assert token not in store
        assert len(store) == 0

    def test_expiry_drops_the_password_without_further_access(self):
        """With a frozen clock only the expiry timer can remove the entry."""
        store = DBCredentialStaging(ttl_seconds=0.05, clock=lambda: 0.0)

        async def _scenario():
            store.stage(_cand())
            await asyncio.sleep(0.15)

        asyncio.run(_scenario())
        assert store._entries == {}

    def test_consuming_a_token_cancels_its_timer(self):
        store = DBCredentialStaging(ttl_seconds=60)

        async def _scenario():
            token = store.stage(_cand())
            timer = store._entries[token]._timer
            store.pop(token)
            return timer

        timer = asyncio.run(_scenario())
        assert timer.cancelled()


class TestCap:
    def test_oldest_token_is_evicted(self):
        store = DBCredentialStaging(ttl_seconds=900, max_tokens=3, clock=_Clock())
        tokens = [store.stage(_cand(f"pw-{i}")) for i in range(4)]

        assert tokens[0] not in store
        assert [store[t].password for t in tokens[1:]] == ["pw-1", "pw-2", "pw-3"]
        assert len(store) == 3


def _tools(cfg: AppConfig) -> ServonautTools:
    cm = MagicMock()
    cm.get.return_value = cfg
    secret_provider = MagicMock()
    secret_provider.set_secret = AsyncMock()
    return ServonautTools(
        config_manager=cm, aws_service=MagicMock(),
        custom_server_service=MagicMock(), cache_service=MagicMock(),
        ssh_service=MagicMock(), connection_service=MagicMock(),
        scp_service=MagicMock(), guard=CommandGuard(cfg.mcp),
        audit=MagicMock(), secret_provider=secret_provider,
    )


class TestToolsWiring:
    def test_limits_come_from_mcp_config(self):
        cfg = AppConfig()
        cfg.mcp.db_staging_ttl_seconds = 60
        cfg.mcp.db_staging_max_tokens = 2
        store = _tools(cfg)._db_staging
        assert (store._ttl, store._max) == (60, 2)

    @pytest.mark.parametrize("bad", [0, -5, True, "900", None])
    def test_invalid_config_falls_back_to_defaults(self, bad):
        cfg = AppConfig()
        cfg.mcp.db_staging_ttl_seconds = bad
        cfg.mcp.db_staging_max_tokens = bad
        store = _tools(cfg)._db_staging
        assert (store._ttl, store._max) == (DEFAULT_TTL_SECONDS, DEFAULT_MAX_TOKENS)

    def test_save_after_expiry_is_refused(self):
        cfg = AppConfig()
        tools = _tools(cfg)
        clock = _Clock()
        tools._db_staging = DBCredentialStaging(ttl_seconds=900, clock=clock)
        token = tools._db_staging.stage(_cand(), instance_id="i-aaa")

        clock.now += 901
        out = asyncio.run(tools.db_setup_save(token))

        assert "unknown or expired" in out
        tools._secret_provider.set_secret.assert_not_called()
        assert cfg.db_profiles == []
