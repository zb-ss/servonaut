"""An empty instance id never resolves to a server.

Unnamed AWS instances carry an empty name, so a lookup that matched ""
against names would pick the first unnamed instance — and db_setup_remove
would then delete that server's db_profile and its stored secret. These
tests use the real instance lookup rather than a stub.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import AppConfig, DBProfile
from servonaut.mcp.guards import CommandGuard
from servonaut.mcp.tools import ServonautTools

_UNNAMED = {"id": "i-0123456789abcdef0", "name": "", "region": "eu-west-1"}


def _tools(cfg: AppConfig, aws_instances: List[Dict[str, Any]]) -> ServonautTools:
    cm = MagicMock()
    cm.get.return_value = cfg

    def _update(**kwargs):
        for key, value in kwargs.items():
            setattr(cfg, key, value)

    cm.update.side_effect = _update
    aws = MagicMock()
    aws.fetch_instances_cached = AsyncMock(return_value=aws_instances)
    custom = MagicMock()
    custom.list_as_instances.return_value = []
    secret_provider = MagicMock()
    secret_provider.delete_secret = AsyncMock(return_value=True)
    return ServonautTools(
        config_manager=cm, aws_service=aws,
        custom_server_service=custom, cache_service=MagicMock(),
        ssh_service=MagicMock(), connection_service=MagicMock(),
        scp_service=MagicMock(), guard=CommandGuard(cfg.mcp),
        audit=MagicMock(), secret_provider=secret_provider,
    )


def _profile() -> DBProfile:
    return DBProfile(
        instance=_UNNAMED["id"], engine="mysql", host="localhost", user="app",
        password_secret=f"db/{_UNNAMED['id']}",
    )


@pytest.mark.parametrize("needle", ["", "  ", "\t"])
def test_find_instance_resolves_empty_needle_to_nothing(needle):
    tools = _tools(AppConfig(), [_UNNAMED])

    assert asyncio.run(tools._find_instance(needle)) is None


def test_find_instance_still_resolves_the_unnamed_instance_by_id():
    tools = _tools(AppConfig(), [_UNNAMED])

    assert asyncio.run(tools._find_instance(_UNNAMED["id"])) is _UNNAMED


@pytest.mark.parametrize("needle", ["", "  "])
def test_remove_with_empty_instance_id_removes_nothing(needle):
    cfg = AppConfig(db_profiles=[_profile()])
    tools = _tools(cfg, [_UNNAMED])

    out = asyncio.run(tools.db_setup_remove(needle))

    assert "instance_id is required" in out
    assert [p.instance for p in cfg.db_profiles] == [_UNNAMED["id"]]
    tools._config_manager.update.assert_not_called()
    tools._secret_provider.delete_secret.assert_not_called()
    tool, _args, _result, allowed, reason = tools._audit.log.call_args.args
    assert (tool, allowed, reason) == (
        "db_setup_remove", False, "validation: instance_id required",
    )


def test_remove_by_id_still_removes_the_unnamed_instance_profile():
    cfg = AppConfig(db_profiles=[_profile()])
    tools = _tools(cfg, [_UNNAMED])

    out = asyncio.run(tools.db_setup_remove(_UNNAMED["id"]))

    assert out.startswith("Removed")
    assert cfg.db_profiles == []
    tools._secret_provider.delete_secret.assert_awaited_once_with(
        f"db/{_UNNAMED['id']}")
