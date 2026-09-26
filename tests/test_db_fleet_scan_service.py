"""Tests for the fleet / bulk DB-credential scan orchestrator — Layer B3.

Pins the done-when behaviour:
- fans out across the fleet, bounded at max_parallel (Semaphore);
- assembles ONE ordered review table with an already-vaulted column;
- skips instances that already have a db/<instance> profile (no re-probe);
- isolates per-box failures — one bad box never aborts the batch;
- commit_all stores committable rows, skips vaulted/empty, isolates a
  failing commit.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import AppConfig, DBProfile
from servonaut.services.db_fleet_scan_service import (
    DbFleetScanService,
    FleetDbScanResult,
    FleetDbScanRow,
)


def run(coro):
    return asyncio.run(coro)


def _candidate(token="dbstg_x"):
    return {
        "token": token, "engine": "mysql", "user": "app", "host": "127.0.0.1",
        "port": 3306, "database": "appdb", "password_preview": "****xyz",
        "source": "/var/www/.env",
    }


def _config_manager(vaulted_instances=()):
    cfg = AppConfig()
    cfg.db_profiles = [
        DBProfile(instance=i, password_secret=f"db/{i}") for i in vaulted_instances
    ]
    cm = MagicMock()
    cm.get.return_value = cfg
    return cm


def _instances(*names):
    return [{"id": n, "name": n} for n in names]


class TestScan:
    def test_scans_all_and_preserves_order(self):
        tools = MagicMock()
        tools.db_scan_stage = AsyncMock(
            return_value={"error": None, "candidates": [_candidate()]}
        )
        svc = DbFleetScanService(tools, _config_manager())
        result = run(svc.scan(_instances("a", "b", "c")))
        assert [r.instance_id for r in result.rows] == ["a", "b", "c"]
        assert all(r.status == "1 found" for r in result.rows)

    def test_already_vaulted_skips_probe(self):
        tools = MagicMock()
        tools.db_scan_stage = AsyncMock(
            return_value={"error": None, "candidates": [_candidate()]}
        )
        svc = DbFleetScanService(tools, _config_manager(vaulted_instances=["b"]))
        result = run(svc.scan(_instances("a", "b", "c")))
        vaulted = {r.instance_id: r.already_vaulted for r in result.rows}
        assert vaulted == {"a": False, "b": True, "c": False}
        # 'b' was never probed — only a + c hit db_scan_stage.
        probed = {c.args[0] for c in tools.db_scan_stage.call_args_list}
        assert probed == {"a", "c"}

    def test_per_box_failure_isolated(self):
        tools = MagicMock()

        async def _scan(iid, **_kwargs):
            if iid == "bad":
                raise RuntimeError("ssh down")
            return {"error": None, "candidates": [_candidate()]}

        tools.db_scan_stage = AsyncMock(side_effect=_scan)
        svc = DbFleetScanService(tools, _config_manager())
        result = run(svc.scan(_instances("a", "bad", "c")))
        by_id = {r.instance_id: r for r in result.rows}
        assert by_id["bad"].error and by_id["bad"].status == "error"
        # The batch completed — good boxes still produced candidates.
        assert by_id["a"].candidates and by_id["c"].candidates

    def test_tool_reported_error_captured(self):
        tools = MagicMock()
        tools.db_scan_stage = AsyncMock(
            return_value={"error": "ssh_error: refused", "candidates": []}
        )
        svc = DbFleetScanService(tools, _config_manager())
        result = run(svc.scan(_instances("a")))
        assert result.rows[0].error == "ssh_error: refused"

    def test_concurrency_is_bounded(self):
        tools = MagicMock()
        state = {"current": 0, "peak": 0}

        async def _scan(iid, **_kwargs):
            state["current"] += 1
            state["peak"] = max(state["peak"], state["current"])
            await asyncio.sleep(0)  # yield so tasks overlap
            state["current"] -= 1
            return {"error": None, "candidates": [_candidate()]}

        tools.db_scan_stage = AsyncMock(side_effect=_scan)
        svc = DbFleetScanService(tools, _config_manager(), max_parallel=3)
        run(svc.scan(_instances(*[f"i{n}" for n in range(20)])))
        assert state["peak"] <= 3


class TestCommitAll:
    def test_commits_committable_skips_vaulted_and_empty(self):
        tools = MagicMock()
        tools.db_setup_save = AsyncMock(return_value="Saved db_profile for x")
        svc = DbFleetScanService(tools, _config_manager())
        result = FleetDbScanResult(rows=[
            FleetDbScanRow("a", "a", False, candidates=[_candidate("t-a")]),
            FleetDbScanRow("b", "b", True),  # vaulted → skip
            FleetDbScanRow("c", "c", False, candidates=[]),  # nothing → skip
            FleetDbScanRow("d", "d", False, candidates=[_candidate("t-d")]),
        ])
        summary = run(svc.commit_all(result))
        assert summary.stored == 2
        assert summary.skipped == 2
        assert summary.failed == 0
        stored_tokens = {c.args[0] for c in tools.db_setup_save.call_args_list}
        assert stored_tokens == {"t-a", "t-d"}

    def test_failing_commit_isolated(self):
        tools = MagicMock()

        async def _save(token, instance_id=""):
            if token == "boom":
                raise RuntimeError("store offline")
            return "Saved db_profile for x"

        tools.db_setup_save = AsyncMock(side_effect=_save)
        svc = DbFleetScanService(tools, _config_manager())
        result = FleetDbScanResult(rows=[
            FleetDbScanRow("a", "a", False, candidates=[_candidate("ok")]),
            FleetDbScanRow("b", "b", False, candidates=[_candidate("boom")]),
            FleetDbScanRow("c", "c", False, candidates=[_candidate("ok2")]),
        ])
        summary = run(svc.commit_all(result))
        assert summary.stored == 2
        assert summary.failed == 1
        assert summary.failures and summary.failures[0][0] == "b"

    def test_commit_row_skips_vaulted(self):
        tools = MagicMock()
        tools.db_setup_save = AsyncMock()
        svc = DbFleetScanService(tools, _config_manager())
        ok, why = run(svc.commit_row(FleetDbScanRow("a", "a", True)))
        assert ok is False and "already vaulted" in why
        tools.db_setup_save.assert_not_awaited()


class TestStagingCap:
    """A fleet batch is not limited by the per-agent staging cap."""

    _SOURCE = "/srv/app/" + ".env"

    @classmethod
    def _real_tools(cls, cfg, instances):
        from servonaut.mcp.guards import CommandGuard
        from servonaut.mcp.tools import ServonautTools

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
        by_id = {inst["id"]: inst for inst in instances}

        async def _find_instance(key):
            return by_id.get(key)

        async def _exec_ssh(inst, command, **_kwargs):
            return (
                f"===FILE:{cls._SOURCE}===\n"
                "DB_CONNECTION=mysql\nDB_HOST=localhost\nDB_PORT=3306\n"
                f"DB_USERNAME=app\nDB_PASSWORD=pw-{inst['id']}\n"
                "DB_DATABASE=appdb\n"
            ), ""

        tools._find_instance = _find_instance
        tools._exec_ssh = _exec_ssh
        return tools

    def test_fleet_larger_than_the_cap_stores_every_candidate(self):
        from servonaut.mcp.db_staging import DEFAULT_MAX_TOKENS

        cfg = AppConfig()
        assert cfg.mcp.db_staging_max_tokens == DEFAULT_MAX_TOKENS
        instances = _instances(*[f"box-{n:03d}" for n in range(DEFAULT_MAX_TOKENS + 10)])
        tools = self._real_tools(cfg, instances)
        svc = DbFleetScanService(tools, MagicMock(get=MagicMock(return_value=cfg)))

        result = run(svc.scan(instances))
        assert all(len(r.candidates) == 1 for r in result.rows)
        summary = run(svc.commit_all(result))

        assert (summary.stored, summary.failed) == (len(instances), 0), summary.failures
        stored = {
            c.args[0]: c.args[1]
            for c in tools._secret_provider.set_secret.call_args_list
        }
        assert len(stored) == len(instances)
        for inst in instances:
            (name,) = [n for n in stored if n.startswith(f"db/{inst['id']}")]
            assert stored[name] == f"pw-{inst['id']}"
        assert {p.instance for p in cfg.db_profiles} == {i["id"] for i in instances}
        # The batch left the agent's store alone and nothing stays staged.
        assert len(tools._db_staging) == 0
        assert len(tools._db_staging_batch) == 0

    def test_a_new_scan_drops_the_previous_batch(self):
        cfg = AppConfig()
        instances = _instances("box-a")
        tools = self._real_tools(cfg, instances)
        svc = DbFleetScanService(tools, MagicMock(get=MagicMock(return_value=cfg)))

        first = run(svc.scan(instances))
        old_token = first.rows[0].top_candidate["token"]
        second = run(svc.scan(instances))

        assert tools._staged_db_entry(old_token) == (None, None)
        new_token = second.rows[0].top_candidate["token"]
        assert tools._staged_db_entry(new_token)[1] is not None
