"""Journey: an MCP client drives ``servonaut --mcp`` over stdio.

The real server starts as a child process and the official MCP SDK client
performs the handshake. ``tools/list`` must match the tool catalogue for the
configured providers. Then every listed tool is called at each guard level
(readonly, standard, dangerous): a tool above the level must be refused with
one audit entry, a tool within it must never be refused, and the command
blocklist applies even at the dangerous level.

Calls use placeholder arguments that point at nothing (an unknown instance,
an unreachable AWS endpoint), so no call reaches anything outside the
sandbox; the suite's guards would fail the journey if one tried. A relay
listener that ``relay_reconnect`` starts inside the sandbox is stopped
afterwards.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import pytest

from e2e.harness import fleet
from e2e.harness.processes import stop_pid_file
from e2e.harness.seed import HomeSeeder

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

LEVELS = ("readonly", "standard", "dangerous")
# Placeholder for every required string argument: matches no instance,
# bucket, site, path or token.
MISSING = "e2e-missing"
# Arguments that need a specific shape to stay inert.
ARGUMENT_OVERRIDES: dict[str, dict[str, Any]] = {
    # An empty list is rejected before any lookup service is contacted.
    "enrich_ips": {"ips": ""},
    # An allowlisted command, so the standard level reaches the tool itself.
    "run_command": {"command": "uptime"},
    "api_request": {"path": "/api/v1/me"},
}
# Tools the guard classifies above readonly that do not consult it yet.
UNGUARDED_AT_READONLY = ("api_request", "mcp_tool_call", "relay_reconnect")


def _catalogue(**gates: bool) -> list[str]:
    from servonaut.mcp.tool_schemas import mcp_tool_list

    return [tool.name for tool in mcp_tool_list(**gates)]


DEFAULT_GATES = {
    "have_ovh": False,
    "have_hetzner": False,
    "have_ip_ban": False,
    "have_memory": True,
}
DEFAULT_TOOLS = _catalogue(**DEFAULT_GATES)


def _allowed(level: str, tool: str) -> bool:
    """What the guard table says about *tool* at *level* (the oracle)."""
    from servonaut.config.schema import MCPConfig
    from servonaut.mcp.guards import CommandGuard

    return CommandGuard(MCPConfig(guard_level=level)).check_tool(tool)[0]


def minimal_arguments(name: str, schema: dict) -> dict[str, Any]:
    """Required arguments only, each with an inert placeholder."""
    properties = schema.get("properties", {})
    arguments: dict[str, Any] = {}
    for key in schema.get("required", []):
        spec = properties.get(key, {})
        kind = spec.get("type")
        if spec.get("enum"):
            arguments[key] = spec["enum"][0]
        elif kind == "array":
            arguments[key] = []
        elif kind == "object":
            arguments[key] = {}
        elif kind in ("integer", "number"):
            arguments[key] = spec.get("minimum", 1)
        elif kind == "boolean":
            arguments[key] = False
        else:
            arguments[key] = MISSING
    arguments.update(ARGUMENT_OVERRIDES.get(name, {}))
    return arguments


def _mcp_home(journey, *, guard_level: str | None = None, all_gates: bool = False):
    """A child home whose config selects the guard level and provider gates."""
    from servonaut.config.schema import HetznerConfig, IPBanConfig, MCPConfig, OVHConfig

    sandbox = journey.new_sandbox(f"mcp-{guard_level or 'default'}")
    overrides: dict[str, Any] = {}
    if guard_level:
        overrides["mcp"] = MCPConfig(guard_level=guard_level)
    if all_gates:
        overrides["ovh"] = OVHConfig(
            enabled=True,
            application_key="e2e-application-key",
            application_secret="e2e-application-secret",
            consumer_key="e2e-consumer-key",
        )
        overrides["hetzner"] = HetznerConfig(enabled=True, api_token="e2e-hetzner-token")
        overrides["ip_ban_configs"] = [
            IPBanConfig(name="edge-waf", method="waf", region="us-east-1", ip_set_name="e2e-set")
        ]
    seeder = HomeSeeder(sandbox.home, api_url=journey.fake_cloud.url)
    seeder.config(**overrides)
    seeder.cache(fleet.cache_rows(), fresh=True)
    return sandbox


def _audit_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


async def test_handshake_and_tool_list(mcp, journey, fake_cloud):
    sandbox = _mcp_home(journey)
    async with mcp(sandbox) as session:
        info = session.initialize_result.serverInfo
        names = await session.tool_names()
    assert info.name == "servonaut"
    assert names == DEFAULT_TOOLS
    assert len(names) == len(set(names))


@pytest.mark.skipif(
    importlib.util.find_spec("ovh") is None or importlib.util.find_spec("hcloud") is None,
    reason="needs the ovh and hetzner extras",
)
async def test_tool_list_with_every_provider_configured(mcp, journey, fake_cloud):
    sandbox = _mcp_home(journey, all_gates=True)
    async with mcp(sandbox) as session:
        names = await session.tool_names()
    everything = _catalogue(have_ovh=True, have_hetzner=True, have_ip_ban=True, have_memory=True)
    assert names == everything
    assert set(everything) > set(DEFAULT_TOOLS)


# ---------------------------------------------------------------------------
# Guard matrix: one server per level, every tool called once.
# ---------------------------------------------------------------------------


@dataclass
class Outcome:
    text: str
    audit: list[dict] = field(default_factory=list)
    seconds: float = 0.0


@dataclass
class LevelRun:
    """One server's answers at one guard level, shared by that level's tests."""

    folder: Path  # the run's evidence: answers, server stderr, cleanup note
    outcomes: dict[str, Outcome] = field(default_factory=dict)
    failure: Optional[str] = None  # why the run did not complete

    def attach_to(self, journey) -> None:
        """Copy the run's evidence into a journey's failure artifacts."""
        target = journey.staging / self.folder.name
        target.mkdir(parents=True, exist_ok=True)
        for item in self.folder.iterdir():
            if item.is_file():
                shutil.copyfile(item, target / item.name)


# Cached per process, including a failed run, so the other tests of a level
# fail at once instead of starting the server again.
_RUNS: dict[str, LevelRun] = {}


async def _call_every_tool(session, audit_file: Path, outcomes: dict[str, Outcome]) -> None:
    for tool in await session.tools():
        seen = len(_audit_rows(audit_file))
        started = time.monotonic()
        text = await session.call(tool.name, minimal_arguments(tool.name, tool.inputSchema))
        outcomes[tool.name] = Outcome(
            text, _audit_rows(audit_file)[seen:], time.monotonic() - started
        )
    seen = len(_audit_rows(audit_file))
    text = await session.call(
        "run_command", {"instance_id": fleet.APP_1.name, "command": "shutdown -h now"}
    )
    outcomes["<blocklist>"] = Outcome(text, _audit_rows(audit_file)[seen:])


async def _level_run(level: str, journey, mcp) -> LevelRun:
    """Start one server at *level* and call every tool once."""
    if level in _RUNS:
        return _RUNS[level]
    run = _RUNS[level] = LevelRun(folder=journey.ctx.root / "mcp-guard" / f"guard-{level}")
    run.folder.mkdir(parents=True, exist_ok=True)
    sandbox = _mcp_home(journey, guard_level=level)
    data_dir = sandbox.home / ".servonaut"
    try:
        async with mcp(sandbox, stderr_path=run.folder / "server.stderr.log") as session:
            await _call_every_tool(session, data_dir / "mcp_audit.jsonl", run.outcomes)
    except Exception as exc:  # noqa: BLE001 - reported by every test of the level
        run.failure = f"{type(exc).__name__}: {exc}"
    finally:
        # relay_reconnect may start a background listener; never leave it behind.
        note = stop_pid_file(data_dir / "relay.pid", sandbox_root=journey.ctx.root)
        (run.folder / "relay-cleanup.txt").write_text(note + "\n")
        (run.folder / "answers.json").write_text(
            json.dumps({k: vars(v) for k, v in run.outcomes.items()}, indent=2, default=str)
        )
    return run


async def _outcome(level: str, tool: str, journey, mcp) -> tuple[LevelRun, Outcome]:
    run = await _level_run(level, journey, mcp)
    if run.failure or tool not in run.outcomes:
        run.attach_to(journey)
        pytest.fail(
            f"the {level} MCP server run did not complete: "
            f"{run.failure or 'no answer for ' + tool}"
        )
    return run, run.outcomes[tool]


def _check_guard_outcome(level: str, tool: str, outcome: Outcome) -> None:
    refused = f"not available in {level} mode" in outcome.text
    detail = f"{tool} at {level}: {outcome.text[:300]!r} audit={outcome.audit}"
    if _allowed(level, tool):
        assert not refused, detail
        return
    assert refused, detail
    assert len(outcome.audit) == 1, detail
    assert outcome.audit[0]["allowed"] is False, detail
    assert outcome.audit[0]["reason"], detail


def _matrix_params() -> list:
    params = []
    for level in LEVELS:
        for tool in DEFAULT_TOOLS:
            marks = [pytest.mark.xdist_group(f"mcp-guard-{level}")]
            if level == "readonly" and tool in UNGUARDED_AT_READONLY:
                marks.append(
                    pytest.mark.xfail(
                        strict=True, reason="this backend tool does not check the guard level yet"
                    )
                )
            params.append(pytest.param(level, tool, marks=marks, id=f"{level}-{tool}"))
    return params


@pytest.mark.parametrize(("level", "tool"), _matrix_params())
async def test_guard_level_is_enforced(level, tool, mcp, journey, fake_cloud):
    run, outcome = await _outcome(level, tool, journey, mcp)
    try:
        _check_guard_outcome(level, tool, outcome)
    except AssertionError:
        run.attach_to(journey)
        raise


@pytest.mark.parametrize(
    "level",
    [
        pytest.param(level, marks=pytest.mark.xdist_group(f"mcp-guard-{level}"))
        for level in ("standard", "dangerous")
    ],
)
async def test_command_blocklist_applies_at_every_level(level, mcp, journey, fake_cloud):
    run, outcome = await _outcome(level, "<blocklist>", journey, mcp)
    try:
        assert outcome.text.startswith("Blocked: Command matches blocklist pattern"), outcome.text
        assert len(outcome.audit) == 1
        assert outcome.audit[0]["allowed"] is False
    except AssertionError:
        run.attach_to(journey)
        raise
