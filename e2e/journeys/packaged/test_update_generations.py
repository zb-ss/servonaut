"""Installed pipx launches and generation lifetime over the real entry points."""

import asyncio
import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

from e2e.harness import fleet
from e2e.harness.bootstrap import DEAD_HTTPS_URL
from e2e.harness.installs import ENV_PYPI_URL, build_wheel, copy_sources
from e2e.harness.processes import mcp_session, require_armed
from e2e.journeys.packaged import support
from servonaut.updates.layout import python_for
from servonaut.updates.processes import birth

pytestmark = [pytest.mark.e2e_pr, pytest.mark.timeout(300)]


def _state(sandbox) -> tuple[Path, dict]:
    directory, = (sandbox.home / ".servonaut" / "updates" / "installs").iterdir()
    return directory, json.loads((directory / "state.json").read_text())


def _wait_ready(sandbox, version):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        directory, state = _state(sandbox)
        ready = state.get("ready")
        if ready and state["generations"][ready]["version"] == version:
            return directory, ready
        if state.get("status") in {"failed", "rolled_back"} and "builder" not in state:
            pytest.fail(f"Generation build failed: {state.get('failure')}\n"
                        f"{(directory / 'builder.log').read_text()[-3500:]}")
        time.sleep(0.05)
    pytest.fail(f"Generation {version} was not ready. Last state: {state}")


def _wait_for_state(sandbox, description, condition):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        directory, state = _state(sandbox)
        if condition(directory, state):
            return state
        time.sleep(0.05)
    pytest.fail(f"Waiting for {description}. Last state: {state}")


def _boot(installs, sandbox, pipx):
    return support.boot_tui(installs, sandbox, pipx.console, support.fleet_names())


def _launch(pipx, sandbox):
    support.ok(pipx.run(sandbox, "--list-backups"))


def _present_offer(installs, sandbox, pipx, version):
    return support.boot_tui(installs, sandbox, pipx.console, [f"Update to v{version}"])


def _worker_is_reaped(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


def _interrupt_mcp_launches(installs, sandbox, pipx, directory, generation):
    children = []
    try:
        for _ in range(20):
            children.append(subprocess.Popen(
                [str(pipx.console), "--mcp"], cwd=sandbox.base, env=installs.env(sandbox),
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ))

        def acknowledged(directory, _state):
            leases = json.loads((directory / "leases.json").read_text())
            return all(
                (row := leases.get(str(child.pid), {})).get("generation") == generation
                and (directory / "acks" / row["id"]).is_file()
                for child in children
            )

        _wait_for_state(sandbox, "all 20 concurrent MCP starts acknowledged", acknowledged)
        for child in children:
            require_armed(installs.armed_log, pid=child.pid)
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
        for child in children:
            child.communicate(timeout=10)
    _launch(pipx, sandbox)
    assert _state(sandbox)[1]["current"] == generation
    leases = json.loads((directory / "leases.json").read_text())
    assert all(str(child.pid) not in leases for child in children)


@pytest.fixture
def active_pipx(journey, installs, current_wheel, build_version, pipx_available):
    sandbox = journey.new_sandbox()
    installs.offer(current_wheel, version=build_version)
    pipx = installs.pipx(sandbox)
    support.ok(pipx.install(sandbox, "servonaut[mcp]"))
    support.seed(installs, sandbox, pipx.python)
    installs.extra_env["SERVONAUT_SKIP_AUTO_APPLY"] = "0"
    _boot(installs, sandbox, pipx)
    directory, first = _wait_ready(sandbox, build_version)
    _launch(pipx, sandbox)
    assert support.reported_version(pipx, sandbox) == build_version
    assert _state(sandbox)[1]["current"] == first
    (directory / "preferences.json").write_text(json.dumps({"check_interval_seconds": 0.01}))
    return sandbox, pipx, directory, first


@pytest.mark.asyncio
async def test_switch_keeps_running_mcp_pinned(
    active_pipx, installs, current_wheel, newer_wheel, build_version, newer_version,
):
    sandbox, pipx, directory, first = active_pipx
    for module in ("argparse", "types"):
        (sandbox.base / f"{module}.py").write_text("raise AssertionError(\"unexpected working-directory import\")\n")
    assert support.reported_version(pipx, sandbox) == build_version
    preferences_path = directory / "preferences.json"
    preferences = json.loads(preferences_path.read_text())
    preferences["status_poll_seconds"] = 0.1
    preferences_path.write_text(json.dumps(preferences))
    installs.offer(current_wheel, newer_wheel, version=newer_version)
    async with mcp_session(
        [str(pipx.console)], env=installs.env(sandbox), cwd=sandbox.base,
        stderr_path=sandbox.base / "mcp-stderr.log", armed_log=installs.armed_log,
    ) as server:
        tools_before = await server.tool_names()
        assert tools_before
        running = await asyncio.to_thread(
            _wait_for_state, sandbox, "discovery started by the MCP launch",
            lambda _directory, state: "builder" in state,
        )
        worker_pid = running["builder"]["pid"]
        _, second = await asyncio.to_thread(_wait_ready, sandbox, newer_version)
        if os.name != "nt":
            await asyncio.to_thread(
                _wait_for_state, sandbox, "MCP discovery worker reaped",
                lambda _directory, _state: _worker_is_reaped(worker_pid),
            )
        assert _state(sandbox)[1]["current"] == first
        await asyncio.to_thread(_present_offer, installs, sandbox, pipx, newer_version)
        assert _state(sandbox)[1]["current"] == first
        assert len((await server.session.call_tool("whoami")).content) == 1
        await asyncio.to_thread(_launch, pipx, sandbox)
        assert await asyncio.to_thread(support.reported_version, pipx, sandbox) == newer_version
        assert _state(sandbox)[1]["current"] == second
        expected = (
            f"Servonaut is running {build_version}. {newer_version} is installed. "
            "Reconnect this MCP server to use it."
        )

        async def wait_for_notice():
            while expected not in await server.call("whoami"):
                await asyncio.sleep(0.1)

        await asyncio.wait_for(wait_for_notice(), timeout=10)
        whoami = (await server.session.call_tool("whoami")).content
        assert "logged_in" in json.loads(whoami[0].text)
        assert whoami[1].text == expected
        assert whoami[1].meta["servonaut.dev/reason"] == "pipx_generation_current"
        assert expected in await server.call("check_status", {"instance_id": fleet.APP_1.instance_id})
        assert expected in await server.call("list_instances")
        assert expected not in await server.call("list_instances")
        leases = json.loads((directory / "leases.json").read_text())
        assert any(row["role"] == "mcp" and row["generation"] == first
                   and row["version"] == build_version for row in leases.values())
        assert await server.tool_names() == tools_before
        assert not server.protocol_errors
        assert (directory / "generations" / first).is_dir()
        async with mcp_session(
            [str(pipx.console)], env=installs.env(sandbox), cwd=sandbox.base,
            stderr_path=sandbox.base / "mcp-new-stderr.log", armed_log=installs.armed_log,
        ) as new_server:
            assert await new_server.tool_names() == tools_before
            assert expected not in await new_server.call("whoami")
            assert not new_server.protocol_errors
            leases = json.loads((directory / "leases.json").read_text())
            assert any(row["role"] == "mcp" and row["generation"] == second
                       and row["version"] == newer_version for row in leases.values())
    (directory / "preferences.json").write_text("{}")
    for _attempt in range(3):
        result = await asyncio.to_thread(pipx.run, sandbox, "--no-such-flag")
        assert result.returncode == 2
    await asyncio.to_thread(_launch, pipx, sandbox)
    assert _state(sandbox)[1]["current"] == second
    if os.name != "nt":
        await asyncio.to_thread(_interrupt_mcp_launches, installs, sandbox, pipx, directory, second)


def test_manual_pipx_upgrade_prepares_new_launcher_when_healthy(
    active_pipx, installs, current_wheel, newer_wheel, build_version, newer_version,
):
    sandbox, pipx, _, first = active_pipx
    installs.offer(current_wheel, newer_wheel, version=newer_version)
    support.ok(pipx.pipx(sandbox, "upgrade", "servonaut"))
    assert support.reported_version(pipx, sandbox) == newer_version
    assert _state(sandbox)[1]["current"] == first
    _boot(installs, sandbox, pipx)
    _wait_ready(sandbox, newer_version)
    _launch(pipx, sandbox)
    assert support.reported_version(pipx, sandbox) == newer_version
    # The sandbox supplies dependencies through the overlay and serves only Servonaut wheels.
    support.ok(pipx.pipx(
        sandbox, "install", "--force", "--pip-args=--no-deps", f"servonaut[mcp]=={build_version}",
    ))
    _launch(pipx, sandbox)
    assert support.reported_version(pipx, sandbox) == build_version
    assert _state(sandbox)[1]["pin"] == {"version": build_version, "from": newer_version}


def test_first_offer_can_be_postponed_once(
    active_pipx, installs, current_wheel, newer_wheel, build_version, newer_version,
):
    sandbox, pipx, _, first = active_pipx
    installs.offer(current_wheel, newer_wheel, version=newer_version)
    _present_offer(installs, sandbox, pipx, newer_version)
    _wait_ready(sandbox, newer_version)
    result = support.ok(installs.runner().run(sandbox, [
        str(pipx.python), "-c",
        "import sys; from servonaut.updates.status import postpone_update; "
        "print(postpone_update(sys.argv[1])); print(postpone_update(sys.argv[1]))",
        newer_version,
    ]))
    assert result.stdout.splitlines() == ["True", "False"]
    assert support.reported_version(pipx, sandbox) == build_version
    assert _state(sandbox)[1]["current"] == first


def test_cli_only_offer_promotes_after_the_postpone_window(
    active_pipx, installs, current_wheel, newer_wheel, build_version, newer_version,
):
    sandbox, pipx, directory, first = active_pipx
    installs.offer(current_wheel, newer_wheel, version=newer_version)
    readonly = [(path, path.read_bytes()) for path in (directory / "state.json", directory / "leases.json")]
    assert support.reported_version(pipx, sandbox) == build_version
    assert support.ok(pipx.run(sandbox, "--help")).stdout.startswith("usage: servonaut ")
    assert all(path.read_bytes() == content for path, content in readonly)
    _launch(pipx, sandbox)
    _, ready = _wait_ready(sandbox, newer_version)
    assert support.reported_version(pipx, sandbox) == build_version
    state = _wait_for_state(sandbox, "idle builder", lambda _directory, state: "builder" not in state)
    assert state["current"] == first
    assert "presented_at" not in state
    (directory / "preferences.json").write_text(json.dumps({"postpone_max_seconds": 0.001}))
    _launch(pipx, sandbox)
    assert support.reported_version(pipx, sandbox) == newer_version
    assert _state(sandbox)[1]["current"] == ready


def test_stale_withdrawn_stage_is_refused_by_next_launch(
    active_pipx, installs, fake_cloud, current_wheel, newer_wheel, build_version, newer_version,
):
    sandbox, pipx, directory, first = active_pipx
    installs.offer(current_wheel, newer_wheel, version=newer_version)
    _present_offer(installs, sandbox, pipx, newer_version)
    _, withdrawn = _wait_ready(sandbox, newer_version)
    fake_cloud.configure(pypi_yanked_files=[newer_wheel.name])
    (directory / "preferences.json").write_text(json.dumps({"validation_max_age_seconds": 0.001}))
    # Admission validates the exact stale candidate before switching.
    _launch(pipx, sandbox)
    assert support.reported_version(pipx, sandbox) == build_version
    state = _wait_for_state(
        sandbox, "withdrawal revalidation",
        lambda _directory, state: "ready" not in state and "builder" not in state,
    )
    assert state["current"] == first
    assert state["failure"]["version"] == newer_version
    assert withdrawn != state["current"]


def test_healthy_generation_starts_offline(active_pipx, installs, build_version):
    sandbox, pipx, _, first = active_pipx
    installs.extra_env[ENV_PYPI_URL] = f"{DEAD_HTTPS_URL}/pypi/servonaut/json"
    installs.extra_env["PIP_INDEX_URL"] = f"{DEAD_HTTPS_URL}/simple/"
    _boot(installs, sandbox, pipx)
    state = _wait_for_state(
        sandbox, "failed offline check",
        lambda _directory, state: state.get("status") == "failed" and "builder" not in state,
    )
    assert state["current"] == first
    assert support.reported_version(pipx, sandbox) == build_version


def test_failed_startup_probe_keeps_healthy_current(
    active_pipx, installs, current_wheel, build_version, newer_version,
):
    sandbox, pipx, _, first = active_pipx
    source = copy_sources(installs.root / "broken-source", version=newer_version)
    app = source / "src" / "servonaut" / "app.py"
    app.write_text("raise RuntimeError(\"test startup import failure\")\n")
    broken = build_wheel(installs.runner(), sandbox, source, installs.root / "broken-wheel", sdist=False)
    installs.offer(current_wheel, broken, version=newer_version)
    _boot(installs, sandbox, pipx)
    state = _wait_for_state(
        sandbox, "failed probe",
        lambda _directory, state: state.get("status") == "failed" and "builder" not in state,
    )
    assert state["current"] == first
    assert "did not pass its startup check" in state["failure"]["message"]
    assert "ready" not in state
    assert support.reported_version(pipx, sandbox) == build_version


def test_unleased_generation_is_collected_and_previous_remains_available(
    active_pipx, installs, current_wheel, newer_wheel, newer_version,
):
    sandbox, pipx, directory, first = active_pipx
    installs.offer(current_wheel, newer_wheel, version=newer_version)
    _present_offer(installs, sandbox, pipx, newer_version)
    _, second = _wait_ready(sandbox, newer_version)
    _launch(pipx, sandbox)
    assert support.reported_version(pipx, sandbox) == newer_version
    major, minor, patch = newer_version.split(".")
    third_version = f"{major}.{minor}.{int(patch) + 1}"
    source = copy_sources(installs.root / "third-source", version=third_version)
    third_wheel = build_wheel(
        installs.runner(), sandbox, source, installs.root / "third-wheel", sdist=False,
    )
    installs.offer(current_wheel, newer_wheel, third_wheel, version=third_version)
    _present_offer(installs, sandbox, pipx, third_version)
    _, third = _wait_ready(sandbox, third_version)
    _launch(pipx, sandbox)
    assert support.reported_version(pipx, sandbox) == third_version
    _boot(installs, sandbox, pipx)
    state = _wait_for_state(
        sandbox, "collection of the oldest generation",
        lambda _directory, state: first not in state["generations"],
    )
    assert state["current"] == third
    assert state["previous"] == second
    assert not (directory / "generations" / first).exists()
    (directory / "preferences.json").write_text("{}")
    executable = python_for(directory / "generations" / third)
    executable.unlink()
    if os.name != "nt":
        # Keep an executable path so exec succeeds. Only the missing
        # startup acknowledgement can trigger the rollback.
        executable.write_text("#!/bin/sh\nexit 7\n")
        executable.chmod(0o700)
        for _attempt in range(2):
            assert pipx.run(sandbox, "--list-backups").returncode == 7
            assert _state(sandbox)[1]["current"] == third
    _launch(pipx, sandbox)
    assert support.reported_version(pipx, sandbox) == newer_version
    state = _state(sandbox)[1]
    assert state["current"] == second
    assert state["status"] == "rolled_back"
    if os.name != "nt":
        assert "repeatedly failed to start" in state["failure"]["message"]


@pytest.mark.skipif(os.name == "nt", reason="interrupts a worker with POSIX SIGKILL")
def test_interrupted_build_is_retried_in_a_fresh_generation(
    active_pipx, installs, fake_cloud, current_wheel, newer_wheel, build_version, newer_version,
):
    sandbox, pipx, directory, first = active_pipx
    installs.offer(current_wheel, newer_wheel, version=newer_version)
    fake_cloud.configure(pypi_download_delay=3.0)
    _boot(installs, sandbox, pipx)

    def downloading(directory, state):
        generation = state.get("builder", {}).get("generation")
        return generation and any((directory / "generations" / generation).glob("wheel-*"))

    state = _wait_for_state(sandbox, "wheel download in progress", downloading)
    builder = state["builder"]
    os.kill(builder["pid"], signal.SIGKILL)
    fake_cloud.configure(pypi_download_delay=0.0)
    assert support.reported_version(pipx, sandbox) == build_version
    _wait_for_state(sandbox, "old worker exit", lambda _directory, _state: birth(builder["pid"]) is None)
    _present_offer(installs, sandbox, pipx, newer_version)
    _, ready = _wait_ready(sandbox, newer_version)
    assert ready != builder["generation"]
    assert not (directory / "generations" / builder["generation"]).exists()
    assert _state(sandbox)[1]["current"] == first
    _launch(pipx, sandbox)
    assert support.reported_version(pipx, sandbox) == newer_version
