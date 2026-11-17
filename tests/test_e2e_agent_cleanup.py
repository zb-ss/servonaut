"""Ownership checks must never turn a stale agent ledger into a broad kill."""

import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import re
from unittest.mock import Mock

import pytest

if os.name == "nt":
    pytest.skip("OpenSSH agent lifecycle uses POSIX processes", allow_module_level=True)

from e2e.harness import agent_cleanup
from e2e.harness import openssh_agent_shim
from servonaut.services.vault.ssh_agent import PrivateSshAgent


def test_process_identity_accepts_setgid_agent_without_reading_exe(tmp_path, monkeypatch):
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "self").mkdir()
    pid = 123456
    entry = proc / str(pid)
    entry.mkdir()
    # Fields through Linux /proc stat field 22 (the start timestamp).
    (entry / "stat").write_text(f"{pid} (ssh-agent) S " + " ".join(["0"] * 18) + " 45678")
    (entry / "cmdline").write_bytes(b"/usr/bin/ssh-agent\0-a\0/tmp/test.sock\0-s\0")
    original = agent_cleanup.Path
    monkeypatch.setattr(agent_cleanup, "Path", lambda value: original(str(value).replace("/proc", str(proc), 1)))

    assert agent_cleanup.process_identity(pid, "/usr/bin/ssh-agent", "/tmp/test.sock") == "45678"
    assert agent_cleanup.process_identity(pid, "/usr/bin/ssh-agent", "/tmp/other.sock") is None


@pytest.mark.parametrize("replacement", [None, "reused-pid"])
def test_stale_record_never_signals_an_unrelated_process(tmp_path, monkeypatch, replacement):
    (tmp_path / agent_cleanup.LEDGER_NAME).write_text(json.dumps({
        "pid": 123456, "executable": "/usr/bin/ssh-agent", "socket": "/tmp/test.sock",
        "started": "original", "shim_dir": "tools",
    }) + "\n")
    monkeypatch.setattr(agent_cleanup, "process_identity", lambda *args: replacement)
    # Avoid opening any real PID in this synthetic identity test.
    monkeypatch.delattr(agent_cleanup.os, "pidfd_open", raising=False)
    kill = Mock()
    monkeypatch.setattr(agent_cleanup.os, "kill", kill)

    agent_cleanup.stop_owned_agents(tmp_path)

    kill.assert_not_called()


def test_agents_from_another_journey_are_left_running(tmp_path):
    agent = PrivateSshAgent.start()
    try:
        # PrivateSshAgent launches by PATH; the guarded shim uses an absolute
        # executable. Match the actual argv[0] of this direct unit-test launch.
        executable = "ssh-agent"
        agent_cleanup.record_agent(tmp_path, tmp_path / "first", agent.pid, executable, str(agent.socket_path))
        agent_cleanup.stop_owned_agents(tmp_path, shim_dir=tmp_path / "second")
        assert agent_cleanup.owns_agent(tmp_path, agent.pid, executable, str(agent.socket_path))
        agent_cleanup.stop_owned_agents(tmp_path, shim_dir=tmp_path / "first")
        assert agent_cleanup.process_identity(agent.pid, executable, str(agent.socket_path)) is None
    finally:
        agent.close()


def test_teardown_cannot_overtake_a_launch_before_its_pid_is_recorded(monkeypatch):
    real_run = subprocess.run
    finished = threading.Event()
    errors, owned, threads, overtook = [], [], [], []
    executable = str(Path(shutil.which("ssh-agent")).resolve())
    with tempfile.TemporaryDirectory(prefix="svt", dir="/tmp") as value:
        root = Path(value)
        def cleanup():
            try:
                agent_cleanup.stop_owned_agents(root)
            except BaseException as exc:
                errors.append(exc)
            finally:
                finished.set()

        def launch(*args, **kwargs):
            result = real_run(*args, **kwargs)
            pid = int(re.search(r"SSH_AGENT_PID=(\d+);", result.stdout)[1])
            owned.append({"pid": pid, "executable": executable, "socket": str(root / "agent.sock"),
                          "started": agent_cleanup.process_identity(pid, executable, str(root / "agent.sock"))})
            worker = threading.Thread(target=cleanup)
            threads.append(worker)
            worker.start()
            # Force cleanup into the native-start/registration boundary.
            # It must wait for the launch lock, rather than observe no PID.
            overtook.append(finished.wait(0.2))
            return result

        monkeypatch.setattr(openssh_agent_shim.subprocess, "run", launch)
        try:
            assert openssh_agent_shim._start_agent(str(root / "tools"), executable, str(root),
                                                  ["-a", str(root / "agent.sock"), "-s"]) == 0
            assert finished.wait(10), "teardown did not finish after registration"
            assert not errors
            assert overtook == [False], "teardown passed the unrecorded native daemon"
            assert agent_cleanup.process_identity(owned[0]["pid"], executable, owned[0]["socket"]) is None
        finally:
            for worker in threads:
                worker.join(10)
            for record in owned:
                agent_cleanup._stop_record(record)


@pytest.mark.parametrize("scope", ["root", "journey"])
def test_closed_owner_refuses_a_late_start_before_launching_a_daemon(tmp_path, monkeypatch, scope):
    shim_dir = tmp_path / "tools"
    agent_cleanup.stop_owned_agents(tmp_path, shim_dir=shim_dir if scope == "journey" else None)
    run = Mock(side_effect=AssertionError("a closed owner must not create another daemon"))
    monkeypatch.setattr(openssh_agent_shim.subprocess, "run", run)

    with pytest.raises(RuntimeError, match="owner is closing"):
        openssh_agent_shim._start_agent(str(shim_dir), "/usr/bin/ssh-agent", str(tmp_path),
                                      ["-a", str(tmp_path / "agent.sock"), "-s"])

    run.assert_not_called()


@pytest.mark.parametrize("ending, status", [("success", 0), ("failure", 1), ("interrupt", 2)])
@pytest.mark.parametrize("keep", [False, True], ids=["removed", "kept"])
def test_vault_journey_teardown_stops_unclosed_agent(ending, status, keep):
    repo = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(repo), str(repo / "src")]),
           "SERVONAUT_E2E_KEEP": str(int(keep))}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", f"e2e/probes/agent_lifecycle.py::test_{ending}", "-q", "-s"],
        cwd=repo, env=env, capture_output=True, text=True, timeout=90, check=False,
    )
    line = next((line for line in result.stdout.splitlines() if line.startswith("AGENT_PROBE ")), None)
    assert line is not None, result.stdout + result.stderr
    record = json.loads(line.removeprefix("AGENT_PROBE "))
    try:
        assert record["started"] is not None, result.stdout + result.stderr
        assert Path(record["implementation"]) == repo / "src/servonaut/services/vault/ssh_agent.py"
        assert result.returncode == status, result.stdout + result.stderr
        assert agent_cleanup.process_identity(record["pid"], record["executable"], record["socket"]) is None, (
            result.stdout + result.stderr
        )
        assert Path(record["root"]).exists() == keep
    finally:
        # The child explicitly reported this launch; never scan other runs.
        agent_cleanup._stop_record(record)
        shutil.rmtree(record["root"], ignore_errors=True)
