"""Opt-in native renderer smoke test; no browser-engine substitute is accepted."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import replace

import pytest

psutil = pytest.importorskip("psutil")
pytest.importorskip("webview")

from scripts.desktop_probe.config import load_config


def running(process: psutil.Process) -> bool:
    try:
        return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def kill_running(processes: Iterable[psutil.Process]) -> None:
    """Only terminate process identities observed under this test's launch."""
    for process in processes:
        try:
            if running(process):
                process.kill()
        except psutil.NoSuchProcess:
            pass


@pytest.mark.skipif(
    os.environ.get("SERVONAUT_DESKTOP_NATIVE_TEST") != "1",
    reason="Run python -m scripts.desktop_probe.check --native to open a window",
)
def test_native_first_frame_and_process_tree_cleanup(
    record_property: Callable[[str, object], None],
) -> None:
    config = load_config()
    command = [sys.executable, "-m", "scripts.desktop_probe", "--smoke"]
    renderer = os.environ.get("SERVONAUT_PROBE_RENDERER")
    if renderer:
        command.extend(["--renderer", renderer])
    process = psutil.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    descendants: set[psutil.Process] = set()
    try:
        deadline = (
            time.monotonic() + config.startup_seconds + config.shutdown_seconds * 4
        )
        while process.poll() is None and time.monotonic() < deadline:
            try:
                descendants.update(process.children(recursive=True))
            except psutil.NoSuchProcess:
                break  # The launcher exited between poll() and the tree snapshot.
            time.sleep(config.probe_poll_seconds)
        timed_out = process.poll() is None
        if timed_out:
            # Native helpers can inherit stdout; stop them too before waiting
            # for pipe EOF, or the timeout would hide the captured stages.
            kill_running([*descendants, process])
        output, _ = process.communicate(timeout=config.shutdown_seconds)
        records = [
            json.loads(line)
            for line in output.decode().splitlines()
            if line.startswith('{"')
        ]
        expected = {
            "native_first_frame",
            "host_stopped",
            "child_exit_ok",
            "graceful_child_stop",
            "port_released",
        }
        stages = {
            "host-ready",
            "window-loaded",
            "bootstrap-injected",
            "first-frame",
            "gui-starting",
            "gui-stopped",
        }
        record_property(
            "native_stages",
            [
                record["native_stage"]
                for record in records
                if set(record) == {"native_stage"} and record["native_stage"] in stages
            ],
        )
        for record in records:
            if set(record) == {"child_errors"}:
                record_property("child_errors", record["child_errors"])
            elif set(record) == {"child_transport"}:
                record_property("child_transport", record["child_transport"])
            elif set(record) == expected and all(
                type(value) is bool for value in record.values()
            ):
                record_property("native_result", record)
        assert not timed_out, "Native window did not exit before deadline"
        assert process.returncode == 0, "Native renderer failed; check OS prerequisites"
        assert any(
            set(record) == expected and all(value is True for value in record.values())
            for record in records
        )
        deadline = time.monotonic() + config.shutdown_seconds
        while (
            any(running(child) for child in descendants) and time.monotonic() < deadline
        ):
            time.sleep(config.probe_poll_seconds)
        assert not any(running(child) for child in descendants), (
            "Native renderer left a running child"
        )
    finally:
        kill_running([*descendants, process])
        process.wait(timeout=config.shutdown_seconds)


def test_native_timeout_keeps_stages_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_popen = psutil.Popen
    observed: list[psutil.Process] = []
    properties: dict[str, object] = {}
    source = """
import subprocess, sys, time
subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
print('{"native_stage":"host-ready"}', flush=True)
time.sleep(60)
"""

    def unresponsive_window(command: list[str], **kwargs: object) -> psutil.Popen:
        process = real_popen([sys.executable, "-c", source], **kwargs)
        observed.append(process)
        return process

    real_kill = kill_running

    def capture_and_kill(processes: Iterable[psutil.Process]) -> None:
        processes = list(processes)
        observed.extend(processes)
        real_kill(processes)

    # Shorten only this synthetic hang; real native checks retain full deadlines.
    config = replace(load_config(), startup_seconds=0.1, shutdown_seconds=1)
    monkeypatch.setattr(psutil, "Popen", unresponsive_window)
    monkeypatch.setattr(sys.modules[__name__], "load_config", lambda: config)
    monkeypatch.setattr(sys.modules[__name__], "kill_running", capture_and_kill)
    with pytest.raises(AssertionError, match="Native window did not exit"):
        test_native_first_frame_and_process_tree_cleanup(properties.__setitem__)
    assert properties["native_stages"] == ["host-ready"]
    assert len(set(observed)) >= 2  # The launcher and its inherited-stdout helper.
    assert not any(running(process) for process in observed)
