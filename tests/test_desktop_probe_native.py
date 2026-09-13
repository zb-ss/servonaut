"""Opt-in native renderer smoke test; no browser-engine substitute is accepted."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

psutil = pytest.importorskip("psutil")
pytest.importorskip("webview")

from scripts.desktop_probe.config import load_config


def running(process: psutil.Process) -> bool:
    try:
        return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


@pytest.mark.skipif(
    os.environ.get("SERVONAUT_DESKTOP_NATIVE_TEST") != "1",
    reason="Run python -m scripts.desktop_probe.check --native to open a window",
)
def test_native_first_frame_and_process_tree_cleanup() -> None:
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
        assert process.poll() is not None, "Native window did not exit before deadline"
        output, _ = process.communicate(timeout=config.shutdown_seconds)
        assert process.returncode == 0, "Native renderer failed; check OS prerequisites"
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
        # Only processes observed under this launch are eligible for cleanup.
        for child in [*descendants, process]:
            try:
                if running(child):
                    child.kill()
            except psutil.NoSuchProcess:
                pass
        process.wait(timeout=config.shutdown_seconds)
