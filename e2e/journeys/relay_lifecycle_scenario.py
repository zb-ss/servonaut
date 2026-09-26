"""A relay scenario that the harness self-test runs in a nested pytest process.

``pytest e2e`` does not collect this file (its name does not start with
``test_``). ``test_harness_relay.py`` runs one of its tests in a separate
pytest process: the test starts a foreground and a background relay
listener, records their PIDs in ``scenario-ready.json`` in its test root,
and then waits. The self-test ends that run the way a stuck, cancelled or
crashed run ends (time limit, ``SIGTERM``, ``SIGKILL``) and checks that no
listener survives it.
"""

from __future__ import annotations

import json
import time

import pytest

from e2e.harness.waits import wait_for

pytestmark = [pytest.mark.e2e_pr]

READY_FILE = "scenario-ready.json"
# Longer than the self-test waits: the run is always ended from outside.
HOLD_SECONDS = 120


@pytest.fixture
def held_listeners(fake_cloud, account_home, relay, e2e_ctx):
    """A foreground and a background listener, both heartbeating."""
    foreground = relay(account_home("foreground")).start()
    background = relay(account_home("background"))
    started = background.run("--bg")
    assert started.returncode == 0, started.describe()
    background_pid = wait_for(background.background_pid, desc="the background listener")
    wait_for(
        lambda: len({h["client_id"] for h in fake_cloud.relay.heartbeats()}) == 2,
        desc="both listeners heartbeating",
    )
    pids = {"foreground": foreground.pid, "background": background_pid}
    (e2e_ctx.root / READY_FILE).write_text(json.dumps(pids), encoding="utf-8")
    return pids


def test_hold_until_stopped(held_listeners):
    time.sleep(HOLD_SECONDS)


@pytest.mark.timeout(2, func_only=True)
def test_hold_past_the_time_limit(held_listeners):
    time.sleep(HOLD_SECONDS)
