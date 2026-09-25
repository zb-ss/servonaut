"""Journey: run the relay listener in the background and manage it.

``servonaut connect --bg`` detaches a listener that heartbeats to the (fake)
service; ``--status`` shows the local and the service's view side by side;
a second ``--bg`` is refused; ``--reconnect`` replaces the listener;
``--stop`` ends it, and ``--status`` then explains that the service still
shows it for a while. A foreground ``connect`` refuses to start while the
background listener holds the relay.
"""

from __future__ import annotations

import re

import pytest

from e2e.harness.waits import wait_for

pytestmark = [pytest.mark.e2e_pr]


def _started_pid(result) -> int:
    match = re.search(r"Relay listener started in background \(PID (\d+)\)", result.stdout)
    assert match, result.describe()
    return int(match.group(1))


def _heartbeat_from_new_client(fake_cloud, seen: set[str]) -> str:
    """Wait for a heartbeat from a listener not seen before; return its id."""
    def new_client():
        ids = {h.get("client_id") for h in fake_cloud.relay.heartbeats()} - seen
        return next(iter(ids), None)

    client_id = wait_for(new_client, desc="a heartbeat from the new listener")
    seen.add(client_id)
    return client_id


def test_background_start_status_reconnect_and_stop(journey, fake_cloud, account_home, relay):
    home = account_home()
    connect = relay(home)
    seen: set[str] = set()

    started = connect.run("--bg")
    assert started.returncode == 0, started.describe()
    pid = _started_pid(started)
    assert connect.background_pid() == pid
    first_client = _heartbeat_from_new_client(fake_cloud, seen)
    wait_for(lambda: connect.armed(pid), desc="background listener guard armed")
    assert connect.lock_owner()["pid"] == pid
    assert connect.lock_owner()["mode"] == "bg"

    status = connect.run("--status")
    assert status.returncode == 0, status.describe()
    assert f"Local view:   running (mode=bg, PID {pid})" in status.stdout
    assert "Backend view: connected" in status.stdout
    assert first_client in status.stdout

    again = connect.run("--bg")
    assert f"Relay listener already running (PID {pid})" in again.stdout
    assert connect.background_pid() == pid

    # A foreground listener cannot take over while the background one runs.
    blocked = connect.run()
    assert blocked.returncode == 2, blocked.describe()
    assert "Another relay listener is already active (mode=bg" in blocked.stdout

    reconnect = connect.run("--reconnect")
    assert reconnect.returncode == 0, reconnect.describe()
    assert f"Stopped relay listener (PID {pid})" in reconnect.stdout
    new_pid = _started_pid(reconnect)
    assert new_pid != pid
    _heartbeat_from_new_client(fake_cloud, seen)

    stopped = connect.run("--stop")
    assert f"Stopped relay listener (PID {new_pid})" in stopped.stdout
    assert connect.background_pid() is None
    assert connect.lock_owner() is None
    wait_for(
        lambda: not fake_cloud.relay.subscriptions(live=True), desc="subscription closed"
    )

    # The service keeps a stopped listener "connected" until its heartbeat
    # ages out; the status command says so instead of contradicting itself.
    after = connect.run("--status")
    assert "Local view:   not running" in after.stdout
    assert "Backend view: connected" in after.stdout
    assert "backend still reports a recent connection" in after.stdout

    fake_cloud.relay.configure(status_ttl=0)
    aged = connect.run("--status")
    assert "Backend view: disconnected" in aged.stdout
    assert "NOTE" not in aged.stdout and "WARNING" not in aged.stdout

    nothing = connect.run("--stop")
    assert "No relay listener PID file found" in nothing.stdout


def test_status_warns_when_the_service_does_not_see_the_listener(
    journey, fake_cloud, account_home, relay
):
    home = account_home()
    connect = relay(home)
    started = connect.run("--bg")
    pid = _started_pid(started)
    _heartbeat_from_new_client(fake_cloud, set())

    fake_cloud.relay.configure(status_ttl=0)  # heartbeats stop "landing"
    status = connect.run("--status")
    assert f"running (mode=bg, PID {pid})" in status.stdout
    assert "Backend view: disconnected" in status.stdout
    assert "WARNING: listener is running locally but the backend does not see it" in (
        status.stdout
    )


def test_status_signed_out_shows_only_the_local_view(journey, fake_cloud, account_home, relay):
    home = account_home(signed_in=False)
    connect = relay(home)

    status = connect.run("--status")
    assert status.returncode == 0, status.describe()
    assert "Local view:   not running" in status.stdout
    assert "Backend view: unavailable (not logged in" in status.stdout

    foreground = connect.run()
    assert foreground.returncode == 1, foreground.describe()
    assert "no Servonaut session found" in foreground.stdout
    assert fake_cloud.relay.subscriptions() == []
