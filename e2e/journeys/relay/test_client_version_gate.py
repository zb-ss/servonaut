"""Journey: client-version gate behavior in the standalone relay listener.

Under ``mode="enforce"`` with a server minimum newer than the running client,
``servonaut connect`` receives HTTP 426, prints the install-specific update
message once, stops cleanly with exit code 5 (``RELAY_EXIT_UPDATE_REQUIRED``),
never enters a retry loop, and never attempts an OAuth token refresh.

Under ``mode="log"`` with the same minimum, the relay connects and heartbeats
normally with zero HTTP 426 responses.
"""

from __future__ import annotations

import pytest

from e2e.harness.relay_events import wait_until_connected
from e2e.harness.waits import wait_for
from servonaut.main import RELAY_EXIT_UPDATE_REQUIRED
from servonaut.services.version_policy import parse_client_signal

pytestmark = [pytest.mark.e2e_pr]

MINIMUM_VERSION = "99.0.0"


def test_relay_stops_with_exit_5_and_does_not_retry_on_426(
    journey, fake_cloud, account_home, relay, cli,
):
    fake_cloud.set_client_version_policy(mode="enforce", minimum_version=MINIMUM_VERSION)
    home = account_home("relay-version-gate-enforce", heartbeat_interval=1)

    status = cli(home, "connect", "--status")
    assert status.returncode == 0, status.describe()
    assert "Backend view: disconnected" in status.stdout
    assert fake_cloud.statuses("/api/cli/status") == [200]

    listener = relay(home).start()
    wait_for(
        lambda: not listener.running,
        timeout=15.0,
        desc="relay stops after HTTP 426 client_update_required",
    )

    assert listener.returncode == RELAY_EXIT_UPDATE_REQUIRED == 5
    output = listener.output()
    assert "too old for team and cloud features" in output, output
    assert MINIMUM_VERSION in output, output
    assert not fake_cloud.relay.subscriptions(live=True)
    assert fake_cloud.requests("/api/oauth/refresh") == []

    refusals = [
        req for req in fake_cloud.requests()
        if req["path"].startswith("/api/cli/") and req["path"] != "/api/cli/status"
    ]
    # The heartbeat and subscribe loops can each have one request in flight.
    paths = {request["path"] for request in refusals}
    assert paths and paths <= {"/api/cli/heartbeat", "/api/cli/mercure-token"}
    assert len(refusals) == len(paths), refusals
    assert all(req["status"] == 426 for req in refusals)
    assert all(parse_client_signal(req["client_header"])[2] == "relay" for req in refusals)


def test_relay_connects_normally_in_log_mode(journey, fake_cloud, account_home, relay):
    fake_cloud.set_client_version_policy(mode="log", minimum_version=MINIMUM_VERSION)
    home = account_home("relay-version-gate-log", heartbeat_interval=1)

    listener = relay(home).start()
    wait_until_connected(fake_cloud, listener)

    assert listener.running
    assert not any(req["status"] == 426 for req in fake_cloud.requests())
    (token,) = fake_cloud.requests("/api/cli/mercure-token")
    heartbeat = wait_for(
        lambda: fake_cloud.requests("/api/cli/heartbeat"), desc="a logged relay heartbeat",
    )
    for request in [token, *heartbeat]:
        assert request["status"] == 200 and request["below_minimum"] is True
        assert parse_client_signal(request["client_header"])[2] == "relay"
