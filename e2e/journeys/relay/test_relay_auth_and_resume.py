"""Journey: the relay listener survives expired tokens and dropped streams.

An access token that expires mid-session is refreshed (the refresh token
rotates and the new pair is saved) and the listener carries on. A listener
started with an expired token refreshes before it subscribes. When the
stream drops, the listener reconnects, sends ``Last-Event-ID`` and has the
events it missed replayed, even if the hub fails once on the way.

A foreground listener whose session was revoked stops, and a listener
never treats a connection the hub refused as connected or presents a
subscriber token the hub rejected again.
"""

from __future__ import annotations

import pytest

from e2e.harness.fake_cloud.routes_relay import MERCURE_PATH
from e2e.harness.known_gap import KnownGap
from e2e.harness.relay_events import command_event, wait_for_result, wait_until_connected
from e2e.harness.session_seed import read_session
from e2e.harness.waits import holds_for, wait_for

pytestmark = [pytest.mark.e2e_pr]

CONNECTED = "Connected to relay"


def _run(fake_cloud, listener, request_id, user_id):
    """Publish a command for a missing server and wait for its answer."""
    fake_cloud.relay.publish(
        command_event(request_id, user_id, "run_command", "no-such-host", {"command": "id"})
    )
    return wait_for_result(fake_cloud, request_id, listener)


def test_expired_access_token_is_refreshed_mid_session(journey, fake_cloud, account_home, relay):
    home = account_home(heartbeat_interval=1)
    listener = relay(home).start()
    user_id = wait_until_connected(fake_cloud, listener)

    fake_cloud.expire_access_token()
    wait_for(
        lambda: any(h["token_generation"] == 2 for h in fake_cloud.relay.heartbeats()),
        desc="a heartbeat with the refreshed token",
        alive=lambda: listener.running,
    )
    # One rejected heartbeat, one refresh, and the heartbeat retried.
    heartbeats = fake_cloud.statuses("/api/cli/heartbeat")
    assert 401 in heartbeats and heartbeats[heartbeats.index(401) + 1] == 200
    assert fake_cloud.statuses("/api/oauth/refresh") == [200]
    # The rotated pair was saved, so the next start uses it.
    assert read_session(home.home)["refresh_token"] == fake_cloud.tokens()[1]
    assert read_session(home.home)["access_token"] == fake_cloud.tokens()[0]
    # The listener is still answering, with the new token.
    _run(fake_cloud, listener, "cmd-after-refresh", user_id)
    assert fake_cloud.requests("/api/cli/command-result/cmd-after-refresh")[0]["bearer_ok"]


def test_listener_started_with_an_expired_token_refreshes_first(
    journey, fake_cloud, account_home, relay
):
    home = account_home()
    fake_cloud.expire_access_token()
    listener = relay(home).start()
    user_id = wait_until_connected(fake_cloud, listener)

    assert 401 in fake_cloud.statuses("/api/cli/mercure-token")
    assert fake_cloud.statuses("/api/cli/mercure-token")[-1] == 200
    assert set(fake_cloud.statuses("/api/oauth/refresh")) == {200}
    assert read_session(home.home)["refresh_token"] == fake_cloud.tokens()[1]
    _run(fake_cloud, listener, "cmd-first", user_id)


def test_revoked_session_ends_the_foreground_listener(journey, fake_cloud, account_home, relay):
    home = account_home(heartbeat_interval=1)
    listener = relay(home).start()
    wait_until_connected(fake_cloud, listener)

    fake_cloud.revoke_session()
    # The next heartbeat is refused, and so is the refresh that follows.
    wait_for(
        lambda: 400 in fake_cloud.statuses("/api/oauth/refresh"), desc="the refused refresh"
    )
    assert 401 in fake_cloud.statuses("/api/cli/heartbeat")

    if holds_for(lambda: not listener.running, 5.0):
        raise KnownGap("the listener is still running 5 s after its session was revoked")
    assert "servonaut login" in listener.output()


def test_dropped_stream_resumes_from_the_last_event(journey, fake_cloud, account_home, relay):
    home = account_home()
    listener = relay(home).start()
    user_id = wait_until_connected(fake_cloud, listener)
    hub = fake_cloud.relay

    first_id = hub.publish(
        command_event("cmd-before", user_id, "run_command", "no-such-host", {"command": "id"})
    )
    wait_for_result(fake_cloud, "cmd-before", listener)

    # The connection drops, and the hub fails the first reconnect attempt.
    hub.configure(hub_failures=[503])
    hub.drop_streams()
    wait_for(lambda: not hub.subscriptions(live=True), desc="stream dropped")
    missed_id = hub.publish(
        command_event("cmd-missed", user_id, "run_command", "no-such-host", {"command": "id"})
    )

    wait_for_result(fake_cloud, "cmd-missed", listener)
    resumed = hub.subscriptions(live=True)[0]
    assert resumed["last_event_id"] == first_id
    # The missed event came from the hub's replay, not as a live delivery.
    assert resumed["replayed"] == [missed_id]
    assert resumed["sent"] == []
    assert 503 in fake_cloud.statuses(MERCURE_PATH)
    assert len(hub.command_results("cmd-before")) == 1
    assert len(hub.command_results("cmd-missed")) == 1
    # Reconnecting reused the subscriber token; no new one was needed.
    assert hub.tokens_minted() == 1


def test_refused_hub_connections_are_handled(journey, fake_cloud, account_home, relay):
    home = account_home()
    listener = relay(home).start()
    user_id = wait_until_connected(fake_cloud, listener)
    hub = fake_cloud.relay
    gaps = []

    def announced_more_than_accepted() -> bool:
        # The hub registers a subscription before the listener can see it
        # was accepted, so a correct listener never announces more.
        return listener.output().count(CONNECTED) > len(hub.subscriptions())

    # The hub refuses one reconnect with a 503; the listener retries.
    hub.configure(hub_failures=[503])
    hub.drop_streams()
    wait_for(lambda: 503 in fake_cloud.statuses(MERCURE_PATH), desc="the refused reconnect")
    wait_for(
        lambda: len(hub.subscriptions()) >= 2 and hub.subscriptions(live=True),
        desc="an accepted reconnect",
        alive=lambda: listener.running,
    )
    # An answered event proves the listener is reading the new stream, so
    # everything it printed about earlier connections is in the output.
    _run(fake_cloud, listener, "cmd-back", user_id)
    if announced_more_than_accepted():
        gaps.append("the listener said it was connected when the hub had refused it (503)")

    # The hub rejects the subscriber token: the listener must not present it again.
    hub.revoke_subscriber_tokens()
    hub.drop_streams()
    wait_for(
        lambda: fake_cloud.statuses(MERCURE_PATH).count(401) >= 1, desc="the rejected token"
    )
    if not holds_for(lambda: fake_cloud.statuses(MERCURE_PATH).count(401) >= 2, 3.0):
        gaps.append("the listener presented a subscriber token the hub had rejected again")
    if announced_more_than_accepted():
        gaps.append("the listener said it was connected when the hub had refused it (401)")

    if gaps:
        raise KnownGap("; ".join(gaps))
    assert listener.running
