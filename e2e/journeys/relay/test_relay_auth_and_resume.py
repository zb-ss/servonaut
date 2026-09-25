"""Journey: the relay listener survives expired tokens and dropped streams.

An access token that expires mid-session is refreshed (the refresh token
rotates and the new pair is saved) and the listener carries on. A listener
started with an expired token refreshes before it subscribes. When the
stream drops, the listener reconnects, sends ``Last-Event-ID`` and receives
what it missed, even if the hub fails once on the way.

Two known gaps are recorded as strict expected failures: a listener whose
session was revoked keeps running without heartbeats, and a subscriber
token the hub rejects is reused instead of replaced.
"""

from __future__ import annotations

import pytest

from e2e.harness.account import command_event, read_session, wait_for

pytestmark = [pytest.mark.e2e_pr]


def _connected(fake_cloud, listener):
    wait_for(
        lambda: fake_cloud.relay.subscriptions(live=True) and fake_cloud.relay.heartbeats(),
        desc="subscription and handshake",
        alive=lambda: listener.running,
    )
    return fake_cloud.entitlements()["user_id"]


def _statuses(fake_cloud, path):
    return [r["status"] for r in fake_cloud.requests(path)]


def _run(fake_cloud, listener, request_id, user_id):
    """Publish a command for a missing server and wait for its answer."""
    fake_cloud.relay.publish(
        command_event(request_id, user_id, "run_command", "no-such-host", {"command": "id"})
    )
    return wait_for(
        lambda: fake_cloud.relay.command_results(request_id),
        desc=f"result {request_id}",
        alive=lambda: listener.running,
    )


def test_expired_access_token_is_refreshed_mid_session(journey, fake_cloud, account_home, relay):
    home = account_home(heartbeat_interval=1)
    listener = relay(home).start()
    user_id = _connected(fake_cloud, listener)

    fake_cloud.expire_access_token()
    wait_for(
        lambda: any(h["token_generation"] == 2 for h in fake_cloud.relay.heartbeats()),
        desc="a heartbeat with the refreshed token",
        alive=lambda: listener.running,
    )
    # One rejected heartbeat, one refresh, and the heartbeat retried.
    heartbeats = _statuses(fake_cloud, "/api/cli/heartbeat")
    assert 401 in heartbeats and heartbeats[heartbeats.index(401) + 1] == 200
    assert _statuses(fake_cloud, "/api/oauth/refresh") == [200]
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
    user_id = _connected(fake_cloud, listener)

    assert 401 in _statuses(fake_cloud, "/api/cli/mercure-token")
    assert _statuses(fake_cloud, "/api/cli/mercure-token")[-1] == 200
    assert set(_statuses(fake_cloud, "/api/oauth/refresh")) == {200}
    assert read_session(home.home)["refresh_token"] == fake_cloud.tokens()[1]
    _run(fake_cloud, listener, "cmd-first", user_id)


@pytest.mark.xfail(
    strict=True,
    reason="a foreground listener keeps running silently after its session is revoked",
)
def test_revoked_session_ends_the_foreground_listener(journey, fake_cloud, account_home, relay):
    home = account_home(heartbeat_interval=1)
    listener = relay(home).start()
    _connected(fake_cloud, listener)

    fake_cloud.revoke_session()
    wait_for(
        lambda: not listener.running, timeout=6, desc="the listener to exit",
    )
    assert "servonaut login" in listener.output()


def test_dropped_stream_resumes_from_the_last_event(journey, fake_cloud, account_home, relay):
    home = account_home()
    listener = relay(home).start()
    user_id = _connected(fake_cloud, listener)
    hub = fake_cloud.relay

    first_id = hub.publish(
        command_event("cmd-before", user_id, "run_command", "no-such-host", {"command": "id"})
    )
    wait_for(lambda: hub.command_results("cmd-before"), desc="first result")

    # The connection drops, and the hub fails the first reconnect attempt.
    hub.configure(hub_failures=[503])
    hub.drop_streams()
    wait_for(lambda: not hub.subscriptions(live=True), desc="stream dropped")
    missed_id = hub.publish(
        command_event("cmd-missed", user_id, "run_command", "no-such-host", {"command": "id"})
    )

    wait_for(
        lambda: hub.command_results("cmd-missed"),
        timeout=10,
        desc="the missed event after reconnecting",
        alive=lambda: listener.running,
    )
    resumed = hub.subscriptions(live=True)[0]
    assert resumed["last_event_id"] == first_id
    assert resumed["sent"] == [missed_id]
    assert 503 in _statuses(fake_cloud, "/.well-known/mercure")
    assert len(hub.command_results("cmd-before")) == 1
    assert len(hub.command_results("cmd-missed")) == 1
    # Reconnecting reused the subscriber token; no new one was needed.
    assert hub.tokens_minted() == 1


@pytest.mark.xfail(
    strict=True,
    reason="a subscriber token the hub rejects is reused instead of replaced",
)
def test_rejected_subscriber_token_is_replaced(journey, fake_cloud, account_home, relay):
    home = account_home()
    listener = relay(home).start()
    _connected(fake_cloud, listener)
    hub = fake_cloud.relay

    hub.revoke_subscriber_tokens()
    hub.drop_streams()
    wait_for(
        lambda: hub.subscriptions(live=True) and hub.tokens_minted() == 2,
        timeout=6,
        desc="a new subscriber token and subscription",
        alive=lambda: listener.running,
    )

