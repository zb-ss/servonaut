"""Self-tests for the relay side of the harness.

* No relay listener outlives a run, however it ends: a journey over its
  time limit and a ``SIGTERM`` still tear down (fixtures stop the
  listeners), and a run killed outright is caught by the watchdog every
  child starts. A nested pytest process runs ``relay_lifecycle_scenario.py``
  and is ended from here.
* FakeCloud refuses what the service refuses: malformed heartbeats and
  results, and topics a subscriber token does not cover. Tokens are new
  after every reset, and each route belongs to one module.
* Failure artifacts keep JSON valid and hide the machine's host name.
"""

from __future__ import annotations

import json
import signal
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from aiohttp import web

from e2e.harness.bootstrap import E2E_DIR
from e2e.harness.processes import belongs_to_sandbox, stop_sandbox_pid
from e2e.harness.waits import wait_for

pytestmark = [pytest.mark.e2e_pr]

SCENARIO = E2E_DIR / "journeys" / "relay_lifecycle_scenario.py"
READY_FILE = "scenario-ready.json"
WATCHDOG_MESSAGE = "the test run that started this process is gone"


# ---------------------------------------------------------------------------
# Interrupted runs
# ---------------------------------------------------------------------------


def _ready(roots: Path):
    found = list(roots.glob(f"*/{READY_FILE}"))
    return json.loads(found[0].read_text(encoding="utf-8")) if found else None


def _nested_file(roots: Path, pattern: str) -> str:
    found = list(roots.glob(f"*/tests/*/{pattern}"))
    return found[0].read_text(encoding="utf-8", errors="replace") if found else ""


@pytest.mark.parametrize("ending", ["time-limit", "sigterm", "sigkill"])
def test_no_relay_listener_outlives_an_interrupted_run(ending, journey):
    sandbox = journey.new_sandbox("nested")
    roots = sandbox.base / "roots"
    roots.mkdir()
    env = journey.child_env(
        sandbox,
        SERVONAUT_E2E_ROOT=str(roots),
        SERVONAUT_E2E_KEEP="1",
        SERVONAUT_E2E_ARTIFACTS=str(sandbox.base / "artifacts"),
    )
    test = "test_hold_past_the_time_limit" if ending == "time-limit" else "test_hold_until_stopped"
    argv = [
        sys.executable, "-m", "pytest", f"{SCENARIO}::{test}",
        "-q", "-p", "no:cacheprovider", "-o", "addopts=",
    ]
    # In the staging folder, so a failure's artifacts include it.
    output_path = journey.staging / "nested-run.out"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as output:
        nested = subprocess.Popen(
            argv, stdout=output, stderr=subprocess.STDOUT, env=env, cwd=sandbox.base,
            start_new_session=True,
        )
    pids: list[int] = []
    try:
        ready = wait_for(
            lambda: _ready(roots),
            timeout=40,
            desc="the nested run's listeners",
            alive=lambda: nested.poll() is None or _ready(roots) is not None,
        )
        pids = [ready["foreground"], ready["background"]]
        if ending == "sigterm":
            nested.send_signal(signal.SIGTERM)
        elif ending == "sigkill":
            nested.kill()  # like os._exit: no teardown at all
        code = nested.wait(timeout=30)
        output = output_path.read_text(encoding="utf-8", errors="replace")

        wait_for(
            lambda: not any(belongs_to_sandbox(pid, sandbox.base) for pid in pids),
            timeout=5,
            desc="every listener of the nested run to exit",
        )
        cleanup_note = "relay cleanup:" in _nested_file(roots, "artifacts/children.log")
        if ending == "time-limit":
            assert code == 1 and "Timeout" in output, output
            assert cleanup_note, "the fixtures did not stop the listeners"
        elif ending == "sigterm":
            assert code == 2 and "KeyboardInterrupt" in output, output
            assert cleanup_note, "the fixtures did not stop the listeners"
        else:
            assert code == -signal.SIGKILL
            assert not cleanup_note
            # The foreground listener said why it stopped.
            assert WATCHDOG_MESSAGE in _nested_file(roots, "relay-1.out")
    finally:
        if nested.poll() is None:
            nested.kill()
            nested.wait(timeout=10)
        for pid in pids:
            stop_sandbox_pid(pid, sandbox_root=sandbox.base)


# ---------------------------------------------------------------------------
# FakeCloud fidelity
# ---------------------------------------------------------------------------


def _client(fake_cloud) -> httpx.Client:
    access, _ = fake_cloud.tokens()
    return httpx.Client(
        base_url=fake_cloud.url, headers={"Authorization": f"Bearer {access}"}, timeout=10
    )


def test_relay_routes_refuse_what_the_service_refuses(fake_cloud):
    handshake = {
        "type": "cli.handshake", "version": "0.0.0", "cli_release_channel": "stable",
        "providers_configured": [], "capabilities": {}, "client_id": "host-1a2b3c4d",
    }
    result = {
        "request_id": "cmd-1", "status": "success", "output": "", "error_message": "",
        "execution_time_ms": 5,
    }
    tool = {"conversation_id": "conv-1", "tool_call_id": "tc-1", "status": "ok",
            "result": "", "bytes": 0}
    with _client(fake_cloud) as client:
        assert client.post("/api/cli/heartbeat", json=handshake).status_code == 200
        for bad in ({"client_id": "host name"}, {"client_id": "x" * 65}, {"version": ""},
                    {"type": "cli.hello"}):
            answer = client.post("/api/cli/heartbeat", json={**handshake, **bad})
            assert answer.status_code == 422, bad
            assert answer.json()["error"]["code"] == "validation_failed"
        assert client.post("/api/cli/command-result/cmd-1", json=result).status_code == 200
        assert client.post("/api/cli/command-result/cmd-2", json=result).status_code == 422
        assert client.post(
            "/api/cli/command-result/cmd-1", json={**result, "status": "done"}
        ).status_code == 422
        assert client.post("/api/ai/chat/tool-result", json=tool).status_code == 202
        assert client.post(
            "/api/ai/chat/tool-result", json={**tool, "conversation_id": ""}
        ).status_code == 422
    assert len(fake_cloud.relay.heartbeats()) == 1
    assert len(fake_cloud.relay.command_results()) == 1
    assert len(fake_cloud.ai.tool_results()) == 1


def test_hub_serves_only_the_topics_the_token_covers(fake_cloud):
    user_id = fake_cloud.entitlements()["user_id"]
    own, other = f"/cli/{user_id}/commands", f"/cli/{user_id + 1}/commands"
    with _client(fake_cloud) as client:
        token = client.get("/api/cli/mercure-token").json()["token"]
        params = [("topic", own), ("topic", other), ("authorization", token)]
        with client.stream("GET", "/.well-known/mercure", params=params) as stream:
            assert stream.status_code == 200
            subscription = wait_for(
                lambda: fake_cloud.relay.subscriptions(live=True), desc="the subscription"
            )[0]
            assert subscription["requested"] == [own, other]
            assert subscription["topics"] == [own]
            fake_cloud.relay.publish({"id": "elsewhere"}, user_id=user_id + 1)
            fake_cloud.relay.publish({"id": "here"})
            wait_for(lambda: fake_cloud.relay.subscriptions()[0]["sent"], desc="delivery")
            assert fake_cloud.relay.subscriptions()[0]["sent"] == ["evt-2"]
        refused = client.get(
            "/.well-known/mercure", params=[("topic", own), ("authorization", "forged")]
        )
        assert refused.status_code == 401
    wait_for(lambda: not fake_cloud.relay.subscriptions(live=True), desc="stream closed")


def test_credentials_change_on_every_reset(fake_cloud):
    first_pair = fake_cloud.tokens()
    with _client(fake_cloud) as client:
        first_token = client.get("/api/cli/mercure-token").json()["token"]
    fake_cloud.reset()
    assert fake_cloud.tokens() != first_pair
    with _client(fake_cloud) as client:
        assert client.get("/api/cli/mercure-token").json()["token"] != first_token
        stale = client.get(
            "/.well-known/mercure", params=[("topic", "/cli/1/commands"),
                                            ("authorization", first_token)]
        )
        assert stale.status_code == 401
    with httpx.Client(base_url=fake_cloud.url, timeout=10) as client:
        old = client.get("/api/v1/me", headers={"Authorization": f"Bearer {first_pair[0]}"})
        assert old.status_code == 401


def test_a_path_can_belong_to_one_route_module_only():
    from e2e.harness.fake_cloud.app import require_unique_routes

    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_post("/api/ai/chat/tool-result", handler)
    app.router.add_get("/api/cli/status", handler)
    app.router.add_post("/api/ai/chat/tool-result", handler)
    with pytest.raises(RuntimeError, match="registered twice: POST /api/ai/chat/tool-result"):
        require_unique_routes(app)


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------


def test_artifacts_keep_nested_json_valid_and_hide_the_host_name(e2e_ctx):
    import re
    import socket

    from e2e.harness.artifacts import _rewrite, scrub

    document = {
        "token": {"value": "fake-nested"},
        "refresh_token": ["fake-listed"],
        "note": "see token=fake-inline in the log",
        "authorization": None,
        "tokens_used": 12,
    }
    for text in (json.dumps(document), json.dumps(document, indent=2)):
        scrubbed = json.loads(scrub(text))
        assert scrubbed["token"] == scrubbed["refresh_token"] == "<redacted>"
        assert "fake-inline" not in scrubbed["note"]
        assert scrubbed["authorization"] is None and scrubbed["tokens_used"] == 12

    host = socket.gethostname()
    client_id = re.sub(r"[^a-zA-Z0-9]+", "-", host).strip("-").lower()[:48] + "-1a2b3c4d"
    line = json.dumps({"client_id": client_id, "host": host})
    rewritten = json.loads(_rewrite(line, e2e_ctx))
    if len(host) >= 4 and host != "localhost":
        assert rewritten == {"client_id": "$HOSTNAME-1a2b3c4d", "host": "$HOSTNAME"}
