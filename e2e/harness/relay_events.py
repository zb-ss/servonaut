"""Relay events shaped like the service's publishes, and connection waits.

The builders produce the envelopes the service publishes on a listener's
Mercure topics; everything in them is a neutral placeholder.
:func:`wait_until_connected` waits until a ``servonaut connect`` listener
has subscribed, sent its handshake and said so.
"""

from __future__ import annotations

from typing import Any

from e2e.harness.waits import wait_for


def wait_until_connected(fake_cloud: Any, listener: Any) -> Any:
    """Wait until *listener* is subscribed to both of the account's topics,
    has sent its handshake and reported that it is connected; return the
    account's user id."""
    user_id = fake_cloud.entitlements()["user_id"]
    topics = [f"/cli/{user_id}/commands", f"/cli/{user_id}/ai-tool-calls"]
    alive = lambda: listener.running  # noqa: E731
    wait_for(
        lambda: any(s["topics"] == topics for s in fake_cloud.relay.subscriptions(live=True)),
        desc="a subscription to both topics",
        alive=alive,
    )
    wait_for(lambda: fake_cloud.relay.heartbeats(), desc="the handshake", alive=alive)
    wait_for(
        lambda: "Waiting for commands" in listener.output(),
        desc="the connected message",
        alive=alive,
    )
    return user_id


def wait_for_result(fake_cloud: Any, request_id: str, listener: Any) -> dict[str, Any]:
    """The first command result *listener* posted for *request_id*."""
    rows = wait_for(
        lambda: fake_cloud.relay.command_results(request_id),
        desc=f"the command result for {request_id}",
        alive=lambda: listener.running,
    )
    return rows[0]


def wait_for_tool_result(fake_cloud: Any, tool_call_id: str, listener: Any) -> dict[str, Any]:
    """The first chat tool result *listener* posted for *tool_call_id*."""
    rows = wait_for(
        lambda: fake_cloud.ai.tool_results(tool_call_id),
        desc=f"the tool result for {tool_call_id}",
        alive=lambda: listener.running,
    )
    return rows[0]


def command_event(
    request_id: str,
    user_id: object,
    command_type: str,
    target: str,
    payload: dict[str, Any],
    *,
    ttl_seconds: int = 20,
) -> dict[str, Any]:
    """A web-console command (``run_command``, ``get_logs``, ...)."""
    return {
        "id": request_id,
        "user_id": user_id,
        "type": command_type,
        "target_server_id": target,
        "payload": payload,
        "ttl_seconds": ttl_seconds,
    }


def tool_call_event(
    tool_call_id: str,
    user_id: object,
    tool: str,
    args: dict[str, Any],
    *,
    guard_level: str = "readonly",
    conversation_id: str = "conv-e2e-1",
) -> dict[str, Any]:
    """An AI chat tool call dispatched to the CLI."""
    return {
        "tool_call_id": tool_call_id,
        "user_id": user_id,
        "tool": tool,
        "args": args,
        "guard_level": guard_level,
        "conversation_id": conversation_id,
    }


def probe_event(request_id: str, user_id: object, tool: str, target: str = "") -> dict[str, Any]:
    """A monitoring probe (answered on the command-result route)."""
    return {
        "id": request_id,
        "user_id": user_id,
        "source": "proactive",
        "type": tool,
        "target_server_id": target,
        "payload": {},
    }


def remediation_event(
    request_id: str, user_id: object, verb: str, target: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """A confirmed remediation (answered on the command-result route)."""
    return {
        "id": request_id,
        "user_id": user_id,
        "source": "proactive_remediation",
        "type": verb,
        "target_server_id": target,
        "payload": payload,
    }
