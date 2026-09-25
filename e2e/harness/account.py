"""Signed-in homes, relay events and condition waits for the account journeys.

:func:`seed_session` writes ``auth.json`` through the real ``AuthToken``
dataclass, holding the token pair FakeCloud currently accepts and the
entitlements it serves, so a journey can start signed in without running the
device flow; :func:`seed_relay_config` points a home's relay at FakeCloud.
The event builders produce the envelopes the service publishes on a
listener's Mercure topics. Everything is a neutral placeholder.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

T = TypeVar("T")

DEFAULT_TIMEOUT = 10.0


def auth_file(home: Path) -> Path:
    return home / ".servonaut" / "auth.json"


def seed_session(home: Path, fake_cloud: Any, *, expires_in: float = 3600.0) -> Path:
    """Sign *home* in with FakeCloud's current session; return ``auth.json``."""
    from servonaut.services.auth_service import AuthToken

    access, refresh = fake_cloud.tokens()
    entitlements = fake_cloud.entitlements()
    now = time.time()
    token = AuthToken(
        access_token=access,
        refresh_token=refresh,
        expires_at=now + expires_in,
        plan=entitlements["plan"],
        email="",
        entitlements=entitlements,
        entitlements_fetched_at=now,
        user_id=entitlements["user_id"],
    )
    path = auth_file(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(token), indent=2), encoding="utf-8")
    path.chmod(0o600)
    return path


def seed_relay_config(
    seeder: Any, *, heartbeat_interval: Optional[int] = None, **overrides: Any
) -> Any:
    """Save a config (through *seeder*, a ``HomeSeeder``) whose relay points at
    FakeCloud, optionally with a short heartbeat interval."""
    relay_config = seeder.build_config().relay
    if heartbeat_interval is not None:
        relay_config.heartbeat_interval = heartbeat_interval
    return seeder.config(relay=relay_config, **overrides)


def read_session(home: Path) -> Optional[dict[str, Any]]:
    """The ``auth.json`` a home holds, or None when signed out."""
    path = auth_file(home)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def wait_for(
    predicate: Callable[[], T],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    desc: str = "condition",
    alive: Optional[Callable[[], bool]] = None,
) -> T:
    """Poll *predicate* until it is truthy and return its value.

    For journeys that drive child processes: *alive*, when given, must stay
    true (a child that exits early fails the wait at once).
    """
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if alive is not None and not alive():
            raise AssertionError(f"the process exited while waiting for {desc}")
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout:.0f}s waiting for {desc}")
        time.sleep(0.02)


async def wait_for_async(
    predicate: Callable[[], T], *, timeout: float = DEFAULT_TIMEOUT, desc: str = "condition"
) -> T:
    """:func:`wait_for` for async journeys: yields to the event loop between polls."""
    import asyncio

    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout:.0f}s waiting for {desc}")
        await asyncio.sleep(0.02)


# ---------------------------------------------------------------------------
# Relay events, shaped like the service's publishes
# ---------------------------------------------------------------------------


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
