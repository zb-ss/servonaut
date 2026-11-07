"""Relay diagnostics use real demo redaction and retain literal native output."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from textual.content import Content
from textual.widgets import Button, Static

from servonaut.app import ServonautApp
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.services.redaction_service import RedactionService
from servonaut.services.relay_manager import RelayState
from servonaut.widgets.busy_indicator import BusyIndicator
from servonaut.widgets.relay_indicator import RelayStatusScreen
from tests._async_bounds import wait_until
from tests.test_relay_status_presentation import _painted
from tests.test_workspace_account_leaf import (
    _AccountHost,
    _inert_boundaries as _inert_boundaries,
)


REAL_NAME = "private-node"
PAYLOAD = (
    "private-node /home/operator/cache "  # leak-guard:allow - synthetic fixture exercises demo redaction.
    "https://relay.example.test/status?detail=hidden "
    "[$text-error]literal[/$text-error] [unmatched"
)
# Independently pinned fixture expectations, not computed through the display
# function being tested. The stable name stand-in follows the public hash rule.
MASKED = (
    "link-replica-22 /home/user/cache https://example.com/status "
    "[$text-error]literal[/$text-error] [unmatched"
)
PRIVATE_PARTS = (REAL_NAME, "/home/operator", "relay.example.test", "detail=hidden")  # leak-guard:allow - synthetic fixture exercises demo redaction.


def _host(demo: bool) -> _AccountHost:
    app = _AccountHost()
    # The native host inherits the actual app contract; no expected-value stub.
    assert app.redact_display_text.__func__ is ServonautApp.redact_display_text
    assert app._demo_known_identifiers.__func__ is ServonautApp._demo_known_identifiers
    app.demo_mode = demo
    app.redaction_service = RedactionService() if demo else None
    app.replace_instances(None, [{
        "id": "id-private-node", "name": REAL_NAME, "type": "small",
        "state": "running", "is_custom": True, "host": "node.example.test",
        "public_ip": "192.0.2.10", "private_ip": "10.0.0.1",
        "region": "local", "key_name": "",
    }])
    assert app.redact_display_text(PAYLOAD) == (MASKED if demo else PAYLOAD)
    return app


def _expected(path: str, demo: bool) -> str:
    value = MASKED if demo else PAYLOAD
    if path == "local":
        return "Local: error\n" + value
    if path in {"exception", "response"}:
        return "Backend: error — " + value
    heartbeat = "just now" if path == "valid-heartbeat" else value
    return "Backend: connected · last heartbeat " + heartbeat


def _compact(text: str) -> str:
    """Ignore only terminal wrap whitespace; exact publisher text is separate."""
    return "".join(text.split())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path", ["local", "exception", "response", "heartbeat", "valid-heartbeat"],
)
@pytest.mark.parametrize("publisher", ["captured", "direct"])
@pytest.mark.parametrize("demo", [False, True])
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
async def test_relay_dynamic_diagnostics_use_demo_redaction_and_paint_literal_text(
    path: str, publisher: str, demo: bool, size: tuple[int, int], monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered, release = asyncio.Event(), asyncio.Event()

    async def status() -> str:
        entered.set()
        await release.wait()
        if path == "exception":
            raise RuntimeError(PAYLOAD)
        if path == "response":
            return json.dumps({"error": {"message": PAYLOAD}})
        payload: dict[str, object] = {"connected": True, "client_ids": []}
        if path in {"heartbeat", "valid-heartbeat"}:
            # A future timestamp pins the unchanged valid relative-age branch.
            payload["last_heartbeat_at"] = (
                "2999-01-01T00:00:00Z" if path == "valid-heartbeat" else PAYLOAD
            )
        return json.dumps(payload)

    read = AsyncMock(side_effect=status)
    monkeypatch.setattr(
        "servonaut.widgets.relay_indicator._build_mcp_tools_for_this_app",
        lambda app: SimpleNamespace(relay_status=read),
    )
    monkeypatch.setattr(
        "servonaut.services.relay_lock.read_owner",
        lambda path: SimpleNamespace(pid=None),
    )
    app = _host(demo)
    app.relay_state = RelayState.ERROR if path == "local" else RelayState.CONNECTED
    app.relay_manager.last_error = PAYLOAD if path == "local" else None
    async with app.run_test(size=size) as pilot:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        origin = app.screen
        screen = RelayStatusScreen()
        await app.push_screen(screen)
        await wait_until(lambda: entered.is_set() and all(
            bool(screen.query("#" + name))
            for name in ("local_status", "backend_status", "relay_backend_busy", "btn_relay_close")
        ))
        busy = screen.query_one("#relay_backend_busy", BusyIndicator)
        assert busy.is_active
        worker = next(worker for worker in app.workers if worker.name == "relay_modal_backend")
        assert worker.node is screen and not worker.is_finished
        release.set()
        await wait_until(lambda: worker.is_finished and not busy.is_active)
        if publisher == "direct":
            # Preserve the existing no-target caller shape as well as the
            # normal screen worker's captured-target publisher branch.
            await screen._refresh_backend()
        assert read.await_count == (2 if publisher == "direct" else 1)
        target = screen.query_one(
            "#local_status" if path == "local" else "#backend_status", Static,
        )
        expected = _expected(path, demo)
        content = target.content
        assert isinstance(content, Content)
        assert content.plain == expected
        if path == "local":
            assert any(span.style == "bold" for span in content.spans)
            assert any(span.style == "$text-error" for span in content.spans)
        elif path in {"heartbeat", "valid-heartbeat"}:
            assert any(span.style == "$text-success" for span in content.spans)
        else:
            assert not content.spans  # Payload theme tags remain literal.
        await pilot.pause()
        target.scroll_visible(animate=False, immediate=True)
        await pilot.pause()
        paint = _painted(app, target)
        assert _compact(expected) in _compact(paint)
        if demo and path != "valid-heartbeat":
            assert all(value not in content.plain and value not in paint for value in PRIVATE_PARTS)
        if path != "valid-heartbeat":
            assert "[$text-error]literal[/$text-error] [unmatched" in content.plain
        for name, label in (
            ("btn_relay_restart", "Restart"), ("btn_relay_stop", "Stop"),
            ("btn_relay_close", "Close"),
        ):
            button = screen.query_one("#" + name, Button)
            assert screen.region.contains_region(button.region)
            assert app.get_widget_at(*button.region.center)[0] is button
            assert label in _painted(app, button)
        if publisher == "captured":
            assert await pilot.click("#btn_relay_close")
        else:
            await pilot.press("escape")
        await wait_until(lambda: app.screen is origin and not any(
            worker.node is screen for worker in app.workers
        ))
        app.relay_manager.restart.assert_not_awaited()
        app.relay_manager.stop.assert_not_awaited()
        assert app._exception is None
