"""Tests for AWSManagerScreen — loading, state logic, keyboard gating, pilot mount."""

from __future__ import annotations

import asyncio
from typing import List, Optional
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from servonaut.screens.aws_manager import AWSManagerScreen, _RUNNING, _STOPPED, _TERMINAL
from servonaut.services.redaction_service import RedactionService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_app(
    *,
    aws_service=None,
    demo_mode: bool = False,
    redaction_service=None,
    instances: Optional[List[dict]] = None,
):
    app = MagicMock()
    app.demo_mode = demo_mode
    app.redaction_service = redaction_service
    app.aws_service = aws_service
    app.aws_audit = None
    app.instances = instances or []
    return app


def _sample_instances() -> List[dict]:
    return [
        {"id": "i-0abc12345678def90", "name": "web-prod", "type": "t3.medium",
         "state": "running", "public_ip": "54.1.2.3", "region": "us-east-1"},
        {"id": "i-0def12345678abc90", "name": "api-staging", "type": "t3.small",
         "state": "stopped", "public_ip": None, "region": "us-west-2"},
        {"id": "i-0ghi12345678xyz90", "name": "bastion", "type": "t3.micro",
         "state": "terminated", "public_ip": None, "region": "us-east-1"},
    ]


# ---------------------------------------------------------------------------
# TestLoadInstancesRedaction
# ---------------------------------------------------------------------------

class TestLoadInstancesRedaction:
    """_load_instances redacts in demo mode."""

    @pytest.mark.asyncio
    async def test_redacts_in_demo_mode(self) -> None:
        mock_svc = MagicMock()
        mock_svc.fetch_instances_cached = AsyncMock(return_value=_sample_instances())
        redaction = RedactionService()
        app = _mock_app(aws_service=mock_svc, demo_mode=True, redaction_service=redaction)

        screen = AWSManagerScreen()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_render_table"), \
             patch.object(screen, "_set_status"):
            await screen._load_instances()

        # After redaction, instance names should differ from originals
        assert screen._instances[0]["name"] != "web-prod"

    @pytest.mark.asyncio
    async def test_no_redaction_without_demo_mode(self) -> None:
        instances = _sample_instances()
        mock_svc = MagicMock()
        mock_svc.fetch_instances_cached = AsyncMock(return_value=instances)
        app = _mock_app(aws_service=mock_svc, demo_mode=False)

        screen = AWSManagerScreen()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_render_table"), \
             patch.object(screen, "_set_status"):
            await screen._load_instances()

        assert screen._instances[0]["name"] == "web-prod"


# ---------------------------------------------------------------------------
# TestSyncActionButtons
# ---------------------------------------------------------------------------

class TestSyncActionButtons:
    """_sync_action_buttons correctly enables/disables based on state."""

    def _make_screen_with_instance(self, state: str) -> AWSManagerScreen:
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = [
            {"id": "i-0abc12345678def90", "name": "test", "type": "t3.micro",
             "state": state, "public_ip": None, "region": "us-east-1"}
        ]
        screen._loading = False
        return screen

    def test_running_enables_stop_reboot_not_start(self) -> None:
        screen = self._make_screen_with_instance("running")
        btn_states = {}

        class FakeBtn:
            def __init__(self, initial=True):
                self.disabled = initial

        btns = {
            "btn_aws_mgr_start": FakeBtn(True),
            "btn_aws_mgr_stop": FakeBtn(True),
            "btn_aws_mgr_reboot": FakeBtn(True),
            "btn_aws_mgr_terminate": FakeBtn(True),
        }

        from textual.widgets import DataTable, Button
        mock_table = MagicMock()
        mock_table.cursor_row = 0

        def query_one_side_effect(selector, *args):
            if "table" in selector:
                return mock_table
            btn_id = selector.lstrip("#")
            return btns.get(btn_id, FakeBtn())

        with patch.object(screen, "query_one", side_effect=query_one_side_effect):
            screen._sync_action_buttons()

        assert btns["btn_aws_mgr_start"].disabled is True   # stopped only
        assert btns["btn_aws_mgr_stop"].disabled is False    # running → enabled
        assert btns["btn_aws_mgr_reboot"].disabled is False  # running → enabled
        assert btns["btn_aws_mgr_terminate"].disabled is False

    def test_stopped_enables_start_only(self) -> None:
        screen = self._make_screen_with_instance("stopped")
        btns = {
            "btn_aws_mgr_start": MagicMock(),
            "btn_aws_mgr_stop": MagicMock(),
            "btn_aws_mgr_reboot": MagicMock(),
            "btn_aws_mgr_terminate": MagicMock(),
        }
        for b in btns.values():
            b.disabled = True

        mock_table = MagicMock()
        mock_table.cursor_row = 0

        def query_one_side_effect(selector, *args):
            if "table" in selector:
                return mock_table
            btn_id = selector.lstrip("#")
            return btns.get(btn_id, MagicMock())

        with patch.object(screen, "query_one", side_effect=query_one_side_effect):
            screen._sync_action_buttons()

        # start: enabled (not disabled)
        assert btns["btn_aws_mgr_start"].disabled is False
        # stop/reboot: disabled (not running)
        assert btns["btn_aws_mgr_stop"].disabled is True
        assert btns["btn_aws_mgr_reboot"].disabled is True

    def test_terminal_disables_all(self) -> None:
        screen = self._make_screen_with_instance("terminated")
        btns = {
            "btn_aws_mgr_start": MagicMock(),
            "btn_aws_mgr_stop": MagicMock(),
            "btn_aws_mgr_reboot": MagicMock(),
            "btn_aws_mgr_terminate": MagicMock(),
        }
        for b in btns.values():
            b.disabled = False

        mock_table = MagicMock()
        mock_table.cursor_row = 0

        def query_one_side_effect(selector, *args):
            if "table" in selector:
                return mock_table
            btn_id = selector.lstrip("#")
            return btns.get(btn_id, MagicMock())

        with patch.object(screen, "query_one", side_effect=query_one_side_effect):
            screen._sync_action_buttons()

        for b in btns.values():
            assert b.disabled is True


# ---------------------------------------------------------------------------
# TestKeyboardGating (ISSUE-4)
# ---------------------------------------------------------------------------

class TestKeyboardGating:
    """Keyboard actions enforce state checks (ISSUE-4 fix)."""

    def _make_screen_with_inst(self, state: str) -> tuple:
        inst = {"id": "i-0abc12345678def90", "name": "test", "type": "t3.micro",
                "state": state, "public_ip": None, "region": "us-east-1"}
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = [inst]
        screen._loading = False
        app = _mock_app()
        return screen, app, inst

    def test_start_blocked_on_running_instance(self) -> None:
        screen, app, inst = self._make_screen_with_inst("running")
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=inst), \
             patch.object(screen, "_run_lifecycle") as mock_lc, \
             patch.object(screen, "notify") as mock_notify:
            screen.action_start()
        mock_lc.assert_not_called()
        mock_notify.assert_called_once()

    def test_start_allowed_on_stopped_instance(self) -> None:
        screen, app, inst = self._make_screen_with_inst("stopped")
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=inst), \
             patch.object(screen, "_run_lifecycle") as mock_lc, \
             patch.object(screen, "notify"):
            screen.action_start()
        mock_lc.assert_called_once()

    def test_stop_blocked_on_stopped_instance(self) -> None:
        screen, app, inst = self._make_screen_with_inst("stopped")
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=inst), \
             patch.object(screen, "_run_lifecycle") as mock_lc, \
             patch.object(screen, "notify") as mock_notify:
            screen.action_stop()
        mock_lc.assert_not_called()

    def test_terminate_blocked_on_terminal_state(self) -> None:
        screen, app, inst = self._make_screen_with_inst("terminated")
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=inst), \
             patch.object(screen, "run_worker") as mock_rw, \
             patch.object(screen, "notify") as mock_notify:
            screen.action_terminate()
        mock_rw.assert_not_called()
        mock_notify.assert_called_once()

    def test_terminate_allowed_on_running_instance(self) -> None:
        screen, app, inst = self._make_screen_with_inst("running")
        captured_coros = []
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=inst), \
             patch.object(screen, "run_worker",
                          side_effect=lambda coro, **kw: captured_coros.append(coro)) as mock_rw, \
             patch.object(screen, "notify"):
            screen.action_terminate()
        for coro in captured_coros:
            coro.close()
        mock_rw.assert_called_once()


# ---------------------------------------------------------------------------
# TestNoneServiceGuidance
# ---------------------------------------------------------------------------

class TestNoneServiceGuidance:
    """When aws_service is None, _refresh sets a helpful status message."""

    def test_not_configured_status_shown(self) -> None:
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        screen._loading = False
        app = _mock_app(aws_service=None)

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_set_status") as mock_status:
            screen._refresh()

        mock_status.assert_called_once()
        msg = mock_status.call_args[0][0]
        assert "not configured" in msg.lower() or "AWS" in msg


# ---------------------------------------------------------------------------
# TestPilotMount (ISSUE-1 smoke test for AWSManagerScreen)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_aws_manager_screen_mounts() -> None:
    """Full Textual pilot mount — verifies screen renders without errors."""
    from textual.app import App, ComposeResult
    from servonaut.config.schema import AppConfig

    fake_config = AppConfig()
    fake_manager = MagicMock()
    fake_manager.get.return_value = fake_config

    mock_aws_service = MagicMock()
    mock_aws_service.fetch_instances_cached = AsyncMock(return_value=[
        {"id": "i-0abc12345678def90", "name": "web", "type": "t3.micro",
         "state": "running", "public_ip": "1.2.3.4", "region": "us-east-1"}
    ])

    class _Harness(App):
        def __init__(self):
            super().__init__()
            self.config_manager = fake_manager
            self.aws_service = mock_aws_service
            self.aws_audit = None
            self.demo_mode = False
            self.redaction_service = None

        def compose(self) -> ComposeResult:
            yield AWSManagerScreen()

    async with _Harness().run_test(headless=True) as pilot:
        # Allow workers to complete
        await pilot.pause(0.1)
        # Screen mounted without exceptions
        assert pilot.app is not None
