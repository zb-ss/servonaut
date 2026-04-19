"""Tests for LoginScreen."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from textual.app import App
from textual.widgets import Button, Static

from servonaut.screens.login import LoginScreen


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_auth_service(*, authenticated: bool = False, plan: str = "free") -> MagicMock:
    """Return a mock AuthService."""
    svc = MagicMock()
    svc.is_authenticated = authenticated
    svc.plan = plan
    # _token is None by default so _show_logged_in_state falls back to entitlements;
    # tests that need a real token should set svc._token explicitly.
    svc._token = None
    svc._get_cached_entitlements = MagicMock(
        return_value={
            "email": "test@example.com",
            "plan": plan,
            "features": {
                "config_sync": True,
                "premium_ai": False,
            },
        }
        if authenticated
        else None
    )
    svc.start_device_flow = AsyncMock(
        return_value={
            "device_code": "dev-code-abc",
            "user_code": "ABCD-1234",
            "verification_uri": "https://servonaut.dev/activate",
            "interval": 5,
        }
    )
    svc.poll_for_token = AsyncMock(return_value=True)
    svc.logout = AsyncMock()
    svc.fetch_entitlements = AsyncMock(return_value=None)
    return svc


class _WrapperApp(App):
    """Minimal host app to mount LoginScreen for testing."""

    def __init__(self, auth_service=None, config_sync_service=None) -> None:
        super().__init__()
        self.auth_service = auth_service
        self.config_sync_service = config_sync_service
        # Tracks whether LoginScreen triggered the relay-start hook.
        self.login_success_calls = 0

    def on_mount(self) -> None:
        self.push_screen(LoginScreen())

    def on_user_login_success(self) -> None:
        self.login_success_calls += 1


# ---------------------------------------------------------------------------
# Logged-out state
# ---------------------------------------------------------------------------


class TestLoginScreenLoggedOut:
    @pytest.mark.asyncio
    async def test_login_button_visible_when_logged_out(self):
        auth = _make_auth_service(authenticated=False)
        app = _WrapperApp(auth_service=auth)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            btn = app.screen.query_one("#btn_login", Button)
            assert btn.display is True

    @pytest.mark.asyncio
    async def test_logout_button_hidden_when_logged_out(self):
        auth = _make_auth_service(authenticated=False)
        app = _WrapperApp(auth_service=auth)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            # The logged-in container (which holds btn_logout) is hidden.
            assert app.screen.query_one("#logged_in_container").display is False

    @pytest.mark.asyncio
    async def test_account_info_hidden_when_logged_out(self):
        auth = _make_auth_service(authenticated=False)
        app = _WrapperApp(auth_service=auth)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            # The logged-in container (which holds account_info) is hidden.
            assert app.screen.query_one("#logged_in_container").display is False


# ---------------------------------------------------------------------------
# Logged-in state
# ---------------------------------------------------------------------------


class TestLoginScreenLoggedIn:
    @pytest.mark.asyncio
    async def test_account_info_visible_when_logged_in(self):
        auth = _make_auth_service(authenticated=True, plan="solo")
        app = _WrapperApp(auth_service=auth)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            info = app.screen.query_one("#account_info", Static)
            assert info.display is True

    @pytest.mark.asyncio
    async def test_plan_info_shown(self):
        auth = _make_auth_service(authenticated=True, plan="solo")
        app = _WrapperApp(auth_service=auth)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            plan = app.screen.query_one("#plan_info", Static)
            assert plan.display is True
            assert "solo" in str(plan.content)

    @pytest.mark.asyncio
    async def test_login_button_hidden_when_logged_in(self):
        auth = _make_auth_service(authenticated=True, plan="solo")
        app = _WrapperApp(auth_service=auth)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            # The logged-out container (which holds btn_login) is hidden.
            assert app.screen.query_one("#logged_out_container").display is False

    @pytest.mark.asyncio
    async def test_logout_button_visible_when_logged_in(self):
        auth = _make_auth_service(authenticated=True, plan="solo")
        app = _WrapperApp(auth_service=auth)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            btn = app.screen.query_one("#btn_logout", Button)
            assert btn.display is True

    @pytest.mark.asyncio
    async def test_sync_button_visible_when_logged_in(self):
        auth = _make_auth_service(authenticated=True)
        app = _WrapperApp(auth_service=auth)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            btn = app.screen.query_one("#btn_sync", Button)
            assert btn.display is True


# ---------------------------------------------------------------------------
# Device flow UI
# ---------------------------------------------------------------------------


class TestLoginScreenDeviceFlow:
    @pytest.mark.asyncio
    async def test_device_flow_sections_hidden_by_default(self):
        auth = _make_auth_service(authenticated=False)
        app = _WrapperApp(auth_service=auth)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            # The device-flow container (which holds all device_* widgets) is hidden.
            assert app.screen.query_one("#device_flow_container").display is False

    @pytest.mark.asyncio
    async def test_device_flow_shows_code_and_url(self):
        auth = _make_auth_service(authenticated=False)
        # Make poll_for_token never return (simulate pending) so we can
        # inspect the intermediate UI state before polling completes.
        import asyncio

        async def _slow_poll(device_code, interval=5):
            await asyncio.sleep(60)  # effectively never returns in test
            return False

        auth.poll_for_token = _slow_poll
        app = _WrapperApp(auth_service=auth)

        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.click("#btn_login")
            # Give worker a moment to call start_device_flow and update the UI
            await pilot.pause()
            await pilot.pause()

            url_widget = app.screen.query_one("#device_url", Static)
            code_widget = app.screen.query_one("#device_code", Static)

            assert url_widget.display is True
            assert code_widget.display is True
            assert "servonaut.dev" in str(url_widget.content)
            assert "ABCD-1234" in str(code_widget.content)


# ---------------------------------------------------------------------------
# Successful auth → UI update
# ---------------------------------------------------------------------------


class TestLoginScreenAuthSuccess:
    @pytest.mark.asyncio
    async def test_successful_auth_shows_logged_in_state(self):
        auth = _make_auth_service(authenticated=False)

        # After poll succeeds, mark as authenticated so _show_logged_in_state works
        async def _poll_and_authenticate(device_code, interval=5):
            auth.is_authenticated = True
            auth._get_cached_entitlements.return_value = {
                "email": "user@example.com",
                "plan": "solo",
                "features": {"config_sync": True},
            }
            auth.plan = "solo"
            return True

        auth.poll_for_token = _poll_and_authenticate
        app = _WrapperApp(auth_service=auth)

        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.click("#btn_login")
            # Wait for device flow + poll worker to complete
            for _ in range(10):
                await pilot.pause()

            account_info = app.screen.query_one("#account_info", Static)
            assert account_info.display is True
            assert "user@example.com" in str(account_info.content)


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


class TestLoginScreenLogout:
    @pytest.mark.asyncio
    async def test_logout_calls_service_and_shows_logged_out_state(self):
        auth = _make_auth_service(authenticated=True, plan="solo")
        app = _WrapperApp(auth_service=auth)

        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            # Trigger logout
            await pilot.click("#btn_logout")
            for _ in range(5):
                await pilot.pause()

            auth.logout.assert_called_once()
            btn_login = app.screen.query_one("#btn_login", Button)
            assert btn_login.display is True


# ---------------------------------------------------------------------------
# auth_service is None
# ---------------------------------------------------------------------------


class TestLoginScreenNoAuthService:
    @pytest.mark.asyncio
    async def test_shows_unavailable_notice_when_auth_service_is_none(self):
        app = _WrapperApp(auth_service=None)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            notice = app.screen.query_one("#no_httpx_notice", Static)
            assert notice.display is True

    @pytest.mark.asyncio
    async def test_login_button_hidden_when_auth_service_is_none(self):
        app = _WrapperApp(auth_service=None)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            # The logged-out container (which holds btn_login) is hidden when
            # the "httpx not installed" notice is shown instead.
            assert app.screen.query_one("#logged_out_container").display is False

    @pytest.mark.asyncio
    async def test_back_button_visible_when_auth_service_is_none(self):
        app = _WrapperApp(auth_service=None)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            btn = app.screen.query_one("#btn_back", Button)
            assert btn.display is True


# ---------------------------------------------------------------------------
# Relay auto-start hook
# ---------------------------------------------------------------------------


class TestLoginTriggersRelayHook:
    """After a successful device flow, the login screen must call
    ``app.on_user_login_success`` so the TUI can start the in-process relay.
    """

    @pytest.mark.asyncio
    async def test_hook_called_exactly_once_on_success(self):
        auth = _make_auth_service(authenticated=False)

        async def _poll_and_authenticate(device_code, interval=5):
            auth.is_authenticated = True
            auth._get_cached_entitlements.return_value = {
                "email": "user@example.com",
                "plan": "solo",
                "features": {},
            }
            auth.plan = "solo"
            return True

        auth.poll_for_token = _poll_and_authenticate
        app = _WrapperApp(auth_service=auth)

        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.click("#btn_login")
            for _ in range(10):
                await pilot.pause()

        assert app.login_success_calls == 1

    @pytest.mark.asyncio
    async def test_hook_not_called_on_failed_login(self):
        """A timed-out / rejected device flow must not trigger the relay hook."""
        auth = _make_auth_service(authenticated=False)
        auth.poll_for_token = AsyncMock(return_value=False)
        app = _WrapperApp(auth_service=auth)

        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.click("#btn_login")
            for _ in range(10):
                await pilot.pause()

        assert app.login_success_calls == 0
