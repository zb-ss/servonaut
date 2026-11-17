"""Tests for LoginScreen."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from rich.cells import cell_len
from textual.app import App
from textual.pilot import Pilot
from textual.widgets import Button, Static

from servonaut.styles import CSS_FILES
from servonaut.screens.login import LoginScreen

from tests._async_bounds import wait_until
from tests._native_actions import click_action


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _login_layout_applied(screen: LoginScreen) -> bool:
    root = screen.query_one("#login_container")
    state = screen.query_one("#logged_out_container")
    target = screen.query_one("#btn_login", Button)
    if (screen._layout_required or not target.is_mounted or target.disabled
            or not state.display or not state.children or target.parent is None):
        return False
    if root.region.width <= 0:
        return False
    narrow = root.region.width < screen.CONTENT_NARROW_WIDTH
    if screen.has_class("-content-narrow") != narrow:
        return False
    if getattr(state.styles.layout, "name", None) != ("vertical" if narrow else "horizontal"):
        return False
    features, sign_in = state.children[0], target.parent
    if narrow:
        aligned = (features.region.width == sign_in.region.width == state.content_region.width
                   and features.region.x == sign_in.region.x
                   and sign_in.region.y >= features.region.bottom)
    else:
        aligned = features.region.y == sign_in.region.y and features.region.right <= sign_in.region.x
    required_scroll = max(0, target.region.bottom - root.scrollable_content_region.bottom + root.scroll_y)
    return (aligned and target.region.width == sign_in.content_region.width > 0
            and target.region.x == sign_in.content_region.x
            and root.max_scroll_y >= required_scroll)


def _assert_login_action_painted(pilot: Pilot, target: Button) -> None:
    app, screen = pilot.app, pilot.app.screen
    root = screen.query_one("#login_container")
    assert app.focused is target
    assert screen.region.contains_region(target.region)
    assert root.scrollable_content_region.contains_region(target.region)
    region = target.content_region
    strips = screen._compositor.render_strips()
    label = target.label.plain
    for y in range(region.y, region.bottom):
        row = strips[y].crop(region.x, region.right).text
        offset = row.find(label)
        if offset < 0:
            continue
        start = region.x + cell_len(row[:offset])
        for x in range(start, start + cell_len(label)):
            hit = app.get_widget_at(x, y)[0]
            assert hit is target or target in hit.ancestors
        return
    pytest.fail("Complete native Login label is not painted")


async def _click_ready_login(pilot: Pilot) -> None:
    screen = pilot.app.screen
    assert isinstance(screen, LoginScreen)
    await wait_until(lambda: _login_layout_applied(screen))
    refreshed = asyncio.Event()
    screen.call_after_refresh(refreshed.set)
    await wait_until(refreshed.is_set)
    await wait_until(lambda: _login_layout_applied(screen))
    assert _login_layout_applied(screen)
    target = screen.query_one("#btn_login", Button)
    native_click = pilot.click

    async def checked_click(widget=None, *args, **kwargs):
        assert widget is target
        _assert_login_action_painted(pilot, target)
        return await native_click(widget, *args, **kwargs)

    with patch.object(pilot, "click", checked_click):
        await click_action(pilot, "#btn_login")


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

    CSS_PATH = CSS_FILES

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
            assert "Solo" in str(plan.content)

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

        async def _slow_poll(device_code, interval=5, *, client_kind):
            await asyncio.sleep(60)  # effectively never returns in test
            return False

        auth.poll_for_token = _slow_poll
        app = _WrapperApp(auth_service=auth)

        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await click_action(pilot, "#btn_login")
            # Give worker a moment to call start_device_flow and update the UI
            await pilot.pause()
            await pilot.pause()

            url_widget = app.screen.query_one("#device_url", Static)
            code_widget = app.screen.query_one("#device_code", Static)

            assert url_widget.display is True
            assert code_widget.display is True
            assert "servonaut.dev" in str(url_widget.content)
            assert "ABCD-1234" in str(code_widget.content)


class TestLoginScreenClientKind:
    """Sign-in tells the server which client asks: the terminal TUI or the desktop window."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("client_kind", [None, "desktop"])
    async def test_device_flow_names_the_client(self, client_kind):
        auth = _make_auth_service(authenticated=False)
        app = _WrapperApp(auth_service=auth)
        if client_kind is not None:
            app.client_kind = client_kind
        expected = client_kind or "tui"

        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await click_action(pilot, "#btn_login")
            for _ in range(50):
                if auth.poll_for_token.await_count:
                    break
                await pilot.pause()

        auth.start_device_flow.assert_awaited_once_with(client_kind=expected)
        auth.poll_for_token.assert_awaited_once_with(
            "dev-code-abc", interval=5, client_kind=expected
        )


# ---------------------------------------------------------------------------
# Successful auth → UI update
# ---------------------------------------------------------------------------


class TestLoginScreenAuthSuccess:
    @pytest.mark.asyncio
    async def test_successful_auth_shows_logged_in_state(self):
        auth = _make_auth_service(authenticated=False)

        # After poll succeeds, mark as authenticated so _show_logged_in_state works
        async def _poll_and_authenticate(device_code, interval=5, *, client_kind):
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
            await click_action(pilot, "#btn_login")
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
            await click_action(pilot, "#btn_logout")
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

        async def _poll_and_authenticate(device_code, interval=5, *, client_kind):
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
            await click_action(pilot, "#btn_login")
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
            screen = app.screen
            with patch.object(app, "notify", wraps=app.notify) as notify:
                await _click_ready_login(pilot)
                await wait_until(lambda: (
                    auth.poll_for_token.await_count == 1 and not screen._polling
                    and any(call.args and call.args[0] == "Authorization failed or timed out."
                            and call.kwargs.get("severity") == "warning"
                            for call in notify.call_args_list)
                ))
                auth.start_device_flow.assert_awaited_once_with(client_kind="tui")
                auth.poll_for_token.assert_awaited_once_with(
                    "dev-code-abc", interval=5, client_kind="tui",
                )
                assert auth.is_authenticated is False
                assert app.screen is screen
                assert screen.query_one("#logged_out_container").display
                assert not screen.query_one("#device_flow_container").display
                assert not screen.query_one("#logged_in_container").display

        assert app.login_success_calls == 0


def test_every_feature_the_plan_map_names_has_a_label():
    """A feature without a label shows its raw slug (``personal_vault``) on the Account screen."""
    from servonaut.screens.login import _ADMIN_ONLY_FEATURES, _FEATURE_LABELS, _UNRELEASED_FEATURES
    from servonaut.services.auth_service import AuthService

    named = {feature for plan in AuthService._PLAN_FEATURES.values() for feature in plan}
    named |= set(AuthService._KNOWN_BOOL_FEATURES)
    shown = named - _UNRELEASED_FEATURES - _ADMIN_ONLY_FEATURES
    assert sorted(shown - set(_FEATURE_LABELS)) == []
