"""Smoke + worker tests for the TUI guided-setup wizard (Layer B1).

Textual ``run_test`` pilot mounts :class:`SecretsSetupScreen` on a host
app exposing the services it reads. We verify:
- the preflight readiness card renders;
- "List projects" populates the option list from the shared helper;
- "Save" PUTs the config (project_id + token env-var NAME only) and
  primes the local cache — never rendering a token value.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from textual.app import App
from textual.widgets import OptionList, Static

from servonaut.screens.secrets_setup import SecretsSetupScreen
from servonaut.services.bws_onboarding import BwsProject


class _WrapperApp(App):
    def __init__(self, *, auth, guard, api, **kwargs):
        super().__init__(**kwargs)
        self.demo_mode = False
        self.redaction_service = None
        self.auth_service = auth
        self.entitlement_guard = guard
        self.api_client = api
        self.ssh_service = MagicMock()

    def on_mount(self) -> None:
        self.push_screen(SecretsSetupScreen())


def _guard(allow=True):
    g = MagicMock()
    g.check = MagicMock(return_value=(allow, "OK" if allow else "upgrade"))
    return g


def _rendered(app: App) -> str:
    out = []
    for s in app.screen.query(Static):
        try:
            r = s.render()
            if r is not None:
                out.append(str(r))
        except Exception:  # noqa: BLE001
            continue
    return "\n".join(out)


@pytest.mark.asyncio
async def test_preflight_renders():
    auth = MagicMock()
    app = _WrapperApp(auth=auth, guard=_guard(True), api=MagicMock())
    with patch("servonaut.services.bws_onboarding.bws_installed", return_value=True), \
         patch("servonaut.services.bws_onboarding.token_is_set", return_value=True):
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            text = _rendered(app)
    assert "Entitled to secrets management" in text
    assert "bws CLI installed" in text


@pytest.mark.asyncio
async def test_list_projects_populates_option_list():
    auth = MagicMock()
    app = _WrapperApp(auth=auth, guard=_guard(True), api=MagicMock())
    projects = [BwsProject("p1", "prod"), BwsProject("p2", "staging")]
    with patch("servonaut.services.bws_onboarding.bws_installed", return_value=True), \
         patch("servonaut.services.bws_onboarding.token_is_set", return_value=True), \
         patch(
             "servonaut.services.bws_onboarding.list_bws_projects",
             AsyncMock(return_value=projects),
         ):
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.click("#list_projects")
            await pilot.pause(0.05)
            option_list = app.screen.query_one("#project_list", OptionList)
            assert option_list.option_count == 2
            text = _rendered(app)
    assert "Found 2 project(s)" in text


@pytest.mark.asyncio
async def test_save_puts_config_and_primes_cache():
    auth = MagicMock()
    auth.apply_user_secrets_config = MagicMock()
    api = MagicMock()
    api.put_user_secrets_config = AsyncMock(return_value={
        "provider": "bitwarden",
        "config": {"project_id": "p1", "token_env_var": "BWS_ACCESS_TOKEN"},
        "updated_at": "2026-06-30T12:00:00Z",
    })
    app = _WrapperApp(auth=auth, guard=_guard(True), api=api)
    with patch("servonaut.services.bws_onboarding.bws_installed", return_value=True), \
         patch("servonaut.services.bws_onboarding.token_is_set", return_value=True), \
         patch(
             "servonaut.services.bws_onboarding.list_bws_projects",
             AsyncMock(return_value=[BwsProject("p1", "prod")]),
         ), \
         patch(
             "servonaut.services.bws_onboarding.bws_test_connection",
             AsyncMock(return_value=4),
         ), \
         patch(
             "servonaut.services.secret_provider_resolver.resolve_secret_provider",
             return_value=MagicMock(),
         ):
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.click("#list_projects")
            await pilot.pause(0.05)
            # Select the sole project directly on the screen state.
            screen = app.screen
            screen._selected_project_id = "p1"
            await pilot.click("#save")
            await pilot.pause(0.05)

    api.put_user_secrets_config.assert_awaited_once()
    provider, config = api.put_user_secrets_config.call_args.args
    assert provider == "bitwarden"
    assert config == {"project_id": "p1", "token_env_var": "BWS_ACCESS_TOKEN"}
    auth.apply_user_secrets_config.assert_called_once()
