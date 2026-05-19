"""Tests for the SecretsScreen UX (Step 9).

Two test surfaces:

1. **Pure helpers** (no Textual harness needed):
   :func:`compute_secrets_status` against mocked
   AuthService + EntitlementGuard; :func:`format_relative_age`
   coarse output buckets.

2. **Screen rendering** (Textual ``app.run_test``):
   Five state variants of :class:`SecretsScreen` produce the right
   pill text + body content + don't leak secret values.
   :class:`ConfirmClearCacheModal` returns the right bool on
   keypress.

The "secret values never leak into rendered text" invariant is the
audit-pinned guarantee (kickoff doc §MCP boundary). A mocked provider
returns a known sentinel value; the test asserts the sentinel never
appears in the screen's rendered text.
"""
from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from textual.app import App
from textual.widgets import Static

from servonaut.config.schema import SecretsConfig
from servonaut.screens.secrets import SecretsScreen
from servonaut.services.secrets_status import (
    SecretsStatusSummary,
    compute_secrets_status,
    format_relative_age,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_auth(
    *,
    authenticated: bool = True,
    plan: str = "solo",
    cached: SecretsConfig | None = None,
    cache_present: bool = False,
    cache_fresh: bool = False,
    fetched_at: float = 0.0,
) -> MagicMock:
    svc = MagicMock()
    svc.is_authenticated = authenticated
    svc.plan = plan
    svc.cached_secrets_config = MagicMock(
        return_value=cached if cached else SecretsConfig.local_default(),
    )
    svc.is_secrets_cache_present = MagicMock(return_value=cache_present)
    svc.is_secrets_cache_fresh = MagicMock(return_value=cache_fresh)
    svc._token = MagicMock(secrets_fetched_at=fetched_at)
    svc.active_team_slug = AsyncMock(return_value="acme")
    return svc


def _mock_guard(allow_secrets: bool = True, allow_team_shared: bool = False) -> MagicMock:
    svc = MagicMock()

    def _check(feature: str):
        if feature == "secrets_management":
            return (allow_secrets, "OK" if allow_secrets else "Requires upgrade")
        if feature == "secrets_team_shared":
            return (allow_team_shared, "OK" if allow_team_shared else "Teams plan")
        return (False, "unknown feature")

    svc.check = MagicMock(side_effect=_check)
    return svc


# ---------------------------------------------------------------------------
# format_relative_age
# ---------------------------------------------------------------------------


class TestFormatRelativeAge:
    def test_zero_is_never(self):
        assert format_relative_age(0) == "never"

    def test_negative_is_never(self):
        assert format_relative_age(-1) == "never"

    @pytest.mark.parametrize("delta,expected", [
        (0, "just now"),
        (3, "just now"),
        (10, "10s ago"),
        (59, "59s ago"),
        (60, "1m ago"),
        (300, "5m ago"),
        (3599, "59m ago"),
        (3600, "1h ago"),
        (86399, "23h ago"),
        (86400, "1 day ago"),
        (172800, "2 days ago"),
    ])
    def test_relative_buckets(self, delta, expected):
        now = 1_000_000_000.0
        assert format_relative_age(now - delta, now=now) == expected


# ---------------------------------------------------------------------------
# compute_secrets_status
# ---------------------------------------------------------------------------


class TestComputeSecretsStatus:
    def test_unauthenticated_returns_blank_snapshot(self):
        auth = _mock_auth(authenticated=False, plan="free")
        guard = _mock_guard(allow_secrets=False)
        s = compute_secrets_status(auth, guard)
        assert s.authenticated is False
        assert s.plan == "free"
        assert s.entitled_secrets_management is False
        assert s.active_provider_name is None
        assert s.cache_present is False

    def test_solo_with_no_team_returns_local_provider(self):
        from servonaut.services.secret_provider import LocalProvider

        auth = _mock_auth(plan="solo")
        guard = _mock_guard(allow_secrets=True)
        with patch(
            "servonaut.services.secret_provider_resolver.resolve_secret_provider",
            return_value=LocalProvider(),
        ):
            s = compute_secrets_status(auth, guard)
        assert s.authenticated is True
        assert s.active_provider_name == "local"
        assert s.local_secrets_path is not None
        assert s.has_health_warning is False

    def test_bitwarden_with_missing_bws_flags_health_warning(self, monkeypatch):
        from servonaut.services.bitwarden_provider import BitwardenProvider

        monkeypatch.delenv("BWS_ACCESS_TOKEN", raising=False)
        auth = _mock_auth(plan="team", cached=SecretsConfig(
            provider="bitwarden",
            config={"project_id": "abc", "token_env_var": "BWS_ACCESS_TOKEN"},
            updated_at="2026-05-17T00:00:00Z",
        ))
        guard = _mock_guard(allow_secrets=True, allow_team_shared=True)
        provider = BitwardenProvider(project_id="abc", bws_path="/usr/bin/fake-bws")
        with patch("servonaut.services.secret_provider_resolver.resolve_secret_provider", return_value=provider), \
             patch("servonaut.services.secrets_status.shutil.which", return_value=None):
            s = compute_secrets_status(auth, guard)
        assert s.active_provider_name == "bitwarden"
        assert s.bitwarden_project_id == "abc"
        assert s.bws_path is None
        assert s.bws_token_set is False
        assert s.has_health_warning is True

    def test_bitwarden_healthy_no_warning(self, monkeypatch):
        from servonaut.services.bitwarden_provider import BitwardenProvider

        monkeypatch.setenv("BWS_ACCESS_TOKEN", "live-token")
        auth = _mock_auth(plan="team", cached=SecretsConfig(
            provider="bitwarden",
            config={"project_id": "abc", "token_env_var": "BWS_ACCESS_TOKEN"},
            updated_at="2026-05-17T00:00:00Z",
        ))
        guard = _mock_guard(allow_secrets=True, allow_team_shared=True)
        provider = BitwardenProvider(project_id="abc", bws_path="/usr/bin/fake-bws")
        with patch("servonaut.services.secret_provider_resolver.resolve_secret_provider", return_value=provider), \
             patch("servonaut.services.secrets_status.shutil.which", return_value="/usr/local/bin/bws"):
            s = compute_secrets_status(auth, guard)
        assert s.has_health_warning is False
        assert s.bws_token_set is True
        assert s.bws_path == "/usr/local/bin/bws"


# ---------------------------------------------------------------------------
# Screen rendering — Textual app harness
# ---------------------------------------------------------------------------


class _WrapperApp(App):
    """Minimal host app that pushes SecretsScreen on mount and exposes the
    services :class:`SecretsScreen` reads via ``self.app``."""

    def __init__(self, *, auth, guard, **kwargs):
        super().__init__(**kwargs)
        self.auth_service = auth
        self.entitlement_guard = guard
        self.api_client = MagicMock()
        self.ssh_service = MagicMock()

    def on_mount(self) -> None:
        self.push_screen(SecretsScreen())


def _collect_rendered_text(app: App) -> str:
    """Concatenate every Static widget's render() output for "values never
    leak" asserts.

    ``Static.render()`` returns the resolved Rich renderable (markup
    stripped, plain text remaining). ``Static.renderable`` is None
    in Textual's current API — :meth:`render` is the right accessor.
    """
    out: list[str] = []
    for s in app.screen.query(Static):
        try:
            r = s.render()
            if r is None:
                continue
            out.append(str(r))
        except Exception:  # noqa: BLE001
            continue
    return "\n".join(out)


class TestSecretsScreenStates:
    @pytest.mark.asyncio
    async def test_unauthenticated_state(self):
        auth = _mock_auth(authenticated=False)
        guard = _mock_guard(allow_secrets=False)
        app = _WrapperApp(auth=auth, guard=guard)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            text = _collect_rendered_text(app)
            assert "Not signed in" in text
            assert "Open Login" in text

    @pytest.mark.asyncio
    async def test_free_tier_state(self):
        auth = _mock_auth(plan="free")
        guard = _mock_guard(allow_secrets=False)
        app = _WrapperApp(auth=auth, guard=guard)
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            text = _collect_rendered_text(app)
            assert "Upgrade required" in text
            assert "Open Pricing" in text

    @pytest.mark.asyncio
    async def test_local_provider_state(self):
        from servonaut.services.secret_provider import LocalProvider

        auth = _mock_auth(plan="solo")
        guard = _mock_guard(allow_secrets=True)
        with patch(
            "servonaut.services.secret_provider_resolver.resolve_secret_provider",
            return_value=LocalProvider(),
        ):
            app = _WrapperApp(auth=auth, guard=guard)
            async with app.run_test(headless=True) as pilot:
                await pilot.pause()
                await pilot.pause(0.05)
                text = _collect_rendered_text(app)
                assert "Local — active" in text
                assert "List stored secrets" in text

    @pytest.mark.asyncio
    async def test_bitwarden_healthy_state(self, monkeypatch):
        from servonaut.services.bitwarden_provider import BitwardenProvider

        monkeypatch.setenv("BWS_ACCESS_TOKEN", "healthy")
        auth = _mock_auth(plan="team", cached=SecretsConfig(
            provider="bitwarden",
            config={"project_id": "proj-123", "token_env_var": "BWS_ACCESS_TOKEN"},
            updated_at="2026-05-17T00:00:00Z",
        ), cache_present=True, cache_fresh=True, fetched_at=time.time() - 30)
        guard = _mock_guard(allow_secrets=True, allow_team_shared=True)
        provider = BitwardenProvider(project_id="proj-123", bws_path="/usr/bin/fake-bws")
        with patch("servonaut.services.secret_provider_resolver.resolve_secret_provider", return_value=provider), \
             patch("servonaut.services.secrets_status.shutil.which", return_value="/usr/local/bin/bws"):
            app = _WrapperApp(auth=auth, guard=guard)
            async with app.run_test(headless=True) as pilot:
                await pilot.pause()
                await pilot.pause(0.05)
                text = _collect_rendered_text(app)
                assert "Bitwarden — active" in text
                assert "proj-123" in text  # project id visible
                assert "Refresh from server" in text

    @pytest.mark.asyncio
    async def test_bitwarden_needs_attention_state(self, monkeypatch):
        from servonaut.services.bitwarden_provider import BitwardenProvider

        monkeypatch.delenv("BWS_ACCESS_TOKEN", raising=False)
        auth = _mock_auth(plan="team", cached=SecretsConfig(
            provider="bitwarden",
            config={"project_id": "proj-123", "token_env_var": "BWS_ACCESS_TOKEN"},
            updated_at="2026-05-17T00:00:00Z",
        ))
        guard = _mock_guard(allow_secrets=True, allow_team_shared=True)
        provider = BitwardenProvider(project_id="proj-123", bws_path="/usr/bin/fake-bws")
        with patch("servonaut.services.secret_provider_resolver.resolve_secret_provider", return_value=provider), \
             patch("servonaut.services.secrets_status.shutil.which", return_value=None):
            app = _WrapperApp(auth=auth, guard=guard)
            async with app.run_test(headless=True) as pilot:
                await pilot.pause()
                await pilot.pause(0.05)
                text = _collect_rendered_text(app)
                assert "needs attention" in text
                assert "falling back to ~/.ssh" in text


# ---------------------------------------------------------------------------
# Audit pin — secret VALUES never appear in rendered text
# ---------------------------------------------------------------------------


class TestNoValueLeaks:
    """The hardest invariant: secret VALUES (not names) never cross the
    UI boundary. Loud failure if a future refactor accidentally
    renders a value."""

    @pytest.mark.asyncio
    async def test_secret_values_never_leak(self, monkeypatch):
        """Pin: even with a provider returning ``UNIQUE_SECRET_VALUE_xyz_abc``,
        that string never appears anywhere in the rendered screen.

        SecretsScreen itself only renders metadata; this test guards
        against a future regression where someone wires the value
        column into the status display by mistake.
        """
        sentinel = "UNIQUE_SECRET_VALUE_xyz_abc_8675309"
        from servonaut.services.bitwarden_provider import BitwardenProvider

        monkeypatch.setenv("BWS_ACCESS_TOKEN", sentinel)  # token IS a value
        provider = BitwardenProvider(project_id="proj-123", bws_path="/usr/bin/fake-bws")
        # ALSO have provider.get_secret return the sentinel if invoked.
        provider.get_secret = AsyncMock(return_value=sentinel)
        provider.list_secrets = AsyncMock(return_value=["name1", "name2"])

        auth = _mock_auth(plan="team", cached=SecretsConfig(
            provider="bitwarden",
            config={"project_id": "proj-123", "token_env_var": "BWS_ACCESS_TOKEN"},
            updated_at="2026-05-17T00:00:00Z",
        ))
        guard = _mock_guard(allow_secrets=True, allow_team_shared=True)
        with patch("servonaut.services.secret_provider_resolver.resolve_secret_provider", return_value=provider), \
             patch("servonaut.services.secrets_status.shutil.which", return_value="/usr/local/bin/bws"):
            app = _WrapperApp(auth=auth, guard=guard)
            async with app.run_test(headless=True) as pilot:
                await pilot.pause()
                await pilot.pause(0.05)
                text = _collect_rendered_text(app)
                # Token value (a kind of secret) must NEVER appear.
                assert sentinel not in text, (
                    "Token value leaked into the screen — the audit-fix-7 "
                    "MCP-boundary invariant is broken. Check whether "
                    "_render_bitwarden accidentally interpolates the env var "
                    "VALUE instead of just the NAME."
                )


# ---------------------------------------------------------------------------
# ConfirmClearCacheModal
# ---------------------------------------------------------------------------


class TestConfirmClearCacheModal:
    """The modal returns True/False/None via Screen.dismiss; verified by
    pushing it on a wrapper app and asserting the callback receives
    the right value."""

    @pytest.mark.asyncio
    async def test_y_keypress_returns_true(self):
        from servonaut.screens.secrets_clear_modal import ConfirmClearCacheModal

        results: list = []

        class _App(App):
            def on_mount(self) -> None:
                self.push_screen(
                    ConfirmClearCacheModal(),
                    lambda r: results.append(r),
                )

        async with _App().run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.press("y")
            await pilot.pause()
        assert results == [True]

    @pytest.mark.asyncio
    async def test_n_keypress_returns_false(self):
        from servonaut.screens.secrets_clear_modal import ConfirmClearCacheModal

        results: list = []

        class _App(App):
            def on_mount(self) -> None:
                self.push_screen(
                    ConfirmClearCacheModal(),
                    lambda r: results.append(r),
                )

        async with _App().run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.press("n")
            await pilot.pause()
        assert results == [False]
