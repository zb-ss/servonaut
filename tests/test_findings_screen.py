"""Tests for the findings inbox + detail screens.

Pins the Phase-2 UX contract:

- unauthenticated → sign-in card;
- free tier (no ``proactive_monitoring`` entitlement) → upgrade card;
- server 402 → upgrade card even when the local cache said entitled;
- entitled + empty → "all clear" state;
- entitled + findings → rows rendered with escaped server strings;
- detail screen renders remediations DISPLAY-ONLY (with the reference
  note) and triage calls the service and updates status.

All fixtures are generic (``web-1``, RFC1918 addresses) — no real
hosts, IPs, or customer identifiers may appear here.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App
from textual.widgets import Static

from servonaut.screens.findings import FindingDetailScreen, FindingsScreen
from servonaut.services.api_client import PaymentRequiredError


# ---------------------------------------------------------------------------
# Fixtures — deliberately generic
# ---------------------------------------------------------------------------


def _finding(**overrides) -> dict:
    base = {
        "id": "fnd_01abc",
        "instance_id": "i-0000test01",
        "detector": "ssh_exposure",
        "rule": "password_auth_enabled",
        "severity": "high",
        "status": "detected",
        "title": "SSH password authentication is enabled",
        "description": "sshd accepts password logins; key-only is recommended.",
        "remediations": [
            {
                "label": "Disable password authentication",
                "description": "Set PasswordAuthentication no and reload sshd.",
                "action": "harden_sshd_password_auth",
                "risk_tier": "low",
                "reversible": True,
            },
        ],
        "evidence": ["sshd_config: PasswordAuthentication yes (10.0.0.5)"],
        "team_scoped": False,
        "detected_at": "2026-07-01T10:00:00Z",
        "last_seen_at": "2026-07-02T10:00:00Z",
    }
    base.update(overrides)
    return base


def _mock_auth(*, authenticated=True, entitled=True) -> MagicMock:
    auth = MagicMock()
    auth.is_authenticated = authenticated
    auth.has_feature = MagicMock(
        side_effect=lambda f: entitled if f == "proactive_monitoring" else False,
    )
    return auth


def _mock_findings_service(findings=None, total=None) -> MagicMock:
    svc = MagicMock()
    rows = findings if findings is not None else []
    svc.list_findings = AsyncMock(return_value={
        "findings": rows,
        "total": total if total is not None else len(rows),
        "limit": 50,
        "offset": 0,
    })
    svc.acknowledge = AsyncMock(
        return_value={"id": "fnd_01abc", "status": "acked"},
    )
    svc.resolve = AsyncMock(
        return_value={"id": "fnd_01abc", "status": "resolved"},
    )
    svc.suppress = AsyncMock(
        return_value={"id": "fnd_01abc", "status": "suppressed"},
    )
    return svc


class _WrapperApp(App):
    """Minimal host exposing the services the screens read off self.app."""

    def __init__(self, *, screen, auth, findings_service, **kwargs):
        super().__init__(**kwargs)
        self._initial_screen = screen
        self.auth_service = auth
        self.findings_service = findings_service
        self.instances = [
            {"id": "i-0000test01", "name": "web-1"},
        ]
        self.demo_mode = False

    def on_mount(self) -> None:
        self.push_screen(self._initial_screen)


def _rendered_text(app: App) -> str:
    out = []
    for s in app.screen.query(Static):
        try:
            r = s.render()
            if r is not None:
                out.append(str(r))
        except Exception:  # noqa: BLE001
            continue
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Inbox states
# ---------------------------------------------------------------------------


class TestFindingsScreenStates:
    @pytest.mark.asyncio
    async def test_unauthenticated_shows_sign_in_card(self):
        app = _WrapperApp(
            screen=FindingsScreen(),
            auth=_mock_auth(authenticated=False),
            findings_service=None,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            text = _rendered_text(app)
            assert "Sign in required" in text
            assert "Open Login" in text

    @pytest.mark.asyncio
    async def test_free_tier_shows_upgrade_card(self):
        app = _WrapperApp(
            screen=FindingsScreen(),
            auth=_mock_auth(entitled=False),
            findings_service=_mock_findings_service(),
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            text = _rendered_text(app)
            assert "Upgrade required" in text
            assert "Open Pricing" in text

    @pytest.mark.asyncio
    async def test_server_402_shows_upgrade_card(self):
        svc = _mock_findings_service()
        svc.list_findings = AsyncMock(side_effect=PaymentRequiredError(
            code="payment_required",
            message="Proactive monitoring requires a Solo or Teams subscription.",
            status=402,
            details={"upgrade_url": "https://servonaut.dev/pricing"},
        ))
        app = _WrapperApp(
            screen=FindingsScreen(),
            auth=_mock_auth(entitled=True),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            text = _rendered_text(app)
            assert "Upgrade required" in text

    @pytest.mark.asyncio
    async def test_entitled_empty_shows_all_clear(self):
        app = _WrapperApp(
            screen=FindingsScreen(),
            auth=_mock_auth(),
            findings_service=_mock_findings_service([]),
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            text = _rendered_text(app)
            assert "No findings" in text

    @pytest.mark.asyncio
    async def test_entitled_rows_render_with_pill_counts(self):
        rows = [
            _finding(),
            _finding(id="fnd_02def", severity="critical",
                     title="Root login over SSH is permitted"),
        ]
        svc = _mock_findings_service(rows)
        app = _WrapperApp(
            screen=FindingsScreen(),
            auth=_mock_auth(),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            text = _rendered_text(app)
            assert "2 total" in text
            svc.list_findings.assert_awaited()
            # Fleet inbox: no instance filter on the wire.
            _, kwargs = svc.list_findings.await_args
            assert kwargs["instance"] is None

    @pytest.mark.asyncio
    async def test_instance_scoped_list_passes_instance_filter(self):
        svc = _mock_findings_service([_finding()])
        app = _WrapperApp(
            screen=FindingsScreen(instance={"id": "i-0000test01", "name": "web-1"}),
            auth=_mock_auth(),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            _, kwargs = svc.list_findings.await_args
            assert kwargs["instance"] == "i-0000test01"

    @pytest.mark.asyncio
    async def test_hostile_markup_in_title_does_not_crash(self):
        """Server strings pass through rich.markup.escape — a title with
        markup must render literally, not blow up or restyle the row."""
        rows = [_finding(title="[red]fake[/red] [b]markup injection")]
        app = _WrapperApp(
            screen=FindingsScreen(),
            auth=_mock_auth(),
            findings_service=_mock_findings_service(rows),
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            # Reaching here without a MarkupError is the assertion;
            # the pill still renders.
            text = _rendered_text(app)
            assert "1 total" in text


# ---------------------------------------------------------------------------
# Detail + triage
# ---------------------------------------------------------------------------


class TestFindingDetailScreen:
    @pytest.mark.asyncio
    async def test_detail_renders_remediations_display_only(self):
        app = _WrapperApp(
            screen=FindingDetailScreen(_finding()),
            auth=_mock_auth(),
            findings_service=_mock_findings_service(),
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            text = _rendered_text(app)
            assert "SSH password authentication is enabled" in text
            assert "Disable password authentication" in text
            assert "low risk" in text
            # The display-only pin: the reference note must be present.
            assert "does not execute them" in text

    @pytest.mark.asyncio
    async def test_ack_calls_service_and_updates_status(self):
        svc = _mock_findings_service()
        app = _WrapperApp(
            screen=FindingDetailScreen(_finding()),
            auth=_mock_auth(),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause(0.05)
            svc.acknowledge.assert_awaited_once_with("fnd_01abc")
            text = _rendered_text(app)
            assert "acked" in text

    @pytest.mark.asyncio
    async def test_suppress_calls_service(self):
        svc = _mock_findings_service()
        app = _WrapperApp(
            screen=FindingDetailScreen(_finding()),
            auth=_mock_auth(),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.press("x")
            await pilot.pause(0.05)
            svc.suppress.assert_awaited_once_with("fnd_01abc")
