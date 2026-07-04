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
from servonaut.services.api_client import APIError, PaymentRequiredError


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
    svc.scan = AsyncMock(return_value={
        "scan_id": "scn_1", "status": "completed", "scope": "fleet",
        "findings": [], "detectors_run": [], "skipped": [], "budget": {},
        "cli_connected": True,
    })

    async def _scan_events(**kwargs):
        for event in [
            {"event": "scan.started", "data": {"scan_id": "scn_1"}},
            {"event": "probe.started",
             "data": {"detector": "ssh_exposure", "tool": "run_command"}},
            {"event": "probe.completed",
             "data": {"detector": "ssh_exposure", "tool": "run_command",
                      "ok": True}},
            {"event": "scan.completed",
             "data": {"scan_id": "scn_1", "findings_count": 0,
                      "budget": {}, "partial": False}},
        ]:
            yield event

    svc.stream_scan = MagicMock(side_effect=lambda **kw: _scan_events(**kw))
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
    async def test_detail_renders_remediations_with_run_gate(self):
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
            # Phase 3 pin: execution is offered, but ONLY behind the
            # server-signed preview + explicit confirmation flow.
            assert "Nothing executes until you confirm" in text
            screen = app.screen_stack[-1]
            assert len(screen._remediation_buttons) == 1

    @pytest.mark.asyncio
    async def test_no_run_buttons_for_resolved_finding(self):
        app = _WrapperApp(
            screen=FindingDetailScreen(_finding(status="resolved")),
            auth=_mock_auth(),
            findings_service=_mock_findings_service(),
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            screen = app.screen_stack[-1]
            assert screen._remediation_buttons == {}

    @pytest.mark.asyncio
    async def test_investigate_remediation_gets_no_run_button(self):
        finding = _finding(remediations=[{
            "label": "Verify the domain is still served",
            "description": "Check routing before renewing.",
            "action": "investigate",
            "risk_tier": "low",
            "reversible": True,
        }])
        app = _WrapperApp(
            screen=FindingDetailScreen(finding),
            auth=_mock_auth(),
            findings_service=_mock_findings_service(),
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            screen = app.screen_stack[-1]
            assert screen._remediation_buttons == {}

    @pytest.mark.asyncio
    async def test_run_button_fetches_preview_and_opens_confirm_modal(self):
        svc = _mock_findings_service()
        svc.remediate_preview = AsyncMock(return_value={
            "finding_id": "fnd_01abc",
            "action": "harden_sshd_password_auth",
            "exec_risk": "low",
            "reversible": True,
            "dry_run": False,
            "command": {
                "verb": "sshd_harden",
                "human": "sudo -n sshd-harden --password-auth no",
            },
            "confirm_token": "tok-signed",
            "expires_at": "2026-07-04T14:00:00Z",
        })
        svc.remediate = AsyncMock()
        app = _WrapperApp(
            screen=FindingDetailScreen(_finding()),
            auth=_mock_auth(),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            screen = app.screen_stack[-1]
            (button_id, _rem), = screen._remediation_buttons.items()
            button = screen.query_one(f"#{button_id}")
            button.press()
            await pilot.pause(0.1)
            svc.remediate_preview.assert_awaited_once_with(
                "fnd_01abc", "harden_sshd_password_auth", dry_run=False,
            )
            # The confirm modal is on top; nothing has executed.
            from servonaut.screens.remediation_confirm import (
                RemediationConfirmModal,
            )
            assert isinstance(app.screen_stack[-1], RemediationConfirmModal)
            svc.remediate.assert_not_awaited()
            # The server's byte-for-byte command string renders verbatim.
            text = _rendered_text(app)
            assert "sudo -n sshd-harden --password-auth no" in text

    @pytest.mark.asyncio
    async def test_confirm_modal_executes_only_after_typed_phrase(self):
        svc = _mock_findings_service()
        svc.remediate_preview = AsyncMock(return_value={
            "finding_id": "fnd_01abc",
            "action": "harden_sshd_password_auth",
            "exec_risk": "low",
            "reversible": True,
            "dry_run": False,
            "command": {
                "verb": "sshd_harden",
                "human": "sudo -n sshd-harden --password-auth no",
            },
            "confirm_token": "tok-signed",
            "expires_at": "2026-07-04T14:00:00Z",
        })
        svc.remediate = AsyncMock(return_value={
            "ok": True, "dry_run": False, "exit_code": 0, "slug": "",
            "finding_id": "fnd_01abc", "finding_status": "resolved",
        })
        app = _WrapperApp(
            screen=FindingDetailScreen(_finding()),
            auth=_mock_auth(),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            screen = app.screen_stack[-1]
            (button_id, _rem), = screen._remediation_buttons.items()
            screen.query_one(f"#{button_id}").press()
            await pilot.pause(0.1)
            modal = app.screen_stack[-1]
            # Execute is disarmed until the phrase is typed.
            run_button = modal.query_one("#remediation_confirm_run")
            assert run_button.disabled is True
            modal.query_one("#remediation_confirm_input").value = "RUN"
            await pilot.pause()
            assert run_button.disabled is False
            run_button.press()
            await pilot.pause(0.1)
            svc.remediate.assert_awaited_once_with(
                "fnd_01abc", "harden_sshd_password_auth", "tok-signed",
                dry_run=False,
            )
            assert screen._finding["status"] == "resolved"

    @pytest.mark.asyncio
    async def test_dry_run_failure_leaves_status_unchanged(self):
        # A dry run that fails must NOT move the finding status and must
        # surface the server slug (ISSUE-7). Server returns the dry-run
        # shape with no finding_status.
        svc = _mock_findings_service()
        svc.remediate_preview = AsyncMock(return_value={
            "finding_id": "fnd_01abc",
            "action": "harden_sshd_password_auth",
            "exec_risk": "low",
            "reversible": True,
            "dry_run": True,
            "command": {
                "verb": "sshd_harden",
                "human": "sudo -n sshd-harden --password-auth no --dry-run",
            },
            "confirm_token": "tok-dry",
            "expires_at": "2026-07-04T14:00:00Z",
        })
        svc.remediate = AsyncMock(return_value={
            "ok": False, "dry_run": True, "exit_code": 1,
            "slug": "sshd_harden_failed", "finding_id": "fnd_01abc",
            "finding_status": None,
        })
        app = _WrapperApp(
            screen=FindingDetailScreen(_finding()),
            auth=_mock_auth(),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            screen = app.screen_stack[-1]
            (button_id, rem), = screen._remediation_buttons.items()
            # Drive the dry-run path directly (the modal's "Dry run
            # first" button re-enters _launch_remediation with dry_run).
            screen._launch_remediation(rem, dry_run=True)
            await pilot.pause(0.1)
            modal = app.screen_stack[-1]
            modal.query_one("#remediation_confirm_input").value = "RUN"
            await pilot.pause()
            modal.query_one("#remediation_confirm_run").press()
            await pilot.pause(0.1)
            svc.remediate.assert_awaited_once_with(
                "fnd_01abc", "harden_sshd_password_auth", "tok-dry",
                dry_run=True,
            )
            # Status untouched; a dry run never mutates.
            assert screen._finding["status"] == "detected"
            assert screen._changed is False

    @pytest.mark.asyncio
    async def test_dispatch_error_is_messaged_as_transient(self):
        # A 502 remediation_dispatch_error (relay/infra failure) is
        # retryable — the finding is unchanged server-side — so it must
        # be surfaced distinctly from a command failure, not as a hard
        # error, and _changed must stay False.
        svc = _mock_findings_service()
        svc.remediate_preview = AsyncMock(return_value={
            "finding_id": "fnd_01abc",
            "action": "harden_sshd_password_auth",
            "exec_risk": "medium",
            "reversible": True,
            "dry_run": False,
            "command": {"verb": "sshd_harden", "human": "sudo -n sshd-harden"},
            "confirm_token": "tok-signed",
            "expires_at": "2026-07-04T14:00:00Z",
        })
        svc.remediate = AsyncMock(side_effect=APIError(
            code="remediation_dispatch_error",
            message="relay hub unavailable",
            status=502,
        ))
        app = _WrapperApp(
            screen=FindingDetailScreen(_finding()),
            auth=_mock_auth(),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            screen = app.screen_stack[-1]
            (_button_id, rem), = screen._remediation_buttons.items()
            screen._launch_remediation(rem, dry_run=False)
            await pilot.pause(0.1)
            modal = app.screen_stack[-1]
            modal.query_one("#remediation_confirm_input").value = "RUN"
            await pilot.pause()
            modal.query_one("#remediation_confirm_run").press()
            await pilot.pause(0.1)
            # Unchanged + the guard released so a retry is possible.
            assert screen._changed is False
            assert screen._remediating is False
            assert screen._finding["status"] == "detected"

    @pytest.mark.asyncio
    async def test_spent_token_releases_guard_and_leaves_finding(self):
        # A 409 remediation_token_used (single-use confirm token already
        # spent) must leave the finding untouched and release the guard so
        # a fresh preview can be started.
        svc = _mock_findings_service()
        svc.remediate_preview = AsyncMock(return_value={
            "finding_id": "fnd_01abc",
            "action": "harden_sshd_password_auth",
            "exec_risk": "medium",
            "reversible": True,
            "dry_run": False,
            "command": {"verb": "sshd_harden", "human": "sudo -n sshd-harden"},
            "confirm_token": "tok-spent",
            "expires_at": "2026-07-04T14:00:00Z",
        })
        svc.remediate = AsyncMock(side_effect=APIError(
            code="remediation_token_used",
            message="This confirm token was already used.",
            status=409,
        ))
        app = _WrapperApp(
            screen=FindingDetailScreen(_finding()),
            auth=_mock_auth(),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            screen = app.screen_stack[-1]
            (_button_id, rem), = screen._remediation_buttons.items()
            screen._launch_remediation(rem, dry_run=False)
            await pilot.pause(0.1)
            modal = app.screen_stack[-1]
            modal.query_one("#remediation_confirm_input").value = "RUN"
            await pilot.pause()
            modal.query_one("#remediation_confirm_run").press()
            await pilot.pause(0.1)
            assert screen._changed is False
            assert screen._remediating is False
            assert screen._finding["status"] == "detected"

    @pytest.mark.asyncio
    async def test_second_launch_blocked_while_remediating(self):
        # The _remediating guard stops a concurrent launch from
        # cancelling an in-flight mutating execute (ISSUE-2). With the
        # guard set, a launch must NOT push a confirm modal.
        svc = _mock_findings_service()
        svc.remediate_preview = AsyncMock()
        app = _WrapperApp(
            screen=FindingDetailScreen(_finding()),
            auth=_mock_auth(),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            screen = app.screen_stack[-1]
            (_button_id, rem), = screen._remediation_buttons.items()
            screen._remediating = True
            depth_before = len(app.screen_stack)
            screen._launch_remediation(rem, dry_run=False)
            await pilot.pause(0.1)
            # No preview fetched, no modal pushed.
            svc.remediate_preview.assert_not_awaited()
            assert len(app.screen_stack) == depth_before

    @pytest.mark.asyncio
    async def test_preview_dry_run_mismatch_refuses_confirm_modal(self):
        # The confirm modal's banner must reflect what the server actually
        # built, not the local request echo. If the server ever returns a
        # preview whose dry_run disagrees with what was requested, the
        # client must refuse rather than show a possibly-misleading
        # confirmation (a "DRY RUN — nothing changes" banner over a
        # confirm_token actually bound to a live command, or vice versa).
        svc = _mock_findings_service()
        svc.remediate_preview = AsyncMock(return_value={
            "finding_id": "fnd_01abc",
            "action": "harden_sshd_password_auth",
            "exec_risk": "low",
            "reversible": True,
            "dry_run": True,  # requested dry_run=False below — mismatch
            "command": {"verb": "sshd_harden", "human": "sudo -n sshd-harden"},
            "confirm_token": "tok-signed",
            "expires_at": "2026-07-04T14:00:00Z",
        })
        svc.remediate = AsyncMock()
        app = _WrapperApp(
            screen=FindingDetailScreen(_finding()),
            auth=_mock_auth(),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            screen = app.screen_stack[-1]
            (_button_id, rem), = screen._remediation_buttons.items()
            depth_before = len(app.screen_stack)
            screen._launch_remediation(rem, dry_run=False)
            await pilot.pause(0.1)
            # No modal pushed — the mismatch was refused, not displayed.
            assert len(app.screen_stack) == depth_before
            svc.remediate.assert_not_awaited()

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


# ---------------------------------------------------------------------------
# Scan-now — SSE variant XOR buffered POST (contract: the stream STARTS a
# scan; calling both would launch two scans and take two concurrency slots)
# ---------------------------------------------------------------------------


class TestScanNow:
    @pytest.mark.asyncio
    async def test_scan_uses_stream_only_never_both(self):
        svc = _mock_findings_service([_finding()])
        app = _WrapperApp(
            screen=FindingsScreen(),
            auth=_mock_auth(),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            await pilot.press("s")
            await pilot.pause(0.1)
            # The SSE variant ran the scan…
            svc.stream_scan.assert_called_once()
            # …and the buffered POST was NEVER issued — two calls would
            # be two scans (double slot + double budget spend).
            svc.scan.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_scan_falls_back_to_post_when_sse_unavailable(self):
        svc = _mock_findings_service([_finding()])
        svc.stream_scan = MagicMock(
            side_effect=RuntimeError("httpx-sse not installed"),
        )
        app = _WrapperApp(
            screen=FindingsScreen(),
            auth=_mock_auth(),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            await pilot.press("s")
            await pilot.pause(0.1)
            svc.scan.assert_awaited_once_with(instance_id=None)

    @pytest.mark.asyncio
    async def test_instance_scoped_scan_streams_with_instance(self):
        svc = _mock_findings_service([_finding()])
        app = _WrapperApp(
            screen=FindingsScreen(
                instance={"id": "i-0000test01", "name": "web-1"},
            ),
            auth=_mock_auth(),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            await pilot.press("s")
            await pilot.pause(0.1)
            svc.stream_scan.assert_called_once_with(instance="i-0000test01")

    @pytest.mark.asyncio
    async def test_scan_key_inert_on_upgrade_card(self):
        """Card states hide the data bindings — pressing s on the
        free-tier card must not start a scan (footer doesn't advertise
        it and the key is inert)."""
        svc = _mock_findings_service()
        app = _WrapperApp(
            screen=FindingsScreen(),
            auth=_mock_auth(entitled=False),
            findings_service=svc,
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            await pilot.press("s")
            await pilot.pause(0.1)
            svc.stream_scan.assert_not_called()
            svc.scan.assert_not_awaited()


class TestEvidenceShapes:
    """Evidence arrives as list-of-strings per contract, but live
    findings also ship dict-shaped evidence — both must render."""

    @pytest.mark.asyncio
    async def test_dict_evidence_renders(self):
        finding = _finding(evidence={
            "df": ["/dev/vda2  39G  36G  3.4G  91% /var"],
            "growth_24h_percent": 6,
        })
        app = _WrapperApp(
            screen=FindingDetailScreen(finding),
            auth=_mock_auth(),
            findings_service=_mock_findings_service(),
        )
        async with app.run_test(headless=True) as pilot:
            await pilot.pause()
            await pilot.pause(0.05)
            text = _rendered_text(app)
            assert "Evidence" in text
            assert "91% /var" in text
            assert "growth_24h_percent: 6" in text

    def test_evidence_lines_shapes(self):
        from servonaut.screens.findings import evidence_lines
        assert evidence_lines(["a", "b"]) == ["a", "b"]
        assert evidence_lines({"k": ["x"], "n": 2}) == ["k:", "  x", "n: 2"]
        assert evidence_lines("solo") == ["solo"]
        assert evidence_lines(None) == []


class TestReconNote:
    def test_profile_used_with_recon_skips(self):
        from servonaut.screens.findings import _recon_note
        assert _recon_note({"profile_used": True,
                            "skipped_by_recon": [{"detector": "x"}]}) == (
            " · stack-aware scan (1 detector(s) not applicable to this stack)"
        )
        assert _recon_note({"profile_used": True,
                            "skipped_by_recon": []}) == " · stack-aware scan"

    def test_absent_or_fail_open_is_silent(self):
        from servonaut.screens.findings import _recon_note
        assert _recon_note(None) == ""
        assert _recon_note({"profile_used": False,
                            "detectors_selected": ["a"]}) == ""
