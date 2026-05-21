"""Screen-level tests for OVH credential-failure feedback.

Every OVH fetch helper swallows API errors and returns an empty list, so an
empty result is indistinguishable from "credentials revoked" until a screen
runs an explicit ``OVHService.check_credentials()`` probe. These tests verify
that the OVH Manager, DNS, and Billing screens surface that probe result in
their UI instead of rendering a misleading empty state.

The screens override ``app`` as a property; ``patch.object`` with
``PropertyMock`` swaps it for the test and restores it afterwards, so no class
state leaks between tests.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, PropertyMock, patch

from servonaut.screens.ovh_billing import OVHBillingScreen
from servonaut.screens.ovh_dns import OVHDNSScreen
from servonaut.screens.ovh_manager import OVHManagerScreen

_AUTH_ERROR = (
    "OVH authentication failed — API credentials are invalid or expired. "
    "Update them in Settings → OVH."
)


def _async(value):
    """Return an async function that resolves to ``value``."""
    async def _fn(*args, **kwargs):
        return value
    return _fn


def _mock_app(*, ovh_service=None, dns_service=None, billing_service=None):
    app = MagicMock()
    app.demo_mode = False
    app.redaction_service = None
    app.ovh_service = ovh_service
    app.ovh_dns_service = dns_service
    app.ovh_billing_service = billing_service
    return app


# ---------------------------------------------------------------------------
# OVH Manager
# ---------------------------------------------------------------------------

class TestOVHManagerFeedback:

    def _run_load(self, app):
        screen = OVHManagerScreen()
        status = MagicMock()
        with patch.object(
            OVHManagerScreen, "app", new_callable=PropertyMock,
            return_value=app,
        ), patch.object(screen, "query_one", return_value=status), \
                patch.object(screen, "_render_table"):
            asyncio.run(screen._load_instances())
        return status

    def test_credential_failure_shows_error_not_empty_state(self):
        ovh = MagicMock()
        ovh.fetch_instances_cached = _async([])
        ovh.check_credentials = _async(_AUTH_ERROR)
        status = self._run_load(_mock_app(ovh_service=ovh))

        rendered = status.update.call_args[0][0]
        assert "authentication failed" in rendered.lower()
        assert "No OVH instances" not in rendered

    def test_genuinely_empty_shows_normal_empty_state(self):
        ovh = MagicMock()
        ovh.fetch_instances_cached = _async([])
        ovh.check_credentials = _async(None)  # credentials are fine
        status = self._run_load(_mock_app(ovh_service=ovh))

        rendered = status.update.call_args[0][0]
        assert "No OVH instances" in rendered

    def test_credentials_not_checked_when_instances_present(self):
        ovh = MagicMock()
        ovh.fetch_instances_cached = _async([{"id": "d1", "name": "n"}])
        ovh.check_credentials = MagicMock(side_effect=AssertionError(
            "check_credentials must not run when instances are present"))
        status = self._run_load(_mock_app(ovh_service=ovh))

        rendered = status.update.call_args[0][0]
        assert "1 instance" in rendered


# ---------------------------------------------------------------------------
# OVH DNS
# ---------------------------------------------------------------------------

class TestOVHDNSFeedback:

    def _run_load(self, app):
        screen = OVHDNSScreen()
        widget = MagicMock()
        with patch.object(
            OVHDNSScreen, "app", new_callable=PropertyMock,
            return_value=app,
        ), patch.object(screen, "query_one", return_value=widget):
            asyncio.run(screen._load_domains())
        return widget

    def test_credential_failure_shown_in_domains_header(self):
        dns = MagicMock()
        dns.list_domains = _async([])
        ovh = MagicMock()
        ovh.check_credentials = _async(_AUTH_ERROR)
        widget = self._run_load(_mock_app(ovh_service=ovh, dns_service=dns))

        rendered = " ".join(
            str(c.args[0]) for c in widget.update.call_args_list
        )
        assert "authentication failed" in rendered.lower()

    def test_header_restored_when_domains_present(self):
        dns = MagicMock()
        dns.list_domains = _async(["example.com"])
        ovh = MagicMock()
        ovh.check_credentials = MagicMock(side_effect=AssertionError(
            "check_credentials must not run when domains are present"))
        widget = self._run_load(_mock_app(ovh_service=ovh, dns_service=dns))

        rendered = " ".join(
            str(c.args[0]) for c in widget.update.call_args_list
        )
        assert "authentication failed" not in rendered.lower()
        assert "Domains" in rendered


# ---------------------------------------------------------------------------
# OVH Billing
# ---------------------------------------------------------------------------

class TestOVHBillingFeedback:

    def test_credential_failure_gates_the_loaders(self):
        ovh = MagicMock()
        ovh.check_credentials = _async(_AUTH_ERROR)
        screen = OVHBillingScreen()
        widget = MagicMock()
        with patch.object(
            OVHBillingScreen, "app", new_callable=PropertyMock,
            return_value=_mock_app(ovh_service=ovh),
        ), patch.object(screen, "query_one", return_value=widget), \
                patch.object(screen, "run_worker") as mock_worker:
            asyncio.run(screen._gate_then_load())

        # The four section loaders must NOT run when credentials are bad.
        mock_worker.assert_not_called()
        rendered = " ".join(
            str(c.args[0]) for c in widget.update.call_args_list
        )
        assert "authentication failed" in rendered.lower()

    def test_valid_credentials_run_all_loaders(self):
        ovh = MagicMock()
        ovh.check_credentials = _async(None)
        screen = OVHBillingScreen()
        # Stub the loaders as plain mocks so calling them yields no
        # un-awaited coroutine when run_worker is mocked out.
        with patch.object(
            OVHBillingScreen, "app", new_callable=PropertyMock,
            return_value=_mock_app(ovh_service=ovh),
        ), patch.object(screen, "run_worker") as mock_worker, \
                patch.object(screen, "_load_current_usage", MagicMock()), \
                patch.object(screen, "_load_spend_history", MagicMock()), \
                patch.object(screen, "_load_invoices", MagicMock()), \
                patch.object(screen, "_load_services", MagicMock()):
            asyncio.run(screen._gate_then_load())

        # current usage, spend history, invoices, services.
        assert mock_worker.call_count == 4
