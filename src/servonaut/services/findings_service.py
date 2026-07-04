"""Thin client for the hosted proactive-findings API.

The CLI is a renderer over the gated ``/api/v1/findings`` endpoints:
it lists findings, triggers scans, streams scan progress, and posts
triage transitions. All detection, playbooks, prompts, and analysis
live server-side — none of that logic may ever land in this repository.

Wire-shape contract (additive-only): findings are stored and passed
around as the raw ``dict`` the server returned. Consumers read fields
via ``.get()`` so new server-side fields never break the client.

Error surface (raised by :class:`servonaut.services.api_client.APIClient`):

- ``PaymentRequiredError`` (402) — free tier / entitlement / monitoring
  budget exhausted. Carries ``upgrade_url`` / ``doc_url`` /
  ``required_tier``.
- ``APIError`` with ``code == "cli_not_connected"`` (409) — scans need
  the user's CLI relay connected (``servonaut connect``).
- ``ValidationFailedError`` (422) — bad filter values (also validated
  locally before the round-trip).
- ``NotFoundError`` (404) — unknown finding id. The server returns the
  same 404 for findings the caller can't see; don't distinguish.
"""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any, AsyncIterator, Dict, Optional

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient

logger = logging.getLogger(__name__)

_BASE = "/api/v1/findings"

#: Lifecycle statuses accepted by the ``status`` filter and returned in
#: ``FindingResource.status``. Mirrors the server's validation message.
FINDING_STATUSES = ("detected", "acked", "remediating", "resolved", "suppressed")

#: Severities accepted by the ``severity`` filter, lowest first.
FINDING_SEVERITIES = ("info", "low", "medium", "high", "critical")

#: Triage transitions exposed as endpoints: POST /{id}/<action>.
_TRIAGE_ACTIONS = ("ack", "resolve", "suppress")

# Server-issued finding ids are interpolated into URL paths — allowlist
# the shape defensively so a hostile payload can't traverse the path.
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")

# A scan blocks until the server finishes probing over the relay, which
# can far exceed the default 30s API timeout.
_SCAN_TIMEOUT_S = 300.0
_STREAM_TIMEOUT_S = 300.0

#: Default page size for finding lists (server default is also 50).
DEFAULT_PAGE_SIZE = 50


def _validate_finding_id(finding_id: str) -> str:
    if not isinstance(finding_id, str) or not _SAFE_ID_RE.match(finding_id):
        raise ValueError(f"Invalid finding id: {finding_id!r}")
    return finding_id


# Remediation action slugs come from the finding's own remediations list
# (playbook-authored, e.g. ``renew_certificate``) and travel in a query
# string — allowlist the shape.
_SAFE_ACTION_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


def _validate_remediation_action(action: str) -> str:
    if not isinstance(action, str) or not _SAFE_ACTION_RE.match(action):
        raise ValueError(f"Invalid remediation action: {action!r}")
    return action


class FindingsService:
    """Gated REST + SSE client for proactive findings.

    Wired in ``app.py::init_paid_services`` alongside the other
    entitlement-gated services. Screens access it via
    ``getattr(self.app, "findings_service", None)``.
    """

    def __init__(self, api_client: "APIClient") -> None:
        self._api = api_client

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def list_findings(
        self,
        *,
        instance: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """GET the findings list, optionally filtered.

        Returns the raw envelope:
        ``{"findings": [FindingResource], "total": N, "limit": L, "offset": O}``.
        """
        if status is not None and status not in FINDING_STATUSES:
            raise ValueError(
                f"Invalid status {status!r}. Allowed: {', '.join(FINDING_STATUSES)}."
            )
        if severity is not None and severity not in FINDING_SEVERITIES:
            raise ValueError(
                f"Invalid severity {severity!r}. "
                f"Allowed: {', '.join(FINDING_SEVERITIES)}."
            )
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if instance:
            params["instance"] = instance
        if status:
            params["status"] = status
        if severity:
            params["severity"] = severity
        return await self._api.get(_BASE, params=params)

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    async def scan(self, *, instance_id: Optional[str] = None) -> Dict[str, Any]:
        """POST a manual scan; omit ``instance_id`` for a fleet-wide scan.

        Blocks until the server finishes and returns the scan envelope
        (``scan_id``, ``findings``, ``detectors_run``, ``skipped``,
        ``budget``, …). 409 ``cli_not_connected`` means the user's relay
        isn't connected (``servonaut connect``).
        """
        body: Dict[str, Any] = {}
        if instance_id:
            body["instance_id"] = instance_id
        return await self._api.post(
            f"{_BASE}/scan", json=body, timeout=_SCAN_TIMEOUT_S,
        )

    def stream_scan(
        self, *, instance: Optional[str] = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        """Open the live scan-progress SSE stream (GET).

        Yields normalised ``{"event": str, "data": dict}`` events:
        ``scan.started``, ``probe.started``, ``probe.completed``,
        ``finding.detected``, ``scan.completed``. Heartbeat ``ping``
        events are absorbed by the SSE layer. Terminal ``error`` events
        (e.g. ``cli_not_connected``) raise
        :class:`servonaut.services.ai_sse.SSEStreamError`.
        """
        params: Dict[str, Any] = {}
        if instance:
            params["instance"] = instance
        return self._api.stream_sse(
            f"{_BASE}/scan/stream",
            None,
            timeout=_STREAM_TIMEOUT_S,
            method="GET",
            params=params or None,
        )

    # ------------------------------------------------------------------
    # Triage
    # ------------------------------------------------------------------

    async def acknowledge(self, finding_id: str) -> Dict[str, Any]:
        return await self._triage(finding_id, "ack")

    async def resolve(self, finding_id: str) -> Dict[str, Any]:
        return await self._triage(finding_id, "resolve")

    async def suppress(self, finding_id: str) -> Dict[str, Any]:
        return await self._triage(finding_id, "suppress")

    async def _triage(self, finding_id: str, action: str) -> Dict[str, Any]:
        if action not in _TRIAGE_ACTIONS:
            raise ValueError(f"Unknown triage action: {action!r}")
        safe_id = _validate_finding_id(finding_id)
        return await self._api.post(f"{_BASE}/{safe_id}/{action}", json=None)

    # ------------------------------------------------------------------
    # Remediation (Phase 3) — two-step, server-signed
    # ------------------------------------------------------------------
    #
    # The CLI NEVER builds or chooses a remediation command. The preview
    # endpoint returns the exact structured command the server would
    # dispatch plus a confirm_token signed over it; the execute endpoint
    # re-validates the token so what the user confirmed is byte-for-byte
    # what runs. Execution itself arrives back at this CLI over the
    # relay (source: "proactive_remediation") through the verb-allowlisted
    # executor — never as free-form shell.

    async def remediate_preview(
        self, finding_id: str, action: str, *, dry_run: bool = False,
    ) -> Dict[str, Any]:
        """GET the server-built preview for one of the finding's own
        remediation actions.

        Returns (contract §F.3): ``{finding_id, action, exec_risk,
        reversible, dry_run, command: {verb, human}, confirm_token,
        expires_at}``. ``command.human`` is the byte-for-byte string to
        render; the token is signed over (finding, action, dry_run,
        command-hash, user) with a 300s TTL — a dry-run token cannot
        execute a live run. 422 for an action the finding's playbook
        doesn't offer or that isn't automatable; 403
        ``remediation_tier_not_permitted`` above the configured ceiling.
        """
        safe_id = _validate_finding_id(finding_id)
        safe_action = _validate_remediation_action(action)
        params: Dict[str, Any] = {"action": safe_action}
        if dry_run:
            params["dry_run"] = 1
        return await self._api.get(
            f"{_BASE}/{safe_id}/remediate/preview", params=params,
        )

    async def remediate(
        self, finding_id: str, action: str, confirm_token: str,
        *, dry_run: bool = False,
    ) -> Dict[str, Any]:
        """POST the confirmed remediation for execution.

        ``confirm_token`` must be the token issued by
        :meth:`remediate_preview` and ``dry_run`` must match the
        previewed variant (it is bound into the token's command hash).
        Blocks while the server dispatches over the relay and settles,
        then returns ``{ok, dry_run, exit_code, slug, stdout_tail,
        stderr_tail, finding_id, finding_status}``. A dry run never
        changes the finding status; a real success settles it to
        ``resolved``; a failure returns it to ``detected`` with
        structured ``last_remediation`` evidence.
        """
        safe_id = _validate_finding_id(finding_id)
        safe_action = _validate_remediation_action(action)
        if not isinstance(confirm_token, str) or not confirm_token:
            raise ValueError("confirm_token is required")
        return await self._api.post(
            f"{_BASE}/{safe_id}/remediate",
            json={
                "action": safe_action,
                "dry_run": bool(dry_run),
                "confirm_token": confirm_token,
            },
            timeout=_SCAN_TIMEOUT_S,
        )
