"""Findings routes: the proactive-monitoring inbox and gated remediation.

This module owns everything under ``/api/v1/findings``. :class:`FindingsCloud`
(``FakeCloud.findings``) holds the findings a journey adds with
:meth:`FindingsCloud.add` and plays the service's side of remediation:

* triage: ``POST /{id}/ack|resolve|suppress`` moves the status;
* remediation is two-step and server-signed. ``GET /{id}/remediate/preview``
  builds the exact command for one of the finding's own playbook actions
  and a single-use confirm token: a nonce and an HMAC over (finding,
  action, dry run, method, command). ``POST /{id}/remediate`` recomputes the
  HMAC from what it is asked to run and refuses a mismatch (403
  ``remediation_token_invalid``) or a spent token (409
  ``remediation_token_used``), then claims ``remediating`` and answers 202
  at once, like the real asynchronous endpoint;
  :meth:`FindingsCloud.consume_open_previews` spends open previews, as a
  confirmation from another session would;
* the outcome settles while the client polls ``GET /{id}``: a run settles
  on the first read unless :meth:`FindingsCloud.hold_next_run` keeps it
  ``remediating`` for a few reads; then a dry run restores the prior status
  and a live run resolves it. A live ``block_ip`` leaves a revertible
  handle;
* ``GET /{id}/revert/preview`` and ``POST /{id}/revert`` undo it the same
  way, signed over the method of the ban being undone (the finding stays
  ``resolved``; the outcome is in ``last_revert``).

Nothing is executed anywhere: the fake only records what was confirmed.
Every route needs the account's current access token.
"""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import hmac
import secrets
import threading
import uuid
from dataclasses import dataclass
from typing import Any, Optional

from aiohttp import web

from e2e.harness.fake_cloud.routes_auth import bearer_ok, json_body, unauthorized
from e2e.harness.fake_cloud.state import ScenarioStore

FINDINGS = "/api/v1/findings"
TOKEN_TTL_SECONDS = 300
BLOCK_METHODS = frozenset({"waf", "security_group", "nacl", "nftables", "ufw", "firewalld"})
_TRIAGE = {"ack": "acked", "resolve": "resolved", "suppress": "suppressed"}
_REMEDIABLE = frozenset({"detected", "acked"})


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _error(code: str, message: str, status: int) -> web.Response:
    return web.json_response({"error": {"code": code, "message": message}}, status=status)


@dataclass
class _Ticket:
    """A confirm token's single-use state (what it covers is in its HMAC)."""

    finding_id: str
    method: Optional[str]
    expires_at: dt.datetime
    used: bool = False


@dataclass
class _Run:
    """A remediation or revert the client started and is polling for."""

    kind: str  # "remediate" | "revert"
    action: str
    dry_run: bool
    method: Optional[str]
    prior_status: str
    polls_left: int
    dispatched_at: str


def block_ip_remediation() -> dict[str, Any]:
    """A playbook entry for banning the address a finding names."""
    return {
        "action": "block_ip",
        "label": "Block the source address",
        "description": "Add the address to the configured IP-ban plane.",
        "risk_tier": "low",
        "reversible": True,
        "automatable": True,
    }


class FindingsCloud:
    """Thread-safe findings and remediation state."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._findings: dict[str, dict[str, Any]] = {}
            self._pending_polls: dict[str, int] = {}
            self._tickets: dict[str, _Ticket] = {}
            self._runs: dict[str, _Run] = {}
            self._served: dict[str, list[str]] = {}
            self._executed: list[dict[str, Any]] = []
            self._key = secrets.token_bytes(32)

    # ------------------------------------------------------------------
    # Journey controls and observations
    # ------------------------------------------------------------------

    def add(self, **fields: Any) -> str:
        """Add a finding (``detected``, with neutral defaults); return its id."""
        finding_id = str(uuid.uuid4())
        stamp = _now().replace(microsecond=0).isoformat()
        finding = {
            "id": finding_id,
            "instance_id": "",
            "detector": "web_traffic",
            "rule": "request_flood",
            "title": "(untitled)",
            "description": "",
            "severity": "medium",
            "status": "detected",
            "detected_at": stamp,
            "last_seen_at": stamp,
            # ``source_ip`` names the address a block_ip remediation bans.
            "evidence": {},
            "remediations": [],
            "last_remediation": None,
            "last_revert": None,
            "team_scoped": False,
        }
        unknown = set(fields) - set(finding)
        if unknown:
            raise KeyError(f"unknown finding fields: {sorted(unknown)}")
        finding.update(copy.deepcopy(fields))
        with self._lock:
            self._findings[finding_id] = finding
        return finding_id

    def hold_next_run(self, finding_id: str, reads: int = 1) -> None:
        """Keep the next remediation or revert running for *reads* polls."""
        with self._lock:
            self._pending_polls[finding_id] = reads

    def get(self, finding_id: str) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._findings[finding_id])

    def served_statuses(self, finding_id: str) -> list[str]:
        """The status each ``GET /{id}`` answered with, oldest first."""
        with self._lock:
            return list(self._served.get(finding_id, []))

    def executed(self) -> list[dict[str, Any]]:
        """Confirmed remediations and reverts, oldest first."""
        with self._lock:
            return copy.deepcopy(self._executed)

    # ------------------------------------------------------------------
    # Operations behind the routes
    # ------------------------------------------------------------------

    def listing(self, query: dict[str, str]) -> dict[str, Any]:
        limit = int(query.get("limit") or 50)
        offset = int(query.get("offset") or 0)
        with self._lock:
            rows = [
                copy.deepcopy(f)
                for f in self._findings.values()
                if all(
                    not query.get(param) or f[field] == query[param]
                    for param, field in (
                        ("instance", "instance_id"),
                        ("status", "status"),
                        ("severity", "severity"),
                    )
                )
            ]
        return {
            "findings": rows[offset:offset + limit],
            "total": len(rows),
            "limit": limit,
            "offset": offset,
        }

    def read(self, finding_id: str) -> Optional[dict[str, Any]]:
        """``GET /{id}``: advance a running remediation, then answer."""
        with self._lock:
            finding = self._findings.get(finding_id)
            if finding is None:
                return None
            run = self._runs.get(finding_id)
            if run is not None:
                if run.polls_left > 0:
                    run.polls_left -= 1
                else:
                    self._settle(finding, run)
                    del self._runs[finding_id]
            self._served.setdefault(finding_id, []).append(finding["status"])
            return copy.deepcopy(finding)

    def triage(self, finding_id: str, action: str) -> Optional[dict[str, Any]]:
        with self._lock:
            finding = self._findings.get(finding_id)
            if finding is None:
                return None
            finding["status"] = _TRIAGE[action]
            return copy.deepcopy(finding)

    def preview(
        self, finding_id: str, query: dict[str, str], *, revert: bool
    ) -> tuple[int, dict[str, Any]]:
        dry_run = query.get("dry_run") in ("1", "true")
        with self._lock:
            finding = self._findings.get(finding_id)
            if finding is None:
                return 404, _body("not_found", "No such finding")
            if revert:
                handle = (finding.get("last_remediation") or {}).get("revert") or {}
                if handle.get("executable") is not True:
                    return 409, _body("remediation_bad_status", "Nothing to revert")
                action, method = "unblock_ip", handle.get("method")
            else:
                action, method = query.get("action", ""), query.get("method")
                problem = self._remediation_problem(finding, action, method)
                if problem:
                    return problem
            human = _command(finding, action, method)
            token, ticket = self._issue(finding_id, action, dry_run, method, human)
        preview: dict[str, Any] = {
            "finding_id": finding_id,
            "exec_risk": "low",
            "dry_run": dry_run,
            "command": {"verb": action, "human": human},
            "confirm_token": token,
            "expires_at": ticket.expires_at.isoformat(),
        }
        if revert:
            preview["verb"] = action
            preview["revert_plan"] = {"human": "re-apply the ban", "executable": False}
        else:
            preview["action"] = action
            preview["reversible"] = action == "block_ip"
            preview["revert_plan"] = {
                "human": "Undo removes the address from the ban plane again.",
                "executable": action == "block_ip",
            }
        return 200, preview

    def _remediation_problem(
        self, finding: dict[str, Any], action: str, method: Optional[str]
    ) -> Optional[tuple[int, dict[str, Any]]]:
        offered = {r.get("action"): r for r in finding.get("remediations") or []}
        option = offered.get(action)
        if option is None or option.get("automatable") is False:
            return 422, _body("remediation_action_not_available", f"{action!r} is not offered")
        if action == "block_ip" and method not in BLOCK_METHODS:
            return 422, _body("block_ip_method_required", "block_ip needs a method")
        if finding["status"] not in _REMEDIABLE:
            return 409, _body("remediation_bad_status", f"status is {finding['status']}")
        return None

    def _signature(
        self, nonce: str, finding_id: str, action: str, dry_run: bool,
        method: Optional[str], command: str,
    ) -> str:
        message = "\x1f".join(
            (nonce, finding_id, action, str(int(dry_run)), method or "", command)
        ).encode()
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def _issue(
        self, finding_id: str, action: str, dry_run: bool, method: Optional[str], command: str
    ) -> tuple[str, _Ticket]:
        nonce = secrets.token_hex(8)
        signature = self._signature(nonce, finding_id, action, dry_run, method, command)
        ticket = _Ticket(finding_id, method, _now() + dt.timedelta(seconds=TOKEN_TTL_SECONDS))
        self._tickets[nonce] = ticket
        return f"rct_{nonce}.{signature}", ticket

    def consume_open_previews(self, finding_id: str) -> int:
        """Spend every open confirm token for *finding_id*; return how many."""
        with self._lock:
            open_tickets = [
                t for t in self._tickets.values() if t.finding_id == finding_id and not t.used
            ]
            for ticket in open_tickets:
                ticket.used = True
            return len(open_tickets)

    def _verified_ticket(
        self, token: str, finding: dict[str, Any], action: str, dry_run: bool,
        method: Optional[str],
    ) -> Optional[_Ticket]:
        """The ticket *token* was issued for, if its HMAC covers this request."""
        nonce, _, signature = token.removeprefix("rct_").partition(".")
        ticket = self._tickets.get(nonce)
        if ticket is None or not token.startswith("rct_"):
            return None
        expected = self._signature(
            nonce, finding["id"], action, dry_run, method, _command(finding, action, method)
        )
        return ticket if hmac.compare_digest(signature, expected) else None

    def execute(
        self, finding_id: str, body: dict[str, Any], *, revert: bool
    ) -> tuple[int, dict[str, Any]]:
        dry_run = bool(body.get("dry_run"))
        with self._lock:
            finding = self._findings.get(finding_id)
            if finding is None:
                return 404, _body("not_found", "No such finding")
            if revert:
                # The method is the applied ban's, never the caller's.
                action = "unblock_ip"
                handle = (finding.get("last_remediation") or {}).get("revert") or {}
                method = handle.get("method")
            else:
                action, method = str(body.get("action") or ""), body.get("method")
            token = str(body.get("confirm_token") or "")
            ticket = self._verified_ticket(token, finding, action, dry_run, method)
            if ticket is None or ticket.expires_at < _now():
                return 403, _body("remediation_token_invalid", "Confirm token does not match")
            if ticket.used:
                return 409, _body("remediation_token_used", "Confirm token already used")
            if finding_id in self._runs:
                return 409, _body("remediation_bad_status", "Already remediating")
            ticket.used = True
            self._runs[finding_id] = _Run(
                kind="revert" if revert else "remediate",
                action=action,
                dry_run=dry_run,
                method=ticket.method,
                prior_status=finding["status"],
                polls_left=self._pending_polls.pop(finding_id, 0),
                dispatched_at=_now().isoformat(),
            )
            finding["status"] = "remediating"
            self._executed.append(
                {"finding_id": finding_id, "kind": self._runs[finding_id].kind,
                 "action": action, "dry_run": dry_run, "method": ticket.method}
            )
        return 202, {
            "accepted": True,
            "finding_id": finding_id,
            "status": "remediating",
            "dry_run": dry_run,
            "action": action,
            "poll": f"{FINDINGS}/{finding_id}",
        }

    @staticmethod
    def _settle(finding: dict[str, Any], run: _Run) -> None:
        outcome = {
            "verb": run.action,
            "status": "dry_run_passed" if run.dry_run else "succeeded",
            "slug": "",
            "exit_code": 0,
            "dry_run": run.dry_run,
            "dispatched_at": run.dispatched_at,
        }
        if run.kind == "revert":
            finding["status"] = "resolved"
            finding["last_revert"] = outcome
            if not run.dry_run:
                finding["last_remediation"]["revert"] = {"executable": False}
            return
        if run.dry_run:
            finding["status"] = run.prior_status
        else:
            finding["status"] = "resolved"
        executable = run.action == "block_ip" and not run.dry_run
        finding["last_remediation"] = {
            **outcome,
            "action": run.action,
            "revert": {
                "executable": executable,
                "method": run.method if executable else None,
            },
        }


def _command(finding: dict[str, Any], action: str, method: Optional[str]) -> str:
    """The byte-for-byte command string a preview shows."""
    evidence = finding.get("evidence")
    address = (evidence.get("source_ip") if isinstance(evidence, dict) else None) or (
        "the reported address"
    )
    if action == "block_ip":
        return f"ban {address} via {method}"
    if action == "unblock_ip":
        return f"unban {address} via {method}"
    return f"{action} on {finding.get('instance_id')}"


def _body(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message}}


def add_routes(app: web.Application, store: ScenarioStore, findings: FindingsCloud) -> None:
    """Register the findings routes on *app* (fixed paths before patterns)."""

    def guarded(handler: Any) -> Any:
        async def wrapper(request: web.Request) -> web.StreamResponse:
            if not bearer_ok(request, store):
                return unauthorized()
            return await handler(request)

        return wrapper

    def fid(request: web.Request) -> str:
        return request.match_info["finding_id"]

    async def listing(request: web.Request) -> web.Response:
        return web.json_response(findings.listing(dict(request.query)))

    async def read(request: web.Request) -> web.Response:
        finding = findings.read(fid(request))
        if finding is None:
            return _error("not_found", "No such finding", 404)
        return web.json_response(finding)

    def triage(action: str) -> Any:
        async def handler(request: web.Request) -> web.Response:
            finding = findings.triage(fid(request), action)
            if finding is None:
                return _error("not_found", "No such finding", 404)
            return web.json_response(finding)

        return handler

    def previewer(revert: bool) -> Any:
        async def handler(request: web.Request) -> web.Response:
            status, body = findings.preview(fid(request), dict(request.query), revert=revert)
            return web.json_response(body, status=status)

        return handler

    def executor(revert: bool) -> Any:
        async def handler(request: web.Request) -> web.Response:
            status, body = findings.execute(fid(request), await json_body(request), revert=revert)
            return web.json_response(body, status=status)

        return handler

    one = f"{FINDINGS}/{{finding_id}}"
    app.router.add_get(FINDINGS, guarded(listing))
    for action in _TRIAGE:
        app.router.add_post(f"{one}/{action}", guarded(triage(action)))
    app.router.add_get(f"{one}/remediate/preview", guarded(previewer(False)))
    app.router.add_post(f"{one}/remediate", guarded(executor(False)))
    app.router.add_get(f"{one}/revert/preview", guarded(previewer(True)))
    app.router.add_post(f"{one}/revert", guarded(executor(True)))
    app.router.add_get(one, guarded(read))
