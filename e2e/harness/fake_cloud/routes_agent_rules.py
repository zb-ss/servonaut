"""Team agent rules: the signed policy each member's Servonaut verifies.

``GET /api/v1/teams/{slug}/policy`` (and its ``/mcp-policy`` alias) answers
any member of the team, as the service does. Inside ``data`` it carries the
team's agent rules signed (``agent_rules_signed``) with this fake's own
Ed25519 key, plus the stored editor copy (``agent_rules``) and its unsigned
version, which a client must never enforce from. A team that saved no rules
serves the format 1 defaults at version 0.

The suite trusts the fake's key for the fake's API origin only, the way a
release trusts its bundled key (:meth:`AgentRulesCloud.trusted_keys`): the
test process patches ``team_policy_keys.TEAM_POLICY_KEYS`` and child
processes get it through the module redirects ``child_guard.py`` applies.
Journeys change a team's rules, version, lifetime or signature with
:meth:`AgentRulesCloud.set_rules`.

Every route needs the account's current access token.
"""

from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import threading
from typing import Any, Callable, Optional

from aiohttp import web
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from e2e.harness.fake_cloud.routes_auth import bearer_ok, unauthorized
from e2e.harness.fake_cloud.state import ScenarioStore

FORMAT = 1
# The service's default lifetime of a signed copy.
DEFAULT_LIFETIME = dt.timedelta(hours=24)
_KEY_ID_HEX_DIGITS = 16


def default_agent_rules() -> dict[str, Any]:
    """The format 1 rules of a team that saved none (the service pins the same object)."""
    return {
        "role_levels": {
            "owner": "standard", "admin": "standard", "member": "standard", "viewer": "readonly",
        },
        "servers": {},
        "command_allowlist": None,
        "command_blocklist": [],
    }


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _rfc3339(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AgentRulesCloud:
    """The teams' agent rules and the key that signs them (thread-safe)."""

    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.generate()
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._teams: dict[str, dict[str, Any]] = {}

    @property
    def public_key(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )

    @property
    def key_id(self) -> str:
        return hashlib.sha256(self.public_key).hexdigest()[:_KEY_ID_HEX_DIGITS]

    def trusted_keys(self, origin: str) -> dict[str, dict[str, str]]:
        """The ``TEAM_POLICY_KEYS`` table that trusts this fake's key for *origin*."""
        return {origin: {self.key_id: base64.b64encode(self.public_key).decode("ascii")}}

    def set_rules(
        self,
        slug: str,
        agent_rules: Optional[dict[str, Any]] = None,
        *,
        version: Optional[int] = None,
        lifetime: Optional[dt.timedelta] = None,
        signed: bool = True,
    ) -> None:
        """Team *slug*'s rules from now on (None: the defaults).

        *version* defaults to one more than before (a save); *signed* False
        serves ``agent_rules_signed: null``, as a service without a signing
        key does.
        """
        with self._lock:
            current = self._teams.get(slug, {})
            self._teams[slug] = {
                "agent_rules": copy.deepcopy(agent_rules) if agent_rules is not None else None,
                "version": version if version is not None else current.get("version", 0) + 1,
                "lifetime": lifetime or DEFAULT_LIFETIME,
                "signed": signed,
            }

    def policy(self, slug: str, team_id: str) -> dict[str, Any]:
        """The ``GET …/policy`` body of team *slug* (id *team_id*)."""
        with self._lock:
            team = copy.deepcopy(self._teams.get(slug, {}))
        stored = team.get("agent_rules")
        version = team.get("version", 0)
        effective = stored if stored is not None else default_agent_rules()
        return {"data": {
            "allowed_tools": [], "blocked_tools": [], "require_approval": [],
            "max_connections": None, "allow_dangerous_ai_tools": False,
            "agent_rules": stored,
            "agent_rules_version": version,
            "agent_rules_signed": (
                self._envelope(team_id, version, effective, team.get("lifetime") or DEFAULT_LIFETIME)
                if team.get("signed", True) else None
            ),
        }}

    def _envelope(
        self, team_id: str, version: int, agent_rules: dict[str, Any], lifetime: dt.timedelta,
    ) -> dict[str, Any]:
        issued = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        payload = json.dumps({
            "format": FORMAT, "team_id": team_id, "version": version,
            "issued_at": _rfc3339(issued), "expires_at": _rfc3339(issued + lifetime),
            "agent_rules": agent_rules,
        }, separators=(",", ":")).encode("utf-8")
        return {
            "payload": _b64url(payload),
            "signatures": [{"key_id": self.key_id, "signature": _b64url(self._key.sign(payload))}],
        }


def add_routes(
    app: web.Application,
    store: ScenarioStore,
    rules: AgentRulesCloud,
    team_id_of: Callable[[str], Optional[str]],
) -> None:
    """Register the policy routes on *app*.

    *team_id_of* answers the id of a team the requesting user belongs to
    (None: not a member, or no such team).
    """

    async def policy(request: web.Request) -> web.Response:
        if not bearer_ok(request, store):
            return unauthorized()
        slug = request.match_info["slug"]
        team_id = team_id_of(slug)
        if team_id is None:
            return web.json_response({"error": {"code": "not_found"}}, status=404)
        return web.json_response(rules.policy(slug, team_id))

    app.router.add_get("/api/v1/teams/{slug}/policy", policy)
    app.router.add_get("/api/v1/teams/{slug}/mcp-policy", policy)
