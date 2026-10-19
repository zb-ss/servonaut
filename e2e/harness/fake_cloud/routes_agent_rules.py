"""Team agent rules: what owners and admins save, and the signed copy members verify.

``GET /api/v1/teams/{slug}/policy`` (and its ``/mcp-policy`` alias) answers
any member of the team, as the service does. Inside ``data`` it carries the
team's effective agent rules signed (``agent_rules_signed``) with this fake's
own Ed25519 key, plus the stored editor copy (``agent_rules``) and its
unsigned version, which a client must never enforce from. A team that saved
no rules serves the format 1 defaults at version 0.

``PUT /api/v1/teams/{slug}/mcp-policy`` is what the website's Policies tab
saves, with the service's rules:

* owners and admins save, members and viewers are refused (403);
* top-level fields merge; inside ``agent_rules`` the ``role_levels`` merge
  per role, ``servers`` and the two command lists replace, and ``null``
  resets a key (``agent_rules: null`` resets them all);
* an unknown key, a role or level the service does not know, a server the
  team does not share or a command name outside ``[A-Za-z0-9][A-Za-z0-9._+-]*``
  is refused with 400 and an ``errors`` map;
* only the owner changes ``allow_dangerous_ai_tools``, raises a level to
  ``dangerous`` (one that already was passes) or changes the owner's own
  level anywhere (403), and raising a level to ``dangerous`` needs
  ``allow_dangerous_ai_tools`` (400);
* the signed rules are the effective ones: ``dangerous`` counts as
  ``standard`` while ``allow_dangerous_ai_tools`` is off;
* the version rises to ``max(previous + 1, unix milliseconds)`` whenever the
  signed rules change, and never goes down.

The suite trusts the fake's key for the fake's API origin only, the way a
release trusts its bundled key (:meth:`AgentRulesCloud.trusted_keys`): the
test process patches ``team_policy_keys.TEAM_POLICY_KEYS`` and child
processes get it through the module redirects ``child_guard.py`` applies.

Journeys set the rules a team saved earlier with
:meth:`AgentRulesCloud.set_rules`, and change how they are served with
:meth:`AgentRulesCloud.serve` (unsigned, tampered with, signed with a key the
suite does not trust, or unavailable) and :meth:`AgentRulesCloud.replay` (a
copy served earlier). :meth:`AgentRulesCloud.served` lists what each GET
answered, so a journey can wait until a client has fetched a version.

Every route needs the account's current access token.
"""

from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from aiohttp import web
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from e2e.harness.fake_cloud.routes_auth import bearer_ok, json_body, unauthorized
from e2e.harness.fake_cloud.state import ScenarioStore
from e2e.harness.fake_cloud.teams import MANAGERS, ROLES, Refusal

FORMAT = 1
# The service's default lifetime of a signed copy.
DEFAULT_LIFETIME = dt.timedelta(hours=24)
LEVELS = ("readonly", "standard", "dangerous")
_KEY_ID_HEX_DIGITS = 16
_RULE_KEYS = ("role_levels", "servers", "command_allowlist", "command_blocklist")
_SERVER_KEYS = ("role_levels",)
_COMMAND_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
DANGEROUS_FLAG = "allow_dangerous_ai_tools"

# How a team's policy is served (AgentRulesCloud.serve).
SIGNED = "signed"            # signed with the key the suite trusts (the default)
UNSIGNED = "unsigned"        # agent_rules_signed is null, as without a signing key
TAMPERED = "tampered"        # the payload was changed after it was signed
UNKNOWN_KEY = "unknown_key"  # signed only with a key the suite does not trust
UNAVAILABLE = "unavailable"  # the policy routes answer 503
REPLAYED = "replayed"        # a copy served earlier (AgentRulesCloud.replay)
SERVING = (SIGNED, UNSIGNED, TAMPERED, UNKNOWN_KEY, UNAVAILABLE)


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


def _default_policy() -> dict[str, Any]:
    """The policy fields beside the agent rules, as a team that saved none has them."""
    return {
        "allowed_tools": [], "blocked_tools": [], "require_approval": [],
        "max_connections": None, DANGEROUS_FLAG: False,
    }


def effective_rules(stored: Optional[dict[str, Any]], allow_dangerous: bool) -> dict[str, Any]:
    """What the service signs for the editor copy *stored*: complete, by format 1's defaults.

    Without *allow_dangerous* every ``dangerous`` level counts as ``standard``.
    """
    rules = default_agent_rules()
    stored = stored or {}
    rules["role_levels"].update(copy.deepcopy(stored.get("role_levels") or {}))
    for key in ("servers", "command_allowlist", "command_blocklist"):
        if key in stored:
            rules[key] = copy.deepcopy(stored[key])
    if not allow_dangerous:
        overrides = [server.get("role_levels", {}) for server in rules["servers"].values()]
        for levels in [rules["role_levels"], *overrides]:
            for role, level in levels.items():
                if level == "dangerous":
                    levels[role] = "standard"
    return rules


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _rfc3339(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _key_id(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:_KEY_ID_HEX_DIGITS]


class RulesRefused(Refusal):
    """A save the service refuses as invalid: 400 with a field → message map."""

    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__(400, "validation_failed", "The policy is not valid.")
        self.errors = errors

    def body(self) -> dict[str, Any]:
        return {**super().body(), "errors": dict(self.errors)}


@dataclass
class _Team:
    """One team's saved policy and how it is served."""

    # The editor copy (None: nothing saved, or reset).
    stored: Optional[dict[str, Any]] = None
    version: int = 0
    lifetime: dt.timedelta = DEFAULT_LIFETIME
    policy: dict[str, Any] = field(default_factory=_default_policy)
    serving: str = SIGNED
    # With REPLAYED: the copy served, and its version.
    replayed: Optional[dict[str, Any]] = None
    replayed_version: Optional[int] = None
    # The last copy served signed for each version (what a replay serves).
    signed: dict[int, dict[str, Any]] = field(default_factory=dict)
    # What each GET answered: {"version", "serving", "status"}.
    served: list[dict[str, Any]] = field(default_factory=list)


class AgentRulesCloud:
    """The teams' agent rules and the keys that sign them (thread-safe)."""

    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.generate()
        # A key the suite never trusts (UNKNOWN_KEY).
        self._untrusted_key = Ed25519PrivateKey.generate()
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self._teams: dict[str, _Team] = {}

    @property
    def public_key(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )

    @property
    def key_id(self) -> str:
        return _key_id(self._key)

    def trusted_keys(self, origin: str) -> dict[str, dict[str, str]]:
        """The ``TEAM_POLICY_KEYS`` table that trusts this fake's key for *origin*."""
        return {origin: {self.key_id: base64.b64encode(self.public_key).decode("ascii")}}

    # -- journey controls ------------------------------------------------------

    def set_rules(
        self,
        slug: str,
        agent_rules: Optional[dict[str, Any]] = None,
        *,
        version: Optional[int] = None,
        lifetime: Optional[dt.timedelta] = None,
        allow_dangerous_ai_tools: Optional[bool] = None,
    ) -> int:
        """Team *slug* saved *agent_rules* earlier (None: the defaults); return the version.

        *agent_rules* is the editor copy (only the keys it changes), served
        as the service signs it (:func:`effective_rules`), without the checks
        a save goes through. *version* defaults to one more than before;
        *lifetime* is how long each signed copy is valid from now on. The
        policy is served signed again.
        """
        with self._lock:
            team = self._teams.setdefault(slug, _Team())
            team.stored = copy.deepcopy(agent_rules) if agent_rules is not None else None
            team.version = version if version is not None else team.version + 1
            if lifetime is not None:
                team.lifetime = lifetime
            if allow_dangerous_ai_tools is not None:
                team.policy[DANGEROUS_FLAG] = allow_dangerous_ai_tools
            self._serve_signed(team)
            return team.version

    def serve(self, slug: str, how: str) -> None:
        """Serve team *slug*'s policy *how* from now on (one of :data:`SERVING`)."""
        if how not in SERVING:
            raise ValueError(f"serve how? one of {', '.join(SERVING)} (a replay: replay())")
        with self._lock:
            team = self._teams.setdefault(slug, _Team())
            self._serve_signed(team)
            team.serving = how

    def replay(self, slug: str, version: int) -> None:
        """Serve the signed copy of *version* served earlier, unchanged, from now on.

        Raises:
            KeyError: no signed copy of *version* was served yet.
        """
        with self._lock:
            team = self._teams[slug]
            team.replayed = copy.deepcopy(team.signed[version])
            team.replayed_version = version
            team.serving = REPLAYED

    def version(self, slug: str) -> int:
        """Team *slug*'s current version."""
        with self._lock:
            team = self._teams.get(slug)
            return team.version if team is not None else 0

    def served(self, slug: str) -> list[dict[str, Any]]:
        """What each GET of team *slug*'s policy answered, oldest first."""
        with self._lock:
            team = self._teams.get(slug)
            return copy.deepcopy(team.served) if team is not None else []

    @staticmethod
    def _serve_signed(team: _Team) -> None:
        team.serving, team.replayed, team.replayed_version = SIGNED, None, None

    # -- answers -----------------------------------------------------------------

    def answer(self, slug: str, team_id: str) -> tuple[int, dict[str, Any]]:
        """``GET …/policy`` of team *slug* (id *team_id*): status and body, recorded."""
        with self._lock:
            team = self._teams.setdefault(slug, _Team())
            if team.serving == UNAVAILABLE:
                team.served.append({"version": None, "serving": UNAVAILABLE, "status": 503})
                return 503, {"error": {"code": "service_unavailable", "message": "Try again later."}}
            body = self._body(team, team_id)
            version = team.replayed_version if team.serving == REPLAYED else team.version
            team.served.append({"version": version, "serving": team.serving, "status": 200})
            return 200, body

    def _body(self, team: _Team, team_id: str) -> dict[str, Any]:
        """The policy body (lock held): the editor copy and the signed effective rules."""
        return {"data": {
            **copy.deepcopy(team.policy),
            "agent_rules": copy.deepcopy(team.stored),
            "agent_rules_version": team.version,
            "agent_rules_signed": self._envelope_for(team, team_id),
        }}

    def _envelope_for(self, team: _Team, team_id: str) -> Optional[dict[str, Any]]:
        if team.serving == UNSIGNED:
            return None
        if team.serving == REPLAYED:
            return copy.deepcopy(team.replayed)
        rules = effective_rules(team.stored, team.policy[DANGEROUS_FLAG])
        payload = self._payload(team_id, team.version, rules, team.lifetime)
        if team.serving == UNKNOWN_KEY:
            return self._envelope(payload, payload, self._untrusted_key)
        if team.serving == TAMPERED:
            return self._envelope(self._loosened(payload), payload, self._key)
        envelope = self._envelope(payload, payload, self._key)
        team.signed[team.version] = copy.deepcopy(envelope)
        return envelope

    @staticmethod
    def _payload(
        team_id: str, version: int, agent_rules: dict[str, Any], lifetime: dt.timedelta,
    ) -> bytes:
        issued = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        return json.dumps({
            "format": FORMAT, "team_id": team_id, "version": version,
            "issued_at": _rfc3339(issued), "expires_at": _rfc3339(issued + lifetime),
            "agent_rules": agent_rules,
        }, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _loosened(payload: bytes) -> bytes:
        """*payload* changed on the way: every role at the dangerous level."""
        document = json.loads(payload)
        document["agent_rules"]["role_levels"] = {role: "dangerous" for role in ROLES}
        return json.dumps(document, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _envelope(served: bytes, signed: bytes, key: Ed25519PrivateKey) -> dict[str, Any]:
        """*served* bytes carrying a signature over *signed* (the same, unless tampered)."""
        return {
            "payload": _b64url(served),
            "signatures": [{"key_id": _key_id(key), "signature": _b64url(key.sign(signed))}],
        }

    # -- saving (PUT …/mcp-policy) -------------------------------------------------

    def save(
        self, slug: str, team_id: str, body: Any, *, role: Optional[str], server_ids: Iterable[str],
    ) -> dict[str, Any]:
        """Save *body* for team *slug* as a member with *role*; the policy body after it.

        Raises:
            Refusal: 404 not a member, 403 not allowed, 400 (RulesRefused) invalid.
        """
        if role is None:
            raise Refusal(404, "not_found", "Team not found.")
        if role not in MANAGERS:
            raise Refusal(403, "forbidden", "Only team owners and admins can change the team's policies.")
        body = body if isinstance(body, dict) else {}
        with self._lock:
            team = self._teams.setdefault(slug, _Team())
            policy, stored = _changed(team, body, set(server_ids))
            _check_powers(role, team, policy, stored)
            before = effective_rules(team.stored, team.policy[DANGEROUS_FLAG])
            after = effective_rules(stored, policy[DANGEROUS_FLAG])
            team.policy, team.stored = policy, stored
            if after != before:
                team.version = max(team.version + 1, int(time.time() * 1000))
            return self._body(team, team_id)


def _changed(
    team: _Team, body: dict[str, Any], server_ids: set[str],
) -> tuple[dict[str, Any], Optional[dict[str, Any]]]:
    """The policy fields and editor copy *body* asks for.

    Raises:
        RulesRefused: anything in *body* is invalid.
    """
    errors: dict[str, str] = {}
    policy = copy.deepcopy(team.policy)
    for key, value in body.items():
        if key == "agent_rules":
            continue
        if key not in policy:
            errors[key] = "This field is not known."
        elif key == DANGEROUS_FLAG and not isinstance(value, bool):
            errors[key] = "This value should be a boolean."
        else:
            policy[key] = copy.deepcopy(value)
    stored = copy.deepcopy(team.stored)
    if "agent_rules" in body:
        stored = _merged_rules(stored, body["agent_rules"], server_ids, errors)
    if errors:
        raise RulesRefused(errors)
    return policy, stored


def _check_powers(
    role: str, team: _Team, policy: dict[str, Any], stored: Optional[dict[str, Any]],
) -> None:
    """Refuse what only the owner may do, and a new dangerous level without the flag."""
    # The levels as requested, before the flag lowers them.
    before, after = effective_rules(team.stored, True), effective_rules(stored, True)
    raised = _dangerous_slots(after) - _dangerous_slots(before)
    if role != "owner":
        if policy[DANGEROUS_FLAG] != team.policy[DANGEROUS_FLAG]:
            raise Refusal(403, "forbidden", "Only the team owner can change allow_dangerous_ai_tools.")
        if raised:
            raise Refusal(403, "forbidden", "Only the team owner can set the dangerous level.")
        servers = set(before["servers"]) | set(after["servers"])
        if _owner_levels(before, servers) != _owner_levels(after, servers):
            raise Refusal(403, "forbidden", "Only the team owner can change the owner's level.")
    if raised and not policy[DANGEROUS_FLAG]:
        raise RulesRefused({"agent_rules": f"The dangerous level needs {DANGEROUS_FLAG}."})


def _merged_rules(
    stored: Optional[dict[str, Any]], changes: Any, server_ids: set[str], errors: dict[str, str],
) -> Optional[dict[str, Any]]:
    """The editor copy *stored* with *changes* (a save's ``agent_rules``) applied."""
    if changes is None:
        return None
    if not isinstance(changes, dict):
        errors["agent_rules"] = "This value should be an object or null."
        return stored
    merged = copy.deepcopy(stored) if stored is not None else {}
    for key, value in changes.items():
        path = f"agent_rules.{key}"
        if key not in _RULE_KEYS:
            errors[path] = "This field is not known."
        elif value is None:
            merged.pop(key, None)
        elif key == "role_levels":
            merged["role_levels"] = {**merged.get("role_levels", {}), **_role_levels(value, path, errors)}
        elif key == "servers":
            merged["servers"] = _servers(value, path, server_ids, errors)
        elif key == "command_allowlist":
            merged[key] = _names(value, path, errors)
        else:
            merged[key] = _patterns(value, path, errors)
    return merged


def _role_levels(value: Any, path: str, errors: dict[str, str]) -> dict[str, str]:
    if not isinstance(value, dict):
        errors[path] = "This value should be an object."
        return {}
    for role, level in value.items():
        if role not in ROLES:
            errors[f"{path}.{role}"] = "This role is not known."
        elif level not in LEVELS:
            errors[f"{path}.{role}"] = f"The level should be one of {', '.join(LEVELS)}."
    return {role: level for role, level in value.items() if role in ROLES and level in LEVELS}


def _servers(value: Any, path: str, server_ids: set[str], errors: dict[str, str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors[path] = "This value should be an object."
        return {}
    servers = {}
    for server_id, override in value.items():
        where = f"{path}.{server_id}"
        if server_id not in server_ids:
            errors[where] = "The team does not share this server."
        elif not isinstance(override, dict) or set(override) - set(_SERVER_KEYS):
            errors[where] = "This value should be an object with role_levels only."
        else:
            servers[server_id] = {"role_levels": _role_levels(
                override.get("role_levels", {}), f"{where}.role_levels", errors,
            )}
    return servers


def _names(value: Any, path: str, errors: dict[str, str]) -> Optional[list[str]]:
    if not isinstance(value, list) or not all(
        isinstance(name, str) and _COMMAND_NAME.fullmatch(name) for name in value
    ):
        errors[path] = "This value should be a list of command names."
        return None
    return list(value)


def _patterns(value: Any, path: str, errors: dict[str, str]) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(pattern, str) and pattern for pattern in value):
        errors[path] = "This value should be a list of patterns."
        return []
    return list(value)


def _slots(rules: dict[str, Any]) -> dict[tuple[str, str], str]:
    """Every level *rules* sets: (server id, or "" team-wide; role) → level."""
    slots = {("", role): level for role, level in rules["role_levels"].items()}
    for server_id, override in rules["servers"].items():
        for role, level in override.get("role_levels", {}).items():
            slots[(server_id, role)] = level
    return slots


def _dangerous_slots(rules: dict[str, Any]) -> set[tuple[str, str]]:
    return {slot for slot, level in _slots(rules).items() if level == "dangerous"}


def _owner_levels(rules: dict[str, Any], servers: Iterable[str]) -> dict[str, str]:
    """The owner's resolved level team-wide ("") and on each of *servers*."""
    team_wide = rules["role_levels"]["owner"]
    levels = {"": team_wide}
    for server_id in servers:
        override = rules["servers"].get(server_id, {}).get("role_levels", {})
        levels[server_id] = override.get("owner", team_wide)
    return levels


def add_routes(
    app: web.Application,
    store: ScenarioStore,
    rules: AgentRulesCloud,
    *,
    team_id_of: Callable[[str], Optional[str]],
    role_of: Callable[[str], Optional[str]],
    server_ids: Callable[[str], list[str]],
) -> None:
    """Register the policy routes on *app*.

    *team_id_of* answers the id of a team the requesting user belongs to and
    *role_of* their role in it (None: not a member, or no such team);
    *server_ids* the ids of the servers a team shares.
    """

    async def policy(request: web.Request) -> web.Response:
        if not bearer_ok(request, store):
            return unauthorized()
        slug = request.match_info["slug"]
        team_id = team_id_of(slug)
        if team_id is None:
            return web.json_response({"error": {"code": "not_found"}}, status=404)
        status, body = rules.answer(slug, team_id)
        return web.json_response(body, status=status)

    async def save(request: web.Request) -> web.Response:
        if not bearer_ok(request, store):
            return unauthorized()
        slug = request.match_info["slug"]
        body = await json_body(request)
        try:
            answer = rules.save(
                slug, team_id_of(slug) or "", body, role=role_of(slug), server_ids=server_ids(slug),
            )
        except Refusal as refusal:
            return web.json_response(refusal.body(), status=refusal.status)
        return web.json_response(answer)

    app.router.add_get("/api/v1/teams/{slug}/policy", policy)
    app.router.add_get("/api/v1/teams/{slug}/mcp-policy", policy)
    app.router.add_put("/api/v1/teams/{slug}/mcp-policy", save)
