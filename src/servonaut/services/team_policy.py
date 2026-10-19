"""Signed team agent rules: verification, replay protection, expiry, cache.

A team's owners and admins set what members' agents may do on the team's
shared servers (see ``team_rules``). The Servonaut API signs those rules, and
``GET /api/v1/teams/{slug}/policy`` returns them in
``data.agent_rules_signed``::

    {"payload": base64url(bytes),
     "signatures": [{"key_id": str, "signature": base64url(Ed25519 signature)}]}

The payload bytes are verified first, with any signature by a key this
release trusts for the API origin in use (``team_policy_keys``; signatures by
other keys are ignored), and only then parsed::

    {"format": 1, "team_id": str, "version": int,
     "issued_at": RFC 3339, "expires_at": RFC 3339, "agent_rules": {...}}

Format 1 ``agent_rules`` has exactly these keys::

    {"role_levels": {role: level},                       # a role left out: readonly
     "servers": {server_id: {"role_levels": {role: level}}},  # roles left out: team-wide
     "command_allowlist": null | [command names],        # null: the built-in list
     "command_blocklist": [Python regular expressions]}  # added to the built-in list

Anything wrong fails closed: the team's shared servers then run at the
readonly level for every role, owners included, and refusals say why in
plain words (:class:`PolicyProblem`). That covers a missing envelope, no
trusted key, a bad signature, another team's rules, an unknown format, a
malformed payload (an unknown key in ``agent_rules`` too: it may be a
restriction this release cannot apply), a version older than one this device
accepted (a replay), the same version with different rules, and rules that
expired without a fresh copy.

Expiry is judged by the API's clock: every fetch records how far the
response's ``Date`` header is from the local clock. Rules are due for a
refresh halfway through their own lifetime.

The last good signed envelope of each team and the highest version seen are
kept in ``~/.servonaut/team_policy.json`` (owner-only, written atomically),
per API origin. The envelope is verified again when it is read back, so
editing the file can only make a team fall back to readonly.
"""
from __future__ import annotations

import base64
import email.utils
import json
import logging
import math
import re
import threading
import time
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from servonaut.services import team_policy_keys
from servonaut.services.team_rules import (
    DEFAULT_TEAM_RULES,
    GUARD_LEVELS,
    TEAM_ROLES,
    TeamRules,
)
from servonaut.utils.atomic_file import write_json_atomic

logger = logging.getLogger(__name__)

# The payload format this release reads.
FORMAT = 1
STATE_FILENAME = "team_policy.json"
_STATE_FORMAT = 1
# Upper bound on the payload this release decodes and parses. Far above any
# team's rules; it keeps a broken response from costing more than that.
MAX_PAYLOAD_BYTES = 1024 * 1024
_MAX_ENCODED_PAYLOAD = (MAX_PAYLOAD_BYTES + 2) // 3 * 4

_PAYLOAD_KEYS = frozenset({
    "format", "team_id", "version", "issued_at", "expires_at", "agent_rules",
})
_AGENT_RULES_KEYS = frozenset({
    "role_levels", "servers", "command_allowlist", "command_blocklist",
})
_SERVER_OVERRIDE_KEYS = frozenset({"role_levels"})
# A team allowlist entry is a command name: the first word of a pipeline
# segment, compared exactly. Anything else is dropped (which only tightens).
_COMMAND_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*={0,2}")
_RFC3339 = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]+))?(?:([Zz])|([+-])([0-9]{2}):([0-9]{2}))"
)


def format_1_default_agent_rules() -> Dict[str, Any]:
    """The ``agent_rules`` of a team that saved none (version 0).

    Format 1 fixes these, and they equal :data:`team_rules.DEFAULT_TEAM_RULES`;
    changing them takes a new format.
    """
    return {
        "role_levels": {
            "owner": "standard", "admin": "standard",
            "member": "standard", "viewer": "readonly",
        },
        "servers": {},
        "command_allowlist": None,
        "command_blocklist": [],
    }


@dataclass(frozen=True)
class PolicyProblem:
    """Why a team's rules fell back to readonly.

    ``reason`` is in plain words and reads after "because".
    """

    code: str
    reason: str


_RETRY = "check that you are online and signed in"
_UPDATE = "update Servonaut"

NOT_LOADED = PolicyProblem("not_loaded", "the team's agent rules have not been loaded yet")
UNREACHABLE = PolicyProblem(
    "unreachable", f"the team's agent rules could not be fetched; {_RETRY}",
)
MISSING = PolicyProblem("missing", "the team service sent no signed agent rules")
UNKNOWN_KEY = PolicyProblem(
    "unknown_key", f"this Servonaut cannot verify the team's agent rules; {_UPDATE}",
)
UNSUPPORTED_FORMAT = PolicyProblem(
    "unsupported_format", f"the team's agent rules need a newer Servonaut; {_UPDATE}",
)
BAD_SIGNATURE = PolicyProblem("bad_signature", "the team's agent rules could not be verified")
WRONG_TEAM = PolicyProblem("wrong_team", "the team service sent another team's agent rules")
MALFORMED = PolicyProblem("malformed", "the team's agent rules could not be read")
REPLAYED = PolicyProblem(
    "replayed", "the team service sent older agent rules than this device already has",
)
CONFLICTING = PolicyProblem(
    "conflicting",
    "the team service sent different agent rules under a version this device already has",
)
EXPIRED = PolicyProblem(
    "expired", f"the team's agent rules expired and could not be refreshed; {_RETRY}",
)


class PolicyRejected(Exception):
    """A signed policy that must not be used, and why."""

    def __init__(self, problem: PolicyProblem, detail: str = "") -> None:
        super().__init__(detail or problem.code)
        self.problem = problem


@dataclass(frozen=True)
class SignedPolicy:
    """A team's verified signed agent rules."""

    team_id: str
    version: int
    issued_at: datetime
    expires_at: datetime
    rules: TeamRules
    # The parsed agent_rules in a canonical form: two copies of one version
    # must say the same (the bytes may differ, e.g. a newer issued_at).
    canonical_rules: str
    # As received, to be verified again when it is read back from disk.
    envelope: Mapping[str, Any]

    def expired(self, server_now: float) -> bool:
        """Whether the rules are past ``expires_at`` at *server_now* (epoch, API clock)."""
        return server_now >= self.expires_at.timestamp()

    def refresh_at(self) -> float:
        """When (epoch, API clock) a fresh copy is due: half the lifetime."""
        issued, expires = self.issued_at.timestamp(), self.expires_at.timestamp()
        return issued + (expires - issued) / 2

    def same_rules(self, other: "SignedPolicy") -> bool:
        """Whether *other* says the same as this copy (team, format, agent_rules)."""
        return (self.team_id, self.canonical_rules) == (other.team_id, other.canonical_rules)


# ---------------------------------------------------------------------------
# Verifying and parsing
# ---------------------------------------------------------------------------

def _b64url_decode(value: Any) -> bytes:
    """Strict base64url (padding optional).

    Raises:
        ValueError: *value* is not base64url text.
    """
    if not isinstance(value, str) or not _BASE64URL.fullmatch(value):
        raise ValueError("not base64url")
    data = value.rstrip("=")
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _signature_verifies(public_key: Any, signature: Any, payload: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _b64url_decode(signature), payload,
        )
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _trusted_signatures(
    signatures: Sequence[Any], keys: Mapping[str, bytes],
) -> List[Tuple[bytes, Any]]:
    """(key, signature) for every signature by a trusted key; others are ignored."""
    found = []
    for entry in signatures:
        if not isinstance(entry, Mapping):
            continue
        key_id = entry.get("key_id")
        if isinstance(key_id, str) and key_id in keys:
            found.append((keys[key_id], entry.get("signature")))
    return found


def verify_envelope(envelope: Any, *, origin: Optional[str], team_id: str) -> SignedPolicy:
    """The team's rules from *envelope*, signed for API *origin*.

    Raises:
        PolicyRejected: The envelope must not be used (see the module docstring).
    """
    if envelope is None:
        raise PolicyRejected(MISSING)
    if not isinstance(envelope, Mapping):
        raise PolicyRejected(MALFORMED, "envelope is not an object")
    encoded, signatures = envelope.get("payload"), envelope.get("signatures")
    if not isinstance(encoded, str) or not isinstance(signatures, list):
        raise PolicyRejected(MALFORMED, "envelope lacks a payload or signatures")
    keys = team_policy_keys.keys_for_origin(origin) if origin else {}
    trusted = _trusted_signatures(signatures, keys)
    if not trusted:
        raise PolicyRejected(UNKNOWN_KEY)
    if len(encoded) > _MAX_ENCODED_PAYLOAD:
        raise PolicyRejected(MALFORMED, "payload too large")
    try:
        payload = _b64url_decode(encoded)
    except ValueError as exc:
        raise PolicyRejected(MALFORMED, "payload is not base64url") from exc
    if not any(_signature_verifies(key, signature, payload) for key, signature in trusted):
        raise PolicyRejected(BAD_SIGNATURE)
    policy = parse_payload(payload, team_id=team_id)
    stored = {"payload": encoded, "signatures": [dict(entry) for entry in signatures
                                                  if isinstance(entry, Mapping)]}
    return replace(policy, envelope=MappingProxyType(stored))


def _unique_keys(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
    document: Dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate key {key!r}")
        document[key] = value
    return document


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def parse_payload(payload: bytes, *, team_id: str) -> SignedPolicy:
    """The policy in verified *payload* bytes, which must be *team_id*'s.

    Raises:
        PolicyRejected: The payload is not format 1, is malformed, or is
            another team's.
    """
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_keys, parse_constant=_no_constants,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise PolicyRejected(MALFORMED, "payload is not JSON") from exc
    if not isinstance(document, dict) or not _is_int(document.get("format")):
        raise PolicyRejected(MALFORMED, "payload has no format")
    if document["format"] != FORMAT:
        raise PolicyRejected(UNSUPPORTED_FORMAT)
    if set(document) != _PAYLOAD_KEYS:
        raise PolicyRejected(MALFORMED, "payload keys")
    signed_team = document["team_id"]
    if not isinstance(signed_team, str) or not signed_team:
        raise PolicyRejected(MALFORMED, "team_id")
    if signed_team != team_id:
        raise PolicyRejected(WRONG_TEAM)
    version = document["version"]
    if not _is_int(version) or version < 0:
        raise PolicyRejected(MALFORMED, "version")
    issued_at = _rfc3339(document["issued_at"])
    expires_at = _rfc3339(document["expires_at"])
    if expires_at <= issued_at:
        raise PolicyRejected(MALFORMED, "expires_at is not after issued_at")
    agent_rules = document["agent_rules"]
    return SignedPolicy(
        team_id=signed_team, version=version, issued_at=issued_at, expires_at=expires_at,
        rules=parse_agent_rules(agent_rules),
        canonical_rules=json.dumps(agent_rules, sort_keys=True, separators=(",", ":")),
        envelope=MappingProxyType({}),
    )


def _rfc3339(value: Any) -> datetime:
    match = _RFC3339.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise PolicyRejected(MALFORMED, "timestamp")
    year, month, day, hour, minute, second, fraction, zulu, sign, hours, minutes = match.groups()
    microsecond = int((fraction or "0")[:6].ljust(6, "0"))
    try:
        if zulu:
            zone = timezone.utc
        else:
            delta = timedelta(hours=int(hours), minutes=int(minutes))
            zone = timezone(-delta if sign == "-" else delta)
        return datetime(
            int(year), int(month), int(day), int(hour), int(minute), int(second),
            microsecond, tzinfo=zone,
        )
    except ValueError as exc:
        raise PolicyRejected(MALFORMED, "timestamp") from exc


def _role_levels(value: Any) -> Mapping[str, str]:
    if not isinstance(value, dict):
        raise PolicyRejected(MALFORMED, "role_levels")
    for role, level in value.items():
        if role not in TEAM_ROLES or level not in GUARD_LEVELS:
            raise PolicyRejected(MALFORMED, "role_levels entry")
    return MappingProxyType(dict(value))


def _servers(value: Any) -> Mapping[str, Mapping[str, str]]:
    if not isinstance(value, dict):
        raise PolicyRejected(MALFORMED, "servers")
    servers = {}
    for server_id, override in value.items():
        if not server_id or not isinstance(override, dict):
            raise PolicyRejected(MALFORMED, "servers entry")
        if set(override) != _SERVER_OVERRIDE_KEYS:
            raise PolicyRejected(MALFORMED, "servers entry keys")
        servers[server_id] = _role_levels(override["role_levels"])
    return MappingProxyType(servers)


def _strings(value: Any, name: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyRejected(MALFORMED, name)
    return value


def parse_agent_rules(agent_rules: Any) -> TeamRules:
    """Format 1 *agent_rules* as the :class:`TeamRules` they set.

    Raises:
        PolicyRejected: A key is missing or unknown, or a value has the wrong
            shape (a level, role or list entry this release does not know).
    """
    if not isinstance(agent_rules, dict) or set(agent_rules) != _AGENT_RULES_KEYS:
        raise PolicyRejected(MALFORMED, "agent_rules keys")
    role_levels = _role_levels(agent_rules["role_levels"])
    servers = _servers(agent_rules["servers"])
    allowlist = agent_rules["command_allowlist"]
    if allowlist is None:
        commands = DEFAULT_TEAM_RULES.command_allowlist
    else:
        names = _strings(allowlist, "command_allowlist")
        commands = tuple(dict.fromkeys(name for name in names if _COMMAND_NAME.fullmatch(name)))
    builtin = DEFAULT_TEAM_RULES.command_blocklist
    added = _strings(agent_rules["command_blocklist"], "command_blocklist")
    blocklist = builtin + tuple(dict.fromkeys(p for p in added if p not in builtin))
    return TeamRules(
        role_levels=role_levels, command_allowlist=commands,
        command_blocklist=blocklist, servers=servers,
    )


def clock_offset(server_date: Optional[str], local_now: float) -> float:
    """Seconds the API's clock (an HTTP ``Date`` value) is ahead of *local_now*.

    0 when the value is missing or not a date.
    """
    if not server_date:
        return 0.0
    try:
        moment = email.utils.parsedate_to_datetime(server_date)
    except (TypeError, ValueError, IndexError, OverflowError):
        return 0.0
    if moment is None:
        return 0.0
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    offset = moment.timestamp() - local_now
    return offset if math.isfinite(offset) else 0.0


def current_api_origin() -> Optional[str]:
    """The origin of the API base in use; None when the override is invalid."""
    from servonaut.services.api_client import _api_base

    try:
        return team_policy_keys.api_origin(_api_base())
    except ValueError:
        return None


def default_state_path() -> Path:
    """``~/.servonaut/team_policy.json``."""
    return Path.home() / ".servonaut" / STATE_FILENAME


# ---------------------------------------------------------------------------
# The store
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TeamPolicyStatus:
    """What applies to one team's shared servers now, and why."""

    slug: str
    team_id: str
    # Team-wide (per-server overrides in ``rules.servers``); the readonly
    # fallback when ``problem`` is set.
    rules: TeamRules
    problem: Optional[PolicyProblem]
    # Of the last good signed copy, if any.
    version: Optional[int]
    expires_at: Optional[datetime]
    # When this device last got an answer about the team (epoch, local clock).
    fetched_at: Optional[float]


@dataclass(frozen=True)
class _TeamState:
    team_id: str
    slug: str
    highest_version: int = -1
    # The last copy accepted, with the API clock's offset when it was fetched.
    policy: Optional[SignedPolicy] = None
    clock_offset: float = 0.0
    fetched_at: Optional[float] = None
    # The last answer (or the cached copy) was refused.
    rejection: Optional[PolicyProblem] = None
    # The last fetch failed; a valid cached copy still applies until it expires.
    fetch_problem: Optional[PolicyProblem] = None


def _number(value: Any) -> Optional[float]:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        return float(value)
    return None


def _team_identity(team: Any) -> Optional[Tuple[str, str]]:
    """(slug, id) of a team-list row; None when either is missing."""
    if not isinstance(team, Mapping):
        return None
    slug, team_id = team.get("slug"), team.get("id")
    if not isinstance(slug, str) or not slug:
        return None
    if _is_int(team_id):
        team_id = str(team_id)
    if not isinstance(team_id, str) or not team_id:
        return None
    return slug, team_id


def _envelope_of(body: Any) -> Any:
    data = body.get("data") if isinstance(body, Mapping) else None
    if not isinstance(data, Mapping):
        data = body
    return data.get("agent_rules_signed") if isinstance(data, Mapping) else None


class TeamPolicyStore:
    """The verified agent rules of every team, by slug.

    :meth:`refresh` fetches them (async); :meth:`rules_for_team` and
    :meth:`status` read what applies now (sync, safe from any thread). The
    state file is read on first use and again by every refresh, so a version
    another Servonaut process accepted counts here too.
    """

    def __init__(
        self,
        state_path: Path,
        *,
        origin: Callable[[], Optional[str]] = current_api_origin,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._path = Path(state_path)
        self._origin = origin
        self._clock = clock
        self._lock = threading.RLock()
        self._save_lock = threading.Lock()
        self._teams: Dict[str, _TeamState] = {}
        self._slugs: Dict[str, str] = {}
        self._loaded = False
        self._loaded_origin: Optional[str] = None
        # Answers are applied in the order their fetches started, so an
        # older answer finishing late never replaces a newer one.
        self._sequence = 0
        self._applied: Dict[str, int] = {}

    @property
    def state_path(self) -> Path:
        return self._path

    # -- reading -------------------------------------------------------------

    def rules_for_team(self, slug: str) -> TeamRules:
        """What the agents may do on team *slug*'s servers now (team-wide)."""
        status = self.status(slug)
        return status.rules if status is not None else TeamRules.readonly(NOT_LOADED.reason)

    def status(self, slug: str) -> Optional[TeamPolicyStatus]:
        """What applies to team *slug* now; None for a team never seen."""
        with self._lock:
            self._ensure_loaded()
            team_id = self._slugs.get(slug)
            state = self._teams.get(team_id) if team_id is not None else None
        return self._status_of(state) if state is not None else None

    def statuses(self) -> List[TeamPolicyStatus]:
        """What applies to every team seen, by slug."""
        with self._lock:
            self._ensure_loaded()
            states = [self._teams[team_id] for team_id in dict.fromkeys(self._slugs.values())]
        return [self._status_of(state) for state in states]

    def load(self) -> None:
        """Read the rules saved on this device, so they apply before any fetch."""
        with self._lock:
            self._ensure_loaded()

    def seconds_until_refresh(self) -> Optional[float]:
        """Seconds until the rules should be fetched again (by the API clock).

        Each team's rules are due halfway through their lifetime. Once that
        is past (the fetch then failed), the next try is halfway through the
        time left until they expire, so the tries come closer together and
        stop at expiry; expired rules are left to the next listing of the
        teams. None when no team has rules in force.
        """
        now = self._clock()
        with self._lock:
            self._ensure_loaded()
            waits = [
                _next_try(state.policy, now + state.clock_offset)
                for state in self._teams.values()
                if state.policy is not None and state.rejection is None
            ]
        waits = [wait for wait in waits if wait is not None]
        return min(waits) if waits else None

    def _status_of(self, state: _TeamState) -> TeamPolicyStatus:
        policy = state.policy
        problem = state.rejection
        if problem is None and policy is None:
            problem = state.fetch_problem or NOT_LOADED
        if problem is None and policy.version < state.highest_version:
            # This device accepted a newer copy whose rules are not here.
            problem = REPLAYED
        if problem is None and policy.expired(self._clock() + state.clock_offset):
            problem = EXPIRED
        rules = TeamRules.readonly(problem.reason) if problem is not None else policy.rules
        return TeamPolicyStatus(
            slug=state.slug, team_id=state.team_id, rules=rules, problem=problem,
            version=policy.version if policy is not None else None,
            expires_at=policy.expires_at if policy is not None else None,
            fetched_at=state.fetched_at,
        )

    # -- refreshing ----------------------------------------------------------

    async def refresh(
        self, team_service: Any, teams: Optional[Iterable[Mapping[str, Any]]] = None,
    ) -> List[TeamPolicyStatus]:
        """Fetch and verify the rules of every team in *teams*.

        *teams* are team-list rows (``slug`` and ``id``); without them the
        team list is read first. A team whose rules cannot be fetched keeps
        its cached rules until they expire; the other teams still refresh.

        Raises:
            Exception: the team list itself could not be read; the caller
                decides how loudly to say so.
        """
        if teams is None:
            teams = await team_service.list_teams()
        with self._lock:
            self._ensure_loaded()
            self._absorb_disk()
        statuses = []
        for team in teams or []:
            identity = _team_identity(team)
            if identity is None:
                logger.warning("A team in the team list has no slug or id; its rules are skipped")
                continue
            slug, team_id = identity
            sequence = self._begin(team_id)
            try:
                body, server_date = await team_service.get_team_policy_with_date(slug)
            except Exception as exc:  # noqa: BLE001 — another team may still refresh
                logger.warning("Could not fetch the agent rules of team %s: %s", slug, exc)
                statuses.append(self._fetch_failed(team_id, slug, sequence))
                continue
            statuses.append(self._apply(team_id, slug, body, server_date, sequence))
        return statuses

    def apply_response(
        self, team: Mapping[str, Any], body: Any, server_date: Optional[str] = None,
    ) -> TeamPolicyStatus:
        """Verify and apply a policy response *body* for *team* (a team-list row).

        *server_date* is the response's ``Date`` header.

        Raises:
            ValueError: *team* has no slug or id.
        """
        identity = _team_identity(team)
        if identity is None:
            raise ValueError("a team needs a slug and an id")
        slug, team_id = identity
        return self._apply(team_id, slug, body, server_date, self._begin(team_id))

    def _begin(self, team_id: str) -> int:
        with self._lock:
            self._sequence += 1
            return self._sequence

    def _is_stale(self, team_id: str, sequence: int) -> bool:
        """Whether a newer fetch of *team_id* was applied already; else claim it."""
        if sequence < self._applied.get(team_id, 0):
            return True
        self._applied[team_id] = sequence
        return False

    def _fetch_failed(self, team_id: str, slug: str, sequence: int) -> TeamPolicyStatus:
        with self._lock:
            state = self._teams.get(team_id) or _TeamState(team_id=team_id, slug=slug)
            if not self._is_stale(team_id, sequence):
                state = replace(state, slug=slug, fetch_problem=UNREACHABLE)
                self._remember(state)
        return self._status_of(state)

    def _apply(
        self, team_id: str, slug: str, body: Any, server_date: Optional[str], sequence: int,
    ) -> TeamPolicyStatus:
        received_at = self._clock()
        offset = clock_offset(server_date, received_at)
        origin = self._current_origin()
        accepted = False
        with self._lock:
            self._ensure_loaded()
            previous = self._teams.get(team_id) or _TeamState(team_id=team_id, slug=slug)
            if self._is_stale(team_id, sequence):
                return self._status_of(previous)
            try:
                policy = verify_envelope(_envelope_of(body), origin=origin, team_id=team_id)
                _check_order(previous, policy)
                if policy.expired(received_at + offset):
                    raise PolicyRejected(EXPIRED)
            except PolicyRejected as exc:
                logger.warning(
                    "Agent rules of team %s refused (%s): %s", slug, exc.problem.code, exc,
                )
                state = replace(
                    previous, slug=slug, rejection=exc.problem, fetch_problem=None,
                    fetched_at=received_at,
                )
            else:
                state = _TeamState(
                    team_id=team_id, slug=slug,
                    highest_version=max(previous.highest_version, policy.version),
                    policy=policy, clock_offset=offset, fetched_at=received_at,
                )
                accepted = True
            self._remember(state)
        if accepted:
            self._save()
        return self._status_of(state)

    def _remember(self, state: _TeamState) -> None:
        self._teams[state.team_id] = state
        self._slugs[state.slug] = state.team_id

    def _current_origin(self) -> Optional[str]:
        try:
            return self._origin()
        except ValueError:
            return None

    # -- the state file ------------------------------------------------------

    def _ensure_loaded(self) -> None:
        """Read the state file for the API origin in use (again if it changed)."""
        origin = self._current_origin()
        if self._loaded and origin == self._loaded_origin:
            return
        self._teams.clear()
        self._slugs.clear()
        self._applied.clear()
        self._loaded, self._loaded_origin = True, origin
        self._absorb_disk()

    def _absorb_disk(self) -> None:
        """Take in the state file's teams.

        A team known here only by a failed fetch takes the saved copy whole.
        For the others a newer valid copy another process saved replaces the
        one held here (an answer refused here still stands), and a higher
        saved version counts (a replay check).
        """
        origin = self._loaded_origin
        if origin is None:
            return
        for team_id, entry in self._disk_entries(origin).items():
            stored = _state_from_disk(team_id, entry, origin)
            if stored is None:
                continue
            current = self._teams.get(team_id)
            if current is None or (
                current.policy is None and current.rejection is None
                and stored.policy is not None
            ):
                self._remember(stored)
                continue
            merged = current
            if _is_newer_copy(stored, current):
                merged = replace(
                    merged, policy=stored.policy, clock_offset=stored.clock_offset,
                    fetched_at=(
                        stored.fetched_at if stored.fetched_at is not None else merged.fetched_at
                    ),
                )
            if stored.highest_version > merged.highest_version:
                merged = replace(merged, highest_version=stored.highest_version)
            self._teams[team_id] = merged

    def _read_document(self) -> Dict[str, Any]:
        try:
            with open(self._path, encoding="utf-8") as handle:
                document = json.load(handle)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, RecursionError) as exc:
            logger.warning("Ignoring the unreadable team agent rules file %s: %s", self._path, exc)
            return {}
        if not isinstance(document, dict) or document.get("format") != _STATE_FORMAT:
            return {}
        return document

    def _disk_entries(self, origin: str) -> Dict[str, Any]:
        origins = self._read_document().get("origins")
        entries = origins.get(origin) if isinstance(origins, dict) else None
        return entries if isinstance(entries, dict) else {}

    def _save(self) -> None:
        """Write the accepted copies, keeping newer ones another process wrote."""
        with self._lock:
            origin = self._loaded_origin
            entries = {
                team_id: _state_to_disk(state)
                for team_id, state in self._teams.items() if state.policy is not None
            }
        if origin is None or not entries:
            return
        with self._save_lock:
            document = self._read_document()
            origins = document.get("origins")
            origins = origins if isinstance(origins, dict) else {}
            current = origins.get(origin)
            current = current if isinstance(current, dict) else {}
            for team_id, entry in entries.items():
                current[team_id] = _newer_entry(
                    current.get(team_id), entry, origin=origin, team_id=team_id,
                )
            origins[origin] = current
            try:
                write_json_atomic(self._path, {"format": _STATE_FORMAT, "origins": origins})
            except (OSError, TypeError) as exc:
                logger.warning("Could not save the team agent rules to %s: %s", self._path, exc)


def _is_newer_copy(stored: _TeamState, current: _TeamState) -> bool:
    """Whether *stored* holds a valid copy newer than the one *current* holds."""
    if stored.policy is None or stored.rejection is not None:
        return False
    return current.policy is None or stored.policy.version > current.policy.version


def _next_try(policy: SignedPolicy, server_now: float) -> Optional[float]:
    """Seconds until *policy* should be fetched again; None once it expired."""
    left = policy.expires_at.timestamp() - server_now
    if left <= 0:
        return None
    due = policy.refresh_at() - server_now
    return due if due > 0 else left / 2


def _check_order(previous: _TeamState, policy: SignedPolicy) -> None:
    """Refuse a replay (older version) or a different copy of the same version.

    Raises:
        PolicyRejected: REPLAYED or CONFLICTING.
    """
    if policy.version < previous.highest_version:
        raise PolicyRejected(REPLAYED)
    known = previous.policy
    if known is not None and known.version == policy.version and not known.same_rules(policy):
        raise PolicyRejected(CONFLICTING)


def _state_to_disk(state: _TeamState) -> Dict[str, Any]:
    return {
        "slug": state.slug,
        "highest_version": state.highest_version,
        "envelope": dict(state.policy.envelope) if state.policy is not None else None,
        "clock_offset": state.clock_offset,
        "fetched_at": state.fetched_at,
    }


def _highest_saved(entry: Any) -> int:
    version = entry.get("highest_version") if isinstance(entry, dict) else None
    return version if _is_int(version) else -1


def _entry_rank(entry: Any, origin: str, team_id: str) -> Tuple[int, float]:
    """(signed version of the saved envelope, when it was fetched); -1 if it does not verify."""
    if not isinstance(entry, dict):
        return (-1, -math.inf)
    try:
        version = verify_envelope(entry.get("envelope"), origin=origin, team_id=team_id).version
    except PolicyRejected:
        version = -1
    fetched = _number(entry.get("fetched_at"))
    return (version, fetched if fetched is not None else -math.inf)


def _newer_entry(
    on_disk: Any, ours: Dict[str, Any], *, origin: str, team_id: str,
) -> Dict[str, Any]:
    """The saved entry of one team with the newer envelope; the highest version is kept.

    Envelopes are ranked by their signed version, then by when they were
    fetched, so an older copy held here never replaces a newer one saved.
    """
    newer = (
        on_disk if _entry_rank(on_disk, origin, team_id) > _entry_rank(ours, origin, team_id)
        else ours
    )
    merged = dict(newer)
    merged["highest_version"] = max(_highest_saved(on_disk), _highest_saved(ours))
    return merged


def _state_from_disk(team_id: str, entry: Any, origin: str) -> Optional[_TeamState]:
    """A team's saved state, its envelope verified again; None if unusable.

    A saved clock offset only counts when it brings expiry closer: an edited
    file can never keep rules alive longer than the local clock would.
    """
    if not isinstance(entry, dict) or not isinstance(entry.get("slug"), str) or not entry["slug"]:
        return None
    slug = entry["slug"]
    highest = entry.get("highest_version")
    highest = highest if _is_int(highest) and highest >= 0 else -1
    fetched_at = _number(entry.get("fetched_at"))
    try:
        policy = verify_envelope(entry.get("envelope"), origin=origin, team_id=team_id)
        if policy.version < highest:
            raise PolicyRejected(REPLAYED)
    except PolicyRejected as exc:
        return _TeamState(
            team_id=team_id, slug=slug, highest_version=highest,
            fetched_at=fetched_at, rejection=exc.problem,
        )
    return _TeamState(
        team_id=team_id, slug=slug, highest_version=max(highest, policy.version),
        policy=policy, clock_offset=max(0.0, _number(entry.get("clock_offset")) or 0.0),
        fetched_at=fetched_at,
    )


_default_store: Optional[TeamPolicyStore] = None
_default_store_lock = threading.Lock()


def team_policy_store() -> TeamPolicyStore:
    """The process's store, on ``~/.servonaut/team_policy.json``."""
    global _default_store
    with _default_store_lock:
        if _default_store is None:
            _default_store = TeamPolicyStore(default_state_path())
        return _default_store
