"""Signed team agent rules for tests.

A throwaway Ed25519 key signs the rules, and :func:`trust_test_key` makes this
process trust it for the API origin in use, the way a release trusts its
bundled key. :func:`trust_signed_team_rules` then gives a team verified rules
in the process's store, through the same verification a fetched policy goes
through. The suite's conftest restores the store and the key table after
every test.
"""
from __future__ import annotations

import atexit
import base64
import json
import shutil
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from servonaut.services import team_policy, team_policy_keys
from servonaut.services.team_policy import TeamPolicyStatus, TeamPolicyStore

TEST_KEY = Ed25519PrivateKey.generate()
LIFETIME = timedelta(hours=1)

_STATE_DIR = Path(tempfile.mkdtemp(prefix="servonaut-team-policy-"))
atexit.register(shutil.rmtree, _STATE_DIR, True)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def raw_public_key(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )


TEST_KEY_ID = team_policy_keys.key_id_for(raw_public_key(TEST_KEY))


def rfc3339(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def team_id_for(slug: str) -> str:
    return f"team-id-{slug}"


def team_row(slug: str = "ops", **changes: Any) -> Dict[str, Any]:
    """A team-list row (``GET /api/v1/teams``)."""
    row = {"id": team_id_for(slug), "slug": slug, "name": slug.title(), "role": "member"}
    row.update(changes)
    return row


def default_agent_rules() -> Dict[str, Any]:
    return team_policy.format_1_default_agent_rules()


def agent_rules_with(
    *, role_levels: Optional[Dict[str, str]] = None, **changes: Any,
) -> Dict[str, Any]:
    """The format 1 defaults with *role_levels* merged in and other keys replaced."""
    rules = default_agent_rules()
    rules["role_levels"].update(role_levels or {})
    rules.update(changes)
    return rules


def payload(
    team_id: str,
    agent_rules: Optional[Dict[str, Any]] = None,
    *,
    version: int = 1,
    issued_at: Optional[datetime] = None,
    expires_at: Optional[datetime] = None,
    fmt: Any = 1,
    **extra: Any,
) -> Dict[str, Any]:
    """A payload document; *extra* adds (or, as None, removes) keys."""
    issued = issued_at or datetime.now(timezone.utc).replace(microsecond=0)
    document: Dict[str, Any] = {
        "format": fmt,
        "team_id": team_id,
        "version": version,
        "issued_at": rfc3339(issued),
        "expires_at": rfc3339(expires_at or issued + LIFETIME),
        "agent_rules": default_agent_rules() if agent_rules is None else agent_rules,
    }
    for key, value in extra.items():
        if value is None:
            document.pop(key, None)
        else:
            document[key] = value
    return document


def sign(
    data: bytes,
    *,
    key: Ed25519PrivateKey = TEST_KEY,
    key_id: str = TEST_KEY_ID,
    extra_signatures: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """An envelope of *data* signed by *key* under *key_id*."""
    signatures = list(extra_signatures or [])
    signatures.append({"key_id": key_id, "signature": b64url(key.sign(data))})
    return {"payload": b64url(data), "signatures": signatures}


def encode(document: Dict[str, Any]) -> bytes:
    return json.dumps(document).encode("utf-8")


def envelope(team_id: str, agent_rules: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    """A signed envelope of :func:`payload` (keyword arguments as there)."""
    return sign(encode(payload(team_id, agent_rules, **kwargs)))


def response(signed: Any) -> Dict[str, Any]:
    """A ``GET /api/v1/teams/{slug}/policy`` body carrying *signed*."""
    return {"data": {"allowed_tools": [], "agent_rules_signed": signed}}


def trust_test_key(
    origin: Optional[str] = None,
    key: Ed25519PrivateKey = TEST_KEY,
    key_id: Optional[str] = None,
) -> None:
    """Trust *key* for *origin* (the API origin in use by default).

    *key_id* defaults to the key's own id (see ``team_policy_keys.key_id_for``).
    """
    key_id = key_id or team_policy_keys.key_id_for(raw_public_key(key))
    origin = origin or team_policy.current_api_origin()
    table = {name: dict(keys) for name, keys in team_policy_keys.TEAM_POLICY_KEYS.items()}
    table.setdefault(origin, {})[key_id] = base64.b64encode(raw_public_key(key)).decode("ascii")
    team_policy_keys.TEAM_POLICY_KEYS = MappingProxyType(
        {name: MappingProxyType(keys) for name, keys in table.items()}
    )


def state_path() -> Path:
    """A state file path no other test uses."""
    return _STATE_DIR / f"team_policy-{uuid.uuid4().hex}.json"


def new_store(**kwargs: Any) -> TeamPolicyStore:
    return TeamPolicyStore(kwargs.pop("state_path", None) or state_path(), **kwargs)


def process_store() -> TeamPolicyStore:
    """The process's store, on a state file of its own."""
    if team_policy._default_store is None:
        team_policy._default_store = new_store()
    return team_policy._default_store


def trust_signed_team_rules(
    slug: str = "ops", agent_rules: Optional[Dict[str, Any]] = None, *, version: int = 1,
) -> TeamPolicyStatus:
    """Give team *slug* verified signed *agent_rules* (format 1 defaults by default)."""
    trust_test_key()
    status = process_store().apply_response(
        team_row(slug), response(envelope(team_id_for(slug), agent_rules, version=version)),
    )
    assert status.problem is None, status.problem
    return status
