"""Interpret bucket policy grants without assuming provider enforcement."""

from __future__ import annotations

import json
import re
from typing import Any

_MANAGED_PUBLIC_READ_SID = "ServonautPublicRead"
_READ_ACTION = re.compile(r"s3:(?:Get|List|Describe)[A-Z][A-Z0-9]*", re.IGNORECASE)
_BUCKET_ARN = re.compile(r"arn:[^:]+:s3:::[^/]+/(.*)", re.DOTALL)
_ANONYMOUS_PRINCIPALS = frozenset({
    "anonymous",
    "allusers",
    "http://acs.amazonaws.com/groups/global/allusers",
    "65a011a29cdf8ec533ec3d1ccaae921c",
})
_SCOPE_NOTE = (
    "Scope describes policy statements. Conditions, explicit denies, ACLs "
    "and public-access blocks can affect actual access."
)


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    seen: set[str] = set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in seen:
            raise ValueError("Policy JSON has a duplicate field.")
        seen.add(folded)
        result[key] = value
    return result


def _invalid_constant(_value: str) -> Any:
    raise ValueError("Bucket policy must be valid JSON.")


def _names(value: Any) -> list[str]:
    if isinstance(value, str) and value:
        return [value]
    if isinstance(value, list) and value:
        if all(isinstance(item, str) and item for item in value):
            return value
    raise ValueError("Policy fields must contain nonempty strings.")


def _choice(statement: dict, positive: str, negative: str) -> tuple[str, Any]:
    if (positive in statement) == (negative in statement):
        raise ValueError(f"Each statement must specify exactly one of {positive} or {negative}.")
    element = positive if positive in statement else negative
    return element, statement[element]


def statements(policy: dict) -> list[dict]:
    rows = policy.get("Statement")
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list) or not rows:
        raise ValueError("Policy must contain at least one statement.")
    for row in rows:
        if not isinstance(row, dict) or row.get("Effect") not in ("Allow", "Deny"):
            raise ValueError("Each policy statement must have an Allow or Deny effect.")
        _names(_choice(row, "Action", "NotAction")[1])
        _names(_choice(row, "Resource", "NotResource")[1])
        principal = _choice(row, "Principal", "NotPrincipal")[1]
        if isinstance(principal, dict) and principal:
            for value in principal.values():
                _names(value)
        else:
            _names(principal)
    return rows


def parse_policy(document: str) -> dict:
    if not isinstance(document, str):
        raise ValueError("Bucket policy must be a JSON string.")
    try:
        policy = json.loads(document, object_pairs_hook=_unique_keys, parse_constant=_invalid_constant)
    except (json.JSONDecodeError, RecursionError):
        raise ValueError("Bucket policy must be valid JSON.") from None
    if not isinstance(policy, dict):
        raise ValueError("Bucket policy must be a JSON object.")
    statements(policy)
    return policy


def _can_include_anonymous(statement: dict) -> bool:
    if "NotPrincipal" in statement:
        return True
    principal = statement["Principal"]
    values = principal.values() if isinstance(principal, dict) else (principal,)
    return any(
        "*" in name or "?" in name or name.lower() in _ANONYMOUS_PRINCIPALS
        for value in values for name in _names(value)
    )


def check_policy(policy: dict, *, allow_public_write: bool) -> None:
    """Restrict broad allows and require explicit opt-in for anonymous mutation."""
    for row in statements(policy):
        if row["Effect"] == "Deny" or allow_public_write:
            continue
        element, value = _choice(row, "Action", "NotAction")
        actions = _names(value)
        wildcard = any("*" in action or "?" in action for action in actions)
        anonymous_write = _can_include_anonymous(row) and (
            element == "NotAction" or any(not _READ_ACTION.fullmatch(action) for action in actions)
        )
        if wildcard or anonymous_write:
            raise ValueError(
                "The policy may grant anonymous write or delete access or uses a wildcard "
                "Allow action. Confirm with the user before setting allow_public_write=true."
            )


def _public_statement(statement: dict) -> dict:
    action_field, actions = _choice(statement, "Action", "NotAction")
    resource_field, value = _choice(statement, "Resource", "NotResource")
    resources = _names(value)
    prefixes = []
    if resource_field == "Resource":
        for resource in resources:
            match = _BUCKET_ARN.fullmatch(resource)
            key = match[1] if match else ""
            if key.endswith("*") and not any(token in key[:-1] for token in ("*", "?", "${")):
                prefixes.append(key[:-1])
    scope = {
        "effect": statement["Effect"],
        "actions" if action_field == "Action" else "excluded_actions": _names(actions),
        "resources" if resource_field == "Resource" else "excluded_resources": resources,
        "prefixes": prefixes,
        "conditional": bool(statement.get("Condition")),
        "excludes_principals": "NotPrincipal" in statement,
    }
    condition = statement.get("Condition")
    if isinstance(condition, dict):
        list_prefixes = {
            operator: value
            for operator, fields in condition.items() if isinstance(fields, dict)
            for key, value in fields.items() if key.casefold() == "s3:prefix"
            if isinstance(value, str) or (
                isinstance(value, list) and all(isinstance(item, str) for item in value)
            )
        }
        if list_prefixes:
            scope["list_prefix_conditions"] = list_prefixes
    return scope


def public_scope(policy: dict | None) -> dict:
    rows = [] if policy is None else statements(policy)
    return {
        "public_scope": [_public_statement(row) for row in rows if _can_include_anonymous(row)],
        "public_scope_note": _SCOPE_NOTE,
    }


def with_public_read(policy: dict | None, bucket_arn: str, enabled: bool) -> dict | None:
    """Toggle the managed grant and preserve all other statements."""
    grant = {
        "Sid": _MANAGED_PUBLIC_READ_SID,
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": f"{bucket_arn}/*",
    }
    rows = [] if policy is None else statements(policy)
    marked = [row for row in rows if row.get("Sid") == _MANAGED_PUBLIC_READ_SID]
    managed = [
        row for row in marked
        if _is_managed_get_object(row, grant["Resource"])
    ]
    if enabled and len(managed) != len(marked):
        raise ValueError("The public-read statement ID is already used. Supply an explicit policy.")
    if (enabled and len(managed) == 1) or (not enabled and not managed):
        return policy
    unchanged = [row for row in rows if row not in managed]
    if enabled:
        unchanged.append(grant)
    if not unchanged:
        return None
    return {**(policy or {"Version": "2012-10-17"}), "Statement": unchanged}


def _is_managed_get_object(row: dict, resource: str) -> bool:
    if set(row) != {"Sid", "Effect", "Principal", "Action", "Resource"} or row["Effect"] != "Allow":
        return False
    principal = row["Principal"]
    if isinstance(principal, dict):
        if set(principal) != {"AWS"}:
            return False
        principal = principal["AWS"]
    return (
        _names(principal) == ["*"]
        and [name.lower() for name in _names(row["Action"])] == ["s3:getobject"]
        and _names(row["Resource"]) == [resource]
    )
