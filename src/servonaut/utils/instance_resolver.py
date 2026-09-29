"""Shared instance resolution: ids, names and ``account/name`` references.

Every surface that turns a user- or agent-supplied reference into a server
(TUI, CLI, MCP tools, AI chat, relay) resolves it here, so the contract is
defined once and tested once:

- an instance id always wins (ids are unique within a provider);
- ``<account>/<name>`` or ``<account>/<id>`` picks a server of one account
  (account labels are unique across providers; a primary account's default
  label is the provider name, so ``hetzner/web-1`` always works);
  ``custom/<name>`` picks a custom server (``custom`` is a reserved label);
- a bare name must match exactly one server. A name shared by several
  servers is refused with :class:`AmbiguousInstanceError`, which lists the
  qualified references to retry with. Nothing is ever picked by guessing.

Matching is case-insensitive.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence

# Row keys (kept in sync with servonaut.services.accounts.fleet).
_ACCOUNT_KEY = "account"
_QUALIFIED_KEY = "account_qualified"
# Qualifier for custom servers, which belong to no provider account.
CUSTOM_QUALIFIER = "custom"

_PROVIDER_TITLES = {"aws": "AWS", "hetzner": "Hetzner", "ovh": "OVH", "custom": "custom"}


class AmbiguousInstanceError(LookupError):
    """A reference that matches more than one server."""

    def __init__(self, reference: str, candidates: Sequence[dict]):
        self.reference = reference
        self.candidates = list(candidates)
        options = ", ".join(describe_candidate(row) for row in self.candidates)
        super().__init__(
            f"{reference!r} matches {len(self.candidates)} servers: {options}. "
            f"Use one of these references or an instance ID."
        )


def _provider(row: dict) -> str:
    if row.get("is_custom"):
        return "custom"
    if row.get("is_ovh"):
        return "ovh"
    if row.get("is_hetzner"):
        return "hetzner"
    return "aws"


def display_name(row: dict) -> str:
    """The name to show for *row*: ``account/name`` when its provider has
    several accounts, otherwise the plain name (unchanged from before)."""
    name = str(row.get("name") or "")
    if row.get(_QUALIFIED_KEY) and row.get(_ACCOUNT_KEY):
        return f"{row[_ACCOUNT_KEY]}/{name or row.get('id') or ''}"
    return name


def _qualifier(row: dict) -> str:
    """The account label of a provider row, ``custom`` for a custom server."""
    if row.get("is_custom"):
        return CUSTOM_QUALIFIER
    return str(row.get(_ACCOUNT_KEY) or "")


def qualified_reference(row: dict) -> str:
    """A reference that picks *row*: ``account/name`` (``account/id`` when
    unnamed), ``custom/name`` for a custom server, else the bare id."""
    qualifier = _qualifier(row)
    name = str(row.get("name") or "")
    instance_id = str(row.get("id") or "")
    if qualifier:
        return f"{qualifier}/{name or instance_id}"
    return instance_id or name


def describe_candidate(row: dict) -> str:
    """``prod/web-1 (i-0abc, AWS)`` for an ambiguity message."""
    ref = qualified_reference(row)
    instance_id = str(row.get("id") or "")
    provider = _provider(row)
    title = _PROVIDER_TITLES.get(provider, provider)
    details = ", ".join(part for part in (instance_id if instance_id != ref else "", title) if part)
    return f"{ref} ({details})" if details else ref


def _key(row: dict) -> tuple:
    return (_provider(row), str(row.get("id") or ""), str(row.get(_ACCOUNT_KEY) or ""))


def match_instances(reference: str, rows: Iterable[dict]) -> List[dict]:
    """Every row *reference* could mean (see the module docstring).

    Returns only the id matches when there are any. Otherwise returns the
    union of ``account/...`` matches and plain name matches, so a custom
    server literally named ``prod/web-1`` and account ``prod``'s ``web-1``
    are both reported rather than one silently shadowing the other.
    """
    needle = (reference or "").strip().lower()
    if not needle:
        return []
    rows = [row for row in rows if isinstance(row, dict)]

    by_id = [row for row in rows if str(row.get("id") or "").lower() == needle]
    if by_id:
        return _unique(by_id)

    matches: List[dict] = []
    if "/" in needle:
        label, _, rest = needle.partition("/")
        if label and rest:
            for row in rows:
                if _qualifier(row).lower() != label:
                    continue
                if (
                    str(row.get("id") or "").lower() == rest
                    or str(row.get("name") or "").lower() == rest
                ):
                    matches.append(row)
    matches.extend(row for row in rows if str(row.get("name") or "").lower() == needle)
    return _unique(matches)


def _unique(rows: List[dict]) -> List[dict]:
    seen: Dict[tuple, dict] = {}
    for row in rows:
        seen.setdefault(_key(row), row)
    return list(seen.values())


def resolve_unique(reference: str, rows: Iterable[dict]) -> Optional[dict]:
    """The one row *reference* names, or None when nothing matches.

    Raises:
        AmbiguousInstanceError: The reference matches several servers.
    """
    matches = match_instances(reference, rows)
    if len(matches) > 1:
        raise AmbiguousInstanceError(reference, matches)
    return matches[0] if matches else None


def resolve_instance_from_lists(
    id_or_name: str,
    aws: Iterable[dict],
    custom: Iterable[dict],
    ovh: Optional[Iterable[dict]] = None,
    hetzner: Optional[Iterable[dict]] = None,
) -> Optional[dict]:
    """Resolve *id_or_name* across the provider lists (see :func:`resolve_unique`).

    Raises:
        AmbiguousInstanceError: The reference matches several servers.
    """
    pools = list(aws) + list(custom) + list(ovh or []) + list(hetzner or [])
    return resolve_unique(id_or_name, pools)
