"""What to tell the user when a server's Bitwarden SSH key was not used."""

from __future__ import annotations

from typing import Any, Final, Mapping, Optional

from servonaut.services.bw_errors import (
    BwCliMissingError,
    BwItemNotFoundError,
    BwItemShapeError,
    BwSessionMissingError,
)

#: The conn entry that carries why a server's Bitwarden key was not used;
#: absent when no Bitwarden ref is involved or the key was read.
BW_KEY_UNAVAILABLE: Final = "bw_key_unavailable"

BW_KEY_UNREADABLE: Final = "BwKeyUnreadable"

#: The reason when the Servonaut API could not say whether the server has a
#: Bitwarden ref, though the ref list says it has one.
BW_REF_LOOKUP_FAILED: Final = "BwRefLookupFailed"

#: The conn entry naming the Bitwarden item whose key ``key_path`` holds; set
#: with a ``bw_*`` key_source. Private to Servonaut: never passed to ssh/scp
#: command builders (callers pick the entries they pass).
BW_ITEM_ID: Final = "bw_item_id"

_KNOWN_CLASSES = (
    BwCliMissingError,
    BwSessionMissingError,
    BwItemNotFoundError,
    BwItemShapeError,
)

_CAUSES: Final = {
    "BwCliMissingError": "The Bitwarden CLI (bw) was not found, so this server's Bitwarden key was not used.",
    "BwSessionMissingError": "Bitwarden is locked, so this server's Bitwarden key was not used.",
    "BwItemNotFoundError": "This server's Bitwarden item was not found, so its Bitwarden key was not used.",
    "BwItemShapeError": "This server's Bitwarden item is not an SSH key item, so its Bitwarden key was not used.",
    BW_KEY_UNREADABLE: "This server's Bitwarden key could not be read, so it was not used.",
    BW_REF_LOOKUP_FAILED: "This server's Bitwarden key reference could not be looked up, so its Bitwarden key was not used.",
}

_IN_APP_FIXES: Final = {
    "BwCliMissingError": "Install it, make sure it is on your PATH and retry.",
    "BwSessionMissingError": "Unlock it under Settings > Bitwarden SSH and retry.",
    "BwItemNotFoundError": "Check the server's SSH key reference and retry.",
    "BwItemShapeError": "Point the server's SSH key reference at a Bitwarden SSH key item and retry.",
    BW_KEY_UNREADABLE: "See the Servonaut log for the error type and retry.",
    BW_REF_LOOKUP_FAILED: "Check that you are signed in to Servonaut and online, then retry.",
}

_HEADLESS_FIXES: Final = {
    "BwCliMissingError": "Install it and make sure it is on the PATH of the environment the agent or CLI starts from, then retry.",
    # Read by an agent: the session value is for the user to handle, never the agent.
    "BwSessionMissingError": "Ask the user to unlock Bitwarden and restart this MCP server with BW_SESSION set in its environment; do not request or handle the session value yourself.",
    "BwItemNotFoundError": "Check the server's SSH key reference in Servonaut and retry.",
    "BwItemShapeError": "Point the server's SSH key reference at a Bitwarden SSH key item in Servonaut and retry.",
    BW_KEY_UNREADABLE: "See the Servonaut log for the error type and retry.",
    BW_REF_LOOKUP_FAILED: "Check that Servonaut is signed in and online, then retry.",
}


def bw_key_reason(exc: BaseException) -> str:
    """The reason code for *exc*; never uses the exception message."""
    for cls in _KNOWN_CLASSES:
        if isinstance(exc, cls):
            return cls.__name__
    return BW_KEY_UNREADABLE


def bw_key_notice(reason: Optional[str], *, headless: bool = False) -> Optional[str]:
    """The user-facing sentence for *reason*, or None when there is no reason."""
    if not reason:
        return None
    code = reason if reason in _CAUSES else BW_KEY_UNREADABLE
    fixes = _HEADLESS_FIXES if headless else _IN_APP_FIXES
    return f"{_CAUSES[code]} {fixes[code]}"


_ALL_NOTICES: Final = frozenset(
    f"{_CAUSES[code]} {fixes[code]}"
    for fixes in (_IN_APP_FIXES, _HEADLESS_FIXES)
    for code in _CAUSES
)


def is_bw_key_notice(text: str) -> bool:
    """Whether *text* is exactly one of the notices."""
    return (text or "").strip() in _ALL_NOTICES


def uses_bw_key(conn: Mapping[str, Any]) -> bool:
    """Whether *conn* authenticates with a Bitwarden key file."""
    return str(conn.get("key_source") or "").startswith("bw_")


def bw_item_id(conn: Mapping[str, Any]) -> Optional[str]:
    """The Bitwarden item whose key *conn* authenticates with, or None."""
    if not uses_bw_key(conn):
        return None
    item_id = conn.get(BW_ITEM_ID)
    return str(item_id) if item_id else None
