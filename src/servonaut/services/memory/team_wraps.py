"""Catch-up wraps for team members after an upload.

The service accepts an upload sealed for its owner alone and answers with
``missing_team_wraps``: for each envelope of a server that a live share covers,
the members that cannot read it yet. This module validates that payload and
seals the envelope's data key for exactly those members.

Nothing here logs or keeps a data key or a private key, and a payload that does
not fit the expected shape is dropped whole (or per recipient) with a log of
its shape only.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from servonaut.services.memory.crypto import (
    X25519_KEY_LEN,
    fingerprint,
    reseal_dek,
)

logger = logging.getLogger(__name__)

# Slugs and ids end up in a URL path: only plain identifier characters pass.
_PATH_SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


@dataclass(frozen=True)
class Recipient:
    """A member that still lacks a wrap, with the key the service holds."""

    user_id: int
    fingerprint: str
    public_key: bytes


@dataclass(frozen=True)
class MissingTeamWrap:
    """One envelope of a live share and the members that miss a wrap for it."""

    envelope_id: str
    instance_id: str
    module: str
    team_slug: str
    grant_id: str
    recipients: Tuple[Recipient, ...]
    key_changed_count: int


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _parse_recipient(raw: Any) -> Tuple[str, Any]:
    """Return ``("ok", Recipient)``, ``("key_changed", None)`` or ``("bad", None)``."""
    if not isinstance(raw, dict):
        return "bad", None
    user_id = raw.get("user_id")
    if not isinstance(user_id, int) or isinstance(user_id, bool):
        return "bad", None
    changed = raw.get("key_changed")
    if not isinstance(changed, bool):
        return "bad", None
    if changed:
        # A changed key needs the user's confirmation: never sealed for.
        return "key_changed", None
    claimed, key_b64 = raw.get("fingerprint"), raw.get("public_key_b64")
    if not _text(claimed) or not _text(key_b64):
        return "bad", None
    try:
        key = base64.b64decode(key_b64, validate=True)
    except (binascii.Error, ValueError):
        return "bad", None
    # The fingerprint we send back is what lets the service skip a member whose
    # key changed since; one that does not belong to this key is not trusted.
    if len(key) != X25519_KEY_LEN or not any(key) or fingerprint(key) != claimed:
        return "bad", None
    return "ok", Recipient(user_id=user_id, fingerprint=claimed, public_key=key)


def _parse_entry(raw: Any) -> Any:
    if not isinstance(raw, dict):
        return None
    for name in ("envelope_id", "instance_id", "module"):
        if not _text(raw.get(name)):
            return None
    for name in ("team_slug", "grant_id"):
        value = raw.get(name)
        if not isinstance(value, str) or not _PATH_SAFE.match(value):
            return None
    raw_recipients = raw.get("recipients")
    if not isinstance(raw_recipients, list):
        return None
    recipients: List[Recipient] = []
    changed = 0
    for item in raw_recipients:
        kind, recipient = _parse_recipient(item)
        if kind == "ok":
            recipients.append(recipient)
        elif kind == "key_changed":
            changed += 1
    return MissingTeamWrap(
        envelope_id=raw["envelope_id"],
        instance_id=raw["instance_id"],
        module=raw["module"],
        team_slug=raw["team_slug"],
        grant_id=raw["grant_id"],
        recipients=tuple(recipients),
        key_changed_count=changed,
    )


def parse_missing_team_wraps(payload: Any) -> List[MissingTeamWrap]:
    """The usable entries of a sync response's ``missing_team_wraps``.

    A wrong overall shape yields an empty list; a bad entry is dropped on its
    own. Only the shape (types, counts) is logged, never an id or a key.
    """
    if payload is None:
        return []
    if not isinstance(payload, list):
        logger.debug("missing_team_wraps ignored: expected a list, got %s", type(payload).__name__)
        return []
    entries: List[MissingTeamWrap] = []
    for raw in payload:
        entry = _parse_entry(raw)
        if entry is None:
            logger.debug("missing_team_wraps entry ignored: malformed (%s)", type(raw).__name__)
            continue
        entries.append(entry)
    return entries


def seal_for_recipients(
    entry: MissingTeamWrap, *, self_wrapped_dek: str, private_key: bytes
) -> List[Dict[str, Any]]:
    """The wrap bodies for *entry*'s recipients, each tied to its fingerprint.

    Raises:
        CryptoError: (``crypto``) if the caller's own wrap cannot be opened.
    """
    if not entry.recipients:
        return []
    sealed = reseal_dek(
        self_wrapped_dek,
        private_key=private_key,
        recipient_public_keys=[r.public_key for r in entry.recipients],
    )
    return [
        {
            "recipient_user_id": r.user_id,
            "envelope_id": entry.envelope_id,
            "wrapped_dek": wrapped,
            "recipient_fingerprint": r.fingerprint,
        }
        for r, wrapped in zip(entry.recipients, sealed)
        if wrapped is not None
    ]


class WrapPinStore:
    """The key fingerprint last sealed for each team member (trust on first use).

    A small JSON file, mode 0600, written atomically. It holds fingerprints
    only (public values), never a key. A missing or unreadable file is an empty
    store: every member is then new.
    """

    def __init__(self, path: Path) -> None:
        self._path = path

    def _load(self) -> Dict[str, str]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            logger.warning("team wrap pins unreadable; treating every member as new")
            return {}
        if not isinstance(data, dict):
            return {}
        return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}

    @staticmethod
    def _key(team_slug: str, user_id: int) -> str:
        return f"{team_slug}:{user_id}"

    def get(self, team_slug: str, user_id: int) -> Optional[str]:
        return self._load().get(self._key(team_slug, user_id))

    def set_many(self, pins: Dict[Tuple[str, int], str]) -> None:
        """Record several pins with one atomic write."""
        if not pins:
            return
        data = self._load()
        data.update({self._key(team, uid): fp for (team, uid), fp in pins.items()})
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=".pins-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, sort_keys=True)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._path)
        except OSError:
            Path(tmp).unlink(missing_ok=True)
            raise


def pinned_fingerprint(store: WrapPinStore, team_slug: str, user_id: int) -> Optional[str]:
    """The fingerprint last sealed for *user_id* in *team_slug*, or None if new."""
    return store.get(team_slug, user_id)


def pin_fingerprint(store: WrapPinStore, team_slug: str, user_id: int, fp: str) -> None:
    """Remember that data keys were sealed for *user_id*'s key *fp*."""
    store.set_many({(team_slug, user_id): fp})


def differs_from_pin(store: WrapPinStore, entry: MissingTeamWrap) -> Tuple[Tuple[Recipient, ...], int]:
    """Split *entry*'s recipients into those matching their pin (or new) and a count of the rest."""
    kept: List[Recipient] = []
    for recipient in entry.recipients:
        pinned = pinned_fingerprint(store, entry.team_slug, recipient.user_id)
        if pinned is None or pinned == recipient.fingerprint:
            kept.append(recipient)
    return tuple(kept), len(entry.recipients) - len(kept)
