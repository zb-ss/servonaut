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
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from servonaut.services.memory.path_segments import check_segment
from servonaut.services.memory.crypto import (
    X25519_KEY_LEN,
    fingerprint,
    reseal_dek,
)

logger = logging.getLogger(__name__)



class KeyTrust(Enum):
    """Whether a member's key may be sealed for."""

    UNUSABLE = "unusable"  # not a key, or not the key its fingerprint names
    TRUSTED = "trusted"  # sealed for, or confirmed, before
    CHANGED = "changed"  # needs the user's confirmation
    NEW = "new"  # first sight: sealed, then pinned


def derive_fingerprint(public_key_b64: Any) -> Optional[str]:
    """The fingerprint of the key held in *public_key_b64*, or None if it is no key."""
    if not _text(public_key_b64):
        return None
    try:
        key = base64.b64decode(public_key_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(key) != X25519_KEY_LEN or not any(key):
        return None
    return fingerprint(key)


def classify_key(
    public_key_b64: Any, claimed: Any, *, flagged: bool, pinned: Optional[str]
) -> KeyTrust:
    """The one rule behind Share, Share again, the catch-up and the top-up.

    The claimed fingerprint is only a claim: it is checked against the key
    actually held, and a pin is compared with the derived value, so the
    service's ``key_changed`` flag can neither hide a swapped key nor keep a
    confirmed one blocked.
    """
    derived = derive_fingerprint(public_key_b64)
    if derived is None or derived != claimed:
        return KeyTrust.UNUSABLE
    if pinned is not None:
        return KeyTrust.TRUSTED if pinned == derived else KeyTrust.CHANGED
    return KeyTrust.CHANGED if flagged else KeyTrust.NEW


@dataclass(frozen=True)
class KeyChange:
    """A member's key the user has to confirm before anything is sealed for it.

    ``previous_fingerprint`` is the key last sealed for when that differs from
    the current one, else what the service reports as the replaced key.
    """

    team_slug: str
    user_id: int
    name: str
    fingerprint: str
    previous_fingerprint: Optional[str] = None
    rotated_at: Optional[str] = None


@dataclass(frozen=True)
class PendingKeyChange:
    """A changed key a catch-up skipped, and the server it was needed for."""

    change: KeyChange
    instance_id: str


@dataclass(frozen=True)
class Recipient:
    """A member that still lacks a wrap, with the key the service holds."""

    user_id: int
    fingerprint: str
    public_key: bytes
    name: str = ""
    flagged: bool = False
    previous_fingerprint: Optional[str] = None
    rotated_at: Optional[str] = None


@dataclass(frozen=True)
class MissingTeamWrap:
    """One envelope of a live share and the members that miss a wrap for it."""

    envelope_id: str
    instance_id: str
    module: str
    team_slug: str
    grant_id: str
    recipients: Tuple[Recipient, ...]


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _optional_text(value: Any) -> Optional[str]:
    return value if _text(value) else None


def _parse_recipient(raw: Any) -> Optional[Recipient]:
    """The recipient described by *raw*, or None when it is malformed.

    A flagged recipient is validated like any other: the user may confirm its
    key, so the key has to be one we would be willing to seal for.
    """
    if not isinstance(raw, dict):
        return None
    user_id = raw.get("user_id")
    if not isinstance(user_id, int) or isinstance(user_id, bool):
        return None
    flagged = raw.get("key_changed")
    if not isinstance(flagged, bool):
        return None
    claimed, key_b64 = raw.get("fingerprint"), raw.get("public_key_b64")
    # The fingerprint we send back is what lets the service skip a member whose
    # key changed since; one that does not belong to this key is not trusted.
    if derive_fingerprint(key_b64) != claimed:
        return None
    return Recipient(
        user_id=user_id,
        fingerprint=claimed,
        public_key=base64.b64decode(key_b64),
        name=raw["name"] if isinstance(raw.get("name"), str) else "",
        flagged=flagged,
        previous_fingerprint=_optional_text(raw.get("previous_fingerprint")),
        rotated_at=_optional_text(raw.get("key_rotated_at")),
    )


def _parse_entry(raw: Any) -> Any:
    if not isinstance(raw, dict):
        return None
    for name in ("envelope_id", "instance_id", "module"):
        if not _text(raw.get(name)):
            return None
    for name in ("team_slug", "grant_id"):
        value = raw.get(name)
        try:
            check_segment(value, name)
        except ValueError:
            return None
    raw_recipients = raw.get("recipients")
    if not isinstance(raw_recipients, list):
        return None
    recipients = [r for r in map(_parse_recipient, raw_recipients) if r is not None]
    return MissingTeamWrap(
        envelope_id=raw["envelope_id"],
        instance_id=raw["instance_id"],
        module=raw["module"],
        team_slug=raw["team_slug"],
        grant_id=raw["grant_id"],
        recipients=tuple(recipients),
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


def default_pin_store() -> WrapPinStore:
    """The pin store beside the memory sync queue."""
    return WrapPinStore(Path.home() / ".servonaut" / "memory" / "team_wrap_pins.json")


def pinned_fingerprint(store: WrapPinStore, team_slug: str, user_id: int) -> Optional[str]:
    """The fingerprint last sealed for *user_id* in *team_slug*, or None if new."""
    return store.get(team_slug, user_id)


def pin_fingerprint(store: WrapPinStore, team_slug: str, user_id: int, fp: str) -> None:
    """Remember that data keys were sealed for *user_id*'s key *fp*."""
    store.set_many({(team_slug, user_id): fp})


@dataclass(frozen=True)
class CoverageEnvelope:
    """One snapshot of a live share and the members that cannot read it yet."""

    envelope_id: str
    module: str
    snapshot_version: Optional[int]
    wrapped_dek: Optional[str]  # the caller's own wrap; None when it holds none
    missing: Tuple[Recipient, ...]


@dataclass(frozen=True)
class GrantCoverage:
    """Who can read the newest snapshots of a live share."""

    envelopes: Tuple[CoverageEnvelope, ...]
    pending: Tuple[Dict[str, Any], ...]


def _parse_coverage_envelope(raw: Any) -> Optional[CoverageEnvelope]:
    if not isinstance(raw, dict):
        return None
    try:
        check_segment(raw.get("envelope_id"), "envelope")
    except ValueError:
        return None
    wrapped = raw.get("wrapped_dek")
    if wrapped is not None and not _text(wrapped):
        return None
    missing = raw.get("missing_recipients")
    if not _text(raw.get("module")) or not isinstance(missing, list):
        return None
    version = raw.get("snapshot_version")
    return CoverageEnvelope(
        envelope_id=raw["envelope_id"],
        module=raw["module"],
        snapshot_version=version if isinstance(version, int) and not isinstance(version, bool) else None,
        wrapped_dek=wrapped,
        missing=tuple(r for r in map(_parse_recipient, missing) if r is not None),
    )


def parse_grant_coverage(payload: Any) -> GrantCoverage:
    """The usable part of a share's coverage report.

    A malformed envelope is dropped whole and a malformed recipient on its own;
    only shapes and counts are logged, never an id or a key.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("envelopes"), list):
        logger.debug("grant coverage ignored: unexpected shape (%s)", type(payload).__name__)
        return GrantCoverage((), ())
    envelopes = []
    for raw in payload["envelopes"]:
        envelope = _parse_coverage_envelope(raw)
        if envelope is None:
            logger.debug("grant coverage envelope ignored: malformed (%s)", type(raw).__name__)
            continue
        envelopes.append(envelope)
    pending = payload.get("pending_recipients")
    return GrantCoverage(
        envelopes=tuple(envelopes),
        pending=tuple(dict(p) for p in pending if isinstance(p, dict)) if isinstance(pending, list) else (),
    )


@dataclass(frozen=True)
class TrustSplit:
    """An entry's recipients, divided by whether they may be sealed for now."""

    sealable: Tuple[Recipient, ...]
    changed: Tuple[KeyChange, ...]


def key_change_for(
    team_slug: str, recipient: Recipient, pinned: Optional[str]
) -> KeyChange:
    """The :class:`KeyChange` describing *recipient*."""
    previous = pinned if pinned is not None and pinned != recipient.fingerprint else None
    return KeyChange(
        team_slug=team_slug,
        user_id=recipient.user_id,
        name=recipient.name,
        fingerprint=recipient.fingerprint,
        previous_fingerprint=previous or recipient.previous_fingerprint,
        rotated_at=recipient.rotated_at,
    )


def split_by_trust(store: WrapPinStore, entry: MissingTeamWrap) -> TrustSplit:
    """Divide *entry*'s recipients into those to seal for and those awaiting confirmation."""
    return split_recipients(store, entry.team_slug, entry.recipients)


def split_recipients(
    store: WrapPinStore, team_slug: str, recipients: Tuple[Recipient, ...]
) -> TrustSplit:
    sealable: List[Recipient] = []
    changed: List[KeyChange] = []
    for recipient in recipients:
        pinned = pinned_fingerprint(store, team_slug, recipient.user_id)
        trust = classify_key(
            base64.b64encode(recipient.public_key).decode(),
            recipient.fingerprint,
            flagged=recipient.flagged,
            pinned=pinned,
        )
        if trust in (KeyTrust.TRUSTED, KeyTrust.NEW):
            sealable.append(recipient)
        elif trust is KeyTrust.CHANGED:
            changed.append(key_change_for(team_slug, recipient, pinned))
    return TrustSplit(sealable=tuple(sealable), changed=tuple(changed))
