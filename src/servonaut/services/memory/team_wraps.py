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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import nacl.public

from servonaut.services.memory.path_segments import check_segment
from servonaut.utils.file_lock import FileLock
from servonaut.services.memory.crypto import (
    X25519_KEY_LEN,
    fingerprint,
    reseal_dek,
)

logger = logging.getLogger(__name__)

_FINGERPRINT_HEX = re.compile(r"[0-9a-f]{64}")



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
    if len(key) != X25519_KEY_LEN or not any(key) or not _can_seal_to(key):
        return None
    return fingerprint(key)


def _can_seal_to(key: bytes) -> bool:
    """Whether a sealed box can be made to *key*.

    libsodium refuses the small-order points; a member holding one could not
    read anything sealed for it, and Share again would revoke the live share
    before finding that out. A fixed dummy message is sealed, never a data key.
    """
    try:
        nacl.public.SealedBox(nacl.public.PublicKey(key)).encrypt(b"\x00")
    except (RuntimeError, ValueError, TypeError):
        return False
    return True


def optional_fingerprint(value: Any) -> Optional[str]:
    """*value* when it is a 64-char lowercase hex fingerprint, else None."""
    if isinstance(value, str) and _FINGERPRINT_HEX.fullmatch(value):
        return value
    return None


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


def is_user_id(value: Any) -> bool:
    """Whether *value* is a service user id: a positive 64-bit integer."""
    return (
        isinstance(value, int) and not isinstance(value, bool)
        and 0 < value < 2**63
    )


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
    if not is_user_id(user_id):
        return None
    flagged = raw.get("key_changed")
    if not isinstance(flagged, bool):
        return None
    claimed, key_b64 = raw.get("fingerprint"), raw.get("public_key_b64")
    # The fingerprint we send back is what lets the service skip a member whose
    # key changed since; one that does not belong to this key is not trusted.
    derived = derive_fingerprint(key_b64)
    if derived is None or derived != claimed:
        return None
    return Recipient(
        user_id=user_id,
        fingerprint=derived,
        public_key=base64.b64decode(key_b64, validate=True),
        name=raw["name"] if isinstance(raw.get("name"), str) else "",
        flagged=flagged,
        previous_fingerprint=optional_fingerprint(raw.get("previous_fingerprint")),
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


# What ``WrapPinStore.get`` answers when the file exists but cannot be read.
# It is never a fingerprint, so every member classifies as changed and the
# user is asked, instead of the store silently starting over (trust on first use).
UNREADABLE_PIN = "unreadable"

_MAX_USER_ID_DIGITS = 19  # a signed 64-bit integer

PinKey = Tuple[str, int]
# A trust decision: the member and the key it was about.
SeenKey = Tuple[str, int, str]


def _valid_pin_entry(key: Any, value: Any) -> bool:
    team_slug, _, user_id = key.rpartition(":") if isinstance(key, str) else ("", "", "")
    try:
        check_segment(team_slug, "team")
    except ValueError:
        return False
    # Checked on the text: a huge digit string must not reach int(). Ids the
    # service issues fit a signed 64-bit integer (at most 19 digits).
    return (
        user_id.isascii() and user_id.isdigit() and user_id[0] != "0"
        and len(user_id) <= _MAX_USER_ID_DIGITS
        and optional_fingerprint(value) is not None
    )


def merge_seen(into: Dict[SeenKey, Optional[str]], new: Dict[SeenKey, Optional[str]]) -> None:
    """Add *new* decisions to *into*; the first decision about a key stays.

    A later envelope may be judged against a pin the user changed meanwhile,
    and that must not become the expectation of a seal made before.
    """
    for key, pinned in new.items():
        into.setdefault(key, pinned)


def pins_of(team_slug: str, wraps: List[Dict[str, Any]]) -> Dict[PinKey, str]:
    """The fingerprint each wrap's recipient was sealed for, one per member.

    A member sealed for two different keys in one batch is left out: which one
    to remember is not known.
    """
    found: Dict[PinKey, Set[str]] = {}
    for wrap in wraps:
        found.setdefault((team_slug, wrap["recipient_user_id"]), set()).add(
            wrap["recipient_fingerprint"]
        )
    return {key: next(iter(fps)) for key, fps in found.items() if len(fps) == 1}


class WrapPinStore:
    """The key fingerprint last sealed for each team member (trust on first use).

    A small JSON file, mode 0600, written atomically. It holds fingerprints
    only (public values), never a key. A missing file is an empty store (first
    use). An unreadable or corrupt one is not: members then read as changed,
    automatic writes leave the file alone, and an explicit confirmation moves
    it aside before starting a new file.

    Every read-modify-write runs under a cross-process lock on a sibling
    ``.lock`` file; a write that cannot get it within the wait raises
    ``OSError`` and counts as not saved.
    """

    def __init__(
        self, path: Path, lock_wait: Optional[Callable[[], Tuple[float, float]]] = None
    ) -> None:
        self._path = path
        self._lock_wait = lock_wait
        self._warned = False

    def _read(self) -> Optional[Dict[str, str]]:
        """The stored pins; ``{}`` when there is no file, None when it is unreadable.

        The whole file is checked: one entry that is not ``<team>:<user id>`` ->
        fingerprint makes the store unreadable, because dropping it would turn
        a member whose key was confirmed into a first sighting.
        """
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            data = None
        if not isinstance(data, dict) or not all(
            _valid_pin_entry(k, v) for k, v in data.items()
        ):
            if not self._warned:
                self._warned = True
                logger.warning("team wrap pins unreadable; every member needs confirming")
            return None
        return dict(data)

    @staticmethod
    def _key(team_slug: str, user_id: int) -> str:
        return f"{team_slug}:{user_id}"

    def get(self, team_slug: str, user_id: int) -> Optional[str]:
        """The pin, None when there is none, :data:`UNREADABLE_PIN` when the file is unreadable."""
        data = self._read()
        if data is None:
            return UNREADABLE_PIN
        return data.get(self._key(team_slug, user_id))

    def _wait(self) -> Tuple[float, float]:
        if self._lock_wait is not None:
            return self._lock_wait()
        from servonaut.config.schema import MemoryConfig  # noqa: PLC0415

        return MemoryConfig().record_lock_wait()

    def _locked(self) -> Any:
        timeout, poll = self._wait()
        return FileLock(self._path.with_name(self._path.name + ".lock")).hold(timeout, poll)

    def set_many(self, pins: Dict[PinKey, str]) -> None:
        """Record several pins with one atomic write: the user's explicit choice.

        Raises:
            OSError: the lock stayed busy or the file could not be written.
        """
        pins = {key: fp for key, fp in pins.items() if is_user_id(key[1])}
        if not pins:
            return
        with self._locked():
            data = self._read()
            if data is None:
                self._move_aside()
                data = {}
            self._write({**data, **{self._key(*key): fp for key, fp in pins.items()}})

    def set_if_seen(
        self, pins: Dict[PinKey, str], seen: Dict[SeenKey, Optional[str]]
    ) -> Set[PinKey]:
        """Record pins an automatic seal produced, unless the pin changed since it was seen.

        *seen* is the pin each trust decision looked at (None for no pin), per
        member and key. A
        pin that is different now, say because the user confirmed another key
        meanwhile, is left as it is. An unreadable file is never written.

        Returns:
            The keys written.

        Raises:
            OSError: the lock stayed busy or the file could not be written.
        """
        pins = {key: fp for key, fp in pins.items() if is_user_id(key[1])}
        if not pins:
            return set()
        with self._locked():
            data = self._read()
            if data is None:
                return set()
            written = {
                key for key, fp in pins.items()
                if (*key, fp) in seen and data.get(self._key(*key)) == seen[(*key, fp)]
            }
            if written:
                self._write({**data, **{self._key(*key): pins[key] for key in written}})
            return written

    def _move_aside(self) -> None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        aside = self._path.with_name(f"{self._path.name}.unreadable-{stamp}")
        os.replace(self._path, aside)
        os.chmod(aside, 0o600)

    def _write(self, data: Dict[str, str]) -> None:
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


def default_pin_store(
    lock_wait: Optional[Callable[[], Tuple[float, float]]] = None,
) -> WrapPinStore:
    """The pin store beside the memory sync queue."""
    return WrapPinStore(
        Path.home() / ".servonaut" / "memory" / "team_wrap_pins.json", lock_wait=lock_wait
    )


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
    # Whom the service says this report is about; checked against the request.
    grant_id: Optional[str] = None
    instance_id: Optional[str] = None


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
        grant_id=_optional_text(payload.get("grant_id")),
        instance_id=_optional_text(payload.get("instance_id")),
        pending=tuple(dict(p) for p in pending if isinstance(p, dict)) if isinstance(pending, list) else (),
    )


SKIP_REASONS = ("key_changed", "no_memory_key", "not_eligible")
UNCONFIRMED = "unconfirmed"  # the service did not say, or what it said did not add up


@dataclass(frozen=True)
class WrapAck:
    """What the service confirmed of a batch of posted wraps.

    ``skipped`` maps each posted recipient that was not stored to the reason:
    one of :data:`SKIP_REASONS`, or :data:`UNCONFIRMED`.
    """

    stored: Tuple[Dict[str, Any], ...]
    skipped: Dict[int, str]


def read_skips(skipped: Any) -> Optional[Dict[int, str]]:
    """``{user_id: reason}`` from a ``skipped_recipients`` list, None if it is malformed.

    Every entry needs an integer ``user_id`` and a non-empty text ``reason``;
    a reason this client does not know is kept as :data:`UNCONFIRMED`.
    """
    if not isinstance(skipped, list):
        return None
    reasons: Dict[int, str] = {}
    for item in skipped:
        user_id = item.get("user_id") if isinstance(item, dict) else None
        reason = item.get("reason") if isinstance(item, dict) else None
        if not is_user_id(user_id) or not _text(reason):
            return None
        reasons[user_id] = reason if reason in SKIP_REASONS else UNCONFIRMED
    return reasons


def acknowledge_wraps(wraps: List[Dict[str, Any]], response: Any) -> WrapAck:
    """The posted *wraps* the service confirms it stored, and why the rest were not.

    Read strictly from ``wraps_stored``, ``wraps_unchanged`` and
    ``skipped_recipients`` (``[{user_id, reason}]``). The counts have to equal
    the number of distinct (recipient, envelope) pairs posted for recipients
    that were not skipped; a response that does not fit means nothing counts as
    stored and every recipient is :data:`UNCONFIRMED`.
    """
    unconfirmed = WrapAck((), {w["recipient_user_id"]: UNCONFIRMED for w in wraps})
    if not isinstance(response, dict):
        return unconfirmed
    stored, unchanged = response.get("wraps_stored"), response.get("wraps_unchanged")
    skips = read_skips(response.get("skipped_recipients"))
    if not all(_is_count(n) for n in (stored, unchanged)) or skips is None:
        logger.debug("wraps response ignored: unexpected shape")
        return unconfirmed
    kept = [
        w for w in wraps
        if w["recipient_user_id"] not in skips and is_user_id(w["recipient_user_id"])
    ]
    pairs = {(w["recipient_user_id"], w["envelope_id"]) for w in kept}
    if stored + unchanged != len(pairs):
        logger.debug("wraps response ignored: counts do not match the wraps posted")
        return unconfirmed
    posted = {w["recipient_user_id"] for w in wraps}
    return WrapAck(tuple(kept), {u: r for u, r in skips.items() if u in posted})


def stored_wraps(wraps: List[Dict[str, Any]], response: Any) -> List[Dict[str, Any]]:
    """The posted *wraps* the service says it stored (see :func:`acknowledge_wraps`)."""
    return list(acknowledge_wraps(wraps, response).stored)


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


@dataclass(frozen=True)
class TrustSplit:
    """An entry's recipients, divided by whether they may be sealed for now."""

    sealable: Tuple[Recipient, ...]
    changed: Tuple[KeyChange, ...]
    # The pin each recipient was judged against, for ``WrapPinStore.set_if_seen``.
    seen: Dict[SeenKey, Optional[str]] = field(default_factory=dict)


def previous_pin(pinned: Optional[str], current: str) -> Optional[str]:
    """The pin to show as the previous key: a real, different fingerprint only."""
    if pinned is None or pinned == UNREADABLE_PIN or pinned == current:
        return None
    return pinned


def key_change_for(
    team_slug: str, recipient: Recipient, pinned: Optional[str]
) -> KeyChange:
    """The :class:`KeyChange` describing *recipient*."""
    previous = previous_pin(pinned, recipient.fingerprint)
    return KeyChange(
        team_slug=team_slug,
        user_id=recipient.user_id,
        name=recipient.name,
        fingerprint=recipient.fingerprint,
        previous_fingerprint=previous or recipient.previous_fingerprint,
        rotated_at=recipient.rotated_at,
    )


def split_by_trust(store: Optional[WrapPinStore], entry: MissingTeamWrap) -> TrustSplit:
    """Divide *entry*'s recipients into those to seal for and those awaiting confirmation."""
    return split_recipients(store, entry.team_slug, entry.recipients)


def split_recipients(
    store: Optional[WrapPinStore], team_slug: str, recipients: Tuple[Recipient, ...]
) -> TrustSplit:
    """Like :func:`split_by_trust` for a bare list; no store means nothing is pinned."""
    sealable: List[Recipient] = []
    changed: List[KeyChange] = []
    seen: Dict[PinKey, Optional[str]] = {}
    for recipient in recipients:
        pinned = pinned_fingerprint(store, team_slug, recipient.user_id) if store else None
        seen[(team_slug, recipient.user_id, recipient.fingerprint)] = pinned
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
    return TrustSplit(sealable=tuple(sealable), changed=tuple(changed), seen=seen)
