"""Independent verification of the SSH CA issuance log."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Protocol
from urllib.parse import urlencode

from .crypto import issuance_entry_hash_from_certificate_hash


class IssuanceAuditError(RuntimeError):
    """The server's issuance log is incomplete or cryptographically invalid."""


class PageClient(Protocol):
    async def get(self, path: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class IssuanceAuditReport:
    entries_checked: int
    head_hash: str
    gaps: tuple[int, ...]
    break_glass_events: tuple[dict[str, str], ...] = ()

    @property
    def valid(self) -> bool:
        return not self.gaps

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries_checked": self.entries_checked,
            "head_hash": self.head_hash,
            "gaps": list(self.gaps),
            "break_glass_events": list(self.break_glass_events),
        }


class CaIssuanceAuditor:
    """Page the append-only log and recompute every entry hash locally."""

    def __init__(
        self,
        api_client: PageClient,
        team_slug: str,
        *,
        team_id: str | None = None,
        local_certificates: Mapping[int, bytes | Path] | None = None,
    ) -> None:
        self.api_client = api_client
        self.team_slug = team_slug
        # The chain hashes the team's id (§3.13); the slug only addresses the API.
        self.team_id = team_id or team_slug
        self.local_certificates = dict(local_certificates or {})

    async def audit(self, *, expected_head: str | None = None) -> IssuanceAuditReport:
        cursor: str | None = None
        previous = b"\0" * 32
        expected_serial = 1
        gaps: list[int] = []
        checked = 0
        declared_head: str | None = None
        observed_hashes: set[bytes] = {previous}
        while True:
            query = {"limit": "500"}
            if cursor:
                query["cursor"] = cursor
            page = await self.api_client.get(
                f"/api/v1/teams/{self.team_slug}/ssh-ca/issued?{urlencode(query)}"
            )
            rows = page.get("data")
            meta = page.get("meta") or {}
            if not isinstance(rows, list):
                raise IssuanceAuditError("Issuance log page has an invalid shape")
            for row in rows:
                if not isinstance(row, Mapping):
                    raise IssuanceAuditError("Issuance log entry has an invalid shape")
                serial = int(row["serial"])
                if serial != expected_serial:
                    gaps.extend(range(expected_serial, serial))
                expected_serial = serial + 1
                claimed_previous = _decode_hash(row["prev_hash"])
                if claimed_previous != previous:
                    raise IssuanceAuditError("Issuance log previous hash does not form a chain")
                certificate_hash = _decode_hash(row["certificate_sha256"])
                self._verify_local_certificate(serial, certificate_hash)
                actual = issuance_entry_hash_from_certificate_hash(
                    previous,
                    self.team_id,
                    serial,
                    str(row["key_id"]),
                    int(row.get("user_id") or 0),  # host certificates have no user
                    str(row["device_id"]) if row.get("device_id") is not None else None,
                    tuple(map(str, row["principals"])),
                    _epoch(row["valid_after"]),
                    _epoch(row["valid_before"]),
                    certificate_hash,
                    _epoch(row["issued_at"]),
                )
                if actual != _decode_hash(row["entry_hash"]):
                    raise IssuanceAuditError("Issuance log entry hash is invalid")
                previous = actual
                observed_hashes.add(actual)
                checked += 1
            head = meta.get("head_hash")
            if head is not None:
                declared_head = str(head)
            cursor_value = meta.get("next_cursor")
            if not cursor_value:
                break
            cursor = str(cursor_value)
        if declared_head is None or previous != _decode_hash(declared_head):
            raise IssuanceAuditError("Issuance log head hash does not match the downloaded chain")
        if expected_head is not None and _decode_hash(expected_head) not in observed_hashes:
            raise IssuanceAuditError("Issuance log does not extend the locally anchored head")
        return IssuanceAuditReport(checked, declared_head, tuple(gaps))

    def _verify_local_certificate(self, serial: int, expected_hash: bytes) -> None:
        certificate = self.local_certificates.get(serial)
        if certificate is None:
            return
        try:
            raw = certificate.read_bytes() if isinstance(certificate, Path) else bytes(certificate)
        except OSError as exc:
            raise IssuanceAuditError("Locally held certificate could not be read") from exc
        if _certificate_blob_sha256(raw) != expected_hash:
            raise IssuanceAuditError("Locally held certificate hash differs from issuance log")


def _certificate_blob_sha256(raw: bytes) -> bytes:
    """Hash the binary certificate blob, as the issuance log does.

    A held certificate is the OpenSSH wire line ``<type> <base64 blob> [comment]``;
    the log records the SHA-256 of the decoded blob, not of the text.
    """
    fields = raw.split()
    if len(fields) < 2:
        raise IssuanceAuditError("Locally held certificate is not an OpenSSH certificate")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (ValueError, UnicodeError) as exc:
        raise IssuanceAuditError("Locally held certificate is not an OpenSSH certificate") from exc
    return hashlib.sha256(blob).digest()


def _decode_hash(value: object) -> bytes:
    if not isinstance(value, str):
        raise IssuanceAuditError("Issuance hash is missing")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise IssuanceAuditError("Issuance hash is invalid") from exc
    if len(decoded) != 32:
        raise IssuanceAuditError("Issuance hash has an invalid length")
    return decoded


def _epoch(value: object) -> int:
    if not isinstance(value, str):
        raise IssuanceAuditError("Issuance timestamp is missing")
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp())
    except ValueError as exc:
        raise IssuanceAuditError("Issuance timestamp is invalid") from exc


_ISO_TIME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?([+-]\d{2}:?\d{2}|Z)?")
_SYSLOG_TIME_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
_MONTHS = {name: index for index, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}


def _log_time(line: str, now: datetime) -> str | None:
    """RFC 3339 time of an auth-log line, or ``None`` when it carries none.

    journald ``short-iso`` and rsyslog high-precision lines carry a zone.
    Classic syslog lines carry neither year nor zone: they are read as UTC in
    the most recent year that does not put them in the future.
    """
    iso = _ISO_TIME_RE.match(line)
    if iso is not None:
        zone = iso.group(2) or "+00:00"
        zone = "+00:00" if zone == "Z" else (zone if ":" in zone else f"{zone[:3]}:{zone[3:]}")
        try:
            return datetime.fromisoformat(iso.group(1) + zone).astimezone(timezone.utc).isoformat()
        except ValueError:
            return None
    syslog = _SYSLOG_TIME_RE.match(line)
    if syslog is None or syslog.group(1) not in _MONTHS:
        return None
    month, day = _MONTHS[syslog.group(1)], int(syslog.group(2))
    hour, minute, second = (int(syslog.group(index)) for index in (3, 4, 5))
    for year in (now.year, now.year - 1):
        try:
            when = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
        except ValueError:
            continue
        if when <= now + timedelta(days=1):
            return when.isoformat()
    return None


def detect_break_glass_usage(
    server_id: str, auth_log: str, key_fingerprint: str, *, now: datetime | None = None,
) -> tuple[dict[str, str], ...]:
    """Extract locally observed break-glass logins for a caller to report.

    Only ``Accepted publickey`` lines naming the key's fingerprint count.
    ``observed_at`` is RFC 3339; a line without a timestamp is skipped rather
    than reported with a guessed time. The caller obtains the log through its
    existing authenticated host transport; this parser never sends it anywhere.
    """
    if not key_fingerprint.startswith("SHA256:"):
        raise ValueError("break-glass key fingerprint must be an OpenSSH SHA256 fingerprint")
    now = now or datetime.now(timezone.utc)
    events: list[dict[str, str]] = []
    source_re = re.compile(r"(?:from|rhost=)\s*([0-9a-fA-F:.]+)")
    for line in auth_log.splitlines():
        if key_fingerprint not in line or "Accepted publickey" not in line:
            continue
        observed_at = _log_time(line, now)
        if observed_at is None:
            continue
        event = {"server_id": server_id, "observed_at": observed_at}
        source = source_re.search(line)
        if source is not None:
            event["source_ip"] = source.group(1)
        events.append(event)
    return tuple(events)
