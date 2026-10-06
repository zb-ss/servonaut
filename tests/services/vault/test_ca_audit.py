"""The CA issuance audit detects altered chains and serial gaps."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import pytest

from servonaut.services.vault.ca_audit import (
    CaIssuanceAuditor,
    IssuanceAuditError,
    detect_break_glass_usage,
)
from servonaut.services.vault.crypto import issuance_entry_hash_from_certificate_hash


class _Api:
    def __init__(self, page: dict[str, Any]) -> None:
        self.page = page

    async def get(self, path: str) -> dict[str, Any]:
        assert path.endswith("?limit=500")
        return self.page


def _hash(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _page(
    *, serial: int = 1, cert_hash: bytes = b"c" * 32, team_id: str = "team", user_id: int | None = 42,
) -> dict[str, Any]:
    previous = b"\0" * 32
    entry = issuance_entry_hash_from_certificate_hash(
        previous, team_id, serial, "key", user_id or 0, "device", ["svn:server:deploy"],
        100, 200, cert_hash, 100,
    )
    row = {
        "serial": serial, "key_id": "key", "user_id": user_id, "device_id": "device",
        "principals": ["svn:server:deploy"],
        "valid_after": "1970-01-01T00:01:40Z", "valid_before": "1970-01-01T00:03:20Z",
        "issued_at": "1970-01-01T00:01:40Z", "certificate_sha256": _hash(cert_hash),
        "prev_hash": _hash(previous), "entry_hash": _hash(entry),
    }
    return {"data": [row], "meta": {"head_hash": _hash(entry)}}


@pytest.mark.asyncio
async def test_audit_recomputes_valid_chain():
    report = await CaIssuanceAuditor(_Api(_page()), "team").audit()
    assert report.entries_checked == 1
    assert report.valid


@pytest.mark.asyncio
async def test_audit_rejects_tampered_entry_hash():
    page = _page()
    page["data"][0]["entry_hash"] = _hash(b"x" * 32)
    with pytest.raises(IssuanceAuditError, match="entry hash"):
        await CaIssuanceAuditor(_Api(page), "team").audit()


def _wire_line(blob: bytes) -> bytes:
    return b"ssh-ed25519-cert-v01@openssh.com " + base64.b64encode(blob) + b" device-1\n"


@pytest.mark.asyncio
async def test_audit_accepts_a_held_certificate_whose_blob_matches_the_log(tmp_path):
    # The log hashes the decoded certificate blob, not the text line on disk.
    held = tmp_path / "device-1-1-aaaaaaaaaaaaaaaaaaaaaaaa.cert.pub"
    held.write_bytes(_wire_line(b"issued certificate blob"))
    page = _page(cert_hash=hashlib.sha256(b"issued certificate blob").digest())

    report = await CaIssuanceAuditor(_Api(page), "team", local_certificates={1: held}).audit()

    assert report.entries_checked == 1


@pytest.mark.asyncio
async def test_audit_rejects_local_certificate_not_matching_its_issued_hash(tmp_path):
    held = tmp_path / "device-1-1-aaaaaaaaaaaaaaaaaaaaaaaa.cert.pub"
    page = _page(cert_hash=hashlib.sha256(b"issued certificate blob").digest())
    held.write_bytes(_wire_line(b"substituted certificate blob"))

    with pytest.raises(IssuanceAuditError, match="Locally held certificate hash"):
        await CaIssuanceAuditor(_Api(page), "team", local_certificates={1: held}).audit()


@pytest.mark.asyncio
async def test_audit_rejects_a_held_file_that_is_not_an_openssh_certificate(tmp_path):
    held = tmp_path / "device-1-1-aaaaaaaaaaaaaaaaaaaaaaaa.cert.pub"
    held.write_bytes(b"not a certificate\n")

    with pytest.raises(IssuanceAuditError, match="not an OpenSSH certificate"):
        await CaIssuanceAuditor(_Api(_page()), "team", local_certificates={1: held}).audit()


@pytest.mark.asyncio
async def test_audit_hashes_the_team_id_not_the_slug():
    page = _page(team_id="0f9b6c1e-team-id")

    assert (await CaIssuanceAuditor(_Api(page), "team", team_id="0f9b6c1e-team-id").audit()).valid
    with pytest.raises(IssuanceAuditError, match="entry hash"):
        await CaIssuanceAuditor(_Api(page), "team").audit()


@pytest.mark.asyncio
async def test_audit_reads_host_certificate_rows_without_a_user():
    report = await CaIssuanceAuditor(_Api(_page(user_id=None)), "team").audit()

    assert report.entries_checked == 1


def test_break_glass_parser_keeps_only_confirmed_key_logins():
    from datetime import datetime, timezone

    events = detect_break_glass_usage(
        "server", "Oct  2 12:00:00 host sshd[1]: Accepted publickey SHA256:abc from 192.0.2.10\nignored SHA256:abc",
        "SHA256:abc", now=datetime(2026, 10, 6, tzinfo=timezone.utc),
    )
    assert events == ({"server_id": "server", "observed_at": "2026-10-02T12:00:00+00:00", "source_ip": "192.0.2.10"},)


def test_break_glass_parser_reads_journald_iso_times_and_skips_undated_lines():
    from datetime import datetime, timezone

    log = (
        "2026-10-06T01:10:05+0200 web-1 sshd[42]: Accepted publickey for root from 10.0.0.5 port 50000 ssh2: ED25519 SHA256:abc\n"
        "Accepted publickey for root from 10.0.0.6 port 1 ssh2: ED25519 SHA256:abc\n"
        "2026-10-06T00:11:00+00:00 web-1 sshd[43]: Accepted publickey for root from 10.0.0.7 port 2 ssh2: ED25519 SHA256:other\n"
    )

    events = detect_break_glass_usage("server", log, "SHA256:abc", now=datetime(2026, 10, 6, 1, tzinfo=timezone.utc))

    assert events == ({"server_id": "server", "observed_at": "2026-10-05T23:10:05+00:00", "source_ip": "10.0.0.5"},)


def test_syslog_time_from_late_december_is_read_as_last_year_in_january():
    from datetime import datetime, timezone

    events = detect_break_glass_usage(
        "server", "Dec 31 23:59:00 h sshd[1]: Accepted publickey for root from 10.0.0.1 port 1 ssh2: ED25519 SHA256:abc",
        "SHA256:abc", now=datetime(2027, 1, 1, 0, 5, tzinfo=timezone.utc),
    )

    assert events[0]["observed_at"] == "2026-12-31T23:59:00+00:00"
