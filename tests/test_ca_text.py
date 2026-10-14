"""The SSH Certificates screen shows CA results in words, never as raw records."""
from __future__ import annotations

from servonaut.screens._ca_text import audit_text, enroll_text, report_text, status_text

SERVER_ID = "c2a4e6f8-1b3d-4f5a-9c7e-0a2b4c6d8e1f"
LABELS = {SERVER_ID: "server-1 (192.0.2.10)"}

STATUS = {
    "enabled": True,
    "user_ca_fingerprint": "SHA256:userca",
    "host_ca_fingerprint": "SHA256:hostca",
    "policy": {
        "interactive_ttl_seconds": 28800, "automation_ttl_seconds": 600,
        "max_ttl_seconds": 57600, "require_member_mfa": False,
    },
    "logins_by_server": {SERVER_ID: ["deploy"]},
    "krl_version": 1,
}

# The shape ``ca_enroll`` returns: the enrollment request (with key material)
# plus the executed result.
ENROLLED = {
    "enrollment": {
        "enrollment_id": "71376930-7935-40b2-b4e7-5762e39b3dd2",
        "user_ca_public_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample team-gen1"],
        "krl": "U1NIS1JMAAAA",
        "server": {"id": SERVER_ID, "name": "server-1", "hostname": "192.0.2.10", "port": 22},
    },
    "result": {
        "status": "succeeded",
        "steps": [
            {"name": "precheck", "status": "ok", "detail": ""},
            {"name": "managed_files", "status": "ok", "detail": ""},
            {"name": "host_certificate", "status": "ok", "detail": ""},
            {"name": "sshd_config_test", "status": "ok", "detail": ""},
            {"name": "reload", "status": "ok", "detail": ""},
            {"name": "certificate_login_proof", "status": "ok", "detail": ""},
        ],
        "error_code": None,
    },
    "reported": {"status": "succeeded"},
    "resumed": False,
}


def test_switched_off_certificates_say_how_to_switch_them_on():
    text = status_text({"enabled": False, "user_ca_fingerprint": None}, team="example-team", server_labels={})

    assert text.startswith("SSH certificates are not switched on for this team.")
    assert "servonaut ca enable --team example-team" in text
    assert "None" not in text


def test_switched_on_certificates_are_described():
    text = status_text(STATUS, team="example-team", server_labels=LABELS)

    assert text.splitlines() == [
        "SSH certificates are on for this team.",
        "User CA: SHA256:userca",
        "Host CA: SHA256:hostca",
        "Certificates last 8 h for people, 10 min for automation (at most 16 h).",
        "Logins on server-1 (192.0.2.10): deploy",
        "Revocation list: version 1",
    ]


def test_a_server_whose_name_is_not_known_yet_is_shown_by_a_short_id():
    text = status_text(STATUS, team="example-team", server_labels={})

    assert "Logins on server c2a4e6f8: deploy" in text


def test_a_successful_enrollment_lists_its_checks_and_hides_the_raw_record():
    text = enroll_text(ENROLLED, server="server-1 (192.0.2.10)")

    assert text.splitlines() == [
        "server-1 (192.0.2.10) is enrolled: it accepts this team's SSH certificates.",
        "Checks: pre-check ok · managed files ok · host certificate ok · sshd config test ok · "
        "sshd reload ok · certificate login ok",
    ]
    for raw in ("enrollment_id", "AAAAC3", "U1NIS1JM", "71376930", "{"):
        assert raw not in text


def test_a_failed_enrollment_says_what_failed():
    failed = {"result": {"status": "rolled_back", "error_code": "sshd_config_invalid", "steps": [
        {"name": "precheck", "status": "ok", "detail": ""},
        {"name": "sshd_config_test", "status": "failed", "detail": "line 3: bad option"},
    ]}, "resumed": True}

    text = enroll_text(failed, server="server-1")

    assert text.splitlines() == [
        "Enrolling server-1 did not complete: rolled_back (sshd_config_invalid).",
        "sshd config test: line 3: bad option",
        "Checks: pre-check ok · sshd config test failed",
        "This continued an enrollment that was already under way.",
    ]


def test_the_audit_is_summarised():
    text = audit_text({"entries_checked": 12, "head_hash": "abc123", "gaps": [], "break_glass_events": []})

    assert text.splitlines() == [
        "Issuance chain audit: 12 entries checked, no gaps.",
        "Chain head: abc123",
    ]


def test_other_reports_use_the_cli_rows():
    text = report_text("Revocation list delivery", {"results": [{"server": "server-1", "status": "ok"}]})

    assert text.splitlines() == [
        "Revocation list delivery",
        "results.1.server: server-1",
        "results.1.status: ok",
    ]
