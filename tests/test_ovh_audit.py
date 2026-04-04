"""Tests for OVHAuditLogger."""

from __future__ import annotations

import json
import stat
from datetime import datetime
from pathlib import Path

import pytest

from servonaut.services.ovh_audit import OVHAuditLogger


@pytest.fixture
def audit_path(tmp_path) -> str:
    return str(tmp_path / "ovh_audit.json")


@pytest.fixture
def logger(audit_path) -> OVHAuditLogger:
    return OVHAuditLogger(audit_path)


class TestLogAction:
    def test_creates_file_on_first_log(self, logger, audit_path):
        logger.log_action("vps_reinstall", "vps-abc.ovh.net", {"image_id": "ubuntu-22"}, True)
        assert Path(audit_path).exists()

    def test_appends_valid_json_line(self, logger, audit_path):
        logger.log_action("vps_reinstall", "vps-abc.ovh.net", {"image_id": "ubuntu-22"}, True)
        lines = Path(audit_path).read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["action"] == "vps_reinstall"
        assert entry["target"] == "vps-abc.ovh.net"
        assert entry["details"] == {"image_id": "ubuntu-22"}
        assert entry["confirmed"] is True

    def test_multiple_entries_appended(self, logger, audit_path):
        logger.log_action("vps_reinstall", "vps-1.ovh.net", {}, True)
        logger.log_action("cloud_delete", "instance-2", {"region": "EU"}, False)
        logger.log_action("vps_upgrade", "vps-3.ovh.net", {"model": "vps2020-starter-1-2-20"}, True)
        lines = Path(audit_path).read_text().strip().splitlines()
        assert len(lines) == 3

    def test_entries_contain_required_fields(self, logger, audit_path):
        logger.log_action("cloud_delete", "i-abc123", {"region": "EU"}, False)
        entry = json.loads(Path(audit_path).read_text().strip())
        assert "ts" in entry
        assert "action" in entry
        assert "target" in entry
        assert "details" in entry
        assert "confirmed" in entry

    def test_confirmed_false_stored_correctly(self, logger, audit_path):
        logger.log_action("vps_reinstall", "vps-x.ovh.net", {}, False)
        entry = json.loads(Path(audit_path).read_text().strip())
        assert entry["confirmed"] is False

    def test_timestamp_is_iso_format(self, logger, audit_path):
        logger.log_action("vps_reinstall", "vps-x.ovh.net", {}, True)
        entry = json.loads(Path(audit_path).read_text().strip())
        parsed = datetime.fromisoformat(entry["ts"])
        assert parsed is not None

    def test_file_permissions_are_600(self, logger, audit_path):
        logger.log_action("vps_reinstall", "vps-x.ovh.net", {}, True)
        mode = stat.S_IMODE(Path(audit_path).stat().st_mode)
        assert mode == 0o600

    def test_creates_parent_directories(self, tmp_path):
        deep_path = str(tmp_path / "a" / "b" / "c" / "ovh_audit.json")
        audit = OVHAuditLogger(deep_path)
        audit.log_action("vps_reinstall", "vps-x.ovh.net", {}, True)
        assert Path(deep_path).exists()

    def test_details_dict_preserved(self, logger, audit_path):
        details = {"image_id": "debian-12", "hostname": "my-vps", "sshKeys": ["key1", "key2"]}
        logger.log_action("vps_reinstall", "vps-x.ovh.net", details, True)
        entry = json.loads(Path(audit_path).read_text().strip())
        assert entry["details"] == details

    def test_empty_details_stored(self, logger, audit_path):
        logger.log_action("vps_reboot", "vps-x.ovh.net", {}, True)
        entry = json.loads(Path(audit_path).read_text().strip())
        assert entry["details"] == {}

    def test_multiple_entries_order_preserved(self, logger, audit_path):
        for i in range(5):
            logger.log_action(f"action_{i}", f"target_{i}", {"idx": i}, True)
        lines = Path(audit_path).read_text().strip().splitlines()
        entries = [json.loads(line) for line in lines]
        for i, entry in enumerate(entries):
            assert entry["action"] == f"action_{i}"
            assert entry["target"] == f"target_{i}"
            assert entry["details"]["idx"] == i
