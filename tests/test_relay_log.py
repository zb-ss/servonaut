"""Tests for the relay structured log writer."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from servonaut.utils import relay_log


@pytest.fixture
def log_path(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "relay.log"
    monkeypatch.setattr(relay_log, "_DEFAULT_LOG_PATH", path)
    return path


class TestLogRelayEvent:
    def test_writes_one_json_line_per_event(self, log_path):
        relay_log.log_relay_event("connected", mode="tui", pid=123)
        relay_log.log_relay_event("stopped", mode="tui")
        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["event"] == "connected"
        assert first["mode"] == "tui"
        assert first["pid"] == 123
        assert "ts" in first

    def test_sensitive_keys_dropped_entirely(self, log_path):
        relay_log.log_relay_event(
            "connected",
            mode="tui",
            token="secret-value",
            authorization="Bearer abc",
            api_key="xxx",
        )
        payload = json.loads(log_path.read_text().strip())
        assert "token" not in payload
        assert "authorization" not in payload
        assert "api_key" not in payload
        assert "secret-value" not in log_path.read_text()

    def test_bearer_value_in_unrecognised_key_scrubbed(self, log_path):
        relay_log.log_relay_event(
            "connected",
            mode="tui",
            upstream_header="Bearer leak-me",
        )
        payload = json.loads(log_path.read_text().strip())
        assert payload["upstream_header"] == "***"

    def test_nested_dict_sensitive_keys_redacted(self, log_path):
        relay_log.log_relay_event(
            "connected",
            mode="tui",
            metadata={"token": "leak", "ok": "yes"},
        )
        payload = json.loads(log_path.read_text().strip())
        assert payload["metadata"]["token"] == "***"
        assert payload["metadata"]["ok"] == "yes"

    def test_silent_on_io_error(self, monkeypatch, tmp_path):
        """Logging must never raise even if the log path is unwritable."""
        unwritable = tmp_path / "nonexistent" / "relay.log"
        monkeypatch.setattr(relay_log, "_DEFAULT_LOG_PATH", unwritable)
        def boom(*a, **kw):
            raise OSError("disk full")
        monkeypatch.setattr(relay_log.Path, "mkdir", lambda *a, **kw: boom())
        # Must not raise.
        relay_log.log_relay_event("connected", mode="tui")
