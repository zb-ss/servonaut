"""Tests for RemoteAuditService."""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.services.remote_audit_service import RemoteAuditService, AUDIT_QUEUE_PATH


def run(coro):
    """Run a coroutine synchronously (no pytest-asyncio required)."""
    return asyncio.run(coro)


@pytest.fixture
def mock_api():
    api = MagicMock()
    api.post = AsyncMock(return_value={"success": True})
    return api


@pytest.fixture
def mock_auth():
    auth = MagicMock()
    auth.is_authenticated = True
    return auth


@pytest.fixture
def audit_service(tmp_path, monkeypatch, mock_api, mock_auth):
    queue_path = tmp_path / "audit_queue.json"
    monkeypatch.setattr(
        "servonaut.services.remote_audit_service.AUDIT_QUEUE_PATH", queue_path
    )
    return RemoteAuditService(mock_api, mock_auth)


class TestRemoteAuditService:
    def test_log_event_sends_to_api(self, audit_service, mock_api):
        run(audit_service.log_event("ssh_connection", {
            "team_slug": "my-team",
            "server": "web-1",
            "user": "admin@example.com",
        }))
        mock_api.post.assert_called_once()
        assert audit_service.get_queue_size() == 0

    def test_log_event_queues_on_failure(self, audit_service, mock_api):
        mock_api.post.side_effect = RuntimeError("offline")
        run(audit_service.log_event("ssh_connection", {
            "team_slug": "my-team",
            "server": "web-1",
        }))
        assert audit_service.get_queue_size() == 1

    def test_log_event_queues_when_unauthenticated(self, tmp_path, monkeypatch):
        queue_path = tmp_path / "audit_queue.json"
        monkeypatch.setattr(
            "servonaut.services.remote_audit_service.AUDIT_QUEUE_PATH", queue_path
        )
        service = RemoteAuditService(None, None)
        run(service.log_event("test", {"data": "value"}))
        assert service.get_queue_size() == 1

    def test_flush_queue(self, audit_service, mock_api):
        # Queue some events
        mock_api.post.side_effect = RuntimeError("offline")
        run(audit_service.log_event("event1", {"team_slug": "team", "data": "1"}))
        run(audit_service.log_event("event2", {"team_slug": "team", "data": "2"}))
        assert audit_service.get_queue_size() == 2

        # Now restore API
        mock_api.post.side_effect = None
        mock_api.post.return_value = {"success": True}

        flushed = run(audit_service.flush_queue())
        assert flushed == 2
        assert audit_service.get_queue_size() == 0

    def test_flush_partial_failure(self, audit_service, mock_api):
        # Queue events
        mock_api.post.side_effect = RuntimeError("offline")
        run(audit_service.log_event("e1", {"team_slug": "team"}))
        run(audit_service.log_event("e2", {"team_slug": "team"}))

        # Partial flush — first succeeds, second fails
        call_count = 0
        async def partial_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count > 1:
                raise RuntimeError("still offline")
            return {"success": True}

        mock_api.post = partial_post
        flushed = run(audit_service.flush_queue())
        assert flushed == 1
        assert audit_service.get_queue_size() == 1


class TestQueuePersistence:
    def test_queue_persists_to_disk(self, tmp_path, monkeypatch):
        queue_path = tmp_path / "audit_queue.json"
        monkeypatch.setattr(
            "servonaut.services.remote_audit_service.AUDIT_QUEUE_PATH", queue_path
        )
        service = RemoteAuditService(None, None)
        run(service.log_event("test", {"data": "value"}))

        assert queue_path.exists()
        data = json.loads(queue_path.read_text())
        assert len(data) == 1

    def test_queue_loads_from_disk(self, tmp_path, monkeypatch):
        queue_path = tmp_path / "audit_queue.json"
        queue_path.write_text(json.dumps([
            {"event_type": "old", "timestamp": "2026-01-01", "details": {}}
        ]))
        monkeypatch.setattr(
            "servonaut.services.remote_audit_service.AUDIT_QUEUE_PATH", queue_path
        )
        service = RemoteAuditService(None, None)
        assert service.get_queue_size() == 1
