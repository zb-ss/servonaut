"""Remote audit trail service for team event logging."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .interfaces import RemoteAuditServiceInterface

if TYPE_CHECKING:
    from servonaut.services.api_client import APIClient
    from servonaut.services.auth_service import AuthService

logger = logging.getLogger(__name__)

AUDIT_QUEUE_PATH = Path.home() / '.servonaut' / 'audit_queue.json'


class RemoteAuditService(RemoteAuditServiceInterface):
    """Logs audit events locally and forwards to API when online."""

    def __init__(
        self,
        api_client: Optional['APIClient'] = None,
        auth_service: Optional['AuthService'] = None,
    ) -> None:
        self._api = api_client
        self._auth = auth_service
        self._queue: List[dict] = []
        self._load_queue()

    async def log_event(self, event_type: str, details: dict) -> None:
        """Log an audit event. Tries remote first, queues on failure."""
        event = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details,
        }

        # Try to send to API if authenticated and in a team
        if self._api and self._auth and self._auth.is_authenticated:
            team_slug = details.get("team_slug")
            if team_slug:
                try:
                    await self._api.post(
                        f"/api/v1/teams/{team_slug}/audit",
                        event,
                    )
                    logger.debug("Audit event sent: %s", event_type)
                    return
                except Exception as e:
                    logger.warning("Failed to send audit event, queuing: %s", e)

        # Queue locally
        self._queue.append(event)
        self._save_queue()
        logger.debug("Audit event queued: %s (queue size: %d)", event_type, len(self._queue))

    async def flush_queue(self) -> int:
        """Flush offline event queue to API. Returns count flushed."""
        if not self._queue:
            return 0
        if not self._api or not self._auth or not self._auth.is_authenticated:
            return 0

        flushed = 0
        remaining: List[dict] = []

        for event in self._queue:
            team_slug = event.get("details", {}).get("team_slug")
            if not team_slug:
                # No team context — drop the event (local-only)
                flushed += 1
                continue
            try:
                await self._api.post(
                    f"/api/v1/teams/{team_slug}/audit",
                    event,
                )
                flushed += 1
            except Exception as e:
                logger.warning("Failed to flush audit event: %s", e)
                remaining.append(event)

        self._queue = remaining
        self._save_queue()
        logger.info("Flushed %d audit events, %d remaining", flushed, len(remaining))
        return flushed

    def get_queue_size(self) -> int:
        """Return number of queued events."""
        return len(self._queue)

    def _load_queue(self) -> None:
        """Load queued events from disk."""
        if not AUDIT_QUEUE_PATH.exists():
            return
        try:
            data = json.loads(AUDIT_QUEUE_PATH.read_text())
            self._queue = data if isinstance(data, list) else []
        except Exception as e:
            logger.warning("Failed to load audit queue: %s", e)
            self._queue = []

    def _save_queue(self) -> None:
        """Persist queued events to disk."""
        try:
            AUDIT_QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
            AUDIT_QUEUE_PATH.write_text(json.dumps(self._queue, indent=2))
        except Exception as e:
            logger.error("Failed to save audit queue: %s", e)
