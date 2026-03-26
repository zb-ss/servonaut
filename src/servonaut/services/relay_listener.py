"""Mercure SSE relay listener: subscribes to commands and POSTs results back."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import asdict, replace

try:
    import httpx
    from httpx_sse import aconnect_sse
    HAS_HTTPX_SSE = True
except ImportError:
    HAS_HTTPX_SSE = False

from servonaut.models.relay_messages import CommandRequest, CommandType, CommandResponse

logger = logging.getLogger(__name__)


class RelayListener:
    """Subscribes to a Mercure hub topic and dispatches commands to RelayExecutors."""

    def __init__(self, executors, base_url: str, mercure_url: str,
                 auth_token: str, user_id: str,
                 heartbeat_interval: int = 30) -> None:
        if not HAS_HTTPX_SSE:
            raise ImportError(
                "httpx-sse required. Install with: pip install 'servonaut[relay]'"
            )
        self._executors = executors
        self._base_url = base_url.rstrip('/')
        self._mercure_url = mercure_url.rstrip('/')
        self._auth_token = auth_token
        self._user_id = user_id
        self._heartbeat_interval = heartbeat_interval
        self._last_event_id: str | None = None
        self._running = False
        self._client: httpx.AsyncClient | None = None

    async def run(self) -> None:
        """Start listener and heartbeat concurrently."""
        self._running = True
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=None)) as client:
            self._client = client
            try:
                await asyncio.gather(
                    self._listen_forever(),
                    self._heartbeat_loop(),
                )
            except asyncio.CancelledError:
                self._running = False
            finally:
                self._client = None

    async def _listen_forever(self) -> None:
        """SSE subscribe loop with exponential backoff on failure."""
        backoff = 1
        max_backoff = 30
        topic = f"/cli/{self._user_id}/commands"

        while self._running:
            try:
                headers = {"Authorization": f"Bearer {self._auth_token}"}
                if self._last_event_id:
                    headers["Last-Event-ID"] = self._last_event_id

                async with aconnect_sse(
                    self._client, "GET", self._mercure_url,
                    params={"topic": topic},
                    headers=headers,
                ) as event_source:
                    backoff = 1  # Reset on successful connection
                    logger.info("Connected to Mercure hub, topic: %s", topic)
                    print("Connected to relay. Waiting for commands...")  # noqa: foreground only

                    async for event in event_source.aiter_sse():
                        if not self._running:
                            return
                        if event.id:
                            self._last_event_id = event.id
                        if event.data:
                            await self._handle_event(event.data)

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    logger.error("401 from Mercure — auth token may have expired")
                    backoff = max_backoff
                else:
                    logger.error("HTTP error from Mercure: %s", e)
            except Exception as e:
                logger.error("Mercure connection error: %s", e)

            if self._running:
                logger.info("Reconnecting in %ds...", backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)

    async def _handle_event(self, data: str) -> None:
        """Parse an SSE event payload and dispatch to executor."""
        try:
            raw = json.loads(data)

            # Validate user_id matches the authenticated identity (mandatory)
            event_user_id = raw.get("user_id", "")
            if event_user_id != self._user_id:
                logger.warning(
                    "Rejected event with missing/mismatched user_id (expected %s)",
                    self._user_id,
                )
                return

            try:
                ttl = int(raw.get("ttl_seconds", 60))
            except (TypeError, ValueError):
                ttl = 60

            request = CommandRequest(
                id=raw["id"],
                user_id=event_user_id,
                type=CommandType(raw["type"]),
                target_server_id=raw["target_server_id"],
                payload=raw.get("payload", {}),
                ttl_seconds=ttl,
            )
            start = time.monotonic()
            response = await self._executors.execute(request)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            response = replace(response, execution_time_ms=elapsed_ms)

            status_icon = "v" if response.status == "success" else "x"
            msg = (f"[{request.type.value}] {request.target_server_id}: "
                   f"{status_icon} ({elapsed_ms}ms)")
            logger.info("Relay command: %s", msg)
            print(f"  {msg}")

            await self._post_result(response)
        except Exception as e:
            logger.error("Failed to handle event: %s — data length: %d", e, len(data))

    async def _post_result(self, response: CommandResponse) -> None:
        """POST the command result back to the backend."""
        url = f"{self._base_url}/api/cli/command-result/{response.request_id}"
        try:
            resp = await self._client.post(
                url,
                json=asdict(response),
                headers={"Authorization": f"Bearer {self._auth_token}"},
                timeout=10.0,
            )
            if resp.status_code >= 400:
                logger.warning(
                    "Failed to post result: %s %s",
                    resp.status_code, resp.text[:200],
                )
        except Exception as e:
            logger.warning("Failed to post result for %s: %s", response.request_id, e)

    async def _heartbeat_loop(self) -> None:
        """Send a heartbeat to the backend every N seconds."""
        url = f"{self._base_url}/api/cli/heartbeat"
        while self._running:
            try:
                await self._client.post(
                    url,
                    json={"status": "connected"},
                    headers={"Authorization": f"Bearer {self._auth_token}"},
                    timeout=10.0,
                )
            except Exception as e:
                logger.warning("Heartbeat failed: %s", e)
            await asyncio.sleep(self._heartbeat_interval)

    def stop(self) -> None:
        """Signal the listener to stop."""
        self._running = False
