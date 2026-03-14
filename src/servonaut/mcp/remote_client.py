"""Remote MCP client connecting to hosted MCP server via SSE."""
from __future__ import annotations

import json
import logging
import asyncio
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from servonaut.services.auth_service import AuthService

logger = logging.getLogger(__name__)

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore[assignment]
    HAS_HTTPX = False

MCP_BASE = "https://mcp.servonaut.dev"

# Tools that always run locally (free tier)
LOCAL_TOOLS = {
    "list_instances", "run_command", "get_logs",
    "check_status", "get_server_info", "transfer_file",
}

# Premium tools that route to hosted MCP
PREMIUM_TOOLS = {
    "deploy", "provision", "cost_report", "security_scan",
}


class RemoteMCPClient:
    """Connect to hosted MCP server via SSE transport."""

    def __init__(self, auth_service: 'AuthService') -> None:
        self._auth = auth_service
        self._connected = False
        self._session_id: Optional[str] = None
        self._message_endpoint: Optional[str] = None
        self._pending_responses: Dict[str, asyncio.Future] = {}
        self._reconnect_delay = 1.0
        self._max_reconnect_delay = 60.0
        self._sse_task: Optional[asyncio.Task] = None

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self) -> bool:
        """Establish SSE connection to mcp.servonaut.dev."""
        if not HAS_HTTPX:
            raise RuntimeError(
                "httpx not installed. Install with: pip install 'servonaut[pro]'"
            )

        token = self._auth.access_token
        if not token:
            raise RuntimeError("Not authenticated. Run 'servonaut --login' first.")

        try:
            async with httpx.AsyncClient(timeout=None) as client:
                response = await client.get(
                    f"{MCP_BASE}/mcp/sse",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "text/event-stream",
                    },
                )

                if response.status_code == 200:
                    # Parse SSE endpoint from initial response
                    data = response.json()
                    self._session_id = data.get("session_id")
                    self._message_endpoint = data.get("message_endpoint", f"{MCP_BASE}/mcp/message")
                    self._connected = True
                    self._reconnect_delay = 1.0  # Reset backoff
                    logger.info("Connected to remote MCP server, session: %s", self._session_id)
                    return True
                else:
                    logger.error("MCP connection failed: %s", response.status_code)
                    return False
        except Exception as e:
            logger.error("MCP connection error: %s", e)
            return False

    async def disconnect(self) -> None:
        """Close SSE connection."""
        self._connected = False
        self._session_id = None
        if self._sse_task and not self._sse_task.done():
            self._sse_task.cancel()
        logger.info("Disconnected from remote MCP server")

    async def call_tool(self, name: str, arguments: dict) -> str:
        """Send tool call to hosted MCP and wait for result."""
        if not self._connected or not self._message_endpoint:
            raise RuntimeError("Not connected to remote MCP server")
        if not HAS_HTTPX:
            raise RuntimeError("httpx not installed")

        token = self._auth.access_token
        if not token:
            raise RuntimeError("Not authenticated")

        try:
            async with httpx.AsyncClient(timeout=120) as client:
                response = await client.post(
                    self._message_endpoint,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "session_id": self._session_id,
                        "method": "tools/call",
                        "params": {
                            "name": name,
                            "arguments": arguments,
                        },
                    },
                )

                if response.status_code >= 400:
                    raise RuntimeError(
                        f"Remote MCP error ({response.status_code}): {response.text}"
                    )

                data = response.json()
                # Extract text content from MCP response
                content = data.get("content", [])
                if content and isinstance(content, list):
                    texts = [c.get("text", "") for c in content if c.get("type") == "text"]
                    return "\n".join(texts)
                return json.dumps(data)

        except httpx.TimeoutException:
            raise RuntimeError(f"Remote tool '{name}' timed out")
        except Exception as e:
            logger.error("Remote tool call failed: %s", e)
            raise

    async def list_tools(self) -> List[dict]:
        """List available tools from remote MCP server."""
        if not self._connected or not self._message_endpoint:
            return []
        if not HAS_HTTPX:
            return []

        token = self._auth.access_token
        if not token:
            return []

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    self._message_endpoint,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "session_id": self._session_id,
                        "method": "tools/list",
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    return data.get("tools", [])
        except Exception as e:
            logger.warning("Failed to list remote tools: %s", e)
        return []

    async def reconnect(self) -> bool:
        """Reconnect with exponential backoff."""
        while not self._connected:
            logger.info(
                "Reconnecting in %.1f seconds...", self._reconnect_delay
            )
            await asyncio.sleep(self._reconnect_delay)

            if await self.connect():
                return True

            # Exponential backoff
            self._reconnect_delay = min(
                self._reconnect_delay * 2, self._max_reconnect_delay
            )

        return True

    @staticmethod
    def is_premium_tool(tool_name: str) -> bool:
        """Check if a tool should route to hosted MCP."""
        return tool_name in PREMIUM_TOOLS

    @staticmethod
    def is_local_tool(tool_name: str) -> bool:
        """Check if a tool should run locally."""
        return tool_name in LOCAL_TOOLS
