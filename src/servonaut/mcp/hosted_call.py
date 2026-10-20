"""One tool call on the hosted MCP server, over its HTTP+SSE transport.

The hosted server speaks MCP's HTTP+SSE transport (protocol 2024-11-05):

* ``GET {base}/mcp/sse`` with the CLI's bearer opens an event stream whose
  first event (``endpoint``) names the message URL for this connection;
* the client POSTs JSON-RPC messages to that URL, and the server only
  acknowledges them there;
* every JSON-RPC reply arrives as a ``message`` event on the stream.

:func:`call_hosted_tool` drives this through the ``mcp`` SDK's own client:
it opens one stream, runs ``initialize`` and a single ``tools/call``, and
closes the stream again straight away, because the server caps how many
streams one user may hold open.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, Iterator, Optional

import httpx

from servonaut.utils.endpoints import MCP_URL_ENV, endpoint_or_default

if sys.version_info >= (3, 11):
    _ExceptionGroup = BaseExceptionGroup  # noqa: F821 - builtin from 3.11
else:  # anyio raises the backport on Python 3.10
    from exceptiongroup import BaseExceptionGroup as _ExceptionGroup

SSE_PATH = "/mcp/sse"

_DEFAULT_MCP_BASE = "https://mcp.servonaut.dev"


def _mcp_base() -> str:
    """Return the hosted MCP base URL, honouring a valid ``SERVONAUT_MCP_URL``.

    Read at call time so secrets loaded after import are picked up.

    Raises:
        EndpointOverrideError: ``SERVONAUT_MCP_URL`` is not https (or http to
            a loopback host). Raised before the bearer token is attached.
    """
    return endpoint_or_default(MCP_URL_ENV, _DEFAULT_MCP_BASE)


class HostedCallError(Exception):
    """The hosted server gave no JSON-RPC answer to the call.

    ``code`` is a stable machine-readable reason; ``status`` is the HTTP
    status the event stream was refused with, when that is what happened.
    """

    def __init__(self, code: str, message: str, *, status: Optional[int] = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


async def call_hosted_tool(
    base: str,
    access_token: str,
    name: str,
    arguments: Dict[str, Any],
    *,
    timeout: float,
) -> Dict[str, Any]:
    """Run tool *name* on the hosted MCP server at *base*.

    Returns ``{"result": {...}}`` with the tool result exactly as the server
    sent it, or ``{"error": {"code", "message"[, "data"]}}`` when the server
    answered with a JSON-RPC error: an unknown tool, or ``-32050`` when it
    refuses the call for capacity or rate.

    Raises:
        ImportError: the ``mcp`` SDK is not installed.
        HostedCallError: no answer arrived within *timeout* seconds, or the
            event stream was refused (``unauthorized`` for HTTP 401).
    """
    import anyio
    from mcp import ClientSession, types
    from mcp.client.sse import sse_client
    from mcp.shared.exceptions import McpError

    request = types.ClientRequest(types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name=name, arguments=arguments),
    ))
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        with anyio.fail_after(timeout):
            async with sse_client(
                f"{base}{SSE_PATH}", headers=headers,
                timeout=timeout, sse_read_timeout=timeout,
            ) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    try:
                        await session.initialize()
                        # send_request rather than call_tool: call_tool would
                        # list the server's tools to validate the result, and
                        # this bridge forwards results untouched. types.Result
                        # keeps every field the server sent.
                        result = await session.send_request(request, types.Result)
                    except McpError as exc:
                        return {"error": _rpc_error(exc)}
    except TimeoutError as exc:
        raise HostedCallError(
            "timeout", f"The hosted MCP server did not answer within {timeout:g} seconds."
        ) from exc
    except Exception as exc:
        raise _classify(exc) from exc
    return {"result": result.model_dump(by_alias=True, mode="json", exclude_none=True)}


def _rpc_error(exc: Exception) -> Dict[str, Any]:
    """The JSON-RPC error object carried by an SDK ``McpError``."""
    # Older 1.x SDKs pass the ErrorData positionally without setting .error.
    data = getattr(exc, "error", None) or (exc.args[0] if exc.args else None)
    if hasattr(data, "model_dump"):
        return data.model_dump(mode="json", exclude_none=True)
    return {"code": -32603, "message": str(exc)}


def _classify(exc: BaseException) -> HostedCallError:
    """Turn a transport failure (possibly inside a task group) into a HostedCallError."""
    leaves = list(_leaves(exc))
    for leaf in leaves:
        if isinstance(leaf, httpx.HTTPStatusError):
            status = leaf.response.status_code
            if status == 401:
                return HostedCallError(
                    "unauthorized", "The hosted MCP server refused the session token.",
                    status=status,
                )
            if status == 429:
                return HostedCallError(
                    "connection_limit",
                    "The hosted MCP server refused a new connection (too many open streams).",
                    status=status,
                )
            return HostedCallError(
                "http_error", f"The hosted MCP server answered HTTP {status}.", status=status,
            )
    for leaf in leaves:
        if isinstance(leaf, (httpx.TimeoutException, TimeoutError)):
            return HostedCallError("timeout", "The hosted MCP server did not answer in time.")
        if isinstance(leaf, httpx.HTTPError):
            return HostedCallError("network_error", str(leaf) or type(leaf).__name__)
    first = leaves[0] if leaves else exc
    return HostedCallError("protocol_error", f"{type(first).__name__}: {first}")


def _leaves(exc: BaseException) -> Iterator[BaseException]:
    """The exceptions inside *exc*, flattening (nested) exception groups."""
    if isinstance(exc, _ExceptionGroup):
        for inner in exc.exceptions:
            yield from _leaves(inner)
    else:
        yield exc
