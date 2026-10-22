"""One tool call on the hosted MCP server.

The hosted server speaks two MCP transports:

* Streamable HTTP, tried first. Every JSON-RPC message is a
  ``POST {base}/mcp`` whose JSON response carries the reply. ``initialize``
  hands out an ``Mcp-Session-Id`` that the later requests send back, and
  ``DELETE {base}/mcp`` ends the session.
* HTTP+SSE (protocol 2024-11-05), for servers without that endpoint.
  ``GET {base}/mcp/sse`` opens an event stream whose first event
  (``endpoint``) names the message URL for this connection. The client POSTs
  JSON-RPC messages to that URL, the server only acknowledges them there, and
  every reply arrives as a ``message`` event on the stream.

:func:`call_hosted_tool` drives either through the ``mcp`` SDK's own clients.
It opens one session, runs ``initialize`` and a single ``tools/call``, and
closes the session again straight away, because the server caps how many
sessions one user may hold open. It falls back to HTTP+SSE only when the
``initialize`` POST is answered 404 or 405, or redirected, as a server
without the endpoint does. A redirect is never followed, so the bearer token
stays on the configured origin. Any other refusal (401, 402, 429, 5xx) is
reported as it is.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, Iterator, List, Optional

import httpx

from servonaut.utils.endpoints import MCP_URL_ENV, endpoint_or_default

if sys.version_info >= (3, 11):
    _ExceptionGroup = BaseExceptionGroup  # noqa: F821 - builtin from 3.11
else:  # anyio raises the backport on Python 3.10
    from exceptiongroup import BaseExceptionGroup as _ExceptionGroup

STREAMABLE_HTTP_PATH = "/mcp"
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
    status the session was refused with, when that is what happened.
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
            session was refused (``unauthorized`` for HTTP 401).
    """
    import anyio
    from mcp import types

    request = types.ClientRequest(types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name=name, arguments=arguments),
    ))
    headers = {"Authorization": f"Bearer {access_token}"}
    deadline = anyio.current_time() + timeout
    try:
        outcome = await _call_over_streamable_http(base, headers, request, timeout)
    except _NoStreamableHttp:
        outcome = await _call_over_sse(base, headers, request, deadline - anyio.current_time())
    if outcome is None:
        raise HostedCallError(
            "timeout", f"The hosted MCP server did not answer within {timeout:g} seconds."
        )
    return outcome


class _NoStreamableHttp(Exception):
    """The server has no Streamable HTTP endpoint: the call goes over HTTP+SSE."""


class _PostStatuses:
    """The HTTP status of each POST of one Streamable HTTP session, in order.

    ``initialize`` is the session's first POST, and nothing else is sent
    until it is answered, so while it is unanswered the last status is the
    answer it got (after any redirect the SDK followed within the origin).
    """

    def __init__(self) -> None:
        self.statuses: List[int] = []
        self.initialized = False

    async def record(self, response: httpx.Response) -> None:
        if response.request.method == "POST":
            self.statuses.append(response.status_code)

    def endpoint_missing(self) -> bool:
        """Whether ``initialize`` was refused as a server without the endpoint does."""
        if self.initialized or not self.statuses:
            return False
        status = self.statuses[-1]
        return status in (404, 405) or 300 <= status < 400


async def _call_over_streamable_http(
    base: str, headers: Dict[str, str], request: Any, timeout: float,
) -> Optional[Dict[str, Any]]:
    """Run the call over Streamable HTTP; None when no answer came within *timeout*.

    Raises:
        _NoStreamableHttp: the server has no Streamable HTTP endpoint.
        HostedCallError: the session was refused or failed.
    """
    import anyio
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    posts = _PostStatuses()
    outcome: Optional[Dict[str, Any]] = None
    try:
        async with httpx.AsyncClient(
            headers=headers, timeout=httpx.Timeout(timeout),
            event_hooks={"response": [posts.record]},
        ) as client:
            async with streamable_http_client(
                f"{base}{STREAMABLE_HTTP_PATH}", http_client=client,
            ) as (read_stream, write_stream, _session_id):
                async with ClientSession(read_stream, write_stream) as session:
                    # The deadline sits inside the transport and ends the body
                    # without raising, so the transport still sends its DELETE
                    # on a timeout and the server frees the slot at once.
                    with anyio.move_on_after(timeout) as scope:
                        outcome = await _initialize_and_call(session, request, posts)
                    if scope.cancelled_caught:
                        return None
    except Exception as exc:
        if posts.endpoint_missing():
            raise _NoStreamableHttp() from exc
        raise _classify(exc) from exc
    if outcome is None:
        # The SDK reports a 404 on the initialize POST as a JSON-RPC error.
        raise _NoStreamableHttp()
    return outcome


async def _initialize_and_call(
    session: Any, request: Any, posts: _PostStatuses,
) -> Optional[Dict[str, Any]]:
    """Initialize *session* and send *request*; None when the endpoint is missing."""
    from mcp import types
    from mcp.shared.exceptions import McpError

    try:
        await session.initialize()
        posts.initialized = True
        # send_request rather than call_tool: call_tool would list the
        # server's tools to validate the result, and this bridge forwards
        # results untouched. types.Result keeps every field the server sent.
        result = await session.send_request(request, types.Result)
    except McpError as exc:
        if posts.endpoint_missing():
            return None
        return {"error": _rpc_error(exc)}
    return {"result": result.model_dump(by_alias=True, mode="json", exclude_none=True)}


async def _call_over_sse(
    base: str, headers: Dict[str, str], request: Any, timeout: float,
) -> Optional[Dict[str, Any]]:
    """Run the call over HTTP+SSE; None when no answer came within *timeout*."""
    import anyio
    from mcp import ClientSession, types
    from mcp.client.sse import sse_client
    from mcp.shared.exceptions import McpError

    try:
        with anyio.fail_after(timeout):
            async with sse_client(
                f"{base}{SSE_PATH}", headers=headers,
                timeout=timeout, sse_read_timeout=timeout,
            ) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    try:
                        await session.initialize()
                        result = await session.send_request(request, types.Result)
                    except McpError as exc:
                        return {"error": _rpc_error(exc)}
    except TimeoutError:
        return None
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
                    "The hosted MCP server refused a new session (too many open sessions).",
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
