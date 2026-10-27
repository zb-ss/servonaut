"""Record a server's SSH host key the way a first connection does.

With ``ssh.host_key_checking`` at ``accept-new``, OpenSSH records the key of
a server it has not met before in Servonaut's known_hosts file. Pinning a
vault key needs that recorded key, so a server never connected to from this
machine can be visited once, over its usual route (through a bastion when a
connection rule says so), without opening a terminal.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Mapping, Optional

from servonaut.services.connection_service import server_connection
from servonaut.services.ssh_host_keys import (
    HOST_KEY_CHECKING_ACCEPT_NEW,
    HostKeyPolicy,
    HostKeyTarget,
    detect_host_key_problem,
)
from servonaut.utils.ssh_utils import run_ssh_subprocess

logger = logging.getLogger(__name__)

# A visit opens up to two connections (a bastion hop, then the server), each
# bounded by ssh.connect_timeout, and runs one command once logged in.
_VISIT_TIMEOUT_CONNECTS = 3


def records_new_host_keys(connection_service: Any) -> bool:
    """True when connecting records a new server's host key (``accept-new`` in effect).

    With ``yes`` (or ``accept-new`` tightened because Servonaut's own file is
    unsafe) a new server is refused; with ``off`` nothing is recorded.
    """
    policy = connection_service.host_key_policy()
    return policy.known_hosts_setup().mode == HOST_KEY_CHECKING_ACCEPT_NEW


def visit_timeout(ssh_config: Any) -> float:
    """Seconds a visit may take, from the configured connect timeout."""
    connect = getattr(ssh_config, "connect_timeout", None)
    if isinstance(connect, bool) or not isinstance(connect, (int, float)) or connect <= 0:
        from servonaut.config.schema import SSHConfig

        connect = SSHConfig().connect_timeout
    return float(connect) * _VISIT_TIMEOUT_CONNECTS


async def visit_for_host_key(
    instance: Mapping[str, Any],
    connection_service: Any,
    ssh_service: Any,
    login: str,
    *,
    timeout: float,
    known_hosts_path: Optional[Path | str] = None,
) -> Optional[str]:
    """Connect to *instance* once so OpenSSH records its host key.

    The key is recorded during the key exchange, before logging in, so a
    refused login still records it; the caller reads what is trusted
    afterwards. The login runs ``true`` and nothing else, with no prompt.

    Returns:
        None when the connection went through, otherwise why it did not, as
        a sentence for the user.
    """
    row = dict(instance)
    conn = server_connection(row, connection_service, ssh_service, login)
    host = conn.get("host")
    if not host:
        return "This server has no address to connect to."
    port = conn.get("port")
    argv = ssh_service.build_ssh_command(
        host=host,
        username=login or conn.get("username") or "root",
        key_path=conn.get("key_path"),
        proxy_args=conn.get("proxy_args"),
        port=port,
        remote_command="true",
        # Nobody can answer a prompt here.
        extra_options=["BatchMode=yes", *(conn.get("extra_options") or [])],
        record_to_known_hosts=known_hosts_path,
    )
    try:
        output = await run_ssh_subprocess(argv, timeout=timeout)
    except asyncio.TimeoutError:
        return "The server did not answer in time."
    except OSError as exc:
        logger.debug("Could not start ssh to record a host key", exc_info=True)
        return f"Could not run ssh ({exc.strerror or type(exc).__name__})."
    if output.returncode == 0:
        return None
    policy = (
        HostKeyPolicy(
            mode="accept-new",
            known_hosts_file=Path(known_hosts_path),
            user_known_hosts_file=Path("/dev/null"),
        )
        if known_hosts_path
        else connection_service.host_key_policy()
    )
    problem = detect_host_key_problem(
        output.diagnostics, output.returncode,
        HostKeyTarget.for_connection(host, port, instance=row, profile=conn.get("profile")),
        policy, stdout=output[0],
    )
    if problem is not None:
        return problem.message
    # ssh's own log first; its stderr when it stopped before writing one. The
    # remote command prints nothing, but a server's login banner can reach
    # stderr: callers show this as plain text, never as markup.
    for text in (output.diagnostics, _decoded(output[1])):
        lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
        if lines:
            return lines[-1]
    return f"ssh could not connect (exit status {output.returncode})."


def _decoded(data: Any) -> str:
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data if isinstance(data, str) else ""
