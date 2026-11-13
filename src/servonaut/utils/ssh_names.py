"""Host and user names that are safe to hand to ssh.

ssh expands ``%h`` (the target host) into the ProxyCommand of a bastion route
and runs the result through the local shell, so a host name carrying a quote,
a backslash, a space or other shell syntax would run as a command on this
computer on an ssh client that does not refuse such names itself. Names come
from server lists, teams and provider accounts, so they are checked where the
command is built, with a message that says what to fix.

Only what a real name never needs is refused. Letters in any script, digits,
``. - _ : %`` and brackets (IPv6 literals and scope ids) all pass. A user name
may also hold ``\\``, ``@`` and spaces (domain and Windows accounts); it is never
interpolated into a shell (ssh gets it inside the ``user@host`` argument), so
only control characters and a quote are refused there. The quote stays refused
because a user name can reach a ProxyCommand or a login script.
"""
from __future__ import annotations

import re


_HOST_UNSAFE = re.compile(r"""[\x00-\x20\x7f-\x9f'"`\\$;|&<>(){}*?!#^~=,]""")
_USER_UNSAFE = re.compile(r"""[\x00-\x1f\x7f-\x9f']""")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_SHOWN_LIMIT = 60


class SSHRefusal(ValueError):
    """A connection Servonaut will not start; the message says what to fix."""


class SSHNameError(SSHRefusal):
    """A host or user name that cannot be used safely in an ssh command."""


def _write_out(match: "re.Match[str]") -> str:
    code = ord(match.group())
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def shown(value: str) -> str:
    # Written out here (not through the markup helpers) so the MCP server,
    # which loads no UI library, can import this module.
    text = _CONTROL.sub(_write_out, value)
    return text if len(text) <= _SHOWN_LIMIT else text[:_SHOWN_LIMIT] + "..."


def check_ssh_host(host: object) -> None:
    """Raise ``SSHNameError`` when *host* holds a character a host name never needs."""
    if isinstance(host, str) and _HOST_UNSAFE.search(host):
        raise SSHNameError(
            f"Not connecting: the host name {shown(host)!r} contains a space, quote, backslash "
            "or shell symbol. Correct the server's address in its details."
        )


def check_ssh_user(user: object) -> None:
    """Raise ``SSHNameError`` when *user* holds a quote or a control character."""
    if isinstance(user, str) and _USER_UNSAFE.search(user):
        raise SSHNameError(
            f"Not connecting: the user name {shown(user)!r} contains a quote or control "
            "character. Correct the server's user name in its details."
        )


def check_ssh_target(host: object, user: object) -> None:
    check_ssh_host(host)
    check_ssh_user(user)
