"""Host and user names that are safe to hand to ssh.

ssh expands ``%h`` (the target host) into the ProxyCommand of a bastion route
and runs the result through the local shell, so a host name carrying a quote,
a backslash, a space or other shell syntax would run as a command on this
computer on an ssh client that does not refuse such names itself. Names come
from server lists, teams and provider accounts, so they are checked where the
command is built, with a message that says what to fix.

Only what a real name never needs is refused. Letters in any script, digits,
``. - _ : %`` and brackets (IPv6 literals and scope ids) all pass. A user name
may also hold ``\\`` and ``@`` (domain accounts), so only a quote, whitespace
and control characters are refused there.
"""
from __future__ import annotations

import re

from servonaut.utils.markup import inert_text

_HOST_UNSAFE = re.compile(r"""[\x00-\x20\x7f-\x9f'"`\\$;|&<>(){}*?!#^~=,]""")
_USER_UNSAFE = re.compile(r"""[\x00-\x20\x7f-\x9f']""")
_SHOWN_LIMIT = 60


class SSHNameError(ValueError):
    """A host or user name that cannot be used safely in an ssh command."""


def _shown(value: str) -> str:
    text = inert_text(value)
    return text if len(text) <= _SHOWN_LIMIT else text[:_SHOWN_LIMIT] + "..."


def check_ssh_host(host: object) -> None:
    """Raise ``SSHNameError`` when *host* holds a character a host name never needs."""
    if isinstance(host, str) and _HOST_UNSAFE.search(host):
        raise SSHNameError(
            f"Not connecting: the host name {_shown(host)!r} contains a space, quote, backslash "
            "or shell symbol. Correct the server's address in its details."
        )


def check_ssh_user(user: object) -> None:
    """Raise ``SSHNameError`` when *user* holds a quote, whitespace or a control character."""
    if isinstance(user, str) and _USER_UNSAFE.search(user):
        raise SSHNameError(
            f"Not connecting: the user name {_shown(user)!r} contains a space, quote or control "
            "character. Correct the server's user name in its details."
        )


def check_ssh_target(host: object, user: object) -> None:
    check_ssh_host(host)
    check_ssh_user(user)
