"""Quoting for values that become words of a command run on a remote host.

Names read back from a server (``find``/``ls`` output, probe results) can be
chosen by any local account there, so a name such as ``x;cmd;.log`` or
``$(cmd)`` must reach the remote shell as one inert word. Every command builder
that interpolates such a value goes through ``shell_word`` or ``shell_path``.
"""
from __future__ import annotations

import shlex


def shell_word(value: str) -> str:
    """Return *value* as a single inert word of a remote shell command.

    A value starting with ``-`` is anchored with ``./`` so the tool cannot
    read it as an option.
    """
    if value.startswith("-"):
        value = f"./{value}"
    return shlex.quote(value)


def shell_path(path: str) -> str:
    """Like ``shell_word``, but a leading ``~`` still means the login home.

    Quoting stops the remote shell from expanding ``~``, so the home part is
    written as ``"$HOME"`` (expanded) and only the rest is quoted.
    """
    if path == "~":
        return '"$HOME"'
    if path.startswith("~/"):
        return '"$HOME"/' + shell_word(path[2:])
    return shell_word(path)
