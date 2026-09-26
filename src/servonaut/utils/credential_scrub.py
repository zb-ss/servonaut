"""Scrub credentials out of text bound for logs and the UI.

Installer, network and download errors quote URLs, and a proxy URL can carry
a user name and password. Everything that surfaces such text (a log line, an
error notification) passes it through :func:`scrub_credentials` first.
"""

from __future__ import annotations

import re
from typing import Iterable, Mapping, Tuple
from urllib.parse import unquote

_MASK = "***"

# User-info is bounded in length: real credentials are short, and an
# unbounded run would make each match attempt scan to the end of the line,
# which is quadratic on long adversarial lines.
_MAX_USERINFO_CHARS = 256

# scheme://userinfo@ — greedy up to the last "@" before the path, so a
# password that itself holds an "@" is covered whole.
_URL_USERINFO = re.compile(
    rf"(?i)\b([a-z][a-z0-9+.-]{{0,32}}://)[^\s/?#]{{0,{_MAX_USERINFO_CHARS}}}@"
)

# user:secret@host without a scheme, the way proxy settings are often
# written. The secret part is greedy for the same reason as above.
_BARE_USERINFO = re.compile(
    rf"(?<![\w.%+-])[\w.%+-]{{1,{_MAX_USERINFO_CHARS}}}:"
    rf"[^\s/?#'\"]{{0,{_MAX_USERINFO_CHARS}}}@(?=[\w\[])"
)

# Shorter literals are too likely to occur by chance to be masked verbatim;
# the URL patterns still cover them wherever they appear inside a URL.
_MIN_LITERAL_CHARS = 4


def scrub_credentials(text: str, secrets: Iterable[str] = ()) -> str:
    """Return *text* with URL credentials and the given *secrets* masked.

    Args:
        text: Text that may quote URLs.
        secrets: Literal values to mask wherever they appear, such as the
            credential parts of the proxy settings a child process was given.
    """
    for secret in sorted(set(secrets), key=len, reverse=True):
        if len(secret) >= _MIN_LITERAL_CHARS:
            text = text.replace(secret, _MASK)
    text = _URL_USERINFO.sub(rf"\1{_MASK}@", text)
    return _BARE_USERINFO.sub(f"{_MASK}@", text)


def proxy_credentials(env: Mapping[str, str]) -> Tuple[str, ...]:
    """Credential literals carried by the proxy settings in *env*.

    Both the user-info part and the password alone, each as written and
    percent-decoded, because a program may echo either form.
    """
    found = set()
    for name, value in env.items():
        if "proxy" not in name.lower() or "@" not in value:
            continue
        userinfo = value.split("://", 1)[-1].rsplit("@", 1)[0]
        password = userinfo.partition(":")[2]
        for literal in (userinfo, password):
            found.update({literal, unquote(literal)})
    return tuple(sorted(literal for literal in found if len(literal) >= _MIN_LITERAL_CHARS))
