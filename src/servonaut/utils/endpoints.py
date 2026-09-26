"""Environment overrides for the third-party endpoints Servonaut calls.

Production code talks to fixed public services: PyPI for the update check,
the Hetzner Cloud API, and ip-api.com / AbuseIPDB for IP lookups. Like
``SERVONAUT_API_URL`` and ``SERVONAUT_MCP_URL``, each can be redirected with an
environment variable, for a mirror, a proxy, or a local fake in tests. An unset
or blank variable keeps the production default unchanged.

An override must be an absolute ``https://`` URL. Plain ``http://`` is accepted
only for a loopback host (``127.0.0.1``, ``::1`` or ``localhost``): a local fake
works, but a typo can never send requests, or the API keys some of them carry,
in clear text to another machine. An invalid override raises
:class:`EndpointOverrideError` rather than quietly falling back to the
production service.
"""

from __future__ import annotations

import os
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost"})


class EndpointOverrideError(ValueError):
    """An endpoint override holds a URL Servonaut refuses to use."""


def validate_endpoint_url(url: str, *, source: str) -> str:
    """Return the normalised form of *url* when it is an acceptable override.

    Anything a client library could parse differently from :func:`urlsplit`
    is refused outright: embedded credentials (``user:pass@``), backslashes,
    whitespace and control characters. Otherwise ``http://10.0.0.8\\@127.0.0.1``
    would pass the loopback check here while an HTTP client connects to
    ``10.0.0.8``. The URL itself is left out of error messages because it can
    carry credentials.

    Args:
        url: Candidate URL.
        source: Name used in the error, normally the environment variable.

    Raises:
        EndpointOverrideError: The URL is malformed, carries credentials, has
            no host, or is not ``https`` (``http`` is allowed for a loopback
            host only).
    """
    if any(ch == "\\" or ch.isspace() or not ch.isprintable() for ch in url):
        raise EndpointOverrideError(
            f"{source} must not contain spaces, backslashes or control characters."
        )
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        parts.port  # noqa: B018 - raises ValueError for a malformed port
    except ValueError as exc:  # unbalanced IPv6 bracket, non-numeric port, ...
        raise EndpointOverrideError(f"{source} is not a valid URL.") from exc
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise EndpointOverrideError(f"{source} must not contain credentials.")
    if not host:
        raise EndpointOverrideError(f"{source} must be an absolute URL with a host.")
    scheme = parts.scheme.lower()
    if scheme == "https" or (scheme == "http" and host in LOOPBACK_HOSTS):
        return urlunsplit(parts)
    raise EndpointOverrideError(
        f"{source} must be an https:// URL "
        "(http:// is accepted only for 127.0.0.1, ::1 or localhost)."
    )


def endpoint_override(env_var: str) -> Optional[str]:
    """Return the validated URL in *env_var*, or ``None`` when it is unset.

    Read at call time, so a value loaded from the secrets file after import is
    honoured.

    Raises:
        EndpointOverrideError: The variable is set to an unacceptable URL.
    """
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return None
    return validate_endpoint_url(raw, source=env_var)
