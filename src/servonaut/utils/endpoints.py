"""Endpoint overrides and the URL rule every one of them must pass.

Production code talks to fixed services: the Servonaut API and hosted MCP
server, PyPI for the update check, the Hetzner Cloud API, and ip-api.com /
AbuseIPDB for IP lookups. Each can be redirected with an environment variable,
for a staging server, a mirror, a proxy, or a local fake in tests. An unset or
blank variable keeps the production default unchanged. The relay listener's
``relay.base_url`` and ``relay.mercure_url`` config values follow the same rule,
because they carry the session token too.

An override must be an absolute ``https://`` URL. Plain ``http://`` is accepted
only for a loopback host (``127.0.0.1``, ``::1`` or ``localhost``): a local fake
works, but a typo can never send requests, or the tokens and API keys they
carry, in clear text to another machine. An invalid override raises
:class:`EndpointOverrideError` rather than quietly falling back to the
production service.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import Final, Optional
from urllib.parse import urlsplit, urlunsplit

LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost"})

# Servonaut API base (login, token refresh, every account API call) and hosted
# MCP base. Requests to both carry the OAuth bearer token.
API_URL_ENV: Final = "SERVONAUT_API_URL"
MCP_URL_ENV: Final = "SERVONAUT_MCP_URL"
ACCOUNT_ENDPOINT_ENVS: Final = (API_URL_ENV, MCP_URL_ENV)

# Config keys of the relay listener URLs, used as the name in refusals.
RELAY_BASE_URL_KEY: Final = "relay.base_url"
RELAY_MERCURE_URL_KEY: Final = "relay.mercure_url"

# Config key of the bring-your-own AI provider base URL.
AI_BASE_URL_KEY: Final = "ai_provider.base_url"


class EndpointOverrideError(ValueError):
    """An endpoint override holds a URL Servonaut refuses to use."""


def validate_endpoint_url(url: str, *, source: str, allow_query: bool = False) -> str:
    """Return the normalised form of *url* when it is an acceptable override.

    Anything a client library could parse differently from :func:`urlsplit`
    is refused outright: embedded credentials (``user:pass@``), backslashes,
    whitespace and control characters. Otherwise ``http://10.0.0.8\\@127.0.0.1``
    would pass the loopback check here while an HTTP client connects to
    ``10.0.0.8``. The URL itself is left out of error messages because it can
    carry credentials.

    Callers append paths to a base URL (``f"{base}/api/..."``), so a ``?`` or
    ``#`` in it would turn every path into part of a query or fragment. Both
    are refused unless *allow_query* says the URL is a complete endpoint, and
    even then a fragment is refused.

    Args:
        url: Candidate URL.
        source: Name used in the error, normally the environment variable.
        allow_query: Accept a query string (for a full endpoint URL, not a
            base that paths are appended to).

    Raises:
        EndpointOverrideError: The URL is malformed, carries credentials, has
            no host, has a query or fragment it may not have, or is not
            ``https`` (``http`` is allowed for a loopback host only).
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
    if "#" in url:
        raise EndpointOverrideError(f"{source} must not contain a fragment (#).")
    if "?" in url and not allow_query:
        raise EndpointOverrideError(f"{source} must not contain a query (?).")
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


def endpoint_or_default(env_var: str, default: str) -> str:
    """Return the validated override in *env_var*, else *default*.

    The result has no trailing slash, so callers can append ``/path``.

    Raises:
        EndpointOverrideError: The variable is set to an unacceptable URL. It
            is raised before any request is built, so nothing is sent.
    """
    return (endpoint_override(env_var) or default).rstrip("/")


def endpoint_override_errors(env_vars: Iterable[str]) -> list[str]:
    """Return the refusal message of each variable in *env_vars* that is invalid.

    Unset and acceptable variables contribute nothing. The messages name the
    variable, never its value.
    """
    errors: list[str] = []
    for env_var in env_vars:
        try:
            endpoint_override(env_var)
        except EndpointOverrideError as exc:
            errors.append(str(exc))
    return errors


def validate_relay_urls(base_url: str, mercure_url: str) -> None:
    """Refuse relay listener URLs that could expose the session token.

    The listener sends the OAuth bearer to ``base_url`` and the Mercure
    subscriber token to ``mercure_url``, so both follow the override rule.

    Raises:
        EndpointOverrideError: Either URL is unacceptable. The message names
            the config key, never the URL.
    """
    validate_endpoint_url(base_url, source=RELAY_BASE_URL_KEY)
    validate_endpoint_url(mercure_url, source=RELAY_MERCURE_URL_KEY)
