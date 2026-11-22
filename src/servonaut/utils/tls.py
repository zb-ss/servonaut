"""One TLS trust setup for every urllib HTTPS request.

A packaged build bundles an OpenSSL whose default certificate path points at
the build machine, so ``ssl.create_default_context()`` alone finds no trusted
roots on a user's computer and every urllib request fails verification. The
context returned here keeps the platform and ``SSL_CERT_FILE`` trust (managed
or corporate roots keep working) and adds the certifi bundle that ships with
the application.
"""

from __future__ import annotations

import functools
import logging
import ssl
import urllib.request

log = logging.getLogger(__name__)


@functools.lru_cache(maxsize=1)
def client_ssl_context() -> ssl.SSLContext:
    """Return a verifying client context with system and certifi roots."""
    context = ssl.create_default_context()
    try:
        import certifi

        context.load_verify_locations(cafile=certifi.where())
    except (ImportError, OSError, ssl.SSLError) as exc:
        log.warning("Bundled CA certificates unavailable (%s).", type(exc).__name__)
    return context


def build_opener(*handlers: object) -> urllib.request.OpenerDirector:
    """Return a urllib opener that verifies HTTPS with :func:`client_ssl_context`."""
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=client_ssl_context()), *handlers
    )
