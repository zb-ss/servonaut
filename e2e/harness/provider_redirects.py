"""Point the Hetzner and OVH client libraries at the local fakes.

Servonaut offers no endpoint setting for either provider on this code base:

* python-ovh only accepts the named endpoints in ``ovh.client.ENDPOINTS``
  (``ovh-eu``, ``ovh-ca``, ...), and the configured name is passed straight
  through;
* ``hcloud.Client`` is built without ``api_endpoint`` unless the product
  honours ``SERVONAUT_HETZNER_API_URL``.

So the suite rewrites the libraries' own defaults: every OVH endpoint name
resolves to the fake (each name to its own base URL when the fake gives it
one, so journeys can tell an ``ovh-eu`` account from an ``ovh-ca`` one), the
OAuth2 token service of each name resolves to the fake's, and hcloud's
``api_endpoint`` default becomes the fake's URL. Nothing inside Servonaut is
patched, and the product builds its clients exactly as it does for a user.
Once the product reads an endpoint override, the suite sets that instead and
the corresponding rewrite here is skipped.

The fake serves plain HTTP on loopback, which the OAuth2 library refuses
unless ``OAUTHLIB_INSECURE_TRANSPORT`` is set; the ``providers`` fixture sets
it for the journey and its children.

Standard library only: ``child_site/sitecustomize.py`` loads this file by path
in every Python child and calls :func:`apply_from_environment`.
"""

from __future__ import annotations

import inspect
import json
import os
from typing import Callable, Mapping, Optional

ENV_REDIRECTS = "SERVONAUT_E2E_PROVIDER_REDIRECTS"
# The product's own override for the Hetzner endpoint, where it exists.
HETZNER_URL_ENV = "SERVONAUT_HETZNER_API_URL"
# Lets the OAuth2 library (python-ovh's service accounts) use plain HTTP.
OAUTH_INSECURE_TRANSPORT_ENV = "OAUTHLIB_INSECURE_TRANSPORT"
# The OVH fake serves an endpoint's OAuth2 token service next to its API:
# ``<root>/1.0`` is the API, ``<root>/auth/oauth2/token`` the token service.
OVH_OAUTH2_TOKEN_PATH = "/auth/oauth2/token"
_OVH_API_VERSION = "/1.0"

Setter = Callable[[object, str, object], None]


def _plain_setattr(target: object, name: str, value: object) -> None:
    setattr(target, name, value)


def ovh_oauth2_token_url(endpoint_url: str) -> str:
    """The fake's OAuth2 token service for the OVH API at *endpoint_url*."""
    root = endpoint_url
    if root.endswith(_OVH_API_VERSION):
        root = root[: -len(_OVH_API_VERSION)]
    return root + OVH_OAUTH2_TOKEN_PATH


def redirect_ovh(
    url: str,
    setitem: Optional[Callable[[dict, str, str], None]] = None,
    *,
    endpoints: Optional[Mapping[str, str]] = None,
) -> None:
    """Resolve every named OVH endpoint, and its OAuth2 token service, to the fake.

    *endpoints* maps endpoint names to their own base URLs; every other name
    resolves to *url*.
    """
    import ovh.client

    def assign(table: dict, name: str, value: str) -> None:
        if setitem is None:
            table[name] = value
        else:
            setitem(table, name, value)

    endpoints = endpoints or {}
    for name in list(ovh.client.ENDPOINTS):
        assign(ovh.client.ENDPOINTS, name, endpoints.get(name, url))
    for name in list(ovh.client.OAUTH2_TOKEN_URLS):
        assign(
            ovh.client.OAUTH2_TOKEN_URLS, name, ovh_oauth2_token_url(endpoints.get(name, url))
        )


def redirect_hcloud(url: str, setter: Setter = _plain_setattr) -> None:
    """Make *url* the default ``api_endpoint`` of ``hcloud.Client``."""
    from hcloud import _client

    init = _client.Client.__init__
    parameters = [
        p for p in inspect.signature(init).parameters.values()
        if p.default is not inspect.Parameter.empty
        and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
    ]
    names = [p.name for p in parameters]
    if not names or names[0] != "api_endpoint" or init.__defaults__ is None:
        raise RuntimeError(
            f"hcloud.Client no longer takes api_endpoint as its first default ({names}); "
            "update e2e/harness/provider_redirects.py"
        )
    setter(init, "__defaults__", (url, *init.__defaults__[1:]))


def apply_from_environment() -> None:
    """Apply the redirects named in ``SERVONAUT_E2E_PROVIDER_REDIRECTS`` (JSON).

    ``{"ovh": url, "ovh_endpoints": {name: url}, "hetzner": url}``; every key
    is optional.
    """
    raw = os.environ.get(ENV_REDIRECTS, "").strip()
    if not raw:
        return
    wanted = json.loads(raw)
    if wanted.get("ovh"):
        redirect_ovh(wanted["ovh"], endpoints=wanted.get("ovh_endpoints"))
    if wanted.get("hetzner"):
        redirect_hcloud(wanted["hetzner"])
