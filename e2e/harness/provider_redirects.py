"""Point the Hetzner and OVH client libraries at the local fakes.

Servonaut offers no endpoint setting for either provider on this code base:

* python-ovh only accepts the named endpoints in ``ovh.client.ENDPOINTS``
  (``ovh-eu``, ``ovh-ca``, ...), and the configured name is passed straight
  through;
* ``hcloud.Client`` is built without ``api_endpoint`` unless the product
  honours ``SERVONAUT_HETZNER_API_URL``.

So the suite rewrites the libraries' own defaults: every OVH endpoint name
resolves to the fake, and hcloud's ``api_endpoint`` default becomes the fake's
URL. Nothing inside Servonaut is patched, and the product builds its clients
exactly as it does for a user. Once the product reads an endpoint override,
the suite sets that instead and the corresponding rewrite here is skipped.

Standard library only: ``child_site/sitecustomize.py`` loads this file by path
in every Python child and calls :func:`apply_from_environment`.
"""

from __future__ import annotations

import inspect
import json
import os
from typing import Callable, Optional

ENV_REDIRECTS = "SERVONAUT_E2E_PROVIDER_REDIRECTS"
# The product's own override for the Hetzner endpoint, where it exists.
HETZNER_URL_ENV = "SERVONAUT_HETZNER_API_URL"

Setter = Callable[[object, str, object], None]


def _plain_setattr(target: object, name: str, value: object) -> None:
    setattr(target, name, value)


def redirect_ovh(url: str, setitem: Optional[Callable[[dict, str, str], None]] = None) -> None:
    """Resolve every named OVH endpoint to *url*."""
    import ovh.client

    for name in list(ovh.client.ENDPOINTS):
        if setitem is None:
            ovh.client.ENDPOINTS[name] = url
        else:
            setitem(ovh.client.ENDPOINTS, name, url)


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
    """Apply the redirects named in ``SERVONAUT_E2E_PROVIDER_REDIRECTS`` (JSON)."""
    raw = os.environ.get(ENV_REDIRECTS, "").strip()
    if not raw:
        return
    wanted = json.loads(raw)
    if wanted.get("ovh"):
        redirect_ovh(wanted["ovh"])
    if wanted.get("hetzner"):
        redirect_hcloud(wanted["hetzner"])
