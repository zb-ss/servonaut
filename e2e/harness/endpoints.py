"""Environment variables that send a child process to the local fakes.

The journey fixtures (``e2e/conftest.py``) and the local QA sandbox
(``e2e/sandbox``) build child environments from these functions, so a child
reaches the same fakes the same way in both. Only the variables are built
here; redirecting the test process itself stays with the fixtures.

Import after the hermetic environment is in place (``fake_cloud_env`` and
``providers_env`` import ``servonaut``).
"""

from __future__ import annotations

import json
from typing import Any

from e2e.harness import provider_redirects

# Read by child_guard.py: module constants pointed at the fakes.
REDIRECTS_ENV = "SERVONAUT_E2E_REDIRECTS"
AWS_ENDPOINT_ENV = "AWS_ENDPOINT_URL"
CLOUDTRAIL_ENDPOINT_ENV = "AWS_ENDPOINT_URL_CLOUDTRAIL"


def fake_cloud_env(server: Any) -> dict[str, str]:
    """The Servonaut API, the hosted MCP endpoint and the package index on FakeCloud.

    The update check reads the package index URL from a module constant too;
    children get it redirected through :data:`REDIRECTS_ENV`.
    """
    from servonaut.services import update_service

    return {
        "SERVONAUT_API_URL": server.url,
        "SERVONAUT_MCP_URL": server.url,
        "SERVONAUT_PYPI_URL": server.pypi_json_url,
        REDIRECTS_ENV: json.dumps({update_service.__name__: {"PYPI_URL": server.pypi_json_url}}),
    }


def moto_env(server: Any) -> dict[str, str]:
    """Every AWS service on the local moto endpoint."""
    return {AWS_ENDPOINT_ENV: server.url}


def cloudtrail_env(stub: Any) -> dict[str, str]:
    """CloudTrail on its own stub (moto does not implement ``LookupEvents``)."""
    return {CLOUDTRAIL_ENDPOINT_ENV: stub.url}


def product_reads_hetzner_endpoint_override() -> bool:
    """True once Servonaut passes ``SERVONAUT_HETZNER_API_URL`` to hcloud."""
    from servonaut.services import hetzner_service

    return hasattr(hetzner_service, "HETZNER_API_URL_ENV")


def providers_env(server: Any) -> dict[str, str]:
    """The Hetzner and OVH client libraries on the FakeProviders server.

    OVH service accounts fetch OAuth2 tokens from the fake over plain HTTP.
    Hetzner uses the product's own endpoint switch where it has one, and the
    library default (redirected in the child) otherwise.
    """
    wanted: dict[str, Any] = {"ovh": server.ovh_url, "ovh_endpoints": server.ovh_endpoint_urls()}
    if not product_reads_hetzner_endpoint_override():
        wanted["hetzner"] = server.hetzner_url
    return {
        provider_redirects.OAUTH_INSECURE_TRANSPORT_ENV: "1",
        provider_redirects.HETZNER_URL_ENV: server.hetzner_url,
        provider_redirects.ENV_REDIRECTS: json.dumps(wanted),
    }
