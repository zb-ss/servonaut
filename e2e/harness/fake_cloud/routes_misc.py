"""Routes for smaller features: SSH verify, bug reports and IP lookups.

* ``GET /api/v1/me/instances/{provider}/{instance_id}/ssh-ref`` answers every
  signed-in request with a Bitwarden item reference whose id is derived from
  the instance (:func:`ssh_ref_item_id`), so a journey knows which item the
  ``bw`` stand-in will be asked for.
* ``POST /api/v1/bug-reports`` accepts a report, signed in or anonymous, and
  returns an id and a link.
* ``POST /ip-api/batch`` answers like ip-api.com's batch lookup, for the
  IP-enrichment base-URL override (every address resolves to the same
  documentation-range network, :data:`GEO_ASN`).

What was sent is read back from the FakeCloud request log.
"""

from __future__ import annotations

import itertools
import uuid
from typing import Callable

from aiohttp import web

from e2e.harness.fake_cloud.routes_auth import bearer_ok
from e2e.harness.fake_cloud.state import ScenarioStore

# Built at run time: no UUID literal is committed.
_ITEM_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "ssh-ref.servonaut-e2e.test")
BUG_REPORT_PREFIX = "br-e2e-"
# RFC 5398 reserves AS64496-AS64511 for documentation.
GEO_ASN = "AS64500 E2E Resolver Network"
IP_API_PREFIX = "/ip-api"


def ssh_ref_item_id(provider: str, instance_id: str) -> str:
    """The Bitwarden item id FakeCloud reports for an instance's SSH ref."""
    return str(uuid.uuid5(_ITEM_NAMESPACE, f"{provider}/{instance_id}"))


def add_routes(
    app: web.Application, store: ScenarioStore, base_url: Callable[[], str]
) -> None:
    """Register the routes on *app*; *base_url* gives FakeCloud's own URL.

    Signed-in routes accept the account's current access token, the same
    check every other route module uses.
    """
    report_ids = itertools.count(1)

    async def ssh_ref(request: web.Request) -> web.Response:
        if not bearer_ok(request, store):
            return web.json_response({"error": "unauthorized"}, status=401)
        provider = request.match_info["provider"]
        instance_id = request.match_info["instance_id"]
        return web.json_response(
            {
                "ssh_credential_provider": "bitwarden",
                "ssh_credential_ref": {"item_id": ssh_ref_item_id(provider, instance_id)},
            }
        )

    async def bug_report(request: web.Request) -> web.Response:
        body = await request.json()
        if not str(body.get("title", "")).strip():
            return web.json_response(
                {"error": "validation_failed", "message": "title is required"}, status=422
            )
        report_id = f"{BUG_REPORT_PREFIX}{next(report_ids):04d}"
        return web.json_response(
            {"id": report_id, "url": f"{base_url()}/bug-reports/{report_id}"}, status=201
        )

    async def ip_api_batch(request: web.Request) -> web.Response:
        queries = await request.json()
        return web.json_response(
            [
                {
                    "status": "success",
                    "query": item.get("query", ""),
                    "country": "Testland",
                    "countryCode": "ZZ",
                    "isp": "E2E Resolver",
                    "org": "E2E Resolver",
                    "as": GEO_ASN,
                    "reverse": "resolver.e2e.test",
                    "proxy": False,
                    "hosting": True,
                }
                for item in queries
            ]
        )

    instance = "/api/v1/me/instances/{provider}/{instance_id}"
    app.router.add_get(f"{instance}/ssh-ref", ssh_ref)
    app.router.add_post("/api/v1/bug-reports", bug_report)
    app.router.add_post(f"{IP_API_PREFIX}/batch", ip_api_batch)
