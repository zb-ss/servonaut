"""Routes for smaller features: bug reports and IP lookups.

SSH key references and SSH verify reports are served by the secrets and
account routes; :func:`ssh_ref_item_id` gives a journey a stable Bitwarden
item id to store as an instance's reference.

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


# Built at run time: no UUID literal is committed.
_ITEM_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "ssh-ref.servonaut-e2e.test")
BUG_REPORT_PREFIX = "br-e2e-"
# RFC 5398 reserves AS64496-AS64511 for documentation.
GEO_ASN = "AS64500 E2E Resolver Network"
IP_API_PREFIX = "/ip-api"


def ssh_ref_item_id(provider: str, instance_id: str) -> str:
    """The Bitwarden item id FakeCloud reports for an instance's SSH ref."""
    return str(uuid.uuid5(_ITEM_NAMESPACE, f"{provider}/{instance_id}"))


def add_routes(app: web.Application, base_url: Callable[[], str]) -> None:
    """Register the routes on *app*; *base_url* gives FakeCloud's own URL."""
    report_ids = itertools.count(1)

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

    app.router.add_post("/api/v1/bug-reports", bug_report)
    app.router.add_post(f"{IP_API_PREFIX}/batch", ip_api_batch)
