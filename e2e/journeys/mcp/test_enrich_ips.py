"""Journey: an MCP client enriches IP addresses.

``enrich_ips`` looks addresses up (network, owner, country, reverse DNS)
so an agent can decide how to block them. The lookup service's base URL can
be pointed elsewhere, for a proxy or a mirror, with
``SERVONAUT_IP_API_URL``; this journey points it at the local stand-in and
checks that the answer comes from there, and that a lookup that cannot be
made is reported in the result instead of failing the call.
"""

from __future__ import annotations

import pytest

from e2e.harness.fake_cloud.routes_misc import GEO_ASN, IP_API_PREFIX
from e2e.harness.known_bugs import ProductBug
from e2e.harness.seed import HomeSeeder

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

LOOKUP_HOST = "ip-api.com"
ADDRESSES = "9.9.9.9, 1.1.1.1"


class IpLookupIgnoresEndpointOverride(ProductBug):
    """enrich_ips calls the public lookup service despite the override."""


async def test_enrich_ips_uses_the_configured_lookup_service(mcp, journey, fake_cloud):
    sandbox = journey.new_sandbox()
    HomeSeeder(sandbox.home, api_url=fake_cloud.url).config()
    journey.env_overrides["SERVONAUT_IP_API_URL"] = f"{fake_cloud.url}{IP_API_PREFIX}"

    async with mcp(sandbox) as session:
        text = await session.call("enrich_ips", {"ips": ADDRESSES})

    # Consume the guard's records here, so the refused lookup is judged below
    # rather than failing the journey's teardown.
    escapes = journey.take_escapes()
    public_lookups = [e for e in escapes if LOOKUP_HOST in str(e.get("target", ""))]
    assert len(public_lookups) == len(escapes), escapes
    if public_lookups:
        # Even refused, the tool answers for every address with the error.
        assert "9.9.9.9" in text and "1.1.1.1" in text, text
        assert "geo lookup failed" in text, text
        raise IpLookupIgnoresEndpointOverride(
            f"{len(public_lookups)} attempt(s) to reach {LOOKUP_HOST}"
        )
    assert fake_cloud.requests(f"{IP_API_PREFIX}/batch", method="POST")
    assert GEO_ASN in text, text
