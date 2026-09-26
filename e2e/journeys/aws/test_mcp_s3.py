"""Journey: an MCP client shares an S3 object through a pre-signed URL.

``s3_generate_presigned_url`` returns a working link to the object. The link
is a bearer secret, so the audit row records the request and a placeholder,
but never the link or its signature.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

import pytest

from e2e.journeys.aws.support import audit_rows, audit_text

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

BUCKET = "e2e-assets"
KEY = "docs/readme.txt"
CONTENT = b"Seeded by the e2e suite.\n"


async def test_presigned_url_works_and_stays_out_of_the_audit(mcp, mcp_home, moto):
    from servonaut.config.schema import MCPConfig

    moto.seed_bucket(BUCKET, {KEY: CONTENT})
    sandbox = mcp_home(mcp=MCPConfig(guard_level="dangerous"))
    async with mcp(sandbox) as session:
        answer = await session.call(
            "s3_generate_presigned_url",
            {"provider": "aws", "bucket": BUCKET, "key": KEY, "expires_in": 300},
        )

    issued = json.loads(answer)
    assert (issued["bucket"], issued["key"], issued["expires_in"]) == (BUCKET, KEY, 300)
    url = issued["url"]
    assert url.startswith(f"{moto.url}/{BUCKET}/{KEY}?")
    # The link points at the object: fetching it returns the content.
    with urllib.request.urlopen(url, timeout=10) as response:
        assert response.read() == CONTENT

    (row,) = audit_rows(sandbox)
    assert (row["tool"], row["allowed"]) == ("s3_generate_presigned_url", True)
    assert row["args"] == {
        "provider": "aws", "bucket": BUCKET, "key": KEY, "expires_in": 300, "region": ""
    }
    # The trail keeps only the length of what it was given: the placeholder.
    assert row["result_length"] == len(f"presigned url issued ({len(url)} chars)")
    raw = audit_text(sandbox)
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    signature = (query.get("Signature") or query.get("X-Amz-Signature"))[0]
    assert url not in raw
    assert signature not in raw
    assert urllib.parse.quote(signature, safe="") not in raw
