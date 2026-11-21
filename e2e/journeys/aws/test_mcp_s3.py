"""Journeys for sharing S3 objects through MCP.

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


async def test_public_bucket_policy_and_object_metadata(mcp, mcp_home, moto):
    from servonaut.config.schema import MCPConfig

    moto.seed_bucket(BUCKET)
    sandbox = mcp_home(mcp=MCPConfig(guard_level="dangerous"))
    source = sandbox.home / "Downloads" / "package.deb"
    source.parent.mkdir(exist_ok=True)
    source.write_bytes(CONTENT)
    bucket = {"provider": "aws", "bucket": BUCKET}
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": "*", "Action": "s3:PutObject",
            "Resource": f"arn:aws:s3:::{BUCKET}/packages/*",
        }],
    }
    async with mcp(sandbox) as session:
        initial = json.loads(await session.call("s3_get_bucket_policy", bucket))
        assert initial["policy"] is None

        rejected = await session.call("s3_set_bucket_policy", {**bucket, "policy_json": json.dumps(policy)})
        assert "allow_public_write=true" in rejected
        updated = json.loads(await session.call("s3_set_bucket_policy", {**bucket, "public_read": True}))
        (scope,) = updated["public_scope"]
        assert scope["actions"] == ["s3:GetObject"] and scope["prefixes"] == [""]

        uploaded = await session.call("s3_upload_object", {
            **bucket, "key": "packages/package.deb", "local_path": str(source),
            "cache_control": "public, max-age=300",
        })
        assert uploaded.startswith("Uploaded ")
        copied = await session.call("s3_copy_object", {
            "provider": "aws", "src_bucket": BUCKET, "src_key": "packages/package.deb",
            "dst_bucket": BUCKET, "dst_key": "packages/package.json",
        })
        assert copied.startswith("Copied ")
        url = json.loads(await session.call("s3_get_public_object_url", {
            **bucket, "key": "packages/package.json", "region": "us-east-1",
        }))
        assert url["url"] == f"https://{BUCKET}.s3.us-east-1.amazonaws.com/packages/package.json"

        for key, content_type in (
            ("packages/package.deb", "application/vnd.debian.binary-package"),
            ("packages/package.json", "application/json"),
        ):
            with urllib.request.urlopen(f"{moto.url}/{BUCKET}/{key}", timeout=10) as response:
                assert response.read() == CONTENT
                assert response.headers["Content-Type"] == content_type
                assert response.headers["Cache-Control"] == "public, max-age=300"

        disabled = json.loads(await session.call("s3_set_bucket_policy", {**bucket, "public_read": False}))
        assert not disabled["policy_present"]
        assert disabled["public_scope"] == []

    changes = [row for row in audit_rows(sandbox) if row["tool"] == "s3_set_bucket_policy"]
    assert [row["allowed"] for row in changes] == [False, True, True]
    assert changes[1]["public_scope"] == [scope]
    assert changes[2]["public_scope"] == []
    assert "policy_json" not in audit_text(sandbox)
