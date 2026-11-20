"""S3 policy guardrails, provider endpoints and metadata preservation."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import boto3
import pytest
from botocore.exceptions import ClientError

from servonaut.services.object_storage_service import ObjectStorageService
from servonaut.services.s3_bucket_policy import check_policy, parse_policy, public_scope, with_public_read


BUCKET = "release-assets"
BUCKET_ARN = f"arn:aws:s3:::{BUCKET}"


def statement(action="s3:GetObject", principal="*", **fields):
    return {
        "Effect": "Allow",
        "Action": action,
        "Principal": principal,
        "Resource": f"{BUCKET_ARN}/packages/*",
        **fields,
    }


def document(*rows):
    return {"Version": "2012-10-17", "Statement": list(rows)}


@pytest.mark.parametrize("row", [
    statement("S3:pUtObJeCt", {"AWS": ["*"]}),
    statement(["s3:GetObject", "s3:DeleteObjectVersion"]),
    statement("s3:RestoreObject"),
    statement("s3:AbortMultipartUpload"),
    statement("s3:PutObjectTagging", "anonymous"),
    statement("*", {"AWS": "111122223333"}),
    statement("s3:GetObject*"),
    statement("s3:GetObjec?", {"AWS": "*"}),
    {"Effect": "Allow", "Principal": "*", "NotAction": "s3:ListBucket", "Resource": "*"},
    {"Effect": "Allow", "NotPrincipal": {"AWS": "111122223333"},
     "Action": "s3:PutObject", "Resource": f"{BUCKET_ARN}/*"},
])
def test_risky_grants_require_explicit_opt_in(row):
    policy = document(row)
    with pytest.raises(ValueError, match="allow_public_write=true"):
        check_policy(policy, allow_public_write=False)
    check_policy(policy, allow_public_write=True)


def test_read_scope_includes_prefixes_and_distinguishes_denials():
    restricted = statement(Condition={"Bool": {"aws:SecureTransport": "true"}})
    deny = statement("s3:*", Effect="Deny")
    private_write = statement("s3:PutObject", principal={"AWS": "111122223333"})
    policy = document(restricted, deny, private_write)
    check_policy(policy, allow_public_write=False)

    allowed, denied = public_scope(policy)["public_scope"]
    assert allowed["actions"] == ["s3:GetObject"]
    assert allowed["prefixes"] == ["packages/"]
    assert allowed["conditional"]
    assert denied["effect"] == "Deny"


def test_bucket_listing_conditions_report_prefixes():
    policy = document(statement(
        "s3:ListBucket", Resource=BUCKET_ARN,
        Condition={"StringLike": {"s3:prefix": ["packages/*"]}},
    ))
    (scope,) = public_scope(policy)["public_scope"]
    assert scope["list_prefix_conditions"] == {"StringLike": ["packages/*"]}


@pytest.mark.parametrize("payload", [
    "{}", "[]", "null", '{"Statement":[]}', '{"Statement":null}',
    '{"Statement":{},"Statement":{}}',
    json.dumps(document(statement(["s3:GetObject", 1]))),
    json.dumps(document(statement(NotAction="s3:PutObject"))),
])
def test_malformed_policy_is_rejected(payload):
    with pytest.raises(ValueError):
        parse_policy(payload)


def test_disable_is_noop_for_unmanaged_single_statement():
    policy = {"Version": "2012-10-17", "Statement": statement()}
    assert with_public_read(policy, BUCKET_ARN, False) is policy


def test_toggle_recognizes_normalized_forms_and_preserves_unmanaged_grants():
    unmanaged = statement()
    policy = with_public_read(document(unmanaged), BUCKET_ARN, True)
    managed = policy["Statement"][1]
    managed.update(
        Principal={"AWS": ["*"]}, Action=["s3:GetObject"], Resource=[f"{BUCKET_ARN}/*"],
    )
    assert with_public_read(policy, BUCKET_ARN, True) is policy
    assert with_public_read(policy, BUCKET_ARN, False) == document(unmanaged)


@pytest.fixture
def aws_storage(monkeypatch, tmp_path):
    moto = pytest.importorskip("moto")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    with moto.mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET)
        yield ObjectStorageService(provider="aws", region="us-east-1"), client


@pytest.mark.asyncio
async def test_aws_policy_round_trip_preserves_unrelated_statement(aws_storage):
    service, client = aws_storage
    assert await service.get_bucket_policy(BUCKET) is None
    private = statement(principal={"AWS": "111122223333"})
    await service.set_bucket_policy(BUCKET, policy_json=json.dumps(document(private)))
    updated = await service.set_bucket_policy(BUCKET, public_read=True)
    assert updated["Statement"][0] == private
    (grant,) = public_scope(updated)["public_scope"]
    assert grant["actions"] == ["s3:GetObject"] and grant["prefixes"] == [""]
    assert await service.get_bucket_policy(BUCKET) == updated
    await service.set_bucket_policy(BUCKET, public_read=False)
    assert json.loads(client.get_bucket_policy(Bucket=BUCKET)["Policy"]) == document(private)


@pytest.mark.asyncio
async def test_write_rejection_preserves_aws_policy(aws_storage):
    service, _ = aws_storage
    initial = await service.set_bucket_policy(BUCKET, public_read=True)
    hostile = json.dumps(document(statement("s3:DeleteObject")))
    with pytest.raises(ValueError, match="allow_public_write=true"):
        await service.set_bucket_policy(BUCKET, policy_json=hostile)
    with pytest.raises(ValueError, match="booleans"):
        await service.set_bucket_policy(BUCKET, policy_json=hostile, allow_public_write="true")
    assert await service.get_bucket_policy(BUCKET) == initial
    explicit = await service.set_bucket_policy(BUCKET, policy_json=hostile, allow_public_write=True)
    assert await service.get_bucket_policy(BUCKET) == explicit


@pytest.mark.asyncio
async def test_aws_copy_replaces_headers_and_preserves_other_metadata(aws_storage, tmp_path):
    service, client = aws_storage
    source = tmp_path / "file.deb"
    source.write_bytes(b"test package")
    await service.upload_object(
        BUCKET, "release.deb", str(source),
        content_type="application/vnd.debian.binary-package", cache_control="public, max-age=60",
    )
    uploaded = client.head_object(Bucket=BUCKET, Key="release.deb")
    assert uploaded["ContentType"] == "application/vnd.debian.binary-package"
    assert uploaded["CacheControl"] == "public, max-age=60"

    client.put_object(
        Bucket=BUCKET, Key="source", Body=b"{}", Metadata={"marker": "fixture"},
        ContentType="text/plain", ContentLanguage="en", CacheControl="no-cache",
    )
    await service.copy_object(
        BUCKET, "source", BUCKET, "manifest.json", content_type="application/json",
    )
    copied = client.head_object(Bucket=BUCKET, Key="manifest.json")
    assert copied["ContentType"] == "application/json"
    assert copied["CacheControl"] == "no-cache"
    assert copied["ContentLanguage"] == "en"
    assert copied["Metadata"] == {"marker": "fixture"}


@pytest.mark.parametrize("provider,region,endpoint,hostname", [
    ("hetzner", "nbg1", "https://nbg1.your-objectstorage.com", "release-assets.nbg1.your-objectstorage.com"),
    ("ovh", "gra", "https://s3.gra.io.cloud.ovh.net", "release-assets.s3.gra.io.cloud.ovh.net"),
    ("ovh", "", "https://s3.de.io.cloud.ovh.net", "release-assets.s3.de.io.cloud.ovh.net"),
])
@pytest.mark.asyncio
async def test_compatible_provider_routes_policy_and_uses_virtual_url(provider, region, endpoint, hostname):
    service = ObjectStorageService(provider=provider, region=region, endpoint_url=endpoint)
    client = Mock()
    client.get_bucket_policy.side_effect = ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy",
    )
    service._client = client
    assert await service.get_bucket_policy(BUCKET) is None
    await service.set_bucket_policy(BUCKET, public_read=True)
    policy = json.loads(client.put_bucket_policy.call_args.kwargs["Policy"])
    assert policy["Statement"][0]["Resource"] == f"{BUCKET_ARN}/*"
    assert await service.public_object_url(BUCKET, "a/b +?#.json") == f"https://{hostname}/a/b%20%2B%3F%23.json"


@pytest.mark.asyncio
async def test_aws_dotted_bucket_uses_tls_compatible_path():
    service = ObjectStorageService(provider="aws", region="us-west-2")
    url = await service.public_object_url("release.assets", "file#2", "us-west-2")
    assert url == "https://s3.us-west-2.amazonaws.com/release.assets/file%232"


@pytest.mark.asyncio
async def test_copy_rejects_invalid_header_before_remote_io():
    service = ObjectStorageService(provider="aws", region="us-east-1")
    client = Mock()
    service._client = client
    with pytest.raises(ValueError, match="printable ASCII"):
        await service.copy_object(BUCKET, "source", BUCKET, "target", cache_control="no-cache\r\n")
    assert not client.mock_calls
