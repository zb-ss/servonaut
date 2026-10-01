"""Tests for ObjectStorageService — all 10 S3 methods, validators, path-traversal."""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from servonaut.services.object_storage_service import ObjectStorageService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def aws_svc():
    return ObjectStorageService(provider="aws")


@pytest.fixture
def hetzner_svc():
    return ObjectStorageService(
        provider="hetzner",
        access_key="AKID",
        secret_key="SECRET",
        region="nbg1",
        endpoint_url="https://nbg1.your-objectstorage.com",
    )


@pytest.fixture
def ovh_svc():
    return ObjectStorageService(
        provider="ovh",
        access_key="AKID",
        secret_key="SECRET",
        region="gra",
        endpoint_url="https://s3.gra.io.cloud.ovh.net",
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

class TestConstruction:

    def test_invalid_provider_raises(self) -> None:
        with pytest.raises(ValueError, match="provider"):
            ObjectStorageService(provider="azure")

    def test_valid_providers_accepted(self) -> None:
        for p in ("aws", "hetzner", "ovh"):
            ObjectStorageService(provider=p)  # no raise

    # [HIGH-1] endpoint_url SSRF validation ---

    def test_http_endpoint_raises(self) -> None:
        """http:// endpoint must be rejected (credentials would go in cleartext)."""
        with pytest.raises(ValueError, match="https"):
            ObjectStorageService(
                provider="hetzner",
                endpoint_url="http://nbg1.your-objectstorage.com",
            )

    def test_data_url_endpoint_raises(self) -> None:
        """Non-http/https schemes must be rejected."""
        with pytest.raises(ValueError):
            ObjectStorageService(
                provider="aws",
                endpoint_url="data:text/plain,evil",
            )

    def test_endpoint_with_embedded_credentials_raises(self) -> None:
        """Credentials embedded in netloc must be rejected."""
        with pytest.raises(ValueError, match="@"):
            ObjectStorageService(
                provider="aws",
                endpoint_url="https://user:pass@evil.com",
            )

    def test_endpoint_with_path_raises(self) -> None:
        """A non-root path in endpoint_url must be rejected."""
        with pytest.raises(ValueError, match="path"):
            ObjectStorageService(
                provider="aws",
                endpoint_url="https://s3.amazonaws.com/some/path",
            )

    def test_endpoint_with_query_raises(self) -> None:
        """Query strings in endpoint_url must be rejected."""
        with pytest.raises(ValueError, match="query"):
            ObjectStorageService(
                provider="aws",
                endpoint_url="https://s3.amazonaws.com?redirect=evil.com",
            )

    def test_https_endpoint_accepted(self) -> None:
        """A clean https:// endpoint must be accepted."""
        ObjectStorageService(
            provider="hetzner",
            endpoint_url="https://nbg1.your-objectstorage.com",
        )  # no raise

    def test_https_endpoint_with_trailing_slash_accepted(self) -> None:
        """Trailing slash (root path) must be accepted."""
        ObjectStorageService(
            provider="hetzner",
            endpoint_url="https://nbg1.your-objectstorage.com/",
        )  # no raise

    # [S-LOW-1] Reserved / dangerous IP ranges must be rejected ---

    def test_link_local_metadata_ip_rejected(self) -> None:
        """Cloud metadata service (169.254.169.254) must be rejected (SSRF)."""
        with pytest.raises(ValueError, match="reserved IP range"):
            ObjectStorageService(
                provider="hetzner",
                endpoint_url="https://169.254.169.254",
            )

    def test_rfc1918_private_ip_rejected(self) -> None:
        """RFC1918 private address (10.0.0.1) must be rejected (SSRF)."""
        with pytest.raises(ValueError, match="reserved IP range"):
            ObjectStorageService(
                provider="hetzner",
                endpoint_url="https://10.0.0.1",
            )

    def test_loopback_ip_rejected(self) -> None:
        """Loopback address (127.0.0.1) must be rejected (SSRF)."""
        with pytest.raises(ValueError, match="reserved IP range"):
            ObjectStorageService(
                provider="hetzner",
                endpoint_url="https://127.0.0.1",
            )

    @pytest.mark.parametrize("encoded", [
        "https://2130706433",   # decimal-encoded 127.0.0.1
        "https://0x7f000001",   # hex-encoded 127.0.0.1
        "https://0177.0.0.1",   # octal-encoded 127.0.0.1
        "https://127.1",        # short-form 127.0.0.1
        "https://0xa000001",    # hex-encoded 10.0.0.1 (private)
    ])
    def test_alternate_encoding_reserved_ip_rejected(self, encoded: str) -> None:
        """Decimal/hex/octal/short-form IP encodings of reserved ranges must
        be rejected — ip_address() does not parse them but the OS resolver
        does, so they would otherwise bypass the SSRF guard."""
        with pytest.raises(ValueError, match="reserved IPv4 range"):
            ObjectStorageService(provider="hetzner", endpoint_url=encoded)

    # [HIGH-1] region format validation ---

    def test_invalid_region_raises(self) -> None:
        """Regions containing characters outside [a-z0-9-] must be rejected."""
        with pytest.raises(ValueError, match="region"):
            ObjectStorageService(
                provider="hetzner",
                endpoint_url="https://nbg1.your-objectstorage.com",
                region="../../etc/passwd",
            )

    def test_region_with_uppercase_raises(self) -> None:
        with pytest.raises(ValueError, match="region"):
            ObjectStorageService(
                provider="aws",
                region="US-East-1",
            )

    def test_valid_region_accepted(self) -> None:
        ObjectStorageService(provider="aws", region="us-east-1")  # no raise
        ObjectStorageService(provider="aws", region="eu-central-1")  # no raise


# ---------------------------------------------------------------------------
# _get_client — credential and endpoint handling
# ---------------------------------------------------------------------------

class TestGetClient:

    def test_endpoint_url_passed_for_hetzner(self, hetzner_svc) -> None:
        with patch("boto3.client") as mock_client:
            hetzner_svc._get_client()
        call_kwargs = mock_client.call_args[1]
        assert call_kwargs.get("endpoint_url") == "https://nbg1.your-objectstorage.com"

    def test_endpoint_url_passed_for_ovh(self, ovh_svc) -> None:
        with patch("boto3.client") as mock_client:
            ovh_svc._get_client()
        call_kwargs = mock_client.call_args[1]
        assert call_kwargs.get("endpoint_url") == "https://s3.gra.io.cloud.ovh.net"

    def test_no_endpoint_for_aws_default(self, aws_svc) -> None:
        with patch("boto3.client") as mock_client:
            aws_svc._get_client()
        call_kwargs = mock_client.call_args[1]
        assert "endpoint_url" not in call_kwargs

    def test_credentials_passed_when_both_set(self) -> None:
        svc = ObjectStorageService(
            provider="aws",
            access_key="AK123",
            secret_key="SK456",
        )
        with patch("boto3.client") as mock_client:
            svc._get_client()
        call_kwargs = mock_client.call_args[1]
        assert call_kwargs.get("aws_access_key_id") == "AK123"
        assert call_kwargs.get("aws_secret_access_key") == "SK456"

    def test_credentials_omitted_when_empty(self, aws_svc) -> None:
        with patch("boto3.client") as mock_client:
            aws_svc._get_client()
        call_kwargs = mock_client.call_args[1]
        assert "aws_access_key_id" not in call_kwargs

    def test_client_cached_after_first_call(self, aws_svc) -> None:
        with patch("boto3.client") as mock_client:
            c1 = aws_svc._get_client()
            c2 = aws_svc._get_client()
        assert mock_client.call_count == 1


# ---------------------------------------------------------------------------
# Bucket validators
# ---------------------------------------------------------------------------

class TestBucketValidator:

    def test_valid_bucket(self) -> None:
        ObjectStorageService._validate_bucket("my-bucket-123")

    def test_bucket_with_dots(self) -> None:
        ObjectStorageService._validate_bucket("my.bucket.name")

    def test_bucket_too_short(self) -> None:
        with pytest.raises(ValueError):
            ObjectStorageService._validate_bucket("ab")

    def test_bucket_with_consecutive_dots(self) -> None:
        with pytest.raises(ValueError, match="consecutive dots"):
            ObjectStorageService._validate_bucket("my..bucket")

    def test_bucket_looks_like_ip(self) -> None:
        with pytest.raises(ValueError, match="IP"):
            ObjectStorageService._validate_bucket("192.168.1.1")

    def test_bucket_uppercase_rejected(self) -> None:
        with pytest.raises(ValueError):
            ObjectStorageService._validate_bucket("MyBucket")


# ---------------------------------------------------------------------------
# Object key validators
# ---------------------------------------------------------------------------

class TestObjectKeyValidator:

    def test_valid_key(self) -> None:
        ObjectStorageService._validate_object_key("folder/file.txt")

    def test_empty_key_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            ObjectStorageService._validate_object_key("")

    def test_null_byte_rejected(self) -> None:
        with pytest.raises(ValueError, match="null"):
            ObjectStorageService._validate_object_key("bad\x00key")

    def test_leading_slash_rejected(self) -> None:
        with pytest.raises(ValueError, match="not start with"):
            ObjectStorageService._validate_object_key("/leading/slash")

    def test_key_too_long(self) -> None:
        with pytest.raises(ValueError, match="1024 bytes"):
            ObjectStorageService._validate_object_key("a" * 1025)


# ---------------------------------------------------------------------------
# Path-traversal validation
# ---------------------------------------------------------------------------

class TestLocalPathValidator:

    def test_path_traversal_rejected(self, tmp_path) -> None:
        """../../etc/passwd-style escapes must be rejected."""
        with pytest.raises(ValueError, match="outside the allowed roots|does not exist"):
            ObjectStorageService._validate_local_path("/etc/passwd", must_exist=False)

    def test_home_path_accepted_for_download(self) -> None:
        home = Path.home()
        # Only validate that the method accepts a home-based path without raising
        # (the parent dir must exist)
        ObjectStorageService._validate_local_path(
            str(home / "test_download_target.txt"), must_exist=False
        )

    def test_nonexistent_upload_path_rejected(self, tmp_path) -> None:
        # Use a path under home so it passes the root-traversal check but fails
        # the existence check.
        home = Path.home()
        nonexistent = home / "_servonaut_test_nonexistent_upload_xyz.txt"
        with pytest.raises(ValueError):
            ObjectStorageService._validate_local_path(str(nonexistent), must_exist=True)

    def test_existing_file_accepted_for_upload(self, tmp_path) -> None:
        f = tmp_path / "upload.txt"
        f.write_text("data")
        # Must not raise; path is under cwd or home
        # (tmp_path is usually /tmp which may or may not be under home — patch Path.home)
        with patch.object(Path, "home", return_value=tmp_path.parent):
            result = ObjectStorageService._validate_local_path(str(f), must_exist=True)
        assert result.name == "upload.txt"


# ---------------------------------------------------------------------------
# list_buckets
# ---------------------------------------------------------------------------

class TestListBuckets:

    def test_returns_list_of_dicts(self, aws_svc) -> None:
        from datetime import datetime, timezone
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = {
            "Buckets": [
                {"Name": "my-bucket", "CreationDate": datetime(2024, 1, 1, tzinfo=timezone.utc)},
            ]
        }
        aws_svc._client = mock_client
        result = asyncio.run(aws_svc.list_buckets())
        assert len(result) == 1
        assert result[0]["name"] == "my-bucket"
        assert "2024" in result[0]["creation_date"]

    def test_returns_empty_when_no_buckets(self, aws_svc) -> None:
        mock_client = MagicMock()
        mock_client.list_buckets.return_value = {"Buckets": []}
        aws_svc._client = mock_client
        result = asyncio.run(aws_svc.list_buckets())
        assert result == []


# ---------------------------------------------------------------------------
# create_bucket
# ---------------------------------------------------------------------------

class TestCreateBucket:

    def test_calls_create_bucket(self, aws_svc) -> None:
        mock_client = MagicMock()
        aws_svc._client = mock_client
        asyncio.run(aws_svc.create_bucket("my-bucket"))
        mock_client.create_bucket.assert_called_once()

    def test_rejects_invalid_bucket_name(self, aws_svc) -> None:
        with pytest.raises(ValueError):
            asyncio.run(aws_svc.create_bucket("AB"))

    # --- region override ---

    def test_region_override_builds_client_for_that_region(self) -> None:
        """An explicit region must reach boto3 as the client's region_name.

        CreateBucket has to be sent to the target region's endpoint, so the
        cached default client cannot be reused for an override.
        """
        svc = ObjectStorageService(provider="aws", region="us-east-1")
        svc._client = MagicMock()  # cached default — must NOT be used
        override_client = MagicMock()
        with patch(
            "servonaut.services.object_storage_service.boto3.client",
            return_value=override_client,
        ) as mock_boto:
            asyncio.run(svc.create_bucket("my-bucket", "eu-central-1"))

        assert mock_boto.call_args.kwargs["region_name"] == "eu-central-1"
        override_client.create_bucket.assert_called_once_with(
            Bucket="my-bucket",
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        svc._client.create_bucket.assert_not_called()

    def test_region_override_is_not_cached(self) -> None:
        """A per-call override must not change the region of later calls."""
        svc = ObjectStorageService(provider="aws", region="us-east-1")
        default_client = MagicMock()
        svc._client = default_client
        with patch(
            "servonaut.services.object_storage_service.boto3.client",
            return_value=MagicMock(),
        ):
            asyncio.run(svc.create_bucket("elsewhere", "eu-central-1"))

        assert svc._client is default_client
        asyncio.run(svc.create_bucket("back-home"))
        default_client.create_bucket.assert_called_once_with(Bucket="back-home")

    def test_us_east_1_override_omits_location_constraint(self) -> None:
        """us-east-1 must be sent WITHOUT CreateBucketConfiguration."""
        svc = ObjectStorageService(provider="aws", region="eu-central-1")
        override_client = MagicMock()
        with patch(
            "servonaut.services.object_storage_service.boto3.client",
            return_value=override_client,
        ):
            asyncio.run(svc.create_bucket("my-bucket", "us-east-1"))
        override_client.create_bucket.assert_called_once_with(Bucket="my-bucket")

    def test_configured_region_used_when_no_override(self) -> None:
        svc = ObjectStorageService(provider="aws", region="eu-west-2")
        mock_client = MagicMock()
        svc._client = mock_client
        asyncio.run(svc.create_bucket("my-bucket"))
        mock_client.create_bucket.assert_called_once_with(
            Bucket="my-bucket",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )

    def test_falls_back_to_boto_resolved_region(self, aws_svc) -> None:
        """No configured region → use the region boto3 resolved for the client.

        Without this the call would go out with no LocationConstraint against
        a non-us-east-1 endpoint and fail with IllegalLocationConstraintException.
        """
        mock_client = MagicMock()
        mock_client.meta.region_name = "ap-southeast-2"
        aws_svc._client = mock_client
        asyncio.run(aws_svc.create_bucket("my-bucket"))
        mock_client.create_bucket.assert_called_once_with(
            Bucket="my-bucket",
            CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
        )

    def test_rejects_malformed_region(self, aws_svc) -> None:
        aws_svc._client = MagicMock()
        with pytest.raises(ValueError, match="region"):
            asyncio.run(aws_svc.create_bucket("my-bucket", "EU_Central 1"))

    def test_endpoint_pinned_provider_rejects_mismatched_region(
        self, hetzner_svc,
    ) -> None:
        """Hetzner/OVH regions come from the endpoint URL — refuse to pretend."""
        hetzner_svc._client = MagicMock()
        with pytest.raises(ValueError, match="pinned to endpoint"):
            asyncio.run(hetzner_svc.create_bucket("my-bucket", "fsn1"))

    def test_endpoint_pinned_provider_accepts_matching_region(
        self, hetzner_svc,
    ) -> None:
        mock_client = MagicMock()
        hetzner_svc._client = mock_client
        asyncio.run(hetzner_svc.create_bucket("my-bucket", "nbg1"))
        mock_client.create_bucket.assert_called_once_with(Bucket="my-bucket")

    def test_created_bucket_region_is_cached(self) -> None:
        """A bucket we just made needs neither discovery nor a redirect."""
        svc = ObjectStorageService(provider="aws", region="us-east-1")
        with patch(
            "servonaut.services.object_storage_service.boto3.client",
            return_value=MagicMock(),
        ):
            asyncio.run(svc.create_bucket("fresh-bucket", "eu-west-3"))
        assert svc._bucket_regions["fresh-bucket"] == "eu-west-3"


# ---------------------------------------------------------------------------
# Cross-region resolution shared by the bucket-scoped operations
# ---------------------------------------------------------------------------

class TestBucketRegionResolution:

    def test_explicit_region_wins(self, aws_svc) -> None:
        aws_svc._client = MagicMock()
        assert aws_svc._region_for_bucket("b", "eu-west-1") == "eu-west-1"

    def test_endpoint_pinned_provider_ignores_discovery(self, hetzner_svc) -> None:
        """No cross-region redirect exists for a fixed endpoint — never probe."""
        client = MagicMock()
        hetzner_svc._client = client
        assert hetzner_svc._region_for_bucket("b", discover=True) == "nbg1"
        client.head_bucket.assert_not_called()

    def test_no_discovery_by_default(self) -> None:
        """Ordinary ops must not pay for a HeadBucket — botocore redirects."""
        svc = ObjectStorageService(provider="aws", region="us-east-1")
        client = MagicMock()
        svc._client = client
        assert svc._region_for_bucket("b") == "us-east-1"
        client.head_bucket.assert_not_called()

    def test_discovery_reads_bucket_region_header(self, aws_svc) -> None:
        client = MagicMock()
        client.head_bucket.return_value = {
            "ResponseMetadata": {"HTTPHeaders": {"x-amz-bucket-region": "eu-north-1"}}
        }
        aws_svc._client = client
        assert aws_svc._region_for_bucket("b", discover=True) == "eu-north-1"

    def test_discovery_reads_header_from_error_response(self, aws_svc) -> None:
        """S3 returns the region on 301/403 too — no read access needed."""
        exc = Exception("AccessDenied")
        exc.response = {
            "ResponseMetadata": {"HTTPHeaders": {"x-amz-bucket-region": "sa-east-1"}}
        }
        client = MagicMock()
        client.head_bucket.side_effect = exc
        aws_svc._client = client
        assert aws_svc._region_for_bucket("b", discover=True) == "sa-east-1"

    def test_discovery_result_is_cached(self, aws_svc) -> None:
        client = MagicMock()
        client.head_bucket.return_value = {
            "ResponseMetadata": {"HTTPHeaders": {"x-amz-bucket-region": "eu-north-1"}}
        }
        aws_svc._client = client
        aws_svc._region_for_bucket("b", discover=True)
        aws_svc._region_for_bucket("b", discover=True)
        client.head_bucket.assert_called_once()

    def test_discovery_failure_degrades_to_configured_region(self) -> None:
        """A failed lookup must not break the operation it was serving."""
        svc = ObjectStorageService(provider="aws", region="us-west-1")
        client = MagicMock()
        client.head_bucket.side_effect = Exception("boom")
        svc._client = client
        assert svc._region_for_bucket("b", discover=True) == "us-west-1"
        assert "b" not in svc._bucket_regions

    def test_malformed_header_region_is_rejected(self, aws_svc) -> None:
        """The header is off-the-wire input feeding a client config."""
        client = MagicMock()
        client.head_bucket.return_value = {
            "ResponseMetadata": {
                "HTTPHeaders": {"x-amz-bucket-region": "../../evil region"}
            }
        }
        aws_svc._client = client
        assert aws_svc._region_for_bucket("b", discover=True) == ""

    @pytest.mark.parametrize("op,args", [
        ("list_objects", ("my-bucket",)),
        ("delete_object", ("my-bucket", "k")),
        ("delete_bucket", ("my-bucket",)),
    ])
    def test_ops_honour_region_override(self, op, args) -> None:
        svc = ObjectStorageService(provider="aws", region="us-east-1")
        svc._client = MagicMock()
        with patch(
            "servonaut.services.object_storage_service.boto3.client",
            return_value=MagicMock(),
        ) as boto:
            asyncio.run(getattr(svc, op)(*args, region="ap-northeast-1"))
        assert boto.call_args.kwargs["region_name"] == "ap-northeast-1"

    def test_ops_reject_malformed_region(self, aws_svc) -> None:
        aws_svc._client = MagicMock()
        with pytest.raises(ValueError, match="region"):
            asyncio.run(aws_svc.list_objects("my-bucket", region="Bad Region"))

    def test_copy_uses_destination_region(self) -> None:
        """A cross-region copy is driven from the destination side."""
        svc = ObjectStorageService(provider="aws", region="us-east-1")
        svc._client = MagicMock()
        dst_client = MagicMock()
        with patch(
            "servonaut.services.object_storage_service.boto3.client",
            return_value=dst_client,
        ) as boto:
            asyncio.run(svc.copy_object("src-b", "k", "dst-b", "k2", "eu-west-1"))
        assert boto.call_args.kwargs["region_name"] == "eu-west-1"
        dst_client.copy_object.assert_called_once_with(
            CopySource={"Bucket": "src-b", "Key": "k"},
            Bucket="dst-b",
            Key="k2",
        )

    def test_move_routes_each_leg_to_its_own_region(self) -> None:
        """Copy goes to the destination region, delete to the source one."""
        svc = ObjectStorageService(provider="aws", region="us-east-1")
        svc._client = MagicMock()
        with patch(
            "servonaut.services.object_storage_service.boto3.client",
            return_value=MagicMock(),
        ) as boto:
            asyncio.run(svc.move_object(
                "src-b", "k", "dst-b", "k2", "eu-west-1", "ap-south-1",
            ))
        used = [c.kwargs["region_name"] for c in boto.call_args_list]
        assert used == ["eu-west-1", "ap-south-1"]

    def test_delete_bucket_evicts_cached_region(self) -> None:
        svc = ObjectStorageService(provider="aws", region="us-east-1")
        svc._bucket_regions["gone"] = "us-east-1"
        svc._client = MagicMock()
        asyncio.run(svc.delete_bucket("gone"))
        assert "gone" not in svc._bucket_regions


# ---------------------------------------------------------------------------
# Presigned URLs — the one op that cannot be redirected after the fact
# ---------------------------------------------------------------------------

class TestPresignedUrlRegion:

    def test_discovers_bucket_region_before_signing(self, aws_svc) -> None:
        """SigV4 binds the region into the signature; getting it wrong yields
        a URL that fails only when somebody opens it."""
        default_client = MagicMock()
        default_client.head_bucket.return_value = {
            "ResponseMetadata": {"HTTPHeaders": {"x-amz-bucket-region": "eu-central-1"}}
        }
        aws_svc._client = default_client
        signer = MagicMock()
        signer.generate_presigned_url.return_value = "https://signed"
        with patch(
            "servonaut.services.object_storage_service.boto3.client",
            return_value=signer,
        ) as boto:
            url = asyncio.run(aws_svc.generate_presigned_url("my-bucket", "k"))
        assert url == "https://signed"
        assert boto.call_args.kwargs["region_name"] == "eu-central-1"

    def test_explicit_region_skips_discovery(self, aws_svc) -> None:
        client = MagicMock()
        aws_svc._client = client
        with patch(
            "servonaut.services.object_storage_service.boto3.client",
            return_value=MagicMock(),
        ) as boto:
            asyncio.run(aws_svc.generate_presigned_url("my-bucket", "k", 60, "us-west-2"))
        client.head_bucket.assert_not_called()
        assert boto.call_args.kwargs["region_name"] == "us-west-2"

    def test_signs_with_configured_region_when_discovery_fails(self) -> None:
        svc = ObjectStorageService(provider="aws", region="us-east-1")
        client = MagicMock()
        client.head_bucket.side_effect = Exception("no permission")
        client.generate_presigned_url.return_value = "https://signed"
        svc._client = client
        url = asyncio.run(svc.generate_presigned_url("my-bucket", "k"))
        assert url == "https://signed"


# ---------------------------------------------------------------------------
# delete_bucket
# ---------------------------------------------------------------------------

class TestDeleteBucket:

    def test_calls_delete_bucket(self, aws_svc) -> None:
        mock_client = MagicMock()
        aws_svc._client = mock_client
        asyncio.run(aws_svc.delete_bucket("my-bucket"))
        mock_client.delete_bucket.assert_called_once_with(Bucket="my-bucket")


# ---------------------------------------------------------------------------
# list_objects — splits CommonPrefixes / Contents
# ---------------------------------------------------------------------------

class TestListObjects:

    def test_splits_folders_and_objects(self, aws_svc) -> None:
        from datetime import datetime, timezone

        mock_client = MagicMock()
        mock_client.list_objects_v2.return_value = {
            "CommonPrefixes": [{"Prefix": "images/"}],
            "Contents": [
                {
                    "Key": "images/photo.jpg",
                    "Size": 4096,
                    "LastModified": datetime(2024, 3, 1, tzinfo=timezone.utc),
                }
            ],
            "IsTruncated": False,
        }
        aws_svc._client = mock_client
        result = asyncio.run(aws_svc.list_objects("my-bucket"))
        assert result["folders"] == ["images/"]
        assert len(result["objects"]) == 1
        assert result["objects"][0]["key"] == "images/photo.jpg"
        assert result["objects"][0]["size"] == 4096
        assert result["is_truncated"] is False

    def test_truncated_flag_passed_through(self, aws_svc) -> None:
        mock_client = MagicMock()
        mock_client.list_objects_v2.return_value = {
            "CommonPrefixes": [],
            "Contents": [],
            "IsTruncated": True,
        }
        aws_svc._client = mock_client
        result = asyncio.run(aws_svc.list_objects("my-bucket"))
        assert result["is_truncated"] is True


# ---------------------------------------------------------------------------
# delete_object
# ---------------------------------------------------------------------------

class TestDeleteObject:

    def test_calls_delete_object(self, aws_svc) -> None:
        mock_client = MagicMock()
        aws_svc._client = mock_client
        asyncio.run(aws_svc.delete_object("my-bucket", "folder/file.txt"))
        mock_client.delete_object.assert_called_once_with(
            Bucket="my-bucket", Key="folder/file.txt"
        )


# ---------------------------------------------------------------------------
# copy_object
# ---------------------------------------------------------------------------

class TestCopyObject:

    def test_calls_copy_object(self, aws_svc) -> None:
        mock_client = MagicMock()
        aws_svc._client = mock_client
        asyncio.run(aws_svc.copy_object("src-bucket", "a/b.txt", "dst-bucket", "c/d.txt"))
        mock_client.copy_object.assert_called_once_with(
            CopySource={"Bucket": "src-bucket", "Key": "a/b.txt"},
            Bucket="dst-bucket",
            Key="c/d.txt",
        )


# ---------------------------------------------------------------------------
# move_object = copy + delete
# ---------------------------------------------------------------------------

class TestMoveObject:

    def test_move_is_copy_then_delete(self, aws_svc) -> None:
        mock_client = MagicMock()
        aws_svc._client = mock_client
        asyncio.run(aws_svc.move_object("src-bucket", "old.txt", "dst-bucket", "new.txt"))
        mock_client.copy_object.assert_called_once()
        mock_client.delete_object.assert_called_once_with(Bucket="src-bucket", Key="old.txt")


# ---------------------------------------------------------------------------
# generate_presigned_url
# ---------------------------------------------------------------------------

class TestGeneratePresignedUrl:

    def test_returns_url(self, aws_svc) -> None:
        mock_client = MagicMock()
        mock_client.generate_presigned_url.return_value = "https://presigned.example.com/url"
        aws_svc._client = mock_client
        result = asyncio.run(aws_svc.generate_presigned_url("my-bucket", "file.txt"))
        assert result == "https://presigned.example.com/url"
        mock_client.generate_presigned_url.assert_called_once_with(
            "get_object",
            Params={"Bucket": "my-bucket", "Key": "file.txt"},
            ExpiresIn=3600,
        )

    def test_validates_expires_in(self, aws_svc) -> None:
        with pytest.raises(ValueError, match="expires_in"):
            asyncio.run(aws_svc.generate_presigned_url("my-bucket", "file.txt", expires_in=0))

    def test_validates_expires_in_max(self, aws_svc) -> None:
        with pytest.raises(ValueError, match="expires_in"):
            asyncio.run(aws_svc.generate_presigned_url("my-bucket", "file.txt", expires_in=700000))


# ---------------------------------------------------------------------------
# Region search (OVH: ListBuckets answers for the endpoint's region only)
# ---------------------------------------------------------------------------

_OVH_TEMPLATE = "https://s3.{region}.io.cloud.ovh.net"


def _searching_svc(region="gra", search_regions=("gra", "uk", "de")):
    return ObjectStorageService(
        provider="ovh",
        access_key="AKID",
        secret_key="SECRET",
        region=region,
        endpoint_url=_OVH_TEMPLATE.format(region=region),
        endpoint_template=_OVH_TEMPLATE,
        search_regions=search_regions,
    )


def _client_error(code):
    from botocore.exceptions import ClientError
    return ClientError({"Error": {"Code": code, "Message": code}}, "ListBuckets")


class _RegionalClients:
    """Stands in for boto3.client: one mock client per region, made on demand.

    *buckets* maps region → bucket names (or an exception to raise).
    """

    def __init__(self, buckets):
        self._buckets = buckets
        self.clients = {}
        self.made = []

    def __call__(self, service, **kwargs):
        region = kwargs["region_name"]
        self.made.append((region, kwargs.get("endpoint_url")))
        client = MagicMock(name=f"s3-{region}")
        answer = self._buckets.get(region, [])
        if isinstance(answer, Exception):
            client.list_buckets.side_effect = answer
        else:
            client.list_buckets.return_value = {"Buckets": [{"Name": n} for n in answer]}
        client.list_objects_v2.return_value = {}
        self.clients[region] = client
        return client


class TestRegionSearchConstruction:

    def test_search_regions_need_a_template(self) -> None:
        with pytest.raises(ValueError, match="endpoint_template"):
            ObjectStorageService(
                provider="ovh", region="gra",
                endpoint_url="https://s3.gra.io.cloud.ovh.net",
                search_regions=("gra", "uk"),
            )

    def test_template_needs_a_region_placeholder(self) -> None:
        with pytest.raises(ValueError, match="placeholder"):
            ObjectStorageService(
                provider="ovh", region="gra",
                endpoint_template="https://s3.io.cloud.ovh.net",
                search_regions=("gra",),
            )

    def test_template_must_derive_https_endpoints(self) -> None:
        with pytest.raises(ValueError, match="https"):
            ObjectStorageService(
                provider="ovh", region="gra",
                endpoint_template="http://s3.{region}.io.cloud.ovh.net",
                search_regions=("gra",),
            )

    def test_malformed_search_region_rejected(self) -> None:
        """Search regions are interpolated into endpoint URLs — same check as the region."""
        with pytest.raises(ValueError, match="region"):
            _searching_svc(search_regions=("gra", "evil.example.com/x"))

    def test_configured_region_searched_first(self) -> None:
        svc = _searching_svc(region="uk", search_regions=("gra", "uk", "de"))
        assert svc._search_regions == ("uk", "gra", "de")


class TestRegionSearch:

    def test_lists_the_buckets_of_every_region(self) -> None:
        clients = _RegionalClients({"uk": ["media-assets"], "de": ["backups"]})
        svc = _searching_svc()
        with patch("servonaut.services.object_storage_service.boto3.client", clients):
            listing = asyncio.run(svc.search_buckets())

        assert [(b["name"], b["region"]) for b in listing.buckets] == [
            ("media-assets", "uk"), ("backups", "de"),
        ]
        assert listing.searched_regions == ("gra", "uk", "de")
        assert listing.failed_regions == {}
        # Each region is asked at its own endpoint.
        assert dict(clients.made) == {
            "gra": "https://s3.gra.io.cloud.ovh.net",
            "uk": "https://s3.uk.io.cloud.ovh.net",
            "de": "https://s3.de.io.cloud.ovh.net",
        }

    def test_list_buckets_returns_the_search_results(self) -> None:
        clients = _RegionalClients({"uk": ["media-assets"]})
        svc = _searching_svc()
        with patch("servonaut.services.object_storage_service.boto3.client", clients):
            buckets = asyncio.run(svc.list_buckets())
        assert buckets == [{"name": "media-assets", "creation_date": "", "region": "uk"}]

    def test_a_region_that_does_not_answer_is_reported_not_fatal(self) -> None:
        clients = _RegionalClients({
            "uk": ["media-assets"],
            "de": _client_error("SignatureDoesNotMatch"),
        })
        svc = _searching_svc()
        with patch("servonaut.services.object_storage_service.boto3.client", clients):
            listing = asyncio.run(svc.search_buckets())

        assert [b["name"] for b in listing.buckets] == ["media-assets"]
        assert listing.failed_regions == {"de": "SignatureDoesNotMatch"}

    def test_unreachable_region_reported_by_error_type(self) -> None:
        from botocore.exceptions import EndpointConnectionError
        clients = _RegionalClients({
            "de": EndpointConnectionError(endpoint_url="https://s3.de.io.cloud.ovh.net"),
        })
        svc = _searching_svc()
        with patch("servonaut.services.object_storage_service.boto3.client", clients):
            listing = asyncio.run(svc.search_buckets())
        assert listing.failed_regions == {"de": "EndpointConnectionError"}

    def test_no_region_answering_raises_the_configured_regions_error(self) -> None:
        clients = _RegionalClients({
            "gra": _client_error("InvalidAccessKeyId"),
            "uk": _client_error("AccessDenied"),
            "de": _client_error("AccessDenied"),
        })
        svc = _searching_svc()
        with patch("servonaut.services.object_storage_service.boto3.client", clients):
            with pytest.raises(Exception, match="InvalidAccessKeyId"):
                asyncio.run(svc.search_buckets())

    def test_same_name_in_two_regions_lists_both(self) -> None:
        """Rows stay apart; an unqualified request goes to the first region listed."""
        clients = _RegionalClients({"gra": ["shared"], "uk": ["shared"]})
        svc = _searching_svc()
        with patch("servonaut.services.object_storage_service.boto3.client", clients):
            listing = asyncio.run(svc.search_buckets())
        assert [(b["name"], b["region"]) for b in listing.buckets] == [
            ("shared", "gra"), ("shared", "uk"),
        ]
        assert svc._bucket_regions["shared"] == "gra"

    def test_regional_clients_are_made_once(self) -> None:
        clients = _RegionalClients({"uk": ["media-assets"]})
        svc = _searching_svc()
        with patch("servonaut.services.object_storage_service.boto3.client", clients):
            asyncio.run(svc.search_buckets())
            asyncio.run(svc.search_buckets())
        assert sorted(region for region, _ in clients.made) == ["de", "gra", "uk"]


class TestRegionSearchRouting:

    def test_listed_bucket_is_reached_in_its_region(self) -> None:
        clients = _RegionalClients({"uk": ["media-assets"]})
        svc = _searching_svc()
        with patch("servonaut.services.object_storage_service.boto3.client", clients):
            asyncio.run(svc.search_buckets())
            asyncio.run(svc.list_objects("media-assets"))
        clients.clients["uk"].list_objects_v2.assert_called_once()
        clients.clients["gra"].list_objects_v2.assert_not_called()

    def test_unseen_bucket_is_looked_for_before_the_request(self) -> None:
        """No redirect exists between regional endpoints — search first."""
        clients = _RegionalClients({"uk": ["media-assets"]})
        svc = _searching_svc()
        with patch("servonaut.services.object_storage_service.boto3.client", clients):
            asyncio.run(svc.delete_object("media-assets", "a.txt"))
        clients.clients["uk"].delete_object.assert_called_once_with(
            Bucket="media-assets", Key="a.txt",
        )

    def test_bucket_found_nowhere_goes_to_the_configured_region(self) -> None:
        clients = _RegionalClients({})
        svc = _searching_svc()
        with patch("servonaut.services.object_storage_service.boto3.client", clients):
            asyncio.run(svc.delete_object("missing", "a.txt"))
        clients.clients["gra"].delete_object.assert_called_once()

    def test_explicit_region_skips_the_search(self) -> None:
        clients = _RegionalClients({"uk": ["media-assets"]})
        svc = _searching_svc()
        with patch("servonaut.services.object_storage_service.boto3.client", clients):
            asyncio.run(svc.list_objects("media-assets", region="uk"))
        assert [region for region, _ in clients.made] == ["uk"]
        clients.clients["uk"].list_buckets.assert_not_called()

    def test_region_override_is_honoured_not_rejected(self) -> None:
        """Unlike an endpoint set by hand, a template reaches every region."""
        clients = _RegionalClients({})
        svc = _searching_svc()
        with patch("servonaut.services.object_storage_service.boto3.client", clients):
            asyncio.run(svc.create_bucket("new-bucket", "waw"))
        waw = clients.clients["waw"]
        waw.create_bucket.assert_called_once_with(Bucket="new-bucket")
        assert ("waw", "https://s3.waw.io.cloud.ovh.net") in clients.made
        assert svc._bucket_regions["new-bucket"] == "waw"

    def test_presigned_url_is_signed_in_the_buckets_region(self) -> None:
        """SigV4 binds the region: a URL signed elsewhere would never open."""
        clients = _RegionalClients({"uk": ["media-assets"]})
        svc = _searching_svc()
        with patch("servonaut.services.object_storage_service.boto3.client", clients):
            asyncio.run(svc.generate_presigned_url("media-assets", "a.txt"))
        clients.clients["uk"].generate_presigned_url.assert_called_once()

    def test_move_deletes_from_the_source_region(self) -> None:
        clients = _RegionalClients({"uk": ["src-bucket"], "de": ["dst-bucket"]})
        svc = _searching_svc()
        with patch("servonaut.services.object_storage_service.boto3.client", clients):
            asyncio.run(svc.search_buckets())
            asyncio.run(svc.move_object("src-bucket", "a.txt", "dst-bucket", "a.txt"))
        clients.clients["de"].copy_object.assert_called_once()
        clients.clients["uk"].delete_object.assert_called_once_with(
            Bucket="src-bucket", Key="a.txt",
        )


class TestSingleEndpointListing:

    def test_reports_the_endpoint_it_asked(self, ovh_svc) -> None:
        client = MagicMock()
        client.list_buckets.return_value = {"Buckets": []}
        ovh_svc._client = client
        listing = asyncio.run(ovh_svc.search_buckets())
        assert listing.buckets == []
        assert listing.endpoint == "https://s3.gra.io.cloud.ovh.net"
        assert listing.region == "gra"
        assert listing.searched_regions == ()

    def test_hand_set_ovh_endpoint_stays_pinned(self, ovh_svc) -> None:
        ovh_svc._client = MagicMock()
        with pytest.raises(ValueError, match="pinned to endpoint"):
            asyncio.run(ovh_svc.create_bucket("my-bucket", "uk"))
