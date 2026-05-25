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
