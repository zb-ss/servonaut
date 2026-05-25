"""Tests for MCP S3 / object-storage tools — 10 tools across 3 providers.

Covers the per-tool matrix from the workflow plan §5:
1. Happy path — service mock returns canned data; correct string/JSON returned.
2. Guard-tier enforcement — tool returns "Blocked:..." at insufficient tier.
3. Service unavailable — _get_object_storage(provider) returns None.
4. Invalid provider string — audit reason 'validation: invalid_provider'.
5. Validator rejection (ValueError from service) — audit reason starts with 'validation: '.
6. API error (generic Exception) — audit reason starts with 'api_error: '.
7. Audit-on-success — _audit.log called once with success=True.
8. Secret-masking on s3_generate_presigned_url (CRITICAL).

Special tests:
- Provider dispatch matrix: parametrised aws/hetzner/ovh routing.
- s3_list_objects: is_truncated=True preserved in JSON output.
- s3_upload_object / s3_download_object: path-traversal ValueError via 'validation:' channel.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from servonaut.config.schema import AppConfig, MCPConfig
from servonaut.mcp.guards import CommandGuard, GuardLevel
from servonaut.mcp.tools import ServonautTools


# ---------------------------------------------------------------------------
# Shared factory
# ---------------------------------------------------------------------------

def make_tools(
    guard_level=GuardLevel.DANGEROUS,
    aws_os_service=None,
    hetzner_os_service=None,
    ovh_os_service=None,
):
    """Build a ServonautTools instance with mocked S3 services."""
    config = AppConfig(mcp=MCPConfig(guard_level=guard_level))
    config_manager = MagicMock()
    config_manager.get.return_value = config

    aws_service = MagicMock()
    aws_service.fetch_instances_cached = AsyncMock(return_value=[])

    custom_server_service = MagicMock()
    custom_server_service.list_as_instances.return_value = []

    ssh_service = MagicMock()
    ssh_service.get_key_path.return_value = None
    ssh_service.discover_key.return_value = None

    connection_service = MagicMock()
    connection_service.resolve_profile.return_value = None
    connection_service.get_target_host.return_value = "1.2.3.4"
    connection_service.get_proxy_args.return_value = []
    connection_service.get_proxy_jump_string.return_value = None

    scp_service = MagicMock()
    scp_service.execute_transfer = AsyncMock(return_value=(0, "", ""))

    ovh_service = MagicMock()
    ovh_service.fetch_instances_cached = AsyncMock(return_value=[])

    guard = CommandGuard(config.mcp)
    audit = MagicMock()
    audit.log = MagicMock()

    tools = ServonautTools(
        config_manager, aws_service, custom_server_service, MagicMock(),
        ssh_service, connection_service, scp_service,
        guard, audit,
        ovh_service=ovh_service,
        aws_object_storage_service=aws_os_service,
        hetzner_object_storage_service=hetzner_os_service,
        ovh_object_storage_service=ovh_os_service,
    )
    return tools


def _make_s3_svc():
    """Return a fully-mocked ObjectStorageService."""
    svc = MagicMock()
    svc.list_buckets = AsyncMock(return_value=[
        {"name": "my-bucket", "creation_date": "2024-01-01T12:00:00+00:00"}
    ])
    svc.list_objects = AsyncMock(return_value={
        "folders": ["images/"], "objects": [
            {"key": "readme.txt", "size": 1024, "last_modified": "2024-01-01"}
        ],
        "is_truncated": False,
    })
    svc.download_object = AsyncMock()
    svc.upload_object = AsyncMock()
    svc.delete_object = AsyncMock()
    svc.create_bucket = AsyncMock()
    svc.delete_bucket = AsyncMock()
    svc.copy_object = AsyncMock()
    svc.move_object = AsyncMock()
    svc.generate_presigned_url = AsyncMock(
        return_value="https://s3.amazonaws.com/bucket/key?X-Amz-Signature=abc123"
    )
    return svc


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# s3_list_buckets
# ---------------------------------------------------------------------------

class TestS3ListBuckets:
    def test_happy_path_renders_table(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_list_buckets(provider="aws"))
        assert "my-bucket" in result
        assert "2024-01-01" in result
        assert "1 total" in result

    def test_invalid_provider_returns_validation_error(self):
        tools = make_tools(aws_os_service=_make_s3_svc())
        result = run(tools.s3_list_buckets(provider="invalid"))
        assert "Error" in result
        assert "provider" in result.lower()
        reason = tools._audit.log.call_args[0][4]
        assert reason == "validation: invalid_provider"

    def test_invalid_provider_uppercase_rejected(self):
        """'AWS' (uppercase) must not route to the aws service — enum is case-sensitive."""
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_list_buckets(provider="AWS"))
        assert "Error" in result
        reason = tools._audit.log.call_args[0][4]
        assert reason == "validation: invalid_provider"

    def test_service_unavailable_when_none(self):
        tools = make_tools(aws_os_service=None)
        result = run(tools.s3_list_buckets(provider="aws"))
        assert "not configured" in result.lower()
        reason = tools._audit.log.call_args[0][4]
        assert reason == "s3_provider_unavailable_aws"

    def test_blocked_below_readonly(self):
        # s3_list_buckets is readonly — it should never be blocked at READONLY
        svc = _make_s3_svc()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_os_service=svc)
        result = run(tools.s3_list_buckets(provider="aws"))
        assert "Blocked" not in result

    def test_api_error(self):
        svc = _make_s3_svc()
        svc.list_buckets = AsyncMock(side_effect=Exception("S3 error"))
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_list_buckets(provider="aws"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        run(tools.s3_list_buckets(provider="aws"))
        tools._audit.log.assert_called_once()
        assert tools._audit.log.call_args[0][0] == "s3_list_buckets"
        assert tools._audit.log.call_args[0][3] is True

    @pytest.mark.parametrize("provider,attr", [
        ("aws", "aws_os_service"),
        ("hetzner", "hetzner_os_service"),
        ("ovh", "ovh_os_service"),
    ])
    def test_provider_dispatch_matrix(self, provider, attr):
        """Each provider string routes to the correct service mock."""
        svc = _make_s3_svc()
        kwargs = {attr: svc}
        tools = make_tools(**kwargs)
        result = run(tools.s3_list_buckets(provider=provider))
        # If routed correctly, list_buckets was called on our mock
        svc.list_buckets.assert_called_once()
        assert "my-bucket" in result


# ---------------------------------------------------------------------------
# s3_list_objects
# ---------------------------------------------------------------------------

class TestS3ListObjects:
    def test_happy_path_returns_json(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_list_objects(provider="aws", bucket="my-bucket"))
        data = json.loads(result)
        assert data["bucket"] == "my-bucket"
        assert "folders" in data
        assert "objects" in data
        assert isinstance(data["is_truncated"], bool)

    def test_truncation_flag_preserved_when_true(self):
        """is_truncated=True from service must appear in the returned JSON."""
        svc = _make_s3_svc()
        svc.list_objects = AsyncMock(return_value={
            "folders": [], "objects": [],
            "is_truncated": True,
        })
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_list_objects(provider="aws", bucket="big-bucket"))
        data = json.loads(result)
        assert data["is_truncated"] is True

    def test_invalid_provider(self):
        tools = make_tools(aws_os_service=_make_s3_svc())
        result = run(tools.s3_list_objects(provider="gcs", bucket="my-bucket"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "validation: invalid_provider"

    def test_service_unavailable(self):
        tools = make_tools()
        result = run(tools.s3_list_objects(provider="hetzner", bucket="my-bucket"))
        assert "not configured" in result.lower()
        assert tools._audit.log.call_args[0][4] == "s3_provider_unavailable_hetzner"

    def test_allowed_at_readonly(self):
        svc = _make_s3_svc()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_os_service=svc)
        result = run(tools.s3_list_objects(provider="aws", bucket="my-bucket"))
        assert "Blocked" not in result

    def test_validator_rejection(self):
        svc = _make_s3_svc()
        svc.list_objects = AsyncMock(side_effect=ValueError("Invalid bucket name 'X!'"))
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_list_objects(provider="aws", bucket="X!"))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        svc = _make_s3_svc()
        svc.list_objects = AsyncMock(side_effect=Exception("NoSuchBucket"))
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_list_objects(provider="aws", bucket="gone"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        run(tools.s3_list_objects(provider="aws", bucket="my-bucket"))
        assert tools._audit.log.call_args[0][0] == "s3_list_objects"
        assert tools._audit.log.call_args[0][3] is True

    def test_list_objects_injects_bucket_and_prefix(self):
        """Regression test for F-ISSUE-1: tool must inject bucket/prefix into JSON.

        The service returns only {folders, objects, is_truncated}.  The tool is
        responsible for adding bucket and prefix so parallel agent calls can
        correlate responses.  The returned JSON must have exactly the five
        allow-listed keys — no more, no less.
        """
        svc = _make_s3_svc()
        # Service returns ONLY the bare response — no bucket/prefix/delimiter
        svc.list_objects = AsyncMock(return_value={
            "folders": [],
            "objects": [],
            "is_truncated": False,
        })
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_list_objects(
            provider="aws", bucket="my-bucket", prefix="logs/",
        ))
        data = json.loads(result)
        # Tool must have injected these from its own arguments
        assert data["bucket"] == "my-bucket"
        assert data["prefix"] == "logs/"
        # Core fields from service response
        assert data["folders"] == []
        assert data["objects"] == []
        assert data["is_truncated"] is False
        # Exactly five keys — allow-list enforced
        assert set(data.keys()) == {"bucket", "prefix", "folders", "objects", "is_truncated"}


# ---------------------------------------------------------------------------
# s3_download_object
# ---------------------------------------------------------------------------

class TestS3DownloadObject:
    def test_happy_path(self):
        svc = _make_s3_svc()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_os_service=svc)
        result = run(tools.s3_download_object(
            provider="aws", bucket="my-bucket", key="readme.txt",
            local_path="/tmp/readme.txt",
        ))
        assert "Downloaded" in result
        assert "my-bucket" in result
        assert "readme.txt" in result

    def test_blocked_at_readonly(self):
        svc = _make_s3_svc()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_os_service=svc)
        result = run(tools.s3_download_object(
            provider="aws", bucket="my-bucket", key="k", local_path="/tmp/x",
        ))
        assert result.startswith("Blocked:")
        assert tools._audit.log.call_args[0][3] is False

    def test_invalid_provider(self):
        tools = make_tools(aws_os_service=_make_s3_svc())
        result = run(tools.s3_download_object(
            provider="", bucket="b", key="k", local_path="/tmp/x",
        ))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "validation: invalid_provider"

    def test_service_unavailable(self):
        tools = make_tools()
        result = run(tools.s3_download_object(
            provider="ovh", bucket="b", key="k", local_path="/tmp/x",
        ))
        assert "not configured" in result.lower()
        assert tools._audit.log.call_args[0][4] == "s3_provider_unavailable_ovh"

    def test_path_traversal_rejection(self):
        """Service raises ValueError on path traversal — tool surfaces via 'validation:' channel."""
        svc = _make_s3_svc()
        svc.download_object = AsyncMock(
            side_effect=ValueError("Path '/etc/passwd' resolves to /etc/passwd outside the allowed roots")
        )
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_os_service=svc)
        result = run(tools.s3_download_object(
            provider="aws", bucket="b", key="k", local_path="/etc/passwd",
        ))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        svc = _make_s3_svc()
        svc.download_object = AsyncMock(side_effect=Exception("NoSuchKey"))
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_os_service=svc)
        result = run(tools.s3_download_object(
            provider="aws", bucket="b", key="missing.txt", local_path="/tmp/x",
        ))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        svc = _make_s3_svc()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_os_service=svc)
        run(tools.s3_download_object(
            provider="aws", bucket="b", key="k", local_path="/tmp/x",
        ))
        assert tools._audit.log.call_args[0][0] == "s3_download_object"
        assert tools._audit.log.call_args[0][3] is True


# ---------------------------------------------------------------------------
# s3_create_bucket
# ---------------------------------------------------------------------------

class TestS3CreateBucket:
    def test_happy_path(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_create_bucket(provider="aws", bucket="new-bucket"))
        assert "Created" in result
        assert "new-bucket" in result
        assert "aws" in result

    def test_blocked_at_standard(self):
        svc = _make_s3_svc()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_os_service=svc)
        result = run(tools.s3_create_bucket(provider="aws", bucket="new-bucket"))
        assert result.startswith("Blocked:")
        reason = tools._audit.log.call_args[0][4]
        assert "standard" in reason.lower()

    def test_invalid_provider(self):
        tools = make_tools(aws_os_service=_make_s3_svc())
        result = run(tools.s3_create_bucket(provider="None", bucket="b"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "validation: invalid_provider"

    def test_service_unavailable(self):
        tools = make_tools()
        result = run(tools.s3_create_bucket(provider="aws", bucket="b"))
        assert "not configured" in result.lower()
        assert tools._audit.log.call_args[0][4] == "s3_provider_unavailable_aws"

    def test_validator_rejection(self):
        svc = _make_s3_svc()
        svc.create_bucket = AsyncMock(side_effect=ValueError("Invalid bucket name"))
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_create_bucket(provider="aws", bucket="BAD!BUCKET"))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        svc = _make_s3_svc()
        svc.create_bucket = AsyncMock(side_effect=Exception("BucketAlreadyExists"))
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_create_bucket(provider="aws", bucket="existing"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        run(tools.s3_create_bucket(provider="aws", bucket="new-bucket"))
        assert tools._audit.log.call_args[0][0] == "s3_create_bucket"
        assert tools._audit.log.call_args[0][3] is True


# ---------------------------------------------------------------------------
# s3_delete_bucket
# ---------------------------------------------------------------------------

class TestS3DeleteBucket:
    def test_happy_path(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_delete_bucket(provider="aws", bucket="old-bucket"))
        assert "Deleted" in result
        assert "old-bucket" in result

    def test_blocked_at_standard(self):
        svc = _make_s3_svc()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_os_service=svc)
        result = run(tools.s3_delete_bucket(provider="aws", bucket="b"))
        assert result.startswith("Blocked:")

    def test_invalid_provider(self):
        tools = make_tools(aws_os_service=_make_s3_svc())
        result = run(tools.s3_delete_bucket(provider="s3", bucket="b"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "validation: invalid_provider"

    def test_service_unavailable(self):
        tools = make_tools()
        result = run(tools.s3_delete_bucket(provider="hetzner", bucket="b"))
        assert "not configured" in result.lower()
        assert tools._audit.log.call_args[0][4] == "s3_provider_unavailable_hetzner"

    def test_validator_rejection(self):
        svc = _make_s3_svc()
        svc.delete_bucket = AsyncMock(side_effect=ValueError("Invalid bucket name"))
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_delete_bucket(provider="aws", bucket="BAD!"))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        svc = _make_s3_svc()
        svc.delete_bucket = AsyncMock(side_effect=Exception("BucketNotEmpty"))
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_delete_bucket(provider="aws", bucket="non-empty"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        run(tools.s3_delete_bucket(provider="aws", bucket="b"))
        assert tools._audit.log.call_args[0][0] == "s3_delete_bucket"
        assert tools._audit.log.call_args[0][3] is True


# ---------------------------------------------------------------------------
# s3_upload_object
# ---------------------------------------------------------------------------

class TestS3UploadObject:
    def test_happy_path(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_upload_object(
            provider="aws", bucket="my-bucket", key="data.csv",
            local_path="/tmp/data.csv",
        ))
        assert "Uploaded" in result
        assert "my-bucket" in result
        assert "data.csv" in result

    def test_blocked_at_standard(self):
        svc = _make_s3_svc()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_os_service=svc)
        result = run(tools.s3_upload_object(
            provider="aws", bucket="b", key="k", local_path="/tmp/x",
        ))
        assert result.startswith("Blocked:")

    def test_invalid_provider(self):
        tools = make_tools(aws_os_service=_make_s3_svc())
        result = run(tools.s3_upload_object(
            provider="gcs", bucket="b", key="k", local_path="/tmp/x",
        ))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "validation: invalid_provider"

    def test_service_unavailable(self):
        tools = make_tools()
        result = run(tools.s3_upload_object(
            provider="ovh", bucket="b", key="k", local_path="/tmp/x",
        ))
        assert "not configured" in result.lower()
        assert tools._audit.log.call_args[0][4] == "s3_provider_unavailable_ovh"

    def test_path_traversal_rejection(self):
        """Service raises ValueError on path traversal — must surface via 'validation:' channel."""
        svc = _make_s3_svc()
        svc.upload_object = AsyncMock(
            side_effect=ValueError("Path resolves outside the allowed roots")
        )
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_upload_object(
            provider="aws", bucket="b", key="k", local_path="../../../etc/passwd",
        ))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        svc = _make_s3_svc()
        svc.upload_object = AsyncMock(side_effect=Exception("AccessDenied"))
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_upload_object(
            provider="aws", bucket="b", key="k", local_path="/tmp/x",
        ))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        run(tools.s3_upload_object(
            provider="aws", bucket="b", key="k", local_path="/tmp/x",
        ))
        assert tools._audit.log.call_args[0][0] == "s3_upload_object"
        assert tools._audit.log.call_args[0][3] is True


# ---------------------------------------------------------------------------
# s3_delete_object
# ---------------------------------------------------------------------------

class TestS3DeleteObject:
    def test_happy_path(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_delete_object(provider="aws", bucket="my-bucket", key="data.csv"))
        assert "Deleted" in result
        assert "my-bucket" in result
        assert "data.csv" in result
        assert "aws" in result

    def test_blocked_at_standard(self):
        svc = _make_s3_svc()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_os_service=svc)
        result = run(tools.s3_delete_object(provider="aws", bucket="b", key="k"))
        assert result.startswith("Blocked:")

    def test_invalid_provider(self):
        tools = make_tools(aws_os_service=_make_s3_svc())
        result = run(tools.s3_delete_object(provider="", bucket="b", key="k"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "validation: invalid_provider"

    def test_service_unavailable(self):
        tools = make_tools()
        result = run(tools.s3_delete_object(provider="aws", bucket="b", key="k"))
        assert "not configured" in result.lower()
        assert tools._audit.log.call_args[0][4] == "s3_provider_unavailable_aws"

    def test_validator_rejection(self):
        svc = _make_s3_svc()
        svc.delete_object = AsyncMock(side_effect=ValueError("Invalid key"))
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_delete_object(provider="aws", bucket="b", key=""))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        svc = _make_s3_svc()
        svc.delete_object = AsyncMock(side_effect=Exception("NoSuchKey"))
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_delete_object(provider="aws", bucket="b", key="gone"))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        run(tools.s3_delete_object(provider="aws", bucket="b", key="k"))
        assert tools._audit.log.call_args[0][0] == "s3_delete_object"
        assert tools._audit.log.call_args[0][3] is True


# ---------------------------------------------------------------------------
# s3_copy_object
# ---------------------------------------------------------------------------

class TestS3CopyObject:
    def test_happy_path(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_copy_object(
            provider="aws", src_bucket="src", src_key="a.txt",
            dst_bucket="dst", dst_key="b.txt",
        ))
        assert "Copied" in result
        assert "src" in result
        assert "a.txt" in result
        assert "dst" in result
        assert "b.txt" in result

    def test_blocked_at_standard(self):
        svc = _make_s3_svc()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_os_service=svc)
        result = run(tools.s3_copy_object(
            provider="aws", src_bucket="s", src_key="k", dst_bucket="d", dst_key="k2",
        ))
        assert result.startswith("Blocked:")

    def test_invalid_provider(self):
        tools = make_tools(aws_os_service=_make_s3_svc())
        result = run(tools.s3_copy_object(
            provider="b2", src_bucket="s", src_key="k", dst_bucket="d", dst_key="k2",
        ))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "validation: invalid_provider"

    def test_service_unavailable(self):
        tools = make_tools()
        result = run(tools.s3_copy_object(
            provider="ovh", src_bucket="s", src_key="k", dst_bucket="d", dst_key="k2",
        ))
        assert "not configured" in result.lower()
        assert tools._audit.log.call_args[0][4] == "s3_provider_unavailable_ovh"

    def test_validator_rejection(self):
        svc = _make_s3_svc()
        svc.copy_object = AsyncMock(side_effect=ValueError("Invalid bucket name"))
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_copy_object(
            provider="aws", src_bucket="BAD!", src_key="k", dst_bucket="d", dst_key="k2",
        ))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        svc = _make_s3_svc()
        svc.copy_object = AsyncMock(side_effect=Exception("AccessDenied"))
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_copy_object(
            provider="aws", src_bucket="s", src_key="k", dst_bucket="d", dst_key="k2",
        ))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        run(tools.s3_copy_object(
            provider="aws", src_bucket="s", src_key="k", dst_bucket="d", dst_key="k2",
        ))
        assert tools._audit.log.call_args[0][0] == "s3_copy_object"
        assert tools._audit.log.call_args[0][3] is True


# ---------------------------------------------------------------------------
# s3_move_object
# ---------------------------------------------------------------------------

class TestS3MoveObject:
    def test_happy_path(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_move_object(
            provider="aws", src_bucket="src", src_key="a.txt",
            dst_bucket="dst", dst_key="b.txt",
        ))
        assert "Moved" in result
        assert "src" in result
        assert "dst" in result

    def test_blocked_at_standard(self):
        svc = _make_s3_svc()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_os_service=svc)
        result = run(tools.s3_move_object(
            provider="aws", src_bucket="s", src_key="k", dst_bucket="d", dst_key="k2",
        ))
        assert result.startswith("Blocked:")

    def test_invalid_provider(self):
        tools = make_tools(aws_os_service=_make_s3_svc())
        result = run(tools.s3_move_object(
            provider="sftp", src_bucket="s", src_key="k", dst_bucket="d", dst_key="k2",
        ))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "validation: invalid_provider"

    def test_service_unavailable(self):
        tools = make_tools()
        result = run(tools.s3_move_object(
            provider="hetzner", src_bucket="s", src_key="k", dst_bucket="d", dst_key="k2",
        ))
        assert "not configured" in result.lower()
        assert tools._audit.log.call_args[0][4] == "s3_provider_unavailable_hetzner"

    def test_validator_rejection(self):
        svc = _make_s3_svc()
        svc.move_object = AsyncMock(side_effect=ValueError("Invalid key path"))
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_move_object(
            provider="aws", src_bucket="s", src_key="", dst_bucket="d", dst_key="k2",
        ))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        svc = _make_s3_svc()
        svc.move_object = AsyncMock(side_effect=Exception("S3 server error"))
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_move_object(
            provider="aws", src_bucket="s", src_key="k", dst_bucket="d", dst_key="k2",
        ))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success(self):
        svc = _make_s3_svc()
        tools = make_tools(aws_os_service=svc)
        run(tools.s3_move_object(
            provider="aws", src_bucket="s", src_key="k", dst_bucket="d", dst_key="k2",
        ))
        assert tools._audit.log.call_args[0][0] == "s3_move_object"
        assert tools._audit.log.call_args[0][3] is True


# ---------------------------------------------------------------------------
# s3_generate_presigned_url  (CRITICAL — secret-masking)
# ---------------------------------------------------------------------------

PRESIGNED_URL = "https://s3.amazonaws.com/bucket/key?X-Amz-Signature=SUPERSECRET&expires=3600"


class TestS3GeneratePresignedUrl:
    def _make_svc_with_url(self, url=PRESIGNED_URL):
        svc = _make_s3_svc()
        svc.generate_presigned_url = AsyncMock(return_value=url)
        return svc

    def test_happy_path_returns_json_with_url(self):
        svc = self._make_svc_with_url()
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_generate_presigned_url(
            provider="aws", bucket="my-bucket", key="secret.tar.gz", expires_in=3600,
        ))
        data = json.loads(result)
        assert data["url"] == PRESIGNED_URL
        assert data["bucket"] == "my-bucket"
        assert data["key"] == "secret.tar.gz"
        assert data["expires_in"] == 3600
        assert data["provider"] == "aws"

    def test_secret_masking_critical(self):
        """CRITICAL: URL must NOT appear in the audit result argument.

        The presigned URL is a bearer token. The audit log must only receive
        a placeholder 'presigned url issued (N chars)' — never the URL itself.
        This test catches any regression that would log the secret.
        """
        svc = self._make_svc_with_url()
        tools = make_tools(aws_os_service=svc)
        run(tools.s3_generate_presigned_url(
            provider="aws", bucket="my-bucket", key="secret.tar.gz", expires_in=3600,
        ))
        tools._audit.log.assert_called_once()
        call_args = tools._audit.log.call_args[0]
        # args dict (position 1) must not contain the URL
        args_dict = call_args[1]
        assert PRESIGNED_URL not in str(args_dict), (
            "URL must not appear in the audit args dict"
        )
        # result string (position 2) must be the placeholder, not the URL
        audit_result = call_args[2]
        assert PRESIGNED_URL not in audit_result, (
            f"URL must not appear in audit result; got: {audit_result!r}"
        )
        assert "presigned url issued" in audit_result, (
            f"Expected placeholder in audit result; got: {audit_result!r}"
        )
        # Confirm the length placeholder is accurate
        expected_placeholder = f"presigned url issued ({len(PRESIGNED_URL)} chars)"
        assert audit_result == expected_placeholder

    def test_blocked_at_standard(self):
        svc = self._make_svc_with_url()
        tools = make_tools(guard_level=GuardLevel.STANDARD, aws_os_service=svc)
        result = run(tools.s3_generate_presigned_url(
            provider="aws", bucket="b", key="k", expires_in=3600,
        ))
        assert result.startswith("Blocked:")
        assert tools._audit.log.call_args[0][3] is False

    def test_blocked_at_readonly(self):
        svc = self._make_svc_with_url()
        tools = make_tools(guard_level=GuardLevel.READONLY, aws_os_service=svc)
        result = run(tools.s3_generate_presigned_url(
            provider="aws", bucket="b", key="k", expires_in=3600,
        ))
        assert result.startswith("Blocked:")

    def test_invalid_provider(self):
        tools = make_tools(aws_os_service=self._make_svc_with_url())
        result = run(tools.s3_generate_presigned_url(
            provider="azure", bucket="b", key="k", expires_in=3600,
        ))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4] == "validation: invalid_provider"

    def test_service_unavailable(self):
        tools = make_tools()
        result = run(tools.s3_generate_presigned_url(
            provider="aws", bucket="b", key="k", expires_in=3600,
        ))
        assert "not configured" in result.lower()
        assert tools._audit.log.call_args[0][4] == "s3_provider_unavailable_aws"

    def test_validator_rejection(self):
        svc = _make_s3_svc()
        svc.generate_presigned_url = AsyncMock(
            side_effect=ValueError("expires_in must be between 1 and 604800")
        )
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_generate_presigned_url(
            provider="aws", bucket="b", key="k", expires_in=0,
        ))
        assert result.startswith("Error:")
        assert tools._audit.log.call_args[0][4].startswith("validation:")

    def test_api_error(self):
        svc = _make_s3_svc()
        svc.generate_presigned_url = AsyncMock(side_effect=Exception("AccessDenied"))
        tools = make_tools(aws_os_service=svc)
        result = run(tools.s3_generate_presigned_url(
            provider="aws", bucket="b", key="k", expires_in=3600,
        ))
        assert "Error" in result
        assert tools._audit.log.call_args[0][4].startswith("api_error:")

    def test_audit_on_success_logs_once_with_success_true(self):
        svc = self._make_svc_with_url()
        tools = make_tools(aws_os_service=svc)
        run(tools.s3_generate_presigned_url(
            provider="aws", bucket="b", key="k", expires_in=3600,
        ))
        tools._audit.log.assert_called_once()
        assert tools._audit.log.call_args[0][0] == "s3_generate_presigned_url"
        assert tools._audit.log.call_args[0][3] is True
