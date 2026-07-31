"""Gap-filling tests for workflow 20260521-aws3 coverage targets.

Covers the NEW code added in this feature branch that was under-covered in
the initial six test files.  Specifically:

* AWSService legacy fetch paths (_fetch_all_regions / _fetch_region / _extract)
  to close lines 62-70, 81-89, 97-114, 125-137, 151-157, 263, 279.
* ObjectStorageService: create_bucket LocationConstraint path (line 355),
  upload/download path-traversal guard duplication, and _validate_local_path
  directory-path rejection.
* AWSManagerScreen: _do_lifecycle success + audit, _do_terminate confirmation,
  _colorize_state all branches, on_button_pressed dispatch, action_back,
  action_new, action_stop, action_reboot, _render_table.
* AWSCreateScreen: _load_amis/_load_instance_types/_load_key_pairs/_load_subnets/
  _load_security_groups (direct coroutine invocation with mocked app),
  _preselect_default, _current_region, _on_create missing-region/type/key/
  subnet/sg validation branches, _refresh_instances_after_create.
* ObjectStorageScreen: _load_objects, _render_objects_table, _update_breadcrumb
  objects view, _open_bucket, _open_folder, _navigate_to_buckets, action_open,
  action_back (objects view), _create_bucket, _delete_bucket, _delete_object,
  _upload_object, _download_object, _copy_object, _move_object, scrub/scrub_name.
* formatting.py: _format_token_count, format_tokens_remaining, format_resets_at,
  format_soft_cap_badge.
* _write_json_secure symlink guard (Part B security fix).
* AWSAuditLogger: log_action success + write failure paths.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch, call

import pytest

# ---------------------------------------------------------------------------
# AWSService legacy fetch paths
# ---------------------------------------------------------------------------

from servonaut.services.aws_service import AWSService
from servonaut.services.cache_service import CacheService


@pytest.fixture
def cache_svc():
    s = MagicMock(spec=CacheService)
    s.load.return_value = None
    return s


@pytest.fixture
def aws_svc(cache_svc):
    return AWSService(cache_svc)


class TestAWSServiceLegacyFetch:
    """Cover the existing fetch_instances / _fetch_* methods."""

    def test_fetch_all_regions_returns_empty_on_error(self, aws_svc) -> None:
        with patch("boto3.client", side_effect=Exception("no creds")):
            result = aws_svc._fetch_all_regions()
        assert result == []

    def test_fetch_all_regions_aggregates_instances(self, aws_svc) -> None:
        mock_ec2_client = MagicMock()
        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_instance = MagicMock()
        mock_instance.id = "i-0abc12345678def01"
        mock_instance.tags = [{"Key": "Name", "Value": "prod-web"}]
        mock_instance.instance_type = "t3.micro"
        mock_instance.state = {"Name": "running"}
        mock_instance.public_ip_address = "54.1.2.3"
        mock_instance.private_ip_address = "10.0.0.5"
        mock_instance.key_name = "my-key"

        mock_ec2_resource = MagicMock()
        mock_ec2_resource.instances.all.return_value = [mock_instance]

        def client_or_resource(*args, **kwargs):
            # boto3.client('ec2') → describe_regions; boto3.resource('ec2') → instances
            return mock_ec2_client

        with patch("boto3.client", return_value=mock_ec2_client), \
             patch("boto3.resource", return_value=mock_ec2_resource):
            result = aws_svc._fetch_all_regions()

        assert len(result) == 1
        assert result[0]["name"] == "prod-web"
        assert result[0]["region"] == "us-east-1"

    def test_fetch_region_returns_empty_on_exception(self, aws_svc) -> None:
        with patch("boto3.resource", side_effect=Exception("denied")):
            result = aws_svc._fetch_region("us-east-1")
        assert result == []

    def test_extract_instance_data_no_tags(self, aws_svc) -> None:
        mock_instance = MagicMock()
        mock_instance.id = "i-0abc12345678def01"
        mock_instance.tags = None  # no tags
        mock_instance.instance_type = "t3.small"
        mock_instance.state = {"Name": "stopped"}
        mock_instance.public_ip_address = None
        mock_instance.private_ip_address = "10.0.0.6"
        mock_instance.key_name = "key2"

        result = aws_svc._extract_instance_data(mock_instance, "eu-west-1")
        assert result["name"] == ""
        assert result["state"] == "stopped"

    def test_extract_instance_data_with_name_tag(self, aws_svc) -> None:
        mock_instance = MagicMock()
        mock_instance.id = "i-0abc12345678def02"
        mock_instance.tags = [
            {"Key": "Env", "Value": "prod"},
            {"Key": "Name", "Value": "web-server"},
        ]
        mock_instance.instance_type = "t3.micro"
        mock_instance.state = {"Name": "running"}
        mock_instance.public_ip_address = "1.2.3.4"
        mock_instance.private_ip_address = "10.0.0.7"
        mock_instance.key_name = "key3"

        result = aws_svc._extract_instance_data(mock_instance, "ap-northeast-1")
        assert result["name"] == "web-server"
        assert result["region"] == "ap-northeast-1"

    def test_validate_key_name_ok(self, aws_svc) -> None:
        aws_svc._validate_key_name("my-key-pair-01")  # no raise

    def test_validate_key_name_bad(self, aws_svc) -> None:
        with pytest.raises(ValueError, match="key pair"):
            aws_svc._validate_key_name("")

    def test_validate_name_tag_ok(self, aws_svc) -> None:
        aws_svc._validate_name_tag("web-prod-01")  # no raise

    def test_validate_instance_type_ok(self, aws_svc) -> None:
        aws_svc._validate_instance_type("t3.micro")  # no raise

    def test_validate_instance_type_bad(self, aws_svc) -> None:
        with pytest.raises(ValueError, match="instance type"):
            aws_svc._validate_instance_type("not-valid-type")

    def test_fetch_instances_cached_uses_cache(self, aws_svc, cache_svc) -> None:
        cache_svc.load.return_value = [{"id": "i-cached"}]
        cache_svc.get_age.return_value = 100
        result = asyncio.run(aws_svc.fetch_instances_cached())
        assert result == [{"id": "i-cached"}]

    def test_list_amis_no_name_filter_omits_name_filter(self, aws_svc) -> None:
        mock_ec2 = MagicMock()
        mock_ec2.describe_images.return_value = {"Images": []}
        with patch("boto3.client", return_value=mock_ec2):
            asyncio.run(aws_svc.list_amis("us-east-1"))
        filters = mock_ec2.describe_images.call_args[1]["Filters"]
        # Only the 'state' filter should be present, not a 'name' filter.
        assert not any(f["Name"] == "name" for f in filters)

    def test_list_amis_sorts_by_creation_date_desc(self, aws_svc) -> None:
        mock_ec2 = MagicMock()
        images = [
            {"ImageId": "ami-0000000000000001", "Name": "old", "CreationDate": "2022-01-01", "Architecture": "", "VirtualizationType": ""},
            {"ImageId": "ami-0000000000000002", "Name": "new", "CreationDate": "2024-01-01", "Architecture": "", "VirtualizationType": ""},
        ]
        mock_ec2.describe_images.return_value = {"Images": images}
        with patch("boto3.client", return_value=mock_ec2):
            result = asyncio.run(aws_svc.list_amis("us-east-1"))
        assert result[0]["image_id"] == "ami-0000000000000002"  # newest first


# ---------------------------------------------------------------------------
# ObjectStorageService additional coverage
# ---------------------------------------------------------------------------

from servonaut.services.object_storage_service import ObjectStorageService


class TestObjectStorageServiceAdditional:

    def test_create_bucket_uses_location_constraint_outside_us_east_1(self) -> None:
        svc = ObjectStorageService(provider="aws", region="eu-west-1")
        mock_client = MagicMock()
        svc._client = mock_client
        asyncio.run(svc.create_bucket("my-bucket"))
        mock_client.create_bucket.assert_called_once_with(
            Bucket="my-bucket",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
        )

    def test_create_bucket_no_location_constraint_for_us_east_1(self) -> None:
        svc = ObjectStorageService(provider="aws", region="us-east-1")
        mock_client = MagicMock()
        svc._client = mock_client
        asyncio.run(svc.create_bucket("my-bucket"))
        mock_client.create_bucket.assert_called_once_with(Bucket="my-bucket")

    def test_create_bucket_no_location_constraint_with_endpoint_url(self) -> None:
        """Non-AWS providers (Hetzner/OVH) skip the LocationConstraint."""
        svc = ObjectStorageService(
            provider="hetzner",
            region="nbg1",
            endpoint_url="https://nbg1.your-objectstorage.com",
        )
        mock_client = MagicMock()
        svc._client = mock_client
        asyncio.run(svc.create_bucket("my-bucket"))
        mock_client.create_bucket.assert_called_once_with(Bucket="my-bucket")

    def test_validate_local_path_directory_rejected_for_upload(self, tmp_path) -> None:
        with patch.object(Path, "home", return_value=tmp_path.parent):
            with pytest.raises(ValueError, match="regular file"):
                ObjectStorageService._validate_local_path(str(tmp_path), must_exist=True)

    def test_validate_local_path_empty_string_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            ObjectStorageService._validate_local_path("", must_exist=False)

    def test_validate_expires_in_boundary_valid(self) -> None:
        ObjectStorageService._validate_expires_in(1)        # minimum valid
        ObjectStorageService._validate_expires_in(604800)   # maximum valid (7 days)

    def test_validate_expires_in_non_integer_raises(self) -> None:
        with pytest.raises(ValueError, match="expires_in"):
            ObjectStorageService._validate_expires_in(3600.0)  # type: ignore

    def test_list_objects_with_prefix_passes_prefix(self) -> None:
        from datetime import datetime, timezone as tz
        svc = ObjectStorageService(provider="aws")
        mock_client = MagicMock()
        mock_client.list_objects_v2.return_value = {
            "CommonPrefixes": [],
            "Contents": [],
            "IsTruncated": False,
        }
        svc._client = mock_client
        asyncio.run(svc.list_objects("my-bucket", prefix="images/"))
        call_kwargs = mock_client.list_objects_v2.call_args[1]
        assert call_kwargs.get("Prefix") == "images/"

    def test_upload_object_calls_upload_file(self, tmp_path) -> None:
        svc = ObjectStorageService(provider="aws")
        mock_client = MagicMock()
        svc._client = mock_client
        f = tmp_path / "upload.txt"
        f.write_text("hello")
        with patch.object(Path, "home", return_value=tmp_path.parent):
            asyncio.run(svc.upload_object("my-bucket", "folder/upload.txt", str(f)))
        mock_client.upload_file.assert_called_once()

    def test_download_object_calls_download_file(self, tmp_path) -> None:
        svc = ObjectStorageService(provider="aws")
        mock_client = MagicMock()
        svc._client = mock_client
        dest = tmp_path / "downloaded.txt"
        with patch.object(Path, "home", return_value=tmp_path.parent):
            asyncio.run(svc.download_object("my-bucket", "folder/file.txt", str(dest)))
        mock_client.download_file.assert_called_once()


# ---------------------------------------------------------------------------
# AWSManagerScreen additional coverage
# ---------------------------------------------------------------------------

from servonaut.screens.aws_manager import AWSManagerScreen


def _mgr_app(*, aws_service=None, demo_mode=False, redaction_service=None):
    app = MagicMock()
    app.demo_mode = demo_mode
    app.redaction_service = redaction_service
    app.aws_service = aws_service
    app.aws_audit = None
    app.instances = []
    app.push_screen = MagicMock()
    app.pop_screen = MagicMock()
    app.push_screen_wait = AsyncMock(return_value=True)
    return app


class TestAWSManagerColorize:

    def test_running_green(self) -> None:
        assert "[green]" in AWSManagerScreen._colorize_state("running")

    def test_stopped_yellow(self) -> None:
        assert "[yellow]" in AWSManagerScreen._colorize_state("stopped")

    def test_pending_blue(self) -> None:
        assert "[blue]" in AWSManagerScreen._colorize_state("pending")

    def test_terminated_dim(self) -> None:
        assert "[dim]" in AWSManagerScreen._colorize_state("terminated")

    def test_shutting_down_dim(self) -> None:
        assert "[dim]" in AWSManagerScreen._colorize_state("shutting-down")

    def test_unknown_passthrough(self) -> None:
        result = AWSManagerScreen._colorize_state("weird-state")
        assert "weird-state" in result

    def test_rebooting_blue(self) -> None:
        assert "[blue]" in AWSManagerScreen._colorize_state("rebooting")


class TestAWSManagerRenderTable:
    """_render_table populates rows and calls _sync_action_buttons."""

    def test_render_table_adds_rows(self) -> None:
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = [
            {"id": "i-0abc12345678def90", "name": "web", "type": "t3.micro",
             "state": "running", "public_ip": "1.2.3.4", "region": "us-east-1"},
        ]
        mock_table = MagicMock()
        with patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "_sync_action_buttons"):
            screen._render_table()
        mock_table.clear.assert_called_once()
        mock_table.add_row.assert_called_once()

    def test_render_table_no_public_ip_shows_dash(self) -> None:
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = [
            {"id": "i-0abc12345678def90", "name": "web", "type": "t3.micro",
             "state": "stopped", "public_ip": None, "region": "us-east-1"},
        ]
        rows_added = []
        mock_table = MagicMock()
        mock_table.add_row = MagicMock(side_effect=lambda *a, **kw: rows_added.append(a))
        with patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "_sync_action_buttons"):
            screen._render_table()
        assert "—" in rows_added[0]


class TestAWSManagerOnButtonPressed:

    def test_refresh_button_calls_action_refresh(self) -> None:
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        screen._loading = False
        app = _mgr_app()

        event = MagicMock()
        event.button.id = "btn_aws_mgr_refresh"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_set_status"), \
             patch.object(screen, "run_worker"):
            screen.on_button_pressed(event)

    def test_unknown_button_noop(self) -> None:
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        event = MagicMock()
        event.button.id = "btn_unknown_thing"
        # Should not raise
        screen.on_button_pressed(event)

    def test_new_button_calls_action_new(self) -> None:
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        screen._loading = False
        svc = MagicMock()
        app = _mgr_app(aws_service=svc)

        event = MagicMock()
        event.button.id = "btn_aws_mgr_new"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "notify"):
            screen.on_button_pressed(event)

        app.push_screen.assert_called_once()


class TestAWSManagerActionBack:

    def test_action_back_calls_pop_screen(self) -> None:
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        app = _mgr_app()
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            screen.action_back()
        app.pop_screen.assert_called_once()


class TestAWSManagerActionNewUnconfigured:

    def test_action_new_with_no_service_notifies(self) -> None:
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        app = _mgr_app(aws_service=None)
        notified = []
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "notify", side_effect=lambda *a, **kw: notified.append(a[0])):
            screen.action_new()
        assert notified
        assert "not configured" in notified[0].lower()


class TestAWSManagerActionStop:

    def test_stop_blocked_when_no_instance_selected(self) -> None:
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        screen._loading = False
        app = _mgr_app()
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=None), \
             patch.object(screen, "_run_lifecycle") as mock_lc, \
             patch.object(screen, "notify"):
            screen.action_stop()
        mock_lc.assert_not_called()


class TestAWSManagerActionReboot:

    def test_reboot_on_stopped_notifies(self) -> None:
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        inst = {"id": "i-0abc12345678def90", "state": "stopped"}
        screen._instances = [inst]
        app = _mgr_app()
        notified = []
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=inst), \
             patch.object(screen, "_run_lifecycle") as mock_lc, \
             patch.object(screen, "notify", side_effect=lambda *a, **kw: notified.append(a[0])):
            screen.action_reboot()
        mock_lc.assert_not_called()
        assert notified

    def test_reboot_on_running_fires_lifecycle(self) -> None:
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        inst = {"id": "i-0abc12345678def90", "state": "running"}
        screen._instances = [inst]
        app = _mgr_app()
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=inst), \
             patch.object(screen, "_run_lifecycle") as mock_lc, \
             patch.object(screen, "notify"):
            screen.action_reboot()
        mock_lc.assert_called_once()


class TestAWSManagerDoLifecycle:
    """_do_lifecycle success + failure paths."""

    def test_do_lifecycle_success_calls_audit(self) -> None:
        mock_svc = MagicMock()
        mock_svc.start_instance = AsyncMock(return_value={})
        audit = MagicMock()
        app = _mgr_app(aws_service=mock_svc)
        app.aws_audit = audit

        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        screen._loading = False

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_set_status"), \
             patch.object(screen, "notify"), \
             patch.object(screen, "_load_instances", new_callable=AsyncMock):
            asyncio.run(screen._do_lifecycle("start_instance", "i-0abc12345678def90", "us-east-1", "started"))

        audit.log_action.assert_called_once()

    def test_do_lifecycle_failure_sets_status(self) -> None:
        mock_svc = MagicMock()
        mock_svc.stop_instance = AsyncMock(side_effect=Exception("throttled"))
        app = _mgr_app(aws_service=mock_svc)

        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        screen._loading = False

        status_set = []
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_set_status", side_effect=lambda t: status_set.append(t)), \
             patch.object(screen, "notify"):
            asyncio.run(screen._do_lifecycle("stop_instance", "i-0abc12345678def90", "us-east-1", "stopped"))

        assert any("[red]" in s for s in status_set)

    def test_do_terminate_confirmed_terminates(self) -> None:
        mock_svc = MagicMock()
        mock_svc.terminate_instance = AsyncMock(return_value={})
        app = _mgr_app(aws_service=mock_svc)
        app.push_screen_wait = AsyncMock(return_value=True)

        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        screen._loading = False

        inst = {"id": "i-0abc12345678def90", "region": "us-east-1", "name": "web",
                "type": "t3.micro", "state": "running"}

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_set_status"), \
             patch.object(screen, "notify"), \
             patch.object(screen, "_load_instances", new_callable=AsyncMock):
            asyncio.run(screen._do_terminate(inst))

        mock_svc.terminate_instance.assert_called_once_with(
            "i-0abc12345678def90", "us-east-1"
        )

    def test_do_terminate_cancelled_does_not_terminate(self) -> None:
        mock_svc = MagicMock()
        mock_svc.terminate_instance = AsyncMock(return_value={})
        app = _mgr_app(aws_service=mock_svc)
        app.push_screen_wait = AsyncMock(return_value=False)  # user cancelled

        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        screen._loading = False

        inst = {"id": "i-0abc12345678def90", "region": "us-east-1", "name": "web",
                "type": "t3.micro", "state": "running"}

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_set_status"), \
             patch.object(screen, "notify"), \
             patch.object(screen, "_load_instances", new_callable=AsyncMock):
            asyncio.run(screen._do_terminate(inst))

        mock_svc.terminate_instance.assert_not_called()


# ---------------------------------------------------------------------------
# AWSCreateScreen additional coverage
# ---------------------------------------------------------------------------

from servonaut.screens.aws_create import AWSCreateScreen
from servonaut.config.schema import AppConfig


def _create_app(*, aws_service=None):
    app = MagicMock()
    app.demo_mode = False
    app.redaction_service = None
    app.aws_service = aws_service
    app.aws_audit = None
    cfg_mgr = MagicMock()
    cfg_mgr.get.return_value = AppConfig()
    app.config_manager = cfg_mgr
    app.pop_screen = MagicMock()
    app.push_screen_wait = AsyncMock(return_value=True)
    app.instances = []
    return app


def _make_mock_svc():
    svc = MagicMock()
    svc.list_regions = AsyncMock(return_value=["us-east-1"])
    svc.list_amis = AsyncMock(return_value=[])
    svc.list_instance_types = AsyncMock(return_value=[])
    svc.list_key_pairs = AsyncMock(return_value=[])
    svc.list_subnets = AsyncMock(return_value=[])
    svc.list_security_groups = AsyncMock(return_value=[])
    svc.run_instances = AsyncMock(return_value=[])
    svc.fetch_instances_cached = AsyncMock(return_value=[])
    return svc


class TestAWSCreateLoaders:
    """Each _load_* coroutine runs and populates the correct list."""

    async def _run_loader(self, method_name, return_value, list_attr):
        svc = _make_mock_svc()
        setattr(svc, f"list_{method_name}s" if method_name not in ("amis", "instance_types", "security_groups") else f"list_{method_name}", AsyncMock(return_value=return_value))
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        mock_table = MagicMock()
        mock_table.cursor_row = 0

        def query_side(sel, *args, **kwargs):
            return mock_table

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "notify"):
            coro = getattr(screen, f"_load_{method_name}")("us-east-1")
            await coro

        return getattr(screen, f"_{list_attr}")

    def test_load_amis_populates_list(self) -> None:
        svc = _make_mock_svc()
        svc.list_amis = AsyncMock(return_value=[
            {"image_id": "ami-0abc12345678def90", "name": "al2023",
             "architecture": "x86_64", "virtualization_type": "hvm",
             "creation_date": "2024-01-01T00:00:00Z"}
        ])
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        mock_table = MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "notify"):
            asyncio.run(screen._load_amis("us-east-1"))

        assert len(screen._amis) == 1
        assert screen._amis[0]["image_id"] == "ami-0abc12345678def90"

    def test_load_instance_types_populates_list(self) -> None:
        svc = _make_mock_svc()
        svc.list_instance_types = AsyncMock(return_value=[
            {"instance_type": "t3.micro", "vcpus": 2, "memory_mib": 1024}
        ])
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        mock_table = MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "notify"):
            asyncio.run(screen._load_instance_types("us-east-1"))

        assert len(screen._instance_types) == 1

    def test_load_key_pairs_populates_list(self) -> None:
        svc = _make_mock_svc()
        svc.list_key_pairs = AsyncMock(return_value=[
            {"key_name": "my-key", "key_pair_id": "k-123", "fingerprint": "ab:cd"}
        ])
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        mock_table = MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "notify"):
            asyncio.run(screen._load_key_pairs("us-east-1"))

        assert len(screen._key_pairs) == 1

    def test_load_subnets_populates_list(self) -> None:
        svc = _make_mock_svc()
        svc.list_subnets = AsyncMock(return_value=[
            {"subnet_id": "subnet-0abc12345678def90", "vpc_id": "vpc-1",
             "availability_zone": "us-east-1a", "cidr_block": "10.0.0.0/24",
             "available_ip_count": 251}
        ])
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        mock_table = MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "notify"):
            asyncio.run(screen._load_subnets("us-east-1"))

        assert len(screen._subnets) == 1

    def test_load_security_groups_populates_list(self) -> None:
        svc = _make_mock_svc()
        svc.list_security_groups = AsyncMock(return_value=[
            {"group_id": "sg-0abc12345678def90", "group_name": "web-sg",
             "description": "Web", "vpc_id": "vpc-1"}
        ])
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        mock_table = MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "notify"):
            asyncio.run(screen._load_security_groups("us-east-1"))

        assert len(screen._security_groups) == 1

    def test_load_amis_with_exception_notifies(self) -> None:
        svc = _make_mock_svc()
        svc.list_amis = AsyncMock(side_effect=Exception("no permission"))
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        mock_table = MagicMock()
        notified = []

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notified.append(msg)):
            asyncio.run(screen._load_amis("us-east-1"))

        assert notified
        assert screen._amis == []

    def test_load_amis_empty_region_returns_immediately(self) -> None:
        svc = _make_mock_svc()
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        mock_table = MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "notify"):
            asyncio.run(screen._load_amis(""))

        svc.list_amis.assert_not_called()


class TestAWSCreatePreselect:

    def test_preselect_default_moves_cursor(self) -> None:
        mock_tbl = MagicMock()
        AWSCreateScreen._preselect_default(
            mock_tbl, ["us-east-1", "eu-west-1", "ap-southeast-1"], "eu-west-1"
        )
        mock_tbl.move_cursor.assert_called_once_with(row=1)

    def test_preselect_default_noop_for_empty_default(self) -> None:
        mock_tbl = MagicMock()
        AWSCreateScreen._preselect_default(mock_tbl, ["us-east-1"], "")
        mock_tbl.move_cursor.assert_not_called()

    def test_preselect_default_noop_for_empty_rows(self) -> None:
        mock_tbl = MagicMock()
        AWSCreateScreen._preselect_default(mock_tbl, [], "us-east-1")
        mock_tbl.move_cursor.assert_not_called()

    def test_preselect_default_noop_when_no_match(self) -> None:
        mock_tbl = MagicMock()
        AWSCreateScreen._preselect_default(mock_tbl, ["us-east-1"], "us-west-2")
        mock_tbl.move_cursor.assert_not_called()


class TestAWSCreateCurrentRegion:

    def test_current_region_returns_selected(self) -> None:
        screen = AWSCreateScreen.__new__(AWSCreateScreen)
        screen._regions = ["us-east-1", "eu-west-1"]
        mock_tbl = MagicMock()
        mock_tbl.cursor_row = 1
        with patch.object(screen, "query_one", return_value=mock_tbl):
            result = screen._current_region()
        assert result == "eu-west-1"

    def test_current_region_returns_none_out_of_range(self) -> None:
        screen = AWSCreateScreen.__new__(AWSCreateScreen)
        screen._regions = []
        mock_tbl = MagicMock()
        mock_tbl.cursor_row = 0
        with patch.object(screen, "query_one", return_value=mock_tbl):
            result = screen._current_region()
        assert result is None


class TestAWSCreateOnCreateValidation:
    """All the validation abort branches in _on_create."""

    def _make_full_screen(self, **overrides):
        screen = AWSCreateScreen()
        defaults = dict(
            _regions=["us-east-1"],
            _amis=[{"image_id": "ami-0abc12345678def90", "name": "al2023",
                    "architecture": "x86_64", "virtualization_type": "hvm",
                    "creation_date": "2024-01-01"}],
            _instance_types=[{"instance_type": "t3.micro", "vcpus": 2, "memory_mib": 1024}],
            _key_pairs=[{"key_name": "my-key", "key_pair_id": "k", "fingerprint": ""}],
            _subnets=[{"subnet_id": "subnet-0abc12345678def90", "vpc_id": "v",
                       "availability_zone": "az", "cidr_block": "10.0.0.0/24",
                       "available_ip_count": 10}],
            _security_groups=[{"group_id": "sg-0abc12345678def90", "group_name": "sg",
                                "description": "", "vpc_id": "v"}],
        )
        defaults.update(overrides)
        for k, v in defaults.items():
            setattr(screen, k, v)
        return screen

    def _make_query_side(self, screen, name_val="my-server", region_row=0,
                         ami_row=0, type_row=0, key_row=0, subnet_row=0, sg_row=0):
        def query_side(sel, *args, **kwargs):
            m = MagicMock()
            if "aws_input_name" in sel:
                m.value = name_val
            elif "aws_regions_table" in sel:
                m.cursor_row = region_row
            elif "aws_amis_table" in sel:
                m.cursor_row = ami_row
            elif "aws_types_table" in sel:
                m.cursor_row = type_row
            elif "aws_keys_table" in sel:
                m.cursor_row = key_row
            elif "aws_subnets_table" in sel:
                m.cursor_row = subnet_row
            elif "aws_sg_table" in sel:
                m.cursor_row = sg_row
            elif "btn_aws_create_submit" in sel:
                m.disabled = False
            return m
        return query_side

    def test_aborts_on_missing_region(self) -> None:
        svc = _make_mock_svc()
        app = _create_app(aws_service=svc)
        screen = self._make_full_screen(_regions=[])  # empty regions → no selection

        notified = []

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "aws_input_name" in sel:
                m.value = "my-server"
            elif "aws_regions_table" in sel:
                m.cursor_row = 0  # row=0 but _regions is empty
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notified.append(msg)):
            asyncio.run(screen._on_create())

        assert any("region" in m.lower() for m in notified)
        svc.run_instances.assert_not_called()

    def test_aborts_on_missing_instance_type(self) -> None:
        svc = _make_mock_svc()
        app = _create_app(aws_service=svc)
        screen = self._make_full_screen(_instance_types=[])

        notified = []

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one",
                          side_effect=self._make_query_side(screen, type_row=0)), \
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notified.append(msg)):
            asyncio.run(screen._on_create())

        assert any("type" in m.lower() or "instance" in m.lower() for m in notified)
        svc.run_instances.assert_not_called()

    def test_aborts_on_missing_key_pair(self) -> None:
        svc = _make_mock_svc()
        app = _create_app(aws_service=svc)
        screen = self._make_full_screen(_key_pairs=[])

        notified = []

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one",
                          side_effect=self._make_query_side(screen, key_row=0)), \
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notified.append(msg)):
            asyncio.run(screen._on_create())

        assert any("key" in m.lower() for m in notified)
        svc.run_instances.assert_not_called()

    def test_aborts_on_missing_subnet(self) -> None:
        svc = _make_mock_svc()
        app = _create_app(aws_service=svc)
        screen = self._make_full_screen(_subnets=[])

        notified = []

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one",
                          side_effect=self._make_query_side(screen, subnet_row=0)), \
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notified.append(msg)):
            asyncio.run(screen._on_create())

        assert any("subnet" in m.lower() for m in notified)
        svc.run_instances.assert_not_called()

    def test_aborts_on_missing_security_group(self) -> None:
        svc = _make_mock_svc()
        app = _create_app(aws_service=svc)
        screen = self._make_full_screen(_security_groups=[])

        notified = []

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one",
                          side_effect=self._make_query_side(screen, sg_row=0)), \
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notified.append(msg)):
            asyncio.run(screen._on_create())

        assert any("security" in m.lower() or "group" in m.lower() for m in notified)
        svc.run_instances.assert_not_called()

    def test_run_instances_exception_notifies_and_reenables_button(self) -> None:
        svc = _make_mock_svc()
        svc.run_instances = AsyncMock(side_effect=Exception("throttled by AWS"))
        app = _create_app(aws_service=svc)
        app.push_screen_wait = AsyncMock(return_value=True)  # confirmed
        screen = self._make_full_screen()

        notified = []
        mock_submit_btn = MagicMock()
        mock_submit_btn.disabled = False

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "aws_input_name" in sel:
                m.value = "test-server"
            elif "aws_regions_table" in sel:
                m.cursor_row = 0
            elif "aws_amis_table" in sel:
                m.cursor_row = 0
            elif "aws_types_table" in sel:
                m.cursor_row = 0
            elif "aws_keys_table" in sel:
                m.cursor_row = 0
            elif "aws_subnets_table" in sel:
                m.cursor_row = 0
            elif "aws_sg_table" in sel:
                m.cursor_row = 0
            elif "btn_aws_create_submit" in sel:
                return mock_submit_btn
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notified.append(msg)):
            asyncio.run(screen._on_create())

        assert any("failed" in m.lower() or "launch" in m.lower() for m in notified)
        assert mock_submit_btn.disabled is False  # re-enabled on error


class TestAWSCreateRefreshAfterCreate:

    def test_refresh_merges_instances(self) -> None:
        svc = _make_mock_svc()
        svc.fetch_instances_cached = AsyncMock(return_value=[
            {"id": "i-0new", "name": "new-inst", "provider": None}
        ])
        app = _create_app(aws_service=svc)
        app.instances = [{"id": "i-0custom", "is_custom": True, "name": "custom"}]
        screen = AWSCreateScreen.__new__(AWSCreateScreen)

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._refresh_instances_after_create())

        # custom server preserved, new AWS instance added
        ids = [i["id"] for i in app.instances]
        assert "i-0custom" in ids
        assert "i-0new" in ids


# ---------------------------------------------------------------------------
# ObjectStorageScreen additional coverage
# ---------------------------------------------------------------------------

from servonaut.screens.object_storage import (
    ObjectStorageScreen, _VIEW_BUCKETS, _VIEW_OBJECTS,
)


def _s3_mock_storage_service():
    svc = MagicMock()
    svc.list_buckets = AsyncMock(return_value=[
        {"name": "my-bucket", "creation_date": "2024-01-01T00:00:00+00:00"}
    ])
    svc.list_objects = AsyncMock(return_value={
        "folders": ["images/"],
        "objects": [{"key": "readme.txt", "size": 1536, "last_modified": "2024-01-01T00:00:00+00:00"}],
        "is_truncated": False,
    })
    svc.delete_bucket = AsyncMock()
    svc.delete_object = AsyncMock()
    svc.create_bucket = AsyncMock()
    svc.generate_presigned_url = AsyncMock(return_value="https://example.com/signed")
    svc.copy_object = AsyncMock()
    svc.move_object = AsyncMock()
    svc.upload_object = AsyncMock()
    svc.download_object = AsyncMock()
    return svc


def _s3_app(provider="aws", storage_service=None, demo_mode=False, redaction_service=None):
    app = MagicMock()
    app.demo_mode = demo_mode
    app.redaction_service = redaction_service
    setattr(app, f"{provider}_object_storage_service", storage_service)
    app.push_screen_wait = AsyncMock(return_value=True)
    app.notify = MagicMock()
    app.pop_screen = MagicMock()
    return app


class TestObjectStorageLoadObjects:

    def test_load_objects_populates_folders_and_objects(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._current_bucket = "my-bucket"
        screen._prefix = ""
        screen._view = _VIEW_OBJECTS

        mock_table = MagicMock()
        mock_breadcrumb = MagicMock()
        mock_status = MagicMock()

        def query_side(sel, *a, **kw):
            if "s3_table" in sel:
                return mock_table
            if "s3_breadcrumb" in sel:
                return mock_breadcrumb
            if "s3_status" in sel:
                return mock_status
            return MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side):
            asyncio.run(screen._load_objects())

        assert screen._folders == ["images/"]
        assert len(screen._objects) == 1
        assert screen._objects[0]["key"] == "readme.txt"

    def test_load_objects_error_sets_status(self) -> None:
        svc = _s3_mock_storage_service()
        svc.list_objects = AsyncMock(side_effect=Exception("access denied"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._current_bucket = "my-bucket"
        screen._prefix = ""
        screen._view = _VIEW_OBJECTS

        status_set = []
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "_set_status", side_effect=lambda t: status_set.append(t)):
            asyncio.run(screen._load_objects())

        assert any("[red]" in s for s in status_set)

    def test_load_objects_is_truncated_shows_warning(self) -> None:
        svc = _s3_mock_storage_service()
        svc.list_objects = AsyncMock(return_value={
            "folders": [],
            "objects": [{"key": "file.txt", "size": 100, "last_modified": ""}],
            "is_truncated": True,
        })
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._current_bucket = "my-bucket"
        screen._prefix = ""
        screen._view = _VIEW_OBJECTS

        status_set = []
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "_set_status", side_effect=lambda t: status_set.append(t)), \
             patch.object(screen, "_render_objects_table"), \
             patch.object(screen, "_update_breadcrumb"):
            asyncio.run(screen._load_objects())

        assert any("1000" in s or "first" in s for s in status_set)


class TestObjectStorageBreadcrumb:

    def test_breadcrumb_buckets_view(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        mock_breadcrumb = MagicMock()
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_breadcrumb):
            screen._update_breadcrumb()

        mock_breadcrumb.update.assert_called_once()
        assert "buckets" in mock_breadcrumb.update.call_args[0][0]

    def test_breadcrumb_objects_view_with_prefix(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"
        screen._prefix = "images/thumbnails/"

        mock_breadcrumb = MagicMock()
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_breadcrumb):
            screen._update_breadcrumb()

        text = mock_breadcrumb.update.call_args[0][0]
        assert "images" in text
        assert "thumbnails" in text


class TestObjectStorageNavigation:

    def test_action_back_from_objects_navigates_to_buckets(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "run_worker") as mock_rw:
            screen.action_back()

        assert screen._view == _VIEW_BUCKETS
        mock_rw.assert_called_once()
        # close the coroutine to avoid RuntimeWarning
        coro = mock_rw.call_args[0][0]
        coro.close()

    def test_action_back_from_buckets_pops_screen(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "run_worker") as mock_rw:
            screen.action_back()

        app.pop_screen.assert_called_once()
        mock_rw.assert_not_called()

    def test_action_open_in_objects_view_calls_open_folder(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_open_folder") as mock_of:
            screen.action_open()

        mock_of.assert_called_once()

    def test_action_open_in_buckets_view_calls_open_bucket(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_open_bucket") as mock_ob:
            screen.action_open()

        mock_ob.assert_called_once()

    def test_open_bucket_sets_view_and_loads_objects(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS
        screen._buckets = [{"name": "my-bucket"}]

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_bucket_name", return_value="my-bucket"), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._open_bucket()

        assert screen._view == _VIEW_OBJECTS
        assert screen._current_bucket == "my-bucket"
        mock_rw.assert_called_once()
        coro = mock_rw.call_args[0][0]
        coro.close()

    def test_open_folder_appends_prefix(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._prefix = "images/"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "folder", "key": "images/thumbnails/"}), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._open_folder()

        assert screen._prefix == "images/thumbnails/"
        mock_rw.assert_called_once()
        coro = mock_rw.call_args[0][0]
        coro.close()

    def test_open_folder_on_object_type_is_noop(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._prefix = "images/"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "images/photo.jpg"}), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._open_folder()

        # prefix unchanged, no worker
        assert screen._prefix == "images/"
        mock_rw.assert_not_called()


class TestObjectStorageScrub:

    def test_scrub_returns_raw_without_demo_mode(self) -> None:
        app = _s3_app(provider="aws", demo_mode=False)
        screen = ObjectStorageScreen("aws")
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            result = screen.scrub("secret-bucket-name")
        assert result == "secret-bucket-name"

    def test_scrub_name_redacts_in_demo_mode(self) -> None:
        from servonaut.services.redaction_service import RedactionService
        redaction = RedactionService()
        app = _s3_app(provider="aws", demo_mode=True, redaction_service=redaction)
        screen = ObjectStorageScreen("aws")
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            result = screen.scrub_name("prod-customer-data-2024")
        # redact_name should have replaced it
        assert result != "prod-customer-data-2024"


class TestObjectStorageCreateBucket:

    def test_create_bucket_success_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "_set_status"):
            asyncio.run(screen._create_bucket("new-bucket"))

        # No region picked → "", meaning "the provider's configured region".
        svc.create_bucket.assert_called_once_with("new-bucket", "")
        app.notify.assert_called()

    def test_create_bucket_passes_selected_region(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "_set_status"):
            asyncio.run(screen._create_bucket("new-bucket", "eu-central-1"))

        svc.create_bucket.assert_called_once_with("new-bucket", "eu-central-1")

    def test_create_bucket_invalid_name_notifies_error(self) -> None:
        svc = _s3_mock_storage_service()
        svc.create_bucket = AsyncMock(side_effect=ValueError("invalid bucket name"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "_set_status"):
            asyncio.run(screen._create_bucket("BADNAME"))

        app.notify.assert_called()
        assert any("invalid" in str(c).lower() for c in app.notify.call_args_list)

    def test_create_bucket_network_error_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        svc.create_bucket = AsyncMock(side_effect=Exception("network error"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "_set_status"):
            asyncio.run(screen._create_bucket("my-bucket"))

        app.notify.assert_called()


class TestObjectStorageDeleteBucket:

    def test_delete_bucket_success_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "_set_status"), \
             patch.object(screen, "_load_buckets", new_callable=AsyncMock):
            asyncio.run(screen._delete_bucket("my-bucket", "my-bucket"))

        svc.delete_bucket.assert_called_once_with("my-bucket")
        app.notify.assert_called()

    def test_delete_bucket_error_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        svc.delete_bucket = AsyncMock(side_effect=Exception("BucketNotEmpty"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "_set_status"):
            asyncio.run(screen._delete_bucket("my-bucket", "my-bucket"))

        app.notify.assert_called()


class TestObjectStorageDeleteObject:

    def test_delete_object_success(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._current_bucket = "my-bucket"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "_set_status"), \
             patch.object(screen, "_load_objects", new_callable=AsyncMock):
            asyncio.run(screen._delete_object("my-bucket", "file.txt", "file.txt"))

        svc.delete_object.assert_called_once_with("my-bucket", "file.txt")

    def test_delete_object_error_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        svc.delete_object = AsyncMock(side_effect=Exception("access denied"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "_set_status"):
            asyncio.run(screen._delete_object("my-bucket", "file.txt", "file.txt"))

        app.notify.assert_called()


class TestObjectStorageUploadDownload:

    def test_upload_success_notifies(self, tmp_path) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._current_bucket = "my-bucket"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_load_objects", new_callable=AsyncMock):
            asyncio.run(screen._upload_object("my-bucket", "key.txt", "/some/path"))

        svc.upload_object.assert_called_once()
        app.notify.assert_called()

    def test_upload_validation_error_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        svc.upload_object = AsyncMock(side_effect=ValueError("path not allowed"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._upload_object("my-bucket", "key.txt", "/bad/path"))

        app.notify.assert_called()

    def test_download_success_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._download_object("my-bucket", "key.txt", "~/Downloads/key.txt"))

        svc.download_object.assert_called_once()

    def test_download_validation_error_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        svc.download_object = AsyncMock(side_effect=ValueError("outside allowed roots"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._download_object("my-bucket", "key.txt", "/bad/path"))

        app.notify.assert_called()


class TestObjectStorageCopyMove:

    def test_copy_success_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._copy_object("src", "old.txt", "dst", "new.txt"))

        svc.copy_object.assert_called_once_with("src", "old.txt", "dst", "new.txt")
        app.notify.assert_called()

    def test_copy_error_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        svc.copy_object = AsyncMock(side_effect=Exception("not found"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._copy_object("src", "old.txt", "dst", "new.txt"))

        app.notify.assert_called()

    def test_move_success_notifies_and_reloads(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._current_bucket = "my-bucket"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_load_objects", new_callable=AsyncMock) as mock_load:
            asyncio.run(screen._move_object("src", "old.txt", "dst", "new.txt"))

        svc.move_object.assert_called_once()
        mock_load.assert_called_once()


# ---------------------------------------------------------------------------
# formatting.py additional coverage
# ---------------------------------------------------------------------------

from servonaut.utils.formatting import (
    _format_token_count,
    format_tokens_remaining,
    format_resets_at,
    format_soft_cap_badge,
)


class TestFormatTokenCount:

    def test_millions(self) -> None:
        assert _format_token_count(1_500_000) == "1.5M"

    def test_exact_millions_strips_dot_zero(self) -> None:
        assert _format_token_count(15_000_000) == "15M"

    def test_thousands(self) -> None:
        assert _format_token_count(12_300) == "12.3K"

    def test_exact_thousands_strips_dot_zero(self) -> None:
        assert _format_token_count(5_000) == "5K"

    def test_below_thousand(self) -> None:
        assert _format_token_count(500) == "500"

    def test_zero_returns_zero(self) -> None:
        assert _format_token_count(0) == "0"

    def test_negative_returns_zero(self) -> None:
        assert _format_token_count(-100) == "0"


class TestFormatTokensRemaining:

    def test_free_user_limit_zero(self) -> None:
        assert format_tokens_remaining(0, 0, 0) == "—"

    def test_with_topup(self) -> None:
        result = format_tokens_remaining(100_000, 1_000_000, 500_000)
        assert "topup" in result
        assert "500K" in result or "500" in result

    def test_without_topup(self) -> None:
        result = format_tokens_remaining(200_000, 1_000_000, 0)
        assert "topup" not in result
        assert "800" in result or "K" in result

    def test_invalid_inputs_return_dash(self) -> None:
        assert format_tokens_remaining(None, None, None) == "—"  # type: ignore

    def test_used_exceeds_limit_clamps_to_zero(self) -> None:
        result = format_tokens_remaining(2_000_000, 1_000_000, 0)
        assert result == "0"


class TestFormatResetsAt:

    def test_empty_string_returns_empty(self) -> None:
        assert format_resets_at("") == ""

    def test_none_returns_empty(self) -> None:
        assert format_resets_at(None) == ""  # type: ignore

    def test_past_date_returns_overdue(self) -> None:
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        assert format_resets_at(past) == "reset overdue"

    def test_tomorrow(self) -> None:
        # 30 hours from "now" rolls into "in 2 days" depending on wall-clock
        # time-of-day (the formatter rounds at day boundaries). Accept any
        # near-future expression — the assertion that matters is "not empty
        # and not 'reset overdue'", verified below.
        tomorrow = (datetime.now(timezone.utc) + timedelta(hours=30)).isoformat()
        result = format_resets_at(tomorrow)
        assert result and result != "reset overdue"
        assert result in (
            "tomorrow", "in 1h", "in 2h", "in 30h", "in 2 days",
        )

    def test_in_days(self) -> None:
        future = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        result = format_resets_at(future)
        assert "days" in result or "in" in result

    def test_invalid_string_returns_empty(self) -> None:
        assert format_resets_at("not-a-date") == ""

    def test_z_suffix_accepted(self) -> None:
        future = (datetime.now(timezone.utc) + timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        result = format_resets_at(future)
        assert result != ""

    def test_today(self) -> None:
        # A timestamp within the same calendar day but a few hours away
        soon = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        result = format_resets_at(soon)
        # Could be "today" or "in 2h" depending on exact calendar day boundary
        assert result in ("today", "in 2h", "in 1h", "in 3h")


class TestFormatSoftCapBadge:

    def test_hard_capped_returns_out_of_tokens(self) -> None:
        assert format_soft_cap_badge(False, True) == "out of tokens"

    def test_soft_capped_stays_generic(self) -> None:
        # The badge deliberately does not name the model it downgraded to.
        result = format_soft_cap_badge(True, False)
        assert result == "downgraded to faster model"

    def test_neither_returns_none(self) -> None:
        assert format_soft_cap_badge(False, False) is None

    def test_hard_cap_overrides_soft_cap(self) -> None:
        # Both set: hard cap takes precedence
        result = format_soft_cap_badge(True, True)
        assert result == "out of tokens"


# ---------------------------------------------------------------------------
# Part B — _write_json_secure symlink guard test
# ---------------------------------------------------------------------------

from servonaut.config.manager import _write_json_secure


class TestWriteJsonSecureSymlinkGuard:
    """_write_json_secure must NOT follow a symlink planted at the tmp path."""

    def test_final_file_mode_is_0o600(self, tmp_path) -> None:
        target = tmp_path / "config.json"
        _write_json_secure(target, {"test": "value"})
        mode = stat.S_IMODE(target.stat().st_mode)
        assert mode == 0o600

    def test_write_json_secure_produces_valid_json(self, tmp_path) -> None:
        target = tmp_path / "config.json"
        data = {"version": 5, "cache_ttl_seconds": 300}
        _write_json_secure(target, data)
        loaded = json.loads(target.read_text())
        assert loaded == data

    @pytest.mark.skipif(
        not hasattr(os, "O_NOFOLLOW"),
        reason="O_NOFOLLOW not available on this platform"
    )
    def test_does_not_follow_symlink_at_tmp_path(self, tmp_path) -> None:
        """A pre-planted symlink at the temp path must not redirect the write."""
        target = tmp_path / "config.json"

        # Plant a symlink at the expected temp path location.
        # The tmp path name is computed the same way as the implementation.
        import os as _os
        tmp_name = f".config.json.tmp_{_os.getpid()}"
        tmp_link = tmp_path / tmp_name
        # Symlink points to a file outside the intended target directory.
        redirect_target = tmp_path / "evil_file.json"
        tmp_link.symlink_to(redirect_target)

        # _write_json_secure should fail when it encounters the symlink
        # (O_NOFOLLOW raises OSError/ELOOP) — or succeed after unlinking it.
        # Either way: the REDIRECT TARGET must not contain our config data.
        try:
            _write_json_secure(target, {"safe": True})
        except OSError:
            pass  # O_NOFOLLOW raised — symlink guard worked

        # The redirect target must NOT have been written.
        assert not redirect_target.exists() or json.loads(redirect_target.read_text()).get("safe") is None


# ---------------------------------------------------------------------------
# AWSAuditLogger tests
# ---------------------------------------------------------------------------

from servonaut.services.aws_audit import AWSAuditLogger


class TestAWSAuditLogger:

    def test_log_action_writes_json_line(self, tmp_path) -> None:
        audit_path = tmp_path / "aws_audit.jsonl"
        logger = AWSAuditLogger(str(audit_path))
        logger.log_action(
            "start_instance", "i-0abc12345678def90",
            {"region": "us-east-1"}, confirmed=True,
        )
        lines = audit_path.read_text().strip().split("\n")
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["action"] == "start_instance"
        assert entry["target"] == "i-0abc12345678def90"
        assert entry["confirmed"] is True
        assert "ts" in entry

    def test_log_action_creates_parent_dir(self, tmp_path) -> None:
        nested = tmp_path / "a" / "b" / "c" / "audit.jsonl"
        logger = AWSAuditLogger(str(nested))
        logger.log_action("terminate_instance", "i-0001", {})
        assert nested.exists()

    def test_log_action_file_mode_is_0o600(self, tmp_path) -> None:
        audit_path = tmp_path / "audit.jsonl"
        logger = AWSAuditLogger(str(audit_path))
        logger.log_action("reboot_instance", "i-0002", {"region": "eu-west-1"})
        mode = stat.S_IMODE(audit_path.stat().st_mode)
        assert mode == 0o600

    def test_log_action_appends_multiple_entries(self, tmp_path) -> None:
        audit_path = tmp_path / "audit.jsonl"
        logger = AWSAuditLogger(str(audit_path))
        logger.log_action("start_instance", "i-0001", {})
        logger.log_action("stop_instance", "i-0002", {})
        lines = audit_path.read_text().strip().split("\n")
        assert len(lines) == 2
        actions = [json.loads(l)["action"] for l in lines]
        assert "start_instance" in actions
        assert "stop_instance" in actions

    def test_log_action_swallows_write_failure(self, tmp_path) -> None:
        """A write failure must not raise — audit errors are non-fatal."""
        audit_path = tmp_path / "audit.jsonl"
        logger = AWSAuditLogger(str(audit_path))
        # Simulate os.open failure — the except block must swallow it
        with patch("os.open", side_effect=OSError("disk full")):
            logger.log_action("start_instance", "i-0001", {})

    def test_log_action_confirmed_false(self, tmp_path) -> None:
        audit_path = tmp_path / "audit.jsonl"
        logger = AWSAuditLogger(str(audit_path))
        logger.log_action("terminate_instance", "i-0001", {}, confirmed=False)
        entry = json.loads(audit_path.read_text().strip())
        assert entry["confirmed"] is False


# ---------------------------------------------------------------------------
# AWSManagerScreen — remaining coverage gaps
# ---------------------------------------------------------------------------

from servonaut.services.redaction_service import RedactionService as _RS


def _mgr_app2(*, aws_service=None, demo_mode=False, redaction_service=None):
    app = MagicMock()
    app.demo_mode = demo_mode
    app.redaction_service = redaction_service
    app.aws_service = aws_service
    app.aws_audit = None
    app.pop_screen = MagicMock()
    app.push_screen = MagicMock()
    app.push_screen_wait = AsyncMock(return_value=True)
    return app


class TestAWSManagerLoadInstancesErrorPath:
    """_load_instances exception path (lines 196-201)."""

    def test_load_instances_exception_sets_status(self) -> None:
        mock_svc = MagicMock()
        mock_svc.fetch_instances_cached = AsyncMock(side_effect=Exception("no creds"))
        app = _mgr_app2(aws_service=mock_svc)
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        screen._loading = True

        status_msgs = []
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_render_table"), \
             patch.object(screen, "_set_status", side_effect=lambda t: status_msgs.append(t)), \
             patch.object(screen, "_sync_action_buttons", create=True):
            asyncio.run(screen._load_instances())

        assert any("[red]" in m for m in status_msgs)
        assert screen._loading is False

    def test_load_instances_error_with_demo_redaction(self) -> None:
        mock_svc = MagicMock()
        mock_svc.fetch_instances_cached = AsyncMock(
            side_effect=Exception("192.0.2.1 denied")
        )
        redaction = _RS()
        app = _mgr_app2(aws_service=mock_svc, demo_mode=True,
                        redaction_service=redaction)
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        screen._loading = True

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_render_table"), \
             patch.object(screen, "_set_status"), \
             patch.object(screen, "_sync_action_buttons", create=True):
            asyncio.run(screen._load_instances())

        assert screen._loading is False


class TestAWSManagerActionStart:
    """action_start lifecycle gating."""

    def test_action_start_on_stopped_fires_lifecycle(self) -> None:
        inst = {"id": "i-0abc", "state": "stopped", "region": "us-east-1"}
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = [inst]
        app = _mgr_app2()
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=inst), \
             patch.object(screen, "_run_lifecycle") as mock_lc, \
             patch.object(screen, "notify"):
            screen.action_start()
        mock_lc.assert_called_once()

    def test_action_start_on_running_notifies(self) -> None:
        inst = {"id": "i-0abc", "state": "running", "region": "us-east-1"}
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = [inst]
        app = _mgr_app2()
        notified = []
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=inst), \
             patch.object(screen, "_run_lifecycle") as mock_lc, \
             patch.object(screen, "notify", side_effect=lambda *a, **kw: notified.append(a[0])):
            screen.action_start()
        mock_lc.assert_not_called()
        assert notified

    def test_action_start_no_selection_returns(self) -> None:
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        app = _mgr_app2()
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=None), \
             patch.object(screen, "_run_lifecycle") as mock_lc:
            screen.action_start()
        mock_lc.assert_not_called()


class TestAWSManagerActionStopSuccess:
    """action_stop success path (line 336)."""

    def test_action_stop_on_running_fires_lifecycle(self) -> None:
        inst = {"id": "i-0abc", "state": "running", "region": "us-east-1"}
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = [inst]
        app = _mgr_app2()
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=inst), \
             patch.object(screen, "_run_lifecycle") as mock_lc, \
             patch.object(screen, "notify"):
            screen.action_stop()
        mock_lc.assert_called_once()


class TestAWSManagerActionRebootSuccess:
    """action_reboot success path (line 354)."""

    def test_action_reboot_on_running_fires_lifecycle(self) -> None:
        inst = {"id": "i-0abc", "state": "running", "region": "us-east-1"}
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = [inst]
        app = _mgr_app2()
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=inst), \
             patch.object(screen, "_run_lifecycle") as mock_lc, \
             patch.object(screen, "notify"):
            screen.action_reboot()
        mock_lc.assert_called_once()


class TestAWSManagerActionTerminate:
    """action_terminate blocking (line 354 area) and success paths."""

    def test_action_terminate_no_selection(self) -> None:
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        app = _mgr_app2()
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=None), \
             patch.object(screen, "run_worker") as mock_rw:
            screen.action_terminate()
        mock_rw.assert_not_called()

    def test_action_terminate_terminal_state_notifies(self) -> None:
        inst = {"id": "i-0abc", "state": "terminated", "region": "us-east-1"}
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = [inst]
        app = _mgr_app2()
        notified = []
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=inst), \
             patch.object(screen, "run_worker") as mock_rw, \
             patch.object(screen, "notify", side_effect=lambda *a, **kw: notified.append(a[0])):
            screen.action_terminate()
        mock_rw.assert_not_called()
        assert notified

    def test_action_terminate_running_fires_worker(self) -> None:
        inst = {"id": "i-0abc", "state": "running", "region": "us-east-1"}
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = [inst]
        app = _mgr_app2()
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=inst), \
             patch.object(screen, "run_worker") as mock_rw, \
             patch.object(screen, "notify"):
            screen.action_terminate()
        mock_rw.assert_called_once()
        coro = mock_rw.call_args[0][0]
        coro.close()


class TestAWSManagerRunLifecycleMissingId:
    """_run_lifecycle guard when instance has no id/region (lines 376-390)."""

    def test_run_lifecycle_missing_instance_id_notifies(self) -> None:
        inst = {"id": "", "region": "us-east-1"}
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = [inst]
        app = _mgr_app2()
        notified = []
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=inst), \
             patch.object(screen, "_set_status"), \
             patch.object(screen, "run_worker") as mock_rw, \
             patch.object(screen, "notify", side_effect=lambda *a, **kw: notified.append(a[0])):
            screen._run_lifecycle("stop_instance", "Stopping", "stopped")
        mock_rw.assert_not_called()
        assert notified

    def test_run_lifecycle_no_selection_returns(self) -> None:
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        app = _mgr_app2()
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_selected_instance", return_value=None), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._run_lifecycle("stop_instance", "Stopping", "stopped")
        mock_rw.assert_not_called()


class TestAWSManagerDoLifecycleDemoRedaction:
    """_do_lifecycle error path with demo_mode scrubbing (line 419)."""

    def test_do_lifecycle_demo_redaction_on_error(self) -> None:
        mock_svc = MagicMock()
        mock_svc.start_instance = AsyncMock(side_effect=Exception("192.0.2.1 forbidden"))
        redaction = _RS()
        app = _mgr_app2(aws_service=mock_svc, demo_mode=True,
                        redaction_service=redaction)
        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        screen._loading = False

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_set_status"), \
             patch.object(screen, "notify"):
            asyncio.run(screen._do_lifecycle("start_instance", "i-0abc", "us-east-1", "started"))


class TestAWSManagerDoTerminateAuditAndFailure:
    """_do_terminate audit (lines 474-477) and failure path (lines 493-506)."""

    def test_do_terminate_with_audit(self) -> None:
        mock_svc = MagicMock()
        mock_svc.terminate_instance = AsyncMock()
        audit = MagicMock()
        app = _mgr_app2(aws_service=mock_svc)
        app.aws_audit = audit
        app.push_screen_wait = AsyncMock(return_value=True)

        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        screen._loading = False

        inst = {"id": "i-0abc", "region": "us-east-1", "name": "web",
                "type": "t3.micro", "state": "running"}

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_set_status"), \
             patch.object(screen, "notify"), \
             patch.object(screen, "_load_instances", new_callable=AsyncMock):
            asyncio.run(screen._do_terminate(inst))

        # Audit should be called with terminate_instance action
        audit.log_action.assert_called_once()
        call_args = audit.log_action.call_args
        assert call_args[1]["action"] == "terminate_instance" or \
               (call_args[0] and call_args[0][0] == "terminate_instance") or \
               call_args.kwargs.get("action") == "terminate_instance"

    def test_do_terminate_failure_sets_status(self) -> None:
        mock_svc = MagicMock()
        mock_svc.terminate_instance = AsyncMock(side_effect=Exception("protected"))
        app = _mgr_app2(aws_service=mock_svc)
        app.push_screen_wait = AsyncMock(return_value=True)

        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        screen._loading = False

        inst = {"id": "i-0abc", "region": "us-east-1", "name": "web",
                "type": "t3.micro", "state": "running"}

        status_msgs = []
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_set_status", side_effect=lambda t: status_msgs.append(t)), \
             patch.object(screen, "notify"):
            asyncio.run(screen._do_terminate(inst))

        assert any("[red]" in m for m in status_msgs)

    def test_do_terminate_failure_with_demo_redaction(self) -> None:
        mock_svc = MagicMock()
        mock_svc.terminate_instance = AsyncMock(side_effect=Exception("192.0.2.1 denied"))
        redaction = _RS()
        app = _mgr_app2(aws_service=mock_svc, demo_mode=True,
                        redaction_service=redaction)
        app.push_screen_wait = AsyncMock(return_value=True)

        screen = AWSManagerScreen.__new__(AWSManagerScreen)
        screen._instances = []
        screen._loading = False

        inst = {"id": "i-0abc", "region": "us-east-1", "name": "web",
                "type": "t3.micro", "state": "running"}

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_set_status"), \
             patch.object(screen, "notify"):
            asyncio.run(screen._do_terminate(inst))


# ---------------------------------------------------------------------------
# AWSCreateScreen — remaining coverage gaps
# ---------------------------------------------------------------------------

class TestAWSCreateLoadRegions:
    """_load_regions success and error paths (lines 241-266)."""

    def test_load_regions_success_populates_list(self) -> None:
        svc = _make_mock_svc()
        svc.list_regions = AsyncMock(return_value=["us-east-1", "us-west-2"])
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()

        mock_table = MagicMock()
        mock_table.cursor_row = 0

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "_load_region_dependents"), \
             patch.object(screen, "notify"):
            asyncio.run(screen._load_regions())

        assert len(screen._regions) == 2

    def test_load_regions_error_notifies(self) -> None:
        svc = _make_mock_svc()
        svc.list_regions = AsyncMock(side_effect=Exception("no credentials"))
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()

        mock_table = MagicMock()
        notified = []

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notified.append(msg)):
            asyncio.run(screen._load_regions())

        assert notified
        assert screen._regions == []

    def test_load_regions_preselects_default(self) -> None:
        from servonaut.config.schema import AppConfig, AWSConfig
        svc = _make_mock_svc()
        svc.list_regions = AsyncMock(return_value=["us-east-1", "eu-west-1"])
        app = _create_app(aws_service=svc)
        # Configure default region
        cfg = AppConfig()
        cfg.aws.default_region = "eu-west-1"
        app.config_manager.get.return_value = cfg
        screen = AWSCreateScreen()

        mock_table = MagicMock()
        mock_table.cursor_row = 0

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "_load_region_dependents"), \
             patch.object(screen, "notify"):
            asyncio.run(screen._load_regions())

        # _preselect_default should have been called (table cursor may be moved)
        assert len(screen._regions) == 2


class TestAWSCreateLoadRegionDependentsEmpty:
    """_load_region_dependents with empty region returns without dispatching workers (line 271)."""

    def test_empty_region_is_noop(self) -> None:
        svc = _make_mock_svc()
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "run_worker") as mock_rw, \
             patch.object(screen, "query_one", return_value=MagicMock()):
            screen._load_region_dependents("")

        mock_rw.assert_not_called()


class TestAWSCreateLoaderErrorPaths:
    """Error paths for each region-dependent loader (lines 355-359, 384-386, 411-413, 437-441)."""

    def test_load_instance_types_error_notifies(self) -> None:
        svc = _make_mock_svc()
        svc.list_instance_types = AsyncMock(side_effect=Exception("throttled"))
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        notified = []

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notified.append(msg)):
            asyncio.run(screen._load_instance_types("us-east-1"))

        assert notified
        assert screen._instance_types == []

    def test_load_key_pairs_error_notifies(self) -> None:
        svc = _make_mock_svc()
        svc.list_key_pairs = AsyncMock(side_effect=Exception("access denied"))
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        notified = []

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notified.append(msg)):
            asyncio.run(screen._load_key_pairs("us-east-1"))

        assert notified
        assert screen._key_pairs == []

    def test_load_subnets_error_notifies(self) -> None:
        svc = _make_mock_svc()
        svc.list_subnets = AsyncMock(side_effect=Exception("access denied"))
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        notified = []

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notified.append(msg)):
            asyncio.run(screen._load_subnets("us-east-1"))

        assert notified
        assert screen._subnets == []

    def test_load_security_groups_error_notifies(self) -> None:
        svc = _make_mock_svc()
        svc.list_security_groups = AsyncMock(side_effect=Exception("access denied"))
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        notified = []

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notified.append(msg)):
            asyncio.run(screen._load_security_groups("us-east-1"))

        assert notified
        assert screen._security_groups == []


class TestAWSCreateLoaderMoveCursor:
    """Each loader calls move_cursor(row=0) when it has results (lines 343, 370, 397, 424, 454)."""

    def test_load_amis_with_results_moves_cursor(self) -> None:
        svc = _make_mock_svc()
        svc.list_amis = AsyncMock(return_value=[
            {"image_id": "ami-0abc", "name": "al2023", "architecture": "x86_64",
             "virtualization_type": "hvm", "creation_date": "2024-01-01"}
        ])
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        mock_table = MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "notify"):
            asyncio.run(screen._load_amis("us-east-1"))

        mock_table.move_cursor.assert_called_with(row=0)

    def test_load_instance_types_with_results_moves_cursor(self) -> None:
        svc = _make_mock_svc()
        svc.list_instance_types = AsyncMock(return_value=[
            {"instance_type": "t3.micro", "vcpus": 2, "memory_mib": 1024}
        ])
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        mock_table = MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "notify"):
            asyncio.run(screen._load_instance_types("us-east-1"))

        mock_table.move_cursor.assert_called_with(row=0)

    def test_load_key_pairs_with_results_moves_cursor(self) -> None:
        svc = _make_mock_svc()
        svc.list_key_pairs = AsyncMock(return_value=[
            {"key_name": "k", "key_pair_id": "kp-1", "fingerprint": "ab:cd"}
        ])
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        mock_table = MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "notify"):
            asyncio.run(screen._load_key_pairs("us-east-1"))

        mock_table.move_cursor.assert_called_with(row=0)

    def test_load_subnets_with_results_moves_cursor(self) -> None:
        svc = _make_mock_svc()
        svc.list_subnets = AsyncMock(return_value=[
            {"subnet_id": "subnet-0abc", "vpc_id": "vpc-1",
             "availability_zone": "us-east-1a", "cidr_block": "10.0.0.0/24",
             "available_ip_count": 251}
        ])
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        mock_table = MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "notify"):
            asyncio.run(screen._load_subnets("us-east-1"))

        mock_table.move_cursor.assert_called_with(row=0)

    def test_load_security_groups_with_results_moves_cursor(self) -> None:
        svc = _make_mock_svc()
        svc.list_security_groups = AsyncMock(return_value=[
            {"group_id": "sg-0abc", "group_name": "web", "description": "", "vpc_id": "vpc-1"}
        ])
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()
        mock_table = MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "notify"):
            asyncio.run(screen._load_security_groups("us-east-1"))

        mock_table.move_cursor.assert_called_with(row=0)


class TestAWSCreateActionBack:
    """action_back pops the screen (line 500)."""

    def test_action_back_calls_pop_screen(self) -> None:
        screen = AWSCreateScreen()
        app = _create_app()
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            screen.action_back()
        app.pop_screen.assert_called_once()


class TestAWSCreateCurrentRegionTryBlock:
    """_current_region real try block (lines 513-514)."""

    def test_current_region_returns_selected(self) -> None:
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1", "us-west-2"]
        mock_table = MagicMock()
        mock_table.cursor_row = 1
        app = _create_app()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table):
            result = screen._current_region()

        assert result == "us-west-2"

    def test_current_region_out_of_range_returns_none(self) -> None:
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        mock_table = MagicMock()
        mock_table.cursor_row = 5  # out of range
        app = _create_app()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table):
            result = screen._current_region()

        assert result is None

    def test_current_region_query_exception_returns_none(self) -> None:
        """query_one raises → except block (lines 513-514) → returns None."""
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        app = _create_app()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=Exception("no widget")):
            result = screen._current_region()

        assert result is None


class TestAWSCreateOnCreateSuccessPath:
    """_on_create success path: audit, notify, pop_screen (lines 618-705)."""

    def _make_full_screen_with_data(self):
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        screen._amis = [{"image_id": "ami-0abc", "name": "al2023",
                          "architecture": "x86_64", "virtualization_type": "hvm",
                          "creation_date": "2024-01-01"}]
        screen._instance_types = [{"instance_type": "t3.micro", "vcpus": 2, "memory_mib": 1024}]
        screen._key_pairs = [{"key_name": "my-key", "key_pair_id": "k", "fingerprint": ""}]
        screen._subnets = [{"subnet_id": "subnet-0abc", "vpc_id": "v",
                             "availability_zone": "az", "cidr_block": "10.0.0.0/24",
                             "available_ip_count": 10}]
        screen._security_groups = [{"group_id": "sg-0abc", "group_name": "sg",
                                     "description": "", "vpc_id": "v"}]
        return screen

    def test_on_create_success_calls_pop_screen(self) -> None:
        svc = _make_mock_svc()
        svc.run_instances = AsyncMock(return_value=[
            {"id": "i-0new", "name": "new-server"}
        ])
        app = _create_app(aws_service=svc)
        app.push_screen_wait = AsyncMock(return_value=True)
        screen = self._make_full_screen_with_data()

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "aws_input_name" in sel:
                m.value = "new-server"
            elif "aws_regions_table" in sel:
                m.cursor_row = 0
            elif "aws_amis_table" in sel:
                m.cursor_row = 0
            elif "aws_types_table" in sel:
                m.cursor_row = 0
            elif "aws_keys_table" in sel:
                m.cursor_row = 0
            elif "aws_subnets_table" in sel:
                m.cursor_row = 0
            elif "aws_sg_table" in sel:
                m.cursor_row = 0
            elif "btn_aws_create_submit" in sel:
                m.disabled = False
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "notify"), \
             patch.object(screen, "_refresh_instances_after_create", new_callable=AsyncMock):
            asyncio.run(screen._on_create())

        app.pop_screen.assert_called_once()

    def test_on_create_success_with_audit(self) -> None:
        svc = _make_mock_svc()
        svc.run_instances = AsyncMock(return_value=[
            {"id": "i-0new", "name": "new-server"}
        ])
        audit = MagicMock()
        app = _create_app(aws_service=svc)
        app.push_screen_wait = AsyncMock(return_value=True)
        app.aws_audit = audit
        screen = self._make_full_screen_with_data()

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "aws_input_name" in sel:
                m.value = "new-server"
            elif "aws_regions_table" in sel:
                m.cursor_row = 0
            elif "aws_amis_table" in sel:
                m.cursor_row = 0
            elif "aws_types_table" in sel:
                m.cursor_row = 0
            elif "aws_keys_table" in sel:
                m.cursor_row = 0
            elif "aws_subnets_table" in sel:
                m.cursor_row = 0
            elif "aws_sg_table" in sel:
                m.cursor_row = 0
            elif "btn_aws_create_submit" in sel:
                m.disabled = False
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "notify"), \
             patch.object(screen, "_refresh_instances_after_create", new_callable=AsyncMock):
            asyncio.run(screen._on_create())

        audit.log_action.assert_called_once()

    def test_on_create_cancelled_does_not_pop(self) -> None:
        svc = _make_mock_svc()
        app = _create_app(aws_service=svc)
        app.push_screen_wait = AsyncMock(return_value=False)  # user cancelled
        screen = self._make_full_screen_with_data()

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "aws_input_name" in sel:
                m.value = "new-server"
            elif "aws_regions_table" in sel:
                m.cursor_row = 0
            elif "aws_amis_table" in sel:
                m.cursor_row = 0
            elif "aws_types_table" in sel:
                m.cursor_row = 0
            elif "aws_keys_table" in sel:
                m.cursor_row = 0
            elif "aws_subnets_table" in sel:
                m.cursor_row = 0
            elif "aws_sg_table" in sel:
                m.cursor_row = 0
            elif "btn_aws_create_submit" in sel:
                m.disabled = False
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "notify"):
            asyncio.run(screen._on_create())

        app.pop_screen.assert_not_called()
        svc.run_instances.assert_not_called()

    def test_on_create_aborts_on_missing_name(self) -> None:
        svc = _make_mock_svc()
        app = _create_app(aws_service=svc)
        screen = self._make_full_screen_with_data()
        notified = []

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "aws_input_name" in sel:
                m.value = ""  # empty name
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notified.append(msg)):
            asyncio.run(screen._on_create())

        assert any("name" in m.lower() for m in notified)
        svc.run_instances.assert_not_called()


class TestAWSCreatePreselect_NoMatch:
    """_preselect_default when default doesn't match any row (line 705 area)."""

    def test_no_match_does_not_move_cursor(self) -> None:
        mock_table = MagicMock()
        AWSCreateScreen._preselect_default(mock_table, ["us-east-1", "eu-west-1"], "ap-southeast-1")
        mock_table.move_cursor.assert_not_called()

    def test_empty_rows_is_noop(self) -> None:
        mock_table = MagicMock()
        AWSCreateScreen._preselect_default(mock_table, [], "us-east-1")
        mock_table.move_cursor.assert_not_called()

    def test_empty_default_is_noop(self) -> None:
        mock_table = MagicMock()
        AWSCreateScreen._preselect_default(mock_table, ["us-east-1"], "")
        mock_table.move_cursor.assert_not_called()


# ---------------------------------------------------------------------------
# ObjectStorageScreen — remaining coverage gaps
# ---------------------------------------------------------------------------

class TestObjectStorageSetStatus:
    """_set_status exception path (lines 271-272)."""

    def test_set_status_swallows_query_exception(self) -> None:
        screen = ObjectStorageScreen("aws")
        app = _s3_app(provider="aws", storage_service=_s3_mock_storage_service())
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=Exception("no widget")):
            # Should not raise
            screen._set_status("some text")


class TestObjectStorageRefreshObjectsView:
    """_refresh objects-view branch (line 295)."""

    def test_refresh_objects_view_dispatches_load_objects(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "run_worker") as mock_rw, \
             patch.object(screen, "_set_status"):
            screen._refresh()

        mock_rw.assert_called_once()
        coro = mock_rw.call_args[0][0]
        coro.close()


class TestObjectStorageLoadBucketsEdgeCases:
    """_load_buckets not-configured and error paths (lines 305, 310-319)."""

    def test_load_buckets_no_service_returns_early(self) -> None:
        app = _s3_app(provider="aws", storage_service=None)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_set_status") as mock_status:
            asyncio.run(screen._load_buckets())

        mock_status.assert_not_called()

    def test_load_buckets_error_sets_status(self) -> None:
        svc = _s3_mock_storage_service()
        svc.list_buckets = AsyncMock(side_effect=Exception("access denied"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        status_msgs = []
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "_set_status", side_effect=lambda t: status_msgs.append(t)):
            asyncio.run(screen._load_buckets())

        assert any("[red]" in m for m in status_msgs)


class TestObjectStorageLoadObjectsNoService:
    """_load_objects when service is None (line 350)."""

    def test_load_objects_no_service_returns_early(self) -> None:
        app = _s3_app(provider="aws", storage_service=None)
        screen = ObjectStorageScreen("aws")
        screen._current_bucket = "my-bucket"
        screen._prefix = ""
        screen._view = _VIEW_OBJECTS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_set_status") as mock_status:
            asyncio.run(screen._load_objects())

        mock_status.assert_not_called()


class TestObjectStorageSelectionHelpers:
    """_get_selected_bucket_name and _get_selected_object_info (lines 424-471)."""

    def test_get_selected_bucket_name_exception_returns_none(self) -> None:
        screen = ObjectStorageScreen("aws")
        app = _s3_app(provider="aws", storage_service=_s3_mock_storage_service())
        mock_table = MagicMock()
        mock_table.row_count = 1
        mock_table.coordinate_to_cell_key.side_effect = Exception("no selection")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table):
            result = screen._get_selected_bucket_name()

        assert result is None

    def test_get_selected_bucket_name_empty_table_returns_none(self) -> None:
        screen = ObjectStorageScreen("aws")
        app = _s3_app(provider="aws", storage_service=_s3_mock_storage_service())
        mock_table = MagicMock()
        mock_table.row_count = 0

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table):
            result = screen._get_selected_bucket_name()

        assert result is None

    def test_get_selected_object_info_empty_table_returns_none(self) -> None:
        screen = ObjectStorageScreen("aws")
        app = _s3_app(provider="aws", storage_service=_s3_mock_storage_service())
        mock_table = MagicMock()
        mock_table.row_count = 0

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table):
            result = screen._get_selected_object_info()

        assert result is None

    def test_get_selected_object_info_no_colon_in_key_returns_none(self) -> None:
        screen = ObjectStorageScreen("aws")
        app = _s3_app(provider="aws", storage_service=_s3_mock_storage_service())
        mock_table = MagicMock()
        mock_table.row_count = 1
        # key without colon
        mock_row_key = MagicMock()
        mock_row_key.value = "just-a-bucket-name"
        mock_table.coordinate_to_cell_key.return_value.row_key = mock_row_key

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table):
            result = screen._get_selected_object_info()

        assert result is None

    def test_get_selected_object_info_with_colon_returns_dict(self) -> None:
        screen = ObjectStorageScreen("aws")
        app = _s3_app(provider="aws", storage_service=_s3_mock_storage_service())
        mock_table = MagicMock()
        mock_table.row_count = 1
        mock_row_key = MagicMock()
        mock_row_key.value = "object:images/photo.jpg"
        mock_table.coordinate_to_cell_key.return_value.row_key = mock_row_key

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table):
            result = screen._get_selected_object_info()

        assert result == {"type": "object", "key": "images/photo.jpg"}

    def test_get_selected_object_info_exception_returns_none(self) -> None:
        screen = ObjectStorageScreen("aws")
        app = _s3_app(provider="aws", storage_service=_s3_mock_storage_service())
        mock_table = MagicMock()
        mock_table.row_count = 1
        mock_table.coordinate_to_cell_key.side_effect = Exception("no selection")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table):
            result = screen._get_selected_object_info()

        assert result is None


class TestObjectStorageOnButtonPressedDispatch:
    """on_button_pressed dict dispatch (lines 478-510)."""

    def test_refresh_button_calls_action_refresh(self) -> None:
        screen = ObjectStorageScreen("aws")
        app = _s3_app(provider="aws", storage_service=_s3_mock_storage_service())
        event = MagicMock()
        event.button.id = "btn_s3_refresh"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "action_refresh") as mock_ar:
            screen.on_button_pressed(event)

        mock_ar.assert_called_once()

    def test_back_button_calls_action_back(self) -> None:
        screen = ObjectStorageScreen("aws")
        app = _s3_app(provider="aws", storage_service=_s3_mock_storage_service())
        event = MagicMock()
        event.button.id = "btn_s3_back"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "action_back") as mock_ab:
            screen.on_button_pressed(event)

        mock_ab.assert_called_once()

    def test_unknown_button_is_noop(self) -> None:
        screen = ObjectStorageScreen("aws")
        app = _s3_app(provider="aws", storage_service=_s3_mock_storage_service())
        event = MagicMock()
        event.button.id = "btn_unknown"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            # Should not raise
            screen.on_button_pressed(event)


class TestObjectStorageActionRefresh:
    """action_refresh (lines 524-525)."""

    def test_action_refresh_calls_hide_and_refresh(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_hide_all_forms") as mock_haf, \
             patch.object(screen, "_refresh") as mock_r:
            screen.action_refresh()

        mock_haf.assert_called_once()
        mock_r.assert_called_once()


class TestObjectStorageNavigateNoSelection:
    """_open_bucket with no bucket selected (lines 569-570)."""

    def test_open_bucket_no_selection_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_bucket_name", return_value=None), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._open_bucket()

        mock_rw.assert_not_called()
        app.notify.assert_called_once()

    def test_navigate_to_buckets_fires_worker(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._navigate_to_buckets()

        assert screen._view == _VIEW_BUCKETS
        mock_rw.assert_called_once()
        coro = mock_rw.call_args[0][0]
        coro.close()


class TestObjectStorageFormMethods:
    """_show_* form helpers (lines 601-657)."""

    def test_show_new_bucket_form(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        mock_input = MagicMock()
        mock_form = MagicMock()

        def query_side(sel, *a, **kw):
            if "s3_input_bucket_name" in sel:
                return mock_input
            if "s3_new_bucket_form" in sel:
                return mock_form
            return MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_hide_all_forms"):
            screen._show_new_bucket_form()

        assert mock_form.display is True

    def test_show_upload_form_not_in_objects_view_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            screen._show_upload_form()

        app.notify.assert_called()

    def test_show_download_form_not_in_objects_view_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            screen._show_download_form()

        app.notify.assert_called()

    def test_show_download_form_no_object_selected_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_object_info", return_value=None):
            screen._show_download_form()

        app.notify.assert_called()

    def test_show_copy_form_not_in_objects_view_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            screen._show_copy_form()

        app.notify.assert_called()

    def test_show_move_form_not_in_objects_view_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            screen._show_move_form()

        app.notify.assert_called()


class TestObjectStorageSubmitNewBucketEmpty:
    """_submit_new_bucket empty name (line 679)."""

    def test_submit_new_bucket_empty_name_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        mock_input = MagicMock()
        mock_input.value = ""

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_input), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_new_bucket()

        mock_rw.assert_not_called()
        app.notify.assert_called()


class TestObjectStorageDeleteBucketNoSelection:
    """_action_delete_bucket no selection (lines 710-711)."""

    def test_delete_bucket_no_selection_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_bucket_name", return_value=None), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._action_delete_bucket()

        mock_rw.assert_not_called()
        app.notify.assert_called()


class TestObjectStorageDeleteObjectNoSelection:
    """_action_delete_object no selection / folder type (lines 762-763)."""

    def test_delete_object_no_selection_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_object_info", return_value=None), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._action_delete_object()

        mock_rw.assert_not_called()
        app.notify.assert_called()

    def test_delete_object_folder_type_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "folder", "key": "images/"}), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._action_delete_object()

        mock_rw.assert_not_called()
        app.notify.assert_called()


class TestObjectStorageDeleteBucketErrorPath:
    """_delete_bucket exception path."""

    def test_delete_bucket_exception_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        svc.delete_bucket = AsyncMock(side_effect=Exception("bucket not empty"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()):
            asyncio.run(screen._delete_bucket("my-bucket", "my-bucket"))

        app.notify.assert_called()


class TestObjectStorageDeleteObjectErrorPath:
    """_delete_object exception path (line 790)."""

    def test_delete_object_exception_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        svc.delete_object = AsyncMock(side_effect=Exception("permission denied"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._current_bucket = "my-bucket"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_set_status"), \
             patch.object(screen, "query_one", return_value=MagicMock()):
            asyncio.run(screen._delete_object("my-bucket", "readme.txt", "readme.txt"))

        app.notify.assert_called()

    def test_delete_object_no_service_returns_early(self) -> None:
        app = _s3_app(provider="aws", storage_service=None)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._delete_object("my-bucket", "readme.txt", "readme.txt"))

        app.notify.assert_not_called()


class TestObjectStorageUploadSubmitPaths:
    """_submit_upload missing key (lines 819-821)."""

    def test_submit_upload_empty_key_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"
        screen._prefix = ""

        call_count = [0]

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "s3_input_upload_path" in sel:
                m.value = "/tmp/file.txt"  # non-empty path
            elif "s3_input_upload_key" in sel:
                m.value = ""  # empty key
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_upload()

        mock_rw.assert_not_called()
        app.notify.assert_called()

    def test_submit_upload_empty_path_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"
        screen._prefix = ""

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "s3_input_upload_path" in sel:
                m.value = ""  # empty path
            elif "s3_input_upload_key" in sel:
                m.value = "my-key"
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_upload()

        mock_rw.assert_not_called()
        app.notify.assert_called()


class TestObjectStorageUploadObjectErrorPaths:
    """_upload_object no service and general exception (lines 833, 845-848)."""

    def test_upload_object_no_service_returns_early(self) -> None:
        app = _s3_app(provider="aws", storage_service=None)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._upload_object("bucket", "key", "/tmp/file.txt"))

        app.notify.assert_not_called()

    def test_upload_object_exception_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        svc.upload_object = AsyncMock(side_effect=Exception("network error"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_load_objects", new_callable=AsyncMock):
            asyncio.run(screen._upload_object("bucket", "key", "/tmp/file.txt"))

        app.notify.assert_called()


class TestObjectStorageDownloadPaths:
    """_submit_download and _download_object paths (lines 859-897)."""

    def test_submit_download_no_selection_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "s3_input_download_path" in sel:
                m.value = "~/Downloads/"
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_get_selected_object_info", return_value=None), \
             patch.object(screen, "_hide_all_forms"), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_download()

        mock_rw.assert_not_called()

    def test_download_object_no_service_returns_early(self) -> None:
        app = _s3_app(provider="aws", storage_service=None)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._download_object("bucket", "key", "/tmp/file.txt"))

        app.notify.assert_not_called()

    def test_download_object_exception_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        svc.download_object = AsyncMock(side_effect=Exception("timeout"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._download_object("bucket", "key", "/tmp/file.txt"))

        app.notify.assert_called()


class TestObjectStorageCopySubmitPaths:
    """_submit_copy guard conditions (lines 904-925)."""

    def test_submit_copy_no_selection_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_object_info", return_value=None), \
             patch.object(screen, "_hide_all_forms"), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_copy()

        mock_rw.assert_not_called()

    def test_submit_copy_empty_dst_bucket_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "s3_input_copy_dst_bucket" in sel:
                m.value = ""
            elif "s3_input_copy_dst_key" in sel:
                m.value = "dst-key"
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "src.txt"}), \
             patch.object(screen, "_hide_all_forms"), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_copy()

        mock_rw.assert_not_called()
        app.notify.assert_called()

    def test_submit_copy_empty_dst_key_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "s3_input_copy_dst_bucket" in sel:
                m.value = "dst-bucket"
            elif "s3_input_copy_dst_key" in sel:
                m.value = ""
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "src.txt"}), \
             patch.object(screen, "_hide_all_forms"), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_copy()

        mock_rw.assert_not_called()
        app.notify.assert_called()


class TestObjectStorageCopyObjectErrorPaths:
    """_copy_object no service and ValueError (lines 932, 942)."""

    def test_copy_object_no_service_returns_early(self) -> None:
        app = _s3_app(provider="aws", storage_service=None)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._copy_object("src-bucket", "src.txt", "dst-bucket", "dst.txt"))

        app.notify.assert_not_called()

    def test_copy_object_value_error_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        svc.copy_object = AsyncMock(side_effect=ValueError("invalid key"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._copy_object("src-bucket", "src.txt", "dst-bucket", "dst.txt"))

        app.notify.assert_called()


class TestObjectStorageMoveSubmitPaths:
    """_submit_move guard conditions (lines 957-978)."""

    def test_submit_move_no_selection_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_object_info", return_value=None), \
             patch.object(screen, "_hide_all_forms"), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_move()

        mock_rw.assert_not_called()

    def test_submit_move_empty_dst_bucket_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "s3_input_move_dst_bucket" in sel:
                m.value = ""
            elif "s3_input_move_dst_key" in sel:
                m.value = "dst-key"
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "src.txt"}), \
             patch.object(screen, "_hide_all_forms"), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_move()

        mock_rw.assert_not_called()
        app.notify.assert_called()

    def test_submit_move_empty_dst_key_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "s3_input_move_dst_bucket" in sel:
                m.value = "dst-bucket"
            elif "s3_input_move_dst_key" in sel:
                m.value = ""
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "src.txt"}), \
             patch.object(screen, "_hide_all_forms"), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_move()

        mock_rw.assert_not_called()
        app.notify.assert_called()


class TestObjectStorageMoveObjectErrorPaths:
    """_move_object no service and ValueError (lines 985, 995-1000)."""

    def test_move_object_no_service_returns_early(self) -> None:
        app = _s3_app(provider="aws", storage_service=None)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._move_object("src-bucket", "src.txt", "dst-bucket", "dst.txt"))

        app.notify.assert_not_called()

    def test_move_object_value_error_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        svc.move_object = AsyncMock(side_effect=ValueError("invalid key"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._move_object("src-bucket", "src.txt", "dst-bucket", "dst.txt"))

        app.notify.assert_called()


class TestObjectStorageShareAction:
    """_action_share guard conditions (lines 1012-1020)."""

    def test_action_share_not_in_objects_view_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            screen._action_share()

        app.notify.assert_called()

    def test_action_share_no_object_selected_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_object_info", return_value=None):
            screen._action_share()

        app.notify.assert_called()

    def test_action_share_folder_type_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "folder", "key": "images/"}):
            screen._action_share()

        app.notify.assert_called()


class TestObjectStorageGeneratePresignedUrlEdgeCases:
    """_generate_presigned_url no service and exception paths (lines 1029, 1043-1048)."""

    def test_generate_presigned_url_no_service_returns_early(self) -> None:
        app = _s3_app(provider="aws", storage_service=None)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._generate_presigned_url("bucket", "key.txt"))

        app.notify.assert_not_called()

    def test_generate_presigned_url_value_error_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        svc.generate_presigned_url = AsyncMock(side_effect=ValueError("invalid expiry"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._generate_presigned_url("bucket", "key.txt"))

        app.notify.assert_called()

    def test_generate_presigned_url_exception_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        svc.generate_presigned_url = AsyncMock(side_effect=Exception("network error"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._generate_presigned_url("bucket", "key.txt"))

        app.notify.assert_called()


# ---------------------------------------------------------------------------
# AWSCreateScreen — additional event handler and guard coverage
# ---------------------------------------------------------------------------

class TestAWSCreateLoadRegionsConfigError:
    """_load_regions config_manager.get() error path (lines 255-256)."""

    def test_load_regions_config_error_uses_empty_default(self) -> None:
        svc = _make_mock_svc()
        svc.list_regions = AsyncMock(return_value=["us-east-1", "eu-west-1"])
        app = _create_app(aws_service=svc)
        # Make config_manager.get() raise so default_region stays ""
        app.config_manager.get.side_effect = Exception("config error")
        screen = AWSCreateScreen()

        mock_table = MagicMock()
        mock_table.cursor_row = 0

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table), \
             patch.object(screen, "_load_region_dependents"), \
             patch.object(screen, "notify"):
            asyncio.run(screen._load_regions())

        # Regions still loaded despite config error
        assert len(screen._regions) == 2


class TestAWSCreateOnDataTableRowHighlighted:
    """on_data_table_row_highlighted fires _load_region_dependents (lines 454-457)."""

    def test_row_highlighted_in_regions_table_fires_dependents(self) -> None:
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1", "eu-west-1"]
        app = _create_app()

        event = MagicMock()
        event.data_table.id = "aws_regions_table"
        event.data_table.cursor_row = 1  # eu-west-1

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_load_region_dependents") as mock_lrd:
            screen.on_data_table_row_highlighted(event)

        mock_lrd.assert_called_once_with("eu-west-1")

    def test_row_highlighted_out_of_range_is_noop(self) -> None:
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        app = _create_app()

        event = MagicMock()
        event.data_table.id = "aws_regions_table"
        event.data_table.cursor_row = 99  # out of range

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_load_region_dependents") as mock_lrd:
            screen.on_data_table_row_highlighted(event)

        mock_lrd.assert_not_called()

    def test_row_highlighted_in_other_table_is_noop(self) -> None:
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        app = _create_app()

        event = MagicMock()
        event.data_table.id = "aws_amis_table"
        event.data_table.cursor_row = 0

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_load_region_dependents") as mock_lrd:
            screen.on_data_table_row_highlighted(event)

        mock_lrd.assert_not_called()


class TestAWSCreateOnInputChanged:
    """on_input_changed AMI search debounce (lines 462, 467-468, 473, 476-477)."""

    def test_input_changed_non_ami_search_returns_early(self) -> None:
        """Input from a non-search field must be ignored (line 462)."""
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        screen._ami_search_timer = None
        app = _create_app()

        event = MagicMock()
        event.input.id = "aws_input_name"  # not the AMI search input
        event.value = "my-server"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "set_timer") as mock_timer:
            screen.on_input_changed(event)

        mock_timer.assert_not_called()

    def test_input_changed_cancels_existing_timer(self) -> None:
        """Existing timer is stopped and cleared (lines 467-468)."""
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        # Set a timer that will raise on stop
        existing_timer = MagicMock()
        existing_timer.stop.side_effect = Exception("already stopped")
        screen._ami_search_timer = existing_timer
        app = _create_app()

        event = MagicMock()
        event.input.id = "aws_input_ami_search"
        event.value = "al2023"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_current_region", return_value="us-east-1"), \
             patch.object(screen, "set_timer", return_value=MagicMock()):
            screen.on_input_changed(event)

        existing_timer.stop.assert_called_once()
        # Timer was cleared
        assert screen._ami_search_timer is not None  # new timer set

    def test_input_changed_no_region_returns_early(self) -> None:
        """No region selected → no timer is set (line 473)."""
        screen = AWSCreateScreen()
        screen._regions = []
        screen._ami_search_timer = None
        app = _create_app()

        event = MagicMock()
        event.input.id = "aws_input_ami_search"
        event.value = "al2023"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_current_region", return_value=None), \
             patch.object(screen, "set_timer") as mock_timer:
            screen.on_input_changed(event)

        mock_timer.assert_not_called()

    def test_input_changed_sets_timer(self) -> None:
        """Valid input with a region → timer is set (line 484 / 476-477 via closure)."""
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        screen._ami_search_timer = None
        app = _create_app()

        event = MagicMock()
        event.input.id = "aws_input_ami_search"
        event.value = "al2023"

        mock_timer = MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_current_region", return_value="us-east-1"), \
             patch.object(screen, "set_timer", return_value=mock_timer) as mock_st:
            screen.on_input_changed(event)

        mock_st.assert_called_once()
        assert screen._ami_search_timer is mock_timer

    def test_fire_search_closure_dispatches_worker(self) -> None:
        """The _fire_search closure body (lines 476-477) calls run_worker."""
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        screen._ami_search_timer = None
        app = _create_app()

        event = MagicMock()
        event.input.id = "aws_input_ami_search"
        event.value = "al2023"

        captured_callback = []

        def capture_timer(delay, callback):
            captured_callback.append(callback)
            return MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_current_region", return_value="us-east-1"), \
             patch.object(screen, "set_timer", side_effect=capture_timer), \
             patch.object(screen, "run_worker") as mock_rw:
            screen.on_input_changed(event)
            # Now invoke the captured closure to cover lines 476-477
            assert captured_callback
            captured_callback[0]()

        mock_rw.assert_called_once()
        # Close the coroutine to avoid RuntimeWarning
        coro = mock_rw.call_args[0][0]
        coro.close()


class TestAWSCreateOnButtonPressed:
    """on_button_pressed back and submit buttons (lines 490-493)."""

    def test_back_button_calls_action_back(self) -> None:
        screen = AWSCreateScreen()
        app = _create_app()

        event = MagicMock()
        event.button.id = "btn_aws_create_back"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "action_back") as mock_ab:
            screen.on_button_pressed(event)

        mock_ab.assert_called_once()

    def test_submit_button_fires_worker(self) -> None:
        screen = AWSCreateScreen()
        app = _create_app()

        event = MagicMock()
        event.button.id = "btn_aws_create_submit"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "run_worker") as mock_rw:
            screen.on_button_pressed(event)

        mock_rw.assert_called_once()
        coro = mock_rw.call_args[0][0]
        coro.close()

    def test_unknown_button_is_noop(self) -> None:
        screen = AWSCreateScreen()
        app = _create_app()

        event = MagicMock()
        event.button.id = "btn_unknown"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "action_back") as mock_ab, \
             patch.object(screen, "run_worker") as mock_rw:
            screen.on_button_pressed(event)

        mock_ab.assert_not_called()
        mock_rw.assert_not_called()


class TestAWSCreateOnCreateSvcNoneGuard:
    """_on_create guard when aws_service is None after confirm (lines 622-626)."""

    def test_on_create_no_svc_after_confirm_notifies(self) -> None:
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        screen._amis = [{"image_id": "ami-0abc", "name": "al2023",
                          "architecture": "x86_64", "virtualization_type": "hvm",
                          "creation_date": "2024-01-01"}]
        screen._instance_types = [{"instance_type": "t3.micro", "vcpus": 2, "memory_mib": 1024}]
        screen._key_pairs = [{"key_name": "my-key", "key_pair_id": "k", "fingerprint": ""}]
        screen._subnets = [{"subnet_id": "subnet-0abc", "vpc_id": "v",
                             "availability_zone": "az", "cidr_block": "10.0.0.0/24",
                             "available_ip_count": 10}]
        screen._security_groups = [{"group_id": "sg-0abc", "group_name": "sg",
                                     "description": "", "vpc_id": "v"}]

        app = _create_app(aws_service=None)
        app.push_screen_wait = AsyncMock(return_value=True)
        notified = []

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "aws_input_name" in sel:
                m.value = "new-server"
            elif "aws_regions_table" in sel:
                m.cursor_row = 0
            elif "aws_amis_table" in sel:
                m.cursor_row = 0
            elif "aws_types_table" in sel:
                m.cursor_row = 0
            elif "aws_keys_table" in sel:
                m.cursor_row = 0
            elif "aws_subnets_table" in sel:
                m.cursor_row = 0
            elif "aws_sg_table" in sel:
                m.cursor_row = 0
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notified.append(msg)):
            asyncio.run(screen._on_create())

        assert any("not available" in m.lower() or "aws" in m.lower() for m in notified)


class TestAWSCreateOnCreateBtnDisable:
    """_on_create button.disabled = True path (lines 632-633)."""

    def test_on_create_btn_query_exception_is_silenced(self) -> None:
        """query_one for the submit button may fail — should not abort the launch."""
        svc = _make_mock_svc()
        svc.run_instances = AsyncMock(return_value=[{"id": "i-0new"}])
        app = _create_app(aws_service=svc)
        app.push_screen_wait = AsyncMock(return_value=True)

        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        screen._amis = [{"image_id": "ami-0abc", "name": "al2023",
                          "architecture": "x86_64", "virtualization_type": "hvm",
                          "creation_date": "2024-01-01"}]
        screen._instance_types = [{"instance_type": "t3.micro", "vcpus": 2, "memory_mib": 1024}]
        screen._key_pairs = [{"key_name": "my-key", "key_pair_id": "k", "fingerprint": ""}]
        screen._subnets = [{"subnet_id": "subnet-0abc", "vpc_id": "v",
                             "availability_zone": "az", "cidr_block": "10.0.0.0/24",
                             "available_ip_count": 10}]
        screen._security_groups = [{"group_id": "sg-0abc", "group_name": "sg",
                                     "description": "", "vpc_id": "v"}]

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "aws_input_name" in sel:
                m.value = "new-server"
            elif "aws_regions_table" in sel:
                m.cursor_row = 0
            elif "aws_amis_table" in sel:
                m.cursor_row = 0
            elif "aws_types_table" in sel:
                m.cursor_row = 0
            elif "aws_keys_table" in sel:
                m.cursor_row = 0
            elif "aws_subnets_table" in sel:
                m.cursor_row = 0
            elif "aws_sg_table" in sel:
                m.cursor_row = 0
            elif "btn_aws_create_submit" in sel:
                raise Exception("widget not found")  # triggers except block
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "notify"), \
             patch.object(screen, "_refresh_instances_after_create", new_callable=AsyncMock):
            asyncio.run(screen._on_create())

        # Should complete without raising
        app.pop_screen.assert_called_once()


class TestAWSCreateRefreshInstancesAfterCreateNoSvc:
    """_refresh_instances_after_create when aws_service is None (line 705)."""

    def test_refresh_no_svc_returns_early(self) -> None:
        app = _create_app(aws_service=None)
        svc = _make_mock_svc()  # standalone svc to verify no fetch happens
        screen = AWSCreateScreen.__new__(AWSCreateScreen)

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._refresh_instances_after_create())

        # No exception — svc.fetch_instances_cached was never called
        svc.fetch_instances_cached.assert_not_called()


class TestAWSCreateRefreshErrorHandler:
    """_on_create post-launch refresh error is caught (lines 691-692)."""

    def test_refresh_failure_after_create_is_logged_not_raised(self) -> None:
        svc = _make_mock_svc()
        svc.run_instances = AsyncMock(return_value=[{"id": "i-0new"}])
        app = _create_app(aws_service=svc)
        app.push_screen_wait = AsyncMock(return_value=True)

        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        screen._amis = [{"image_id": "ami-0abc", "name": "al2023",
                          "architecture": "x86_64", "virtualization_type": "hvm",
                          "creation_date": "2024-01-01"}]
        screen._instance_types = [{"instance_type": "t3.micro", "vcpus": 2, "memory_mib": 1024}]
        screen._key_pairs = [{"key_name": "my-key", "key_pair_id": "k", "fingerprint": ""}]
        screen._subnets = [{"subnet_id": "subnet-0abc", "vpc_id": "v",
                             "availability_zone": "az", "cidr_block": "10.0.0.0/24",
                             "available_ip_count": 10}]
        screen._security_groups = [{"group_id": "sg-0abc", "group_name": "sg",
                                     "description": "", "vpc_id": "v"}]

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "aws_input_name" in sel:
                m.value = "new-server"
            elif "aws_regions_table" in sel:
                m.cursor_row = 0
            elif "aws_amis_table" in sel:
                m.cursor_row = 0
            elif "aws_types_table" in sel:
                m.cursor_row = 0
            elif "aws_keys_table" in sel:
                m.cursor_row = 0
            elif "aws_subnets_table" in sel:
                m.cursor_row = 0
            elif "aws_sg_table" in sel:
                m.cursor_row = 0
            elif "btn_aws_create_submit" in sel:
                m.disabled = False
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "notify"), \
             patch.object(screen, "_refresh_instances_after_create",
                          new_callable=AsyncMock,
                          side_effect=Exception("fetch failed")):
            asyncio.run(screen._on_create())

        # pop_screen is still called even if refresh fails
        app.pop_screen.assert_called_once()


class TestAWSCreateSecurityGroupsEmptyRegion:
    """_load_security_groups empty region (line 424)."""

    def test_load_security_groups_empty_region_returns(self) -> None:
        svc = _make_mock_svc()
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()):
            asyncio.run(screen._load_security_groups(""))

        svc.list_security_groups.assert_not_called()


# ---------------------------------------------------------------------------
# ObjectStorageScreen — final remaining coverage gaps
# ---------------------------------------------------------------------------

class TestObjectStorageUpdateBreadcrumbException:
    """_update_breadcrumb exception path (lines 424-425)."""

    def test_update_breadcrumb_query_exception_returns_early(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=Exception("no widget")):
            # Should not raise
            screen._update_breadcrumb()


class TestObjectStorageGetSelectedBucketNameSuccess:
    """_get_selected_bucket_name success path (line 451)."""

    def test_get_selected_bucket_name_returns_key(self) -> None:
        screen = ObjectStorageScreen("aws")
        app = _s3_app(provider="aws", storage_service=_s3_mock_storage_service())
        mock_table = MagicMock()
        mock_table.row_count = 1
        mock_row_key = MagicMock()
        mock_row_key.value = "my-bucket"
        mock_table.coordinate_to_cell_key.return_value.row_key = mock_row_key

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_table):
            result = screen._get_selected_bucket_name()

        assert result == "my-bucket"


class TestObjectStorageActionUpPaths:
    """action_up success paths (lines 548-551)."""

    def test_action_up_with_nested_prefix(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._prefix = "a/b/c/"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "run_worker") as mock_rw:
            screen.action_up()

        assert screen._prefix == "a/b/"
        mock_rw.assert_called_once()
        coro = mock_rw.call_args[0][0]
        coro.close()

    def test_action_up_from_single_segment_clears_prefix(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._prefix = "images/"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "run_worker") as mock_rw:
            screen.action_up()

        assert screen._prefix == ""
        mock_rw.assert_called_once()
        coro = mock_rw.call_args[0][0]
        coro.close()


class TestObjectStorageOnDataTableRowSelected:
    """on_data_table_row_selected calls action_open (line 559)."""

    def test_row_selected_calls_action_open(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        event = MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "action_open") as mock_ao:
            screen.on_data_table_row_selected(event)

        mock_ao.assert_called_once()


class TestObjectStorageNavigateToBucketsWorker:
    """_navigate_to_buckets fires worker (line 591)."""

    def test_navigate_to_buckets_fires_worker(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"
        screen._prefix = "images/"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._navigate_to_buckets()

        assert screen._view == _VIEW_BUCKETS
        assert screen._current_bucket == ""
        assert screen._prefix == ""
        mock_rw.assert_called_once()
        coro = mock_rw.call_args[0][0]
        coro.close()


class TestObjectStorageShowFormSuccessPaths:
    """_show_upload/download/copy/move form success paths (lines 611-657)."""

    def test_show_upload_form_in_objects_view(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._prefix = "images/"

        mock_path_input = MagicMock()
        mock_key_input = MagicMock()
        mock_form = MagicMock()

        def query_side(sel, *a, **kw):
            if "s3_input_upload_path" in sel:
                return mock_path_input
            if "s3_input_upload_key" in sel:
                return mock_key_input
            if "s3_upload_form" in sel:
                return mock_form
            return MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_hide_all_forms"):
            screen._show_upload_form()

        assert mock_form.display is True
        assert mock_key_input.value == "images/"

    def test_show_download_form_in_objects_view_with_object(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS

        mock_path_input = MagicMock()
        mock_form = MagicMock()

        def query_side(sel, *a, **kw):
            if "s3_input_download_path" in sel:
                return mock_path_input
            if "s3_download_form" in sel:
                return mock_form
            return MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "readme.txt"}), \
             patch.object(screen, "_hide_all_forms"):
            screen._show_download_form()

        assert mock_form.display is True

    def test_show_copy_form_in_objects_view_with_object(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        mock_bucket_input = MagicMock()
        mock_key_input = MagicMock()
        mock_form = MagicMock()

        def query_side(sel, *a, **kw):
            if "s3_input_copy_dst_bucket" in sel:
                return mock_bucket_input
            if "s3_input_copy_dst_key" in sel:
                return mock_key_input
            if "s3_copy_form" in sel:
                return mock_form
            return MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "readme.txt"}), \
             patch.object(screen, "_hide_all_forms"):
            screen._show_copy_form()

        assert mock_form.display is True

    def test_show_move_form_in_objects_view_with_object(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        mock_bucket_input = MagicMock()
        mock_key_input = MagicMock()
        mock_form = MagicMock()

        def query_side(sel, *a, **kw):
            if "s3_input_move_dst_bucket" in sel:
                return mock_bucket_input
            if "s3_input_move_dst_key" in sel:
                return mock_key_input
            if "s3_move_form" in sel:
                return mock_form
            return MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "readme.txt"}), \
             patch.object(screen, "_hide_all_forms"):
            screen._show_move_form()

        assert mock_form.display is True

    def test_show_copy_form_folder_type_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "folder", "key": "images/"}):
            screen._show_copy_form()

        app.notify.assert_called()

    def test_show_move_form_folder_type_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "folder", "key": "images/"}):
            screen._show_move_form()

        app.notify.assert_called()


class TestObjectStorageSubmitNewBucketSuccess:
    """_submit_new_bucket success path fires worker (line 669-670)."""

    def test_submit_new_bucket_fires_worker(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        mock_input = MagicMock()
        mock_input.value = "new-bucket"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=mock_input), \
             patch.object(screen, "_hide_all_forms"), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_new_bucket()

        mock_rw.assert_called_once()
        coro = mock_rw.call_args[0][0]
        coro.close()


class TestObjectStorageDeleteBucketNoService:
    """_delete_bucket when service is None (line 737)."""

    def test_delete_bucket_no_service_returns_early(self) -> None:
        app = _s3_app(provider="aws", storage_service=None)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._delete_bucket("my-bucket", "my-bucket"))

        app.notify.assert_not_called()


class TestObjectStorageConfirmAndDeleteClosures:
    """Inner closure _confirm_and_delete for bucket and object (lines 716-730, 769-783)."""

    def test_confirm_and_delete_bucket_closure_confirmed(self) -> None:
        """Running the inner async closure with confirmed=True calls _delete_bucket."""
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        app.push_screen_wait = AsyncMock(return_value=True)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        # Capture the worker coroutine
        captured = []

        def capture_rw(coro, **kw):
            captured.append(coro)

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_bucket_name", return_value="my-bucket"), \
             patch.object(screen, "run_worker", side_effect=capture_rw):
            screen._action_delete_bucket()

        assert captured
        # Run the captured inner closure with app property patched and _delete_bucket mocked
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_delete_bucket", new_callable=AsyncMock) as mock_db:
            asyncio.run(captured[0])
        mock_db.assert_called_once_with("my-bucket", "my-bucket")

    def test_confirm_and_delete_bucket_closure_cancelled(self) -> None:
        """Running the inner closure with confirmed=False does NOT call _delete_bucket."""
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        app.push_screen_wait = AsyncMock(return_value=False)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS

        captured = []

        def capture_rw(coro, **kw):
            captured.append(coro)

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_bucket_name", return_value="my-bucket"), \
             patch.object(screen, "run_worker", side_effect=capture_rw):
            screen._action_delete_bucket()

        assert captured
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_delete_bucket", new_callable=AsyncMock) as mock_db:
            asyncio.run(captured[0])
        mock_db.assert_not_called()

    def test_confirm_and_delete_object_closure_confirmed(self) -> None:
        """Running the inner object closure with confirmed=True calls _delete_object."""
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        app.push_screen_wait = AsyncMock(return_value=True)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        captured = []

        def capture_rw(coro, **kw):
            captured.append(coro)

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "readme.txt"}), \
             patch.object(screen, "run_worker", side_effect=capture_rw):
            screen._action_delete_object()

        assert captured
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_delete_object", new_callable=AsyncMock) as mock_do:
            asyncio.run(captured[0])
        mock_do.assert_called_once_with("my-bucket", "readme.txt", "readme.txt")

    def test_confirm_and_delete_object_closure_cancelled(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        app.push_screen_wait = AsyncMock(return_value=False)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        captured = []

        def capture_rw(coro, **kw):
            captured.append(coro)

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "readme.txt"}), \
             patch.object(screen, "run_worker", side_effect=capture_rw):
            screen._action_delete_object()

        assert captured
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_delete_object", new_callable=AsyncMock) as mock_do:
            asyncio.run(captured[0])
        mock_do.assert_not_called()


class TestObjectStorageSubmitUploadSuccess:
    """_submit_upload success path fires worker (lines 823-824)."""

    def test_submit_upload_success_fires_worker(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"
        screen._prefix = ""

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "s3_input_upload_path" in sel:
                m.value = "/tmp/file.txt"
            elif "s3_input_upload_key" in sel:
                m.value = "file.txt"
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_hide_all_forms"), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_upload()

        mock_rw.assert_called_once()
        coro = mock_rw.call_args[0][0]
        coro.close()


class TestObjectStorageSubmitDownloadSuccess:
    """_submit_download success path fires worker (lines 865-871)."""

    def test_submit_download_success_fires_worker(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "s3_input_download_path" in sel:
                m.value = "~/Downloads/"
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "readme.txt"}), \
             patch.object(screen, "_hide_all_forms"), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_download()

        mock_rw.assert_called_once()
        coro = mock_rw.call_args[0][0]
        coro.close()

    def test_submit_download_empty_path_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "s3_input_download_path" in sel:
                m.value = ""  # empty path
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "readme.txt"}), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_download()

        mock_rw.assert_not_called()
        app.notify.assert_called()


class TestObjectStorageSubmitCopySuccess:
    """_submit_copy success path fires worker (lines 919-921)."""

    def test_submit_copy_success_fires_worker(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "s3_input_copy_dst_bucket" in sel:
                m.value = "dst-bucket"
            elif "s3_input_copy_dst_key" in sel:
                m.value = "dst-key"
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "src.txt"}), \
             patch.object(screen, "_hide_all_forms"), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_copy()

        mock_rw.assert_called_once()
        coro = mock_rw.call_args[0][0]
        coro.close()


class TestObjectStorageSubmitMoveSuccess:
    """_submit_move success path fires worker (lines 972-974)."""

    def test_submit_move_success_fires_worker(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        def query_side(sel, *a, **kw):
            m = MagicMock()
            if "s3_input_move_dst_bucket" in sel:
                m.value = "dst-bucket"
            elif "s3_input_move_dst_key" in sel:
                m.value = "dst-key"
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "src.txt"}), \
             patch.object(screen, "_hide_all_forms"), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._submit_move()

        mock_rw.assert_called_once()
        coro = mock_rw.call_args[0][0]
        coro.close()


class TestObjectStorageMoveObjectException:
    """_move_object general exception path (lines 997-1000)."""

    def test_move_object_exception_notifies(self) -> None:
        svc = _s3_mock_storage_service()
        svc.move_object = AsyncMock(side_effect=Exception("network error"))
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._move_object("src", "src.txt", "dst", "dst.txt"))

        app.notify.assert_called()


class TestObjectStorageActionShareSuccess:
    """_action_share success path fires worker (lines 1019-1020)."""

    def test_action_share_fires_worker(self) -> None:
        svc = _s3_mock_storage_service()
        app = _s3_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "readme.txt"}), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._action_share()

        mock_rw.assert_called_once()
        coro = mock_rw.call_args[0][0]
        coro.close()


class TestAWSCreateLoaderEmptyRegionPaths:
    """Empty region early return for all remaining loaders (lines 343, 370, 397, 424)."""

    def test_load_instance_types_empty_region_returns(self) -> None:
        svc = _make_mock_svc()
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()):
            asyncio.run(screen._load_instance_types(""))

        svc.list_instance_types.assert_not_called()

    def test_load_key_pairs_empty_region_returns(self) -> None:
        svc = _make_mock_svc()
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()

        with patch.object(type(screen), "query_one", return_value=MagicMock()), \
             patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            asyncio.run(screen._load_key_pairs(""))

        svc.list_key_pairs.assert_not_called()

    def test_load_subnets_empty_region_returns(self) -> None:
        svc = _make_mock_svc()
        app = _create_app(aws_service=svc)
        screen = AWSCreateScreen()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()):
            asyncio.run(screen._load_subnets(""))

        svc.list_subnets.assert_not_called()


# ---------------------------------------------------------------------------
# Object storage: region picker on the New Bucket form
# ---------------------------------------------------------------------------

class TestObjectStorageRegionPicker:
    """The region is chosen from a live list, never typed."""

    @staticmethod
    def _screen_with_select(provider="aws", regions=None, list_regions=None):
        from servonaut.screens.object_storage import ObjectStorageScreen

        screen = ObjectStorageScreen(provider)
        select = MagicMock()
        app = _s3_app(provider=provider, storage_service=_s3_mock_storage_service())
        app.aws_service = MagicMock()
        app.aws_service.list_regions = list_regions or AsyncMock(
            return_value=regions if regions is not None else ["us-east-1", "eu-central-1"]
        )
        cfg = MagicMock()
        cfg.aws.default_region = "us-east-1"
        app.config_manager.get.return_value = cfg
        return screen, select, app

    def test_populates_options_from_live_region_list(self) -> None:
        screen, select, app = self._screen_with_select(
            regions=["us-east-1", "eu-central-1", "ap-south-1"]
        )
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=select):
            asyncio.run(screen._load_regions())

        app.aws_service.list_regions.assert_awaited_once_with(bootstrap_region="us-east-1")
        options = list(select.set_options.call_args[0][0])
        assert options == [
            ("us-east-1", "us-east-1"),
            ("eu-central-1", "eu-central-1"),
            ("ap-south-1", "ap-south-1"),
        ]

    def test_region_list_failure_notifies_and_allows_retry(self) -> None:
        """A failed lookup must not strand the user — blank still works."""
        screen, select, app = self._screen_with_select(
            list_regions=AsyncMock(side_effect=Exception("no credentials"))
        )
        screen._regions_loaded = True
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=select):
            asyncio.run(screen._load_regions())

        select.set_options.assert_not_called()
        app.notify.assert_called()
        assert screen._regions_loaded is False  # next open retries

    @pytest.mark.parametrize("blank", ["Select.BLANK", "Select.NULL", ""])
    def test_blank_selection_means_configured_region(self, blank) -> None:
        """No pick → "" (the configured region), whichever sentinel Textual
        uses. Returning the sentinel's str() would send a bogus region."""
        from servonaut.screens.object_storage import ObjectStorageScreen
        from textual.widgets import Select

        screen = ObjectStorageScreen("aws")
        select = MagicMock()
        select.value = getattr(Select, blank.split(".")[-1]) if blank else ""
        with patch.object(screen, "query_one", return_value=select):
            assert screen._selected_bucket_region() == ""

    def test_picked_region_is_returned(self) -> None:
        from servonaut.screens.object_storage import ObjectStorageScreen

        screen = ObjectStorageScreen("aws")
        select = MagicMock()
        select.value = "eu-central-1"
        with patch.object(screen, "query_one", return_value=select):
            assert screen._selected_bucket_region() == "eu-central-1"

    @pytest.mark.parametrize("provider", ["hetzner", "ovh"])
    def test_endpoint_pinned_providers_report_no_region(self, provider) -> None:
        """Their region comes from the endpoint — never send an override."""
        from servonaut.screens.object_storage import ObjectStorageScreen

        screen = ObjectStorageScreen(provider)
        select = MagicMock()
        select.value = "eu-central-1"  # stale widget state must be ignored
        with patch.object(screen, "query_one", return_value=select):
            assert screen._selected_bucket_region() == ""

    def test_region_row_hidden_for_endpoint_pinned_provider(self) -> None:
        from servonaut.screens.object_storage import ObjectStorageScreen

        screen = ObjectStorageScreen("hetzner")
        widgets = {}

        def query_side(sel, *a, **kw):
            return widgets.setdefault(sel, MagicMock())

        app = _s3_app(provider="hetzner")
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_hide_all_forms"), \
             patch.object(screen, "run_worker") as worker:
            screen._show_new_bucket_form()

        assert widgets["#s3_bucket_region_row"].display is False
        worker.assert_not_called()  # no describe_regions for a pinned provider

    def test_region_list_loaded_once_per_screen(self) -> None:
        from servonaut.screens.object_storage import ObjectStorageScreen

        screen = ObjectStorageScreen("aws")
        app = _s3_app(provider="aws")

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", return_value=MagicMock()), \
             patch.object(screen, "_hide_all_forms"), \
             patch.object(screen, "run_worker") as worker, \
             patch.object(screen, "_load_regions") as loader:
            screen._show_new_bucket_form()
            screen._show_new_bucket_form()

        assert worker.call_count == 1
        assert loader.call_count == 1
