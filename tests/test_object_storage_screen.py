"""Tests for ObjectStorageScreen — pilot mount, demo mode, navigation, guards."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import List, Optional
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from servonaut.screens.object_storage import (
    ObjectStorageScreen,
    _VIEW_BUCKETS,
    _VIEW_OBJECTS,
    _format_size,
)
from textual.widgets import Input

from servonaut.services.redaction_service import RedactionService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_storage_service(*, buckets=None, objects=None):
    svc = MagicMock()
    svc.list_buckets = AsyncMock(return_value=buckets or [
        {"name": "my-bucket", "creation_date": "2024-01-01T00:00:00+00:00"},
    ])
    svc.list_objects = AsyncMock(return_value=objects or {
        "folders": ["images/"],
        "objects": [
            {"key": "readme.txt", "size": 1536, "last_modified": "2024-01-01T00:00:00+00:00"}
        ],
        "is_truncated": False,
    })
    svc.delete_bucket = AsyncMock()
    svc.delete_object = AsyncMock()
    svc.create_bucket = AsyncMock()
    svc.generate_presigned_url = AsyncMock(return_value="https://presigned.example.com/url")
    return svc


def _mock_app(
    *,
    provider: str = "aws",
    storage_service=None,
    demo_mode: bool = False,
    redaction_service=None,
):
    app = MagicMock()
    app.demo_mode = demo_mode
    app.redaction_service = redaction_service
    setattr(app, f"{provider}_object_storage_service", storage_service)
    app.push_screen_wait = AsyncMock(return_value=True)
    app.notify = MagicMock()
    return app


# ---------------------------------------------------------------------------
# TestProviderServiceSelection
# ---------------------------------------------------------------------------

class TestProviderServiceSelection:
    """provider param selects the right service attribute."""

    def test_aws_selects_aws_object_storage_service(self) -> None:
        svc = _mock_storage_service()
        app = _mock_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            result = screen._get_storage_service()
        assert result is svc

    def test_hetzner_selects_hetzner_storage_service(self) -> None:
        svc = _mock_storage_service()
        app = _mock_app(provider="hetzner", storage_service=svc)
        screen = ObjectStorageScreen("hetzner")
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            result = screen._get_storage_service()
        assert result is svc

    def test_not_configured_returns_none(self) -> None:
        app = _mock_app(provider="ovh", storage_service=None)
        screen = ObjectStorageScreen("ovh")
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            result = screen._get_storage_service()
        assert result is None


# ---------------------------------------------------------------------------
# TestNotConfiguredGuard
# ---------------------------------------------------------------------------

class TestNotConfiguredGuard:
    """_refresh shows 'not configured' when service is None."""

    def test_shows_not_configured_when_service_none(self) -> None:
        app = _mock_app(provider="aws", storage_service=None)
        screen = ObjectStorageScreen("aws")
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_set_status") as mock_status, \
             patch.object(screen, "run_worker") as mock_rw:
            screen._refresh()
        mock_rw.assert_not_called()
        mock_status.assert_called_once()


# ---------------------------------------------------------------------------
# TestLoadBuckets
# ---------------------------------------------------------------------------

class TestLoadBuckets:

    @pytest.mark.asyncio
    async def test_load_buckets_renders_table(self) -> None:
        svc = _mock_storage_service()
        app = _mock_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")

        mock_table = MagicMock()
        mock_breadcrumb = MagicMock()
        mock_status = MagicMock()

        def query_side(sel, *args, **kwargs):
            if "s3_table" in sel:
                return mock_table
            if "s3_breadcrumb" in sel:
                return mock_breadcrumb
            if "s3_status" in sel:
                return mock_status
            return MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side):
            await screen._load_buckets()

        svc.list_buckets.assert_called_once()
        mock_table.add_row.assert_called_once()

    @pytest.mark.asyncio
    async def test_load_buckets_scrubs_in_demo_mode(self) -> None:
        svc = _mock_storage_service()
        redaction = RedactionService()
        app = _mock_app(provider="aws", storage_service=svc, demo_mode=True,
                        redaction_service=redaction)
        screen = ObjectStorageScreen("aws")

        row_data = []
        mock_table = MagicMock()
        mock_table.add_row = MagicMock(side_effect=lambda *args, **kw: row_data.append(args))
        mock_breadcrumb = MagicMock()

        def query_side(sel, *args, **kwargs):
            if "s3_table" in sel:
                return mock_table
            if "s3_breadcrumb" in sel:
                return mock_breadcrumb
            return MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side):
            await screen._load_buckets()

        # The bucket name should NOT be the raw "my-bucket"
        assert row_data
        bucket_name_cell = row_data[0][1]
        assert bucket_name_cell != "my-bucket"


# ---------------------------------------------------------------------------
# TestFolderNavigation
# ---------------------------------------------------------------------------

class TestFolderNavigation:
    """Prefix push/pop for folder navigation."""

    def test_up_strips_last_prefix_segment(self) -> None:
        svc = _mock_storage_service()
        app = _mock_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._prefix = "images/thumbnails/"

        captured_coros = []
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "run_worker",
                          side_effect=lambda coro, **kw: captured_coros.append(coro)) as mock_rw:
            screen.action_up()
        for coro in captured_coros:
            coro.close()

        assert screen._prefix == "images/"
        mock_rw.assert_called_once()

    def test_up_strips_single_segment_to_empty(self) -> None:
        svc = _mock_storage_service()
        app = _mock_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._prefix = "images/"

        captured_coros = []
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "run_worker",
                          side_effect=lambda coro, **kw: captured_coros.append(coro)):
            screen.action_up()
        for coro in captured_coros:
            coro.close()

        assert screen._prefix == ""

    def test_up_does_nothing_in_buckets_view(self) -> None:
        svc = _mock_storage_service()
        app = _mock_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS
        screen._prefix = ""

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "run_worker") as mock_rw:
            screen.action_up()

        mock_rw.assert_not_called()


# ---------------------------------------------------------------------------
# TestDeleteRoutesThroughConfirm
# ---------------------------------------------------------------------------

class TestDeleteRoutesThroughConfirm:
    """Delete bucket/object routes through ConfirmActionScreen via worker."""

    def test_delete_bucket_fires_worker(self) -> None:
        svc = _mock_storage_service()
        app = _mock_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_BUCKETS
        screen._buckets = [{"name": "my-bucket", "creation_date": ""}]

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_bucket_name", return_value="my-bucket"), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._action_delete_bucket()

        mock_rw.assert_called_once()
        # Close the un-awaited coroutine passed to run_worker to suppress
        # RuntimeWarning: coroutine was never awaited.
        coro = mock_rw.call_args[0][0]
        coro.close()

    def test_delete_object_fires_worker(self) -> None:
        svc = _mock_storage_service()
        app = _mock_app(provider="aws", storage_service=svc)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object", "key": "readme.txt"}), \
             patch.object(screen, "run_worker") as mock_rw:
            screen._action_delete_object()

        mock_rw.assert_called_once()
        # Close the un-awaited coroutine passed to run_worker to suppress
        # RuntimeWarning: coroutine was never awaited.
        coro = mock_rw.call_args[0][0]
        coro.close()


# ---------------------------------------------------------------------------
# TestPresignedUrlScrub
# ---------------------------------------------------------------------------

class TestPresignedUrlScrub:

    @pytest.mark.asyncio
    async def test_presigned_url_scrubbed_in_demo(self) -> None:
        svc = _mock_storage_service()
        # URL contains an "IP" that will get redacted
        svc.generate_presigned_url = AsyncMock(
            return_value="https://192.0.2.100/my-bucket/file.txt?X-Amz-Signature=abc"
        )
        redaction = RedactionService()
        app = _mock_app(provider="aws", storage_service=svc, demo_mode=True,
                        redaction_service=redaction)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "my-bucket"

        url_shown = []
        mock_url_widget = MagicMock()
        mock_url_widget.update = MagicMock(side_effect=lambda x: url_shown.append(x))

        def query_side(sel, *args, **kwargs):
            if "s3_presigned_url_display" in sel:
                return mock_url_widget
            m = MagicMock()
            m.display = False
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_hide_all_forms"):
            await screen._generate_presigned_url("my-bucket", "file.txt")

        assert url_shown
        assert "192.0.2.100" not in url_shown[0]


# ---------------------------------------------------------------------------
# TestFormatSize (ISSUE-8 fix verification)
# ---------------------------------------------------------------------------

class TestFormatSize:

    def test_1536_bytes_is_1_point_5_kb(self) -> None:
        assert _format_size(1536) == "1.5 KB"

    def test_zero_bytes(self) -> None:
        assert _format_size(0) == "0 B"

    def test_1024_bytes_is_1_kb(self) -> None:
        assert _format_size(1024) == "1.0 KB"

    def test_bytes_unit_for_small(self) -> None:
        result = _format_size(512)
        assert "512" in result and "B" in result

    def test_mb(self) -> None:
        assert _format_size(1024 * 1024) == "1.0 MB"


# ---------------------------------------------------------------------------
# TestCopyMoveFormPrefillScrub — copy/move forms must not pre-fill a raw,
# un-redacted object key / bucket name into the editable Input in demo mode.
# ---------------------------------------------------------------------------

class TestCopyMoveFormPrefillScrub:

    def _run_form(self, form_method: str, key_input_sel: str,
                  bucket_input_sel: str) -> tuple:
        svc = _mock_storage_service()
        redaction = RedactionService()
        app = _mock_app(provider="aws", storage_service=svc, demo_mode=True,
                        redaction_service=redaction)
        screen = ObjectStorageScreen("aws")
        screen._view = _VIEW_OBJECTS
        screen._current_bucket = "acme-corp-prod-bucket"

        inputs: dict = {}

        def query_side(sel, *args, **kwargs):
            m = MagicMock()
            m.display = False
            inputs[sel] = m
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock,
                           return_value=app), \
             patch.object(screen, "_get_selected_object_info",
                          return_value={"type": "object",
                                        "key": "customers/acme-corp/contract.pdf"}), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "_hide_all_forms"):
            getattr(screen, form_method)()

        return inputs.get(key_input_sel), inputs.get(bucket_input_sel)

    def test_copy_form_prefill_scrubbed_in_demo(self) -> None:
        key_w, bucket_w = self._run_form(
            "_show_copy_form", "#s3_input_copy_dst_key",
            "#s3_input_copy_dst_bucket")
        assert key_w is not None and "acme-corp" not in str(key_w.value)
        assert bucket_w is not None and "acme-corp" not in str(bucket_w.value)
        # path separators preserved
        assert str(key_w.value).count("/") == 2

    def test_move_form_prefill_scrubbed_in_demo(self) -> None:
        key_w, bucket_w = self._run_form(
            "_show_move_form", "#s3_input_move_dst_key",
            "#s3_input_move_dst_bucket")
        assert key_w is not None and "acme-corp" not in str(key_w.value)
        assert bucket_w is not None and "acme-corp" not in str(bucket_w.value)


# ---------------------------------------------------------------------------
# TestPilotMountBucketsView (ISSUE-1 smoke test)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_object_storage_screen_buckets_pilot() -> None:
    """Full Textual pilot mount — verifies buckets view renders without WorkerFailed."""
    from textual.app import App, ComposeResult
    from servonaut.config.schema import AppConfig

    svc = _mock_storage_service()

    class _Harness(App):
        def __init__(self):
            super().__init__()
            self.aws_object_storage_service = svc
            self.hetzner_object_storage_service = None
            self.ovh_object_storage_service = None
            self.demo_mode = False
            self.redaction_service = None
            cfg_mgr = MagicMock()
            cfg_mgr.get.return_value = AppConfig()
            self.config_manager = cfg_mgr

        def compose(self) -> ComposeResult:
            yield ObjectStorageScreen("aws")

    async with _Harness().run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        # Confirm buckets were loaded (list_buckets called)
        svc.list_buckets.assert_called()
        assert pilot.app is not None


# ---------------------------------------------------------------------------
# TestPilotMountObjectsView
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_object_storage_screen_objects_pilot() -> None:
    """Pilot mount then navigate into a bucket — objects view renders."""
    from textual.app import App, ComposeResult
    from servonaut.config.schema import AppConfig

    svc = _mock_storage_service()

    class _Harness(App):
        def __init__(self):
            super().__init__()
            self.aws_object_storage_service = svc
            self.hetzner_object_storage_service = None
            self.ovh_object_storage_service = None
            self.demo_mode = False
            self.redaction_service = None
            cfg_mgr = MagicMock()
            cfg_mgr.get.return_value = AppConfig()
            self.config_manager = cfg_mgr

        def compose(self) -> ComposeResult:
            yield ObjectStorageScreen("aws")

    async with _Harness().run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        screen = pilot.app.query_one(ObjectStorageScreen)
        # Simulate opening a bucket
        screen._current_bucket = "my-bucket"
        screen._view = _VIEW_OBJECTS
        screen.run_worker(screen._load_objects(), exclusive=True, name="s3_load_objects")
        await pilot.pause(0.2)
        assert svc.list_objects.called
        assert pilot.app is not None


# ---------------------------------------------------------------------------
# Region picker — real mount, real widget
# ---------------------------------------------------------------------------

def _region_harness(provider: str, list_regions):
    """Build a pilot App hosting an ObjectStorageScreen for *provider*."""
    from textual.app import App, ComposeResult
    from servonaut.config.schema import AppConfig

    svc = _mock_storage_service()

    class _Harness(App):
        def __init__(self):
            super().__init__()
            for p in ("aws", "hetzner", "ovh"):
                setattr(self, f"{p}_object_storage_service", svc if p == provider else None)
            self.demo_mode = False
            self.redaction_service = None
            aws = MagicMock()
            aws.list_regions = list_regions
            self.aws_service = aws
            cfg_mgr = MagicMock()
            cfg_mgr.get.return_value = AppConfig()
            self.config_manager = cfg_mgr

        def compose(self) -> ComposeResult:
            yield ObjectStorageScreen(provider)

    return _Harness(), svc


@pytest.mark.asyncio
async def test_new_bucket_form_region_select_renders_and_populates() -> None:
    """Mount for real: the picker must exist, fill from the live list, and
    hand the chosen region to create_bucket."""
    from textual.widgets import Select

    app, svc = _region_harness(
        "aws", AsyncMock(return_value=["us-east-1", "eu-central-1", "ap-south-1"]),
    )
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        screen = pilot.app.query_one(ObjectStorageScreen)
        screen._show_new_bucket_form()
        await pilot.pause(0.3)

        assert screen.query_one("#s3_bucket_region_row").display is True
        select = screen.query_one("#s3_select_bucket_region", Select)
        # Blank until the user picks — blank means "configured region".
        # The sentinel is not a str; that, not its name, is what we rely on.
        assert not isinstance(select.value, str)
        assert screen._selected_bucket_region() == ""

        select.value = "eu-central-1"
        assert screen._selected_bucket_region() == "eu-central-1"

        screen.query_one("#s3_input_bucket_name", Input).value = "new-bucket"
        screen._submit_new_bucket()
        await pilot.pause(0.3)
        svc.create_bucket.assert_awaited_once_with("new-bucket", "eu-central-1")


@pytest.mark.asyncio
async def test_new_bucket_form_hides_region_for_endpoint_pinned_provider() -> None:
    """Hetzner's region is fixed by its endpoint — no picker, no probe."""
    list_regions = AsyncMock(return_value=["us-east-1"])
    app, svc = _region_harness("hetzner", list_regions)
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        screen = pilot.app.query_one(ObjectStorageScreen)
        screen._show_new_bucket_form()
        await pilot.pause(0.3)

        assert screen.query_one("#s3_bucket_region_row").display is False
        list_regions.assert_not_awaited()

        screen.query_one("#s3_input_bucket_name", Input).value = "new-bucket"
        screen._submit_new_bucket()
        await pilot.pause(0.3)
        svc.create_bucket.assert_awaited_once_with("new-bucket", "")
