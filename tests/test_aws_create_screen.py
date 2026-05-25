"""Tests for AWSCreateScreen — validation, debounce, create flow."""

from __future__ import annotations

import asyncio
from typing import List, Optional
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from servonaut.screens.aws_create import AWSCreateScreen
from servonaut.config.schema import AppConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_app(*, aws_service=None, demo_mode: bool = False):
    app = MagicMock()
    app.demo_mode = demo_mode
    app.redaction_service = None
    app.aws_service = aws_service
    app.aws_audit = None
    cfg = AppConfig()
    cfg_mgr = MagicMock()
    cfg_mgr.get.return_value = cfg
    app.config_manager = cfg_mgr
    app.pop_screen = MagicMock()
    app.push_screen_wait = AsyncMock(return_value=True)
    app.instances = []
    return app


def _make_mock_aws_service():
    svc = MagicMock()
    svc.list_regions = AsyncMock(return_value=["us-east-1", "eu-west-1"])
    svc.list_amis = AsyncMock(return_value=[
        {"image_id": "ami-0abc12345678def90", "name": "al2023", "architecture": "x86_64",
         "virtualization_type": "hvm", "creation_date": "2024-01-01T00:00:00Z"}
    ])
    svc.list_instance_types = AsyncMock(return_value=[
        {"instance_type": "t3.micro", "vcpus": 2, "memory_mib": 1024}
    ])
    svc.list_key_pairs = AsyncMock(return_value=[
        {"key_name": "my-key", "key_pair_id": "key-123", "fingerprint": "ab:cd:ef"}
    ])
    svc.list_subnets = AsyncMock(return_value=[
        {"subnet_id": "subnet-0abc12345678def90", "vpc_id": "vpc-0abc",
         "availability_zone": "us-east-1a", "cidr_block": "10.0.1.0/24", "available_ip_count": 251}
    ])
    svc.list_security_groups = AsyncMock(return_value=[
        {"group_id": "sg-0abc12345678def90", "group_name": "web-sg",
         "description": "Web", "vpc_id": "vpc-0abc"}
    ])
    svc.run_instances = AsyncMock(return_value=[
        {"id": "i-0newinstance123", "state": "pending",
         "type": "t3.micro", "region": "us-east-1"}
    ])
    svc.fetch_instances_cached = AsyncMock(return_value=[])
    return svc


# ---------------------------------------------------------------------------
# TestOnCreateAborts
# ---------------------------------------------------------------------------

class TestOnCreateAborts:
    """_on_create aborts with notify when required selections are missing."""

    async def _run_create_with_setup(self, app, screen):
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app):
            await screen._on_create()

    @pytest.mark.asyncio
    async def test_aborts_on_missing_name(self) -> None:
        svc = _make_mock_aws_service()
        app = _mock_app(aws_service=svc)
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        screen._amis = []
        screen._instance_types = []
        screen._key_pairs = []
        screen._subnets = []
        screen._security_groups = []

        mock_name_input = MagicMock()
        mock_name_input.value = ""  # empty name

        def query_side(sel, *args, **kwargs):
            if "aws_input_name" in sel:
                return mock_name_input
            return MagicMock()

        notify_calls = []
        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notify_calls.append(msg)):
            await screen._on_create()

        assert any("name" in msg.lower() for msg in notify_calls)
        svc.run_instances.assert_not_called()

    @pytest.mark.asyncio
    async def test_aborts_on_missing_ami_selection(self) -> None:
        svc = _make_mock_aws_service()
        app = _mock_app(aws_service=svc)
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        screen._amis = []  # empty list → no valid row
        screen._instance_types = [{"instance_type": "t3.micro", "vcpus": 2, "memory_mib": 1024}]
        screen._key_pairs = [{"key_name": "k", "key_pair_id": "", "fingerprint": ""}]
        screen._subnets = [{"subnet_id": "subnet-0abc12345678def90", "vpc_id": "v",
                            "availability_zone": "az", "cidr_block": "10.0.0.0/24",
                            "available_ip_count": 10}]
        screen._security_groups = [{"group_id": "sg-0abc12345678def90", "group_name": "sg",
                                    "description": "", "vpc_id": "v"}]

        notify_calls = []

        def query_side(sel, *args, **kwargs):
            m = MagicMock()
            if "aws_input_name" in sel:
                m.value = "my-server"
            elif "aws_regions_table" in sel:
                m.cursor_row = 0
            elif "aws_amis_table" in sel:
                m.cursor_row = 0   # cursor=0 but _amis is empty → aborts
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
             patch.object(screen, "notify", side_effect=lambda msg, **kw: notify_calls.append(msg)):
            await screen._on_create()

        assert any("ami" in msg.lower() or "select" in msg.lower() for msg in notify_calls)
        svc.run_instances.assert_not_called()


# ---------------------------------------------------------------------------
# TestRegionChangeTriggersDependentLoads
# ---------------------------------------------------------------------------

class TestRegionChangeTriggersDependentLoads:

    def test_load_region_dependents_fires_all_workers(self) -> None:
        svc = _make_mock_aws_service()
        app = _mock_app(aws_service=svc)
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        screen._amis = []
        screen._instance_types = []
        screen._key_pairs = []
        screen._subnets = []
        screen._security_groups = []

        worker_calls = []
        coroutines = []

        def _capture(coro, **kw):
            coroutines.append(coro)
            worker_calls.append(kw.get("name", ""))

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "run_worker", side_effect=_capture):
            screen._load_region_dependents("us-east-1")

        # Close coroutines to suppress RuntimeWarning: coroutine was never awaited.
        for coro in coroutines:
            coro.close()

        # Should have fired AMIs, types, keys, subnets, SGs
        assert len(worker_calls) == 5
        names = set(worker_calls)
        assert "aws_create_load_amis" in names
        assert "aws_create_load_types" in names


# ---------------------------------------------------------------------------
# TestAMISearchDebounce (ISSUE-6)
# ---------------------------------------------------------------------------

class TestAMISearchDebounce:

    def test_debounce_timer_set_on_input_change(self) -> None:
        svc = _make_mock_aws_service()
        app = _mock_app(aws_service=svc)
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        screen._ami_search_timer = None

        from textual.widgets import Input
        event = MagicMock(spec=Input.Changed)
        event.input = MagicMock()
        event.input.id = "aws_input_ami_search"
        event.value = "ubuntu"

        timer_created = []

        def mock_set_timer(delay, fn):
            timer_created.append((delay, fn))
            return MagicMock()

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_current_region", return_value="us-east-1"), \
             patch.object(screen, "set_timer", side_effect=mock_set_timer), \
             patch.object(screen, "run_worker"):
            screen.on_input_changed(event)

        # Timer was created
        assert len(timer_created) == 1
        assert timer_created[0][0] == pytest.approx(0.4)

    def test_old_timer_cancelled_on_new_keystroke(self) -> None:
        svc = _make_mock_aws_service()
        app = _mock_app(aws_service=svc)
        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]

        old_timer = MagicMock()
        old_timer.stop = MagicMock()
        screen._ami_search_timer = old_timer

        from textual.widgets import Input
        event = MagicMock(spec=Input.Changed)
        event.input = MagicMock()
        event.input.id = "aws_input_ami_search"
        event.value = "al2023"

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "_current_region", return_value="us-east-1"), \
             patch.object(screen, "set_timer", return_value=MagicMock()), \
             patch.object(screen, "run_worker"):
            screen.on_input_changed(event)

        old_timer.stop.assert_called_once()


# ---------------------------------------------------------------------------
# TestCreateFlow
# ---------------------------------------------------------------------------

class TestCreateFlow:

    @pytest.mark.asyncio
    async def test_valid_create_calls_run_instances(self) -> None:
        svc = _make_mock_aws_service()
        app = _mock_app(aws_service=svc)

        screen = AWSCreateScreen()
        screen._regions = ["us-east-1"]
        screen._amis = [
            {"image_id": "ami-0abc12345678def90", "name": "al2023",
             "architecture": "x86_64", "virtualization_type": "hvm",
             "creation_date": "2024-01-01T00:00:00Z"}
        ]
        screen._instance_types = [{"instance_type": "t3.micro", "vcpus": 2, "memory_mib": 1024}]
        screen._key_pairs = [{"key_name": "my-key", "key_pair_id": "k123", "fingerprint": "ab"}]
        screen._subnets = [{"subnet_id": "subnet-0abc12345678def90", "vpc_id": "vpc-1",
                            "availability_zone": "us-east-1a", "cidr_block": "10.0.1.0/24",
                            "available_ip_count": 251}]
        screen._security_groups = [{"group_id": "sg-0abc12345678def90", "group_name": "sg",
                                    "description": "d", "vpc_id": "vpc-1"}]

        def query_side(sel, *args, **kwargs):
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
                m.disabled = False
            return m

        with patch.object(type(screen), "app", new_callable=PropertyMock, return_value=app), \
             patch.object(screen, "query_one", side_effect=query_side), \
             patch.object(screen, "notify"):
            await screen._on_create()

        svc.run_instances.assert_called_once()
        call_kwargs = svc.run_instances.call_args[1]
        assert call_kwargs["name_tag"] == "test-server"
        assert call_kwargs["region"] == "us-east-1"
        assert call_kwargs["ami_id"] == "ami-0abc12345678def90"
