"""CloudTrail filters are pickers over the values actually present.

Typing a filter meant guessing an exact, case-sensitive value, and the API
honours only one lookup attribute per call, so combining two used to return
rows matching just one of them. The pickers offer what is really there and
combine locally.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Select

from servonaut.config.schema import AppConfig
from servonaut.screens.cloudtrail_browser import CloudTrailBrowserScreen
from servonaut.services.redaction_service import RedactionService

EVENTS = [
    {"event_time": "2026-01-01 00:00:03", "event_name": "AssumeRole", "username": "",
     "source_ip": "192.0.2.1", "resource_name": "", "resource_type": "AWS::IAM::Role",
     "region": "eu-west-2", "error_code": ""},
    {"event_time": "2026-01-01 00:00:02", "event_name": "AssumeRole", "username": "deploy",
     "source_ip": "192.0.2.2", "resource_name": "", "resource_type": "AWS::IAM::Role",
     "region": "eu-west-2", "error_code": ""},
    {"event_time": "2026-01-01 00:00:01", "event_name": "RunInstances", "username": "deploy",
     "source_ip": "192.0.2.3", "resource_name": "i-0abc12345678def01",
     "resource_type": "AWS::EC2::Instance", "region": "eu-west-2", "error_code": ""},
]


def _harness(*, demo: bool = False, events=None):
    config = AppConfig()
    config.cloudtrail_max_events = 100
    manager = MagicMock()
    manager.get.return_value = config
    service = MagicMock()
    service.lookup_events = AsyncMock(return_value=list(events if events is not None else EVENTS))

    class _Harness(App):
        CSS_PATH = None

        def __init__(self) -> None:
            super().__init__()
            self.config_manager = manager
            self.cloudtrail_service = service
            self.demo_mode = demo
            self.redaction_service = RedactionService() if demo else None

        def compose(self) -> ComposeResult:
            yield CloudTrailBrowserScreen()

    app = _Harness()
    app.lookup_mock = service.lookup_events  # type: ignore[attr-defined]
    return app


def _screen(app) -> CloudTrailBrowserScreen:
    return app.query_one(CloudTrailBrowserScreen)


def _choices(select: Select):
    """The real options, without the leading blank ("All …") row."""
    return [(str(label), value) for label, value in select._options if value is not Select.NULL]


async def _load(pilot, screen) -> None:
    screen.action_fetch()
    await pilot.pause()
    for _ in range(40):
        if screen._events:
            break
        await pilot.pause(0.05)


@pytest.mark.asyncio
async def test_unselected_pickers_mean_no_filter() -> None:
    """An untouched picker holds a sentinel, not a value: reading it as a
    string would send a bogus filter to the API."""
    async with _harness().run_test(headless=True) as pilot:
        screen = _screen(pilot.app)
        assert screen._filter_values() == {"event_name": "", "username": "", "resource_type": ""}

        await _load(pilot, screen)
        assert pilot.app.lookup_mock.await_args.kwargs["event_name"] == ""
        assert pilot.app.lookup_mock.await_args.kwargs["username"] == ""
        assert pilot.app.lookup_mock.await_args.kwargs["resource_type"] == ""


@pytest.mark.asyncio
async def test_options_are_the_values_present_with_counts_most_common_first() -> None:
    async with _harness().run_test(headless=True) as pilot:
        screen = _screen(pilot.app)
        await _load(pilot, screen)

        choices = _choices(pilot.app.query_one("#ct_select_event_name", Select))
        labels = [label for label, _ in choices]
        values = [value for _, value in choices]
        assert "AssumeRole" in values and "RunInstances" in values
        assert any("AssumeRole" in label and "(2)" in label for label in labels)
        # Most common first.
        assert values.index("AssumeRole") < values.index("RunInstances")

        types_ = _choices(pilot.app.query_one("#ct_select_resource_type", Select))
        assert [v for _, v in types_] == ["AWS::IAM::Role", "AWS::EC2::Instance"]


@pytest.mark.asyncio
async def test_blank_usernames_are_not_offered() -> None:
    async with _harness().run_test(headless=True) as pilot:
        screen = _screen(pilot.app)
        await _load(pilot, screen)

        users = _choices(pilot.app.query_one("#ct_select_username", Select))
        assert [v for _, v in users] == ["deploy"]


@pytest.mark.asyncio
async def test_picking_narrows_the_table_immediately_and_combines() -> None:
    async with _harness().run_test(headless=True) as pilot:
        screen = _screen(pilot.app)
        await _load(pilot, screen)
        assert len(screen._visible) == 3

        pilot.app.query_one("#ct_select_username", Select).value = "deploy"
        await pilot.pause()
        assert len(screen._visible) == 2

        # Combining two criteria is a local pass; the API cannot do it.
        pilot.app.query_one("#ct_select_event_name", Select).value = "RunInstances"
        await pilot.pause()
        assert [e["event_name"] for e in screen._visible] == ["RunInstances"]
        assert screen._current_page == 0

        pilot.app.query_one("#ct_select_username", Select).value = Select.NULL
        await pilot.pause()
        assert len(screen._visible) == 1


@pytest.mark.asyncio
async def test_selection_survives_a_refetch_and_is_sent_to_the_api() -> None:
    async with _harness().run_test(headless=True) as pilot:
        screen = _screen(pilot.app)
        await _load(pilot, screen)

        pilot.app.query_one("#ct_select_event_name", Select).value = "AssumeRole"
        await pilot.pause()
        await _load(pilot, screen)

        assert pilot.app.lookup_mock.await_args.kwargs["event_name"] == "AssumeRole"
        assert pilot.app.query_one("#ct_select_event_name", Select).value == "AssumeRole"


@pytest.mark.asyncio
async def test_usernames_are_redacted_in_the_option_label_but_not_the_value() -> None:
    async with _harness(demo=True).run_test(headless=True) as pilot:
        screen = _screen(pilot.app)
        await _load(pilot, screen)

        users = _choices(pilot.app.query_one("#ct_select_username", Select))
        assert [v for _, v in users] == ["deploy"]
        assert all("deploy" not in label for label, _ in users)
