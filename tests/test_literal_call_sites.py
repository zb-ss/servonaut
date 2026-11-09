"""Names and scan output from outside the app are drawn as typed at each call site.

One hostile sample carries a markup-looking link tag and a terminal escape.
Each case runs the screen's own code, then draws the result in a real app.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, List

import pytest
from textual.app import App
from textual.containers import VerticalScroll
from textual.widgets import Input, Static, TextArea

from servonaut.screens import confirm_action, ovh_dns, team_management
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.screens.power_confirm import PowerActionConfirmModal
from servonaut.screens.scan_results import ScanResultsScreen
from servonaut.styles import CSS_FILES

SAMPLE = "x[link=x]\x1b[2J"
SHOWN = "x[link=x]\\x1b[2J"


class _Host(App):
    CSS_PATH = CSS_FILES

    def __init__(self, widget=None, screen=None) -> None:
        super().__init__()
        self._widget = widget
        self._screen = screen

    def compose(self):
        if self._widget is not None:
            yield self._widget

    def on_mount(self) -> None:
        if self._screen is not None:
            self.push_screen(self._screen)


def _drawn(app) -> str:
    strips = app.screen._compositor.render_strips()
    return "\n".join("".join(segment.text for segment in strip) for strip in strips)


def _no_live_escape(text: str) -> None:
    assert "\x1b" not in text


class _Recorder:
    def __init__(self) -> None:
        self.screens: List[dict] = []

    def __call__(self, **kwargs: Any) -> dict:
        self.screens.append(kwargs)
        return kwargs


async def _run_confirm(module, method, fake, monkeypatch) -> dict:
    """Run *method*'s worker with a recording stand-in for the confirmation."""
    recorder = _Recorder()
    monkeypatch.setattr(module, "ConfirmActionScreen", recorder)
    workers: list = []

    async def push_screen_wait(screen):
        return False

    fake.run_worker = lambda coro, **kwargs: workers.append(coro)
    fake.app = SimpleNamespace(
        demo_mode=False, redaction_service=None, push_screen_wait=push_screen_wait,
        ovh_audit=None,
    )
    fake.notify = lambda *args, **kwargs: None
    method(fake)
    for coro in workers:
        await coro
    assert recorder.screens, "no confirmation was asked"
    return recorder.screens[0]


async def _draw_confirmation(kwargs: dict) -> str:
    app = _Host(screen=ConfirmActionScreen(**kwargs))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        text = _drawn(app)
        placeholder = app.screen.query_one("#confirm_input", Input).placeholder
    _no_live_escape(text)
    _no_live_escape(placeholder)
    return text + "\n" + placeholder


@pytest.mark.asyncio
async def test_the_dns_record_delete_description_and_prompt_are_literal(monkeypatch) -> None:
    fake = SimpleNamespace(
        _selected_zone="example.test",
        _get_selected_record=lambda: {"id": 1, "fieldType": "TXT", "subDomain": SAMPLE, "target": SAMPLE},
        _display_record_target=lambda record: str(record["target"]),
        _display_subdomain=lambda value: value,
        _account=None,
    )
    kwargs = await _run_confirm(ovh_dns, ovh_dns.OVHDNSScreen._action_delete, fake, monkeypatch)
    drawn = await _draw_confirmation(kwargs)
    assert drawn.count(SHOWN) >= 3  # description (twice), typed prompt, placeholder


@pytest.mark.asyncio
async def test_the_reverse_dns_delete_description_is_literal(monkeypatch) -> None:
    fake = SimpleNamespace(
        _get_selected_rdns=lambda: {"ip": SAMPLE, "ip_block": "1.2.3.4/32", "hostname": SAMPLE},
        redact_rdns_host=lambda value: value,
        _account=None,
    )
    kwargs = await _run_confirm(ovh_dns, ovh_dns.OVHDNSScreen._action_rdns_delete, fake, monkeypatch)
    drawn = await _draw_confirmation(kwargs)
    assert drawn.count(SHOWN) >= 3


@pytest.mark.asyncio
async def test_the_member_removal_description_is_literal(monkeypatch) -> None:
    fake = SimpleNamespace(
        _current_team_slug="team-1",
        _can_manage_members=lambda: True,
        _selected_member=lambda: {"id": "m1", "role": "member", "email": SAMPLE},
        _member_display_email=lambda member: member["email"],
    )
    kwargs = await _run_confirm(
        team_management, team_management.TeamManagementScreen._action_remove_member, fake, monkeypatch,
    )
    drawn = await _draw_confirmation(kwargs)
    assert drawn.count(SHOWN) >= 3


@pytest.mark.asyncio
async def test_the_typed_confirm_prompt_and_placeholder_are_literal() -> None:
    drawn = await _draw_confirmation(dict(
        title="Delete", description="Delete it.", consequences=["It goes."],
        confirm_text=SAMPLE, action_label="Delete",
    ))
    assert drawn.count(SHOWN) >= 2
    assert confirm_action.inert_text(SAMPLE) in drawn


class _KeywordPanel(App):
    CSS_PATH = CSS_FILES

    def compose(self):
        yield Static("", id="keyword_matches_label")
        yield VerticalScroll(id="keyword_matches_container")


@pytest.mark.asyncio
async def test_a_keyword_match_source_is_literal() -> None:
    from servonaut.screens.instance_list import InstanceListScreen

    host = _KeywordPanel()
    async with host.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        fake = SimpleNamespace(query_one=host.query_one, app=SimpleNamespace(demo_mode=False))
        InstanceListScreen._display_keyword_matches(
            fake, [{"server_id": "web-1", "source": SAMPLE, "content": SAMPLE}],
        )
        await pilot.pause(0.3)
        text = _drawn(host)
    _no_live_escape(text)
    assert text.count(SHOWN) >= 2


@pytest.mark.asyncio
async def test_the_scan_detail_shows_escape_sequences_as_text() -> None:
    detail = TextArea(id="scan_match_detail", read_only=True)
    host = _Host(widget=detail)
    async with host.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        fake = SimpleNamespace(
            query_one=lambda selector, kind=None: detail,
            _results=[{"source": SAMPLE, "timestamp": "t", "content": SAMPLE}],
            app=SimpleNamespace(demo_mode=False, redaction_service=None),
        )
        ScanResultsScreen._show_match(fake, 0)
        await pilot.pause(0.3)
        assert "\x1b" not in detail.text
        assert detail.text.count(SHOWN) == 2


@pytest.mark.asyncio
async def test_the_power_dialog_title_is_literal() -> None:
    screen = PowerActionConfirmModal(
        action=SAMPLE, server_name="web-1", provider="Example Cloud", consequence="It stops.",
    )
    app = _Host(screen=screen)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.3)
        title = app.screen.query_one("#power_confirm_title", Static).visual.plain
    assert title == f"{SHOWN} server"
