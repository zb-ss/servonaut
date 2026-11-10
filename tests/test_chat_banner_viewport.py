"""Real memory/quota copy leaves useful transcript rows on short terminals."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from textual.pilot import Pilot
from textual.containers import VerticalScroll
from textual.widget import Widget
from textual.widgets import Button, Static, TextArea
from textual.widgets.text_area import Selection

from servonaut.config.schema import AppConfig
from servonaut.services.chat_service import ChatMessage, ChatSession
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.instance_table import InstanceTable
from servonaut.widgets.sidebar import Sidebar
from tests._async_bounds import wait_until
from tests.test_fleet_workspace_layout import (
    _LayoutHost, _assert_strip_painted, _open_chat,
)

pytestmark = pytest.mark.usefixtures("navigation_open")


class _Config:
    def __init__(self) -> None:
        self.value = AppConfig()
        self.value.ai_provider = replace(
            self.value.ai_provider, provider_preference="servonaut",
        )

    def get(self) -> AppConfig:
        return self.value

    def update(self, **changes: object) -> None:
        self.value = replace(self.value, **changes)


async def _tab_to(pilot: Pilot, target: Widget) -> None:
    for _ in range(len(pilot.app.screen.focus_chain) + 1):
        if pilot.app.focused is target:
            return
        await pilot.press("tab")
    raise AssertionError(f"Native Tab did not reach {target!r}")


def _painted(app: _LayoutHost, widget: Widget) -> str:
    box = widget.scrollable_content_region
    assert app.screen.region.contains_region(box)
    strips = app.screen._compositor.render_strips()
    return "\n".join(
        strips[y].crop(box.x, box.right).text
        for y in range(box.y, box.bottom)
    )


def _assert_actions(app: _LayoutHost, panel: ChatPanel) -> None:
    for name in ("new", "history", "provider", "close", "mic", "convo", "send"):
        button = panel.query_one(f"#btn-chat-{name}", Button)
        assert panel.region.contains_region(button.region)
        assert app.get_widget_at(*button.region.center)[0] is button
        assert button.label.plain.strip() in _painted(app, button)


@pytest.mark.asyncio
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("message_count", [2, 8])
async def test_short_chat_real_banners_keep_reply_visible_after_native_restore(
    monkeypatch: pytest.MonkeyPatch,
    navigation_visible: bool,
    message_count: int,
) -> None:
    # Same no-provider seam as the existing compact presentation tests. Real
    # session, banner, quota and message renderers below populate their UI.
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    app = _LayoutHost(navigation_visible=navigation_visible)
    app.config_manager = _Config()
    app.instances[1]["id"] = "i-0123456789abcdef0"
    app.memory_service = SimpleNamespace(
        list_all=lambda: [],
        is_memory_disabled=lambda instance_id, instance_name: False,
        get_all_modules=lambda instance_id, provider: {},
    )
    app.auth_service = SimpleNamespace(
        is_authenticated=True,
        has_feature=lambda feature: feature == "premium_ai",
        _token=SimpleNamespace(entitlements={
            "quota": {"tokens_used": 1200, "tokens_limit": 500000},
        }),
    )
    messages = []
    for turn in range(message_count // 2):
        messages.extend((
            ChatMessage("user", f"Question {turn} café [literal] Ω"),
            ChatMessage(
                "assistant",
                "\n".join(f"Reply {turn} line {line} Ω" for line in range(18))
                + f"\nLatest reply {turn} café [literal] Ω",
            ),
        ))
    session = ChatSession(messages=messages)
    app.chat_service = SimpleNamespace(
        list_sessions=lambda: [], create_session=lambda: session,
    )
    last = f"Latest reply {message_count // 2 - 1} café [literal] Ω"

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.press("down")
        table = app.screen.query_one(InstanceTable)
        assert table.get_selected_instance()["name"] == "db-1"
        panel = await _open_chat(app, pilot)
        panel._start_or_resume_session()
        panel._update_memory_banner()
        transcript = panel.query_one("#chat-messages", VerticalScroll)
        banner = panel.query_one("#chat-memory-banner", Static)
        quota = panel.query_one("#chat-quota-footer", Static)
        editor = panel.query_one("#chat-input", TextArea)
        await wait_until(lambda: len(transcript.children) == message_count)
        await wait_until(
            lambda: transcript.max_scroll_y > 0
            and transcript.scroll_y == transcript.max_scroll_y
        )
        await pilot.pause()

        assert app.screen.has_class("-chat-replace")
        assert app.screen.has_class("-chat-compact")
        assert app.screen.query_one(Sidebar).display is navigation_visible
        assert banner.display and not banner.has_class("hidden")
        assert "No memory yet for" in str(banner.content)
        assert "No memory yet for" in _painted(app, banner)
        assert "Build now" in _painted(app, banner)
        assert quota.display and not quota.has_class("hidden")
        assert "Quota:" in str(quota.content)
        assert "Quota:" in _painted(app, quota)
        assert transcript.max_scroll_y > 0
        # Existing no-banner six-row test remains unchanged. With both real
        # banners, at least four usable rows must remain, not one text row.
        assert transcript.scrollable_content_region.height >= 4
        assert last in _painted(app, transcript)
        _assert_actions(app, panel)
        _assert_strip_painted(app, app.screen.query_one("#instance_detail", TextArea))

        await _tab_to(pilot, transcript)
        await pilot.press("home", "home")
        await wait_until(lambda: transcript.scroll_y == 0)
        assert "Question 0 café [literal] Ω" in _painted(app, transcript)
        await pilot.press("end")
        await wait_until(lambda: transcript.scroll_y == transcript.max_scroll_y)
        assert last in _painted(app, transcript)

        await _tab_to(pilot, editor)
        draft = "multiline café [literal] Ω\nsecond draft line"
        editor.load_text(draft)
        editor.selection = Selection.cursor((1, len("second draft line")))
        await pilot.press("!")
        assert editor.text == draft + "!"
        assert editor.region.height == 4 and editor.content_region.height >= 2
        assert app.get_widget_at(*editor.content_region.center)[0] is editor
        document, selection = editor.document, editor.selection
        old_scroll = transcript.scroll_offset

        await pilot.press("f2")
        await wait_until(lambda: panel._collapsed and not panel.display)
        await pilot.press("f2")
        await wait_until(lambda: not panel._collapsed and app.focused is editor)
        await pilot.pause()
        assert panel._session is session and session.messages == messages
        assert editor.document is document and editor.text == draft + "!"
        assert editor.selection == selection
        assert transcript.scroll_offset == old_scroll
        assert transcript.scrollable_content_region.height >= 4
        assert last in _painted(app, transcript)
        assert banner.display and quota.display
        _assert_actions(app, panel)
        _assert_strip_painted(app, app.screen.query_one("#instance_detail", TextArea))
        assert app._exception is None
