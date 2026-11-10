"""Server actions parity: header, cards, monitoring, findings count, footer.

Hosted in the real app so the shipped stylesheet decides the geometry. These
tests run with the real navigation rule: below 110 columns it starts hidden.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from textual.widgets import Static

from servonaut.screens.server_actions import ServerActionsScreen
from servonaut.services.live_stats_service import LiveStatsError
from servonaut.widgets.action_button import ActionButton
from servonaut.widgets.chat_panel import ChatPanel
from tests._async_bounds import wait_until
from tests.test_fleet_workspace_layout import _LayoutHost
from tests.test_server_actions_overview import _open_actions

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _no_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)


def _button(screen, button_id: str) -> ActionButton:
    return screen.query_one(f"#{button_id}", ActionButton)


async def test_the_header_is_one_row_of_context_without_a_bar_or_credential_line() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        context = screen.query_one("#server_context", Static)
        assert context.has_class("screen-title")
        assert context.region.height == 1
        plain = context.content.plain
        assert app.instances[0]["name"] in plain and "·" in plain
        assert "SSH credential" not in plain
        outer = screen.query_one("#sa-context")
        assert all(edge[0] in ("", "none") for edge in outer.styles.border)
        assert screen.query_one("#action_buttons").styles.border.bottom[0] == "solid"


async def test_back_shows_esc_and_ssh_connect_keeps_its_words() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _open_actions(app, pilot)
        assert _button(screen, "btn_back").label.plain.endswith("esc")
        assert "SSH connect" in _button(screen, "btn_ssh").words
        assert _button(screen, "btn_ssh").label.plain.startswith("SSH connect")


async def test_cards_keep_two_columns_at_100_columns_with_the_navigation_hidden() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _open_actions(app, pilot)
        await wait_until(lambda: screen.query_one("#card_network").region.width > 0)
        assert not screen.has_class("-stack-cards")
        identity, network = screen.query_one("#card_identity"), screen.query_one("#card_network")
        assert identity.region.y == network.region.y
        assert identity.region.right <= network.region.x


async def test_cards_stack_when_the_content_is_narrower_than_96_columns() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _open_actions(app, pilot)
        await pilot.resize_terminal(90, 30)
        await wait_until(lambda: screen.has_class("-stack-cards"))
        await pilot.pause()
        identity, network = screen.query_one("#card_identity"), screen.query_one("#card_network")
        assert network.region.y >= identity.region.bottom


async def test_a_short_terminal_drops_the_blank_row_after_a_card_title() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _open_actions(app, pilot)
        await wait_until(lambda: screen._short_cards)
        identity = screen.query_one("#server_identity", Static).content.plain.splitlines()
        assert identity[0] == "Identity" and identity[1].strip()
        assert len(identity) == 3  # title and the two most useful facts


async def test_diagnostics_and_memory_cards_hold_the_agreed_actions() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        diagnostics = [b.id for b in screen.query("#sa-diagnostics ActionButton")]
        assert diagnostics == ["btn_logs", "btn_ai_analysis", "btn_scan", "btn_ban_ip"]
        ban = _button(screen, "btn_ban_ip")
        assert ban.has_class("-error") and ban.words == "Ban IP…"
        assert _button(screen, "btn_scan").words == "Keyword scan"
        memory = [b.id for b in screen.query("#card_memory ActionButton")]
        assert memory == ["btn_memory", "btn_findings", "btn_db_creds"]
        assert not screen.query("#btn_host_key_policy")


async def test_findings_shows_the_open_count_and_opens_the_inbox() -> None:
    app = _LayoutHost()
    app.findings_service = SimpleNamespace(list_findings=AsyncMock(return_value={"findings": [
        {"status": "detected"}, {"status": "acked"}, {"status": "resolved"},
    ]}))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        await wait_until(lambda: "Findings 2" in _button(screen, "btn_findings").label.plain)
        pushed: list[object] = []
        with patch.object(app, "push_screen", lambda s, *a, **k: pushed.append(s)):
            await pilot.press("f")
        assert [type(item).__name__ for item in pushed] == ["FindingsScreen"]


async def test_refresh_takes_one_sample_without_starting_the_poll() -> None:
    app = _LayoutHost()
    calls = {"collect": 0, "watch": 0}

    class _Service:
        async def collect(self, instance):
            calls["collect"] += 1
            return SimpleNamespace()

        def watch(self, instance):
            calls["watch"] += 1
            raise AssertionError("Refresh must not start the poll")

    app.live_stats_service = _Service()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        with patch("servonaut.screens.server_actions.format_live_stats", lambda stats, **kw: "one sample"):
            _button(screen, "btn_live_refresh").press()
            await wait_until(lambda: "one sample" in str(screen.query_one("#live_stats", Static).content))
        assert calls == {"collect": 1, "watch": 0}
        assert not screen._live_on
        assert _button(screen, "btn_live").label.plain.startswith("Start monitoring")
        assert not _button(screen, "btn_live_refresh").disabled


async def test_a_failed_refresh_shows_the_error_briefly_then_the_idle_text() -> None:
    app = _LayoutHost()

    class _Service:
        async def collect(self, instance):
            raise LiveStatsError("no route")

    app.live_stats_service = _Service()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        with patch("servonaut.screens.server_actions._SAMPLE_ERROR_SECONDS", 0.2):
            _button(screen, "btn_live_refresh").press()
            await wait_until(lambda: "no route" in str(screen.query_one("#live_stats", Static).content))
            await wait_until(lambda: "no route" not in str(screen.query_one("#live_stats", Static).content))
        assert not _button(screen, "btn_live_refresh").disabled


async def test_there_is_no_click_to_run_help_line() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        assert not screen.query("#action_help")
        assert "filesystem" in str(_button(screen, "btn_browse").tooltip)


def _footer_keys(screen) -> set[str]:
    return {key for key, active in screen.active_bindings.items() if active.binding.show}


async def test_the_footer_shows_four_keys_and_help_when_narrow() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(100, 30)) as pilot:
        screen = await _open_actions(app, pilot)
        await wait_until(lambda: "6" not in _footer_keys(screen))
        keys = _footer_keys(screen) & {"1", "2", "3", "4", "5", "6", "7", "8", "m", "d", "f", "l", "r", "v", "question_mark"}
        assert keys == {"1", "2", "3", "4", "question_mark"}


async def test_the_footer_adds_logs_and_ban_ip_when_wide() -> None:
    app = _LayoutHost()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        await wait_until(lambda: "6" in _footer_keys(screen))
        assert {"6", "8"} <= _footer_keys(screen)


async def _toggle_navigation(app, pilot) -> None:
    app.action_toggle_navigation()
    await pilot.pause()
    await pilot.pause()


@pytest.mark.parametrize("width,height", [(100, 30), (120, 40)])
async def test_card_stacking_follows_a_navigation_toggle_both_ways(width: int, height: int) -> None:
    app = _LayoutHost()
    async with app.run_test(size=(width, height)) as pilot:
        screen = await _open_actions(app, pilot)
        body = screen.query_one("#sa-body")

        def stacked_as_expected() -> bool:
            return screen.has_class("-stack-cards") == (body.size.width < 96)

        await wait_until(lambda: body.size.width > 0 and stacked_as_expected())
        for _ in range(2):
            await _toggle_navigation(app, pilot)
            await wait_until(stacked_as_expected)
            identity, network = screen.query_one("#card_identity"), screen.query_one("#card_network")
            side_by_side = identity.region.y == network.region.y
            assert side_by_side == (not screen.has_class("-stack-cards"))


class _SequencedService:
    def __init__(self, *outcomes) -> None:
        self.outcomes = list(outcomes)

    async def collect(self, instance):
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


async def test_a_good_sample_is_not_wiped_by_an_earlier_errors_timer() -> None:
    app = _LayoutHost()
    app.live_stats_service = _SequencedService(LiveStatsError("no route"), SimpleNamespace())
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        text = lambda: str(screen.query_one("#live_stats", Static).content)  # noqa: E731
        with (
            patch("servonaut.screens.server_actions._SAMPLE_ERROR_SECONDS", 0.4),
            patch("servonaut.screens.server_actions.format_live_stats", lambda stats, **kw: "good sample"),
        ):
            _button(screen, "btn_live_refresh").press()
            await wait_until(lambda: "no route" in text())
            _button(screen, "btn_live_refresh").press()
            await wait_until(lambda: "good sample" in text())
            await pilot.pause(0.8)  # past the first error's window
        assert "good sample" in text()


@pytest.mark.parametrize("message", ["[$text-error]x", "a[/]b", "[link=https://example.test]click[/link]"])
async def test_an_ssh_error_is_shown_literally(message: str) -> None:
    app = _LayoutHost()
    app.live_stats_service = _SequencedService(LiveStatsError(message))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        _button(screen, "btn_live_refresh").press()
        await wait_until(lambda: message in str(screen.query_one("#live_stats", Static).content))
        live = screen.query_one("#live_stats", Static)
        assert live.content.plain == message if hasattr(live.content, "plain") else str(live.content) == message


async def test_an_unexpected_error_in_a_sample_shows_a_short_message_and_keeps_the_app() -> None:
    app = _LayoutHost()
    app.live_stats_service = _SequencedService(RuntimeError("boom [b]"))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        _button(screen, "btn_live_refresh").press()
        await wait_until(lambda: "failed" in str(screen.query_one("#live_stats", Static).content))
        assert "boom" not in str(screen.query_one("#live_stats", Static).content)
        assert app.is_running and not _button(screen, "btn_live_refresh").disabled


async def test_refresh_is_off_while_monitoring_and_says_why() -> None:
    app = _LayoutHost()

    class _Service:
        async def watch(self, instance):
            import asyncio
            while True:
                await asyncio.sleep(0.05)
                yield SimpleNamespace()

    app.live_stats_service = _Service()
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        with patch("servonaut.screens.server_actions.format_live_stats", lambda stats, **kw: "stats"):
            await pilot.press("l")
            await wait_until(lambda: screen._live_on)
            refresh = _button(screen, "btn_live_refresh")
            await wait_until(lambda: refresh.disabled)
            assert "already updating" in str(refresh.tooltip)
            await pilot.press("l")
            await wait_until(lambda: not refresh.disabled)


async def test_a_one_off_sample_is_headed_with_its_time_not_a_stop_hint() -> None:
    app = _LayoutHost()
    app.live_stats_service = _SequencedService(SimpleNamespace())
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        stats = SimpleNamespace(
            cpu_pct=10, mem_pct=20, mem_used_mb=1, mem_total_mb=5, load_1m=0.1, load_5m=0.2, load_15m=0.3,
            disk_pct=30, disk_used_gb=3, disk_total_gb=10, uptime="1 day",
        )
        app.live_stats_service = _SequencedService(stats)
        _button(screen, "btn_live_refresh").press()
        await wait_until(lambda: "sampled" in str(screen.query_one("#live_stats", Static).content))
        assert "to stop" not in str(screen.query_one("#live_stats", Static).content)


@pytest.mark.parametrize("open_findings,shown", [(3, "Findings 3"), (120, "Findings 99+")])
async def test_findings_count_has_no_brackets_and_never_caps_silently(open_findings: int, shown: str) -> None:
    app = _LayoutHost()
    rows = [{"status": "detected"}] * open_findings
    app.findings_service = SimpleNamespace(list_findings=AsyncMock(return_value={"findings": rows}))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        await wait_until(lambda: _button(screen, "btn_findings").label.plain.startswith(shown))
        assert "(" not in _button(screen, "btn_findings").label.plain
        assert _button(screen, "btn_findings").label.plain.rstrip().endswith("f")


async def test_the_findings_count_is_read_again_when_the_screen_resumes() -> None:
    app = _LayoutHost()
    service = SimpleNamespace(list_findings=AsyncMock(return_value={"findings": [{"status": "detected"}]}))
    app.findings_service = service
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        await wait_until(lambda: "Findings 1" in _button(screen, "btn_findings").label.plain)
        service.list_findings.return_value = {"findings": [{"status": "detected"}] * 4}
        screen.on_screen_resume()
        await wait_until(lambda: "Findings 4" in _button(screen, "btn_findings").label.plain)


async def test_every_action_button_has_a_tooltip() -> None:
    app = _LayoutHost()
    app.instances[0].update(is_ovh=True, provider_type="vps")
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        await wait_until(lambda: bool(screen.query("#btn_ovh_firewall")))
        for button in screen.query(ActionButton):
            if button.id == "btn_live_refresh" or button.display:
                assert button.tooltip, button.id


async def test_footer_bindings_are_copied_per_screen() -> None:
    app = _LayoutHost()
    class_bindings = {b.key: b.show for b in ServerActionsScreen.BINDINGS}
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await _open_actions(app, pilot)
        await wait_until(lambda: "6" in _footer_keys(screen))
    assert {b.key: b.show for b in ServerActionsScreen.BINDINGS} == class_bindings
    assert ServerActionsScreen._merged_bindings is not None if hasattr(ServerActionsScreen, "_merged_bindings") else True


@pytest.mark.parametrize("width,height", [(130, 40), (100, 30)])
async def test_card_rows_stay_on_one_line(width: int, height: int) -> None:
    app = _LayoutHost()
    async with app.run_test(size=(width, height)) as pilot:
        screen = await _open_actions(app, pilot)
        await wait_until(lambda: screen.query_one("#card_network").region.width > 0)
        await pilot.pause()
        for row in screen.query(".sa-card-actions"):
            ys = {button.region.y for button in row.query(ActionButton) if button.display}
            assert len(ys) == 1, (row.parent.id, ys)
