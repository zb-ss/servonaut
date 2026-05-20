"""Unit tests for the T11 first-connect memory-build prompt.

Covers:
    * ``should_show_first_connect_prompt`` gating: enabled flag +
      dismissed-count ceiling.
    * ``_increment_dismissal`` increments and saturates at MAX_DISMISSALS.
    * ``memory reset-prompts`` CLI resets the counter.
    * Rich-markup escape on the instance name so hostile names can't
      inject markup.

Textual pilot tests (full banner mount/dismiss) are skipped here — the
widget is thin UI over the `should_show_first_connect_prompt` gate and
its persistence path is exercised via direct AppConfig manipulation.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from servonaut.config.schema import AppConfig
from servonaut.widgets.memory_prompt import (
    MAX_DISMISSALS,
    MemoryPrompt,
    memory_needs_reprompt,
    should_show_first_connect_prompt,
)


# ---------------------------------------------------------------------------
# should_show_first_connect_prompt gating
# ---------------------------------------------------------------------------


class TestShouldShowFirstConnectPrompt:
    def test_defaults_allow_prompt(self) -> None:
        assert should_show_first_connect_prompt(AppConfig()) is True

    def test_suppressed_after_max_dismissals(self) -> None:
        cfg = AppConfig(memory_first_connect_dismissed_count=MAX_DISMISSALS)
        assert should_show_first_connect_prompt(cfg) is False

    def test_suppressed_when_memory_disabled(self) -> None:
        cfg = AppConfig()
        cfg.memory.enabled = False
        assert should_show_first_connect_prompt(cfg) is False

    def test_none_config_returns_false(self) -> None:
        assert should_show_first_connect_prompt(None) is False

    def test_count_below_max_allows(self) -> None:
        cfg = AppConfig(memory_first_connect_dismissed_count=MAX_DISMISSALS - 1)
        assert should_show_first_connect_prompt(cfg) is True

    def test_count_above_max_still_suppressed(self) -> None:
        """Defensive: out-of-band values shouldn't re-enable the prompt."""
        cfg = AppConfig(memory_first_connect_dismissed_count=MAX_DISMISSALS + 10)
        assert should_show_first_connect_prompt(cfg) is False


# ---------------------------------------------------------------------------
# memory_needs_reprompt — per-instance age gating
# ---------------------------------------------------------------------------


class TestMemoryNeedsReprompt:
    """The banner must not nag on every SSH connect — only when memory is
    missing entirely or its snapshot has aged past the re-prompt threshold."""

    _FOURTEEN_DAYS = 14 * 86400

    def test_missing_memory_always_reprompts(self) -> None:
        # age None == server has no memory at all.
        assert memory_needs_reprompt(None, self._FOURTEEN_DAYS) is True

    def test_fresh_memory_is_suppressed(self) -> None:
        # Probed an hour ago — well within the threshold.
        assert memory_needs_reprompt(3600, self._FOURTEEN_DAYS) is False

    def test_recently_stale_module_does_not_reprompt(self) -> None:
        # 6 hours old — a volatile module's TTL may have lapsed, but the
        # snapshot as a whole is nowhere near 14 days. This is the bug fix:
        # the banner must stay quiet here.
        assert memory_needs_reprompt(6 * 3600, self._FOURTEEN_DAYS) is False

    def test_old_memory_reprompts(self) -> None:
        # 15 days old — past the 14-day threshold.
        assert memory_needs_reprompt(15 * 86400, self._FOURTEEN_DAYS) is True

    def test_exactly_at_threshold_is_suppressed(self) -> None:
        # Boundary: age == threshold is NOT yet stale (strict greater-than).
        assert memory_needs_reprompt(self._FOURTEEN_DAYS, self._FOURTEEN_DAYS) is False


# ---------------------------------------------------------------------------
# Dismissal increment behaviour (direct, without mounting the widget)
# ---------------------------------------------------------------------------


class TestDismissalIncrement:
    def _widget_with_fake_app(self, initial_count: int = 0):
        prompt = MemoryPrompt({"id": "i-test", "name": "test"})

        class _FakeConfigManager:
            def __init__(self, cfg: AppConfig) -> None:
                self._cfg = cfg
                self.saved = []

            def get(self) -> AppConfig:
                return self._cfg

            def save(self, cfg: AppConfig) -> None:
                self._cfg = cfg
                self.saved.append(cfg)

        cfg = AppConfig(memory_first_connect_dismissed_count=initial_count)
        fake_app = MagicMock()
        fake_app.config_manager = _FakeConfigManager(cfg)
        # Only replace the .app accessor — everything else should not be
        # exercised by _increment_dismissal.
        type(prompt).app = property(lambda self, _app=fake_app: _app)  # type: ignore[assignment]
        return prompt, fake_app

    def test_first_dismissal_increments_to_1(self) -> None:
        prompt, fake_app = self._widget_with_fake_app(initial_count=0)
        prompt._increment_dismissal()
        saved = fake_app.config_manager.saved[-1]
        assert saved.memory_first_connect_dismissed_count == 1

    def test_third_dismissal_saturates_at_max(self) -> None:
        prompt, fake_app = self._widget_with_fake_app(
            initial_count=MAX_DISMISSALS
        )
        prompt._increment_dismissal()
        saved = fake_app.config_manager.saved[-1]
        # Saturates at MAX_DISMISSALS — does not overflow.
        assert saved.memory_first_connect_dismissed_count == MAX_DISMISSALS

    def test_increment_persists_monotonically(self) -> None:
        prompt, fake_app = self._widget_with_fake_app(initial_count=0)
        for expected in range(1, MAX_DISMISSALS + 1):
            prompt._increment_dismissal()
            saved = fake_app.config_manager.saved[-1]
            assert saved.memory_first_connect_dismissed_count == expected


# ---------------------------------------------------------------------------
# memory reset-prompts CLI
# ---------------------------------------------------------------------------


class TestResetPromptsCommand:
    def test_reset_sets_count_to_zero(self, tmp_path, monkeypatch, capsys) -> None:
        # Redirect config file to a temp path so we don't stomp the real one.
        monkeypatch.setenv("HOME", str(tmp_path))

        from servonaut.cli import memory as memory_cli
        from servonaut.config.manager import ConfigManager

        # Seed config with a non-zero count.
        cm = ConfigManager()
        cfg = cm.get()
        cfg.memory_first_connect_dismissed_count = 2
        cm.save(cfg)
        assert cm.get().memory_first_connect_dismissed_count == 2

        rc = memory_cli._cmd_reset_prompts(args=MagicMock())
        assert rc == 0

        # Re-open the config manager — must see 0.
        cm2 = ConfigManager()
        assert cm2.get().memory_first_connect_dismissed_count == 0

        captured = capsys.readouterr()
        assert "reset" in captured.out.lower()


# ---------------------------------------------------------------------------
# Markup safety
# ---------------------------------------------------------------------------


class TestMarkupEscape:
    """Hostile instance names must be escaped before rendering to Rich markup."""

    def test_hostile_name_is_escaped(self) -> None:
        from rich.markup import escape as rich_escape

        hostile = "[red]inject[/red]"
        prompt = MemoryPrompt({"id": "i-x", "name": hostile})
        rendered = prompt._label_markup()

        # Raw hostile tag must not appear unescaped.
        assert "[red]inject[/red]" not in rendered
        # Escaped form must be present.
        assert rich_escape(hostile) in rendered

    def test_plain_name_passes_through(self) -> None:
        prompt = MemoryPrompt({"id": "i-ok", "name": "prod-web-01"})
        rendered = prompt._label_markup()
        assert "prod-web-01" in rendered

    def test_falls_back_to_id_when_no_name(self) -> None:
        prompt = MemoryPrompt({"id": "i-noname"})
        assert "i-noname" in prompt._label_markup()

    def test_empty_instance_uses_default(self) -> None:
        prompt = MemoryPrompt({})
        # Falls back to the literal "server" string.
        assert "server" in prompt._label_markup()


# ---------------------------------------------------------------------------
# Action pathways (accept / dismiss / button / key) without pilot
# ---------------------------------------------------------------------------


class _FakeConfigManager:
    def __init__(self, cfg: AppConfig) -> None:
        self._cfg = cfg
        self.saved: list = []

    def get(self) -> AppConfig:
        return self._cfg

    def save(self, cfg: AppConfig) -> None:
        self._cfg = cfg
        self.saved.append(cfg)


class _FakeApp:
    def __init__(self, cfg: AppConfig, memory_service=None) -> None:
        self.config_manager = _FakeConfigManager(cfg)
        self.memory_service = memory_service
        self.notifications: list = []
        self.worker_calls: list = []

    def notify(self, msg: str, *args, **kwargs) -> None:
        self.notifications.append((msg, args, kwargs))

    def run_worker(self, coro, **kwargs):
        self.worker_calls.append(("run_worker", kwargs))
        # Close so asyncio doesn't warn about an un-awaited coroutine.
        try:
            coro.close()
        except Exception:  # noqa: BLE001
            pass


def _bind_app(prompt: MemoryPrompt, app: _FakeApp) -> None:
    """Make prompt.app return *app* without actually mounting the widget."""
    type(prompt).app = property(lambda self, _a=app: _a)  # type: ignore[assignment]


class TestActionPathways:
    def _make_prompt(self, cfg_count: int = 0, memory_service=None):
        prompt = MemoryPrompt({"id": "i-acc", "name": "acc-server"})
        cfg = AppConfig(memory_first_connect_dismissed_count=cfg_count)
        app = _FakeApp(cfg, memory_service=memory_service)
        _bind_app(prompt, app)

        widget_calls: list = []

        def _widget_run_worker(coro, **kwargs):
            # If anything ends up here, the build will be cancelled the
            # instant _hide() removes the widget — that's the bug we
            # regression-test against.
            widget_calls.append(("run_worker", kwargs))
            try:
                coro.close()
            except Exception:  # noqa: BLE001
                pass

        def _add_class(name: str) -> None:
            widget_calls.append(("add_class", name))

        def _remove() -> None:
            widget_calls.append(("remove",))

        prompt.run_worker = _widget_run_worker  # type: ignore[assignment]
        prompt.add_class = _add_class  # type: ignore[assignment]
        prompt.remove = _remove  # type: ignore[assignment]
        return prompt, app, widget_calls

    def test_action_accept_dispatches_build(self) -> None:
        mem = MagicMock()
        prompt, app, widget_calls = self._make_prompt(memory_service=mem)
        prompt.action_accept()

        # The build worker MUST run on the app, not on the widget.
        # action_accept calls self._hide() which removes the widget right
        # after dispatching — any worker owned by the widget gets
        # cancelled and the build silently never executes.
        assert any(
            c[0] == "run_worker" for c in app.worker_calls
        ), "build worker should be spawned via app.run_worker, not prompt.run_worker"
        assert not any(
            c[0] == "run_worker" for c in widget_calls
        ), (
            "regression: build worker spawned on the widget would be "
            "cancelled by self.remove() in _hide() and the probe would "
            "silently not run"
        )
        # The banner was hidden.
        assert any(c == ("add_class", "hidden") for c in widget_calls)

    def test_action_accept_without_memory_service_notifies(self) -> None:
        prompt, app, calls = self._make_prompt(memory_service=None)
        prompt.action_accept()
        assert app.notifications, "Missing memory service must surface a notification"

    def test_action_dismiss_banner_increments_counter(self) -> None:
        prompt, app, calls = self._make_prompt(cfg_count=0)
        prompt.action_dismiss_banner()
        saved = app.config_manager.saved[-1]
        assert saved.memory_first_connect_dismissed_count == 1
        # Banner is hidden.
        assert any(c == ("add_class", "hidden") for c in calls)

    def test_on_button_pressed_accept(self) -> None:
        prompt, app, calls = self._make_prompt(memory_service=MagicMock())
        event = MagicMock()
        event.button.id = "memory_prompt_accept"
        prompt.on_button_pressed(event)
        assert any(c[0] == "run_worker" for c in app.worker_calls)

    def test_on_button_pressed_dismiss(self) -> None:
        prompt, app, calls = self._make_prompt(cfg_count=0)
        event = MagicMock()
        event.button.id = "memory_prompt_dismiss"
        prompt.on_button_pressed(event)
        assert app.config_manager.saved[-1].memory_first_connect_dismissed_count == 1

    def test_on_button_pressed_unknown_id_is_noop(self) -> None:
        prompt, app, calls = self._make_prompt()
        event = MagicMock()
        event.button.id = "not_our_button"
        prompt.on_button_pressed(event)
        assert calls == [], "Unknown button id must not trigger any side effects"

    def test_on_key_accepts_y(self) -> None:
        prompt, app, calls = self._make_prompt(memory_service=MagicMock())
        event = MagicMock()
        event.character = "y"
        prompt.on_key(event)
        assert any(c[0] == "run_worker" for c in app.worker_calls)
        event.stop.assert_called_once()

    def test_on_key_dismisses_n(self) -> None:
        prompt, app, calls = self._make_prompt()
        event = MagicMock()
        event.character = "n"
        prompt.on_key(event)
        assert app.config_manager.saved, "n key must persist a dismissal"
        event.stop.assert_called_once()

    def test_on_key_ignores_other_chars(self) -> None:
        prompt, app, calls = self._make_prompt()
        event = MagicMock()
        event.character = "x"
        prompt.on_key(event)
        event.stop.assert_not_called()
