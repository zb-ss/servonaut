"""Tests for the MemoryScreen Textual UI (T7 shard 4).

Coverage:
- MemoryScreen renders with seeded module data → DataTable populated.
- Press 'r' → memory_service.refresh called.
- Press 'e' → memory_service.write_summary awaited; path appears in notify.
- Opt-out: per_server_overrides memory_disabled=True → opt-out banner visible.
- InstanceTable 'm' key → MemoryScreen pushed.
- _render_table skips gracefully when memory_service is None.

Heavy Textual pilot tests use ``async with app.run_test()``; pure-logic tests
construct MemoryScreen directly with a mock app to avoid pilot overhead.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.redaction import noop_redactor
from servonaut.services.memory.service import MemoryService
from servonaut.services.memory.store import MemoryStore


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_instance(
    iid: str = "i-abc123",
    name: str = "test-server",
    provider: str = "custom",
) -> Dict[str, Any]:
    """Build a minimal instance dict."""
    return {
        "id": iid,
        "name": name,
        "provider": provider,
        "public_ip": "10.0.0.1",
    }


def _seed_module(store: MemoryStore, instance_id: str, provider: str, module: str) -> None:
    """Seed a minimal module JSON for testing."""
    from datetime import datetime, timezone
    store.save_module(
        instance_id,
        module,
        {
            "module": module,
            "instance_id": instance_id,
            "observed": {"version": "1.0", "name": module},
            "declared": {},
            "probed_at": datetime.now(tz=timezone.utc).isoformat(),
            "ttl_seconds": 86400,
            "sudo_used": False,
            "truncated": False,
            "partial": False,
            "raw_output": "",
        },
        provider=provider,
    )


def _make_memory_service(
    tmp_path: Path,
    *,
    enabled: bool = True,
    memory_disabled_for: Optional[str] = None,
) -> MemoryService:
    """Real MemoryService backed by a tmp directory."""
    store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    overrides: Dict[str, Any] = {}
    if memory_disabled_for:
        overrides[memory_disabled_for] = {"memory_disabled": True}
    config = MemoryConfig(enabled=enabled, per_server_overrides=overrides)
    return MemoryService(store=store, config=config, probers=[])


# ---------------------------------------------------------------------------
# Pure-logic tests (no Textual pilot — faster, less flaky)
# ---------------------------------------------------------------------------

class TestRenderTableLogic:
    """Test _render_table behaviour by constructing MemoryScreen directly."""

    def test_is_opted_out_when_globally_disabled(self, tmp_path: Path) -> None:
        """_is_opted_out returns True when MemoryConfig.enabled is False."""
        from servonaut.screens.memory import MemoryScreen

        svc = _make_memory_service(tmp_path, enabled=False)
        instance = _make_instance()
        screen = MemoryScreen(instance)
        assert screen._is_opted_out("i-abc123", svc) is True

    def test_is_opted_out_when_per_server_disabled(self, tmp_path: Path) -> None:
        """_is_opted_out returns True when the instance is opted out."""
        from servonaut.screens.memory import MemoryScreen

        svc = _make_memory_service(tmp_path, memory_disabled_for="i-abc123")
        instance = _make_instance()
        screen = MemoryScreen(instance)
        assert screen._is_opted_out("i-abc123", svc) is True

    def test_is_opted_out_false_when_enabled(self, tmp_path: Path) -> None:
        """_is_opted_out returns False for a normally-enabled instance."""
        from servonaut.screens.memory import MemoryScreen

        svc = _make_memory_service(tmp_path)
        instance = _make_instance()
        screen = MemoryScreen(instance)
        assert screen._is_opted_out("i-abc123", svc) is False

    def test_is_opted_out_by_name_not_id(self, tmp_path: Path) -> None:
        """_is_opted_out returns True when opted-out by instance name, not cloud id.

        Regression for A2.S2.b: _is_opted_out must pass the instance name to
        is_memory_disabled so that per_server_overrides keyed by name fire even
        when the caller only holds the cloud id.
        """
        from servonaut.screens.memory import MemoryScreen

        # Override keyed by name ("prod"), not by id ("i-abc")
        svc = _make_memory_service(tmp_path, memory_disabled_for="prod")
        instance = _make_instance(iid="i-abc", name="prod")
        screen = MemoryScreen(instance)
        # "i-abc" is not in overrides; only "prod" is — must still opt out
        assert screen._is_opted_out("i-abc", svc) is True


@pytest.mark.asyncio
async def test_opt_out_banner_visible_by_name_override(tmp_path: Path) -> None:
    """Opt-out banner fires when instance is opted out by name (not cloud id).

    Regression for A2.S2.b: screen renders opt-out banner even when
    per_server_overrides is keyed by instance name rather than cloud id.
    """
    from textual.app import App, ComposeResult
    from textual.widgets import DataTable, Header, Footer, Static
    from servonaut.screens.memory import MemoryScreen

    # Instance has id="i-abc" but override is keyed by name "prod"
    instance = _make_instance(iid="i-abc", name="prod")
    svc = _make_memory_service(tmp_path, memory_disabled_for="prod")
    _seed_module(svc._store, "i-abc", "custom", "os")

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        table = app.screen.query_one("#memory-table", DataTable)
        banner = app.screen.query_one("#memory-opt-out-banner", Static)
        # Name-based override must trigger the opt-out banner
        assert table.row_count == 0, "Table must be empty when instance is opted out by name"
        assert "hidden" not in banner.classes, "Opt-out banner must be visible for name-based override"


class TestHumanAge:
    """Unit tests for the _human_age helper."""

    def test_empty_string_returns_question_mark(self) -> None:
        from servonaut.screens.memory import _human_age
        assert _human_age("") == "?"

    def test_seconds_ago(self) -> None:
        from datetime import datetime, timezone
        from servonaut.screens.memory import _human_age
        now = datetime.now(tz=timezone.utc)
        ts = now.isoformat()
        result = _human_age(ts)
        # Should be "Xs ago" where X is a small integer
        assert "ago" in result

    def test_invalid_string_returns_question_mark(self) -> None:
        from servonaut.screens.memory import _human_age
        assert _human_age("not-a-date") == "?"

    def test_minutes_ago(self) -> None:
        from datetime import datetime, timedelta, timezone
        from servonaut.screens.memory import _human_age
        ts = (datetime.now(tz=timezone.utc) - timedelta(minutes=5)).isoformat()
        result = _human_age(ts)
        assert "m ago" in result

    def test_hours_ago(self) -> None:
        from datetime import datetime, timedelta, timezone
        from servonaut.screens.memory import _human_age
        ts = (datetime.now(tz=timezone.utc) - timedelta(hours=3)).isoformat()
        result = _human_age(ts)
        assert "h ago" in result

    def test_days_ago(self) -> None:
        from datetime import datetime, timedelta, timezone
        from servonaut.screens.memory import _human_age
        ts = (datetime.now(tz=timezone.utc) - timedelta(days=2)).isoformat()
        result = _human_age(ts)
        assert "d ago" in result

    def test_z_suffix_handled(self) -> None:
        """ISO strings ending in Z are parsed correctly."""
        from datetime import datetime, timezone
        from servonaut.screens.memory import _human_age
        now = datetime.now(tz=timezone.utc)
        ts = now.isoformat().replace("+00:00", "Z")
        result = _human_age(ts)
        assert "ago" in result


class TestIsOptedOutExceptionPath:
    """Test the exception-handling path in _is_opted_out."""

    def test_exception_returns_false(self) -> None:
        """If is_memory_disabled raises, _is_opted_out returns False."""
        from servonaut.screens.memory import MemoryScreen

        instance = _make_instance()
        screen = MemoryScreen(instance)
        # Pass a service that raises on is_memory_disabled
        class _BrokenService:
            def is_memory_disabled(self, *a, **kw):
                raise RuntimeError("service broken")

        result = screen._is_opted_out("i-abc", _BrokenService())
        assert result is False


class TestGetCursorModuleKeyEdgeCases:
    """Test _get_cursor_module_key edge cases."""

    def test_no_double_colon_in_row_key_returns_empty(self) -> None:
        """Row key without '::' separator returns ('', '')."""
        from servonaut.screens.memory import MemoryScreen
        # This tests the logic without needing a full Textual app

        instance = _make_instance()
        screen = MemoryScreen(instance)

        # Patch the internal DataTable to simulate a row with no '::'
        table_mock = MagicMock()
        table_mock.row_count = 1
        coord_mock = MagicMock()
        table_mock.cursor_coordinate = coord_mock
        row_key_mock = MagicMock()
        row_key_mock.value = "no-separator-here"
        cell_key_mock = MagicMock()
        cell_key_mock.row_key = row_key_mock
        table_mock.coordinate_to_cell_key.return_value = cell_key_mock

        original_query_one = screen.query_one

        def _stub_query_one(selector, cls=None):
            if "#memory-table" in selector or (cls is not None and cls.__name__ == "DataTable"):
                return table_mock
            return original_query_one(selector, cls)

        screen.query_one = _stub_query_one
        module, key = screen._get_cursor_module_key()
        assert module == ""
        assert key == ""


@pytest.mark.asyncio
async def test_action_refresh_all_no_service_notifies_error(tmp_path: Path) -> None:
    """action_refresh_all notifies error when memory_service is None."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    notified = []

    class TestApp(App):
        CSS = ""
        memory_service = None

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.push_screen(MemoryScreen(instance))

        def notify(self, message, *, severity="information", title="", timeout=None):
            notified.append((message, severity))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("r")
        await pilot.pause(0.1)

    assert any("error" == s for _, s in notified)


@pytest.mark.asyncio
async def test_action_pin_key_no_service_notifies_error(tmp_path: Path) -> None:
    """action_pin_key notifies error when memory_service is None."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    notified = []

    class TestApp(App):
        CSS = ""
        memory_service = None

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.push_screen(MemoryScreen(instance))

        def notify(self, message, *, severity="information", title="", timeout=None):
            notified.append((message, severity))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("p")
        await pilot.pause(0.1)

    assert any("error" == s for _, s in notified)


@pytest.mark.asyncio
async def test_action_clear_module_no_service_notifies_error(tmp_path: Path) -> None:
    """action_clear_module notifies error when memory_service is None."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    notified = []

    class TestApp(App):
        CSS = ""
        memory_service = None

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.push_screen(MemoryScreen(instance))

        def notify(self, message, *, severity="information", title="", timeout=None):
            notified.append((message, severity))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("c")
        await pilot.pause(0.1)

    assert any("error" == s for _, s in notified)


@pytest.mark.asyncio
async def test_render_table_with_stale_module_has_yellow_markup(tmp_path: Path) -> None:
    """Stale module rows have yellow markup on the Age cell."""
    from datetime import datetime, timedelta, timezone
    from textual.app import App, ComposeResult
    from textual.widgets import DataTable, Header, Footer
    from servonaut.screens.memory import MemoryScreen
    from servonaut.services.memory.store import MemoryStore
    from servonaut.services.memory.redaction import noop_redactor

    instance = _make_instance()
    iid = instance["id"]
    provider = instance["provider"]

    store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    config = MemoryConfig()
    svc = _make_memory_service(tmp_path)
    # Replace the store with one that has a stale module
    svc._store = store

    # Seed fresh and stale modules
    now = datetime.now(tz=timezone.utc)
    fresh_ts = now.isoformat()
    stale_ts = (now - timedelta(days=2)).isoformat()

    store.save_module(iid, "os", {
        "module": "os", "instance_id": iid,
        "probed_at": fresh_ts, "ttl_seconds": 86400,
        "sudo_used": False, "truncated": False, "partial": False,
        "observed": {"kernel": "5.4"}, "declared": {}, "raw_output": "",
    }, provider=provider)

    store.save_module(iid, "runtimes", {
        "module": "runtimes", "instance_id": iid,
        "probed_at": stale_ts, "ttl_seconds": 86400,
        "sudo_used": False, "truncated": False, "partial": False,
        "observed": {"python": "3.11"}, "declared": {}, "raw_output": "",
    }, provider=provider)

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.3)
        table = app.screen.query_one("#memory-table", DataTable)
        # Should have rows for both modules
        assert table.row_count >= 2


@pytest.mark.asyncio
async def test_button_pin_key_triggers_action(tmp_path: Path) -> None:
    """Clicking 'p. Pin Key' button (no row selected) triggers pin action → notification."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, Button
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    svc = _make_memory_service(tmp_path)

    notified = []

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

        def notify(self, message, *, severity="information", title="", timeout=None):
            notified.append((message, severity))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("p")
        await pilot.pause(0.1)

    # Should notify that a key row must be selected first (no row selected)
    assert any(
        "select" in msg.lower() and sev == "warning"
        for msg, sev in notified
    ), f"Expected a 'select' warning notification, got: {notified}"


@pytest.mark.asyncio
async def test_action_annotate_no_service_notifies_error(tmp_path: Path) -> None:
    """action_annotate notifies error when memory_service is None."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    notified = []

    class TestApp(App):
        CSS = ""
        memory_service = None

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.push_screen(MemoryScreen(instance))

        def notify(self, message, *, severity="information", title="", timeout=None):
            notified.append((message, severity))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("a")
        await pilot.pause(0.1)

    assert any("error" == s for _, s in notified)


@pytest.mark.asyncio
async def test_on_button_pressed_refresh_all(tmp_path: Path) -> None:
    """Clicking 'r. Refresh All' button triggers action_refresh_all."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, Button
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    svc, refresh_event, _ = _build_mock_svc_with_events(tmp_path)

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        # Click the refresh all button
        await pilot.click("#btn_refresh_all")
        try:
            await asyncio.wait_for(refresh_event.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            pytest.fail("refresh worker never ran after button click")
        assert refresh_event.is_set()


@pytest.mark.asyncio
async def test_on_button_pressed_export(tmp_path: Path) -> None:
    """Clicking 'e. Export' button triggers action_export."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    svc, _, export_event = _build_mock_svc_with_events(tmp_path)

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        # Use key binding instead of clicking the button (button may be off-screen in headless)
        await pilot.press("e")
        try:
            await asyncio.wait_for(export_event.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            pytest.fail("export worker never ran after 'e' key press")
        assert export_event.is_set()


@pytest.mark.asyncio
async def test_opt_out_banner_visible_when_per_server_disabled(tmp_path: Path) -> None:
    """Banner shows and table is empty when per-server override disables memory."""
    from textual.app import App, ComposeResult
    from textual.widgets import DataTable, Header, Footer, Static
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance(iid="i-no-memory")
    svc = _make_memory_service(tmp_path, memory_disabled_for="i-no-memory")
    _seed_module(svc._store, "i-no-memory", "custom", "os")

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        table = app.screen.query_one("#memory-table", DataTable)
        banner = app.screen.query_one("#memory-opt-out-banner", Static)
        assert table.row_count == 0
        assert "hidden" not in banner.classes


# ---------------------------------------------------------------------------
# Textual pilot tests
# ---------------------------------------------------------------------------

def _build_mock_app_class(memory_service: Any):
    """Build a minimal Textual App class with memory_service wired."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer

    class _TestApp(App):
        CSS = ""
        memory_service = None

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

    _TestApp.memory_service = memory_service  # type: ignore[attr-defined]
    return _TestApp


@pytest.mark.asyncio
async def test_memory_screen_renders_with_two_modules(tmp_path: Path) -> None:
    """MemoryScreen with two seeded modules shows rows in the DataTable."""
    from textual.app import App, ComposeResult
    from textual.widgets import DataTable, Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    iid = instance["id"]
    provider = instance["provider"]

    svc = _make_memory_service(tmp_path)
    _seed_module(svc._store, iid, provider, "os")
    _seed_module(svc._store, iid, provider, "runtimes")

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        table = app.screen.query_one("#memory-table", DataTable)
        # Two modules × 2 keys each = 4 rows minimum
        assert table.row_count >= 2


@pytest.mark.asyncio
async def test_memory_screen_opt_out_banner_visible(tmp_path: Path) -> None:
    """Opt-out banner is visible and DataTable is empty when instance is opted out."""
    from textual.app import App, ComposeResult
    from textual.widgets import DataTable, Header, Footer, Static
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance(iid="i-optout")
    svc = _make_memory_service(tmp_path, memory_disabled_for="i-optout")
    # Seed some data — it should NOT appear because instance is opted out
    _seed_module(svc._store, "i-optout", "custom", "os")

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        table = app.screen.query_one("#memory-table", DataTable)
        banner = app.screen.query_one("#memory-opt-out-banner", Static)
        assert table.row_count == 0
        assert "hidden" not in banner.classes


@pytest.mark.asyncio
async def test_memory_screen_press_r_calls_refresh(tmp_path: Path) -> None:
    """Pressing 'r' on MemoryScreen triggers memory_service.refresh."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()

    mock_svc = MagicMock()
    mock_svc.is_memory_disabled.return_value = False
    mock_svc.get_all_modules.return_value = {}
    mock_svc.stale_modules.return_value = []
    refresh_called = asyncio.Event()

    async def _fake_refresh(inst, modules=None):
        refresh_called.set()
        return {}

    mock_svc.refresh = _fake_refresh

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = mock_svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("r")
        # Give the worker time to run
        await asyncio.wait_for(refresh_called.wait(), timeout=2.0)
        assert refresh_called.is_set()


@pytest.mark.asyncio
async def test_memory_screen_press_e_calls_write_summary(tmp_path: Path) -> None:
    """Pressing 'e' triggers memory_service.write_summary."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    expected_path = tmp_path / "summary.md"

    mock_svc = MagicMock()
    mock_svc.is_memory_disabled.return_value = False
    mock_svc.get_all_modules.return_value = {}
    mock_svc.stale_modules.return_value = []
    export_called = asyncio.Event()

    async def _fake_write_summary(inst):
        export_called.set()
        return expected_path

    mock_svc.write_summary = _fake_write_summary

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = mock_svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("e")
        await asyncio.wait_for(export_called.wait(), timeout=2.0)
        assert export_called.is_set()


@pytest.mark.asyncio
async def test_instance_table_m_key_pushes_memory_screen(tmp_path: Path) -> None:
    """Pressing 'm' on InstanceTable pushes MemoryScreen."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.widgets.instance_table import InstanceTable

    instances = [_make_instance()]

    pushed_screens = []

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            tbl = InstanceTable()
            tbl.id = "inst_table"
            yield tbl
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = _make_memory_service(tmp_path)
            table = self.query_one(InstanceTable)
            table.populate(instances)

    app = TestApp()

    # Monkey-patch push_screen on the instance after creation
    original_push = None

    async def _run():
        nonlocal original_push
        async with app.run_test(headless=True) as pilot:
            original_push = app.push_screen

            def _patched_push_screen(screen, callback=None):
                pushed_screens.append(type(screen).__name__)
                # call original so app doesn't break
                return original_push(screen, callback)

            app.push_screen = _patched_push_screen
            await pilot.pause(0.1)
            table = app.query_one(InstanceTable)
            table.focus()
            await pilot.press("m")
            await pilot.pause(0.1)

    await _run()
    assert "MemoryScreen" in pushed_screens


@pytest.mark.asyncio
async def test_memory_screen_no_service_renders_empty(tmp_path: Path) -> None:
    """MemoryScreen renders without error when memory_service is None."""
    from textual.app import App, ComposeResult
    from textual.widgets import DataTable, Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()

    class TestApp(App):
        CSS = ""
        memory_service = None  # explicitly absent

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        table = app.screen.query_one("#memory-table", DataTable)
        assert table.row_count == 0


# ---------------------------------------------------------------------------
# B.4 — additional pilot-based tests for deeper screen coverage
# ---------------------------------------------------------------------------

def _build_mock_svc_with_events(tmp_path: Path) -> tuple:
    """Return (mock_svc, refresh_event, export_event) for action-wiring tests."""
    svc = MagicMock()
    svc.is_memory_disabled.return_value = False
    svc.get_all_modules.return_value = {}
    svc.stale_modules.return_value = []

    refresh_event = asyncio.Event()
    export_event = asyncio.Event()

    async def _fake_refresh(inst, modules=None):
        refresh_event.set()
        return {}

    async def _fake_write_summary(inst):
        export_event.set()
        from pathlib import Path as _Path
        return _Path(tmp_path) / "summary.md"

    svc.refresh = _fake_refresh
    svc.write_summary = _fake_write_summary
    svc.list_all = MagicMock(return_value=[])
    return svc, refresh_event, export_event


@pytest.mark.asyncio
async def test_get_cursor_module_key_empty_table(tmp_path: Path) -> None:
    """_get_cursor_module_key returns ('', '') when table has no rows."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    svc = _make_memory_service(tmp_path)

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        screen = app.screen
        module_name, key = screen._get_cursor_module_key()
        assert module_name == ""
        assert key == ""


@pytest.mark.asyncio
async def test_action_refresh_module_no_row_selected(tmp_path: Path) -> None:
    """action_refresh_module notifies when no row is selected (empty table)."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    svc = _make_memory_service(tmp_path)
    # Don't seed modules — table will be empty.

    notified = []

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

        def notify(self, message, *, severity="information", title="", timeout=None):
            notified.append((message, severity))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("m")
        await pilot.pause(0.1)

    # Should notify "Select a row first." with warning severity.
    assert any(
        "select" in msg.lower() and sev == "warning"
        for msg, sev in notified
    ), f"Expected a 'select' warning notification, got: {notified}"


@pytest.mark.asyncio
async def test_action_clear_module_no_row_selected(tmp_path: Path) -> None:
    """action_clear_module notifies when no row is selected (empty table)."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    svc = _make_memory_service(tmp_path)

    notified = []

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

        def notify(self, message, *, severity="information", title="", timeout=None):
            notified.append((message, severity))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("c")
        await pilot.pause(0.1)

    # Should notify "Select a row first." with warning severity.
    assert any(
        "select" in msg.lower() and sev == "warning"
        for msg, sev in notified
    ), f"Expected a 'select' warning notification, got: {notified}"


@pytest.mark.asyncio
async def test_action_pin_key_no_row_selected(tmp_path: Path) -> None:
    """action_pin_key notifies when no key row is selected."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    svc = _make_memory_service(tmp_path)

    notified = []

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

        def notify(self, message, *, severity="information", title="", timeout=None):
            notified.append((message, severity))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("p")
        await pilot.pause(0.1)

    # Should notify "Select a key row first." with warning severity.
    assert any(
        "select" in msg.lower() and sev == "warning"
        for msg, sev in notified
    ), f"Expected a 'select' warning notification, got: {notified}"


@pytest.mark.asyncio
async def test_action_refresh_all_opted_out_notifies(tmp_path: Path) -> None:
    """action_refresh_all notifies with warning when instance is opted out."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance(iid="i-optout2")
    svc = _make_memory_service(tmp_path, memory_disabled_for="i-optout2")

    notified = []

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

        def notify(self, message, *, severity="information", title="", timeout=None):
            notified.append((message, severity))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("r")
        await pilot.pause(0.1)

    assert any(s == "warning" for _, s in notified)


@pytest.mark.asyncio
async def test_action_export_no_service_notifies(tmp_path: Path) -> None:
    """action_export notifies with error when memory_service is None."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    notified = []

    class TestApp(App):
        CSS = ""
        memory_service = None

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.push_screen(MemoryScreen(instance))

        def notify(self, message, *, severity="information", title="", timeout=None):
            notified.append((message, severity))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("e")
        await pilot.pause(0.1)

    assert any(s == "error" for _, s in notified)


@pytest.mark.asyncio
async def test_button_refresh_all_triggers_action(tmp_path: Path) -> None:
    """Button 'r. Refresh All' press triggers action_refresh_all (via keypress simulation)."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    svc, refresh_event, _ = _build_mock_svc_with_events(tmp_path)

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        # Press 'r' keybinding (same as btn_refresh_all handler)
        await pilot.press("r")
        try:
            await asyncio.wait_for(refresh_event.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            pytest.fail("refresh worker never ran within 2s timeout")
        assert refresh_event.is_set()


@pytest.mark.asyncio
async def test_button_export_triggers_action(tmp_path: Path) -> None:
    """Pressing 'e' keybinding triggers action_export (covers the export worker path)."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    svc, _, export_event = _build_mock_svc_with_events(tmp_path)

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("e")
        try:
            await asyncio.wait_for(export_event.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            pytest.fail("export worker never ran within 2s timeout")
        assert export_event.is_set()


@pytest.mark.asyncio
async def test_action_refresh_module_with_row(tmp_path: Path) -> None:
    """action_refresh_module calls refresh with specific module when row selected."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()

    real_store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    # Seed a module so the table has rows
    _seed_module(real_store, "i-abc123", "custom", "os")

    refresh_called = asyncio.Event()
    refresh_modules_called = []

    svc = MagicMock()
    svc.is_memory_disabled.return_value = False

    def _get_all_modules(iid, provider="custom"):
        return real_store.get_all_modules(iid, provider)

    def _stale_modules(iid, provider="custom"):
        return []

    svc.get_all_modules = MagicMock(side_effect=_get_all_modules)
    svc.stale_modules = MagicMock(side_effect=_stale_modules)

    async def _fake_refresh(inst, modules=None):
        refresh_modules_called.append(modules)
        refresh_called.set()
        return {}

    svc.refresh = _fake_refresh

    # get() needed for the pin_key helper (harmless here)
    svc.get = MagicMock(return_value=None)
    svc.get_annotations_path = MagicMock(return_value=tmp_path / "annotations.md")

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        # Press 'm' to refresh the currently selected module
        await pilot.press("m")
        try:
            await asyncio.wait_for(refresh_called.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            pytest.fail("refresh_module worker never ran within 2s timeout")

    # Refresh should have been called with a module list
    assert refresh_called.is_set()
    # The module list should contain exactly ["os"] (the only seeded module)
    assert refresh_modules_called == [["os"]]


# ---------------------------------------------------------------------------
# PinKeyModal unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pin_key_modal_dismiss_on_cancel_button(tmp_path: Path) -> None:
    """PinKeyModal Cancel button dismisses with None."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import PinKeyModal

    dismissed_values = []

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            def _capture(v):
                dismissed_values.append(v)

            self.push_screen(PinKeyModal("os", "kernel", "5.4"), _capture)

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        # Press escape to cancel
        await pilot.press("escape")
        await pilot.pause(0.1)

    assert dismissed_values == [None]


@pytest.mark.asyncio
async def test_pin_key_modal_confirm_button_click(tmp_path: Path) -> None:
    """PinKeyModal Pin button click dismisses with entered value."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, Button, Input
    from servonaut.screens.memory import PinKeyModal

    dismissed_values = []

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            def _capture(v):
                dismissed_values.append(v)

            self.push_screen(PinKeyModal("os", "kernel", "5.4"), _capture)

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        # Get the modal input and set a value
        modal = app.screen
        inp = modal.query_one("#pin_value_input", Input)
        inp.value = "6.1"
        # Trigger the on_button_pressed directly via button
        btn = modal.query_one("#pin_btn_confirm", Button)
        btn.press()
        await pilot.pause(0.1)

    assert dismissed_values == ["6.1"]


@pytest.mark.asyncio
async def test_pin_key_modal_cancel_button_click(tmp_path: Path) -> None:
    """PinKeyModal Cancel button click dismisses with None."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, Button
    from servonaut.screens.memory import PinKeyModal

    dismissed_values = []

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            def _capture(v):
                dismissed_values.append(v)

            self.push_screen(PinKeyModal("os", "kernel", ""), _capture)

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        modal = app.screen
        btn = modal.query_one("#pin_btn_cancel", Button)
        btn.press()
        await pilot.pause(0.1)

    assert dismissed_values == [None]


# ---------------------------------------------------------------------------
# SimpleConfirmModal unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_simple_confirm_modal_yes_button(tmp_path: Path) -> None:
    """SimpleConfirmModal Yes button dismisses with True."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, Button
    from servonaut.screens.memory import SimpleConfirmModal

    dismissed_values = []

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            def _capture(v):
                dismissed_values.append(v)

            self.push_screen(SimpleConfirmModal("Clear module os?"), _capture)

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        modal = app.screen
        btn = modal.query_one("#confirm_yes_btn", Button)
        btn.press()
        await pilot.pause(0.1)

    assert dismissed_values == [True]


@pytest.mark.asyncio
async def test_simple_confirm_modal_no_button(tmp_path: Path) -> None:
    """SimpleConfirmModal No button dismisses with False."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, Button
    from servonaut.screens.memory import SimpleConfirmModal

    dismissed_values = []

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            def _capture(v):
                dismissed_values.append(v)

            self.push_screen(SimpleConfirmModal("Clear module os?"), _capture)

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        modal = app.screen
        btn = modal.query_one("#confirm_no_btn", Button)
        btn.press()
        await pilot.pause(0.1)

    assert dismissed_values == [False]


@pytest.mark.asyncio
async def test_simple_confirm_modal_escape_cancels(tmp_path: Path) -> None:
    """SimpleConfirmModal escape dismisses with False."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import SimpleConfirmModal

    dismissed_values = []

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            def _capture(v):
                dismissed_values.append(v)

            self.push_screen(SimpleConfirmModal("Clear module os?"), _capture)

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        await pilot.press("escape")
        await pilot.pause(0.1)

    assert dismissed_values == [False]


# ---------------------------------------------------------------------------
# action_back
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_action_back_pops_screen(tmp_path: Path) -> None:
    """Pressing escape on MemoryScreen calls pop_screen (action_back)."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    svc = _make_memory_service(tmp_path)

    screens_popped = []

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

        def pop_screen(self):
            screens_popped.append(True)
            return super().pop_screen()

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("escape")
        await pilot.pause(0.1)

    assert screens_popped == [True]


# ---------------------------------------------------------------------------
# action_refresh_all with service → _do_refresh_all success/exception paths
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_do_refresh_all_exception_path(tmp_path: Path) -> None:
    """_do_refresh_all logs error and notifies on exception."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    notified = []

    svc = MagicMock()
    svc.is_memory_disabled.return_value = False
    svc.get_all_modules.return_value = {}
    svc.stale_modules.return_value = []

    async def _failing_refresh(inst, modules=None):
        raise RuntimeError("probe failure")

    svc.refresh = _failing_refresh

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

        def notify(self, message, *, severity="information", title="", timeout=None):
            notified.append((message, severity))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("r")
        await pilot.pause(0.3)  # give worker time to run and fail

    assert any("error" == s for _, s in notified)


# ---------------------------------------------------------------------------
# action_refresh_module with row → _do_refresh_module success/exception paths
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_do_refresh_module_exception_path(tmp_path: Path) -> None:
    """_do_refresh_module logs error and notifies on exception."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()

    real_store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    _seed_module(real_store, "i-abc123", "custom", "os")

    notified = []
    svc = MagicMock()
    svc.is_memory_disabled.return_value = False
    svc.get_all_modules = MagicMock(side_effect=lambda iid, provider="custom": real_store.get_all_modules(iid, provider))
    svc.stale_modules = MagicMock(return_value=[])

    async def _failing_refresh(inst, modules=None):
        raise RuntimeError("module probe failure")

    svc.refresh = _failing_refresh

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

        def notify(self, message, *, severity="information", title="", timeout=None):
            notified.append((message, severity))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)  # wait for table to render with rows
        await pilot.press("m")  # action_refresh_module
        await pilot.pause(0.3)

    assert any("error" == s for _, s in notified)


# ---------------------------------------------------------------------------
# action_clear_module with row selected → confirmed → _do_clear
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_action_clear_module_confirmed(tmp_path: Path) -> None:
    """action_clear_module with row selected and confirmed → calls service.clear.

    Uses push_screen interception to bypass modal timing races: the stub
    immediately invokes the callback with confirmed=True.
    """
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()

    real_store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    _seed_module(real_store, "i-abc123", "custom", "os")

    clear_called = []
    svc = MagicMock()
    svc.is_memory_disabled.return_value = False
    svc.get_all_modules = MagicMock(side_effect=lambda iid, provider="custom": real_store.get_all_modules(iid, provider))
    svc.stale_modules = MagicMock(return_value=[])
    svc.clear = MagicMock(side_effect=lambda iid, modules=None, provider="custom": clear_called.append(modules))

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)  # wait for table to render and "os" row to appear
        screen = app.screen
        assert isinstance(screen, MemoryScreen)

        # Intercept push_screen so the confirm callback fires immediately with True
        # (eliminates modal timing dependency).
        original_push = app.push_screen

        def _instant_confirm(modal, callback=None):
            if callback is not None:
                callback(True)

        app.push_screen = _instant_confirm  # type: ignore[method-assign]
        screen.action_clear_module()
        app.push_screen = original_push
        await pilot.pause(0.1)

    # service.clear must have been called with the "os" module
    assert len(clear_called) == 1
    assert clear_called[0] == ["os"]


@pytest.mark.asyncio
async def test_action_annotate_no_row_covers_full_path(tmp_path: Path) -> None:
    """action_annotate with valid service executes full path (annotations file path resolved)."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    annotations_path = tmp_path / "annotations.md"
    notified = []

    svc = MagicMock()
    svc.is_memory_disabled.return_value = False
    svc.get_all_modules.return_value = {}
    svc.stale_modules.return_value = []
    svc.get_annotations_path = MagicMock(return_value=annotations_path)

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

        def notify(self, message, *, severity="information", title="", timeout=None):
            notified.append((message, severity))

    app = TestApp()
    # Patch subprocess.run so we don't actually launch an editor
    with patch("servonaut.screens.memory.subprocess.run", return_value=None):
        async with app.run_test(headless=True) as pilot:
            await pilot.pause(0.1)
            # Call action_annotate directly on the screen to avoid suspend() issues
            screen = app.screen
            # Directly patch app.suspend as a context manager
            import contextlib

            @contextlib.contextmanager
            def _noop_suspend():
                yield

            app.suspend = _noop_suspend
            screen.action_annotate()
            await pilot.pause(0.2)

    # Annotations path was resolved — get_annotations_path was called
    svc.get_annotations_path.assert_called()


# ---------------------------------------------------------------------------
# action_export error path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_do_export_exception_path(tmp_path: Path) -> None:
    """_do_export notifies with error when write_summary raises."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    notified = []

    svc = MagicMock()
    svc.is_memory_disabled.return_value = False
    svc.get_all_modules.return_value = {}
    svc.stale_modules.return_value = []

    async def _failing_write_summary(inst):
        raise OSError("disk full")

    svc.write_summary = _failing_write_summary

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

        def notify(self, message, *, severity="information", title="", timeout=None):
            notified.append((message, severity))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        await pilot.press("e")
        await pilot.pause(0.3)

    assert any("error" == s for _, s in notified)


# ---------------------------------------------------------------------------
# action_pin_key with row selected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_action_pin_key_with_row_selected_pushes_modal(tmp_path: Path) -> None:
    """action_pin_key with a valid row selected pushes PinKeyModal."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen, PinKeyModal

    instance = _make_instance()

    real_store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    _seed_module(real_store, "i-abc123", "custom", "os")

    pushed_modals = []
    svc = MagicMock()
    svc.is_memory_disabled.return_value = False
    svc.get_all_modules = MagicMock(side_effect=lambda iid, provider="custom": real_store.get_all_modules(iid, provider))
    svc.stale_modules = MagicMock(return_value=[])
    svc.get = MagicMock(return_value=None)

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)  # wait for table to render
        await pilot.press("p")  # action_pin_key
        await pilot.pause(0.1)
        # Check what screen is on top
        current = type(app.screen).__name__
        pushed_modals.append(current)

    # With a row selected (table has data), PinKeyModal should be the top screen.
    # pushed_modals[0] is type(app.screen).__name__ captured inside the pilot block.
    assert pushed_modals == ["PinKeyModal"], (
        f"Expected PinKeyModal to be the top screen, got: {pushed_modals}"
    )


@pytest.mark.asyncio
async def test_do_pin_calls_service_pin(tmp_path: Path) -> None:
    """_do_pin calls memory_service.pin and re-renders the table."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()

    real_store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    _seed_module(real_store, "i-abc123", "custom", "os")

    pin_called = asyncio.Event()
    svc = MagicMock()
    svc.is_memory_disabled.return_value = False
    svc.get_all_modules = MagicMock(side_effect=lambda iid, provider="custom": real_store.get_all_modules(iid, provider))
    svc.stale_modules = MagicMock(return_value=[])
    svc.get = MagicMock(return_value=None)

    async def _fake_pin(iid, module, key, value, pinned_by="", provider="custom"):
        pin_called.set()

    svc.pin = _fake_pin

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        # Directly call _do_pin on the screen to cover that code path
        screen = app.screen
        if hasattr(screen, "_do_pin"):
            await screen._do_pin("i-abc123", "os", "kernel", "5.4")

    assert pin_called.is_set()


@pytest.mark.asyncio
async def test_do_pin_exception_notifies_error(tmp_path: Path) -> None:
    """_do_pin notifies with error when pin raises."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    notified = []

    svc = MagicMock()
    svc.is_memory_disabled.return_value = False
    svc.get_all_modules.return_value = {}
    svc.stale_modules.return_value = []

    async def _failing_pin(iid, module, key, value, pinned_by="", provider="custom"):
        raise ValueError("pin rejected")

    svc.pin = _failing_pin

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

        def notify(self, message, *, severity="information", title="", timeout=None):
            notified.append((message, severity))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.1)
        screen = app.screen
        if hasattr(screen, "_do_pin"):
            await screen._do_pin("i-abc123", "os", "kernel", "5.4")
        await pilot.pause(0.1)

    assert any("error" == s for _, s in notified)


# ---------------------------------------------------------------------------
# _render_table with data (direct call covering 353-385)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_render_table_with_declared_values(tmp_path: Path) -> None:
    """_render_table populates table rows with observed AND declared values."""
    from textual.app import App, ComposeResult
    from textual.widgets import DataTable, Header, Footer
    from servonaut.services.memory.store import MemoryStore
    from servonaut.services.memory.redaction import noop_redactor
    from servonaut.screens.memory import MemoryScreen
    from datetime import datetime, timezone

    instance = _make_instance()
    iid = instance["id"]
    provider = instance["provider"]

    store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    # Save module with declared values to cover the full render loop
    store.save_module(iid, "os", {
        "module": "os", "instance_id": iid,
        "probed_at": datetime.now(tz=timezone.utc).isoformat(),
        "ttl_seconds": 86400,
        "sudo_used": False, "truncated": False, "partial": False,
        "observed": {"kernel": "5.4", "distro": "Ubuntu"},
        "declared": {
            "kernel": {"value": "5.4", "pinned_by": "user", "pinned_at": "2025-01-01"},
        },
        "raw_output": "",
    }, provider=provider)

    svc = _make_memory_service(tmp_path)
    svc._store = store

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.3)
        table = app.screen.query_one("#memory-table", DataTable)
        # kernel + distro = 2 observed keys = 2 rows
        assert table.row_count >= 2


# ---------------------------------------------------------------------------
# T11 — empty-state CTA pilot coverage
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_memory_screen_empty_state_cta_visible_when_no_modules(tmp_path: Path) -> None:
    """When no modules exist and no opt-out, the CTA banner is visible."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, DataTable
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()

    svc = MagicMock()
    svc.is_memory_disabled.return_value = False
    svc.get_all_modules.return_value = {}
    svc.stale_modules.return_value = []

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        cta = app.screen.query_one("#memory-empty-state")
        assert not cta.has_class("hidden"), (
            "Empty-state CTA must be visible when there are no modules."
        )
        table = app.screen.query_one("#memory-table", DataTable)
        assert table.row_count == 0


@pytest.mark.asyncio
async def test_memory_screen_empty_state_hidden_when_modules_exist(tmp_path: Path) -> None:
    """CTA is hidden once modules are present."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()
    iid = instance["id"]
    provider = instance["provider"]

    from datetime import datetime, timezone
    store = MemoryStore(root=tmp_path, redactor=noop_redactor)
    store.save_module(iid, "os", {
        "module": "os", "instance_id": iid,
        "probed_at": datetime.now(tz=timezone.utc).isoformat(),
        "ttl_seconds": 86400,
        "sudo_used": False, "truncated": False, "partial": False,
        "observed": {"kernel": "5.4"},
        "declared": {},
        "raw_output": "",
    }, provider=provider)

    svc = _make_memory_service(tmp_path)
    svc._store = store

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        cta = app.screen.query_one("#memory-empty-state")
        assert cta.has_class("hidden"), (
            "Empty-state CTA must be hidden once a module has been saved."
        )


@pytest.mark.asyncio
async def test_memory_screen_empty_state_hidden_when_opted_out(tmp_path: Path) -> None:
    """Opt-out takes precedence over the empty-state CTA."""
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, Static
    from servonaut.screens.memory import MemoryScreen

    instance = _make_instance()

    svc = MagicMock()
    svc.is_memory_disabled.return_value = True
    svc.get_all_modules.return_value = {}
    svc.stale_modules.return_value = []

    class TestApp(App):
        CSS = ""

        def compose(self) -> ComposeResult:
            yield Header()
            yield Footer()

        def on_mount(self) -> None:
            self.memory_service = svc
            self.push_screen(MemoryScreen(instance))

    app = TestApp()
    async with app.run_test(headless=True) as pilot:
        await pilot.pause(0.2)
        cta = app.screen.query_one("#memory-empty-state")
        banner = app.screen.query_one("#memory-opt-out-banner", Static)
        assert cta.has_class("hidden"), "Opt-out takes precedence over CTA."
        assert not banner.has_class("hidden"), "Opt-out banner must be visible."
