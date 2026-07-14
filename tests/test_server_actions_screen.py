"""Tests for ServerActionsScreen — Verify SSH feature."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from servonaut.screens.server_actions import ConfirmSshVerifyModal, ServerActionsScreen
from servonaut.services.ssh_ref_resolver import ResolvedSshRef


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_instance(
    instance_id: str = "i-abc123",
    provider: str = "aws",
    public_ip: str = "1.2.3.4",
    name: str = "test-server",
) -> dict:
    return {
        "id": instance_id,
        "provider": provider,
        "public_ip": public_ip,
        "name": name,
        "state": "running",
        "type": "t3.micro",
        "region": "us-east-1",
        "key_name": "my-key",
    }


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# ConfirmSshVerifyModal — unit tests (no Textual pilot needed)
# ---------------------------------------------------------------------------

class TestConfirmSshVerifyModal:
    def test_instantiates_with_ref(self):
        modal = ConfirmSshVerifyModal(host="1.2.3.4", has_ref=True)
        assert modal._host == "1.2.3.4"
        assert modal._has_ref is True

    def test_instantiates_without_ref(self):
        modal = ConfirmSshVerifyModal(host="10.0.0.1", has_ref=False)
        assert modal._has_ref is False

    def test_inherits_from_modal_screen(self):
        from textual.screen import ModalScreen
        assert issubclass(ConfirmSshVerifyModal, ModalScreen)

    def test_generic_param_is_bool(self):
        """ConfirmSshVerifyModal[bool] — check via __orig_bases__ or mro."""
        import inspect
        # The class must be declared as ModalScreen[bool]
        bases = getattr(ConfirmSshVerifyModal, "__orig_bases__", [])
        base_strs = [str(b) for b in bases]
        assert any("bool" in s for s in base_strs), (
            f"Expected ModalScreen[bool] in bases; got {base_strs}"
        )

    def test_escape_binding_exists(self):
        bindings = ConfirmSshVerifyModal.BINDINGS
        keys = [b.key for b in bindings]
        assert "escape" in keys


# ---------------------------------------------------------------------------
# ServerActionsScreen — compose includes Verify SSH button
# ---------------------------------------------------------------------------

class TestServerActionsScreenCompose:
    """Lightweight checks on ServerActionsScreen without a running pilot."""

    def test_verify_ssh_binding_registered(self):
        """'v' binding for action_verify_ssh must be in BINDINGS."""
        keys = [b.key for b in ServerActionsScreen.BINDINGS]
        assert "v" in keys, f"Expected 'v' in BINDINGS; got {keys}"

    def test_action_verify_ssh_method_exists(self):
        assert hasattr(ServerActionsScreen, "action_verify_ssh")
        assert callable(ServerActionsScreen.action_verify_ssh)

    def test_run_ssh_probe_method_exists(self):
        assert hasattr(ServerActionsScreen, "_run_ssh_probe")

    def test_verify_ssh_flow_method_exists(self):
        assert hasattr(ServerActionsScreen, "_verify_ssh_flow")

    def test_live_binding_registered(self):
        keys = [b.key for b in ServerActionsScreen.BINDINGS]
        assert "l" in keys, f"Expected 'l' in BINDINGS; got {keys}"


# ---------------------------------------------------------------------------
# Detail pane: live stats formatting + gating
# ---------------------------------------------------------------------------

class TestLiveStatsPanel:
    def test_format_live_stats_renders_fields(self):
        from servonaut.utils.live_stats import LiveStats
        screen = _make_screen()
        s = LiveStats(
            cpu_pct=12.0, mem_used_mb=3104, mem_total_mb=7976,
            load_1m=0.4, load_5m=0.5, load_15m=0.6, uptime="up 4 days",
            disk_used_gb=48, disk_total_gb=80, disk_pct=61,
        )
        out = screen._format_live_stats(s)
        assert "12%" in out
        assert "3104/7976 MB" in out
        assert "0.40 0.50 0.60" in out
        assert "61%" in out
        assert "up 4 days" in out

    def test_format_live_stats_handles_none(self):
        from servonaut.utils.live_stats import LiveStats
        screen = _make_screen()
        out = screen._format_live_stats(LiveStats())
        # Unparsable fields degrade to '?', never raise.
        assert out.count("?") >= 4

    def test_bar_thresholds(self):
        screen = _make_screen()
        assert "green" in screen._bar(10.0)
        assert "yellow" in screen._bar(80.0)
        assert "red" in screen._bar(95.0)
        assert "dim" in screen._bar(None)

    def test_provider_for_memory_scans_all(self):
        screen = _make_screen()
        assert screen._provider_for_memory() == ""

    def test_toggle_live_without_memory_service_warns(self):
        fake_app = _FakeApp()  # has no memory_service attribute
        screen = _make_screen(app=fake_app)
        screen._live_on = False
        screen.action_toggle_live()
        sevs = [n["severity"] for n in fake_app._notifications]
        assert "warning" in sevs


# ---------------------------------------------------------------------------
# Focus-help line: clickable proxy for the focused action button
# ---------------------------------------------------------------------------

class TestActionHelpClick:
    def _click_event(self, widget_id):
        ev = MagicMock()
        ev.widget = MagicMock()
        ev.widget.id = widget_id
        return ev

    def test_click_on_help_line_presses_focused_button(self):
        screen = _make_screen()
        screen._focused_action_id = "btn_browse"
        pressed = []
        btn = MagicMock()
        btn.press = lambda: pressed.append("pressed")
        screen.query_one = lambda sel, *a: btn
        screen.on_click(self._click_event("action_help"))
        assert pressed == ["pressed"]

    def test_click_elsewhere_is_ignored(self):
        screen = _make_screen()
        screen._focused_action_id = "btn_browse"
        pressed = []
        btn = MagicMock()
        btn.press = lambda: pressed.append("pressed")
        screen.query_one = lambda sel, *a: btn
        # A click on some other widget must NOT press the focused button.
        screen.on_click(self._click_event("server_info"))
        assert pressed == []

    def test_click_with_no_focused_action_is_noop(self):
        screen = _make_screen()
        screen._focused_action_id = None
        pressed = []
        btn = MagicMock()
        btn.press = lambda: pressed.append("pressed")
        screen.query_one = lambda sel, *a: btn
        screen.on_click(self._click_event("action_help"))
        assert pressed == []


# ---------------------------------------------------------------------------
# Inline Browse Files (mounted in the detail pane, no screen push)
# ---------------------------------------------------------------------------

class TestInlineBrowse:
    def test_browse_opens_inline_not_a_screen(self):
        screen = _make_screen()
        screen._validate_instance_connection = lambda: True
        called = []
        screen._open_inline_browse = lambda: called.append("inline")
        screen.action_action_1()
        assert called == ["inline"]

    def test_browse_validation_blocks_inline(self):
        screen = _make_screen()
        screen._validate_instance_connection = lambda: False
        called = []
        screen._open_inline_browse = lambda: called.append("inline")
        screen.action_action_1()
        assert called == []  # invalid connection → no inline view

    def test_back_with_inline_open_closes_it_without_popping(self):
        fake_app = _FakeApp()
        popped = []
        fake_app.pop_screen = lambda: popped.append(1)
        screen = _make_screen(app=fake_app)
        screen._inline_view = "browse"
        cleared = []
        screen._clear_inline = lambda: (cleared.append(1), setattr(screen, "_inline_view", None))
        screen._safe_focus = lambda sel: None
        screen.action_back()
        assert cleared == [1]
        assert popped == []  # first Esc closes inline, does not leave the screen

    def test_back_without_inline_pops_screen(self):
        fake_app = _FakeApp()
        popped = []
        fake_app.pop_screen = lambda: popped.append(1)
        screen = _make_screen(app=fake_app)
        screen._inline_view = None
        screen.action_back()
        assert popped == [1]


# ---------------------------------------------------------------------------
# Detail pane: cached memory snapshot rendering
# ---------------------------------------------------------------------------

class TestMemoryPanelRender:
    def test_render_calls_get_all_modules_with_scan_all(self):
        fake_app = _FakeApp()
        mem = MagicMock()
        mem.is_memory_disabled.return_value = False
        mem.get_all_modules.return_value = {}
        fake_app.memory_service = mem
        screen = _make_screen(app=fake_app)

        updated = {}
        panel = MagicMock()
        panel.update = lambda text: updated.update({"text": text})
        screen.query_one = lambda sel, *a: panel

        screen._render_memory_panel()
        # provider "" → store scans every provider directory
        mem.get_all_modules.assert_called_once()
        assert mem.get_all_modules.call_args.args[1] == ""
        assert "No memory cached" in updated["text"]

    def test_render_disabled_shows_disabled_message(self):
        fake_app = _FakeApp()
        mem = MagicMock()
        mem.is_memory_disabled.return_value = True
        fake_app.memory_service = mem
        screen = _make_screen(app=fake_app)

        updated = {}
        panel = MagicMock()
        panel.update = lambda text: updated.update({"text": text})
        screen.query_one = lambda sel, *a: panel

        screen._render_memory_panel()
        assert "disabled" in updated["text"].lower()
        mem.get_all_modules.assert_not_called()


# ---------------------------------------------------------------------------
# _verify_ssh_flow — worker logic
# ---------------------------------------------------------------------------

class _FakeApp:
    """Minimal app double for testing ServerActionsScreen flow without Textual."""

    def __init__(self, bw_service=None, instances=None):
        self.bw_ssh_config_service = bw_service
        self.instances = instances or []
        self._notifications = []
        self._pushed_screens = []
        self._push_screen_wait_result = True
        self.demo_mode = False
        self.redaction_service = None

        # Minimal config manager double
        cfg = MagicMock()
        cfg.default_username = "root"
        cm = MagicMock()
        cm.get.return_value = cfg
        self.config_manager = cm

    def notify(self, message, *, severity="information", markup=True, timeout=None):
        self._notifications.append({"message": message, "severity": severity})

    async def push_screen_wait(self, modal):
        self._pushed_screens.append(modal)
        return self._push_screen_wait_result

    @property
    def screen_stack(self):
        return []


def _make_screen(instance=None, app=None) -> ServerActionsScreen:
    """Build ServerActionsScreen without mounting it in a Textual app."""
    inst = instance or _make_instance()
    screen = ServerActionsScreen.__new__(ServerActionsScreen)
    screen._instance = inst
    if app is not None:
        screen._app = app  # bypass the Textual descriptor
    # Patch self.app to return the fake
    if app is not None:
        screen.__class__ = type(
            "PatchedServerActionsScreen",
            (ServerActionsScreen,),
            {"app": property(lambda self: app)},
        )
    return screen


class TestVerifySshFlowNoService:
    def test_no_bw_service_shows_warning(self):
        fake_app = _FakeApp(bw_service=None)
        screen = _make_screen(app=fake_app)
        _run(screen._verify_ssh_flow())
        sevs = [n["severity"] for n in fake_app._notifications]
        assert "warning" in sevs

    def test_no_bw_service_does_not_push_modal(self):
        fake_app = _FakeApp(bw_service=None)
        screen = _make_screen(app=fake_app)
        _run(screen._verify_ssh_flow())
        assert fake_app._pushed_screens == []


class TestVerifySshFlowNoRef:
    def test_no_ref_modal_pushed(self):
        bw = MagicMock()
        bw.get_personal_instance_ref = AsyncMock(return_value=None)
        fake_app = _FakeApp(bw_service=bw)
        screen = _make_screen(app=fake_app)
        _run(screen._verify_ssh_flow())
        # First modal: ConfirmSshVerifyModal; second: SshRefEditorModal (new)
        assert len(fake_app._pushed_screens) >= 1
        assert isinstance(fake_app._pushed_screens[0], ConfirmSshVerifyModal)
        assert not fake_app._pushed_screens[0]._has_ref

    def test_no_ref_confirmed_pushes_editor_modal(self):
        """Confirm on no-ref now opens SshRefEditorModal instead of stub notify."""
        from servonaut.screens.ssh_ref_editor import SshRefEditorModal
        bw = MagicMock()
        bw.get_personal_instance_ref = AsyncMock(return_value=None)
        fake_app = _FakeApp(bw_service=bw)
        screen = _make_screen(app=fake_app)
        _run(screen._verify_ssh_flow())
        # ConfirmSshVerifyModal + SshRefEditorModal
        assert len(fake_app._pushed_screens) == 2
        assert isinstance(fake_app._pushed_screens[1], SshRefEditorModal)
        # No stub "not yet implemented" notify should appear
        msgs = [n["message"] for n in fake_app._notifications]
        assert not any("not yet implemented" in m for m in msgs)

    def test_cancel_on_no_ref_no_stub_notify(self):
        """If user cancels on the no-ref modal, no stub notify is shown."""
        bw = MagicMock()
        bw.get_personal_instance_ref = AsyncMock(return_value=None)
        fake_app = _FakeApp(bw_service=bw)
        fake_app._push_screen_wait_result = False
        screen = _make_screen(app=fake_app)
        _run(screen._verify_ssh_flow())
        msgs = [n["message"] for n in fake_app._notifications]
        assert not any("not yet implemented" in m for m in msgs)

    def test_decrypt_failed_shows_distinct_error_not_editor(self):
        """A 500 decrypt_failed must surface a distinct error, not reopen the editor."""
        from servonaut.services.api_client import APIError
        exc = APIError(
            code="decrypt_failed",
            message="Could not decrypt stored ref",
            status=500,
        )
        bw = MagicMock()
        bw.get_personal_instance_ref = AsyncMock(side_effect=exc)
        fake_app = _FakeApp(bw_service=bw)
        screen = _make_screen(app=fake_app)
        # Should NOT raise — the flow returns early with a distinct notify.
        _run(screen._verify_ssh_flow())
        # (a) a distinct error notify mentioning decrypt is shown
        sevs = [n["severity"] for n in fake_app._notifications]
        assert "error" in sevs
        msgs = [n["message"] for n in fake_app._notifications]
        assert any("decrypt" in m.lower() for m in msgs)
        # (b) no modal (neither confirm nor editor) is pushed
        assert fake_app._pushed_screens == []


class TestVerifySshFlowWithRef:
    def _make_bw(self, report_result=None, report_exc=None):
        bw = MagicMock()
        ref_row = {
            "ssh_credential_ref": {"item_id": "bw-item-uuid"},
        }
        bw.get_personal_instance_ref = AsyncMock(return_value=ref_row)
        if report_exc:
            bw.report_personal_instance_verify = AsyncMock(side_effect=report_exc)
        else:
            bw.report_personal_instance_verify = AsyncMock(
                return_value=report_result or {}
            )
        return bw

    def test_has_ref_modal_is_has_ref_true(self):
        bw = self._make_bw()
        fake_app = _FakeApp(bw_service=bw)
        # Patch _run_ssh_probe so it returns 'verified' quickly
        async def _fast_probe(item_id, host):
            return "verified"
        screen = _make_screen(app=fake_app)
        screen._run_ssh_probe = _fast_probe
        _run(screen._verify_ssh_flow())
        assert fake_app._pushed_screens[0]._has_ref is True

    def test_verified_status_posts_verified(self):
        bw = self._make_bw()
        fake_app = _FakeApp(bw_service=bw)
        async def _fast_probe(item_id, host):
            return "verified"
        screen = _make_screen(app=fake_app)
        screen._run_ssh_probe = _fast_probe
        _run(screen._verify_ssh_flow())
        bw.report_personal_instance_verify.assert_awaited_once()
        call_kwargs = bw.report_personal_instance_verify.call_args
        assert call_kwargs.kwargs["status"] == "verified"

    def test_not_found_status_posts_not_found(self):
        bw = self._make_bw()
        fake_app = _FakeApp(bw_service=bw)
        async def _fast_probe(item_id, host):
            return "not_found"
        screen = _make_screen(app=fake_app)
        screen._run_ssh_probe = _fast_probe
        _run(screen._verify_ssh_flow())
        call_kwargs = bw.report_personal_instance_verify.call_args
        assert call_kwargs.kwargs["status"] == "not_found"

    def test_auth_failed_status_posts_auth_failed(self):
        bw = self._make_bw()
        fake_app = _FakeApp(bw_service=bw)
        async def _fast_probe(item_id, host):
            return "auth_failed"
        screen = _make_screen(app=fake_app)
        screen._run_ssh_probe = _fast_probe
        _run(screen._verify_ssh_flow())
        call_kwargs = bw.report_personal_instance_verify.call_args
        assert call_kwargs.kwargs["status"] == "auth_failed"

    def test_tier_gate_402_shows_friendly_notify(self):
        from servonaut.services.api_client import APIError
        exc = APIError(code="payment_required", message="Upgrade required", status=402)
        bw = self._make_bw(report_exc=exc)
        fake_app = _FakeApp(bw_service=bw)
        async def _fast_probe(item_id, host):
            return "verified"
        screen = _make_screen(app=fake_app)
        screen._run_ssh_probe = _fast_probe
        # Should NOT raise — 402 is handled gracefully
        _run(screen._verify_ssh_flow())
        sevs = [n["severity"] for n in fake_app._notifications]
        assert "warning" in sevs
        msgs = [n["message"] for n in fake_app._notifications]
        assert any("paid" in m.lower() or "plan" in m.lower() for m in msgs)

    def test_instance_dict_updated_after_probe(self):
        bw = self._make_bw()
        inst = _make_instance()
        fake_app = _FakeApp(bw_service=bw, instances=[inst])
        async def _fast_probe(item_id, host):
            return "verified"
        screen = _make_screen(instance=inst, app=fake_app)
        screen._run_ssh_probe = _fast_probe
        _run(screen._verify_ssh_flow())
        assert inst["ssh_verify_status"] == "verified"
        assert "ssh_verified_at" in inst

    def test_not_found_clears_verified_at(self):
        bw = self._make_bw()
        inst = _make_instance()
        inst["ssh_verified_at"] = "2026-05-20T00:00:00+00:00"
        fake_app = _FakeApp(bw_service=bw, instances=[inst])
        async def _fast_probe(item_id, host):
            return "not_found"
        screen = _make_screen(instance=inst, app=fake_app)
        screen._run_ssh_probe = _fast_probe
        _run(screen._verify_ssh_flow())
        assert inst.get("ssh_verified_at") is None

    def test_user_cancel_aborts_flow(self):
        bw = self._make_bw()
        fake_app = _FakeApp(bw_service=bw)
        fake_app._push_screen_wait_result = False  # user cancels
        async def _fast_probe(item_id, host):
            return "verified"
        screen = _make_screen(app=fake_app)
        screen._run_ssh_probe = _fast_probe
        _run(screen._verify_ssh_flow())
        bw.report_personal_instance_verify.assert_not_awaited()


# ---------------------------------------------------------------------------
# Helpers for SshRefResolver chain tests
# ---------------------------------------------------------------------------

def _make_connect_app(
    *,
    resolved: object = None,
    resolver_raises: Exception = None,
    bw_key_body: str = "FAKE_KEY",
    bw_resolver_raises: Exception = None,
    launch_result: bool = True,
    team_service=None,
    bw_service=None,
) -> "_FakeConnectApp":
    """Build a fake app pre-wired for _ssh_connect_flow tests."""

    class _FakeConnectApp:
        def __init__(self):
            self._notifications = []
            self.demo_mode = False
            self.redaction_service = None
            self.instances = []

            cfg = MagicMock()
            cfg.default_username = "ubuntu"
            cm = MagicMock()
            cm.get.return_value = cfg
            self.config_manager = cm

            self.ssh_service = MagicMock()
            self.ssh_service.build_ssh_command.return_value = ["ssh", "host"]
            self.ssh_service.get_key_path.return_value = "/home/user/.ssh/id_rsa"
            self.ssh_service.discover_key.return_value = "/home/user/.ssh/id_rsa"

            self.connection_service = MagicMock()
            self.connection_service.resolve_profile.return_value = None
            self.connection_service.get_target_host.return_value = "1.2.3.4"
            self.connection_service.get_proxy_args.return_value = []
            self.connection_service.get_extra_options.return_value = {}

            self.terminal_service = MagicMock()
            self.terminal_service.launch_ssh_in_terminal.return_value = launch_result

            self.bw_ssh_config_service = bw_service
            self.team_service = team_service

        def notify(self, message, *, severity="information", markup=True, timeout=None):
            self._notifications.append({"message": message, "severity": severity})

        @property
        def screen_stack(self):
            return []

    return _FakeConnectApp()


def _make_connect_screen(
    instance: dict = None,
    app=None,
) -> ServerActionsScreen:
    """Build a ServerActionsScreen for _ssh_connect_flow tests."""
    inst = instance or _make_instance()
    screen = ServerActionsScreen.__new__(ServerActionsScreen)
    screen._instance = inst
    if app is not None:
        screen.__class__ = type(
            "ConnectScreen",
            (ServerActionsScreen,),
            {"app": property(lambda self: app)},
        )
    return screen


# ---------------------------------------------------------------------------
# TestSshConnectResolverChain
# ---------------------------------------------------------------------------

_PERSONAL_RESOLVED = ResolvedSshRef(
    source="personal",
    item_id="bw-uuid-personal",
    vault_url=None,
    collection_id=None,
    local_key_path=None,
    team_slug=None,
    server_id=None,
)

_TEAM_RESOLVED = ResolvedSshRef(
    source="team",
    item_id="bw-uuid-team",
    vault_url=None,
    collection_id=None,
    local_key_path=None,
    team_slug="acme",
    server_id="srv-1",
)

_LOCAL_RESOLVED = ResolvedSshRef(
    source="local",
    item_id=None,
    vault_url=None,
    collection_id=None,
    local_key_path="/home/user/.ssh/id_rsa",
    team_slug=None,
    server_id=None,
)


class TestSshConnectResolverChain:
    """SSH Connect walks SshRefResolver before falling back to local.

    Strategy: patch at source-module paths because all imports in
    _ssh_connect_flow are local (inside the function body).  The source
    module is the correct patch target for locally-imported names.
    """

    # Source-module patch targets (all imports in _ssh_connect_flow are local).
    _P_RESOLVE = "servonaut.services.ssh_ref_resolver.SshRefResolver.resolve"
    _P_BW_KEY = "servonaut.services.bw_resolver.BwResolver.resolve_ssh_key"
    _P_PERSIST = "servonaut.utils.ephemeral_key.persistent_bw_ssh_key"

    def _run_flow(self, screen):
        return asyncio.run(screen._ssh_connect_flow())

    def test_personal_match_uses_bw_resolver(self):
        """When resolver returns personal source, BwResolver is called and terminal launched."""
        app = _make_connect_app()

        with (
            patch(self._P_RESOLVE, new_callable=AsyncMock, return_value=_PERSONAL_RESOLVED),
            patch(self._P_BW_KEY, return_value="FAKE_KEY"),
            patch(self._P_PERSIST, return_value="/tmp/bw-fake.key") as mock_persistent,
        ):
            screen = _make_connect_screen(app=app)
            self._run_flow(screen)

        mock_persistent.assert_called_once_with("FAKE_KEY")
        app.terminal_service.launch_ssh_in_terminal.assert_called_once()

    def test_team_match_uses_bw_resolver(self):
        """When resolver returns team source, BwResolver is called and terminal launched."""
        app = _make_connect_app()

        with (
            patch(self._P_RESOLVE, new_callable=AsyncMock, return_value=_TEAM_RESOLVED),
            patch(self._P_BW_KEY, return_value="FAKE_TEAM_KEY"),
            patch(self._P_PERSIST, return_value="/tmp/bw-team.key") as mock_persistent,
        ):
            screen = _make_connect_screen(app=app)
            self._run_flow(screen)

        mock_persistent.assert_called_once_with("FAKE_TEAM_KEY")
        app.terminal_service.launch_ssh_in_terminal.assert_called_once()

    def test_local_match_uses_existing_ssh_service_path(self):
        """When resolver returns local source, BW is not involved and terminal launched."""
        app = _make_connect_app()

        with (
            patch(self._P_RESOLVE, new_callable=AsyncMock, return_value=_LOCAL_RESOLVED),
            patch(self._P_PERSIST) as mock_persistent,
            patch(self._P_BW_KEY) as mock_bw,
        ):
            screen = _make_connect_screen(app=app)
            self._run_flow(screen)

        mock_persistent.assert_not_called()
        mock_bw.assert_not_called()
        app.terminal_service.launch_ssh_in_terminal.assert_called_once()

    def test_no_match_notifies_user(self):
        """When resolver returns None, user gets a warning and terminal is not launched."""
        app = _make_connect_app()

        with patch(self._P_RESOLVE, new_callable=AsyncMock, return_value=None):
            screen = _make_connect_screen(app=app)
            self._run_flow(screen)

        app.terminal_service.launch_ssh_in_terminal.assert_not_called()
        sevs = [n["severity"] for n in app._notifications]
        assert "warning" in sevs

    def test_bw_cli_missing_surfaces_friendly_error(self):
        """BwCliMissingError from BwResolver -> notify error, no terminal launch."""
        from servonaut.services.bw_resolver import BwCliMissingError

        app = _make_connect_app()

        with (
            patch(self._P_RESOLVE, new_callable=AsyncMock, return_value=_PERSONAL_RESOLVED),
            patch(self._P_BW_KEY, side_effect=BwCliMissingError("bw not found")),
        ):
            screen = _make_connect_screen(app=app)
            self._run_flow(screen)

        app.terminal_service.launch_ssh_in_terminal.assert_not_called()
        sevs = [n["severity"] for n in app._notifications]
        assert "error" in sevs
        msgs = [n["message"] for n in app._notifications]
        assert any("Bitwarden CLI" in m for m in msgs)

    def test_bw_session_locked_surfaces_friendly_error(self):
        """BwSessionMissingError -> notify error mentioning 'bw unlock'."""
        from servonaut.services.bw_resolver import BwSessionMissingError

        app = _make_connect_app()

        with (
            patch(self._P_RESOLVE, new_callable=AsyncMock, return_value=_PERSONAL_RESOLVED),
            patch(self._P_BW_KEY, side_effect=BwSessionMissingError("vault locked")),
        ):
            screen = _make_connect_screen(app=app)
            self._run_flow(screen)

        app.terminal_service.launch_ssh_in_terminal.assert_not_called()
        msgs = [n["message"] for n in app._notifications]
        assert any("bw unlock" in m for m in msgs)

    def test_bw_item_not_found_surfaces_friendly_error(self):
        """BwItemNotFoundError -> notify error mentioning item UUID."""
        from servonaut.services.bw_resolver import BwItemNotFoundError

        app = _make_connect_app()

        with (
            patch(self._P_RESOLVE, new_callable=AsyncMock, return_value=_PERSONAL_RESOLVED),
            patch(self._P_BW_KEY, side_effect=BwItemNotFoundError("not found")),
        ):
            screen = _make_connect_screen(app=app)
            self._run_flow(screen)

        app.terminal_service.launch_ssh_in_terminal.assert_not_called()
        msgs = [n["message"] for n in app._notifications]
        assert any("item" in m.lower() for m in msgs)

    def test_resolver_called_only_once_per_action(self):
        """SshRefResolver.resolve is invoked exactly once per connect action."""
        app = _make_connect_app()

        with patch(self._P_RESOLVE, new_callable=AsyncMock, return_value=None) as mock_resolve:
            screen = _make_connect_screen(app=app)
            self._run_flow(screen)

        mock_resolve.assert_awaited_once()

    def test_tier_notification_includes_source_name(self):
        """Notification message names the tier that resolved the credential."""
        app = _make_connect_app()

        with patch(self._P_RESOLVE, new_callable=AsyncMock, return_value=_LOCAL_RESOLVED):
            screen = _make_connect_screen(app=app)
            self._run_flow(screen)

        msgs = [n["message"] for n in app._notifications]
        assert any("local" in m.lower() for m in msgs)

    def test_personal_notification_names_personal_tier(self):
        """Notification says 'personal' when BW personal ref was used."""
        app = _make_connect_app()

        with (
            patch(self._P_RESOLVE, new_callable=AsyncMock, return_value=_PERSONAL_RESOLVED),
            patch(self._P_BW_KEY, return_value="KEY"),
            patch(self._P_PERSIST, return_value="/tmp/bw-fake.key"),
        ):
            screen = _make_connect_screen(app=app)
            self._run_flow(screen)

        msgs = [n["message"] for n in app._notifications]
        assert any("personal" in m.lower() for m in msgs)


# ---------------------------------------------------------------------------
# SshRefEditorModal — unit tests
# ---------------------------------------------------------------------------

class _FakeModalApp:
    """Minimal app double for SshRefEditorModal tests."""

    def __init__(self, bw_service=None):
        self.bw_ssh_config_service = bw_service
        self._notifications = []

    def notify(self, message, *, severity="information", markup=True, timeout=None):
        self._notifications.append({"message": message, "severity": severity})

    def run_worker(self, *args, **kwargs):
        pass


def _make_modal(instance=None, existing_ref=None, app=None):
    """Build SshRefEditorModal without mounting."""
    from servonaut.screens.ssh_ref_editor import SshRefEditorModal
    inst = instance or _make_instance()
    modal = SshRefEditorModal.__new__(SshRefEditorModal)
    modal._instance = inst
    modal._existing_ref = existing_ref
    modal._edit_mode = existing_ref is not None
    modal._dismissed_with = None
    if app is not None:
        modal.__class__ = type(
            "PatchedSshRefEditorModal",
            (SshRefEditorModal,),
            {"app": property(lambda self: app)},
        )
    return modal


class TestSshRefEditorModal:
    """Unit tests for SshRefEditorModal — no Textual pilot required."""

    def test_inherits_from_modal_screen(self):
        from textual.screen import ModalScreen
        from servonaut.screens.ssh_ref_editor import SshRefEditorModal
        assert issubclass(SshRefEditorModal, ModalScreen)

    def test_generic_param_is_bool(self):
        from servonaut.screens.ssh_ref_editor import SshRefEditorModal
        bases = getattr(SshRefEditorModal, "__orig_bases__", [])
        base_strs = [str(b) for b in bases]
        assert any("bool" in s for s in base_strs), (
            f"Expected ModalScreen[bool] in bases; got {base_strs}"
        )

    def test_add_mode_no_existing_ref(self):
        from servonaut.screens.ssh_ref_editor import SshRefEditorModal
        inst = _make_instance()
        modal = SshRefEditorModal(inst, existing_ref=None)
        assert modal._edit_mode is False

    def test_edit_mode_with_existing_ref(self):
        from servonaut.screens.ssh_ref_editor import SshRefEditorModal
        inst = _make_instance()
        existing = {"ssh_credential_ref": {"item_id": "bw-uuid-123"}}
        modal = SshRefEditorModal(inst, existing_ref=existing)
        assert modal._edit_mode is True

    def test_escape_binding_exists(self):
        from servonaut.screens.ssh_ref_editor import SshRefEditorModal
        keys = [b.key for b in SshRefEditorModal.BINDINGS]
        assert "escape" in keys

    def test_save_empty_item_id_notifies_error_no_api_call(self):
        """Save with empty item_id → error notify, no API call."""
        bw = MagicMock()
        bw.put_personal_instance_ref = AsyncMock()
        fake_app = _FakeModalApp(bw_service=bw)
        modal = _make_modal(app=fake_app)

        # Patch Input query
        item_input = MagicMock()
        item_input.value = ""
        collection_input = MagicMock()
        collection_input.value = ""
        vault_input = MagicMock()
        vault_input.value = ""

        def _query_one(selector, widget_type=None):
            if "#item_id" in selector:
                return item_input
            if "#collection_id" in selector:
                return collection_input
            if "#vault_url" in selector:
                return vault_input
            raise ValueError(selector)

        modal.query_one = _query_one
        modal.dismiss = MagicMock()

        _run(modal._do_save())

        sevs = [n["severity"] for n in fake_app._notifications]
        assert "error" in sevs
        bw.put_personal_instance_ref.assert_not_awaited()
        modal.dismiss.assert_not_called()

    def test_save_success_calls_put_with_correct_body(self):
        """Save with valid item_id → PUT called with ssh_credential_ref body."""
        bw = MagicMock()
        bw.put_personal_instance_ref = AsyncMock(return_value={})
        fake_app = _FakeModalApp(bw_service=bw)
        inst = _make_instance(instance_id="i-abc123", provider="aws")
        modal = _make_modal(instance=inst, app=fake_app)

        item_input = MagicMock()
        item_input.value = "11111111-2222-3333-4444-555555555555"
        collection_input = MagicMock()
        collection_input.value = ""
        vault_input = MagicMock()
        vault_input.value = ""

        def _query_one(selector, widget_type=None):
            if "#item_id" in selector:
                return item_input
            if "#collection_id" in selector:
                return collection_input
            if "#vault_url" in selector:
                return vault_input
            raise ValueError(selector)

        modal.query_one = _query_one
        modal.dismiss = MagicMock()

        _run(modal._do_save())

        bw.put_personal_instance_ref.assert_awaited_once()
        call_kwargs = bw.put_personal_instance_ref.call_args
        assert call_kwargs.kwargs["ssh_credential_ref"]["item_id"] == "11111111-2222-3333-4444-555555555555"
        assert "ref" not in call_kwargs.kwargs  # never use 'ref' field directly
        modal.dismiss.assert_called_once_with(True)

    def test_save_optional_fields_included_when_set(self):
        """Collection ID and vault URL are included in ssh_credential_ref when set."""
        bw = MagicMock()
        bw.put_personal_instance_ref = AsyncMock(return_value={})
        fake_app = _FakeModalApp(bw_service=bw)
        modal = _make_modal(app=fake_app)

        item_input = MagicMock()
        item_input.value = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        collection_input = MagicMock()
        collection_input.value = "col-abc"
        vault_input = MagicMock()
        vault_input.value = "https://vault.example.com"

        def _query_one(selector, widget_type=None):
            if "#item_id" in selector:
                return item_input
            if "#collection_id" in selector:
                return collection_input
            if "#vault_url" in selector:
                return vault_input
            raise ValueError(selector)

        modal.query_one = _query_one
        modal.dismiss = MagicMock()

        _run(modal._do_save())

        call_kwargs = bw.put_personal_instance_ref.call_args
        ref = call_kwargs.kwargs["ssh_credential_ref"]
        assert ref["collection_id"] == "col-abc"
        assert ref["vault_url"] == "https://vault.example.com"

    def test_save_402_notifies_warning_modal_stays_open(self):
        """402 → warning notify, dismiss NOT called (modal stays open)."""
        from servonaut.services.api_client import APIError
        exc = APIError(code="payment_required", message="Upgrade required", status=402)
        bw = MagicMock()
        bw.put_personal_instance_ref = AsyncMock(side_effect=exc)
        fake_app = _FakeModalApp(bw_service=bw)
        modal = _make_modal(app=fake_app)

        item_input = MagicMock()
        item_input.value = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        collection_input = MagicMock()
        collection_input.value = ""
        vault_input = MagicMock()
        vault_input.value = ""

        def _query_one(selector, widget_type=None):
            if "#item_id" in selector:
                return item_input
            if "#collection_id" in selector:
                return collection_input
            if "#vault_url" in selector:
                return vault_input
            raise ValueError(selector)

        modal.query_one = _query_one
        modal.dismiss = MagicMock()

        _run(modal._do_save())

        sevs = [n["severity"] for n in fake_app._notifications]
        assert "warning" in sevs
        msgs = [n["message"] for n in fake_app._notifications]
        assert any("/pricing" in m for m in msgs)
        modal.dismiss.assert_not_called()

    def test_save_422_notifies_server_message_verbatim(self):
        """422 → server error message notified verbatim."""
        from servonaut.services.api_client import APIError
        server_msg = "item_id must be a valid UUID"
        exc = APIError(code="unprocessable", message=server_msg, status=422)
        bw = MagicMock()
        bw.put_personal_instance_ref = AsyncMock(side_effect=exc)
        fake_app = _FakeModalApp(bw_service=bw)
        modal = _make_modal(app=fake_app)

        item_input = MagicMock()
        item_input.value = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        collection_input = MagicMock()
        collection_input.value = ""
        vault_input = MagicMock()
        vault_input.value = ""

        def _query_one(selector, widget_type=None):
            if "#item_id" in selector:
                return item_input
            if "#collection_id" in selector:
                return collection_input
            if "#vault_url" in selector:
                return vault_input
            raise ValueError(selector)

        modal.query_one = _query_one
        modal.dismiss = MagicMock()

        _run(modal._do_save())

        msgs = [n["message"] for n in fake_app._notifications]
        assert server_msg in msgs

    def test_delete_calls_delete_api_and_dismisses_true(self):
        """Delete → calls delete_personal_instance_ref, dismisses True."""
        bw = MagicMock()
        bw.delete_personal_instance_ref = AsyncMock(return_value=None)
        fake_app = _FakeModalApp(bw_service=bw)
        inst = _make_instance(instance_id="i-abc123", provider="aws")
        existing = {"ssh_credential_ref": {"item_id": "bw-uuid"}}
        modal = _make_modal(instance=inst, existing_ref=existing, app=fake_app)
        modal.dismiss = MagicMock()

        _run(modal._do_delete())

        bw.delete_personal_instance_ref.assert_awaited_once_with(
            provider="aws",
            instance_id="i-abc123",
        )
        modal.dismiss.assert_called_once_with(True)

    def test_delete_api_error_notifies_and_stays_open(self):
        """Delete API error → notify error, dismiss not called."""
        from servonaut.services.api_client import APIError
        exc = APIError(code="not_found", message="Ref not found", status=404)
        bw = MagicMock()
        bw.delete_personal_instance_ref = AsyncMock(side_effect=exc)
        fake_app = _FakeModalApp(bw_service=bw)
        modal = _make_modal(app=fake_app)
        modal.dismiss = MagicMock()

        _run(modal._do_delete())

        sevs = [n["severity"] for n in fake_app._notifications]
        assert "error" in sevs
        modal.dismiss.assert_not_called()

    def test_cancel_action_dismisses_false(self):
        """action_cancel (ESC binding) dismisses with False."""
        from servonaut.screens.ssh_ref_editor import SshRefEditorModal
        modal = SshRefEditorModal(_make_instance())
        modal.dismiss = MagicMock()
        modal.action_cancel()
        modal.dismiss.assert_called_once_with(False)


# ---------------------------------------------------------------------------
# ServerActionsScreen.action_manage_ssh_ref — integration
# ---------------------------------------------------------------------------

class TestManageSshRefAction:
    def test_manage_ssh_ref_binding_registered(self):
        """'r' binding for action_manage_ssh_ref must be in BINDINGS."""
        keys = [b.key for b in ServerActionsScreen.BINDINGS]
        assert "r" in keys, f"Expected 'r' in BINDINGS; got {keys}"

    def test_action_manage_ssh_ref_method_exists(self):
        assert hasattr(ServerActionsScreen, "action_manage_ssh_ref")
        assert callable(ServerActionsScreen.action_manage_ssh_ref)

    def test_manage_ssh_ref_flow_method_exists(self):
        assert hasattr(ServerActionsScreen, "_manage_ssh_ref_flow")

    def test_no_bw_service_shows_warning(self):
        """When bw_ssh_config_service is absent, shows warning."""
        fake_app = _FakeApp(bw_service=None)
        screen = _make_screen(app=fake_app)
        _run(screen._manage_ssh_ref_flow())
        sevs = [n["severity"] for n in fake_app._notifications]
        assert "warning" in sevs

    def test_pushes_modal_in_add_mode_when_no_existing_ref(self):
        """When no ref exists, SshRefEditorModal pushed in add mode."""
        from servonaut.screens.ssh_ref_editor import SshRefEditorModal
        bw = MagicMock()
        bw.get_personal_instance_ref = AsyncMock(return_value=None)
        fake_app = _FakeApp(bw_service=bw)
        screen = _make_screen(app=fake_app)
        _run(screen._manage_ssh_ref_flow())
        assert len(fake_app._pushed_screens) == 1
        modal = fake_app._pushed_screens[0]
        assert isinstance(modal, SshRefEditorModal)
        assert modal._edit_mode is False

    def test_pushes_modal_in_edit_mode_when_ref_exists(self):
        """When ref exists, SshRefEditorModal pushed in edit mode."""
        from servonaut.screens.ssh_ref_editor import SshRefEditorModal
        ref_row = {"ssh_credential_ref": {"item_id": "bw-existing"}}
        bw = MagicMock()
        bw.get_personal_instance_ref = AsyncMock(return_value=ref_row)
        fake_app = _FakeApp(bw_service=bw)
        screen = _make_screen(app=fake_app)
        _run(screen._manage_ssh_ref_flow())
        assert len(fake_app._pushed_screens) == 1
        modal = fake_app._pushed_screens[0]
        assert isinstance(modal, SshRefEditorModal)
        assert modal._edit_mode is True


# ---------------------------------------------------------------------------
# ConfirmSshVerifyModal no-ref path now pushes SshRefEditorModal
# ---------------------------------------------------------------------------

class TestVerifySshNoRefPathPushesEditorModal:
    def test_no_ref_confirmed_pushes_ssh_ref_editor(self):
        """When has_ref=False and user confirms, SshRefEditorModal is pushed."""
        from servonaut.screens.ssh_ref_editor import SshRefEditorModal
        bw = MagicMock()
        bw.get_personal_instance_ref = AsyncMock(return_value=None)
        fake_app = _FakeApp(bw_service=bw)
        screen = _make_screen(app=fake_app)
        _run(screen._verify_ssh_flow())
        # Two pushes: ConfirmSshVerifyModal first, then SshRefEditorModal
        assert len(fake_app._pushed_screens) == 2
        assert isinstance(fake_app._pushed_screens[0], ConfirmSshVerifyModal)
        assert isinstance(fake_app._pushed_screens[1], SshRefEditorModal)

    def test_no_ref_confirmed_does_not_show_stub_notify(self):
        """The old 'not yet implemented' stub notify must NOT appear."""
        bw = MagicMock()
        bw.get_personal_instance_ref = AsyncMock(return_value=None)
        fake_app = _FakeApp(bw_service=bw)
        screen = _make_screen(app=fake_app)
        _run(screen._verify_ssh_flow())
        msgs = [n["message"] for n in fake_app._notifications]
        assert not any("not yet implemented" in m for m in msgs)
