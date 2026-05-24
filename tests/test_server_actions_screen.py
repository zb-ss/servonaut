"""Tests for ServerActionsScreen — Verify SSH feature."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from servonaut.screens.server_actions import ConfirmSshVerifyModal, ServerActionsScreen


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
        assert len(fake_app._pushed_screens) == 1
        assert isinstance(fake_app._pushed_screens[0], ConfirmSshVerifyModal)
        assert not fake_app._pushed_screens[0]._has_ref

    def test_no_ref_confirmed_shows_stub_notify(self):
        bw = MagicMock()
        bw.get_personal_instance_ref = AsyncMock(return_value=None)
        fake_app = _FakeApp(bw_service=bw)
        screen = _make_screen(app=fake_app)
        _run(screen._verify_ssh_flow())
        msgs = [n["message"] for n in fake_app._notifications]
        assert any("not yet implemented" in m for m in msgs)

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
