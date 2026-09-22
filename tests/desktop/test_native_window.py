"""Contract tests for pywebview native window lifecycle and bridge integration."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("webview")

from servonaut.desktop.bridge import DesktopBootstrapBridge, DesktopBridgeError
from servonaut.desktop.launcher import (
    DesktopLaunchRequest,
    DesktopSessionOwner,
    run_desktop,
)
from servonaut.desktop.model import ReadyResponse, SecretToken
from servonaut.runtime import (
    DistributionKind,
    PackageManagementCapability,
    PackageManagementKind,
    RuntimeLayout,
)


def _test_runtime(tmp_path: Path) -> RuntimeLayout:
    return RuntimeLayout(
        kind=DistributionKind.SOURCE,
        product_version="3.0.0",
        build_revision=None,
        resource_root=tmp_path,
        executable_root=tmp_path,
        data_root=tmp_path / "data",
        executable=Path(sys.executable),
        python_executable=Path(sys.executable),
        path_console=None,
        console_helper=None,
        desktop_child=None,
        package_management=PackageManagementCapability(
            PackageManagementKind.UNSUPPORTED, (), False
        ),
        is_frozen=False,
    )


def test_native_window_configuration_contract() -> None:
    """Ensure pywebview window creation and startup options enforce security invariants."""
    import webview

    token = SecretToken.generate()
    bridge = DesktopBootstrapBridge(
        expected_origin="http://127.0.0.1:9999",
        token=token,
    )

    with (
        patch.object(webview, "create_window") as mock_create,
        patch.object(webview, "start") as mock_start,
    ):
        mock_window = MagicMock()
        mock_create.return_value = mock_window

        runtime = _test_runtime(Path("/tmp"))
        request = DesktopLaunchRequest(
            runtime=runtime,
            width=1024,
            height=768,
            title="Servonaut Desktop",
        )

        owner = DesktopSessionOwner()
        # Mock owner start to return confirmed ready origin without starting real process
        with patch.object(
            owner, "start", return_value=ReadyResponse(origin="http://127.0.0.1:9999")
        ):
            owner._bridge = bridge
            with patch(
                "servonaut.desktop.launcher.DesktopSessionOwner", return_value=owner
            ):
                ret = run_desktop(request)
                assert ret == 0

        # Assert create_window received security-mandated arguments
        mock_create.assert_called_once()
        kwargs = mock_create.call_args.kwargs
        assert kwargs["title"] == "Servonaut Desktop"
        assert kwargs["url"] == "http://127.0.0.1:9999"
        assert kwargs["width"] == 1024
        assert kwargs["height"] == 768
        assert kwargs["js_api"] is bridge

        # Assert webview.start was called with required private isolation settings
        mock_start.assert_called_once_with(
            gui=None,
            debug=False,
            http_server=False,
            private_mode=True,
        )


def test_native_window_bridge_claim_contract() -> None:
    """Verify that the JS bridge claim_session is only callable once by pywebview."""
    token = SecretToken.generate()
    bridge = DesktopBootstrapBridge(
        expected_origin="http://127.0.0.1:9999",
        token=token,
        get_current_url=lambda: "http://127.0.0.1:9999/",
    )

    # First claim succeeds
    claimed = bridge.claim_session()
    assert claimed == token.encoded_value()

    # Second claim fails
    with pytest.raises(DesktopBridgeError):
        bridge.claim_session()


@pytest.mark.skipif(
    not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"),
    reason="Headless environment without display server",
)
@pytest.mark.skipif(
    os.environ.get("SERVONAUT_DESKTOP_NATIVE_TEST") != "1",
    reason="Set SERVONAUT_DESKTOP_NATIVE_TEST=1 to execute live GUI window render",
)
def test_live_native_window_smoke() -> None:
    """Optional live native window smoke test when display server is available."""
    import webview

    window = webview.create_window(
        "Servonaut Native Smoke",
        "data:text/html,<html><body><h1>Smoke</h1></body></html>",
        width=400,
        height=300,
    )

    def close_soon() -> None:
        import time

        time.sleep(0.5)
        window.destroy()

    import threading

    threading.Thread(target=close_soon, daemon=True).start()

    webview.start(debug=False, private_mode=True)
