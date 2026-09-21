"""Contract tests for DesktopSessionOwner, DesktopDialogService, and run_desktop."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from servonaut.desktop.dialogs import DesktopDialogError, DesktopDialogService
from servonaut.desktop.launcher import (
    DesktopLauncherError,
    DesktopLaunchRequest,
    DesktopSessionOwner,
    run_desktop,
)
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


def _child_script_code() -> str:
    return """
import sys
from servonaut.desktop.control import read_parent_frame, encode_control_frame
from servonaut.desktop.model import ReadyResponse

req = read_parent_frame(sys.stdin.buffer, platform_name='posix')
resp = ReadyResponse(origin=req.origin)
sys.stdout.buffer.write(encode_control_frame(resp))
sys.stdout.buffer.flush()
# Keep running until EOF or terminate
try:
    sys.stdin.buffer.read()
except Exception:
    pass
"""


def test_session_owner_lifecycle(tmp_path: Path) -> None:
    child_script = tmp_path / "mock_child.py"
    child_script.write_text(_child_script_code(), encoding="utf-8")

    runtime = _test_runtime(tmp_path)
    owner = DesktopSessionOwner()

    request = DesktopLaunchRequest(
        runtime=runtime,
        child_argv=[sys.executable, str(child_script)],
        startup_timeout=5.0,
        shutdown_timeout=1.0,
    )

    ready = owner.start(request)
    assert ready.origin.startswith("http://127.0.0.1:")
    assert owner.origin == ready.origin
    assert owner.is_running
    assert owner.bridge is not None
    assert owner.bridge.expected_origin == ready.origin
    assert not owner.bridge.claimed

    # Duplicate start raises
    with pytest.raises(DesktopLauncherError) as exc_info:
        owner.start(request)
    assert "session-already-started" in exc_info.value.code

    # Graceful shutdown
    owner.request_shutdown()
    owner.close()

    assert not owner.is_running
    assert owner.tree is None
    assert owner.origin is None


def test_session_owner_cleanup_on_startup_failure(tmp_path: Path) -> None:
    # Child script that immediately exits without sending ReadyResponse
    child_script = tmp_path / "failing_child.py"
    child_script.write_text("import sys; sys.exit(1)\n", encoding="utf-8")

    runtime = _test_runtime(tmp_path)
    owner = DesktopSessionOwner()

    request = DesktopLaunchRequest(
        runtime=runtime,
        child_argv=[sys.executable, str(child_script)],
        startup_timeout=2.0,
        shutdown_timeout=1.0,
    )

    with pytest.raises(DesktopLauncherError) as exc_info:
        owner.start(request)
    assert "child-handshake-failed" in exc_info.value.code

    # Cleanup must be complete: no lingering process or socket
    assert not owner.is_running
    assert owner.tree is None


def test_dialog_service_methods() -> None:
    mock_window = MagicMock()
    service = DesktopDialogService(mock_window)

    # Open single file
    mock_window.create_file_dialog.return_value = ["/path/to/file.txt"]
    res = service.open_file(directory="/tmp")
    assert res == Path("/path/to/file.txt")
    mock_window.create_file_dialog.assert_called_with(
        dialog_type=10,
        directory="/tmp",
        allow_multiple=False,
        file_types=(),
    )

    # Open multiple files
    mock_window.create_file_dialog.return_value = ["/path/1.txt", "/path/2.txt"]
    multi_res = service.open_files()
    assert multi_res == (Path("/path/1.txt"), Path("/path/2.txt"))

    # Open folder
    mock_window.create_file_dialog.return_value = ["/path/to/dir"]
    folder_res = service.open_folder()
    assert folder_res == Path("/path/to/dir")

    # Save file
    mock_window.create_file_dialog.return_value = ["/path/to/saved.json"]
    save_res = service.save_file(save_filename="saved.json")
    assert save_res == Path("/path/to/saved.json")

    # Cancellation
    mock_window.create_file_dialog.return_value = None
    assert service.open_file() is None
    mock_window.create_file_dialog.return_value = []
    assert service.open_file() is None


def test_dialog_service_no_window() -> None:
    service = DesktopDialogService(window=None)
    with pytest.raises(DesktopDialogError) as exc_info:
        service.open_file()
    assert "dialog-window-unavailable" in exc_info.value.code


def test_run_desktop_webview_parameters(tmp_path: Path) -> None:
    child_script = tmp_path / "mock_child.py"
    child_script.write_text(_child_script_code(), encoding="utf-8")

    runtime = _test_runtime(tmp_path)
    request = DesktopLaunchRequest(
        runtime=runtime,
        child_argv=[sys.executable, str(child_script)],
        width=1280,
        height=800,
        title="Test Servonaut",
        renderer="gtk",
    )

    mock_webview = MagicMock()
    mock_window = MagicMock()
    mock_webview.create_window.return_value = mock_window

    with patch.dict("sys.modules", {"webview": mock_webview}):
        ret = run_desktop(request)
        assert ret == 0

    mock_webview.create_window.assert_called_once()
    _create_args, create_kwargs = mock_webview.create_window.call_args
    assert create_kwargs["title"] == "Test Servonaut"
    assert create_kwargs["width"] == 1280
    assert create_kwargs["height"] == 800
    assert create_kwargs["url"].startswith("http://127.0.0.1:")
    assert create_kwargs["js_api"] is not None

    mock_webview.start.assert_called_once_with(
        gui="gtk",
        debug=False,
        http_server=False,
        private_mode=True,
    )


def test_run_desktop_missing_webview(tmp_path: Path) -> None:
    runtime = _test_runtime(tmp_path)
    request = DesktopLaunchRequest(runtime=runtime, child_argv=["python"])

    with patch.dict("sys.modules", {"webview": None}):
        ret = run_desktop(request)
        assert ret == 1


def test_run_desktop_navigation_rejection(tmp_path: Path) -> None:
    child_script = tmp_path / "mock_child.py"
    child_script.write_text(_child_script_code(), encoding="utf-8")

    runtime = _test_runtime(tmp_path)
    request = DesktopLaunchRequest(
        runtime=runtime,
        child_argv=[sys.executable, str(child_script)],
    )

    mock_webview = MagicMock()
    mock_window = MagicMock()
    mock_webview.create_window.return_value = mock_window

    loaded_callbacks = []
    mock_window.events.loaded.__iadd__.side_effect = lambda cb: loaded_callbacks.append(
        cb
    )

    # Return foreign URL
    mock_window.get_current_url.return_value = "http://attacker.com/evil"

    with patch.dict("sys.modules", {"webview": mock_webview}):
        # When start is called, simulate loaded callback
        def on_start(**_kwargs):
            for cb in loaded_callbacks:
                cb()

        mock_webview.start.side_effect = on_start
        ret = run_desktop(request)
        assert ret == 0

    # Window destroy must have been called due to foreign navigation
    mock_window.destroy.assert_called()


def test_run_desktop_child_crash(tmp_path: Path) -> None:
    child_script = tmp_path / "crash_child.py"
    # Sends ready frame, then crashes with code 42
    child_script.write_text(
        """
import sys, time
from servonaut.desktop.control import read_parent_frame, encode_control_frame
from servonaut.desktop.model import ReadyResponse

req = read_parent_frame(sys.stdin.buffer, platform_name='posix')
resp = ReadyResponse(origin=req.origin)
sys.stdout.buffer.write(encode_control_frame(resp))
sys.stdout.buffer.flush()
time.sleep(0.1)
sys.exit(42)
""",
        encoding="utf-8",
    )

    runtime = _test_runtime(tmp_path)
    request = DesktopLaunchRequest(
        runtime=runtime,
        child_argv=[sys.executable, str(child_script)],
    )

    mock_webview = MagicMock()
    mock_window = MagicMock()
    mock_webview.create_window.return_value = mock_window

    def fake_start(**_kwargs):
        # Wait a bit so the child monitor thread observes exit code 42
        import time

        time.sleep(0.3)

    mock_webview.start.side_effect = fake_start

    with patch.dict("sys.modules", {"webview": mock_webview}):
        ret = run_desktop(request)
        assert ret == 42
