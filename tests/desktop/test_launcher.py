"""Contract tests for DesktopSessionOwner and run_desktop."""

from __future__ import annotations

import ast
import importlib.util
import logging
import re
import socket
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from servonaut.desktop import launcher
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

    ready = owner.start(request, get_current_url=lambda: None)
    assert ready.origin.startswith("http://127.0.0.1:")
    assert owner.origin == ready.origin
    assert owner.is_running
    assert owner.bridge is not None
    assert owner.bridge.expected_origin == ready.origin
    assert not owner.bridge.claimed

    # Duplicate start raises
    with pytest.raises(DesktopLauncherError) as exc_info:
        owner.start(request, get_current_url=lambda: None)
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
        owner.start(request, get_current_url=lambda: None)
    assert "child-handshake-failed" in exc_info.value.code

    # Cleanup must be complete: no lingering process or socket
    assert not owner.is_running
    assert owner.tree is None


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
    assert "js_api" not in create_kwargs

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
    # ...and the foreign page was handed nothing.
    mock_window.run_js.assert_not_called()


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


def test_session_listener_does_not_allow_address_reuse(tmp_path: Path) -> None:
    child_script = tmp_path / "mock_child.py"
    child_script.write_text(_child_script_code(), encoding="utf-8")
    owner = DesktopSessionOwner()
    request = DesktopLaunchRequest(
        runtime=_test_runtime(tmp_path),
        child_argv=[sys.executable, str(child_script)],
        shutdown_timeout=1.0,
    )

    owner.start(request, get_current_url=lambda: None)
    try:
        assert owner._listener is not None
        reuse = owner._listener.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
        assert reuse == 0
    finally:
        owner.request_shutdown()
        owner.close()


class _RecordingSocket:
    def __init__(self, *_args: object) -> None:
        self.options: list[tuple[int, int, int]] = []
        self.closed = False

    def setsockopt(self, level: int, option: int, value: int) -> None:
        self.options.append((level, option, value))

    def bind(self, _address: tuple[str, int]) -> None:
        pass

    def listen(self, _backlog: int) -> None:
        pass

    def close(self) -> None:
        self.closed = True


def test_windows_listener_claims_exclusive_use(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercised with a fake socket; exclusive use itself only exists on Windows."""
    exclusive_option = -5
    monkeypatch.setattr(
        launcher.socket, "SO_EXCLUSIVEADDRUSE", exclusive_option, raising=False
    )
    monkeypatch.setattr(launcher.socket, "socket", _RecordingSocket)

    listener = launcher._bind_loopback_listener(platform_name="win32")

    assert (socket.SOL_SOCKET, exclusive_option, 1) in listener.options
    assert all(option != socket.SO_REUSEADDR for _, option, _ in listener.options)


def _run_loaded_window(
    tmp_path: Path,
    *,
    location: Callable[[MagicMock, str], None],
    loads: int = 1,
) -> MagicMock:
    """Run the launcher and fire the window's ``loaded`` event *loads* times.

    *location* gets the mock window and the URL it was opened at, and sets up
    what ``get_current_url`` reports. Returns the mock window.
    """
    child_script = tmp_path / "mock_child.py"
    child_script.write_text(_child_script_code(), encoding="utf-8")
    request = DesktopLaunchRequest(
        runtime=_test_runtime(tmp_path),
        child_argv=[sys.executable, str(child_script)],
    )
    mock_webview = MagicMock()
    mock_window = MagicMock()
    mock_webview.create_window.return_value = mock_window
    loaded_callbacks: list[Callable[[], None]] = []
    mock_window.events.loaded.__iadd__.side_effect = loaded_callbacks.append

    def fake_start(**_kwargs: object) -> None:
        location(mock_window, mock_webview.create_window.call_args.kwargs["url"])
        for _ in range(loads):
            for callback in loaded_callbacks:
                callback()

    mock_webview.start.side_effect = fake_start
    with patch.dict("sys.modules", {"webview": mock_webview}):
        assert run_desktop(request) == 0
    return mock_window


def _at_root(window: MagicMock, url: str) -> None:
    window.get_current_url.return_value = url + "/"


def test_run_desktop_hands_the_token_to_the_root_document_once(tmp_path: Path) -> None:
    """The token reaches the page once; a reload is not handed it again."""
    window = _run_loaded_window(tmp_path, location=_at_root, loads=2)

    window.run_js.assert_called_once()
    script = window.run_js.call_args.args[0]
    token = re.search(r'window\.startServonaut\("([A-Za-z0-9_-]+)"\)', script)
    assert token is not None
    assert len(token.group(1)) == 43
    window.destroy.assert_not_called()


def test_run_desktop_unknown_location_gets_no_token(tmp_path: Path) -> None:
    """A window whose location cannot be read is closed, not handed the token."""

    def unreadable(window: MagicMock, _url: str) -> None:
        window.get_current_url.side_effect = RuntimeError("no location")

    window = _run_loaded_window(tmp_path, location=unreadable)

    window.run_js.assert_not_called()
    window.destroy.assert_called()


def test_run_desktop_refused_claim_gets_no_token(tmp_path: Path) -> None:
    """The bridge re-checks the location; a page that moved on is closed."""

    def moves_away(window: MagicMock, url: str) -> None:
        # The launcher sees the root document, then the bridge sees elsewhere.
        window.get_current_url.side_effect = [url + "/", url + "/other.html"]

    window = _run_loaded_window(tmp_path, location=moves_away)

    window.run_js.assert_not_called()
    window.destroy.assert_called()


def test_run_desktop_does_not_log_the_token_when_the_hand_over_fails(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    def failing_page(window: MagicMock, url: str) -> None:
        _at_root(window, url)
        window.run_js.side_effect = RuntimeError("script failed")

    with caplog.at_level(logging.DEBUG):
        window = _run_loaded_window(tmp_path, location=failing_page)

    script = window.run_js.call_args.args[0]
    token = re.search(r'startServonaut\("([^"]+)"\)', script).group(1)
    assert "Could not hand the desktop session to the page: RuntimeError" in caplog.text
    assert token not in caplog.text


def test_session_start_script_passes_the_token_as_a_string_literal() -> None:
    script = launcher._session_start_script('a"b</script>\\')

    assert "typeof window.startServonaut === 'function'" in script
    assert 'window.startServonaut("a\\"b</script>\\\\")' in script


def test_launcher_never_exposes_a_js_api_to_the_page() -> None:
    """pywebview builds js_api methods in the page with ``new Function``.

    The desktop page's Content-Security-Policy (``script-src 'self'``, no
    ``'unsafe-eval'``) refuses that, so an exposed API never appears, the page
    never receives its session token and the window stays blank. The token is
    handed over with ``window.run_js`` instead; this guards every call site.
    """
    tree = ast.parse(Path(launcher.__file__).read_text(encoding="utf-8"))
    create_window_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "create_window"
    ]
    assert create_window_calls
    for call in create_window_calls:
        assert "js_api" not in {keyword.arg for keyword in call.keywords}
        assert all(keyword.arg is not None for keyword in call.keywords)


def test_run_desktop_start_failure_is_reported_natively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The GUI process has no console, so a failed start must be shown to the user."""
    child_script = tmp_path / "failing_child.py"
    child_script.write_text("import sys; sys.exit(1)\n", encoding="utf-8")
    log_file = tmp_path / "data" / "logs" / "desktop.log"
    request = DesktopLaunchRequest(
        runtime=_test_runtime(tmp_path),
        child_argv=[sys.executable, str(child_script)],
        startup_timeout=2.0,
        log_file=log_file,
    )
    shown: list[tuple[str, str]] = []
    monkeypatch.setattr(
        launcher, "show_native_error", lambda *args: shown.append(args)
    )

    with patch.dict("sys.modules", {"webview": MagicMock()}):
        assert run_desktop(request) == 1

    assert len(shown) == 1
    title, message = shown[0]
    assert title == request.title
    assert "child-handshake-failed" in message
    assert str(log_file) in message


def test_run_desktop_missing_webview_is_reported_natively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = DesktopLaunchRequest(
        runtime=_test_runtime(tmp_path), child_argv=["python"]
    )
    shown: list[tuple[str, str]] = []
    monkeypatch.setattr(
        launcher, "show_native_error", lambda *args: shown.append(args)
    )

    with patch.dict("sys.modules", {"webview": None}):
        assert run_desktop(request) == 1

    assert len(shown) == 1


def test_native_error_uses_message_box_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercised with a fake user32; the real dialog only exists on Windows."""
    user32 = MagicMock()
    monkeypatch.setattr(launcher.sys, "platform", "win32")
    monkeypatch.setattr(
        launcher.ctypes, "windll", SimpleNamespace(user32=user32), raising=False
    )

    launcher.show_native_error("Servonaut", "Could not start")

    user32.MessageBoxW.assert_called_once()
    _owner, text, caption, _flags = user32.MessageBoxW.call_args.args
    assert (text, caption) == ("Could not start", "Servonaut")


def test_native_error_passes_text_to_osascript_as_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """User-visible text must never be spliced into the AppleScript source."""
    run = MagicMock()
    monkeypatch.setattr(launcher.sys, "platform", "darwin")
    monkeypatch.setattr(launcher.subprocess, "run", run)
    message = 'Failed "quoted" & more'

    launcher.show_native_error("Servonaut", message)

    argv = run.call_args.args[0]
    assert argv[0] == "osascript"
    assert argv[-2:] == ["Servonaut", message]
    script = " ".join(argv[1:-2])
    assert message not in script


def test_native_error_is_skipped_elsewhere(monkeypatch: pytest.MonkeyPatch) -> None:
    run = MagicMock()
    monkeypatch.setattr(launcher.sys, "platform", "linux")
    monkeypatch.setattr(launcher.subprocess, "run", run)

    launcher.show_native_error("Servonaut", "Could not start")

    run.assert_not_called()


def _load_gui_entry() -> object:
    entry = (
        Path(__file__).resolve().parents[2]
        / "packaging"
        / "desktop_shell"
        / "entries"
        / "servonaut_desktop.py"
    )
    spec = importlib.util.spec_from_file_location("servonaut_desktop_gui_entry", entry)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.usefixtures("restore_root_logging")
def test_gui_entry_writes_its_log_under_the_data_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry = _load_gui_entry()
    runtime = _test_runtime(tmp_path)
    requests: list[DesktopLaunchRequest] = []
    monkeypatch.setattr(entry, "detect_runtime", lambda: runtime)
    monkeypatch.setattr(
        entry, "run_desktop", lambda request: requests.append(request) or 0
    )

    assert entry.main([]) == 0

    logging.getLogger("servonaut.desktop").error("desktop start probe")
    for handler in logging.getLogger().handlers:
        handler.flush()
    log_file = runtime.data_root / "logs" / "desktop.log"
    assert requests[0].log_file == log_file
    assert "desktop start probe" in log_file.read_text(encoding="utf-8")
