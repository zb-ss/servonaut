"""Log workspaces keep their live tail, hotkeys and picker flows beside chat."""

from __future__ import annotations

import asyncio
import io
import queue
import subprocess as real_subprocess
from collections.abc import Awaitable, Callable, Iterator
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from textual.pilot import Pilot
from textual.widgets import RichLog, Static

from servonaut.app import ServonautApp
from servonaut.config.schema import AppConfig
from servonaut.screens.instance_list import InstanceListScreen
from servonaut.screens.log_picker import (
    AddPathModal, BrowseRemoteScreen, LogPickerModal, ManagePathsModal,
)
from servonaut.screens.log_viewer import LogViewerScreen
from servonaut.widgets.chat_panel import ChatPanel
from servonaut.widgets.sidebar import Sidebar
from servonaut.widgets.workspace import WorkspaceScreen
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import (
    BoundarySample, ReflowCase, assert_essential_targets, assert_layout, collapse_chat, content,
    one_layout_transition, open_case, open_chat, preserve_native_state,
)
from tests.test_workspace_pilot import _Host, _click

pytestmark = pytest.mark.usefixtures("navigation_open")


LOGS = ["/var/log/syslog", "/var/log/app.log"]


class _FakeSshLog:
    """The viewer's log-wrapper interface without files or environment reads."""

    def __init__(self) -> None:
        self.close_calls = 0

    def command(self, argv: list[str]) -> list[str]:
        return argv

    def environment(self) -> None:
        return None

    def read(self) -> str:
        return ""

    def close(self) -> None:
        self.close_calls += 1


class _FakeProcess:
    """A tail process whose stdout yields queued lines until terminated."""

    def __init__(self) -> None:
        self._lines: queue.Queue = queue.Queue()
        self.stdout = iter(self._lines.get, None)
        self.stderr = io.BytesIO(b"")
        self.returncode: int | None = None
        self.pid = 4242
        self.terminated = 0

    def feed(self, *lines: str) -> None:
        for line in lines:
            self._lines.put((line + "\n").encode())

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated += 1
        self.returncode = -15
        self._lines.put(None)

    kill = terminate

    def wait(self, timeout: float | None = None) -> int | None:
        return self.returncode


class _LogHost(_Host):
    """The accepted native workspace host with an inert log service."""

    def __init__(self, navigation_visible: bool = True) -> None:
        super().__init__(navigation_visible=navigation_visible)
        config = AppConfig()

        def update(**changes: object) -> None:
            for key, value in changes.items():
                setattr(config, key, value)

        self.config_manager = SimpleNamespace(get=lambda: config, update=update, save=Mock())
        self.processes: list[_FakeProcess] = []
        self.log_viewer_service = SimpleNamespace(
            probe_log_paths=AsyncMock(return_value=list(LOGS)),
            scan_log_directories=AsyncMock(return_value=[]),
            classify_log_file=Mock(return_value="active"),
            get_read_command=Mock(side_effect=lambda path, lines: f"tail -n {lines} -F {path}"),
            resolve_connection=AsyncMock(return_value={
                "host": "192.0.2.10", "username": "admin", "key_path": None,
                "proxy_args": [], "port": 22, "extra_options": [],
            }),
            get_custom_paths=Mock(return_value=["/srv/app/custom.log"]),
            add_custom_path=Mock(return_value=True),
            remove_custom_path=Mock(return_value=True),
            last_probe_source=None, last_probe_probed_at=None,
        )
        self.ssh_service = SimpleNamespace(
            build_ssh_command=Mock(return_value=["ssh", "admin@192.0.2.10"]),
        )
        self.connection_service = SimpleNamespace(
            resolve_profile=Mock(return_value=None),
            get_target_host=Mock(return_value="192.0.2.10"),
            get_proxy_args=Mock(return_value=[]),
            get_extra_options=Mock(return_value=[]),
            get_target_port=Mock(return_value=22),
        )

    def popen(self, *args: object, **kwargs: object) -> _FakeProcess:
        process = _FakeProcess()
        self.processes.append(process)
        return process


@pytest.fixture(autouse=True)
def _inert_boundaries(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr(ChatPanel, "on_mount", lambda self: None)
    ssh_logs: list[_FakeSshLog] = []

    def create_ssh_log() -> _FakeSshLog:
        log = _FakeSshLog()
        ssh_logs.append(log)
        return log

    monkeypatch.setattr("servonaut.screens.log_viewer.SshLog", create_ssh_log)
    monkeypatch.setattr("servonaut.screens.log_viewer.background_process_kwargs", lambda: {})
    monkeypatch.setattr("servonaut.screens.log_viewer.track_background_process", lambda process: None)
    # The viewer's tail goes through the dedicated fake in _patch_viewer_popen,
    # which replaces only log_viewer's own subprocess alias. Every global
    # process start (Popen and run) and every network connection trips here.
    process = Mock(side_effect=AssertionError("Unexpected subprocess"))
    monkeypatch.setattr("subprocess.Popen", process)
    monkeypatch.setattr("subprocess.run", process)
    socket_connection = Mock(side_effect=AssertionError("Unexpected network"))
    monkeypatch.setattr("socket.create_connection", socket_connection)
    connection = AsyncMock(side_effect=AssertionError("Unexpected network"))
    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", connection)
    yield
    process.assert_not_called()
    socket_connection.assert_not_called()
    connection.assert_not_awaited()
    assert all(log.close_calls > 0 for log in ssh_logs), "An SSH log wrapper was not closed"


def _patch_viewer_popen(monkeypatch: pytest.MonkeyPatch, app: _LogHost) -> None:
    fake = SimpleNamespace(
        Popen=app.popen, PIPE=real_subprocess.PIPE, DEVNULL=real_subprocess.DEVNULL,
        TimeoutExpired=real_subprocess.TimeoutExpired,
    )
    monkeypatch.setattr("servonaut.screens.log_viewer.subprocess", fake)


def _viewer_instance() -> dict:
    return {"id": "id-web-1", "name": "web-1", "is_custom": True, "username": "admin"}


def _opener(kind: str) -> Callable[[ServonautApp, Pilot], Awaitable[WorkspaceScreen]]:
    async def open_screen(app: ServonautApp, pilot: Pilot) -> WorkspaceScreen:
        await wait_until(lambda: isinstance(app.screen, InstanceListScreen))
        screen = (LogViewerScreen(_viewer_instance()) if kind == "viewer"
                  else BrowseRemoteScreen(instance=_viewer_instance()))
        await app.push_screen(screen)
        return screen
    return open_screen


async def _ready(screen: WorkspaceScreen) -> None:
    if isinstance(screen, LogViewerScreen):
        await wait_until(lambda: screen._current_log == LOGS[0] and screen._flush_timer is not None)
        screen.app.processes[-1].feed("first café line", "second Ω line")
        await wait_until(lambda: len(screen._content_buffer) == 2)
    else:
        await wait_until(lambda: bool(screen.query("#browse_tree")))


def _seed(screen: WorkspaceScreen) -> None:
    return None


def _state(screen: WorkspaceScreen) -> object:
    if isinstance(screen, LogViewerScreen):
        return (screen._current_log, screen._is_paused, screen._flush_timer,
                tuple(screen._content_buffer), screen._process)
    return (screen.query_one("#browse_tree"), screen.query_one("#browse_header", Static).render().plain)


# Derived native first focus: the RichLog for the viewer and the mounted tree
# for the browser; open_case characterises both on the first native run.
# Qualified native columns and separately measured layout policy.
_MEASURED_BOUNDARIES = {
    'viewer': {
        ('chat-min', False): (
            BoundarySample((108, 50), 63, True, True),
            BoundarySample((109, 50), 64, False, True),
            BoundarySample((110, 50), 65, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((146, 50), 63, True, True),
            BoundarySample((148, 50), 64, True, True),
            BoundarySample((149, 50), 65, False, True),
        ),
        # Capped chat makes these widths integral; the native test verifies them.
        ('content-narrow', False): (
            BoundarySample((167, 50), 103, False, True),
            BoundarySample((168, 50), 104, False, False),
            BoundarySample((169, 50), 105, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((192, 50), 103, False, True),
            BoundarySample((193, 50), 104, False, False),
            BoundarySample((194, 50), 105, False, False),
        ),
    },
    'browse': {
        ('chat-min', False): (
            BoundarySample((92, 50), 47, True, True),
            BoundarySample((93, 50), 48, False, True),
            BoundarySample((94, 50), 49, False, True),
        ),
        ('chat-min', True): (
            BoundarySample((120, 50), 47, True, True),
            BoundarySample((121, 50), 48, True, True),
            BoundarySample((122, 50), 49, False, True),
        ),
        ('content-narrow', False): (
            BoundarySample((131, 50), 79, False, True),
            BoundarySample((133, 50), 80, False, True),
            BoundarySample((134, 50), 81, False, False),
        ),
        ('content-narrow', True): (
            BoundarySample((168, 50), 79, False, True),
            BoundarySample((169, 50), 80, False, False),
            BoundarySample((170, 50), 81, False, False),
        ),
    },
}


CASES = (
    ReflowCase("viewer", _LogHost, _opener("viewer"), _ready, "#log_output",
               ("#log_output",), _seed, _state, (("#log_output", "first café line"),), boundaries=_MEASURED_BOUNDARIES['viewer']),
    ReflowCase("browse", _LogHost, _opener("browse"), _ready, "#browse_tree",
               ("#browse_tree",), _seed, _state, (), boundaries=_MEASURED_BOUNDARIES['browse']),
)
IDS = [case.name for case in CASES]


@pytest.fixture
def popen(monkeypatch: pytest.MonkeyPatch) -> Callable[[_LogHost], _LogHost]:
    def install(app: _LogHost) -> _LogHost:
        _patch_viewer_popen(monkeypatch, app)
        return app
    return install


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=IDS)
@pytest.mark.parametrize("size", [(160, 50), (100, 30)])
@pytest.mark.parametrize("navigation_visible", [False, True])
@pytest.mark.parametrize("chat_open", [False, True])
async def test_log_workspace_pane_combinations(
    case: ReflowCase, size: tuple[int, int], navigation_visible: bool, chat_open: bool,
    popen: Callable[[_LogHost], _LogHost],
) -> None:
    app = popen(case.app_factory(navigation_visible))
    async with app.run_test(size=size) as pilot:
        screen = await open_case(case, app, pilot)
        baseline = case.state(screen)
        if chat_open:
            await open_chat(app, pilot, screen)
        assert_layout(app, screen)
        assert screen.query_one(Sidebar).display is navigation_visible
        assert case.state(screen) == baseline
        if content(screen).display:
            await assert_essential_targets(case, app, pilot, screen)
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=IDS)
async def test_log_workspace_native_state_survives_reflow(
    case: ReflowCase, popen: Callable[[_LogHost], _LogHost],
) -> None:
    app = popen(case.app_factory(False))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await preserve_native_state(case, app, pilot, screen)
        assert app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=IDS)
@pytest.mark.parametrize("kind", ["chat-min", "content-narrow"])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_log_workspace_uses_qualified_native_boundaries(
    case: ReflowCase, kind: str, navigation_visible: bool,
    popen: Callable[[_LogHost], _LogHost],
) -> None:
    # Fails closed until qualified native samples exist (boundaries=None).
    samples = case.boundary_samples(kind, navigation_visible)
    app = popen(case.app_factory(navigation_visible))
    async with app.run_test(size=samples[0].size) as pilot:
        screen = await open_case(case, app, pilot)
        baseline = case.state(screen)
        await open_chat(app, pilot, screen)
        threshold = (
            screen.CHAT_MIN_CONTENT_WIDTH if kind == "chat-min"
            else screen.CONTENT_NARROW_WIDTH
        )
        # Samples straddle the declared threshold by exactly one native cell.
        assert [sample.native_content_width for sample in samples] == [
            threshold - 1, threshold, threshold + 1,
        ]
        for sample in samples:
            with one_layout_transition(screen):
                await pilot.resize_terminal(*sample.size)
                await pilot.pause()
            assert screen.has_class("-chat-replace") is sample.expected_replace
            assert screen.has_class("-content-narrow") is sample.expected_content_narrow
            assert_layout(app, screen)
            if sample.expected_replace:
                # Counterfactual: force the columns the policy hides, measure
                # the native width, then restore and re-check the real flags.
                with patch.object(screen, "CHAT_MIN_CONTENT_WIDTH", 1):
                    screen.apply_workspace_state()
                    await pilot.pause()
                    assert content(screen).region.width == sample.native_content_width
                screen.apply_workspace_state()
                await pilot.pause()
                assert screen.has_class("-chat-replace") is sample.expected_replace
                assert screen.has_class("-content-narrow") is sample.expected_content_narrow
                assert not content(screen).display
            else:
                assert content(screen).region.width == sample.native_content_width
                await assert_essential_targets(case, app, pilot, screen)
            assert case.state(screen) == baseline


async def _enter_rail(pilot: Pilot, screen: WorkspaceScreen) -> Sidebar:
    await pilot.press("shift+f6")
    sidebar = screen.query_one(Sidebar)
    await wait_until(lambda: sidebar.navigation_mode and sidebar.has_focus_within)
    return sidebar


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,key", [
    ("viewer", "p"), ("viewer", "c"), ("viewer", "m"), ("viewer", "l"),
    ("viewer", "a"), ("viewer", "y"), ("viewer", "v"), ("viewer", "plus"),
    ("browse", "f"), ("browse", "d"),
])
@pytest.mark.parametrize("navigation_visible", [False, True])
async def test_rail_focused_log_keys_have_no_side_effects(
    kind: str, key: str, navigation_visible: bool, popen: Callable[[_LogHost], _LogHost],
) -> None:
    case = next(case for case in CASES if case.name == kind)
    app = popen(case.app_factory(navigation_visible))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        app.copy_to_clipboard("retain clipboard sentinel")
        before = (case.state(screen), app.clipboard,
                  app.log_viewer_service.get_custom_paths.call_count)
        sidebar = await _enter_rail(pilot, screen)
        await pilot.press(key)
        await pilot.pause()
        # A dismissed browser or any pushed dialog would change the top screen.
        assert app.screen is screen
        assert (case.state(screen), app.clipboard,
                app.log_viewer_service.get_custom_paths.call_count) == before
        assert sidebar.navigation_mode and sidebar.has_focus_within
        await pilot.press("escape")
        await wait_until(lambda: not sidebar.navigation_mode)
        assert app.screen is screen and app._exception is None


@pytest.mark.asyncio
async def test_browse_priority_enter_stays_off_the_rail(
    popen: Callable[[_LogHost], _LogHost],
) -> None:
    case = next(case for case in CASES if case.name == "browse")
    app = popen(case.app_factory(True))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        assert screen.check_action("select_node", ()) is True
        await _enter_rail(pilot, screen)
        # The rail button, not the tree action, owns Enter here.
        assert screen.check_action("select_node", ()) is None
        assert screen.check_action("select_as_file", ()) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("key,expected", [("plus", AddPathModal), ("m", ManagePathsModal),
                                           ("l", LogPickerModal)])
async def test_log_keys_still_open_their_dialogs_from_content(
    key: str, expected: type, popen: Callable[[_LogHost], _LogHost],
) -> None:
    case = next(case for case in CASES if case.name == "viewer")
    app = popen(case.app_factory(True))
    async with app.run_test(size=(160, 50)) as pilot:
        await open_case(case, app, pilot)
        await pilot.press(key)
        await wait_until(lambda: isinstance(app.screen, expected))


@pytest.mark.asyncio
async def test_pause_still_toggles_from_content(popen: Callable[[_LogHost], _LogHost]) -> None:
    case = next(case for case in CASES if case.name == "viewer")
    app = popen(case.app_factory(True))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await pilot.press("p")
        await wait_until(lambda: screen._is_paused)
        await pilot.press("p")
        await wait_until(lambda: not screen._is_paused)


@pytest.mark.asyncio
async def test_f2_toggles_chat_on_viewer_but_manages_paths_in_picker(
    popen: Callable[[_LogHost], _LogHost],
) -> None:
    case = next(case for case in CASES if case.name == "viewer")
    app = popen(case.app_factory(True))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        timer = screen._flush_timer
        await pilot.press("f2")
        await wait_until(lambda: bool(screen.query(ChatPanel)))
        assert not screen._is_paused and screen._flush_timer is timer
        await collapse_chat(app, pilot, screen)
        await pilot.press("l")
        await wait_until(lambda: isinstance(app.screen, LogPickerModal))
        picker = app.screen
        await pilot.press("f2")
        await wait_until(lambda: isinstance(app.screen, ManagePathsModal))
        assert picker in app.screen_stack and not app.screen.query(ChatPanel)


@pytest.mark.asyncio
async def test_live_tail_keeps_streaming_through_chat_reflow(
    popen: Callable[[_LogHost], _LogHost],
) -> None:
    case = next(case for case in CASES if case.name == "viewer")
    app = popen(case.app_factory(True))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        timer, process = screen._flush_timer, screen._process
        await open_chat(app, pilot, screen)
        process.feed("beside chat")
        await wait_until(lambda: "beside chat" in screen._content_buffer)
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert screen.has_class("-chat-replace") and not content(screen).display
        process.feed("while replaced")
        await wait_until(lambda: "while replaced" in screen._content_buffer)
        await pilot.resize_terminal(160, 50)
        await collapse_chat(app, pilot, screen)
        assert screen._flush_timer is timer and screen._process is process
        assert not screen._is_paused and process.terminated == 0
        assert screen.query_one("#log_output", RichLog).is_attached


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["manage-escape", "manage-close", "picker-escape"])
async def test_closing_a_path_dialog_resumes_the_live_tail(
    route: str, popen: Callable[[_LogHost], _LogHost],
) -> None:
    # Characterises the pop_screen lead: the desired contract is that every
    # close route resumes the paused stream. A red here is the original
    # evidence a dismiss correction needs; no product change is made for it.
    case = next(case for case in CASES if case.name == "viewer")
    app = popen(case.app_factory(True))
    async with app.run_test(size=(160, 50)) as pilot:
        screen = await open_case(case, app, pilot)
        await pilot.press("l" if route == "picker-escape" else "m")
        modal = LogPickerModal if route == "picker-escape" else ManagePathsModal
        await wait_until(lambda: isinstance(app.screen, modal))
        assert screen._is_paused and screen._flush_timer is None
        if route == "manage-close":
            await _click(pilot, "#manage_close")
        else:
            await pilot.press("escape")
        await wait_until(lambda: app.screen is screen)
        await pilot.pause()
        assert not screen._is_paused and screen._flush_timer is not None


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["back", "rail-switch"])
async def test_nested_browse_from_manage_paths_characterises_stack_and_stream(
    route: str, popen: Callable[[_LogHost], _LogHost],
) -> None:
    # Option (a): the browser adopts the rail. This records what the nested
    # Manage -> Browse stack does on Back and on a rail switch; the safe
    # expectation is no orphaned dialog and a stream that is not left paused.
    case = next(case for case in CASES if case.name == "viewer")
    app = popen(case.app_factory(True))
    async with app.run_test(size=(160, 50)) as pilot:
        viewer = await open_case(case, app, pilot)
        await pilot.press("m")
        await wait_until(lambda: isinstance(app.screen, ManagePathsModal))
        manage = app.screen
        await _click(pilot, "#manage_browse")
        await wait_until(lambda: isinstance(app.screen, BrowseRemoteScreen))
        browse = app.screen
        if route == "back":
            await pilot.press("escape")
            await wait_until(lambda: app.screen is manage)
            assert browse not in app.screen_stack and viewer._is_paused
            return
        sidebar = await _enter_rail(pilot, browse)
        target = sidebar.query_one("#nav_list")
        target.focus()
        await pilot.press("enter")
        await wait_until(lambda: browse not in app.screen_stack)
        stack = tuple(type(screen).__name__ for screen in app.screen_stack)
        assert manage not in app.screen_stack, stack
        assert not viewer._is_paused or viewer not in app.screen_stack, stack
