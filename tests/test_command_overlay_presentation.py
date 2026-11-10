"""The live command console keeps native input and output behavior across themes."""

from __future__ import annotations

import asyncio
import io
import shlex
import subprocess
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, create_autospec

import pytest
from textual.app import App, ComposeResult
from textual.containers import Container, Vertical, VerticalScroll
from textual.pilot import Pilot
from textual.widgets import Button, Input, RichLog, Static
from textual.widgets._toast import Toast

from servonaut.config.schema import AppConfig
from servonaut.screens.command_overlay import CommandOverlay
from servonaut.screens.command_picker import CommandPickerModal, SaveCommandModal
from servonaut.services.connection_service import ConnectionService
from servonaut.services.ssh_service import SSHService
from servonaut.styles import CSS_FILES
from servonaut.styles.themes import SERVONAUT_THEMES
from servonaut.widgets.command_output import CommandOutput
from tests._async_bounds import wait_until
from tests._workspace_reflow_conformance import assert_button_label_painted
from tests.test_navigation_dialog_contrast import _assert_readable, _painted_text_styles
from tests.test_selection_copy import _Clipboard
from tests.test_selection_copy import clipboard as clipboard
from tests.test_workspace_reflow import _painted

pytestmark = pytest.mark.usefixtures("navigation_open")


THEMES = ("servonaut", "servonaut-light", "ansi-dark", "ansi-light")
SIZES = ((100, 30), (160, 50))
ROW = {"id": "id-web-1", "name": "web-1", "is_custom": True, "username": "operator"}
COMMAND = 'printf "café Ω"'
_TRIPS: list[str] = []
# Original native evidence is mandatory before changing a notification region or key policy.
ORIGINAL_NOTICE_INPUT_EXPOSED: dict[tuple[str, tuple[int, int]], bool] | None = {
    ('servonaut', (100, 30)): False,
    ('servonaut', (160, 50)): True,
    ('servonaut-light', (100, 30)): False,
    ('servonaut-light', (160, 50)): True,
    ('ansi-dark', (100, 30)): False,
    ('ansi-dark', (160, 50)): True,
    ('ansi-light', (100, 30)): False,
    ('ansi-light', (160, 50)): True,
}
ORIGINAL_INPUT_CTRL_C: tuple[bool, bool] | None = (False, True)


def _refuse(name: str) -> None:
    _TRIPS.append(name)
    raise AssertionError("Unexpected console boundary: " + name)


@dataclass
class _Run:
    lines: tuple[str, ...] = ("café [literal] Ω",)
    stderr: str = ""
    diagnostics: str = ""
    code: int = 0
    held: bool = False
    late: bool = False
    failure: Exception | None = None
    release: threading.Event = field(default_factory=threading.Event)
    closed: bool = False


class _Pipe:
    def __init__(self, run: _Run) -> None:
        self.run = run
        self.rows = iter(run.lines)
        self.released = False

    def readline(self) -> bytes:
        try:
            return (next(self.rows) + "\n").encode()
        except StopIteration:
            if self.run.held and not self.released:
                assert self.run.release.wait(5), "The fake process gate was not released"
                self.released = True
                if self.run.late:
                    return "late café Ω\n".encode()
            return b""


class _Process:
    def __init__(self, run: _Run) -> None:
        self.run = run
        self.stdout = _Pipe(run)
        self.stderr = io.BytesIO(run.stderr.encode())
        self.returncode: int | None = None
        self.terminated = 0

    def terminate(self) -> None:
        self.terminated += 1
        if not self.run.late:
            self.run.release.set()

    def wait(self) -> int:
        self.returncode = -15 if self.terminated else self.run.code
        return self.returncode


class _Log:
    """The real SshLog interface, with neither files nor environment reads."""

    def __init__(self, runner: _Runner) -> None:
        self.run = runner.next_run
        runner.runs.append(self.run)

    def command(self, argv: list[str]) -> list[str]:
        return argv

    def environment(self) -> dict[str, str]:
        return {}

    def read(self) -> str:
        return self.run.diagnostics

    def close(self) -> None:
        self.run.closed = True


class _Runner:
    def __init__(self) -> None:
        self.next_run = _Run()
        self.runs: list[_Run] = []
        self.processes: list[_Process] = []
        self.argv: list[list[str]] = []

    def popen(self, argv: list[str], **kwargs: object) -> _Process:
        if not argv or argv[0] != "fixture-ssh":
            _refuse("unrecognized Popen")
        # This fake accepts only the exact subprocess surface the console uses.
        assert set(kwargs) == {"stdout", "stderr", "stdin", "env"}
        assert kwargs["stdout"] == kwargs["stderr"] == subprocess.PIPE
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["env"] == {}
        self.argv.append(list(argv))
        if self.next_run.failure:
            raise self.next_run.failure
        process = _Process(self.next_run)
        self.processes.append(process)
        return process


class _History:
    def __init__(self) -> None:
        self.commands = ["pwd", "printf older"]
        self.added: list[tuple[str, str]] = []
        self.saved: list[tuple[str, str]] = []

    def get_instance_history(self, instance_id: str) -> list[str]:
        assert instance_id == ROW["id"]
        return list(self.commands)

    def get_global_history(self) -> list[str]:
        return list(self.commands)

    def get_saved_commands(self) -> list[dict[str, str]]:
        return [{"name": "Example command", "command": COMMAND}]

    def add_to_history(self, instance_id: str, command: str) -> None:
        self.added.append((instance_id, command))
        self.commands.append(command)

    def save_command(self, name: str, command: str) -> None:
        self.saved.append((name, command))


class _Host(App):
    CSS_PATH = CSS_FILES

    def __init__(self) -> None:
        super().__init__()
        for theme in SERVONAUT_THEMES:
            self.register_theme(theme)
        self.theme = "servonaut"
        self.animation_level = "none"
        self.demo_mode = False
        self.redaction_service = None
        self.instances = [dict(ROW)]
        self.command_history = _History()
        self.config_manager = SimpleNamespace(
            get=Mock(return_value=AppConfig()),
            save=Mock(side_effect=lambda *a, **kw: _refuse("config save")),
            update=Mock(side_effect=lambda *a, **kw: _refuse("config update")),
        )
        self.connection_service = create_autospec(ConnectionService, instance=True)
        for name, value in {"resolve_profile": None, "get_target_host": "192.0.2.10",
                            "get_proxy_args": [], "get_extra_options": [], "get_target_port": 2222}.items():
            getattr(self.connection_service, name).return_value = value
        self.ssh_service = create_autospec(SSHService, instance=True)
        self.ssh_service.get_key_path.side_effect = lambda *a, **kw: _refuse("key discovery")
        self.ssh_service.discover_key.side_effect = lambda *a, **kw: _refuse("key discovery")
        self.ssh_service.build_ssh_command.side_effect = lambda **kw: ["fixture-ssh", kw["remote_command"]]
        self.vault_command_service = None
        self.vault_lease_cache = None

    def compose(self) -> ComposeResult:
        yield Input(id="origin")

    def connection_instance(self, instance: dict) -> dict:
        assert instance == ROW
        return dict(ROW)


@pytest.fixture(autouse=True)
def _inert_boundaries(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Runner]:
    _TRIPS.clear()
    for name in ("NO_COLOR", "FORCE_COLOR", "TEXTUAL_THEME"):
        monkeypatch.delenv(name, raising=False)
    runner = _Runner()
    monkeypatch.setattr("servonaut.config.manager.load_secrets_env", lambda: None)
    monkeypatch.setattr("servonaut.screens.command_overlay.SshLog", lambda: _Log(runner))
    monkeypatch.setattr("servonaut.screens.command_overlay.background_process_kwargs", lambda: {})
    monkeypatch.setattr("servonaut.screens.command_overlay.track_background_process", lambda process: None)
    monkeypatch.setattr("servonaut.screens.command_overlay.subprocess.Popen", runner.popen)
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: _refuse("subprocess run"))
    monkeypatch.setattr("asyncio.create_subprocess_exec", AsyncMock(side_effect=lambda *a, **kw: _refuse("async process")))
    monkeypatch.setattr("socket.create_connection", lambda *a, **kw: _refuse("network"))
    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", AsyncMock(side_effect=lambda *a, **kw: _refuse("network")))
    monkeypatch.setattr("webbrowser.open", lambda *a, **kw: _refuse("browser"))
    for name in ("get_password", "set_password", "delete_password"):
        monkeypatch.setattr("keyring." + name, lambda *a, **kw: _refuse("keyring"))
    resolved = {"host": "192.0.2.10", "username": "operator", "key_path": None,
                "proxy_args": [], "extra_options": [], "port": 2222, "profile": None}
    monkeypatch.setattr("servonaut.services.ssh_credentials.resolve_with_vault", AsyncMock(return_value=resolved))
    yield runner
    for run in runner.runs:
        run.release.set()
    assert not _TRIPS


async def _open(app: _Host, pilot: Pilot) -> CommandOverlay:
    overlay = CommandOverlay(dict(ROW))
    await app.push_screen(overlay)
    field = overlay.query_one("#command_input", Input)
    await wait_until(lambda: app.focused is field)
    await pilot.pause()
    return overlay


def _controls(app: _Host, overlay: CommandOverlay) -> tuple:
    container = overlay.query_one("#command_overlay_container", Container)
    context = overlay.query_one("#command_context", VerticalScroll)
    tools = overlay.query_one("#command_tools", Container)
    composer = overlay.query_one("#command_composer", Vertical)
    field = overlay.query_one("#command_input", Input)
    header = overlay.query_one("#command_header", Static)
    output = overlay.query_one(CommandOutput)
    hints = overlay.query_one("#command_hints", Static)
    label = overlay.query_one("#command_input_label")
    # Pin the declared percentages independently of the measured box.
    expected_width, expected_height = app.size.width * 94 // 100, app.size.height * 9 // 10
    assert tuple(container.region.size) == (expected_width, expected_height)
    assert container.region.x == (app.size.width - expected_width) // 2
    assert container.region.y == (app.size.height - expected_height) // 2
    assert overlay.region.contains_region(container.region)
    assert context.parent is tools.parent is output.parent is composer.parent is container
    assert header.parent is context
    assert field.parent is hints.parent is label.parent is composer
    for widget in (context, tools, output, composer):
        assert container.content_region.contains_region(widget.region)
    assert context.content_region.contains_region(header.region)
    for widget in (label, field, hints):
        assert composer.content_region.contains_region(widget.region)
    assert container.region.contains_region(field.region)
    for row in range(field.region.y, field.region.bottom):
        assert app.get_widget_at(field.region.center[0], row)[0] is field
    assert header.region.bottom <= output.region.y
    assert output.region.bottom <= label.region.y
    assert label.region.bottom <= field.region.y
    assert field.region.bottom <= hints.region.y
    buttons = list(tools.query(Button))
    assert [button.id for button in buttons] == [
        "command_pick", "command_save", "command_select", "command_copy",
        "command_stop", "command_close",
    ]
    for button in buttons:
        assert button.parent is tools
        assert tools.content_region.contains_region(button.region)
        assert overlay.region.contains_region(button.region)
        assert_button_label_painted(app, button)
    assert "web-1" in _painted(app, header)
    for key in ("Ctrl+R", "Ctrl+S", "Ctrl+C", "Esc"):
        assert key in _painted(app, hints)
    _assert_readable(_painted_text_styles(header, "web-1"), context="Console server heading")
    return field.region, header.region, hints.region


async def _submit(overlay: CommandOverlay, pilot: Pilot, command: str) -> None:
    field = overlay.query_one("#command_input", Input)
    field.focus()
    await wait_until(lambda: overlay.app.focused is field)
    field.value = command
    await pilot.press("enter")


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", SIZES)
async def test_console_native_geometry_tail_history_copy_stop_and_close(theme: str, size: tuple[int, int], _inert_boundaries: _Runner, clipboard: _Clipboard) -> None:
    runner = _inert_boundaries
    app = _Host()
    app.theme = theme
    async with app.run_test(size=size) as pilot:
        origin = app.query_one("#origin", Input)
        overlay = await _open(app, pilot)
        positions = _controls(app, overlay)
        run = runner.next_run = _Run(lines=tuple(f"line {index}" for index in range(120)) + (" café [literal] Ω ",))
        await _submit(overlay, pilot, COMMAND)
        await wait_until(lambda: run.closed)
        output = overlay.query_one(CommandOutput)
        await wait_until(lambda: output.max_scroll_y > 0 and output.scroll_y == output.max_scroll_y)
        assert _controls(app, overlay) == positions
        assert "café [literal] Ω" in _painted(app, output)
        assert overlay._history[-1] == COMMAND and app.command_history.added == [(ROW["id"], COMMAND)]
        field = overlay.query_one("#command_input", Input)
        await pilot.press("up")
        assert field.value == COMMAND
        await pilot.press("up")
        assert field.value == "printf older"
        await pilot.press("down", "down")
        assert field.value == ""
        output.focus()
        await wait_until(lambda: app.focused is output)
        await pilot.press("y")
        expected = "\n".join(overlay._output_lines)
        assert clipboard.calls == [expected] and expected.endswith(" café [literal] Ω ")
        assert runner.argv == [["fixture-ssh", f"bash -ic {shlex.quote(COMMAND)}"]]
        app.ssh_service.build_ssh_command.assert_called_once_with(
            host="192.0.2.10", username="operator", key_path=None,
            remote_command=f"bash -ic {shlex.quote(COMMAND)}", proxy_args=[], port=2222,
            extra_options=[],
        )
        held = runner.next_run = _Run(lines=(), held=True)
        await _submit(overlay, pilot, "printf held")
        await wait_until(lambda: overlay._running_process is not None)
        process = runner.processes[-1]
        # Input owns native Ctrl+C copy; the console Stop binding is exercised from output.
        output.focus()
        await wait_until(lambda: app.focused is output)
        await pilot.press("ctrl+c")
        await wait_until(lambda: held.closed and overlay._running_process is None)
        assert process.terminated == 1 and app.screen is overlay
        assert _controls(app, overlay) == positions
        await pilot.press("escape")
        await wait_until(lambda: app.screen is not overlay)
        assert app.focused is origin and app._exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("native_writer", [False, True])
async def test_console_copy_keeps_exact_payload_and_input_printable_keys(native_writer: bool, _inert_boundaries: _Runner, clipboard: _Clipboard) -> None:
    clipboard.succeeds = native_writer
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        overlay = await _open(app, pilot)
        await pilot.press("y", "v")
        assert overlay.query_one("#command_input", Input).value == "yv"
        assert clipboard.calls == []
        output = overlay.query_one(CommandOutput)
        output.focus()
        await wait_until(lambda: app.focused is output)
        expected = "\n".join(overlay._output_lines)
        await pilot.press("y")
        assert clipboard.calls == [expected]
        if not native_writer:
            assert app.clipboard == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["picker", "save"])
async def test_console_picker_fills_without_running_and_save_uses_trimmed_name(route: str, _inert_boundaries: _Runner) -> None:
    runner = _inert_boundaries
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        overlay = await _open(app, pilot)
        field = overlay.query_one("#command_input", Input)
        if route == "picker":
            await pilot.press("ctrl+r")
            await wait_until(lambda: isinstance(app.screen, CommandPickerModal))
            await pilot.press("enter")
            await wait_until(lambda: app.screen is overlay)
            assert field.value == COMMAND and field.cursor_position == len(COMMAND)
            assert app.focused is field and runner.argv == []
        else:
            field.value = "  " + COMMAND + "  "
            await pilot.press("ctrl+s")
            await wait_until(lambda: isinstance(app.screen, SaveCommandModal))
            app.screen.query_one("#save_name_input", Input).value = "  Example  "
            await pilot.press("enter")
            await wait_until(lambda: app.screen is overlay)
            assert app.command_history.saved == [("Example", COMMAND)]
            assert app.focused is field and runner.argv == []


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["spawn", "ssh"])
async def test_console_loading_and_terminal_failure_stay_literal_and_input_usable(failure: str, _inert_boundaries: _Runner) -> None:
    runner = _inert_boundaries
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        overlay = await _open(app, pilot)
        positions = _controls(app, overlay)
        field = overlay.query_one("#command_input", Input)
        output = overlay.query_one(CommandOutput)
        run = runner.next_run = (_Run(failure=OSError("Connection refused")) if failure == "spawn"
                                else _Run(lines=(), stderr="operator@192.0.2.10: Permission denied (publickey).\n", code=255, held=True))
        await _submit(overlay, pilot, "printf failure")
        if failure == "ssh":
            await wait_until(lambda: overlay._running_process is not None)
            await wait_until(lambda: "Connecting..." in _painted(app, output))
            assert not run.closed and overlay._running_process.returncode is None
            assert app.focused is field and not field.disabled
            await pilot.press("p", "w", "d")
            await wait_until(lambda: field.value == "pwd")
            assert _controls(app, overlay) == positions
            assert len(runner.argv) == 1
            run.release.set()
        await wait_until(lambda: run.closed)
        expected = "Connection refused. Check if instance is accessible." if failure == "spawn" else "Permission denied (publickey)."
        assert any(expected in line for line in overlay._output_lines)
        await wait_until(lambda: expected in _painted(app, output))
        assert overlay._running_process is None and app.screen is overlay
        assert app.focused is field and not field.disabled
        assert field.value == ("pwd" if failure == "ssh" else "")
        assert _controls(app, overlay) == positions
        assert len(runner.argv) == 1
        assert app._exception is None


@pytest.mark.asyncio
async def test_console_escape_stops_process_and_late_worker_does_not_reopen_modal(_inert_boundaries: _Runner) -> None:
    runner = _inert_boundaries
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        overlay = await _open(app, pilot)
        run = runner.next_run = _Run(lines=(), held=True, late=True)
        await _submit(overlay, pilot, "printf late")
        await wait_until(lambda: overlay._running_process is not None)
        process = runner.processes[-1]
        await pilot.press("escape")
        await wait_until(lambda: app.screen is not overlay and not overlay.is_attached)
        assert process.terminated == 1
        run.release.set()
        await wait_until(lambda: run.closed)
        assert app.screen is not overlay and not overlay.is_attached
        assert app.focused is app.query_one("#origin") and app._exception is None
        assert len(runner.argv) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", SIZES)
async def test_console_notification_never_obscures_input_after_original_qualification(theme: str, size: tuple[int, int]) -> None:
    key = (theme, size)
    assert ORIGINAL_NOTICE_INPUT_EXPOSED is not None and key in ORIGINAL_NOTICE_INPUT_EXPOSED, "Qualify original native Toast/input geometry first"
    # Reference overlap was measured; current controls must remain exposed.
    assert isinstance(ORIGINAL_NOTICE_INPUT_EXPOSED[key], bool), "Qualify original notification geometry as boolean data"
    app = _Host()
    app.theme = theme
    async with app.run_test(size=size, notifications=True) as pilot:
        overlay = await _open(app, pilot)
        positions = _controls(app, overlay)
        overlay.notify("Fixture command information", title="Command", timeout=30)
        await wait_until(lambda: bool(app.screen.query(Toast)))
        assert _controls(app, overlay) == positions


@pytest.mark.asyncio
async def test_console_input_ctrl_c_matches_qualified_original_native_routing(_inert_boundaries: _Runner) -> None:
    assert ORIGINAL_INPUT_CTRL_C is not None, "Qualify original Input Ctrl+C copy/stop behavior; no key policy change here"
    runner = _inert_boundaries
    app = _Host()
    async with app.run_test(size=(100, 30)) as pilot:
        overlay = await _open(app, pilot)
        run = runner.next_run = _Run(lines=(), held=True)
        await _submit(overlay, pilot, "printf held")
        await wait_until(lambda: overlay._running_process is not None)
        field = overlay.query_one("#command_input", Input)
        field.value = "native input selection"
        await pilot.press("ctrl+shift+a", "ctrl+c")
        await pilot.pause()
        actual = (bool(runner.processes[-1].terminated), app.clipboard == field.value)
        assert actual == ORIGINAL_INPUT_CTRL_C
        run.release.set()
        await wait_until(lambda: run.closed)


@pytest.mark.asyncio
@pytest.mark.parametrize("theme", ["servonaut", "ansi-light"])
async def test_console_tokens_do_not_restyle_foreign_header_or_richlog(theme: str) -> None:
    class _ForeignHost(_Host):
        def compose(self) -> ComposeResult:
            yield Static("Unrelated heading", id="command_header")
            yield RichLog(id="ordinary_output")

    app = _ForeignHost()
    app.theme = theme
    async with app.run_test(size=(100, 30)) as pilot:
        header = app.query_one("#command_header", Static)
        log = app.query_one("#ordinary_output", RichLog)
        log.write("Unrelated output")
        await pilot.pause()
        # Textual normalizes absent/none border edges to the empty type string.
        assert header.region.height == 1 and header.styles.border_bottom[0] == ""
        assert all(value == 0 for value in header.styles.padding)
        assert log.styles.border_top[0] == ""
        assert "Unrelated output" in _painted(app, log)
