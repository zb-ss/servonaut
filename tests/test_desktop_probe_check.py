"""The explicit desktop check must never pass because checks were skipped."""

import math
import signal
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from textual.widgets import Button, Input

from scripts.desktop_probe import check
from scripts.desktop_probe.check import Results
from scripts.desktop_probe.child import ProbeApp, ProbeStreamScreen
from scripts.desktop_probe.config import (
    MAX_TIME_SCALE,
    TIME_SCALE_ENV,
    load_config,
    scaled_seconds,
)
from scripts.desktop_probe.diagnostics import (
    PREFIX,
    exception_record,
    parse_record,
    sanitize_stderr_tail,
)
from scripts.desktop_probe.renderer import WEBGL_REGISTRATION, canvas_renderer
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.widgets.command_output import CommandOutput
from tests._async_bounds import wait_until


@pytest.mark.parametrize('system,native,renderer,include_glib', [
    ('Linux', True, None, True),
    ('Linux', True, 'gtk', True),
    ('Linux', False, 'gtk', False),
    ('Linux', True, 'edgechromium', False),
    ('Windows', True, None, False),
    ('Windows', True, 'gtk', False),
    ('Darwin', True, 'cocoa', False),
])
def test_check_selects_glib_only_for_a_native_linux_gtk_probe(
    monkeypatch, tmp_path, system, native, renderer, include_glib,
) -> None:
    from scripts.desktop_probe import check

    captured = []
    monkeypatch.setattr(check.platform, 'system', lambda: system)
    monkeypatch.setenv('PYTEST_ADDOPTS', '-k unrelated')

    def run(arguments, *, plugins):
        captured.extend(arguments)
        assert check.os.environ['PYTEST_ADDOPTS'] == ''
        return 0

    monkeypatch.setattr(pytest, 'main', run)
    args = SimpleNamespace(browser=None, native=native, renderer=renderer)
    assert check.run_tests(args, tmp_path, Results()) == 0
    node = 'tests/desktop/test_launcher.py::test_glib_takes_the_program_name'
    assert captured.count(node) == int(include_glib)
    assert ('tests/test_desktop_probe_native.py' in captured) is native
    assert check.os.environ['PYTEST_ADDOPTS'] == '-k unrelated'


@pytest.mark.parametrize("outcome", ["failed", "skipped"])
def test_check_rejects_unsuccessful_test(outcome: str) -> None:
    results = Results()
    results.pytest_runtest_logreport(
        SimpleNamespace(
            when="call", failed=False, skipped=False, nodeid="example", outcome=outcome
        )
    )
    assert not results.is_success(0)


def test_budget_multiplier_scales_only_wall_clock_budgets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(TIME_SCALE_ENV, raising=False)
    base = load_config()
    monkeypatch.setenv(TIME_SCALE_ENV, "2.5")
    scaled = load_config()
    assert scaled.startup_seconds == base.startup_seconds * 2.5
    assert scaled.shutdown_seconds == base.shutdown_seconds * 2.5
    assert scaled.probe_poll_seconds == base.probe_poll_seconds
    assert scaled.stream_update_interval_seconds == base.stream_update_interval_seconds
    assert scaled_seconds(2) == 5


@pytest.mark.parametrize(
    "value", ["0.5", "0", "-1", "nan", "inf", "-inf", "1e308", "10.5", "fast"]
)
def test_budget_multiplier_never_shortens_disables_or_overflows_budgets(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv(TIME_SCALE_ENV, value)
    with pytest.raises(ValueError, match=TIME_SCALE_ENV):
        load_config()
    with pytest.raises(ValueError, match=TIME_SCALE_ENV):
        scaled_seconds(1)


def test_largest_budget_multiplier_keeps_every_budget_finite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(TIME_SCALE_ENV, str(MAX_TIME_SCALE))
    config = load_config()
    for budget in (
        config.startup_seconds,
        config.shutdown_seconds,
        scaled_seconds(config.startup_seconds),
    ):
        assert math.isfinite(budget) and budget > 0


def test_check_requires_execution_and_zero_exit() -> None:
    results = Results()
    assert not results.is_success(0)
    results.tests["example"] = "passed"
    assert results.is_success(0)
    assert not results.is_success(1)


@pytest.mark.parametrize("failed,skipped", [(True, False), (False, True)])
def test_check_rejects_collection_failure_or_skip(failed: bool, skipped: bool) -> None:
    results = Results()
    results.tests["example"] = "passed"
    results.pytest_collectreport(SimpleNamespace(failed=failed, skipped=skipped))
    assert not results.is_success(0)


def test_check_keeps_teardown_failures_without_exception_details() -> None:
    results = Results()
    results.pytest_runtest_logreport(
        SimpleNamespace(
            when="call", failed=False, skipped=False, nodeid="example", outcome="passed"
        )
    )
    results.pytest_runtest_logreport(
        SimpleNamespace(
            when="teardown",
            failed=True,
            skipped=False,
            nodeid="example",
            outcome="failed",
            longrepr="auth.synthetic-credential",
        )
    )
    assert results.tests == {"example": "failed"}
    assert not results.is_success(0)
    assert "synthetic-credential" not in str(vars(results))


def test_failure_locations_omit_exception_values_and_absolute_paths() -> None:
    results = Results()
    try:
        raise ValueError("auth.synthetic-credential")
    except ValueError as error:
        info = pytest.ExceptionInfo.from_exception(error)
    results.pytest_exception_interact(
        SimpleNamespace(nodeid="example"), SimpleNamespace(excinfo=info), None
    )
    failure = results.failures["example"]
    assert failure["exception"] == "ValueError"
    assert failure["frames"][0]["file"] == Path(__file__).name
    assert "synthetic-credential" not in str(failure)
    assert str(Path(__file__).parent) not in str(failure)


def test_child_exception_diagnostic_omits_values() -> None:
    import json

    try:
        raise ValueError("auth.synthetic-credential")
    except ValueError as error:
        record = exception_record(error)
    assert record["exception"] == "ValueError"
    assert "synthetic-credential" not in str(record)
    assert str(Path(__file__).parent) not in str(record)
    assert parse_record((PREFIX + json.dumps(record)).encode()) == record


@pytest.mark.parametrize(
    "line",
    [
        b"unstructured stderr auth.synthetic-credential",
        PREFIX.encode() + b'{"exception":"ValueError","frames":[],"message":"private"}',
        PREFIX.encode()
        + b'{"exception":"ValueError","frames":[{"file":"/private/file.py","line":1}]}',
        PREFIX.encode() + b"null",
    ],
    ids=("unstructured", "unexpected-field", "absolute-path", "null"),
)
def test_child_diagnostics_reject_unexpected_fields_or_paths(line: bytes) -> None:
    assert parse_record(line) is None


def test_sanitize_stderr_tail_bounds_and_scrubs_credentials_urls_and_paths() -> None:
    raw_lines = [f"noise line {index}" for index in range(25)]
    raw_lines.extend([
        "WebView2 initialization failed: auth.synthetic-credential at http://127.0.0.1:41234/ws",
        "startServonaut(\"synthetic-credential\") token=synthetic-credential",
        "path C:\\Users\\runner\\AppData\\Local\\Temp\\wv2 and /home/runner/work/app/file.py",
        "x" * 300,
    ])
    tail = sanitize_stderr_tail("\n".join(raw_lines), max_lines=5, max_line_length=120)
    assert len(tail) == 5
    joined = "\n".join(tail)
    assert "WebView2 initialization failed" in joined
    assert "synthetic-credential" not in joined
    assert "127.0.0.1" not in joined
    assert "C:\\Users\\runner" not in joined
    assert "/home/runner/work" not in joined
    assert "auth.<redacted>" in joined
    assert "startServonaut(<redacted>)" in joined
    assert "<url>" in joined
    assert "<path>" in joined
    assert all(len(line) <= 120 for line in tail)


def test_check_records_native_stderr_only_on_failure() -> None:
    results = Results()
    results.pytest_runtest_logreport(
        SimpleNamespace(
            when="call",
            failed=False,
            skipped=False,
            nodeid="passing",
            outcome="passed",
            user_properties=[("native_stderr", ["benign warning"])],
        )
    )
    results.pytest_runtest_logreport(
        SimpleNamespace(
            when="call",
            failed=True,
            skipped=False,
            nodeid="failing",
            outcome="failed",
            user_properties=[
                ("native_stages", ["host-ready", "gui-starting", "window-shown"]),
                ("native_stderr", ["WebView2 initialization failed"]),
            ],
        )
    )
    assert "passing" not in results.failures
    assert results.failures["failing"]["native_stages"] == [
        "host-ready",
        "gui-starting",
        "window-shown",
    ]
    assert results.failures["failing"]["native_stderr"] == [
        "WebView2 initialization failed",
    ]


@pytest.mark.asyncio
async def test_probe_host_reports_first_root_request_once() -> None:
    aiohttp = pytest.importorskip("aiohttp")
    from scripts.desktop_probe.host import ProbeHost

    seen: list[str] = []
    host = ProbeHost(on_root_request=lambda: seen.append("root"))
    await host.start()
    try:
        async with aiohttp.ClientSession() as client:
            async with client.get(host.origin + "/style.css") as response:
                assert response.status == 200
            assert seen == []
            async with client.get(host.origin + "/") as response:
                assert response.status == 200
            async with client.get(host.origin + "/") as response:
                assert response.status == 200
            assert seen == ["root"]
    finally:
        await host.stop()


def test_canvas_adapter_changes_only_the_reviewed_registration() -> None:
    assert (
        canvas_renderer(b"before;" + WEBGL_REGISTRATION + b"after;") == b"before;after;"
    )
    for source in (b"unrecognized", WEBGL_REGISTRATION * 2):
        with pytest.raises(RuntimeError, match="registration changed"):
            canvas_renderer(source)


@pytest.mark.asyncio
async def test_probe_uses_the_real_confirmation_modal() -> None:
    app = ProbeApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        app.action_show_probe_modal()
        await pilot.pause()
        assert isinstance(app.screen, ConfirmActionScreen)
        prompt = app.screen.query_one("#confirm_input", Input)
        confirm = app.screen.query_one("#btn_confirm", Button)
        assert confirm.disabled
        prompt.value = "CONFIRM"
        # The input reports the change in a message that bubbles up to the
        # dialog after this call returns. A single pause does not always
        # outlast it: on Windows the clocks tick every 15.6 ms, and the
        # pause's idle check can end before the dialog has handled it.
        await wait_until(lambda: not confirm.disabled)


@pytest.mark.asyncio
async def test_probe_stream_uses_a_richlog_and_starts_updates() -> None:
    app = ProbeApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await pilot.pause()
        app.action_show_probe_stream()
        await pilot.pause()
        assert isinstance(app.screen, ProbeStreamScreen)
        assert app.screen.query_one("#probe_stream_output", CommandOutput)
        assert app.screen.query_one("#probe_paste_input", Input).has_focus
        await pilot.pause(delay=0.12)
        assert app.screen._stream_index > 0


def test_check_passes_a_scaled_timeout_and_the_recorded_timeout_method(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(TIME_SCALE_ENV, "3")
    arguments = check.pytest_arguments(["tests/example.py"])
    assert f"--timeout={60 * 3:g}" in arguments
    expected = "signal" if hasattr(signal, "SIGALRM") else "thread"
    assert arguments[arguments.index("-o") + 1] == f"timeout_method={expected}"
    assert arguments[-1] == "tests/example.py"


def test_check_uses_the_thread_timeout_method_without_sigalrm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(signal, "SIGALRM", raising=False)
    arguments = check.pytest_arguments([])
    assert "timeout_method=thread" in arguments


def _check_records_a_timed_out_test_as_a_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(check, "BASE_TEST_TIMEOUT_SECONDS", 0.5)
    probe = tmp_path / "test_slow_probe.py"
    probe.write_text(
        "import time\n\n\ndef test_slow():\n    time.sleep(10)\n\n\n"
        "def test_fast():\n    pass\n",
        encoding="utf-8",
    )
    results = Results()
    started = time.monotonic()
    exit_code = check.run_pytest([str(probe)], results)
    assert time.monotonic() - started < 8
    assert exit_code != 0
    assert not results.is_success(exit_code)
    slow = next(name for name in results.tests if name.endswith("::test_slow"))
    fast = next(name for name in results.tests if name.endswith("::test_fast"))
    assert results.tests[slow] == "failed"
    assert results.tests[fast] == "passed"
    assert slow in results.failures


# The desktop probe runs this file and fails on any skipped test, so on a
# platform without SIGALRM (Windows) this check is not defined at all rather
# than skipped. There the probe keeps the thread timeout method, which ends the
# process, so an in-process overrun cannot be observed.
if hasattr(signal, "SIGALRM"):
    test_check_records_a_timed_out_test_as_a_failure = (
        _check_records_a_timed_out_test_as_a_failure
    )
