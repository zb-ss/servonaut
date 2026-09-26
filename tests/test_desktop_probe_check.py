"""The explicit desktop check must never pass because checks were skipped."""

import math
from pathlib import Path
from types import SimpleNamespace

import pytest
from textual.widgets import Button, Input

from scripts.desktop_probe.check import Results
from scripts.desktop_probe.child import ProbeApp, ProbeStreamScreen
from scripts.desktop_probe.config import (
    MAX_TIME_SCALE,
    TIME_SCALE_ENV,
    load_config,
    scaled_seconds,
)
from scripts.desktop_probe.diagnostics import PREFIX, exception_record, parse_record
from scripts.desktop_probe.renderer import WEBGL_REGISTRATION, canvas_renderer
from servonaut.screens.confirm_action import ConfirmActionScreen
from servonaut.widgets.command_output import CommandOutput


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
        await pilot.pause()
        assert not confirm.disabled


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
