"""The explicit desktop check must never pass because checks were skipped."""

from types import SimpleNamespace

import pytest

from scripts.desktop_probe.check import Results


@pytest.mark.parametrize("outcome", ["failed", "skipped"])
def test_check_rejects_unsuccessful_test(outcome: str) -> None:
    results = Results()
    results.pytest_runtest_logreport(
        SimpleNamespace(
            when="call", failed=False, skipped=False, nodeid="example", outcome=outcome
        )
    )
    assert not results.is_success(0)


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
