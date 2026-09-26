"""Self-test for the child-process harness in ``tests/_hermetic_app.py``.

The boot tests assert that the harness recorded *nothing*. That is only
meaningful if the harness would record something when it should, so these
checks make the guard observe a real violation.
"""
from __future__ import annotations

from tests._hermetic_app import _CHILD_TIMEOUT_SECONDS, run_hermetic_app


def test_child_timeout_stays_below_the_pytest_timeout(pytestconfig):
    """A hung child must fail with its own output, not a bare pytest timeout."""
    assert _CHILD_TIMEOUT_SECONDS < float(pytestconfig.getini("timeout"))


def test_guard_records_access_to_the_guarded_home(tmp_path):
    guarded = tmp_path / "guarded-home"
    secret = guarded / ".servonaut" / "config.json"
    secret.parent.mkdir(parents=True)
    secret.write_text("{}", encoding="utf-8")

    report = run_hermetic_app(
        tmp_path, "probe-guard", str(secret), guarded_home=guarded
    )

    assert report["error"] is None, report["error"]
    assert ["open", str(secret)] in report["home_accesses"]


def test_guard_refuses_and_records_remote_network(tmp_path):
    report = run_hermetic_app(
        tmp_path, "probe-guard", str(tmp_path / "absent"), guarded_home=tmp_path / "guarded"
    )

    assert report["error"] is None, report["error"]
    assert report["result"] == {"network_blocked": True}
    assert ["socket.getaddrinfo", "'example.com'"] in report["network_attempts"]
