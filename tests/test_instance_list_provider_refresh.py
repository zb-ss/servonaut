"""The fleet table refreshes every provider and reports AWS changes truthfully."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from servonaut.screens.instance_list import InstanceListScreen

AWS_ROW = {"id": "i-1", "name": "app-1", "state": "running"}
CUSTOM_ROW = {"id": "custom-1", "name": "edge-1", "is_custom": True}
OVH_ROW = {"id": "vps-1", "name": "mail-1", "is_ovh": True}
HETZNER_ROW = {"id": "7", "name": "cache-1", "is_hetzner": True}


def _app(*, aws_fresh: bool, hetzner_fresh: bool = False, ovh_fresh: bool = True):
    app = MagicMock()
    app.demo_mode = False
    app.redaction_service = None
    app.instances = [dict(AWS_ROW)]
    app.cache_service.is_fresh.return_value = aws_fresh
    app.ovh_service.is_cache_fresh.return_value = ovh_fresh
    app.hetzner_service.is_cache_fresh.return_value = hetzner_fresh
    app.aws_service.last_fetch_error = None
    return app


def _screen(app) -> tuple[InstanceListScreen, list[str]]:
    """A screen whose widgets are stubs; returns it with the started worker names."""
    screen = InstanceListScreen()
    started: list[str] = []

    def run_worker(work, *, name="", **_kwargs):
        if hasattr(work, "close"):
            work.close()
        started.append(name)

    screen.run_worker = run_worker
    screen.query_one = MagicMock()
    screen._update_table = MagicMock()
    screen._update_status_bar = MagicMock()
    return screen, started


def _with_app(app):
    return patch.object(InstanceListScreen, "app", new=property(lambda self: app))


def test_fresh_aws_cache_still_loads_an_expired_hetzner_cache():
    app = _app(aws_fresh=True, hetzner_fresh=False)
    screen, started = _screen(app)
    with _with_app(app):
        screen.on_mount()
    assert "hetzner_refresh" in started
    assert "fetch_instances" not in started and "background_refresh" not in started


def test_fresh_aws_and_hetzner_caches_fetch_nothing():
    app = _app(aws_fresh=True, hetzner_fresh=True)
    screen, started = _screen(app)
    with _with_app(app):
        screen.on_mount()
    assert started == []


def test_refresh_key_refreshes_every_provider():
    app = _app(aws_fresh=True)
    screen, started = _screen(app)
    with _with_app(app):
        screen.action_refresh()
    assert started == ["fetch_instances", "ovh_refresh", "hetzner_refresh"]
    app.aws_service.fetch_instances_cached.assert_called_once_with(force_refresh=True)


def test_refresh_key_skips_providers_that_are_not_configured():
    app = _app(aws_fresh=True)
    app.ovh_service = None
    app.hetzner_service = None
    screen, started = _screen(app)
    with _with_app(app):
        screen.action_refresh()
    assert started == ["fetch_instances"]


def _finish_background_refresh(screen, app, aws_rows):
    worker = SimpleNamespace(
        name="background_refresh", is_finished=True, error=None, result=aws_rows,
    )
    with _with_app(app):
        screen.on_worker_state_changed(SimpleNamespace(worker=worker))
    messages = [c.args[0] for c in app.notify.call_args_list]
    assert len(messages) == 1, messages
    return messages[0]


@pytest.mark.parametrize(
    "aws_rows, expected",
    [
        ([AWS_ROW], "Refreshed: 1 instances (up to date)"),
        ([AWS_ROW, {"id": "i-2", "name": "app-2"}], "Refreshed: 2 instances (1 more)"),
    ],
)
def test_refresh_toast_counts_aws_rows_only(aws_rows, expected):
    app = _app(aws_fresh=False)
    app.custom_server_service.list_as_instances.return_value = [CUSTOM_ROW]
    app.ovh_service.get_cached_instances.return_value = [OVH_ROW]
    app.hetzner_service.get_cached_instances.return_value = [HETZNER_ROW]
    screen, _ = _screen(app)
    screen._instances = [AWS_ROW, CUSTOM_ROW, OVH_ROW, HETZNER_ROW]

    assert _finish_background_refresh(screen, app, [dict(r) for r in aws_rows]) == expected
    assert len(screen._instances) == len(aws_rows) + 3


def test_refresh_toast_reports_a_removed_aws_instance():
    app = _app(aws_fresh=False)
    app.custom_server_service.list_as_instances.return_value = [CUSTOM_ROW]
    app.ovh_service.get_cached_instances.return_value = []
    app.hetzner_service.get_cached_instances.return_value = []
    screen, _ = _screen(app)
    screen._instances = [AWS_ROW, {"id": "i-2", "name": "app-2"}, CUSTOM_ROW]

    message = _finish_background_refresh(screen, app, [dict(AWS_ROW)])
    assert message == "Refreshed: 1 instances (1 fewer)"
