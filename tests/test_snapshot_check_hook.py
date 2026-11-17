"""Snapshot geometry checks run in the captured app and cannot hide behind a match."""

from types import SimpleNamespace

import pytest
from textual.app import App
from textual.widgets import Static

from tests.snapshots import _snapshot, conftest as snapshot_fixtures


class CheckApp(App):
    def compose(self):
        yield Static("A stable captured screen", id="body")


async def scenario(pilot):
    await pilot.pause()


@pytest.fixture
def matching_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr(_snapshot, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(_snapshot, "SNAPSHOT_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(_snapshot, "FAILURE_DIR", tmp_path / "failures")
    node = SimpleNamespace(path=tmp_path / "test_example.py", name="matching")
    mode = _snapshot.Mode(update=False, strict=True, mismatch=None)
    expected = _snapshot.capture_svg(CheckApp(), (50, 10), scenario)
    path = _snapshot.snapshot_path(node)
    path.parent.mkdir(parents=True)
    path.write_text(expected, encoding="utf-8")
    return snapshot_fixtures.screen_snapshot.__wrapped__(SimpleNamespace(node=node), mode)


def test_check_runs_once_inside_the_same_mounted_app(matching_snapshot):
    observed = []

    def check(pilot):
        assert pilot.app.is_running
        assert pilot.app.query_one("#body", Static).is_mounted
        observed.append(pilot.app)

    app = CheckApp()
    matching_snapshot(app, (50, 10), scenario, check=check)

    assert observed == [app]
    assert not app.is_running


def test_a_failing_check_fails_even_when_the_image_matches(matching_snapshot):
    matching_snapshot(CheckApp(), (50, 10), scenario)

    def check(pilot):
        assert pilot.app.query_one("#body", Static).is_mounted
        raise AssertionError("body exceeds viewport bounds")

    with pytest.raises(AssertionError, match="snapshot geometry check.*body exceeds viewport bounds"):
        matching_snapshot(CheckApp(), (50, 10), scenario, check=check)
