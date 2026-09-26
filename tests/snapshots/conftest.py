"""Fixtures for the screenshot tests.

Each test gets an empty home directory, a clean environment, a frozen wall
clock and the seeded state from ``_harness``. Nothing reaches the network:
the update check and the AWS fetch return fixed answers, and the OVH and
Hetzner services are stand-ins (see ``_harness.SnapshotApp``).

``screen_snapshot`` captures a screen and compares it with the stored SVG
(see ``_snapshot``).
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path
from typing import Callable, Iterator, Tuple

import pytest
import time_machine
from textual.app import App

from .. import _home_isolation
from . import _harness, _snapshot

# Variables that change what a screen shows (credentials that make a panel
# report "configured", editors, SSH agents, colour switches). Prefixes cover
# whole families.
_CLEARED_VARIABLES = (
    "NO_COLOR",
    "FORCE_COLOR",
    "HCLOUD_TOKEN",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "EDITOR",
    "VISUAL",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "ABUSEIPDB_API_KEY",
)
_CLEARED_PREFIXES = ("SERVONAUT_", "AWS_", "OVH_", "OLLAMA_")

# Per-user data directories the suite points inside its throwaway home.
_XDG_VARIABLES = ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME")


@pytest.fixture
def empty_home() -> Iterator[Path]:
    """Swap the suite's throwaway home for an empty one for one test.

    Many servonaut modules bind their data paths to the home directory when
    they are imported, so the whole session shares one throwaway home (see
    ``tests/conftest.py``) and earlier tests may have left files in it. The
    directory is parked under a sibling name and an empty one takes its
    place, so every bound path starts empty; the original comes back after
    the test.
    """
    isolation = _home_isolation.current()
    home = isolation.temp_home
    real_home = isolation.real_home
    # Only ever move the suite's own throwaway directory.
    if Path(os.environ.get("HOME", "")).resolve() != home.resolve() or (
        real_home is not None and home.resolve() == real_home.resolve()
    ):
        pytest.fail("the test home is not the suite's throwaway home; refusing to swap it")
    parked = home.with_name(home.name + "-parked")
    home.rename(parked)
    try:
        home.mkdir()
        for name in _XDG_VARIABLES:
            directory = os.environ.get(name)
            if directory and Path(directory).is_relative_to(home):
                Path(directory).mkdir(parents=True, exist_ok=True)
        yield home
    finally:
        shutil.rmtree(home, ignore_errors=True)
        parked.rename(home)


@pytest.fixture
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove variables that would make a screen draw differently."""
    for name in list(os.environ):
        if name in _CLEARED_VARIABLES or name.startswith(_CLEARED_PREFIXES):
            monkeypatch.delenv(name, raising=False)


@pytest.fixture
def frozen_clock() -> Iterator[None]:
    """Freeze the wall clock at ``_harness.FROZEN_NOW``, in UTC.

    Only the wall clock stops: the monotonic clock that Textual's timers and
    asyncio use keeps running.
    """
    previous_tz = os.environ.get("TZ")
    os.environ["TZ"] = "UTC"
    if hasattr(time, "tzset"):
        time.tzset()
    try:
        with time_machine.travel(_harness.FROZEN_NOW, tick=False):
            yield
    finally:
        if previous_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = previous_tz
        if hasattr(time, "tzset"):
            time.tzset()


@pytest.fixture
def offline_services(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fixed answers for everything the app would fetch at start-up."""
    from servonaut.services.aws_service import AWSService
    from servonaut.services.update_service import UpdateService

    def no_update(_self: object) -> None:
        return None

    async def seeded_instances(_self: object, force_refresh: bool = False) -> list:
        del force_refresh
        return [dict(row) for row in _harness.AWS_ROWS]

    monkeypatch.setattr(UpdateService, "check_for_update", no_update)
    monkeypatch.setattr(AWSService, "fetch_instances_cached", seeded_instances)
    monkeypatch.setattr(
        "servonaut.widgets.sidebar.get_version", lambda: _harness.PINNED_VERSION
    )


@pytest.fixture
def snapshot_mode(request: pytest.FixtureRequest) -> _snapshot.Mode:
    """Update, strict or plain comparison; skips on a Textual version mismatch.

    Runs before ``clean_environment``, which removes the ``SERVONAUT_*``
    variables, so it can still read the strict-mode switch.
    """
    mode = _snapshot.current_mode(request.config)
    if mode.mismatch and not (mode.update or mode.strict):
        pytest.skip(mode.mismatch)
    return mode


@pytest.fixture(autouse=True)
def snapshot_state(
    snapshot_mode, empty_home, clean_environment, frozen_clock, offline_services
) -> None:
    """The seeded state every screenshot test starts from."""
    _harness.seed_home()


@pytest.fixture
def screen_snapshot(
    request: pytest.FixtureRequest, snapshot_mode: _snapshot.Mode
) -> Callable[[App, Tuple[int, int], _snapshot.Scenario], None]:
    """Capture *app* at a size after a scenario and check it against its snapshot."""

    def check(app: App, size: Tuple[int, int], scenario: _snapshot.Scenario) -> None:
        svg = _snapshot.capture_svg(app, size, scenario)
        _snapshot.check_snapshot(request.node, svg, snapshot_mode)

    return check
