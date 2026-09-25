"""Fixtures for the relay and account journeys (registered in ``e2e/conftest.py``).

``relay(sandbox)`` returns a :class:`~e2e.harness.processes.RelayProcess`
for ``servonaut connect`` in that sandbox; every one a journey creates is
closed when the journey ends, which stops any listener it left running.
``account_home(...)`` prepares a child home: a config pointing the relay at
FakeCloud, the neutral fleet, and optionally a signed-in session.
"""

from __future__ import annotations

import itertools
from typing import Any, Callable, Optional

import pytest

from e2e.harness import fleet
from e2e.harness.account import seed_relay_config, seed_session
from e2e.harness.bootstrap import Sandbox


@pytest.fixture
def relay(journey: Any, fake_cloud: Any, servonaut_cmd: list[str]) -> Any:
    """Factory: ``relay(sandbox)`` → a RelayProcess, closed at teardown."""
    from e2e.harness.processes import RelayProcess

    created: list[RelayProcess] = []
    counter = itertools.count(1)

    def make(sandbox: Sandbox) -> RelayProcess:
        process = RelayProcess(
            servonaut_cmd,
            home=sandbox.home,
            env=journey.child_env(sandbox),
            cwd=sandbox.base,
            sandbox_root=journey.ctx.root,
            armed_log=journey.armed_log,
            output_path=journey.directory / f"relay-{next(counter)}.out",
            log=journey.children,
        )
        created.append(process)
        return process

    yield make
    notes = [note for process in reversed(created) for note in process.close()]
    if notes:
        journey.children.append("relay cleanup: " + "; ".join(notes))


@pytest.fixture
def account_home(journey: Any, fake_cloud: Any) -> Callable[..., Sandbox]:
    """Factory: a child home with a relay-ready config, the fleet, a session."""
    from e2e.harness.seed import HomeSeeder

    def make(
        name: str = "account",
        *,
        signed_in: bool = True,
        heartbeat_interval: Optional[int] = None,
        **config: Any,
    ) -> Sandbox:
        sandbox = journey.new_sandbox(name)
        seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
        seed_relay_config(seeder, heartbeat_interval=heartbeat_interval, **config)
        seeder.cache(fleet.cache_rows(), fresh=True)
        if signed_in:
            seed_session(sandbox.home, fake_cloud)
        return sandbox

    return make
