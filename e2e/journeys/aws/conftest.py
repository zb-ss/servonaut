"""Fixtures for the AWS journeys: CloudTrail, CloudWatch filters, MCP homes.

The local AWS endpoint itself (``moto``) comes from ``e2e/conftest.py``.
"""

from __future__ import annotations

import itertools
from typing import Any, Callable

import pytest

from e2e.harness import fleet
from e2e.harness.bootstrap import Sandbox
from e2e.harness.seed import HomeSeeder


@pytest.fixture(scope="session")
def _cloudtrail_server() -> Any:
    from e2e.harness.cloudtrail_stub import CloudTrailStub

    server = CloudTrailStub().start()
    yield server
    server.stop()


@pytest.fixture
def cloudtrail(_cloudtrail_server: Any, moto: Any, journey: Any, monkeypatch: Any) -> Any:
    """The local CloudTrail endpoint, emptied; every other AWS service stays on moto."""
    _cloudtrail_server.reset()
    monkeypatch.setenv("AWS_ENDPOINT_URL_CLOUDTRAIL", _cloudtrail_server.url)
    journey.env_overrides["AWS_ENDPOINT_URL_CLOUDTRAIL"] = _cloudtrail_server.url
    return _cloudtrail_server


@pytest.fixture
def cloudwatch(moto: Any, monkeypatch: Any) -> Any:
    """``moto`` with CloudWatch Logs filter patterns evaluated as AWS does."""
    from e2e.harness import aws_logs_filter

    aws_logs_filter.install(monkeypatch)
    return moto


@pytest.fixture
def mcp_home(journey: Any, fake_cloud: Any) -> Callable[..., Sandbox]:
    """Factory: a fresh child home whose config has the given overrides."""
    counter = itertools.count(1)

    def build(**overrides: Any) -> Sandbox:
        sandbox = journey.new_sandbox(f"mcp-aws-{next(counter)}")
        seeder = HomeSeeder(sandbox.home, api_url=fake_cloud.url)
        seeder.config(**overrides)
        seeder.cache(fleet.cache_rows(), fresh=True)
        return sandbox

    return build

