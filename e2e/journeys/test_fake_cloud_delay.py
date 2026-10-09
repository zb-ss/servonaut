"""FakeCloud can answer slowly, so a walk through the app shows what users see while it waits."""
from __future__ import annotations

import time
from typing import Any

import httpx
import pytest

pytestmark = [pytest.mark.e2e_pr]


def test_slow_down_holds_every_api_answer_and_reset_ends_it(fake_cloud: Any) -> None:
    fake_cloud.slow_down(0.3)
    with httpx.Client(base_url=fake_cloud.url, verify=False, timeout=10) as client:
        started = time.monotonic()
        answer = client.post("/api/oauth/device", json={"client_id": "servonaut-cli"})
        assert answer.status_code == 200
        assert time.monotonic() - started >= 0.3

    with pytest.raises(ValueError):
        fake_cloud.slow_down(-1)

    fake_cloud.reset()
    assert fake_cloud.api_delay_seconds == 0.0


def test_the_sandbox_takes_the_delay_in_seconds() -> None:
    from e2e.sandbox import cli

    parser = cli._parser()
    assert parser.parse_args(["up", "--api-delay", "1.5"]).api_delay == 1.5
    assert parser.parse_args(["up"]).api_delay == 0.0
    for bad in ("-1", "31", "soon"):
        with pytest.raises(SystemExit):
            parser.parse_args(["up", "--api-delay", bad])
