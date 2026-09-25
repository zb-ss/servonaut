"""Mutable scenario state shared by the FakeCloud routes."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field, fields
from typing import Any, Optional

from e2e.harness.fake_cloud.session import ACCESS_TOKEN, REFRESH_TOKEN, TokenSession

__all__ = ["ACCESS_TOKEN", "REFRESH_TOKEN", "USER_CODE", "Scenario", "ScenarioStore"]

USER_CODE = "E2E-0001"

# Device-flow poll outcomes a scenario can script for /api/oauth/token.
TOKEN_OUTCOMES = frozenset({"pending", "slow_down", "expired", "denied", "success"})


@dataclass
class Scenario:
    """What FakeCloud answers. Tests change it through ``FakeCloud.configure``."""

    # Consumed one per /api/oauth/token call; once empty every poll succeeds.
    token_outcomes: list[str] = field(default_factory=list)
    device_interval: int = 1
    device_expires_in: int = 60
    plan: str = "solo"
    user_id: int = 4242
    premium_ai: bool = True
    # Relay listeners the plan allows (0 keeps the relay off).
    mcp_connections: int = 1
    quota: Optional[dict[str, Any]] = field(
        default_factory=lambda: {
            "tokens_used": 1200,
            "tokens_limit": 500000,
            "tokens_topup_remaining": 0,
            "resets_at": "2030-01-01T00:00:00+00:00",
            "soft_capped": False,
            "hard_capped": False,
            "rpm_limit": 30,
            "tokens_per_minute_limit": 60000,
        }
    )
    # Version the fake package index reports for servonaut.
    pypi_version: str = "0.0.0"


class ScenarioStore:
    """Thread-safe holder for the active :class:`Scenario`."""

    def __init__(self, default_pypi_version: str) -> None:
        self._lock = threading.Lock()
        self._default_pypi_version = default_pypi_version
        self._scenario = self._fresh()
        self._device_codes = 0
        self.session = TokenSession()

    def _fresh(self) -> Scenario:
        return Scenario(pypi_version=self._default_pypi_version)

    def reset(self) -> None:
        with self._lock:
            self._scenario = self._fresh()
            self._device_codes = 0
        self.session.reset()

    def configure(self, **changes: Any) -> None:
        known = {f.name for f in fields(Scenario)}
        unknown = set(changes) - known
        if unknown:
            raise KeyError(f"unknown FakeCloud scenario keys: {sorted(unknown)}")
        outcomes = changes.get("token_outcomes")
        if outcomes is not None and not set(outcomes) <= TOKEN_OUTCOMES:
            raise ValueError(f"token outcomes must be among {sorted(TOKEN_OUTCOMES)}")
        with self._lock:
            for key, value in changes.items():
                setattr(self._scenario, key, list(value) if key == "token_outcomes" else value)

    def snapshot(self) -> Scenario:
        with self._lock:
            current = self._scenario
            return Scenario(**{f.name: getattr(current, f.name) for f in fields(Scenario)})

    def next_token_outcome(self) -> str:
        with self._lock:
            if self._scenario.token_outcomes:
                return self._scenario.token_outcomes.pop(0)
            return "success"

    def next_device_code(self) -> str:
        with self._lock:
            self._device_codes += 1
            return f"dc-fake-{self._device_codes}"
