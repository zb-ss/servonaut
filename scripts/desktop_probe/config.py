"""Configuration for the opt-in renderer probe."""

import json
import math
import os
from dataclasses import dataclass
from pathlib import Path

TIME_SCALE_ENV = "SERVONAUT_PROBE_TIME_SCALE"
# Enough for the slowest supported runner; a larger value is a typo, and an
# unbounded one could turn budgets into infinities that asyncio rejects.
MAX_TIME_SCALE = 10.0
# Wall-clock budgets that grow with a slow runner. Poll and stream intervals
# are behaviour, not budgets, and stay fixed.
_SCALED_BUDGETS = ("startup_seconds", "shutdown_seconds")


@dataclass(frozen=True)
class ProbeConfig:
    startup_seconds: float
    shutdown_seconds: float
    probe_poll_seconds: float
    max_packet_bytes: int
    max_message_bytes: int
    max_diagnostic_entries: int
    max_columns: int
    max_rows: int
    width: int
    height: int
    font_size: int
    stream_update_interval_seconds: float
    stream_update_count: int
    textual_serve_version: str
    renderer_sha256: str


def time_scale() -> float:
    """Return the runner's wall-clock budget multiplier (default 1).

    A slow CI runner sets ``SERVONAUT_PROBE_TIME_SCALE`` so that startup and
    shutdown budgets grow with the machine instead of being tuned to the
    fastest host. It can only lengthen the reviewed defaults, never shorten
    them, is capped at ``MAX_TIME_SCALE``, and an invalid value is an error
    rather than silently ignored.
    """
    raw = os.environ.get(TIME_SCALE_ENV, "").strip()
    if not raw:
        return 1.0
    message = f"{TIME_SCALE_ENV} must be a number from 1 to {MAX_TIME_SCALE:g}"
    try:
        scale = float(raw)
    except ValueError:
        raise ValueError(message) from None
    if not math.isfinite(scale) or not 1 <= scale <= MAX_TIME_SCALE:
        raise ValueError(message)
    return scale


def scaled_seconds(seconds: float) -> float:
    """Scale a wall-clock budget by the runner's multiplier."""
    return _finite_budget(seconds * time_scale())


def _finite_budget(seconds: float) -> float:
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError(f"Probe budget must be finite and positive, got {seconds!r}")
    return seconds


def load_config() -> ProbeConfig:
    """Load reviewed defaults, not values from the user's application config.

    Only the runner's budget multiplier is applied on top of them.
    """
    values = json.loads(Path(__file__).with_name("settings.json").read_text())
    scale = time_scale()
    for name in _SCALED_BUDGETS:
        values[name] = _finite_budget(values[name] * scale)
    return ProbeConfig(**values)
