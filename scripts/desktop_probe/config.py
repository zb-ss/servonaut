"""Configuration for the opt-in renderer probe."""

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProbeConfig:
    startup_seconds: float
    shutdown_seconds: float
    probe_poll_seconds: float
    max_packet_bytes: int
    max_message_bytes: int
    max_columns: int
    max_rows: int
    width: int
    height: int
    font_size: int
    textual_serve_version: str
    renderer_sha256: str


def load_config() -> ProbeConfig:
    """Load reviewed defaults, not values from the user's application config."""
    return ProbeConfig(
        **json.loads(Path(__file__).with_name("settings.json").read_text())
    )
