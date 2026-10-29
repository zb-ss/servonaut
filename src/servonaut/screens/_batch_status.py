"""Keep batch failure notifications readable without losing the total."""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from servonaut.config.schema import AppConfig


def failure_details(app: Any, failures: Sequence[str]) -> list[str]:
    manager = getattr(app, "config_manager", None)
    config = manager.get() if manager is not None else AppConfig()
    limit = getattr(config, "batch_failure_detail_limit", None)
    if type(limit) is not int or limit < 0:
        limit = AppConfig().batch_failure_detail_limit
    messages = list(failures[:limit])
    if len(failures) > limit:
        messages.append(f"And {len(failures) - limit} more failure(s); see the log for details.")
    return messages
