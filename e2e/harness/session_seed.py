"""Seed a child home with a signed-in session and a relay-ready config.

:func:`seed_session` writes ``auth.json`` through the real ``AuthToken``
dataclass, holding the token pair FakeCloud currently accepts and the
entitlements it serves, so a journey can start signed in without running the
device flow. :func:`seed_relay_config` points a home's relay at FakeCloud.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional


def auth_file(home: Path) -> Path:
    return home / ".servonaut" / "auth.json"


def seed_session(home: Path, fake_cloud: Any, *, expires_in: float = 3600.0) -> Path:
    """Sign *home* in with FakeCloud's current session; return ``auth.json``."""
    from servonaut.services.auth_service import AuthToken

    access, refresh = fake_cloud.tokens()
    entitlements = fake_cloud.entitlements()
    now = time.time()
    token = AuthToken(
        access_token=access,
        refresh_token=refresh,
        expires_at=now + expires_in,
        plan=entitlements["plan"],
        email="",
        entitlements=entitlements,
        entitlements_fetched_at=now,
        user_id=entitlements["user_id"],
    )
    path = auth_file(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(token), indent=2), encoding="utf-8")
    path.chmod(0o600)
    return path


def read_session(home: Path) -> Optional[dict[str, Any]]:
    """The ``auth.json`` a home holds, or None when signed out."""
    path = auth_file(home)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def seed_relay_config(
    seeder: Any, *, heartbeat_interval: Optional[int] = None, **overrides: Any
) -> Any:
    """Save a config (through *seeder*, a ``HomeSeeder``) whose relay points at
    FakeCloud, optionally with a short heartbeat interval."""
    relay_config = seeder.build_config().relay
    if heartbeat_interval is not None:
        relay_config.heartbeat_interval = heartbeat_interval
    return seeder.config(relay=relay_config, **overrides)
