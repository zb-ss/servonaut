"""A team's copy of a server's memory on disk, for journeys of the team-copy merge.

Before memory folded a team's shared server into the user's own row, the copy
was filed under its own folder. :func:`seed_team_copy` writes one with a note
for the share of the user's own ``app-1``; the team shares it as ``srv-2``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from e2e.harness import fleet

SHARE_ID = "srv-2"
SHARED_APP_1 = {
    "id": SHARE_ID, "name": "app-1-team", "hostname": "app-1.example.com", "port": 22,
    "instance_id": fleet.APP_1.instance_id, "status": "active",
}
TEAM_FOLDER = "team ops"
TEAM_NOTE = "Restart the worker after every deploy."
TEAM_DISTRO = "team-distro"


def memory_root(home: Path) -> Path:
    return home / ".servonaut" / "memory"


def seed_team_copy(home: Path, note: str = TEAM_NOTE, *, with_module: bool = True) -> Path:
    """Write the team's copy of app-1's memory (a note, and a probed module unless *with_module* is off) under *home*; returns its folder."""
    folder = memory_root(home) / TEAM_FOLDER / SHARE_ID
    folder.mkdir(parents=True)
    module = {
        "module": "os", "instance_id": SHARE_ID, "probed_at": "2026-10-01T00:00:00+00:00",
        "observed": {"distro": TEAM_DISTRO},
    }
    if with_module:
        (folder / "os.json").write_text(json.dumps(module), encoding="utf-8")
    (folder / "annotations.md").write_text(note, encoding="utf-8")
    return folder


def own_notes(home: Path) -> str:
    """The user's own app-1 notes as stored, or '' when none."""
    path = memory_root(home) / "aws" / fleet.APP_1.instance_id / "annotations.md"
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def marker(folder: Path) -> Any:
    """The merge marker in the copy's folder, or None."""
    path = folder / "team_merged.marker"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
