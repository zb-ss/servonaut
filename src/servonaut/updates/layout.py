"""Locate the pipx launcher and the immutable environment of a running session."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from servonaut.updates.state import InstallState
from servonaut.updates.status import locate_install

_GENERATION_ID = re.compile(r"[a-f0-9]{32}")


def generation_id(value: object) -> bool:
    return isinstance(value, str) and _GENERATION_ID.fullmatch(value) is not None


def python_for(root: Path) -> Path:
    return root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def console_for(root: Path) -> Path:
    return root / ("Scripts/servonaut.exe" if os.name == "nt" else "bin/servonaut")


@dataclass(frozen=True)
class UpdateLayout:
    store: InstallState
    generation: str | None = None

    @property
    def launcher(self) -> Path:
        return console_for(self.store.root)

    @classmethod
    def detect(cls, prefix: Path | None = None) -> UpdateLayout | None:
        resolved = locate_install(prefix)
        if resolved is None:
            return None
        anchor, generation = resolved
        return cls(InstallState(anchor), generation)
