"""The release channel a user chose for a packaged desktop installation.

A packaged build is cut for one channel and records it in its build marker.
The user may follow the other one instead; that choice is kept in a small file
under the data root and read each time an update is checked, so switching
applies without a restart. No file means the build marker's channel.
"""

from __future__ import annotations

import json
import logging
import os
import stat
from pathlib import Path
from typing import Final, Literal

from servonaut.distribution import ReleaseChannel
from servonaut.utils.atomic_file import write_json_atomic

log = logging.getLogger(__name__)

Channel = Literal["stable", "rc"]
PREFERENCE_DIR: Final = "updates"
PREFERENCE_FILE: Final = "desktop-channel.json"
_MAX_BYTES: Final = 256
_CHANNELS: Final[dict[str, ReleaseChannel]] = {
    "stable": ReleaseChannel.STABLE,
    "rc": ReleaseChannel.PREVIEW,
}


def preference_path(data_root: Path) -> Path:
    return data_root / PREFERENCE_DIR / PREFERENCE_FILE


def release_channel_for(channel: Channel) -> ReleaseChannel:
    return _CHANNELS[channel]


def display_channel_for(channel: ReleaseChannel | str) -> Channel:
    """The UI name of a release channel (a preview is a release candidate)."""
    return "rc" if channel in (ReleaseChannel.PREVIEW, ReleaseChannel.PREVIEW.value) else "stable"


def read_channel_preference(data_root: Path) -> Channel | None:
    """Return the saved choice, or None when it is absent, unreadable or invalid."""
    path = preference_path(data_root)
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_BYTES:
            return None
        if hasattr(os, "geteuid") and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
            return None
        value = json.loads(path.read_bytes())
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        log.debug("Ignoring an unreadable update channel preference.")
        return None
    channel = value.get("channel") if isinstance(value, dict) and set(value) == {"channel"} else None
    return channel if channel in _CHANNELS else None


def write_channel_preference(data_root: Path, channel: str) -> bool:
    """Save the choice atomically with owner-only permissions; False when refused."""
    if channel not in _CHANNELS:
        return False
    path = preference_path(data_root)
    try:
        write_json_atomic(path, {"channel": channel})
    except OSError as exc:
        log.warning("Could not save the update channel (%s).", type(exc).__name__)
        return False
    return True
