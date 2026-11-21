"""Paths and role names shared by Debian packaging and the running app."""

import os
import re
from pathlib import Path
from typing import Optional

INSTALL_ROOT = Path("/opt")
HELPER_ROOT = Path("/usr/libexec")
CONTROL_ROOT = Path("/run/servonaut-apt")
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]+")
ROLES = ("servonaut", "servonaut-desktop", "servonaut-desktop-child")
GENERATION = re.compile(r"[0-9a-f]{64}")
MARKER = "servonaut-runtime.json"
PAYLOAD = "payload"
GENERATIONS = "generations"
STATUS = "status.json"
LEASE = ".lease"
MAX_STATUS_BYTES = 8192
RESTART_GENERATION_ENV = "SERVONAUT_APT_RESTART_GENERATION"
APT_LEASE_WAIT_ENV = "SERVONAUT_APT_LEASE_WAIT_SECONDS"
# Maintenance holds an exclusive lease only for one procfs scan and retirement.
_DEFAULT_SHARED_LEASE_WAIT_SECONDS = 0.5
_SHARED_LEASE_POLL_SECONDS = 0.005


def invocation_role(path: Path, root: Path, helper: Path) -> Optional[str]:
    """Find the stable role in the invoked symlink chain."""
    visited = set()
    while True:
        path = Path(os.path.abspath(path))
        if path in visited:
            return None
        visited.add(path)
        if path.name in ROLES and path.parent.resolve() == root:
            return path.name if path.resolve() == helper else None
        if not path.is_symlink():
            return None
        target = path.readlink()
        path = target if target.is_absolute() else path.parent / target


def acquire_shared_lease(descriptor: int) -> bool:
    """Let a retiring generation settle without blocking on a user's lock."""
    import fcntl
    import math
    import time

    try:
        wait = float(os.environ.get(APT_LEASE_WAIT_ENV, ""))
    except ValueError:
        wait = _DEFAULT_SHARED_LEASE_WAIT_SECONDS
    if not math.isfinite(wait):
        wait = _DEFAULT_SHARED_LEASE_WAIT_SECONDS
    deadline = time.monotonic() + max(0.05, min(wait, 2.0))
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(remaining, _SHARED_LEASE_POLL_SECONDS))
