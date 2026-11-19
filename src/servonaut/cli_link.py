"""Give the macOS desktop app a ``servonaut`` command, as the Linux package does.

The Linux package installs ``/usr/bin/servonaut``. The macOS app keeps its
command line inside the app bundle, so with only the app installed nothing
named ``servonaut`` exists outside it: agent entries and scripts that run
``servonaut`` (or ``~/.local/bin/servonaut``, where pipx puts it) fail, and
so does every ``servonaut ...`` command the documentation names.

The app links ``~/.local/bin/servonaut`` to its own command line when nothing
is there. A link it made earlier is updated when the app moves; a dangling
link runs nothing and is replaced. Anything else, such as pipx's link, a
hand-made script or another install, is left alone.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePath

from servonaut.runtime import (
    DistributionKind,
    RuntimeCapabilityError,
    RuntimeLayout,
    RuntimeMarkerError,
    validate_launch_argv,
)

logger = logging.getLogger(__name__)

COMMAND_NAME = "servonaut"


class CliLinkState(str, Enum):
    """What became of ``~/.local/bin/servonaut``."""

    CREATED = "created"
    # A link this app made earlier now points at its current location.
    UPDATED = "updated"
    UNCHANGED = "unchanged"
    # Something else holds the name; it is left as it is.
    OCCUPIED = "occupied"
    # The app runs from a location that will not last.
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True)
class CliLinkResult:
    path: Path
    state: CliLinkState
    # The app command line the link points at (or would point at).
    target: Path
    detail: str = ""
    # For OCCUPIED: what holds the name now, when it is a link.
    holder: str = ""


def cli_link_path() -> Path:
    """Where the command is linked: the directory pipx also uses."""
    return Path.home() / ".local" / "bin" / COMMAND_NAME


def ensure_cli_link(runtime: RuntimeLayout) -> CliLinkResult | None:
    """Make ``~/.local/bin/servonaut`` run the macOS app's command line.

    Returns:
        What happened, or None when the running install is not the macOS app.
    """
    from servonaut.utils.platform_utils import get_os

    if get_os() != "darwin":
        return None
    target = app_command(runtime)
    if target is None:
        return None
    link = cli_link_path()
    if _is_temporary_location(target):
        return CliLinkResult(
            link,
            CliLinkState.SKIPPED,
            target,
            "Servonaut runs from its disk image or a quarantined copy; move it to "
            "the Applications folder and start it again",
        )
    try:
        return _link(link, target)
    except OSError as exc:
        return CliLinkResult(link, CliLinkState.FAILED, target, str(exc))


def app_command(runtime: RuntimeLayout) -> Path | None:
    """The desktop app's own command line, or None for any other install."""
    if runtime.kind is not DistributionKind.PACKAGED_DESKTOP:
        return None
    try:
        return Path(validate_launch_argv(runtime.current_app_argv(), runtime=runtime)[0])
    except (OSError, RuntimeCapabilityError, RuntimeMarkerError, ValueError) as exc:
        logger.info("The desktop app's command line is unavailable: %s", exc)
        return None


def is_app_bundle_command(path: str | PurePath) -> bool:
    """Whether *path* is the command line inside a macOS app bundle."""
    parts = PurePath(path).parts
    return (
        len(parts) >= 4
        and parts[-1] == COMMAND_NAME
        and parts[-2] == "MacOS"
        and parts[-3] == "Contents"
        and parts[-4].endswith(".app")
    )


def _is_temporary_location(target: Path) -> bool:
    # A copy macOS translocated (started from Downloads before it was moved)
    # or the mounted disk image disappears when the app quits, which would
    # leave the link dangling.
    text = str(target)
    return "/AppTranslocation/" in text or text.startswith("/Volumes/")


def _link(link: Path, target: Path) -> CliLinkResult:
    if link.is_symlink():
        current = os.readlink(link)
        if current == str(target):
            return CliLinkResult(link, CliLinkState.UNCHANGED, target)
        if not link.exists() or is_app_bundle_command(current):
            _replace_with_link(link, target)
            return CliLinkResult(link, CliLinkState.UPDATED, target)
        return CliLinkResult(
            link, CliLinkState.OCCUPIED, target, "it runs another install", current
        )
    if link.exists():
        return CliLinkResult(
            link, CliLinkState.OCCUPIED, target, "it is a file Servonaut did not make"
        )
    link.parent.mkdir(parents=True, exist_ok=True)
    _replace_with_link(link, target)
    return CliLinkResult(link, CliLinkState.CREATED, target)


def _replace_with_link(link: Path, target: Path) -> None:
    # Build the link beside the old one and rename it over, so the name never
    # disappears while an agent may be starting it.
    staging = link.with_name(f".{link.name}.{os.getpid()}.tmp")
    try:
        staging.unlink(missing_ok=True)
        staging.symlink_to(target)
        os.replace(staging, link)
    finally:
        staging.unlink(missing_ok=True)
