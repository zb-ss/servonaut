"""Entry script for the Servonaut desktop GUI launcher executable."""

from __future__ import annotations

import sys

from servonaut.desktop.launcher import DesktopLaunchRequest, run_desktop
from servonaut.runtime import (
    DesktopProcessRole,
    DistributionKind,
    detect_runtime,
    validate_desktop_process_role,
)
from servonaut.utils.logging_setup import configure_rotating_log

# The GUI keeps a file of its own: the child process writes the app log, and
# on Windows two processes holding one rotating file block its rotation.
_GUI_LOG_NAME = "desktop.log"


def main(argv: list[str] | None = None) -> int:
    """Run the desktop GUI launcher."""
    args = sys.argv[1:] if argv is None else list(argv)

    runtime = detect_runtime()
    if runtime.is_frozen and runtime.kind == DistributionKind.PACKAGED_DESKTOP:
        validate_desktop_process_role(
            runtime,
            DesktopProcessRole.GUI,
            current_executable=runtime.executable,
        )

    if args and args[0] == "--_artifact-selftest":
        from servonaut._artifact_selftest import run_artifact_selftest

        return run_artifact_selftest(runtime)

    log_file = configure_rotating_log(
        runtime.data_root / "logs", filename=_GUI_LOG_NAME
    )
    request = DesktopLaunchRequest(runtime=runtime, log_file=log_file)
    return run_desktop(request)


if __name__ == "__main__":
    sys.exit(main())
