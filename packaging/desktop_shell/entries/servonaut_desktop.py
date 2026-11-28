"""Entry script for the Servonaut desktop GUI launcher executable."""

from __future__ import annotations

import logging
import sys

from servonaut.desktop.launcher import DesktopLaunchRequest, run_desktop, show_native_error
from servonaut.runtime import (
    DesktopProcessRole,
    DistributionKind,
    detect_runtime,
    validate_desktop_process_role,
)
from servonaut.services.apt_runtime import APT_RESTART_EXIT_CODE, exec_apt_restart
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

    if args == ["--_artifact-selftest"]:
        from servonaut.desktop.artifact_selftest import run_desktop_artifact_selftest

        return run_desktop_artifact_selftest(runtime)

    log_file = configure_rotating_log(
        runtime.data_root / "logs", filename=_GUI_LOG_NAME
    )
    if runtime.is_frozen and runtime.kind == DistributionKind.PACKAGED_DESKTOP:
        # A Dock launch gets launchd's PATH, without Homebrew or the user's
        # shell additions. The child and everything it starts inherit this.
        from servonaut.utils.login_path import merge_login_path

        merge_login_path()

    request = DesktopLaunchRequest(runtime=runtime, log_file=log_file)
    exit_code = run_desktop(request)
    if exit_code == APT_RESTART_EXIT_CODE:
        try:
            exec_apt_restart(runtime.executable, [])
        except (OSError, ValueError) as error:
            logging.getLogger(__name__).error("Servonaut could not restart: %s", error)
            return 1
    if sys.platform == "darwin":
        from servonaut.updates.macos_install import (
            GUIDANCE, INSTALL_QUIT_CODE, MacUpdateError, recover_after_quit, start_on_quit,
        )

        if exit_code == INSTALL_QUIT_CODE:
            try:
                start_on_quit(runtime)
                return 0
            except (OSError, MacUpdateError, ValueError) as exc:
                logging.getLogger(__name__).warning("Could not prepare application replacement: %s", exc)
                show_native_error("Servonaut update", GUIDANCE)
                return 1
        recover_after_quit(runtime)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
