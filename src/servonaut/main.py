#!/usr/bin/env python3
"""Servonaut — Interactive TUI for managing AWS EC2 SSH connections."""
from __future__ import annotations

import argparse
import logging
from pathlib import Path


def _setup_logging(debug: bool = False) -> Path:
    """Configure logging to file (and optionally stderr).

    Args:
        debug: If True, also log to stderr and use DEBUG level.

    Returns:
        Path to the log file.
    """
    log_dir = Path.home() / '.servonaut' / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / 'servonaut.log'

    level = logging.DEBUG if debug else logging.INFO
    fmt = '%(asctime)s %(levelname)-7s [%(name)s] %(message)s'

    handlers: list[logging.Handler] = [
        logging.FileHandler(log_file, encoding='utf-8'),
    ]
    if debug:
        handlers.append(logging.StreamHandler())

    logging.basicConfig(level=level, format=fmt, handlers=handlers)

    # Quiet noisy libraries
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('textual').setLevel(logging.WARNING)

    logging.getLogger(__name__).info("Servonaut started — log: %s", log_file)
    return log_file


def _run_update() -> None:
    """Check for updates and run upgrade from CLI."""
    from servonaut.services.update_service import UpdateService

    svc = UpdateService()
    print(f"Current version: {svc.current_version}")
    print("Checking for updates...")

    latest = svc.check_for_update()
    if not latest:
        print("Already up to date!")
        return

    print(f"New version available: {latest}")
    method = svc.detect_install_method()
    cmd = svc.get_upgrade_command()
    print(f"Install method: {method}")
    print(f"Running: {' '.join(cmd)}")

    import subprocess
    result = subprocess.run(cmd)
    if result.returncode == 0:
        print(f"\nUpdated to v{latest}. Restart servonaut to use the new version.")
    else:
        print(f"\nUpdate failed (exit code {result.returncode}).")


def _install_desktop() -> None:
    """Create a desktop shortcut for the current OS."""
    import shutil
    from pathlib import Path
    from servonaut.utils.platform_utils import get_os

    os_type = get_os()
    servonaut_bin = shutil.which("servonaut")

    if not servonaut_bin:
        print("Error: 'servonaut' command not found in PATH.")
        print("Install with: pipx install servonaut")
        return

    if os_type == "linux":
        desktop_dir = Path.home() / ".local" / "share" / "applications"
        desktop_dir.mkdir(parents=True, exist_ok=True)
        desktop_file = desktop_dir / "servonaut.desktop"

        # Find a suitable terminal emulator
        terminals = [
            ("kitty", "kitty -e"),
            ("alacritty", "alacritty -e"),
            ("gnome-terminal", "gnome-terminal -- "),
            ("konsole", "konsole -e"),
            ("xfce4-terminal", "xfce4-terminal -e"),
            ("xterm", "xterm -e"),
        ]
        terminal_exec = None
        for name, prefix in terminals:
            if shutil.which(name):
                terminal_exec = prefix
                break

        if not terminal_exec:
            print("Error: No supported terminal emulator found.")
            return

        content = f"""[Desktop Entry]
Type=Application
Name=Servonaut
Comment=Server Manager — SSH, SCP, AI Analysis, and more
Exec={terminal_exec} {servonaut_bin}
Icon=utilities-terminal
Terminal=false
Categories=System;TerminalEmulator;
Keywords=ssh;server;aws;ec2;
"""
        desktop_file.write_text(content)
        desktop_file.chmod(0o755)
        print(f"Desktop shortcut created: {desktop_file}")
        print("Servonaut should now appear in your application launcher.")

    elif os_type == "darwin":
        app_dir = Path.home() / "Applications" / "Servonaut.app" / "Contents" / "MacOS"
        app_dir.mkdir(parents=True, exist_ok=True)

        script = app_dir / "Servonaut"
        script.write_text(f"""#!/bin/bash
open -a Terminal "{servonaut_bin}"
""")
        script.chmod(0o755)

        plist_dir = app_dir.parent
        plist = plist_dir / "Info.plist"
        plist.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Servonaut</string>
    <key>CFBundleName</key>
    <string>Servonaut</string>
    <key>CFBundleIdentifier</key>
    <string>com.servonaut.app</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
</dict>
</plist>
""")
        print(f"App bundle created: {app_dir.parent.parent}")
        print("Servonaut should now appear in ~/Applications and Spotlight.")

    else:
        print(f"Desktop shortcuts not yet supported on {os_type}.")
        print(f"You can create an alias: alias servonaut='{servonaut_bin}'")


def main() -> None:
    """Entry point for servonaut command."""
    parser = argparse.ArgumentParser(
        description='Servonaut — Interactive TUI for managing AWS EC2 SSH connections'
    )
    from importlib.metadata import version as pkg_version
    parser.add_argument('--version', action='version',
                        version=f'servonaut {pkg_version("servonaut")}')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging (also prints to stderr)')
    parser.add_argument('--config', type=str, default=None,
                        help='Path to config file (default: ~/.servonaut/config.json)')
    parser.add_argument('--update', action='store_true',
                        help='Check for updates and upgrade if available')
    parser.add_argument('--install-desktop', action='store_true',
                        help='Create a desktop shortcut for your OS')
    parser.add_argument('--demo', action='store_true',
                        help='Demo mode: redact IPs, names, and identifiers for screenshots')
    parser.add_argument('--mcp', action='store_true',
                        help='Start MCP server (stdio transport)')
    parser.add_argument('--mcp-install', type=str, nargs='?', const='claude',
                        metavar='TARGET',
                        help='Install MCP server into a coding agent '
                             '(claude, opencode, cursor, windsurf, vscode, all)')
    args = parser.parse_args()

    if args.update:
        _run_update()
        return

    if args.install_desktop:
        _install_desktop()
        return

    if args.mcp_install:
        from servonaut.mcp.installer import install_mcp_server
        install_mcp_server(args.mcp_install)
        return

    if args.mcp:
        import asyncio
        _setup_logging(debug=args.debug)
        from servonaut.mcp.server import run_server
        asyncio.run(run_server())
        return

    log_file = _setup_logging(debug=args.debug)

    from servonaut.app import ServonautApp
    app = ServonautApp()
    if args.demo:
        app.demo_mode = True
    app.run()

if __name__ == '__main__':
    main()
