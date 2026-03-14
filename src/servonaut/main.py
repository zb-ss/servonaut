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


async def _run_login() -> None:
    """Start OAuth2 device flow login."""
    from servonaut.services.auth_service import AuthService

    auth = AuthService()
    if auth.is_authenticated:
        print(f"Already logged in (plan: {auth.plan})")
        print("Run 'servonaut --logout' first to switch accounts.")
        return

    print("Starting login...")
    try:
        data = await auth.start_device_flow()
    except RuntimeError as e:
        print(f"Error: {e}")
        return

    user_code = data.get("user_code", "???")
    verification_uri = data.get("verification_uri", "")
    device_code = data.get("device_code", "")
    interval = data.get("interval", 5)

    print(f"\nEnter this code: {user_code}")
    if verification_uri:
        print(f"Visit: {verification_uri}")
        import webbrowser
        try:
            webbrowser.open(verification_uri)
            print("(Browser opened)")
        except Exception:
            pass

    print("\nWaiting for authorization...")
    success = await auth.poll_for_token(device_code, interval)

    if success:
        print(f"\nLogged in successfully! Plan: {auth.plan}")
    else:
        print("\nAuthorization failed or timed out. Please try again.")


async def _run_logout() -> None:
    """Revoke tokens and clear auth."""
    from servonaut.services.auth_service import AuthService

    auth = AuthService()
    if not auth.is_authenticated:
        print("Not logged in.")
        return

    await auth.logout()
    print("Logged out successfully.")


def _show_status() -> None:
    """Show account and subscription status."""
    from servonaut.services.auth_service import AuthService

    auth = AuthService()
    status = auth.get_status()

    if not status["authenticated"]:
        print("Not logged in (free tier)")
        print("Run 'servonaut --login' to sign in.")
        return

    print(f"Plan: {status['plan']}")
    ents = status.get("entitlements", {})
    features = ents.get("features", {})
    if features:
        print("\nFeatures:")
        for feat, enabled in sorted(features.items()):
            marker = "+" if enabled else "-"
            print(f"  {marker} {feat}")

    limits = {
        "config_snapshots": ents.get("config_snapshots"),
        "ai_requests_per_day": ents.get("ai_requests_per_day"),
        "mcp_connections": ents.get("mcp_connections"),
        "team_members": ents.get("team_members"),
    }
    active_limits = {k: v for k, v in limits.items() if v is not None}
    if active_limits:
        print("\nLimits:")
        for key, value in active_limits.items():
            print(f"  {key}: {value}")


def _open_subscribe() -> None:
    """Open Stripe checkout in browser."""
    import webbrowser
    url = "https://servonaut.dev/pricing"
    print(f"Opening {url} ...")
    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"Could not open browser: {e}")
        print(f"Visit: {url}")


async def _run_config_push() -> None:
    """Push local config to cloud."""
    from servonaut.services.auth_service import AuthService
    from servonaut.services.api_client import APIClient
    from servonaut.services.config_sync_service import ConfigSyncService
    from servonaut.config.manager import ConfigManager

    auth = AuthService()
    if not auth.is_authenticated:
        print("Not logged in. Run 'servonaut --login' first.")
        return

    api = APIClient(auth)
    cm = ConfigManager()
    sync = ConfigSyncService(api, cm)

    print("Pushing config to cloud...")
    try:
        result = await sync.push()
        print(f"Config pushed. Version: {result.get('version', '?')}")
        print(f"Hash: {result.get('config_hash', '?')}")
    except Exception as e:
        print(f"Error: {e}")


async def _run_config_pull() -> None:
    """Pull latest config from cloud."""
    from servonaut.services.auth_service import AuthService
    from servonaut.services.api_client import APIClient
    from servonaut.services.config_sync_service import ConfigSyncService
    from servonaut.config.manager import ConfigManager

    auth = AuthService()
    if not auth.is_authenticated:
        print("Not logged in. Run 'servonaut --login' first.")
        return

    api = APIClient(auth)
    cm = ConfigManager()
    sync = ConfigSyncService(api, cm)

    print("Pulling config from cloud...")
    try:
        result = await sync.pull()
        config_data = result.get("config_data")
        if not config_data:
            print("No config found in cloud.")
            return

        changes = sync.diff(config_data)
        if not changes:
            print("Local config is already up to date.")
            return

        print(f"Changes detected in {len(changes)} field(s):")
        for field_name in sorted(changes):
            print(f"  - {field_name}")

        confirm = input("\nApply remote config? [y/N] ").strip().lower()
        if confirm == "y":
            sync.apply_remote_config(config_data)
            print("Config updated.")
        else:
            print("Cancelled.")
    except Exception as e:
        print(f"Error: {e}")


async def _run_mcp_remote() -> None:
    """Start remote-only MCP client."""
    from servonaut.services.auth_service import AuthService
    from servonaut.mcp.remote_client import RemoteMCPClient

    auth = AuthService()
    if not auth.is_authenticated:
        print("Not logged in. Run 'servonaut --login' first.")
        return

    client = RemoteMCPClient(auth)
    print("Connecting to remote MCP server...")
    connected = await client.connect()
    if connected:
        print("Connected. Remote MCP client running.")
        # Keep alive until interrupted
        try:
            import asyncio
            while True:
                await asyncio.sleep(30)
        except (KeyboardInterrupt, asyncio.CancelledError):
            await client.disconnect()
            print("\nDisconnected.")
    else:
        print("Failed to connect to remote MCP server.")


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
    parser.add_argument('--mcp', action='store_true',
                        help='Start MCP server (stdio transport)')
    parser.add_argument('--mcp-remote', action='store_true',
                        help='Start remote MCP client (SSE transport)')
    parser.add_argument('--mcp-install', action='store_true',
                        help='Install MCP server into Claude Code settings')
    parser.add_argument('--login', action='store_true',
                        help='Log in to servonaut.dev')
    parser.add_argument('--logout', action='store_true',
                        help='Log out and revoke tokens')
    parser.add_argument('--status', action='store_true',
                        help='Show account and subscription status')
    parser.add_argument('--subscribe', action='store_true',
                        help='Open subscription page in browser')
    parser.add_argument('--config-push', action='store_true',
                        help='Push local config to cloud')
    parser.add_argument('--config-pull', action='store_true',
                        help='Pull latest config from cloud')
    args = parser.parse_args()

    if args.update:
        _run_update()
        return

    if args.install_desktop:
        _install_desktop()
        return

    if args.login:
        import asyncio
        _setup_logging(debug=args.debug)
        asyncio.run(_run_login())
        return

    if args.logout:
        import asyncio
        _setup_logging(debug=args.debug)
        asyncio.run(_run_logout())
        return

    if args.status:
        _show_status()
        return

    if args.subscribe:
        _open_subscribe()
        return

    if args.config_push:
        import asyncio
        _setup_logging(debug=args.debug)
        asyncio.run(_run_config_push())
        return

    if args.config_pull:
        import asyncio
        _setup_logging(debug=args.debug)
        asyncio.run(_run_config_pull())
        return

    if args.mcp_install:
        from servonaut.mcp.installer import install_mcp_server
        install_mcp_server()
        return

    if args.mcp_remote:
        import asyncio
        _setup_logging(debug=args.debug)
        asyncio.run(_run_mcp_remote())
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
    app.run()

if __name__ == '__main__':
    main()
