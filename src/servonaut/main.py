#!/usr/bin/env python3
"""Servonaut — Interactive TUI for managing AWS EC2 SSH connections."""
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
from pathlib import Path

_RELAY_PID_FILE = Path.home() / '.servonaut' / 'relay.pid'


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


def _relay_run_foreground() -> None:
    """Run the relay listener in the foreground (blocks until interrupted)."""
    import asyncio

    from servonaut.config.manager import ConfigManager
    from servonaut.services.cache_service import CacheService
    from servonaut.services.aws_service import AWSService
    from servonaut.services.ssh_service import SSHService
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.scp_service import SCPService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.relay_executors import RelayExecutors
    from servonaut.services.relay_listener import RelayListener

    # Headless service init (same pattern as MCP server)
    config_manager = ConfigManager()
    config = config_manager.get()
    relay_cfg = config.relay

    auth_token = os.environ.get('SERVONAUT_RELAY_TOKEN', '')
    user_id = os.environ.get('SERVONAUT_USER_ID', '')

    if not auth_token:
        print("Error: SERVONAUT_RELAY_TOKEN environment variable is required.")
        sys.exit(1)
    if not user_id:
        print("Error: SERVONAUT_USER_ID environment variable is required.")
        sys.exit(1)
    if not relay_cfg.base_url:
        print("Error: relay.base_url is not configured in ~/.servonaut/config.json")
        sys.exit(1)
    if not relay_cfg.mercure_url:
        print("Error: relay.mercure_url is not configured in ~/.servonaut/config.json")
        sys.exit(1)
    if not relay_cfg.base_url.startswith('https://'):
        print("Error: relay.base_url must use HTTPS (got: %s)" % relay_cfg.base_url)
        sys.exit(1)
    if not relay_cfg.mercure_url.startswith('https://'):
        print("Error: relay.mercure_url must use HTTPS (got: %s)" % relay_cfg.mercure_url)
        sys.exit(1)

    cache_service = CacheService(ttl_seconds=config.cache_ttl_seconds)
    aws_service = AWSService(cache_service)
    custom_server_service = CustomServerService(config_manager)
    ssh_service = SSHService(config_manager)
    connection_service = ConnectionService(config_manager)
    scp_service = SCPService()

    executors = RelayExecutors(
        config_manager, aws_service, custom_server_service,
        ssh_service, connection_service, scp_service,
    )
    listener = RelayListener(
        executors=executors,
        base_url=relay_cfg.base_url,
        mercure_url=relay_cfg.mercure_url,
        auth_token=auth_token,
        user_id=user_id,
        heartbeat_interval=relay_cfg.heartbeat_interval,
    )

    print(f"Starting Servonaut relay listener (user: {user_id})")
    print(f"  Hub: {relay_cfg.mercure_url}")
    print(f"  API: {relay_cfg.base_url}")
    print("Press Ctrl+C to stop.")

    asyncio.run(listener.run())


def _relay_start_background() -> None:
    """Launch the relay listener as a detached subprocess and write a PID file."""
    import subprocess

    _RELAY_PID_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Check if already running
    if _RELAY_PID_FILE.exists():
        try:
            existing_pid = int(_RELAY_PID_FILE.read_text().strip())
            os.kill(existing_pid, 0)
            print(f"Relay listener already running (PID {existing_pid}). "
                  "Use 'servonaut connect --stop' first.")
            return
        except PermissionError:
            print(f"Relay listener running as different user (PID {existing_pid}). "
                  "Use 'servonaut connect --stop' first.")
            return
        except (ProcessLookupError, ValueError):
            _RELAY_PID_FILE.unlink(missing_ok=True)

    # Launch as a new subprocess (not fork) — portable and avoids fd leaks
    proc = subprocess.Popen(
        [sys.executable, '-m', 'servonaut.main', 'connect'],
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _RELAY_PID_FILE.write_text(str(proc.pid))
    print(f"Relay listener started in background (PID {proc.pid})")
    print(f"PID file: {_RELAY_PID_FILE}")


def _relay_stop() -> None:
    """Stop a background relay listener by sending SIGTERM."""
    if not _RELAY_PID_FILE.exists():
        print("No relay listener PID file found. Is it running?")
        return
    pid = None
    try:
        pid = int(_RELAY_PID_FILE.read_text().strip())
        os.kill(pid, signal.SIGTERM)
        _RELAY_PID_FILE.unlink(missing_ok=True)
        print(f"Sent SIGTERM to relay listener (PID {pid})")
    except ValueError:
        print("PID file contains invalid content — removing.")
        _RELAY_PID_FILE.unlink(missing_ok=True)
    except ProcessLookupError:
        print(f"Process {pid} not found — cleaning up stale PID file.")
        _RELAY_PID_FILE.unlink(missing_ok=True)
    except Exception as e:
        print(f"Error stopping relay listener: {e}")


def _relay_status() -> None:
    """Print the status of the background relay listener."""
    if not _RELAY_PID_FILE.exists():
        print("Relay listener: not running (no PID file)")
        return
    pid = None
    try:
        pid = int(_RELAY_PID_FILE.read_text().strip())
        os.kill(pid, 0)  # Signal 0: check if process exists
        print(f"Relay listener: running (PID {pid})")
    except ValueError:
        print("PID file contains invalid content — removing.")
        _RELAY_PID_FILE.unlink(missing_ok=True)
    except ProcessLookupError:
        print(f"Relay listener: not running (stale PID file, PID {pid})")
    except Exception as e:
        print(f"Relay listener: unknown status — {e}")


def _relay_reconnect() -> None:
    """Stop any running background listener and launch a fresh one.

    Why: `--status` only confirms the local process exists — it can't see a
    stale SSE socket that looks alive to the OS but the backend no longer sees
    traffic on. A simple stop+start is the least-astonishing recovery.
    """
    import time as _time

    if _RELAY_PID_FILE.exists():
        try:
            pid = int(_RELAY_PID_FILE.read_text().strip())
        except ValueError:
            pid = None
            _RELAY_PID_FILE.unlink(missing_ok=True)
        if pid is not None:
            try:
                os.kill(pid, signal.SIGTERM)
                # Give the listener ~3s to exit cleanly before we start a new one
                # (otherwise _relay_start_background refuses to reuse the PID file).
                for _ in range(30):
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                    _time.sleep(0.1)
                print(f"Sent SIGTERM to relay listener (PID {pid})")
            except ProcessLookupError:
                print(f"Previous listener (PID {pid}) was already gone.")
            except Exception as e:
                print(f"Error stopping previous listener: {e}")
            _RELAY_PID_FILE.unlink(missing_ok=True)

    _relay_start_background()


def _list_backups_cli() -> None:
    """Print the local config backup list and exit."""
    from servonaut.config.manager import ConfigManager
    cm = ConfigManager()
    backups = cm.list_backups()
    if not backups:
        print("No local backups yet.")
        return
    print(f"{'#':>3}  {'Timestamp':<19}  {'Size':>8}  Path")
    print("-" * 70)
    for idx, entry in enumerate(backups, start=1):
        ts = entry['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
        size = entry['size_bytes']
        size_str = f"{size} B" if size < 1024 else f"{size / 1024:.1f} KB"
        print(f"{idx:>3}  {ts:<19}  {size_str:>8}  {entry['path']}")


def _restore_backup_cli(index: int) -> None:
    """Restore a local config backup by 1-based index. Prompts if index == -1."""
    from servonaut.config.manager import ConfigManager
    cm = ConfigManager()
    backups = cm.list_backups()
    if not backups:
        print("No local backups to restore.")
        return

    # Interactive picker when no index given
    if index is None or index == -1:
        print("Available backups (newest first):")
        print(f"{'#':>3}  {'Timestamp':<19}  {'Size':>8}")
        print("-" * 40)
        for idx, entry in enumerate(backups, start=1):
            ts = entry['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
            size = entry['size_bytes']
            size_str = f"{size} B" if size < 1024 else f"{size / 1024:.1f} KB"
            print(f"{idx:>3}  {ts:<19}  {size_str:>8}")
        try:
            choice = input("Enter number to restore (or Enter to cancel): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return
        if not choice:
            print("Cancelled.")
            return
        try:
            index = int(choice)
        except ValueError:
            print("Invalid choice.")
            return

    if index < 1 or index > len(backups):
        print(f"Index {index} out of range (1-{len(backups)}).")
        return

    entry = backups[index - 1]
    try:
        cm.restore_backup(entry['path'])
        print(f"Restored from {entry['path']}")
        print("Your previous config was backed up; launch Servonaut to continue.")
    except Exception as exc:
        print(f"Restore failed: {exc}")


def _run_connect(args: argparse.Namespace) -> None:
    """Handle the `connect` subcommand."""
    if args.stop:
        _relay_stop()
        return
    if args.status:
        _relay_status()
        return
    if args.reconnect:
        _relay_reconnect()
        return
    if args.bg:
        _relay_start_background()
    else:
        _relay_run_foreground()


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
    parser.add_argument('--list-backups', action='store_true',
                        help='List local config backups and exit')
    parser.add_argument('--restore-backup', type=int, metavar='N', nargs='?', const=-1,
                        help='Restore a local config backup by index (1=newest). '
                             'With no argument, prompts interactively.')

    subparsers = parser.add_subparsers(dest='subcommand')
    connect_parser = subparsers.add_parser(
        'connect',
        help='Subscribe to Mercure hub and relay commands to managed servers',
    )
    connect_group = connect_parser.add_mutually_exclusive_group()
    connect_group.add_argument('--bg', action='store_true',
                               help='Run relay listener in the background')
    connect_group.add_argument('--stop', action='store_true',
                               help='Stop a background relay listener')
    connect_group.add_argument('--status', action='store_true',
                               help='Show status of background relay listener')
    connect_group.add_argument('--reconnect', action='store_true',
                               help='Stop a stale background listener (if any) and '
                                    'start a fresh one')

    args = parser.parse_args()

    if args.subcommand == 'connect':
        _setup_logging(debug=args.debug)
        _run_connect(args)
        return

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

    if args.list_backups:
        _list_backups_cli()
        return

    if args.restore_backup is not None:
        _restore_backup_cli(args.restore_backup)
        return

    log_file = _setup_logging(debug=args.debug)

    from servonaut.app import ServonautApp
    app = ServonautApp()
    if args.demo:
        app.demo_mode = True
    app.run()

if __name__ == '__main__':
    main()
