#!/usr/bin/env python3
"""Servonaut — Interactive TUI for managing AWS EC2 SSH connections."""
from __future__ import annotations

import argparse
import asyncio
import io
import logging
import os
import shlex
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

# Forwarded variables that reached this process as empty strings and were
# removed before any SDK could read them. Filled by _prune_empty_env() at the
# top of _main(); reported by _setup_logging() once a handler exists.
_PRUNED_ENV_NAMES: tuple[str, ...] = ()


def _prune_empty_env() -> None:
    """Drop empty forwarded environment variables before dispatching."""
    global _PRUNED_ENV_NAMES
    from servonaut.mcp.installer import prune_empty_forwarded_env
    _PRUNED_ENV_NAMES = prune_empty_forwarded_env()


def _setup_logging(debug: bool = False) -> Path:
    """Configure logging to a size-rotated file (and optionally stderr).

    Args:
        debug: If True, also log to stderr and use DEBUG level.

    Returns:
        Path to the active log file.
    """
    from servonaut.utils.logging_setup import configure_rotating_log

    log_file = configure_rotating_log(Path.home() / '.servonaut' / 'logs', debug=debug)
    logging.getLogger(__name__).info("Servonaut started — log: %s", log_file)
    if _PRUNED_ENV_NAMES:
        logging.getLogger(__name__).info(
            "Ignoring empty environment variables: %s", ", ".join(_PRUNED_ENV_NAMES)
        )
    return log_file


def _run_update() -> None:
    """Check for updates and run upgrade from CLI."""
    from servonaut.runtime import detect_runtime
    from servonaut.services.update_service import UpdateService

    svc = UpdateService(detect_runtime())
    print(f"Current version: {svc.current_version}")
    print("Checking for updates...")

    latest = svc.check_for_update()
    if not latest:
        if svc.update_status or svc.update_guidance:
            print(svc.update_status or svc.update_guidance)
            return
        print("Already up to date!")
        return

    print(f"New version available: {latest}")
    print(f"Install method: {svc.detect_install_method()}")
    command = svc.get_upgrade_command()
    if command is None:
        print(svc.update_status or svc.update_guidance or "Update manually.")
        raise SystemExit(1)
    print(f"Running: {' '.join(command)}")

    success, message = asyncio.run(svc.run_upgrade())
    print(f"\n{message}")
    if not success:
        raise SystemExit(1)


def _desktop_exec_argument(argument: str) -> str:
    """Encode one argument using the Desktop Entry ``Exec`` grammar.

    Desktop entries are not shell commands: single quotes have no special
    meaning, and percent signs introduce field codes.  Quote each complete
    argument and apply the Desktop Entry escaping rules instead.
    """
    if "\x00" in argument:
        raise ValueError("Desktop entry arguments cannot contain null bytes.")
    escaped = (
        argument.replace("\\", "\\\\\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace('"', r'\\"')
        .replace("`", r"\\`")
        .replace("$", "\\\\$")
        .replace("%", "%%")
    )
    return f'"{escaped}"'


def _desktop_exec(argv: Sequence[str]) -> str:
    """Build a spec-compliant desktop-entry command line from argv."""
    if not argv:
        raise ValueError("Desktop entry command is empty.")
    if "=" in argv[0]:
        raise ValueError("Desktop entry executable cannot contain '='.")
    return " ".join(_desktop_exec_argument(argument) for argument in argv)


def _write_macos_command_helper(path: Path, argv: Sequence[str]) -> None:
    """Write an executable POSIX-shell helper that preserves argv boundaries."""
    if not argv:
        raise ValueError("macOS launcher command is empty.")
    path.write_text(f"#!/bin/sh\nexec {shlex.join(argv)}\n", encoding="utf-8")
    path.chmod(0o755)


def _write_macos_launcher(path: Path, helper_name: str) -> None:
    """Write a bundle-relative launcher that asks Terminal to open a helper."""
    path.write_text(
        "#!/bin/sh\n"
        'script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)\n'
        f'exec open -a Terminal "$script_dir/{helper_name}"\n',
        encoding="utf-8",
    )
    path.chmod(0o755)


def _install_desktop() -> None:
    """Create a desktop shortcut for the current OS."""
    import shutil
    from servonaut.runtime import (
        DistributionKind,
        RuntimeCapabilityError,
        detect_runtime,
        validate_launch_argv,
    )
    from servonaut.utils.platform_utils import get_os

    runtime = detect_runtime()
    if runtime.kind is DistributionKind.PACKAGED_DESKTOP:
        print("This packaged desktop build already provides its GUI launcher.")
        return
    try:
        app_argv = validate_launch_argv(runtime.current_app_argv(), runtime=runtime)
    except RuntimeCapabilityError as exc:
        print(f"Error: could not validate the Servonaut launch command: {exc}")
        return

    os_type = get_os()

    if os_type == "linux":
        desktop_dir = Path.home() / ".local" / "share" / "applications"
        desktop_dir.mkdir(parents=True, exist_ok=True)
        desktop_file = desktop_dir / "servonaut.desktop"

        # Find a suitable terminal emulator
        terminals = [
            ("kitty", ("kitty", "-e")),
            ("alacritty", ("alacritty", "-e")),
            ("gnome-terminal", ("gnome-terminal", "--")),
            ("konsole", ("konsole", "-e")),
            ("xfce4-terminal", ("xfce4-terminal", "-e")),
            ("xterm", ("xterm", "-e")),
        ]
        terminal_argv = None
        for name, prefix in terminals:
            if shutil.which(name):
                terminal_argv = prefix
                break

        if not terminal_argv:
            print("Error: No supported terminal emulator found.")
            return

        try:
            desktop_exec = _desktop_exec([*terminal_argv, *app_argv])
        except ValueError as exc:
            print(f"Error: could not create a desktop launcher: {exc}")
            return

        content = f"""[Desktop Entry]
Type=Application
Name=Servonaut
Comment=Server Manager — SSH, SCP, AI Analysis, and more
Exec={desktop_exec}
Icon=utilities-terminal
Terminal=false
Categories=System;TerminalEmulator;
Keywords=ssh;server;aws;ec2;
"""
        desktop_file.write_text(content, encoding="utf-8")
        desktop_file.chmod(0o755)
        print(f"Desktop shortcut created: {desktop_file}")
        print("Servonaut should now appear in your application launcher.")

    elif os_type == "darwin":
        app_dir = Path.home() / "Applications" / "Servonaut.app" / "Contents" / "MacOS"
        app_dir.mkdir(parents=True, exist_ok=True)

        command_helper = app_dir / "Servonaut.command"
        _write_macos_command_helper(command_helper, app_argv)

        script = app_dir / "Servonaut"
        _write_macos_launcher(script, command_helper.name)

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
        print(f"You can launch Servonaut with: {shlex.join(app_argv)}")


def _relay_run_foreground() -> None:
    """Run the relay listener in the foreground (blocks until interrupted).

    Guarded by :class:`RelayLock` so a TUI in-process listener and this
    foreground listener cannot both talk to Mercure at the same time.
    """
    import asyncio

    from servonaut.config.manager import ConfigManager
    from servonaut.runtime import detect_runtime
    from servonaut.services.cache_service import CacheService
    from servonaut.services.aws_service import AWSService
    from servonaut.services.ssh_service import SSHService
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.scp_service import SCPService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.relay_executors import RelayExecutors
    from servonaut.services.relay_listener import RelayListener
    from servonaut.services.relay_lock import (
        RelayAlreadyActiveError, RelayLock,
    )
    from servonaut.utils.relay_log import log_relay_event

    runtime = detect_runtime()
    lock_path = runtime.data_root / "relay.lock"
    # Headless service init (same pattern as MCP server)
    config_manager = ConfigManager()
    config = config_manager.get()
    relay_cfg = config.relay

    auth_token = os.environ.get('SERVONAUT_RELAY_TOKEN', '')
    user_id = os.environ.get('SERVONAUT_USER_ID', '')

    # The stored OAuth session (`servonaut login`) is the primary auth
    # source; the env-var pair is the legacy/CI override and wins when
    # BOTH are set. The session is also what enables AI tool execution —
    # tool results POST to the API with the bearer.
    auth_service = None
    try:
        from servonaut.services.auth_service import AuthService
        candidate = AuthService()
        if candidate.is_authenticated:
            auth_service = candidate
    except Exception as exc:
        logging.getLogger(__name__).debug(
            "AuthService unavailable for relay: %s", exc,
        )

    token_source = auth_token  # str (legacy) or callable (OAuth session)
    refresh_callback = None
    if not (auth_token and user_id):
        if auth_service is None:
            print(
                "Error: no Servonaut session found. Run `servonaut login` "
                "first, or set both SERVONAUT_RELAY_TOKEN and "
                "SERVONAUT_USER_ID."
            )
            sys.exit(1)
        from servonaut.services.relay_manager import _extract_user_id
        token_source = lambda: auth_service.access_token  # noqa: E731
        refresh_callback = auth_service.refresh_token
        user_id = _extract_user_id(auth_service) or ''
        if not user_id:
            print(
                "Error: could not determine your user id from the stored "
                "session. Re-run `servonaut login`."
            )
            sys.exit(1)

    # Auto-fill relay URLs from the API base if missing (same logic the TUI
    # runs at mount), so a bg listener launched before the user has ever
    # opened the TUI doesn't dead-end on a config block they never edited.
    if not relay_cfg.base_url or not relay_cfg.mercure_url:
        from servonaut.services.relay_manager import derive_relay_urls
        from servonaut.services.auth_service import _api_base
        try:
            derived_base, derived_mercure = derive_relay_urls(_api_base())
        except ValueError as exc:
            print(f"Error: cannot derive relay URLs from SERVONAUT_API_URL: {exc}")
            sys.exit(1)
        if not relay_cfg.base_url:
            relay_cfg.base_url = derived_base
        if not relay_cfg.mercure_url:
            relay_cfg.mercure_url = derived_mercure
        try:
            config_manager.save(config)
        except Exception as exc:
            print(f"Error: failed to persist relay URLs to config.json: {exc}")
            sys.exit(1)
        print(
            f"Auto-populated relay URLs: base_url={relay_cfg.base_url} "
            f"mercure_url={relay_cfg.mercure_url}"
        )
    if not relay_cfg.base_url.startswith('https://'):
        print("Error: relay.base_url must use HTTPS (got: %s)" % relay_cfg.base_url)
        sys.exit(1)
    if not relay_cfg.mercure_url.startswith('https://'):
        print("Error: relay.mercure_url must use HTTPS (got: %s)" % relay_cfg.mercure_url)
        sys.exit(1)

    try:
        lock = RelayLock(mode="bg", path=lock_path).acquire()
    except RelayAlreadyActiveError as e:
        owner = e.owner
        if owner.mode == "tui":
            print(
                "A TUI session is already holding the relay connection "
                f"(PID {owner.pid}). Close the TUI first, or use "
                "'servonaut connect --force-bg' to detach it."
            )
        else:
            print(
                f"Another relay listener is already active "
                f"(mode={owner.mode}, PID={owner.pid}). Close it first."
            )
        sys.exit(2)

    cache_service = CacheService(ttl_seconds=config.cache_ttl_seconds)
    aws_service = AWSService(cache_service)
    custom_server_service = CustomServerService(config_manager)
    ssh_service = SSHService(config_manager)
    connection_service = ConnectionService(config_manager)
    scp_service = SCPService(
        ssh_config=config.ssh,
        transfer_timeout_seconds=config.mcp.transfer_timeout_seconds,
    )

    executors = RelayExecutors(
        config_manager, aws_service, custom_server_service,
        ssh_service, connection_service, scp_service,
    )

    # AI chat tool executor — lets headless sessions answer tool calls the
    # hosted AI dispatches on /cli/{uid}/ai-tool-calls. Needs the OAuth
    # session (tool results POST to the API); in env-token-only mode it
    # stays disabled and tool dispatches time out server-side as before.
    ai_tool_executor = None
    probe_bridge = None
    ai_tool_note = "disabled (run `servonaut login` to enable)"
    if auth_service is not None:
        try:
            from servonaut.services.api_client import APIClient
            from servonaut.services.ai_tool_bridge import AIToolBridge
            from servonaut.services.ip_ban_service import IPBanService
            from servonaut.services.relay_tool_executor import (
                RelayAIToolExecutor, build_headless_confirm,
            )
            from servonaut.services.relay_listener import build_probe_confirm
            from servonaut.mcp.audit import AuditTrail
            from servonaut.mcp.server import build_headless_tools

            api_client = APIClient(auth_service)
            mcp_audit = AuditTrail(config.mcp.audit_path)
            headless_tools = build_headless_tools(config_manager)
            ip_ban_service = IPBanService(config_manager)

            bridge = AIToolBridge(
                api_client=api_client,
                relay_executors=executors,
                mcp_audit=mcp_audit,
                confirm_callback=build_headless_confirm(config_manager),
                auth_service=auth_service,
                servonaut_tools=headless_tools,
                ip_ban_service=ip_ban_service,
            )
            ai_tool_executor = RelayAIToolExecutor(bridge)
            # Separate bridge for proactive-monitoring probes: fixed
            # probe policy (readonly + in-DB introspection, never a
            # prompt) regardless of relay.ai_tool_auto_approve, and
            # audit rows tagged source="proactive". Results POST to the
            # command-result route (the listener owns that).
            probe_bridge = AIToolBridge(
                api_client=api_client,
                relay_executors=executors,
                mcp_audit=mcp_audit,
                confirm_callback=build_probe_confirm(),
                auth_service=auth_service,
                servonaut_tools=headless_tools,
                ip_ban_service=ip_ban_service,
                audit_source="proactive",
            )
            ai_tool_note = (
                f"enabled (auto-approve up to: "
                f"{config.relay.ai_tool_auto_approve})"
            )
        except ImportError as exc:
            ai_tool_note = f"disabled (missing dependency: {exc})"
        except Exception as exc:
            ai_tool_note = f"disabled (init failed: {exc})"
            logging.getLogger(__name__).exception(
                "AI tool executor init failed",
            )

    listener = RelayListener(
        executors=executors,
        base_url=relay_cfg.base_url,
        mercure_url=relay_cfg.mercure_url,
        auth_token=token_source,
        user_id=user_id,
        heartbeat_interval=relay_cfg.heartbeat_interval,
        refresh_callback=refresh_callback,
        ai_tool_executor=ai_tool_executor,
        probe_bridge=probe_bridge,
    )

    print(f"Starting Servonaut relay listener (user: {user_id})")
    print(f"  Hub: {relay_cfg.mercure_url}")
    print(f"  API: {relay_cfg.base_url}")
    print(f"  AI chat tools: {ai_tool_note}")
    print("Press Ctrl+C to stop.")
    log_relay_event("starting", mode="bg", client_id=listener.client_id)

    try:
        asyncio.run(listener.run())
    finally:
        log_relay_event("stopped", mode="bg", reason="shutdown")
        lock.release()


def _relay_paths(runtime) -> tuple[Path, Path, Path]:
    """Return the relay PID, lock, and control paths owned by one runtime."""
    data_root = runtime.data_root
    return (
        data_root / "relay.pid",
        data_root / "relay.lock",
        data_root / "relay-control.json",
    )


def _read_background_pid(pid_path: Path) -> int | None:
    """Read a positive PID from an advisory background-listener record."""
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    return pid if pid > 0 else None


def _relay_start_background(runtime=None) -> None:
    """Launch a verified runtime command as a detached relay listener."""
    from servonaut.runtime import (
        RuntimeCapabilityError,
        validate_launch_argv,
    )
    from servonaut.services.process_control import is_process_alive, spawn_detached
    from servonaut.services.relay_control import configured_control_timeout_seconds
    from servonaut.services.relay_lock import active_owner, is_active_owner

    if runtime is None:
        from servonaut.runtime import detect_runtime

        runtime = detect_runtime()
    pid_path, lock_path, _ = _relay_paths(runtime)
    owner = active_owner(lock_path)
    if owner is not None:
        if owner.mode == "tui" and is_process_alive(owner.pid):
            print(
                "A TUI session is already holding the relay connection "
                f"(PID {owner.pid}). Use 'servonaut connect --force-bg' to detach it."
            )
        elif owner.mode == "bg" and owner.pid is not None:
            print(
                f"Relay listener already running (PID {owner.pid}). "
                "Use 'servonaut connect --stop' first."
            )
        else:
            print("A relay lock is active; refusing to start another listener.")
        return

    if pid_path.exists():
        existing_pid = _read_background_pid(pid_path)
        if (
            existing_pid is not None
            and is_process_alive(existing_pid)
            and is_active_owner(existing_pid, "bg", lock_path)
        ):
            print(
                f"Relay listener already running (PID {existing_pid}). "
                "Use 'servonaut connect --stop' first."
            )
            return
        pid_path.unlink(missing_ok=True)

    try:
        command = validate_launch_argv(
            runtime.current_app_argv("connect"), runtime=runtime
        )
    except RuntimeCapabilityError as exc:
        print(f"Could not launch the relay listener: {exc}")
        raise SystemExit(1)
    try:
        pid_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"Could not prepare relay listener storage: {exc}")
        raise SystemExit(1)
    try:
        process = spawn_detached(command)
    except OSError as exc:
        print(f"Could not start relay listener: {exc}")
        raise SystemExit(1)
    try:
        pid_path.write_text(str(process.pid), encoding="utf-8")
    except OSError as exc:
        cleanup_error: OSError | subprocess.TimeoutExpired | None = None
        try:
            process.terminate()
            process.wait(timeout=configured_control_timeout_seconds())
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.wait(timeout=configured_control_timeout_seconds())
            except (OSError, subprocess.TimeoutExpired) as kill_error:
                cleanup_error = kill_error
        except OSError as terminate_error:
            cleanup_error = terminate_error
        if cleanup_error is not None:
            print(f"Could not clean up unrecorded relay listener: {cleanup_error}")
        print(f"Could not record relay listener PID: {exc}")
        raise SystemExit(1)
    print(f"Relay listener started in background (PID {process.pid})")
    print(f"PID file: {pid_path}")


def _relay_stop(runtime=None) -> bool:
    """Stop only a live background listener proven to own the active lock."""
    from servonaut.services.process_control import (
        is_process_alive,
        terminate_process,
        wait_for_process_exit,
    )
    from servonaut.services.relay_control import configured_control_timeout_seconds
    from servonaut.services.relay_lock import is_active_owner

    if runtime is None:
        from servonaut.runtime import detect_runtime

        runtime = detect_runtime()
    pid_path, lock_path, _ = _relay_paths(runtime)
    if not pid_path.exists():
        print("No relay listener PID file found. Is it running?")
        return True
    pid = _read_background_pid(pid_path)
    if pid is None:
        print("PID file contains invalid content — removing.")
        pid_path.unlink(missing_ok=True)
        return True
    if not is_process_alive(pid):
        print(f"Process {pid} not found — cleaning up stale PID file.")
        pid_path.unlink(missing_ok=True)
        return True
    if not is_active_owner(pid, "bg", lock_path):
        print("Relay lock ownership could not be confirmed; refusing to terminate PID.")
        return False
    try:
        terminate_process(pid)
    except OSError as exc:
        print(f"Error stopping relay listener: {exc}")
        return False
    if not wait_for_process_exit(pid, configured_control_timeout_seconds()):
        print(f"Relay listener (PID {pid}) did not stop before the bounded wait elapsed.")
        return False
    pid_path.unlink(missing_ok=True)
    print(f"Stopped relay listener (PID {pid})")
    return True


def _relay_status() -> None:
    """Show both the local process view and the backend's view of the listener.

    Local view: is the PID file there, is the process alive, what mode does the
    lock file claim (tui vs bg).
    Backend view: ``/api/cli/status`` — connected / last_heartbeat_at / client_ids.
    If the two disagree, print a divergence warning so the user knows heartbeats
    aren't actually landing.
    """
    from servonaut.runtime import detect_runtime
    from servonaut.services.process_control import is_process_alive
    from servonaut.services.relay_lock import active_owner

    # --- Local view ---------------------------------------------------------
    runtime = detect_runtime()
    pid_path, lock_path, _ = _relay_paths(runtime)
    owner = active_owner(lock_path)
    lock_alive = owner is not None and is_process_alive(owner.pid)
    pidfile_pid = None
    pidfile_alive = False
    if pid_path.exists():
        pidfile_pid = _read_background_pid(pid_path)
        pidfile_alive = pidfile_pid is not None and is_process_alive(pidfile_pid)

    local_running = lock_alive or pidfile_alive
    if owner is not None and owner.mode and lock_alive:
        local_summary = f"running (mode={owner.mode}, PID {owner.pid})"
    elif pidfile_alive:
        local_summary = f"running (bg, PID {pidfile_pid}; lock file empty)"
    elif pidfile_pid is not None:
        local_summary = f"not running (stale PID file, PID {pidfile_pid})"
    else:
        local_summary = "not running"
    print(f"Local view:   {local_summary}")

    # --- Backend view -------------------------------------------------------
    backend = _fetch_backend_status()
    if backend is None:
        print("Backend view: unavailable (not logged in or httpx missing).")
        return
    if "error" in backend:
        print(f"Backend view: error — {backend['error']}")
        return

    connected = bool(backend.get("connected"))
    last_hb = backend.get("last_heartbeat_at") or "never"
    clients = backend.get("client_ids") or []
    print(
        f"Backend view: {'connected' if connected else 'disconnected'}"
        f" (last_heartbeat_at={last_hb}, client_ids={clients})"
    )

    if local_running and not connected:
        print(
            "WARNING: listener is running locally but the backend does not see "
            "it. Heartbeats may not be reaching staging/production. Try "
            "'servonaut connect --reconnect'."
        )
    elif connected and not local_running:
        print(
            "NOTE: backend still reports a recent connection, but no local "
            "listener is running. This resolves in ~60s once the heartbeat "
            "TTL expires."
        )


def _fetch_backend_status():
    """Synchronously call /api/cli/status via the same MCP pipeline the agents use.

    Returns the parsed body dict, a dict with ``error`` on failure, or ``None``
    if we simply don't have credentials or httpx.
    """
    try:
        from servonaut.services.auth_service import AuthService
    except ImportError:
        return None

    auth = AuthService()
    if not auth.is_authenticated:
        return None

    try:
        from servonaut.mcp.tools import ServonautTools
        from servonaut.mcp.guards import CommandGuard
        from servonaut.mcp.audit import AuditTrail
        from servonaut.config.manager import ConfigManager
    except ImportError:
        return None

    import asyncio
    import json
    config_manager = ConfigManager()
    cfg = config_manager.get()
    tools = ServonautTools(
        config_manager=config_manager,
        aws_service=_NoopAws(),
        custom_server_service=_NoopCustom(),
        cache_service=_NoopCache(),
        ssh_service=None,
        connection_service=None,
        scp_service=None,
        guard=CommandGuard(cfg.mcp, config_manager),
        audit=AuditTrail(cfg.mcp.audit_path),
        auth_service=auth,
        memory_service=None,
    )
    try:
        raw = asyncio.run(tools.relay_status())
        return json.loads(raw)
    except Exception as e:
        return {"error": str(e)}


class _NoopAws:  # helpers: the status call never touches these
    async def fetch_instances_cached(self):
        return []


class _NoopCustom:
    def list_as_instances(self):
        return []


class _NoopCache:
    pass


def _relay_force_bg() -> None:
    """Force-hand over the relay from an in-process TUI listener to a bg listener.

    An authenticated loopback control acknowledgement proves that the TUI
    stopped its listener and released the authoritative lock before spawning.
    """
    from servonaut.runtime import detect_runtime
    from servonaut.services.process_control import is_process_alive
    from servonaut.services.relay_control import request_relay_release
    from servonaut.services.relay_lock import active_owner

    runtime = detect_runtime()
    _, lock_path, record_path = _relay_paths(runtime)
    owner = active_owner(lock_path)
    if owner is not None and owner.mode == "tui":
        if not is_process_alive(owner.pid):
            print("The active TUI relay lock has no live owner; refusing handover.")
            raise SystemExit(3)
        response = asyncio.run(
            request_relay_release(record_path=record_path, lock_path=lock_path)
        )
        if not response.ok or not response.released:
            print(response.error or "TUI relay handover was not acknowledged.")
            raise SystemExit(3)
    _relay_start_background(runtime)


def _relay_reconnect() -> None:
    """Stop any running background listener and launch a fresh one.

    Why: `--status` only confirms the local process exists — it can't see a
    stale SSE socket that looks alive to the OS but the backend no longer sees
    traffic on. A simple stop+start is the least-astonishing recovery.
    """
    from servonaut.runtime import detect_runtime

    runtime = detect_runtime()
    if _relay_stop(runtime):
        _relay_start_background(runtime)


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
    if getattr(args, "force_bg", False):
        _relay_force_bg()
        return
    if args.bg:
        _relay_start_background()
    else:
        _relay_run_foreground()


def _configure_stdio() -> None:
    """Ensure standard streams use UTF-8 encoding across all platforms."""
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except (AttributeError, io.UnsupportedOperation, ValueError, OSError):
                continue


def main() -> None:
    """Entry point for the ``servonaut`` command.

    Thin wrapper that turns an unhandled Ctrl+C anywhere in the CLI into
    a one-line "Cancelled." and exit code 130 (128+SIGINT) instead of a
    traceback. Handlers that want a friendlier outcome catch
    KeyboardInterrupt themselves before it reaches this backstop.
    """
    _configure_stdio()
    try:
        _main()
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        sys.exit(130)


def _main() -> None:
    """Parse arguments and dispatch to the selected command."""
    _configure_stdio()
    if sys.argv[1:] == ["--_artifact-selftest"]:
        from servonaut.runtime import DistributionKind, detect_runtime

        runtime = detect_runtime()
        if (
            runtime.kind is DistributionKind.FROZEN_CLI
            and runtime.is_frozen
            and runtime.build_revision is not None
        ):
            from servonaut._artifact_selftest import run_artifact_selftest

            raise SystemExit(run_artifact_selftest(runtime))
    _prune_empty_env()
    parser = argparse.ArgumentParser(
        description='Servonaut — Interactive TUI for managing AWS EC2 SSH connections'
    )
    from servonaut import get_version
    parser.add_argument('--version', action='version',
                        version=f'servonaut {get_version()}')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging (also prints to stderr)')
    parser.add_argument('--config', type=str, default=None,
                        help='Config file for the TUI (default: ~/.servonaut/config.json); '
                             'other runtime files keep their usual location')
    parser.add_argument('--update', action='store_true',
                        help='Check for updates and upgrade if available')
    parser.add_argument('--install-desktop', action='store_true',
                        help='Create a desktop shortcut for your OS')
    parser.add_argument('--demo', action='store_true',
                        help='Demo mode: redact IPs, names, and identifiers for screenshots. '
                             'Toggle at runtime with Ctrl+Shift+D. See docs/demo-mode.md for details.')
    parser.add_argument('--mcp', action='store_true',
                        help='Start MCP server (stdio transport)')
    parser.add_argument('--mcp-install', type=str, nargs='?', const='claude',
                        metavar='TARGET',
                        help='Install MCP server into a coding agent '
                             '(claude, opencode, cursor, windsurf, vscode, '
                             'codex, agy, gemini, all)')
    parser.add_argument('--list-backups', action='store_true',
                        help='List local config backups and exit')
    parser.add_argument('--restore-backup', type=int, metavar='N', nargs='?', const=-1,
                        help='Restore a local config backup by index (1=newest). '
                             'With no argument, prompts interactively.')
    parser.add_argument('--ai-provider', type=str, default=None,
                        metavar='NAME',
                        help='Override AI provider for this process '
                             '(servonaut/openai/anthropic/ollama/gemini). '
                             'Bypasses ai.provider_preference; not persisted.')
    parser.add_argument('--no-tools', action='store_true',
                        help='Disable tool execution for AI chat '
                             '(sets allow_tools:false).')

    subparsers = parser.add_subparsers(dest='subcommand')
    connect_parser = subparsers.add_parser(
        'connect',
        help=('Keep your CLI online so AI agents and team-mates can dispatch '
              'MCP tool calls to this machine. Stays running until stopped; '
              'use --bg to detach.'),
    )
    connect_group = connect_parser.add_mutually_exclusive_group()
    connect_group.add_argument('--bg', action='store_true',
                               help='Run relay listener in the background')
    connect_group.add_argument('--stop', action='store_true',
                               help='Stop a background relay listener')
    connect_group.add_argument('--status', action='store_true',
                               help='Show local + backend view of the relay listener')
    connect_group.add_argument('--reconnect', action='store_true',
                               help='Stop a stale background listener (if any) and '
                                    'start a fresh one')
    connect_group.add_argument('--force-bg', dest='force_bg', action='store_true',
                               help=("Detach the TUI's in-process listener (if any) "
                                     'and start a background listener in its place'))

    # ---- memory subcommand ----
    memory_parser = subparsers.add_parser(
        'memory',
        help='Manage per-server memory (probe, show, pin, annotate, export, clear).',
    )
    memory_sub = memory_parser.add_subparsers(dest='memory_command')
    memory_sub.required = True

    # memory build
    mem_build = memory_sub.add_parser(
        'build',
        help='Probe and store server facts for an instance (or all instances with --all).',
    )
    mem_build.add_argument('instance', nargs='?', help='Instance name or ID.')
    mem_build.add_argument('--all', action='store_true',
                           help='Probe all known instances (up to 5 concurrent).')
    mem_build.add_argument('--modules', nargs='+', metavar='MODULE',
                           help='Specific modules to probe (default: all).')
    mem_build.add_argument('--json', action='store_true',
                           help='Output results as JSON.')

    # memory refresh
    mem_refresh = memory_sub.add_parser(
        'refresh',
        help='Re-probe all (or selected) modules for an instance. '
             'Always re-probes regardless of TTL freshness.',
    )
    mem_refresh.add_argument('instance', help='Instance name or ID.')
    mem_refresh.add_argument('--modules', nargs='+', metavar='MODULE',
                             help='Specific modules to refresh (default: all).')

    # memory show
    mem_show = memory_sub.add_parser(
        'show',
        help='Display stored memory for an instance.',
    )
    mem_show.add_argument('instance', help='Instance name or ID.')
    mem_show.add_argument('--format', choices=['summary', 'markdown', 'json'],
                          default='summary',
                          help='Output format (default: summary).')
    mem_show.add_argument('--stale', action='store_true',
                          help='With --format json: emit only stale modules. '
                               'With summary/markdown: same as full output (all modules shown).')
    mem_show.add_argument('--module', metavar='NAME',
                          help='Show a single named module only.')

    # memory export
    mem_export = memory_sub.add_parser(
        'export',
        help='Write the memory summary to a Markdown file.',
    )
    mem_export.add_argument('instance', help='Instance name or ID.')
    mem_export.add_argument('--out', metavar='PATH',
                            help='Output path (default: ~/.servonaut/memory/<provider>/<id>/summary.md).')

    # memory annotate
    mem_annotate = memory_sub.add_parser(
        'annotate',
        help='Open the annotations file for an instance in $VISUAL/$EDITOR/vi.',
    )
    mem_annotate.add_argument('instance', help='Instance name or ID.')

    # memory pin
    mem_pin = memory_sub.add_parser(
        'pin',
        help='Pin a declared value for a field in a memory module.',
    )
    mem_pin.add_argument('instance', help='Instance name or ID.')
    mem_pin.add_argument('dot_expr', metavar='module.field',
                         help='Dot-separated module and field, e.g. "os.arch".')
    mem_pin.add_argument('value', help='Value to pin.')

    # memory clear
    mem_clear = memory_sub.add_parser(
        'clear',
        help='Delete stored memory for an instance.',
    )
    mem_clear.add_argument('instance', help='Instance name or ID.')
    mem_clear.add_argument('--modules', nargs='+', metavar='MODULE',
                           help='Specific modules to clear (default: all).')
    mem_clear.add_argument('--all', action='store_true',
                           help='Clear all modules (same as omitting --modules).')

    # memory purge — wipes module files + index entries across the whole
    # store (or for one instance).  Distinct from `memory clear` which
    # only clears module data for one instance and leaves the index row.
    mem_purge = memory_sub.add_parser(
        'purge',
        help='Wipe locally-stored memory + index entries (irreversible).',
    )
    purge_target = mem_purge.add_mutually_exclusive_group(required=True)
    purge_target.add_argument(
        '--instance',
        metavar='ID_OR_NAME',
        help='Purge memory + index entry for this instance only.',
    )
    purge_target.add_argument(
        '--all', action='store_true',
        help='Purge memory + index for EVERY instance (use with care).',
    )
    mem_purge.add_argument(
        '--yes', '-y', action='store_true',
        help='Skip the typed-confirmation prompt.',
    )

    # memory pull
    mem_pull = memory_sub.add_parser(
        'pull',
        help='Pull annotations from Memory Sync server and write back to local store.',
    )
    mem_pull.add_argument('instance', help='Instance name or ID.')

    # memory reset-prompts — T11
    memory_sub.add_parser(
        'reset-prompts',
        help=(
            'Reset the first-connect memory-build prompt counter so the '
            'TUI banner re-appears after your next successful SSH connect.'
        ),
    )

    # ---- ai subcommand ----
    from servonaut.cli.ai import add_ai_parser, handle_ai_command
    add_ai_parser(subparsers)

    # ---- hetzner subcommand ----
    from servonaut.cli.hetzner import add_hetzner_parser, handle_hetzner_command
    add_hetzner_parser(subparsers)

    # ---- secrets subcommand ----
    from servonaut.cli.secrets import add_secrets_parser, handle_secrets_command
    add_secrets_parser(subparsers)

    # ---- ssh subcommand (BW Password Manager SSH integration) ----
    from servonaut.cli.ssh import add_ssh_parser, handle_ssh_command
    add_ssh_parser(subparsers)

    # ---- servers subcommand (verify, etc.) ----
    from servonaut.cli.servers import add_servers_parser, handle_servers_command
    add_servers_parser(subparsers)

    # ---- db subcommand (DB credential setup for db_processlist/db_top_queries) ----
    from servonaut.cli.db import add_db_parser
    add_db_parser(subparsers)

    # ---- login / logout subcommands (headless device-flow sign-in) ----
    from servonaut.cli.login import add_login_parser, add_logout_parser
    add_login_parser(subparsers)
    add_logout_parser(subparsers)

    args = parser.parse_args()

    # Top-level --ai-provider / --no-tools flags propagate via env vars so
    # the chat-panel TUI (and any subcommand) reads them without a side
    # channel. ``setdefault`` ensures the user can pre-set these in their
    # shell environment without the CLI flags overriding them silently.
    if getattr(args, 'ai_provider', None):
        os.environ.setdefault('SERVONAUT_AI_PROVIDER', args.ai_provider)
    if getattr(args, 'no_tools', False):
        os.environ.setdefault('SERVONAUT_AI_NO_TOOLS', '1')

    if getattr(args, 'subcommand', None) == 'ai':
        _setup_logging(debug=args.debug)
        sys.exit(handle_ai_command(args))

    if getattr(args, 'subcommand', None) == 'hetzner':
        _setup_logging(debug=args.debug)
        sys.exit(handle_hetzner_command(args))

    if getattr(args, 'subcommand', None) == 'secrets':
        _setup_logging(debug=args.debug)
        sys.exit(handle_secrets_command(args))

    if getattr(args, 'subcommand', None) == 'ssh':
        _setup_logging(debug=args.debug)
        sys.exit(handle_ssh_command(args))

    if getattr(args, 'subcommand', None) == 'servers':
        _setup_logging(debug=args.debug)
        sys.exit(handle_servers_command(args))

    if getattr(args, 'subcommand', None) == 'db':
        _setup_logging(debug=args.debug)
        from servonaut.cli.db import handle_db_command
        sys.exit(handle_db_command(args))

    if getattr(args, 'subcommand', None) == 'memory':
        _setup_logging(debug=args.debug)
        from servonaut.cli.memory import run_memory
        sys.exit(run_memory(args))

    if getattr(args, 'subcommand', None) == 'login':
        _setup_logging(debug=args.debug)
        from servonaut.cli.login import handle_login_command
        sys.exit(handle_login_command(args))

    if getattr(args, 'subcommand', None) == 'logout':
        _setup_logging(debug=args.debug)
        from servonaut.cli.login import handle_logout_command
        sys.exit(handle_logout_command(args))

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

    _setup_logging(debug=args.debug)

    from servonaut.app import ServonautApp
    from servonaut.runtime import detect_runtime
    from servonaut.utils.native_stderr import redirect_native_stderr
    runtime_layout = detect_runtime()
    app = ServonautApp(
        config_path=Path(args.config) if args.config else None,
        runtime_layout=runtime_layout,
    )
    if args.demo:
        app.demo_mode = True
    # Native libraries (speech synthesis, PortAudio/ALSA) write straight
    # to fd 2 from C code, which Textual cannot capture — without this
    # their diagnostics scribble over the interface. Skipped under
    # --debug, where seeing everything on the terminal is the point.
    if args.debug:
        app.run()
    else:
        native_log = runtime_layout.data_root / "logs" / "native_stderr.log"
        with redirect_native_stderr(native_log):
            app.run()

if __name__ == '__main__':
    main()
