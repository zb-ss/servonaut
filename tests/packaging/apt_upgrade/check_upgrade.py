"""Exercise one signed APT upgrade with real packaged sessions in flight."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import tempfile
from contextlib import AsyncExitStack, ExitStack
from pathlib import Path

from tests.packaging.apt_upgrade.archive import SignedArchive, debian_version, run
from tests.packaging.apt_upgrade.sessions import (
    LAUNCHER, ROOT, Mcp, Relay, desktop, gui, open_settings, ping, require_generation,
    desktop_output, environment, read_until, require_native_path, restart_desktop_child,
    restart_terminal, tui,
)


def status() -> dict:
    return json.loads((ROOT / "status.json").read_bytes())


async def check_source_runtime(processes, connections, root: Path, home: Path, env: dict[str, str], version: str) -> None:
    await asyncio.to_thread(
        subprocess.run, [LAUNCHER, "--mcp-install", "claude"],
        env=env, capture_output=True, check=True, timeout=25,
    )
    installed = json.loads((home / ".claude.json").read_bytes())["mcpServers"]["servonaut"]
    assert installed["command"] == "/opt/servonaut/servonaut" and installed["args"] == ["--mcp"]
    relay = Relay()
    try:
        await relay.start(processes, connections, root / "source-relay-home")
        await relay.report(version, require_header=True)
    finally:
        relay.closed.set()
    print("PASS fresh packaged CLI persists a stable MCP command and its relay sends the client identity", flush=True)


async def check(
    archive: SignedArchive, root: Path, old: Path, new: Path, *,
    native_gui: bool, verify_pr_source: bool, verify_restart: bool,
) -> None:
    before_version = debian_version(old)
    after_version = debian_version(new)
    archive.offer(old)
    archive.install(before_version)
    initial = status()
    original = initial["current"]
    original_marker = json.loads((ROOT / original / "servonaut-runtime.json").read_bytes())
    relay = Relay()
    with ExitStack() as processes:
        async with AsyncExitStack() as connections:
            try:
                terminal, master = await asyncio.to_thread(tui, processes, root / "tui-home")
                mcp = await asyncio.to_thread(Mcp, processes, root / "mcp-home")
                child, ws = await desktop(processes, connections, root / "desktop-home")
                listener, config = await relay.start(processes, connections, root / "relay-home")
                old_window = await asyncio.to_thread(gui, processes, root / "old-window", original) if native_gui else None
                relay_id = await relay.report(original_marker["product_version"])
                config_bytes = config.read_bytes()
                roles = [terminal, mcp.proc, child, listener]
                require_generation(roles, original)
                print("PASS TUI, MCP, desktop child and relay use the configured candidate generation", flush=True)

                await asyncio.to_thread(archive.offer, new)
                await asyncio.to_thread(archive.install, after_version)
                promoted = status()
                assert promoted["current"] != original and promoted["previous"] == original
                assert promoted["unconsolidated_bytes"] == 0
                require_generation(roles, original)
                print("PASS signed APT upgrade preserves all four running executable paths", flush=True)
                if verify_restart:
                    await asyncio.gather(
                        asyncio.to_thread(read_until, master, lambda data: b"Restart to update" in data),
                        desktop_output(ws, b"Servonaut was updated"),
                    )
                if old_window is not None:
                    require_native_path(old_window[0], ROOT / original / "servonaut-desktop")
                    require_native_path(old_window[1], ROOT / original / "servonaut-desktop-child")
                    await asyncio.to_thread(gui, processes, root / "new-window", promoted["current"])
                    print("PASS open GUI and its child keep the old generation; a new GUI spawns its new child", flush=True)

                await ping(ws, "after")
                tools = await asyncio.to_thread(mcp.call, "tools/list")
                assert any(tool["name"] == "whoami" for tool in tools["tools"])
                while not relay.received.empty():
                    relay.received.get_nowait()
                assert await relay.report(original_marker["product_version"]) == relay_id
                assert config.read_bytes() == config_bytes
                print("PASS same desktop WebSocket, MCP stdio and relay identity after upgrade", flush=True)

                await asyncio.to_thread(open_settings, master)
                require_generation(roles, original)
                print("PASS existing TUI opens Settings after upgrade", flush=True)

                fresh = root / "new-home"
                env = environment(fresh)
                new_marker = json.loads((ROOT / promoted["current"] / "servonaut-runtime.json").read_bytes())
                output = subprocess.run([LAUNCHER, "--version"], env=env, capture_output=True, timeout=25, check=True)
                assert new_marker["product_version"].encode() in output.stdout, output.stdout
                print(f"PASS new launcher uses {new_marker['product_version']}; config bytes preserved", flush=True)
                if verify_pr_source:
                    await check_source_runtime(processes, connections, root, fresh, env, new_marker["product_version"])
                if verify_restart:
                    await asyncio.gather(
                        asyncio.to_thread(restart_terminal, terminal, master, promoted["current"]),
                        restart_desktop_child(child, ws),
                    )
                    require_generation([mcp.proc, listener], original)
                    assert config.read_bytes() == config_bytes
                    print("PASS deliberate TUI exec and desktop child hand-off preserve other sessions", flush=True)
                    update = await asyncio.to_thread(
                        subprocess.run, [LAUNCHER, "--update"], env=env, capture_output=True, timeout=25, check=True,
                    )
                    assert b"sudo apt update && sudo apt install --only-upgrade servonaut" in update.stdout
                    print("PASS generation CLI detects the configured APT source without running apt", flush=True)
            finally:
                relay.closed.set()


def main() -> None:
    if not Path("/.dockerenv").is_file() or os.geteuid() != 0:
        raise SystemExit("Run the upgrade fixture as root inside its disposable Ubuntu container")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--native-gui", action="store_true")
    parser.add_argument("--verify-pr-source", action="store_true")
    parser.add_argument("--verify-restart", action="store_true")
    args = parser.parse_args()
    os.environ["DEBIAN_FRONTEND"] = "noninteractive"
    with tempfile.TemporaryDirectory(prefix="servonaut-apt-upgrade-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        archive = SignedArchive(root)
        try:
            if args.verify_restart:
                # The fixture archive uses its own list and source overrides.
                # The app reads this official-style entry as local configuration evidence.
                keyring = Path("/usr/share/keyrings/servonaut-upgrade-fixture.gpg")
                shutil.copyfile(root / "fixture-archive.gpg", keyring)
                Path("/etc/apt/sources.list.d/servonaut-upgrade-fixture.sources").write_text(
                    "Types: deb\nURIs: https://releases.servonaut.dev/apt/\nSuites: stable\n"
                    f"Components: main\nArchitectures: amd64\nSigned-By: {keyring}\n",
                    encoding="utf-8",
                )
            asyncio.run(check(
                archive, root, args.before, args.after,
                native_gui=args.native_gui or args.verify_pr_source, verify_pr_source=args.verify_pr_source,
                verify_restart=args.verify_restart,
            ))
            run(["dpkg", "--purge", "servonaut"])
            assert not ROOT.exists()
            assert (root / "relay-home" / ".servonaut" / "config.json").is_file()
            print("PASS purge removes retained payloads and preserves fixture configuration", flush=True)
        finally:
            archive.close()


if __name__ == "__main__":
    main()
