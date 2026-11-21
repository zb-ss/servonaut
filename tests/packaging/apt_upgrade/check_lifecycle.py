"""Prove payload leases, late resource isolation, fallback copying and collection."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from servonaut.desktop.process_tree import spawn_desktop_child
from servonaut.debian_layout import CONTROL_ROOT
from servonaut.runtime import detect_runtime, validate_launch_argv
from servonaut.services.apt_runtime import AptBuildIdentity, AptChange, DpkgPackageState, inspect_apt_upgrade

from tests.packaging.apt_upgrade.archive import SignedArchive, run
from tests.packaging.apt_upgrade.sessions import LAUNCHER, ROOT, TIMEOUT, read_until, stop


def status() -> dict:
    return json.loads((ROOT / "status.json").read_bytes())


def dpkg_state(package: str) -> DpkgPackageState:
    status, version = run([
        "dpkg-query", "-W", "-f=${db:Status-Status}\t${Version}", package,
    ]).decode().split("\t")
    return DpkgPackageState(status, version)


def original_identity(original: Path) -> AptBuildIdentity:
    image = original.stat()
    return AptBuildIdentity("1.0.1", "fixture-1", 1, (image.st_dev, image.st_ino))


def probe(child: subprocess.Popen, revision: int) -> None:
    child.stdin.write(b"probe\n")
    child.stdin.flush()
    response = read_until(child.stdout.fileno(), lambda data: b"\n" in data)
    assert json.loads(response) == {
        "python": revision, "native": revision,
        "stylesheet": f"Label {{ padding: {revision}; }}", "data": f"data-{revision}",
    }, response


def wait_for_native_image(child: subprocess.Popen, executable: Path) -> None:
    proc_image = Path("/proc") / str(child.pid) / "exe"
    deadline = time.monotonic() + TIMEOUT
    while child.poll() is None and time.monotonic() < deadline:
        try:
            if proc_image.readlink() == executable.resolve():
                return
        except FileNotFoundError:
            pass
        time.sleep(0.05)
    raise AssertionError("Native fixture did not load its generation executable")


def probe_root_maintenance() -> None:
    lock = CONTROL_ROOT / "servonaut.lock"
    assert CONTROL_ROOT.stat().st_mode & 0o777 == 0o700 and CONTROL_ROOT.stat().st_uid == 0
    assert lock.stat().st_mode & 0o777 == 0o600 and lock.stat().st_uid == lock.stat().st_gid == 0
    user_can_read = subprocess.run(["/usr/bin/test", "-r", str(lock)], user="nobody", timeout=5)
    assert user_can_read.returncode == 1
    helper = "/usr/libexec/servonaut/apt-generation"
    with lock.open("rb") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        subprocess.run([helper, "prune"], check=True, timeout=5)
        busy = subprocess.run([helper, "activate"], capture_output=True, text=True, timeout=5)
        assert busy.returncode == 1 and "maintenance is busy" in busy.stderr
    print("PASS root-only maintenance lock rejects user access and never waits behind root maintenance")


def launch(command: list[str], env: dict[str, str], processes: ExitStack) -> subprocess.Popen:
    child = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, user="nobody",
    )
    processes.callback(stop, child)
    assert read_until(child.stdout.fileno(), lambda data: b"\n" in data) == b"ready\n"
    return child


def check(archive: SignedArchive, packages: Path, home: Path, expect_copy: bool) -> None:
    def install(version: str, *options: str) -> dict:
        archive.offer(packages / f"servonaut_{version}_amd64.deb")
        archive.install(version, *options)
        return status()

    initial = install("1.0.1")
    probe_root_maintenance()
    original = ROOT / initial["current"]
    original_image = original / "servonaut"
    running = original_identity(original_image)
    with patch.object(sys, "executable", str(original_image)):
        runtime = detect_runtime()
    mcp_command = validate_launch_argv(runtime.mcp_argv(), runtime=runtime)
    assert mcp_command == ["/opt/servonaut/servonaut", "--mcp"]
    same = inspect_apt_upgrade(original_image, running, dpkg_state)
    assert same.change is AptChange.UNCHANGED and same.installed == running
    marker = ROOT.parent / "servonaut-runtime.json"
    backup = home / "original-marker"
    marker.rename(backup)
    try:
        assert inspect_apt_upgrade(original_image, running, dpkg_state).change is AptChange.DEFERRED
        marker.write_text("{", encoding="utf-8")
        assert inspect_apt_upgrade(original_image, running, dpkg_state).change is AptChange.DEFERRED
    finally:
        backup.replace(marker)
    if expect_copy:
        assert initial["copied_bytes"] > 0 and initial["unconsolidated_bytes"] > 0
        assert same.unconsolidated_bytes == initial["unconsolidated_bytes"]
        assert same.allocated_bytes == initial["allocated_bytes"]
        assert install("1.0.1", "--reinstall")["copied_bytes"] == initial["copied_bytes"]
        print(f"PASS fallback storage reports {initial['allocated_bytes']} allocated bytes")
    else:
        assert initial["copied_bytes"] == initial["unconsolidated_bytes"] == 0
        # Interrupted work is discarded before preparing another generation.
        (ROOT / ".prepare-interrupted").mkdir()
        (ROOT / ".status-interrupted").touch()
    (ROOT / ".retired-interrupted").mkdir()

    with ExitStack() as processes:
        env = {"PATH": os.defpath, "HOME": str(home)}
        alias = home / "launch-fixture"
        alias.symlink_to(LAUNCHER)
        (ROOT / "status.json").write_text('{"current":"invalid"}')
        live = launch([str(alias)], env, processes)
        install("1.0.1", "--reinstall")
        assert status()["current"] == original.name
        print("PASS alias launches from recovered status and configure repairs the on-disk pointer")
        # Interrupt the package transaction after unpack and before configure.
        next_package = packages / "servonaut_1.0.1-2_amd64.deb"
        run(["dpkg", "--unpack", str(next_package)])
        assert dpkg_state("servonaut").status == "unpacked"
        assert inspect_apt_upgrade(original_image, running, dpkg_state).change is AptChange.DEFERRED
        assert status()["current"] == original.name
        second = install("1.0.1-2")
        assert second["previous"] == original.name
        changed = inspect_apt_upgrade(original_image, running, dpkg_state)
        assert changed.change is AptChange.RESTART_REQUIRED
        assert changed.installed and changed.installed.product_version == running.product_version
        assert changed.installed.packaging_revision == 2
        print("PASS missing, partial and unpacked state defers; a configured same-version rebuild needs restart")
        assert not (ROOT / ".prepare-interrupted").exists()
        assert not (ROOT / ".status-interrupted").exists()
        assert not (ROOT / ".retired-interrupted").exists()

        # A direct child launch must keep its lease even after its parent exits.
        # The fixture script's actual /proc/exe is Python, and it has not loaded
        # the late resource files, so the procfs fallback cannot retain it.
        with patch.object(sys, "executable", str(original_image)):
            owned = spawn_desktop_child(["/opt/servonaut/servonaut-desktop-child"], env=env)
        processes.callback(owned.close)
        processes.callback(owned.terminate)
        descendant = owned.process
        assert read_until(descendant.stdout.fileno(), lambda data: b"\n" in data) == b"ready\n"

        # Contention on the public lease must not delay a launch or dpkg.
        lease = ROOT / second["current"] / ".lease"
        with lease.open("rb") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            contended = launch([LAUNCHER], env, processes)
            probe(contended, 2)
            stop(contended)
            third = install("1.0.3")
        assert third["previous"] == second["current"]
        assert (ROOT / second["current"]).is_dir()
        assert original.is_dir()
        probe(live, 1)
        print("PASS active oldest generation retained through two verified upgrades and delayed loads")

        current = launch([LAUNCHER], env, processes)
        probe(current, 3)
        print("PASS a busy lease does not delay launch and a new launch sees the configured generation")

        stop(live)
        # With the original process gone, an automatic cleanup must preserve
        # the direct child's lease even before that child has mapped resources.
        run(["/usr/libexec/servonaut/apt-generation", "prune"])
        assert original.is_dir()
        probe(descendant, 1)
        print("PASS direct desktop child retains the old generation after the original session exits")
        owned.terminate()

        native_executable = original / "native-session"
        native = subprocess.Popen([str(native_executable)], env=env)
        processes.callback(stop, native)
        wait_for_native_image(native, native_executable)
        run(["/usr/libexec/servonaut/apt-generation", "prune"])
        assert original.is_dir() and native.poll() is None
        print("PASS procfs retains a native old generation with no inherited lease")

    fourth = install("1.0.4")
    assert fourth["previous"] == third["current"]
    assert not original.exists() and not (ROOT / second["current"]).exists()
    print("PASS next upgrade collects inactive older generations")
    with subprocess.Popen(
        mcp_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, user="nobody",
    ) as later_mcp:
        try:
            assert read_until(later_mcp.stdout.fileno(), lambda data: b"\n" in data) == b"ready\n"
            probe(later_mcp, 4)
        finally:
            stop(later_mcp)
    print("PASS saved MCP command still starts a new generation after collection")
    with ExitStack() as processes:
        live = launch([LAUNCHER], env, processes)
        run(["dpkg", "--remove", "servonaut"])
        assert inspect_apt_upgrade(original_image, running, dpkg_state).change is AptChange.REMOVED
        assert {path.name for path in ROOT.iterdir()} == {fourth["current"]}
        probe(live, 4)
    install("1.0.4")
    run(["dpkg", "--remove", "servonaut"])
    assert not ROOT.exists() or not list(ROOT.iterdir())
    print("PASS removal keeps only leased generations and removes all unused payloads")

    install("1.0.4")
    archive.offer(packages / "servonaut_1.0.0_amd64.deb")
    archive.install("1.0.0", "--allow-downgrades")
    assert not ROOT.exists() or not list(ROOT.iterdir())
    assert not (ROOT.parent / "servonaut").is_symlink()
    print("PASS downgrade to a pre-generation package removes the unused generation store")


def main() -> None:
    if not Path("/.dockerenv").is_file() or os.geteuid() != 0:
        raise SystemExit("Run the lifecycle fixture as root inside its disposable container")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages", type=Path)
    parser.add_argument("--expect-copy", action="store_true")
    parser.add_argument("--symlink-opt", action="store_true")
    args = parser.parse_args()
    if args.symlink_opt:
        mounted_apps = Path("/mnt/application-storage")
        mounted_apps.mkdir()
        Path("/opt").rmdir()
        Path("/opt").symlink_to(mounted_apps)
    os.environ["DEBIAN_FRONTEND"] = "noninteractive"
    with tempfile.TemporaryDirectory(prefix="apt-generation-lifecycle-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        config = root / "fixture-config"
        config.write_bytes(b"fixture user configuration\n")
        archive = SignedArchive(root)
        try:
            check(archive, args.packages, root, args.expect_copy)
            run(["dpkg", "--purge", "servonaut"])
            assert not ROOT.exists() or not tuple(ROOT.iterdir())
            assert config.read_bytes() == b"fixture user configuration\n"
            print("PASS purge clears generation content and preserves fixture configuration")
        finally:
            archive.close()


if __name__ == "__main__":
    main()
