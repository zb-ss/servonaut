"""Prove the built wrappers participate in the real Applications gate in CI."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import fcntl
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from scripts.standalone_cli.smoke_artifact import isolated_child_environment
from servonaut.updates.macos_native import EXECUTABLES, WORKER_SUFFIX, native_command
from servonaut.updates.macos_transaction import BUNDLE_NAME, rename_native


def _check_wrappers(bundle: Path, fd: int, home: Path) -> None:
    environment = isolated_child_environment(home)
    executables = bundle / "Contents" / "MacOS"
    proc_path = ctypes.CDLL("libproc.dylib").proc_pidpath
    proc_path.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
    proc_path.restype = ctypes.c_int

    def in_executable(process, name):
        buffer = ctypes.create_string_buffer(4096)
        return proc_path(process.pid, buffer, len(buffer)) > 0 and Path(os.fsdecode(buffer.value)).name == name

    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        for name in EXECUTABLES:
            with subprocess.Popen(
                [executables / name, "--version"], cwd=home, env=environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ) as process:
                try:
                    process.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    at_wrapper = in_executable(process, name)
                    process.kill()
                    if not at_wrapper:
                        raise RuntimeError(f"{name} reached its worker while application admission was exclusive")
                else:
                    raise RuntimeError(f"{name} ran while application admission was exclusive")
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)

    with subprocess.Popen(
        [executables / "servonaut", "--version"], cwd=home, env=environment,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ) as process:
        try:
            deadline = time.monotonic() + 10
            while process.poll() is None and time.monotonic() < deadline:
                if not in_executable(process, "servonaut" + WORKER_SUFFIX):
                    time.sleep(0.02)
                    continue
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    if process.wait(timeout=15) != 0:
                        raise RuntimeError("The guarded console could not start")
                    return
                else:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                time.sleep(0.02)
            raise RuntimeError("The real frozen console did not hold shared admission")
        finally:
            if process.poll() is None:
                process.kill()


def qualify_applications_gate(source: Path) -> None:
    parent = Path("/Applications")
    target = parent / BUNDLE_NAME
    if os.path.lexists(target):
        raise RuntimeError("Refusing to replace an existing application in the CI fixture")
    with tempfile.TemporaryDirectory(dir=parent, prefix=".servonaut-admission-check-") as scratch:
        prepared = Path(scratch) / BUNDLE_NAME
        native_command("/usr/bin/ditto", "--rsrc", "--extattr", "--acl", source, prepared, timeout=180)
        identity = prepared.lstat()
        rename_native(prepared, target)
        try:
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                home = Path(scratch) / "home"
                home.mkdir()
                _check_wrappers(target, fd, home)
            finally:
                os.close(fd)
        finally:
            with contextlib.suppress(FileNotFoundError):
                if os.path.samestat(identity, target.lstat()):
                    shutil.rmtree(target)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path)
    qualify_applications_gate(parser.parse_args().app)
