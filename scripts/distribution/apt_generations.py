#!/usr/bin/python3 -I
"""Maintain and launch immutable Debian payload generations on Linux."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from itertools import islice
from pathlib import Path

# BEGIN DEBIAN LAYOUT IMPORT
from servonaut.debian_layout import (
    CONTROL_ROOT, GENERATION, GENERATIONS, HELPER_ROOT, INSTALL_ROOT, LEASE,
    MARKER, MAX_STATUS_BYTES, PACKAGE_NAME, PAYLOAD, RESTART_GENERATION_ENV, ROLES, STATUS, acquire_shared_lease,
    invocation_role,
)
# END DEBIAN LAYOUT IMPORT

LINK_SCRATCH = ".staging-links"
LINK_UNAVAILABLE = {errno.EXDEV, errno.EMLINK, errno.EOPNOTSUPP, errno.ENOSYS, errno.EPERM}


@dataclass(frozen=True)
class Entry:
    """One package-owned payload file, link or directory."""

    relative: Path
    source: Path
    mode: int
    digest: str = ""
    target: str = ""
    owner: tuple[int, int] = (0, 0)
    attributes: tuple[tuple[str, str], ...] = ()

    @property
    def file_identity(self) -> tuple:
        return self.digest, self.mode, self.owner, self.attributes

    @property
    def description(self) -> tuple:
        return (self.relative.as_posix(), self.file_identity, self.target)


def secure(path: Path) -> os.stat_result:
    """Accept only package-owned paths without non-root write permission."""
    info = path.lstat()
    if info.st_uid != 0 or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
        raise ValueError(f"Unsafe Servonaut package file: {path.name}")
    return info


def inspect_entry(relative: Path, path: Path, root: Path) -> Entry:
    info = secure(path)
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(path)
        if os.path.isabs(target) or not (path.parent / target).resolve().is_relative_to(root):
            raise ValueError(f"Servonaut payload link escapes its generation: {relative}")
        return Entry(relative, path, info.st_mode, target=target)
    if stat.S_ISDIR(info.st_mode):
        return Entry(relative, path, info.st_mode)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Unsupported Servonaut payload file: {relative}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    attributes = tuple(
        (name, os.getxattr(path, name).hex()) for name in sorted(os.listxattr(path))
    )
    return Entry(relative, path, info.st_mode, digest.hexdigest(),
                 owner=(info.st_uid, info.st_gid), attributes=attributes)


def walk(root: Path) -> Iterator[Entry]:
    def descend(directory: Path) -> Iterator[Entry]:
        for path in sorted(directory.iterdir()):
            item = inspect_entry(path.relative_to(root), path, root)
            yield item
            if stat.S_ISDIR(item.mode):
                yield from descend(path)

    if not stat.S_ISDIR(secure(root).st_mode):
        raise ValueError("Servonaut payload root must be a directory")
    yield from descend(root)


def packaged_payload(root: Path) -> list[Entry]:
    staging = root / PAYLOAD
    entries = list(walk(staging))
    paths = {item.relative for item in entries if item.digest and item.mode & stat.S_IXUSR}
    if any(Path(role) not in paths for role in ROLES):
        raise ValueError("Servonaut payload is missing an executable")
    marker = inspect_entry(Path(MARKER), root / MARKER, root)
    if not marker.digest:
        raise ValueError("Servonaut runtime marker must be a regular file")
    if any(item.relative in (Path(MARKER), Path(LEASE)) for item in entries):
        raise ValueError("Servonaut payload names reserved generation files")
    return [*entries, marker]


def generation_id(entries: Sequence[Entry]) -> str:
    records = [entry.description for entry in sorted(entries, key=lambda entry: entry.relative)]
    return hashlib.sha256(json.dumps(records, separators=(",", ":")).encode()).hexdigest()


def read_status(store: Path) -> dict:
    status_path = store / STATUS
    descriptor = os.open(status_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("Invalid Servonaut generation status file")
        data = handle.read(MAX_STATUS_BYTES + 1)
    if len(data) > MAX_STATUS_BYTES:
        raise ValueError("Servonaut generation status exceeds its size limit")
    status = json.loads(data)
    if not isinstance(status, dict) or status.get("schema_version") != 1 or any(
        not isinstance(status.get(role), str) or status[role] and not GENERATION.fullmatch(status[role])
        for role in ("current", "previous")
    ):
        raise ValueError("Invalid Servonaut generation status")
    if type(status.get("copied_bytes")) is not int or status["copied_bytes"] < 0:
        raise ValueError("Invalid Servonaut copy total")
    return status


def sync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_status(store: Path, status: dict) -> None:
    with tempfile.NamedTemporaryFile(mode="w", dir=store, prefix=".status-", delete=False) as out:
        pending = Path(out.name)
        try:
            json.dump(status, out, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fchmod(out.fileno(), 0o644)
            os.fsync(out.fileno())
            os.replace(pending, store / STATUS)
            sync_directory(store)
        finally:
            pending.unlink(missing_ok=True)


def make_directory(path: Path, mode: int) -> None:
    path.mkdir(mode=mode, exist_ok=True)
    if not stat.S_ISDIR(secure(path).st_mode):
        raise ValueError(f"Invalid Servonaut directory: {path.name}")
    path.chmod(mode)


@contextmanager
def maintenance(root: Path) -> Iterator[Path]:
    make_directory(CONTROL_ROOT, 0o700)
    lock_path = CONTROL_ROOT / f"{root.name}.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or (info.st_uid, info.st_gid) != (0, 0):
            raise ValueError("Invalid Servonaut maintenance lock")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise BlockingIOError("Servonaut generation maintenance is busy") from error
        store = root / GENERATIONS
        yield store
    finally:
        os.close(descriptor)


def remove_interrupted_files(store: Path) -> None:
    for path in store.iterdir():
        try:
            if path.name.startswith((".prepare-", ".retired-")) and path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.name.startswith(".status-"):
                path.unlink(missing_ok=True)
        except OSError as error:
            print(f"Servonaut deferred interrupted-file cleanup: {error}", file=sys.stderr)
    sync_directory(store)


def generations(store: Path) -> Iterator[Path]:
    for directory in sorted(store.iterdir()):
        if GENERATION.fullmatch(directory.name):
            try:
                if stat.S_ISDIR(secure(directory).st_mode):
                    yield directory
            except (OSError, ValueError):
                continue


def valid_generation(directory: Path) -> bool:
    try:
        if not launchable(directory):
            return False
        entries = [item for item in walk(directory) if item.relative != Path(LEASE)]
        lease = secure(directory / LEASE)
        return stat.S_ISREG(lease.st_mode) and generation_id(entries) == directory.name
    except (OSError, ValueError, RuntimeError):
        return False


def configured_status(store: Path) -> dict | None:
    try:
        status = read_status(store)
        current, previous = status["current"], status["previous"]
        if current and launchable(store / current) and (
            not previous or previous != current and launchable(store / previous)
        ):
            return status
    except (OSError, ValueError, RecursionError):
        pass
    return None


def marker_inode(path: Path) -> tuple[int, int] | None:
    try:
        info = secure(path)
        if stat.S_ISREG(info.st_mode):
            return info.st_dev, info.st_ino
    except (OSError, ValueError):
        pass
    return None


def verified_candidates(store: Path, marker: tuple[int, int] | None) -> Iterator[Path]:
    """Try the configured marker's generation first, then other retained builds."""
    ranked = []
    for item in generations(store):
        try:
            linked = marker is not None and marker_inode(item / MARKER) == marker
            ranked.append((linked, item.stat().st_mtime_ns, item))
        except OSError:
            continue  # a concurrent collector already retired it
    for _, _, item in sorted(ranked, reverse=True):
        if valid_generation(item):
            yield item


def recover_status(store: Path) -> dict:
    """Use retained complete generations when the cached pointer cannot be read."""
    status = configured_status(store)
    if status is not None:
        return status
    candidates = verified_candidates(store, marker_inode(store.parent / MARKER))
    names = [item.name for item in islice(candidates, 2)] + ["", ""]
    return {"current": names[0], "previous": names[1], "copied_bytes": 0}


def launchable(directory: Path) -> bool:
    names = (*ROLES, LEASE, MARKER)
    return directory.is_dir() and all((directory / name).is_file() for name in names)


def retained_files(store: Path) -> dict[tuple, Path]:
    retained = {}
    for directory in generations(store):
        try:
            entries = list(walk(directory))
        except (OSError, ValueError, RuntimeError):
            continue
        for item in entries:
            if item.digest and item.relative != Path(LEASE):
                retained[item.file_identity] = item.source
    return retained


def link_or_copy(source: Path, destination: Path) -> int:
    try:
        os.link(source, destination)
        return 0
    except OSError as error:
        if error.errno not in LINK_UNAVAILABLE:
            raise
    info = source.stat()
    shutil.copyfile(source, destination)
    os.chown(destination, info.st_uid, info.st_gid)
    shutil.copystat(source, destination)
    with destination.open("rb") as handle:
        os.fsync(handle.fileno())
        return os.fstat(handle.fileno()).st_blocks * 512


def materialize(store: Path, name: str, entries: Sequence[Entry]) -> int:
    target = store / name
    if target.exists():
        if valid_generation(target):
            return 0
        retire_invalid_generation(target)

    retained = retained_files(store)
    pending = Path(tempfile.mkdtemp(prefix=".prepare-", dir=store))
    copied = 0
    try:
        pending.chmod(0o755)
        for item in entries:
            destination = pending / item.relative
            if item.target:
                destination.symlink_to(item.target)
            elif item.digest:
                source = retained.get(item.file_identity, item.source)
                copied += link_or_copy(source, destination)
                retained[item.file_identity] = destination
            else:
                make_directory(destination, stat.S_IMODE(item.mode))
        lease = pending / LEASE
        lease.touch(mode=0o644, exist_ok=False)
        lease.chmod(0o644)
        for directory, _, _ in os.walk(pending, topdown=False):
            sync_directory(Path(directory))
        pending.rename(target)
        sync_directory(store)
    finally:
        if pending.exists():
            shutil.rmtree(pending)
    return copied


def consolidate(entries: Sequence[Entry], current: Path, scratch: Path) -> int:
    """Make identical package paths share the staged generation's inode."""
    if scratch.exists():
        if not stat.S_ISDIR(secure(scratch).st_mode):
            raise ValueError("Invalid Servonaut staging directory")
        shutil.rmtree(scratch)
    make_directory(scratch, 0o700)
    extra = 0
    pending = scratch / "payload-link"
    try:
        for item in entries:
            if not item.digest:
                continue
            source = current / item.relative
            original = item.source.stat()
            if os.path.samestat(source.stat(), original):
                continue
            try:
                os.link(source, pending)
                os.replace(pending, item.source)
            except OSError as error:
                if error.errno not in LINK_UNAVAILABLE:
                    raise
                extra += original.st_blocks * 512
                pending.unlink(missing_ok=True)
    finally:
        shutil.rmtree(scratch)
    return extra


def mapped_by_process(generation: Path, processes: Path = Path("/proc")) -> bool:
    unresolved = INSTALL_ROOT / generation.parent.parent.name / GENERATIONS / generation.name
    prefixes = tuple(os.fsencode(path) + b"/" for path in {generation, generation.resolve(), unresolved})
    for process in processes.iterdir():
        if not process.name.isdecimal():
            continue
        try:
            if os.fsencode(os.readlink(process / "exe")).startswith(prefixes):
                return True
        except OSError:
            pass
        try:
            with (process / "maps").open("rb") as maps:
                for row in maps:
                    fields = row.split(maxsplit=5)
                    if len(fields) == 6 and fields[5].startswith(prefixes):
                        return True
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            # Procfs visibility restrictions leave the lease as the primary guard.
            continue
    return False


def open_lease(directory: Path):
    descriptor = os.open(directory / LEASE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Invalid Servonaut generation lease")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def retire(directory: Path) -> None:
    store = directory.parent
    retired = Path(tempfile.mkdtemp(prefix=".retired-", dir=store))
    directory.rename(retired / directory.name)
    sync_directory(retired)
    sync_directory(store)
    shutil.rmtree(retired)
    sync_directory(store)


def retire_invalid_generation(directory: Path) -> None:
    try:
        lease = open_lease(directory)
    except (OSError, ValueError):
        lease = None
    try:
        if lease is not None:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if mapped_by_process(directory):
            raise ValueError("An incomplete Servonaut generation is still in use")
        retire(directory)
    finally:
        if lease is not None:
            lease.close()


def prune(store: Path, current: str, previous: str, processes: Path = Path("/proc")) -> None:
    for directory in generations(store):
        if directory.name in (current, previous):
            continue
        try:
            with open_lease(directory) as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if not mapped_by_process(directory, processes):
                    retire(directory)
        except (OSError, ValueError):
            continue


def allocation(*roots: Path) -> int:
    blocks = {}
    for root in roots:
        if root.is_file():
            row = root.stat()
            blocks[(row.st_dev, row.st_ino)] = row.st_blocks * 512
            continue
        for directory, _, files in os.walk(root):
            for name in files:
                row = (Path(directory) / name).lstat()
                if stat.S_ISREG(row.st_mode):
                    blocks[(row.st_dev, row.st_ino)] = row.st_blocks * 512
    return sum(blocks.values())


def activate(root: Path) -> None:
    if not stat.S_ISDIR(secure(root).st_mode):
        raise ValueError("Invalid Servonaut package root")
    with maintenance(root) as store:
        make_directory(store, 0o755)
        remove_interrupted_files(store)
        old = recover_status(store)
        entries = packaged_payload(root)
        name = generation_id(entries)
        copies = materialize(store, name, entries)
        extra = consolidate(entries, store / name, root / LINK_SCRATCH)
        previous = old["previous"] if name == old["current"] else old["current"]
        status = {
            "schema_version": 1, "current": name, "previous": previous,
            "copied_bytes": old["copied_bytes"] + copies, "unconsolidated_bytes": extra,
        }
        total = allocation(root / PAYLOAD, root / MARKER, store)
        write_status(store, {**status, "allocated_bytes": total})
        # Cleanup is best-effort after a successful atomic activation.
        try:
            prune(store, name, previous)
            total = allocation(root / PAYLOAD, root / MARKER, store)
            write_status(store, {**status, "allocated_bytes": total})
        except OSError as error:
            print(f"Servonaut retained generation cleanup deferred: {error}", file=sys.stderr)
        if extra:
            print(f"Servonaut payload storage uses {total} bytes, including {extra} without shared links.")


def cleanup(root: Path, *, remove: bool = False) -> None:
    if not (root / GENERATIONS).is_dir():
        return
    try:
        with maintenance(root) as store:
            if not stat.S_ISDIR(secure(root).st_mode) or not stat.S_ISDIR(secure(store).st_mode):
                return
            remove_interrupted_files(store)
            if not remove:
                state = recover_status(store)
                prune(store, state["current"], state["previous"])
                return
            (store / STATUS).unlink(missing_ok=True)
            prune(store, "", "")
            if not any(store.iterdir()) and not store.is_mount():
                store.rmdir()
                sync_directory(root)
                if not any(root.iterdir()):
                    root.rmdir()
                    sync_directory(root.parent)
    except BlockingIOError:
        # Package removal and upgrades can continue while another root process
        # maintains the store. Leased generations are handled the same way.
        return


def parent_generation(store: Path) -> str:
    try:
        image = Path(os.readlink(Path("/proc") / str(os.getppid()) / "exe"))
    except OSError:
        return ""
    if image.name in ROLES and image.parent.parent == store and GENERATION.fullmatch(image.parent.name):
        return image.parent.name
    return ""


def launch(store: Path, role: str, args: Sequence[str]) -> None:
    use_installed = os.environ.pop(RESTART_GENERATION_ENV, "") == "1"
    pinned = "" if use_installed else parent_generation(store)
    recovered = ""
    recovery_hint = None

    def selected() -> str:
        nonlocal recovered, recovery_hint
        if pinned:
            return pinned
        status = configured_status(store)
        if status is not None:
            return status["current"]
        # Check the live pointer again just before exec, but reuse a verified
        # recovery while the store membership and canonical marker stay put.
        marker = marker_inode(store.parent / MARKER)
        hint = (store.stat().st_mtime_ns, marker)
        if hint != recovery_hint:
            candidate = next(verified_candidates(store, marker), None)
            recovered = candidate.name if candidate is not None else ""
            recovery_hint = hint
        return recovered

    while current := selected():
        generation = store / current
        try:
            lease = open_lease(generation)
        except FileNotFoundError:
            if selected() != current:
                continue
            raise
        with lease:
            if acquire_shared_lease(lease.fileno()):
                os.set_inheritable(lease.fileno(), True)
            if selected() != current:
                continue
            try:
                same_lease = os.path.samestat(os.fstat(lease.fileno()), (generation / LEASE).stat())
            except FileNotFoundError:
                continue
            if not same_lease:
                continue
            binary = generation / role
            os.execv(binary, [str(binary), *args])
    raise ValueError("No configured Servonaut generation is available")


def main() -> int:
    executable = Path(sys.argv[0])
    try:
        if executable == Path("-"):
            if os.geteuid() != 0 or len(sys.argv) != 2 or not PACKAGE_NAME.fullmatch(sys.argv[1]):
                raise ValueError("Invalid Servonaut cleanup command")
            cleanup(INSTALL_ROOT.resolve() / sys.argv[1], remove=True)
            return 0
        helper = Path(__file__).resolve()
        if helper.parent.parent != HELPER_ROOT.resolve() or not PACKAGE_NAME.fullmatch(helper.parent.name):
            raise ValueError("Invalid Servonaut helper location")
        root = INSTALL_ROOT.resolve() / helper.parent.name
        role = invocation_role(executable, root, helper)
        if role is not None:
            launch(root / GENERATIONS, role, sys.argv[1:])
        elif os.geteuid() == 0 and sys.argv[1:] == ["activate"]:
            activate(root)
        elif os.geteuid() == 0 and sys.argv[1:] == ["prune"]:
            cleanup(root)
        else:
            raise ValueError("Invalid Servonaut generation command")
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Servonaut: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
