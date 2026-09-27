"""Code-signing layout of the macOS application bundle.

A PyInstaller onedir keeps code and data side by side in its contents
directory. A signed .app may not: ``codesign`` treats everything under
``Contents/MacOS`` and ``Contents/Frameworks`` as nested code, stores the
signature of a data file found there in extended attributes (lost by most
copies) and refuses directories with a dot in their name there. This module
maps the onedir onto the layout PyInstaller's own ``BUNDLE`` target builds,
which the bootloader expects: an executable in ``*.app/Contents/MacOS`` loads
its contents from ``Contents/Frameworks``.

* The executables go to ``Contents/MacOS``.
* Mach-O files, recognised by their magic bytes, go to ``Contents/Frameworks``
  and every other file to ``Contents/Resources``.
* A directory holding only one kind is placed whole on its side and linked
  from the other; a mixed directory exists on both sides, its files linked
  across one by one, so every path the app computes from ``sys._MEIPASS``
  still resolves.
* A ``.framework`` bundle is kept whole in ``Contents/Frameworks``.
* A code directory with a dot in its name is created with the dot replaced by
  ``__dot__`` and reached through a link with its real name.
* The runtime marker, read beside the executables, lives in
  ``Contents/Resources`` and is linked into ``Contents/MacOS``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
import filecmp
import os
from pathlib import Path, PurePosixPath
import posixpath
import stat
from typing import Literal

from scripts.desktop_shell.native_headers import NativeHeaderError, is_macho_file
from scripts.standalone_cli.artifact_types import PayloadEntry

CONTENTS_DIRECTORY = "_internal"
RUNTIME_MARKER = "servonaut-runtime.json"
EXECUTABLES: tuple[str, ...] = (
    "servonaut-desktop",
    "servonaut-desktop-child",
    "servonaut",
)
# The onedir also exposes a copy of its frontend at the top level. The app
# reads the one in its contents directory, so the bundle carries that one only.
FRONTEND_COPY = "frontend"
DOT_REPLACEMENT = "__dot__"

MACOS_DIR = PurePosixPath("Contents/MacOS")
FRAMEWORKS_DIR = PurePosixPath("Contents/Frameworks")
RESOURCES_DIR = PurePosixPath("Contents/Resources")
_CODE_LOCATIONS = (MACOS_DIR, FRAMEWORKS_DIR)
_TOP = PurePosixPath(".")

_DATA = "data"
_CODE = "code"
_MIXED = "mixed"
_FRAMEWORK = "framework"


class MacosLayoutError(ValueError):
    """Raised when a payload cannot be laid out as a signable application bundle."""


@dataclass(frozen=True, order=True)
class BundleEntry:
    """One directory, file or link of the bundle, relative to the .app directory."""

    path: PurePosixPath
    kind: Literal["directory", "file", "symlink"]
    source: PurePosixPath | None = None
    link_target: str | None = None
    executable: bool = False


def code_files(payload_root: Path, entries: Iterable[PayloadEntry]) -> frozenset[PurePosixPath]:
    """Return the payload's regular files that are Mach-O code, judged by magic bytes."""
    return frozenset(
        entry.relative_path
        for entry in entries
        if entry.kind == "file" and _is_code(payload_root / entry.relative_path)
    )


def _is_code(path: Path) -> bool:
    try:
        return is_macho_file(path)
    except NativeHeaderError as error:
        raise MacosLayoutError(str(error)) from error


def plan_app_layout(
    entries: Sequence[PayloadEntry], code: frozenset[PurePosixPath]
) -> list[BundleEntry]:
    """Map a desktop onedir payload onto the signable bundle layout.

    ``entries`` is the payload walk and ``code`` the subset of its regular
    files that are Mach-O code. The result is sorted and free of duplicates.

    Raises:
        MacosLayoutError: For an unexpected top-level entry, an executable that
            is not Mach-O code or a missing contents directory.
    """
    top_level = {
        entry.relative_path.name: entry
        for entry in entries
        if len(entry.relative_path.parts) == 1
    }
    planned = [*_top_level_entries(top_level, code)]
    internal_root = PurePosixPath(CONTENTS_DIRECTORY)
    internal = [
        _relative_to(entry, internal_root)
        for entry in entries
        if entry.relative_path.parts[0] == CONTENTS_DIRECTORY
        and entry.relative_path != internal_root
    ]
    internal_code = frozenset(
        path.relative_to(internal_root) for path in code if path.parts[0] == CONTENTS_DIRECTORY
    )
    planned.extend(_relocate_contents(internal, internal_code, internal_root))
    return _deduplicated(planned)


def verify_app_layout(app_path: Path) -> None:
    """Require every file in a code location to be code and every code file to be there.

    Contents of a nested ``.framework`` bundle are exempt: it is signed as a
    bundle of its own.

    Raises:
        MacosLayoutError: When the bundle breaks a code-signing placement rule.
    """
    contents = app_path / "Contents"
    for directory, subdirectories, files in os.walk(contents):
        here = PurePosixPath(Path(directory).relative_to(app_path).as_posix())
        if _framework_root(here) is not None or here.name.endswith(".framework"):
            subdirectories.clear()
            continue
        in_code_location = _is_below(here, _CODE_LOCATIONS)
        for name in subdirectories:
            path = Path(directory) / name
            dotted = "." in name and not name.endswith(".framework")
            if in_code_location and dotted and not path.is_symlink():
                raise MacosLayoutError(f"code directory name contains a dot: {here / name}")
        for name in files:
            path = Path(directory) / name
            if path.is_symlink():
                continue
            is_code = _is_code(path)
            if in_code_location and not is_code:
                raise MacosLayoutError(f"data file in a code location: {here / name}")
            if not in_code_location and is_code:
                raise MacosLayoutError(
                    f"code outside Contents/MacOS or Contents/Frameworks: {here / name}"
                )


def require_frontend_copy_matches(payload_root: Path, entries: Sequence[PayloadEntry]) -> None:
    """Require the omitted top-level frontend copy to equal the one the bundle keeps.

    Raises:
        MacosLayoutError: When the two copies differ, so omitting one would
            change what the app serves.
    """
    copy = _subtree(entries, PurePosixPath(FRONTEND_COPY))
    if not copy:
        return
    kept = _subtree(entries, PurePosixPath(CONTENTS_DIRECTORY, FRONTEND_COPY))
    if {path: entry.kind for path, entry in copy.items()} != {
        path: entry.kind for path, entry in kept.items()
    }:
        raise MacosLayoutError("the top-level frontend copy differs from the bundled frontend")
    for path, entry in copy.items():
        if entry.kind == "file" and not filecmp.cmp(
            payload_root / FRONTEND_COPY / path,
            payload_root / CONTENTS_DIRECTORY / FRONTEND_COPY / path,
            shallow=False,
        ):
            raise MacosLayoutError(f"the top-level frontend copy of {path} differs")


def _subtree(
    entries: Sequence[PayloadEntry], root: PurePosixPath
) -> dict[PurePosixPath, PayloadEntry]:
    return {
        entry.relative_path.relative_to(root): entry
        for entry in entries
        if entry.relative_path.is_relative_to(root)
    }


def _top_level_entries(
    top_level: dict[str, PayloadEntry], code: frozenset[PurePosixPath]
) -> Iterable[BundleEntry]:
    for name in EXECUTABLES:
        entry = top_level.get(name)
        if entry is None or entry.kind != "file":
            raise MacosLayoutError(f"payload executable '{name}' is missing")
        if entry.relative_path not in code:
            raise MacosLayoutError(f"payload executable '{name}' is not Mach-O code")
        yield BundleEntry(MACOS_DIR / name, "file", entry.relative_path, executable=True)

    marker = top_level.get(RUNTIME_MARKER)
    if marker is None or marker.kind != "file":
        raise MacosLayoutError(f"payload runtime marker '{RUNTIME_MARKER}' is missing")
    yield BundleEntry(RESOURCES_DIR / RUNTIME_MARKER, "file", marker.relative_path)
    yield _crosslink(MACOS_DIR / RUNTIME_MARKER, RESOURCES_DIR / RUNTIME_MARKER)

    internal = top_level.get(CONTENTS_DIRECTORY)
    if internal is None or internal.kind != "directory":
        raise MacosLayoutError(f"payload contents directory '{CONTENTS_DIRECTORY}' is missing")

    known = {*EXECUTABLES, RUNTIME_MARKER, CONTENTS_DIRECTORY, FRONTEND_COPY}
    unexpected = sorted(set(top_level) - known)
    if unexpected:
        raise MacosLayoutError(f"unexpected top-level payload entries: {unexpected}")


def _relocate_contents(
    entries: Sequence[PayloadEntry],
    code: frozenset[PurePosixPath],
    source_root: PurePosixPath,
) -> Iterable[BundleEntry]:
    """Place the contents directory's entries, as PyInstaller's BUNDLE does."""
    types = _classify_directories(entries, code)
    for directory, kind in types.items():
        yield from _directory_entries(directory, kind, types)
    for entry in entries:
        if entry.kind == "directory":
            if _framework_root(entry.relative_path) is not None:
                yield BundleEntry(_frameworks_path(entry.relative_path), "directory")
            continue
        yield from _file_entries(entry, code, types, source_root)


def _classify_directories(
    entries: Sequence[PayloadEntry], code: frozenset[PurePosixPath]
) -> dict[PurePosixPath, str]:
    """Classify each directory outside a framework as data, code, mixed or framework."""
    types: dict[PurePosixPath, str | None] = {}
    for entry in entries:
        if entry.kind == "directory":
            continue
        framework = _framework_root(entry.relative_path)
        if framework is not None:
            types[framework] = _FRAMEWORK
            kind: str | None = _CODE
            parents: Sequence[PurePosixPath] = framework.parents
        else:
            parents = entry.relative_path.parents
            if entry.kind == "symlink":
                kind = None
            else:
                kind = _CODE if entry.relative_path in code else _DATA
        for parent in parents:
            if parent != _TOP:
                types[parent] = _merged_type(types.get(parent), kind)
    for entry in entries:
        path = entry.relative_path
        if entry.kind == "directory" and _framework_root(path) is None:
            types.setdefault(path, None)
    # A directory holding only links, or nothing, is treated as data.
    return {path: kind or _DATA for path, kind in sorted(types.items())}


def _merged_type(current: str | None, kind: str | None) -> str | None:
    if kind is None or current == kind:
        return current
    if current is None:
        return kind
    return _MIXED


def _directory_entries(
    directory: PurePosixPath, kind: str, types: dict[PurePosixPath, str]
) -> Iterable[BundleEntry]:
    if kind in (_DATA, _MIXED):
        yield BundleEntry(RESOURCES_DIR / directory, "directory")
    if kind in (_CODE, _MIXED, _FRAMEWORK):
        yield BundleEntry(_frameworks_directory(directory), "directory")
        if kind != _FRAMEWORK and "." in directory.name:
            yield BundleEntry(
                _frameworks_path(directory),
                "symlink",
                link_target=_sanitized(directory.name),
            )
    if kind != _MIXED and _needs_crosslink(directory, types):
        if kind == _DATA:
            yield _crosslink(FRAMEWORKS_DIR / directory, RESOURCES_DIR / directory)
        else:
            yield _crosslink(RESOURCES_DIR / directory, FRAMEWORKS_DIR / directory)


def _file_entries(
    entry: PayloadEntry,
    code: frozenset[PurePosixPath],
    types: dict[PurePosixPath, str],
    source_root: PurePosixPath,
) -> Iterable[BundleEntry]:
    path = entry.relative_path
    source = source_root / path
    if _framework_root(path) is not None:
        yield _placed(entry, _frameworks_path(path), source, is_code=path in code)
        return
    crosslinked = _needs_crosslink(path, types)
    if entry.kind == "symlink":
        parent_type = types.get(path.parent)
        if crosslinked:
            # Linked on both sides; each resolves to the file or its cross-link.
            yield BundleEntry(_frameworks_path(path), "symlink", link_target=entry.link_target)
            yield BundleEntry(RESOURCES_DIR / path, "symlink", link_target=entry.link_target)
        elif parent_type == _DATA:
            yield BundleEntry(RESOURCES_DIR / path, "symlink", link_target=entry.link_target)
        else:
            yield BundleEntry(_frameworks_path(path), "symlink", link_target=entry.link_target)
        return
    if path in code:
        yield _placed(entry, _frameworks_path(path), source, is_code=True)
        if crosslinked:
            yield _crosslink(RESOURCES_DIR / path, FRAMEWORKS_DIR / path)
        return
    yield _placed(entry, RESOURCES_DIR / path, source, is_code=False)
    if crosslinked:
        yield _crosslink(FRAMEWORKS_DIR / path, RESOURCES_DIR / path)


def _placed(
    entry: PayloadEntry, destination: PurePosixPath, source: PurePosixPath, *, is_code: bool
) -> BundleEntry:
    if entry.kind == "symlink":
        return BundleEntry(destination, "symlink", link_target=entry.link_target)
    executable = is_code or bool(entry.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    return BundleEntry(destination, "file", source, executable=executable)


def _needs_crosslink(path: PurePosixPath, types: dict[PurePosixPath, str]) -> bool:
    """Entries at the top of the contents directory or in a mixed one exist on both sides."""
    return path.parent == _TOP or types.get(path.parent) == _MIXED


def _crosslink(location: PurePosixPath, target: PurePosixPath) -> BundleEntry:
    """A link at ``location`` to ``target``, both relative to the .app directory."""
    relative = posixpath.relpath(target.as_posix(), location.parent.as_posix())
    return BundleEntry(_sanitized_location(location), "symlink", link_target=relative)


def _sanitized_location(location: PurePosixPath) -> PurePosixPath:
    if location.is_relative_to(FRAMEWORKS_DIR):
        return _frameworks_path(location.relative_to(FRAMEWORKS_DIR))
    return location


def _frameworks_path(path: PurePosixPath) -> PurePosixPath:
    """Where a contents entry lives in Contents/Frameworks: its parents lose their dots.

    Inside a ``.framework`` bundle only the parents of the bundle are renamed.
    """
    framework = _framework_root(path)
    if framework is not None:
        parent, remaining = framework.parent, path.relative_to(framework.parent)
    else:
        parent, remaining = path.parent, PurePosixPath(path.name)
    return FRAMEWORKS_DIR.joinpath(*(_sanitized(part) for part in parent.parts), remaining)


def _frameworks_directory(directory: PurePosixPath) -> PurePosixPath:
    """The real code directory; unlike a link to it, its own name loses its dot too."""
    if directory.name.endswith(".framework") or _framework_root(directory) is not None:
        return _frameworks_path(directory)
    return FRAMEWORKS_DIR.joinpath(*(_sanitized(part) for part in directory.parts))


def _sanitized(name: str) -> str:
    return name.replace(".", DOT_REPLACEMENT)


def _framework_root(path: PurePosixPath) -> PurePosixPath | None:
    """The outermost ``.framework`` directory above ``path``, if any."""
    for parent in reversed(path.parents):
        if parent.name.endswith(".framework"):
            return parent
    return None


def _is_below(path: PurePosixPath, roots: Iterable[PurePosixPath]) -> bool:
    return any(path == root or path.is_relative_to(root) for root in roots)


def _relative_to(entry: PayloadEntry, root: PurePosixPath) -> PayloadEntry:
    return PayloadEntry(
        entry.relative_path.relative_to(root),
        entry.kind,
        entry.mode,
        entry.size,
        entry.sha256,
        entry.link_target,
    )


def _deduplicated(entries: Iterable[BundleEntry]) -> list[BundleEntry]:
    by_path: dict[PurePosixPath, BundleEntry] = {}
    for entry in entries:
        existing = by_path.setdefault(entry.path, entry)
        if existing != entry:
            raise MacosLayoutError(f"two payload entries map to {entry.path}")
    return sorted(by_path.values())


def materialize_app_layout(
    payload_root: Path,
    app_path: Path,
    layout: Sequence[BundleEntry],
    *,
    copy_file: Callable[[Path, Path], object],
) -> None:
    """Create the planned directories, files and links below ``app_path``."""
    for entry in layout:
        destination = app_path / entry.path
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if entry.kind == "directory":
            destination.mkdir(mode=0o755, exist_ok=True)
        elif entry.kind == "symlink":
            os.symlink(entry.link_target or "", destination)
        else:
            if entry.source is None:
                raise MacosLayoutError(f"planned file has no source: {entry.path}")
            copy_file(payload_root / entry.source, destination)
            destination.chmod(0o755 if entry.executable else 0o644)
