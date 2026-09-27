"""Report the GTK binding of a Linux desktop build venv as JSON.

The desktop builder runs this file with the build venv's interpreter after the
locked install, passing the root introspection namespaces as a JSON object of
``{namespace: version}``. It only gathers facts: the builder checks them
against the Linux ABI contract. It imports nothing from this repository, since
the build venv cannot import it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _typelib_closure(roots: dict[str, str]) -> dict[str, dict[str, object]]:
    """Resolve each root typelib and, transitively, every typelib it depends on."""
    from PyInstaller.utils.hooks.gi import GiModuleInfo

    pending = list(roots.items())
    closure: dict[str, dict[str, object]] = {}
    while pending:
        namespace, version = pending.pop()
        key = f"{namespace}-{version}"
        if key in closure:
            continue
        info = GiModuleInfo(namespace, version)
        if not info.available:
            raise SystemExit(f"typelib {key} is not available on this host")
        closure[key] = {
            "path": info.typelib,
            "shared_libraries": list(info.sharedlibs),
        }
        pending.extend(tuple(dependency.rsplit("-", 1)) for dependency in info.dependencies)
    return closure


def _extension_modules(*packages: object) -> list[str]:
    return sorted(
        str(path)
        for package in packages
        for path in Path(package.__file__).parent.glob("*.so")  # type: ignore[attr-defined]
    )


def _host_libraries(
    extensions: list[str], typelibs: dict[str, dict[str, object]]
) -> dict[str, str]:
    """Map the typelibs' libraries, and every library they or the extensions
    link (``ldd`` lists them transitively), to their host locations."""
    from PyInstaller.depend import bindepend

    libraries: dict[str, str] = {}
    for key, info in sorted(typelibs.items()):
        for name in info["shared_libraries"]:  # type: ignore[union-attr]
            location = bindepend.resolve_library_path(name)
            if location is None:
                raise SystemExit(f"typelib {key} names {name}, which the host lacks")
            libraries[name] = location
    for root in [*extensions, *libraries.values()]:
        for name, location in bindepend.get_imports(root):
            if location is None:
                raise SystemExit(f"{root} links {name}, which the host cannot resolve")
            libraries[Path(name).name] = location
    return libraries


def _glib_version() -> str:
    """The version of the GLib library itself.

    The GLib typelib's version constants describe the introspection data,
    which gobject-introspection generates from its own GLib snapshot, so they
    can lag the installed library.
    """
    import ctypes

    glib = ctypes.CDLL("libglib-2.0.so.0")
    return ".".join(
        str(ctypes.c_uint.in_dll(glib, f"glib_{part}_version").value)
        for part in ("major", "minor", "micro")
    )


def probe(roots: dict[str, str]) -> dict[str, object]:
    import cairo
    import gi

    typelibs = _typelib_closure(roots)
    extensions = _extension_modules(gi, cairo)
    return {
        "pygobject_version": gi.__version__,
        "pycairo_version": cairo.version,
        "glib_version": _glib_version(),
        "modules": {"gi": gi.__file__, "cairo": cairo.__file__},
        "extension_modules": extensions,
        "typelibs": typelibs,
        "host_libraries": _host_libraries(extensions, typelibs),
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: linux_gi_probe.py '{\"Gtk\": \"3.0\"}'\n")
        return 2
    roots = json.loads(argv[1])
    if not isinstance(roots, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in roots.items()
    ):
        sys.stderr.write("root namespaces must be a JSON object of strings\n")
        return 2
    sys.stdout.write(json.dumps(probe(roots), sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
