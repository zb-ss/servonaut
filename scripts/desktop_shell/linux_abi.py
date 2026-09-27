"""Linux Python/GI ABI contract, payload audit, and fallback specifications."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

UBUNTU_2204_BASELINE = "ubuntu-22.04"
UBUNTU_2404_FORWARD = "ubuntu-24.04"
UBUNTU_2604_FORWARD = "ubuntu-26.04"
REQUIRED_PYTHON_VERSION = "3.12"
PINNED_PYGOBJECT_VERSION = "3.48.2"
MINIMUM_PYCAIRO_VERSION = "1.26.0"
GLIB_FLOOR = "2.72"
GLIB_PROHIBITED_FLOOR = "2.80"
REQUIRED_GTK_VERSION = "3"
REQUIRED_WEBKIT_API = "4.1"

REQUIRED_SYSTEM_DEPS = (
    "libgirepository1.0-dev",
    "libgtk-3-dev",
    "libwebkit2gtk-4.1-dev",
    "gir1.2-webkit2-4.1",
)

# The prohibited lists below are the source of truth; the linux_abi block of
# packaging/desktop_shell/target-policy.json mirrors them for reviewers, and a
# contract test fails when the two drift apart.
PROHIBITED_COPIED_DISTRO_MODULES = (
    "gi",
    "_gi",
    "cairo",
    "_gi_cairo",
)

PROHIBITED_BUNDLED_CLOSURES = (
    "libgtk-3",
    "libglib-2.0",
    "libgobject-2.0",
    "libwebkit2gtk-4.1",
    "libjavascriptcoregtk-4.1",
)

PROHIBITED_LIBRARIES = (
    "libreadline",
    "libfaster_whisper",
    "libctranslate2",
    "libsherpa_onnx",
    "libonnxruntime",
)

# Debian packages the build host needs besides REQUIRED_SYSTEM_DEPS: the
# inputs of the PyGObject and pycairo source builds, and the GIRepository
# typelib that PyInstaller's GObject introspection helpers load.
SOURCE_BUILD_SYSTEM_DEPS = (
    "pkg-config",
    "libcairo2-dev",
    "libffi-dev",
    "gir1.2-girepository-2.0",
    "gir1.2-gtk-3.0",
)

# What the frozen window smoke needs: a virtual display and a screenshot tool.
GUI_SMOKE_SYSTEM_DEPS = ("xvfb", "xauth", "imagemagick")

# The introspection namespaces pywebview's GTK backend requires.
GI_ROOT_NAMESPACES = (
    ("Gtk", "3.0"),
    ("Gdk", "3.0"),
    ("WebKit2", "4.1"),
    ("Soup", "3.0"),
)

# Their dependency closure on the Ubuntu 22.04 baseline. The payload bundles
# exactly these typelibs, each through its own PyInstaller hook. The shared
# libraries they describe, and those libraries' data and plugins, come from
# the host so that nothing in the payload can shadow the host's GTK stack.
REQUIRED_TYPELIBS = frozenset(
    {
        "Atk-1.0",
        "GLib-2.0",
        "GModule-2.0",
        "GObject-2.0",
        "Gdk-3.0",
        "GdkPixbuf-2.0",
        "Gio-2.0",
        "Gtk-3.0",
        "HarfBuzz-0.0",
        "JavaScriptCore-4.1",
        "Pango-1.0",
        "Soup-3.0",
        "WebKit2-4.1",
        "cairo-1.0",
        "xlib-2.0",
    }
)

# Extension modules of the frozen binding, as paths relative to the payload's
# contents directory up to the CPython ABI tag.
REQUIRED_GI_EXTENSIONS = (
    "gi/_gi.cpython-312-",
    "gi/_gi_cairo.cpython-312-",
    "cairo/_cairo.cpython-312-",
)

_CONTENTS_DIRECTORY = "_internal"
_TYPELIB_DIRECTORY = "gi_typelibs"

_PYGOBJECT_VER_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")
_RELEASE_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_SONAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.+-]*\.so(?:\.[0-9]+)*$")
_DISTRIBUTION_NAME_RE = re.compile(r"[-_.]+")


class LinuxAbiError(ValueError):
    """Raised when Linux ABI requirements or payload audit constraints are violated."""


def validate_pygobject_abi(
    pygobject_version: str, glib_version: str | None = None
) -> None:
    """Validate PyGObject version against the Ubuntu 22.04 GLib floor contract.

    pywebview's [gtk] extra selects PyGObject 3.50+, whose documented GLib floor is 2.80.
    Ubuntu 22.04 LTS supplies GLib 2.72, making PyGObject 3.50 unusable on the baseline.
    The pinned policy builds PyGObject 3.48.2 from source for Python 3.12.
    """
    match = _PYGOBJECT_VER_RE.match(pygobject_version.strip())
    if not match:
        raise LinuxAbiError(
            f"Malformed PyGObject version string: {pygobject_version!r}"
        )

    major = int(match.group(1))
    minor = int(match.group(2))

    if (major, minor) > (3, 48):
        raise LinuxAbiError(
            f"PyGObject {pygobject_version} is prohibited on Linux baseline: "
            f"PyGObject >= 3.50 requires GLib >= {GLIB_PROHIBITED_FLOOR}, but "
            f"Ubuntu 22.04 supplies GLib {GLIB_FLOOR}. Pinned version is {PINNED_PYGOBJECT_VERSION}."
        )

    if pygobject_version.strip() != PINNED_PYGOBJECT_VERSION:
        raise LinuxAbiError(
            f"PyGObject version must be exactly {PINNED_PYGOBJECT_VERSION}, got {pygobject_version.strip()!r}"
        )

    if glib_version is not None:
        glib_match = _PYGOBJECT_VER_RE.match(glib_version.strip())
        if glib_match:
            g_major = int(glib_match.group(1))
            g_minor = int(glib_match.group(2))
            if (g_major, g_minor) < (2, 72):
                raise LinuxAbiError(
                    f"Host GLib version {glib_version} is below required floor {GLIB_FLOOR}"
                )


def audit_linux_onedir_payload(payload_dir: Path) -> list[str]:
    """Audit a Linux onedir payload directory for forbidden bundled closures and foreign ABIs.

    Rules:
    1. Distro Python modules (e.g. system Python 3.10 gi) must never be copied into Python 3.12.
    2. Host GTK3, GLib, and WebKit closures must not be bundled (they must remain dynamically
       linked host dependencies to avoid conflicting with the host WebKit stack).
    3. GNU Readline must not be bundled (GPL license contamination risk).
    4. Voice libraries and models must not be present.
    """
    payload_dir = payload_dir.resolve()
    if not payload_dir.is_dir():
        raise LinuxAbiError(f"Payload directory not found: {payload_dir}")

    violations: list[str] = []

    for path in payload_dir.rglob("*"):
        rel_parts = path.relative_to(payload_dir).parts
        name = path.name

        # Check for foreign Python ABI files (e.g., cpython-310-*.so in a 3.12 bundle)
        if "cpython-310" in name or "cpython-311" in name:
            violations.append(
                f"Foreign Python ABI file found in 3.12 payload: {'/'.join(rel_parts)}"
            )

        # Check for copied distro GI modules
        for mod in PROHIBITED_COPIED_DISTRO_MODULES:
            if (
                name == mod or name.startswith((f"{mod}.", f"{mod}_"))
            ) and path.is_symlink():
                target = str(path.resolve())
                if target.startswith(("/usr/lib", "/lib", "/usr/local/lib")):
                    violations.append(
                        f"Prohibited symlink to host distro module: {'/'.join(rel_parts)} -> {target}"
                    )

        # Check for bundled native libraries that must remain host dependencies
        for lib_prefix in PROHIBITED_BUNDLED_CLOSURES:
            if name.startswith(f"{lib_prefix}.so") or f"{lib_prefix}-" in name:
                violations.append(
                    f"Prohibited bundled host library closure: {'/'.join(rel_parts)} "
                    f"(must remain host dependency to prevent WebKit conflicts)"
                )

        # Check for prohibited Readline or voice libraries
        for lib in PROHIBITED_LIBRARIES:
            if lib in name:
                violations.append(
                    f"Prohibited library bundled in payload: {'/'.join(rel_parts)}"
                )

        # Check for bundled voice ONNX assets
        if name.endswith(".onnx"):
            violations.append(
                f"Prohibited voice ONNX model found in payload: {'/'.join(rel_parts)}"
            )

    return violations


@dataclass(frozen=True)
class LinuxGiBinding:
    """The GTK binding of a Linux build venv, checked against this contract.

    ``host_libraries`` names every shared library the host GTK stack links,
    so the build can keep all of them out of the payload.
    """

    pygobject_version: str
    pycairo_version: str
    glib_version: str
    typelibs: tuple[str, ...]
    host_libraries: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "pygobject_version": self.pygobject_version,
            "pycairo_version": self.pycairo_version,
            "glib_version": self.glib_version,
            "typelibs": list(self.typelibs),
            "host_libraries": list(self.host_libraries),
        }

    @classmethod
    def from_json(cls, raw: object) -> LinuxGiBinding:
        """Read a binding back from build provenance, checking every field."""
        if not isinstance(raw, dict) or set(raw) != {
            "pygobject_version",
            "pycairo_version",
            "glib_version",
            "typelibs",
            "host_libraries",
        }:
            raise LinuxAbiError("recorded GTK binding has unexpected fields")
        binding = cls(
            pygobject_version=_required_text(raw, "pygobject_version"),
            pycairo_version=_required_text(raw, "pycairo_version"),
            glib_version=_required_text(raw, "glib_version"),
            typelibs=_text_tuple(raw["typelibs"], "typelibs"),
            host_libraries=_text_tuple(raw["host_libraries"], "host_libraries"),
        )
        validate_pygobject_abi(binding.pygobject_version, binding.glib_version)
        _require_typelib_closure(binding.typelibs)
        _require_host_gtk_stack(binding.host_libraries)
        return binding


def validate_gi_binding_probe(probe: object, site_packages: Path) -> LinuxGiBinding:
    """Check what the build venv's GTK binding probe reported.

    The binding must be the pinned PyGObject and a supported pycairo, compiled
    for Python 3.12 into the build venv itself (a distro ``python3-gi`` never
    qualifies), and must resolve exactly the required typelib closure.
    """
    if not isinstance(probe, dict):
        raise LinuxAbiError("GTK binding probe must report a JSON object")
    site_packages = site_packages.resolve()
    modules = _required_mapping(probe, "modules")
    for module in ("gi", "cairo"):
        origin = Path(_required_text(modules, module)).resolve()
        if not origin.is_relative_to(site_packages):
            raise LinuxAbiError(
                f"{module} is imported from outside the build venv ({origin}); "
                "distro Python modules are never used"
            )
    _require_gi_extensions(_required_list(probe, "extension_modules"), site_packages)

    pygobject_version = _required_text(probe, "pygobject_version")
    glib_version = _required_text(probe, "glib_version")
    validate_pygobject_abi(pygobject_version, glib_version)
    pycairo_version = _required_text(probe, "pycairo_version")
    if _release(pycairo_version) < _release(MINIMUM_PYCAIRO_VERSION):
        raise LinuxAbiError(
            f"pycairo {pycairo_version} is older than {MINIMUM_PYCAIRO_VERSION}"
        )

    typelibs = tuple(sorted(_required_mapping(probe, "typelibs")))
    _require_typelib_closure(typelibs)
    host_libraries = _host_library_names(
        _required_mapping(probe, "host_libraries"), site_packages
    )
    return LinuxGiBinding(
        pygobject_version=pygobject_version,
        pycairo_version=pycairo_version,
        glib_version=glib_version,
        typelibs=typelibs,
        host_libraries=host_libraries,
    )


def missing_gi_payload_components(payload_dir: Path) -> list[str]:
    """List required binding files the payload lacks, and typelibs it should not have."""
    contents = payload_dir / _CONTENTS_DIRECTORY
    typelib_dir = contents / _TYPELIB_DIRECTORY
    bundled = (
        {path.name for path in typelib_dir.iterdir()} if typelib_dir.is_dir() else set()
    )
    expected = {f"{name}.typelib" for name in REQUIRED_TYPELIBS}
    problems = [f"missing {_TYPELIB_DIRECTORY}/{name}" for name in sorted(expected - bundled)]
    problems += [
        f"unexpected {_TYPELIB_DIRECTORY}/{name}" for name in sorted(bundled - expected)
    ]
    for prefix in REQUIRED_GI_EXTENSIONS:
        package, stem = prefix.split("/")
        package_dir = contents / package
        found = package_dir.is_dir() and any(
            path.name.startswith(stem) and path.name.endswith(".so")
            for path in package_dir.iterdir()
        )
        if not found:
            problems.append(f"missing {prefix}*.so")
    return problems


def find_bundled_host_libraries(
    payload_dir: Path, host_libraries: Iterable[str]
) -> list[str]:
    """Return payload paths that would shadow a library of the host GTK stack.

    The frozen launcher runs with its contents directory on the library search
    path, and the host WebKit processes it starts inherit that path, so any
    bundled copy would be loaded in place of the host's own.
    """
    names = set(host_libraries)
    return sorted(
        path.relative_to(payload_dir).as_posix()
        for path in payload_dir.rglob("*")
        if path.name in names and (path.is_symlink() or path.is_file())
    )


def bundled_distribution_version(payload_dir: Path, distribution: str) -> str | None:
    """Return the version in the payload's copied metadata for *distribution*."""
    wanted = _normalized_distribution(distribution)
    contents = payload_dir / _CONTENTS_DIRECTORY
    if not contents.is_dir():
        return None
    for dist_info in contents.glob("*.dist-info"):
        metadata = _metadata_fields(dist_info / "METADATA")
        if _normalized_distribution(metadata.get("Name", "")) == wanted:
            return metadata.get("Version")
    return None


def _metadata_fields(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {}
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if not line:
            break
        key, separator, value = line.partition(":")
        if separator and key in ("Name", "Version"):
            fields.setdefault(key, value.strip())
    return fields


def _normalized_distribution(name: str) -> str:
    return _DISTRIBUTION_NAME_RE.sub("-", name).lower()


def _require_gi_extensions(extensions: list[object], site_packages: Path) -> None:
    relative: list[str] = []
    for extension in extensions:
        if not isinstance(extension, str) or not extension:
            raise LinuxAbiError("GTK binding probe reported an invalid extension module")
        path = Path(extension).resolve()
        if not path.is_relative_to(site_packages):
            raise LinuxAbiError(f"extension module is outside the build venv: {path}")
        relative.append(path.relative_to(site_packages).as_posix())
    for prefix in REQUIRED_GI_EXTENSIONS:
        if not any(name.startswith(prefix) and name.endswith(".so") for name in relative):
            raise LinuxAbiError(f"GTK binding has no Python 3.12 extension {prefix}*.so")


def _require_typelib_closure(typelibs: Iterable[str]) -> None:
    found = set(typelibs)
    if found != REQUIRED_TYPELIBS:
        raise LinuxAbiError(
            "typelib closure differs from the contract: "
            f"missing {sorted(REQUIRED_TYPELIBS - found)}, "
            f"unexpected {sorted(found - REQUIRED_TYPELIBS)}"
        )


def _host_library_names(
    libraries: Mapping[object, object], site_packages: Path
) -> tuple[str, ...]:
    for name, location in libraries.items():
        if not isinstance(location, str) or not Path(location).is_absolute():
            raise LinuxAbiError(f"host library {name} has no absolute location")
        if Path(location).resolve().is_relative_to(site_packages):
            raise LinuxAbiError(f"host library {name} resolves into the build venv")
    names = tuple(sorted(libraries))  # type: ignore[arg-type]
    _require_host_gtk_stack(names)
    return names


def _require_host_gtk_stack(names: Iterable[object]) -> None:
    """The closure must name shared libraries, including those the contract keeps on the host."""
    found = tuple(names)
    for name in found:
        if not isinstance(name, str) or not _SONAME_RE.fullmatch(name):
            raise LinuxAbiError(f"invalid host library name: {name!r}")
    for prefix in PROHIBITED_BUNDLED_CLOSURES:
        if not any(name.startswith(f"{prefix}.so") for name in found):
            raise LinuxAbiError(f"host library closure does not include {prefix}")


def _release(version: str) -> tuple[int, int, int]:
    match = _RELEASE_RE.match(version.strip())
    if not match:
        raise LinuxAbiError(f"Malformed release version: {version!r}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _required_text(raw: Mapping[str, object], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise LinuxAbiError(f"GTK binding field {key} must be a non-empty string")
    return value.strip()


def _required_mapping(raw: Mapping[str, object], key: str) -> Mapping[object, object]:
    value = raw.get(key)
    if not isinstance(value, dict) or not value:
        raise LinuxAbiError(f"GTK binding field {key} must be a non-empty object")
    return value


def _required_list(raw: Mapping[str, object], key: str) -> list[object]:
    value = raw.get(key)
    if not isinstance(value, list) or not value:
        raise LinuxAbiError(f"GTK binding field {key} must be a non-empty list")
    return value


def _text_tuple(value: object, key: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise LinuxAbiError(f"recorded GTK binding {key} must list names")
    return tuple(value)


def get_split_runtime_fallback_spec() -> dict[str, Any]:
    """Return the reviewed split-runtime fallback specification.

    If CPython 3.12 + PyGObject 3.48.2 build fails or dual-baseline native window
    evidence fails on Ubuntu 22.04/24.04, this reviewed fallback is chosen:
    - GUI parent & private child run on Ubuntu 22.04 system Python 3.10 dependency stack
    - Console helper runs on Python 3.12 standalone onedir
    - Both roles consume the exact same Servonaut wheel and product version
    - No copying of ABI-specific packages between interpreters
    """
    return {
        "status": "reviewed_fallback",
        "description": "Two Linux interpreter roles with separate runtimes",
        "gui_and_child_runtime": {
            "python_version": "3.10",
            "base_image": "ubuntu:22.04",
            "stack": "system-packages",
            "required_system_packages": [
                "python3-gi",
                "python3-gi-cairo",
                "gir1.2-gtk-3.0",
                "gir1.2-webkit2-4.1",
            ],
        },
        "console_helper_runtime": {
            "python_version": "3.12",
            "stack": "standalone-onedir",
        },
        "shared_constraints": {
            "same_product_version": True,
            "same_wheel_artifact": True,
            "no_abi_package_copy": True,
            "independent_processes": True,
        },
    }
