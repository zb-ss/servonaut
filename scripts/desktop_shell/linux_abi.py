"""Linux Python/GI ABI contract, payload audit, and fallback specifications."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

UBUNTU_2204_BASELINE = "ubuntu-22.04"
UBUNTU_2404_FORWARD = "ubuntu-24.04"
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

_PYGOBJECT_VER_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")


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
