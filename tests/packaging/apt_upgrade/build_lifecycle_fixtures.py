"""Build four small Debian payloads with distinct delayed resource values."""

from __future__ import annotations

import argparse
import json
import shlex
import tempfile
from pathlib import Path

from scripts.distribution.package_deb import REQUIRED_PAYLOAD_BINARIES, package_deb
from tests.packaging.apt_upgrade.archive import run

PROBE = """#!/usr/bin/python3 -I
import ctypes
import importlib.util
import json
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parent
print("ready", flush=True)
for line in sys.stdin:
    if line.strip() != "probe":
        raise SystemExit("Invalid fixture request")
    spec = importlib.util.spec_from_file_location("late_value", root / "late_value.py")
    late = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(late)
    native = ctypes.CDLL(str(root / "libfixture.so"))
    print(json.dumps({
        "python": late.VALUE, "native": native.fixture_value(),
        "stylesheet": (root / "fixture.tcss").read_text().strip(),
        "data": (root / "fixture-link.txt").read_text().strip(),
    }), flush=True)
"""


def build(output: Path, compiler: str) -> None:
    with tempfile.TemporaryDirectory(prefix="deb-generation-fixtures-") as directory:
        for revision in range(5):
            payload = Path(directory) / str(revision)
            payload.mkdir()
            for role in REQUIRED_PAYLOAD_BINARIES:
                executable = payload / role
                executable.write_text(PROBE, encoding="utf-8")
                executable.chmod(0o755)
            (payload / "late_value.py").write_text(f"VALUE = {revision}\n", encoding="utf-8")
            (payload / "fixture.tcss").write_text(f"Label {{ padding: {revision}; }}\n", encoding="utf-8")
            (payload / "fixture.txt").write_text(f"data-{revision}\n", encoding="utf-8")
            (payload / "fixture-link.txt").symlink_to("fixture.txt")
            run([
                *shlex.split(compiler), "-shared", "-fPIC", "-nostdlib", "-x", "c",
                "-o", str(payload / "libfixture.so"), "-",
            ], input_bytes=f"int fixture_value(void) {{ return {revision}; }}\n".encode())
            run([
                *shlex.split(compiler), "-Wall", "-Werror", "-x", "c", "-o", str(payload / "native-session"), "-",
            ], input_bytes=b"#include <unistd.h>\nint main(void) { for (;;) pause(); }\n")
            version = "1.0.1" if revision == 2 else f"1.0.{revision}"
            packaging_revision = 2 if revision == 2 else None
            (payload / "servonaut-runtime.json").write_text(json.dumps({
                "schema_version": 1, "distribution": "packaged-desktop",
                "product_version": version, "packaging_revision": packaging_revision or 1, "channel": "stable",
                "build_revision": f"fixture-{revision}", "console_helper": "servonaut",
                "desktop_child": "servonaut-desktop-child",
            }), encoding="utf-8")
            legacy_postinst = Path(__file__).resolve().parents[3] / "packaging" / "deb" / "postinst"
            package, _, _ = package_deb(
                payload, output, version, packaging_revision=packaging_revision,
                maintainer="Archive Fixture <fixture@example.com>",
                postinst_file=legacy_postinst if revision == 0 else None,
            )
            print(package.name)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    build(args.output, args.cc)


if __name__ == "__main__":
    main()
