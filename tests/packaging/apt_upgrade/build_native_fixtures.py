"""Make a signed-archive upgrade pair from a released and a freshly built payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from scripts.distribution.package_deb import package_deb
from servonaut.debian_layout import INSTALL_ROOT, MARKER
from servonaut.runtime import MAX_PACKAGING_REVISION
from tests.packaging.apt_upgrade.archive import debian_version, run


def build(released: Path, checksum: str, candidate: Path, output: Path) -> None:
    digest = hashlib.sha256()
    with released.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != checksum:
        raise ValueError("The released Debian archive does not match the fixture checksum")
    with tempfile.TemporaryDirectory(prefix="apt-native-pair-") as directory:
        root = Path(directory)
        old = root / "released"
        run(["dpkg-deb", "--extract", str(released), str(old)])
        package = run(["dpkg-deb", "--field", str(released), "Package"]).decode().strip()
        if package != "servonaut":
            raise ValueError("The released Debian archive must install Servonaut")
        previous = old / INSTALL_ROOT.relative_to("/") / package
        previous_marker = json.loads((previous / MARKER).read_bytes())

        prepared = shutil.copytree(candidate, root / "candidate", symlinks=True)
        marker_path = prepared / MARKER
        marker = json.loads(marker_path.read_bytes())
        if marker["product_version"] == previous_marker["product_version"]:
            marker["packaging_revision"] = previous_marker["packaging_revision"] + 1
        if not 1 <= marker["packaging_revision"] <= MAX_PACKAGING_REVISION:
            raise ValueError("The fixture packaging revision is outside the supported range")
        marker_path.write_text(json.dumps(marker), encoding="utf-8")

        maintainer = "Upgrade Fixture <fixture@example.com>"
        before, _, _ = package_deb(previous, output, previous_marker["product_version"],
                                   maintainer=maintainer, filename="before.deb")
        after, _, _ = package_deb(prepared, output, marker["product_version"], maintainer=maintainer,
                                  packaging_revision=marker["packaging_revision"], filename="after.deb")
        run(["dpkg", "--compare-versions", debian_version(before), "lt", debian_version(after)])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--released-sha256")
    source.add_argument("--source-pair", action="store_true")
    args = parser.parse_args()
    if args.source_pair:
        build_source_pair(args.before, args.candidate, args.output)
    else:
        build(args.before, args.released_sha256, args.candidate, args.output)


def build_source_pair(before: Path, after: Path, output: Path) -> None:
    """Package two native builds of this source, with strictly increasing versions."""
    versions = [json.loads((payload / MARKER).read_bytes())["product_version"] for payload in (before, after)]
    if versions[0] == versions[1]:
        raise ValueError("The restart fixture requires two separately built product versions")
    packages = [
        package_deb(
            payload, output, version, maintainer="Upgrade Fixture <fixture@example.com>", filename=filename,
        )[0]
        for payload, version, filename in zip((before, after), versions, ("before.deb", "after.deb"))
    ]
    run(["dpkg", "--compare-versions", debian_version(packages[0]), "lt", debian_version(packages[1])])


if __name__ == "__main__":
    main()
