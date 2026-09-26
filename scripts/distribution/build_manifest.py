"""CLI script to build, validate, and sign release manifests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Optional

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from servonaut.distribution.builder import ManifestBuilder
from servonaut.distribution.manifest import (
    ArtifactKind,
    ManifestError,
    ReleaseChannel,
    ReleaseManifest,
    canonicalize_json,
)
from servonaut.runtime import DistributionKind


def parse_artifact_spec(spec: str) -> dict[str, str]:
    """Parse comma-separated key=value artifact specifier."""
    parts = spec.split(",")
    data: dict[str, str] = {}
    for part in parts:
        if "=" not in part:
            raise ValueError(f"Invalid artifact specifier item '{part}'. Expected key=value.")
        k, v = part.split("=", 1)
        data[k.strip()] = v.strip()
    return data


_PACKAGED_DISTRIBUTIONS = frozenset(
    {DistributionKind.FROZEN_CLI, DistributionKind.PACKAGED_DESKTOP}
)


def _lists_packaged_builds(artifact_specs: list[str]) -> bool:
    """Whether any artifact spec names a packaged build that carries a marker."""
    for spec_str in artifact_specs:
        raw = parse_artifact_spec(spec_str).get("distribution", "")
        try:
            distribution = DistributionKind(raw.replace("_", "-"))
        except ValueError:
            # An unknown distribution is refused where the artifact is added.
            continue
        if distribution in _PACKAGED_DISTRIBUTIONS:
            return True
    return False


def load_private_key(key_path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from PEM or raw 32-byte seed file."""
    raw = key_path.read_bytes()
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        # Not an unencrypted PEM key; fall back to a raw 32-byte seed.
        key = None
    if isinstance(key, Ed25519PrivateKey):
        return key

    if len(raw) == 32:
        return Ed25519PrivateKey.from_private_bytes(raw)
    raise ValueError(f"Could not load Ed25519 private key from {key_path}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Assemble and sign a canonical Servonaut ReleaseManifest.")
    parser.add_argument("--version", required=True, help="Product semantic version (X.Y.Z)")
    parser.add_argument("--channel", default="stable", choices=["stable", "preview", "nightly"])
    parser.add_argument(
        "--revision",
        type=int,
        default=None,
        help=(
            "Packaging revision the listed builds carry in their runtime markers; "
            "required whenever the manifest lists packaged builds"
        ),
    )
    parser.add_argument("--published-at", default=None, help="ISO 8601 UTC timestamp (default: now)")
    parser.add_argument(
        "--expires-at",
        required=True,
        help="ISO 8601 UTC timestamp after which clients refuse the manifest; must be later than --published-at",
    )
    parser.add_argument(
        "--artifact",
        action="append",
        dest="artifacts",
        default=[],
        help="Artifact spec: file=<path>,kind=<kind>,distribution=<dist>,platform=<plat>,arch=<arch>,url=<url>[,min_os=<os>]",
    )
    parser.add_argument("--output", type=Path, default=Path("servonaut-release-manifest.json"), help="Output manifest file")
    signing = parser.add_mutually_exclusive_group(required=True)
    signing.add_argument("--key-file", type=Path, default=None, help="Ed25519 private key for signing")
    signing.add_argument(
        "--unsigned",
        action="store_true",
        help="Write an unsigned manifest; clients refuse it, so use it only for inspection",
    )
    parser.add_argument("--key-id", default=None, help="Signing key ID (required with --key-file)")

    args = parser.parse_args(argv)
    if args.key_file is not None and not args.key_id:
        parser.error("--key-id is required when --key-file is provided.")
    if args.revision is None and _lists_packaged_builds(args.artifacts):
        # A manifest without a revision orders before every packaged build of
        # its version, so an installed build would be offered it as an update.
        parser.error(
            "--revision is required when the manifest lists packaged builds; "
            "use the packaging revision written into their runtime markers."
        )

    channel = ReleaseChannel(args.channel)
    try:
        builder = ManifestBuilder(
            product_version=args.version,
            channel=channel,
            packaging_revision=args.revision,
            published_at=args.published_at,
            expires_at=args.expires_at,
        )
    except ManifestError as err:
        parser.error(str(err))

    for spec_str in args.artifacts:
        spec = parse_artifact_spec(spec_str)
        file_path = Path(spec["file"])
        kind = ArtifactKind(spec["kind"])
        dist_str = spec["distribution"].replace("_", "-")
        distribution = DistributionKind(dist_str)
        platform = spec["platform"]
        arch = spec["arch"]
        download_url = spec["url"]
        min_os = spec.get("min_os")
        artifact_id = spec.get("id")

        builder.add_artifact_file(
            file_path,
            kind=kind,
            distribution=distribution,
            platform=platform,
            arch=arch,
            download_url=download_url,
            artifact_id=artifact_id,
            min_os=min_os,
        )

    if args.key_file is not None:
        priv_key = load_private_key(args.key_file)
        manifest = builder.build_signed(priv_key, args.key_id)
    else:
        manifest = builder.build()

    canonical_bytes = canonicalize_json(manifest.to_dict())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_bytes + b"\n")
    print(f"Wrote canonical release manifest to {args.output} ({len(canonical_bytes)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
