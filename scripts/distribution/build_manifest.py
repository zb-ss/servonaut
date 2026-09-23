"""CLI script to build, validate, and sign release manifests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from servonaut.distribution.builder import ManifestBuilder
from servonaut.distribution.manifest import (
    ArtifactKind,
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


def load_private_key(key_path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from PEM or raw 32-byte seed file."""
    raw = key_path.read_bytes()
    try:
        key = serialization.load_pem_private_key(raw, password=None)
        if isinstance(key, Ed25519PrivateKey):
            return key
    except Exception:
        pass

    if len(raw) == 32:
        return Ed25519PrivateKey.from_private_bytes(raw)
    raise ValueError(f"Could not load Ed25519 private key from {key_path}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Assemble and sign a canonical Servonaut ReleaseManifest.")
    parser.add_argument("--version", required=True, help="Product semantic version (X.Y.Z)")
    parser.add_argument("--channel", default="stable", choices=["stable", "preview", "nightly"])
    parser.add_argument("--revision", type=int, default=None, help="Packaging revision")
    parser.add_argument("--published-at", default=None, help="ISO 8601 UTC timestamp")
    parser.add_argument("--expires-at", default=None, help="ISO 8601 UTC timestamp")
    parser.add_argument(
        "--artifact",
        action="append",
        dest="artifacts",
        default=[],
        help="Artifact spec: file=<path>,kind=<kind>,distribution=<dist>,platform=<plat>,arch=<arch>,url=<url>[,min_os=<os>]",
    )
    parser.add_argument("--output", type=Path, default=Path("servonaut-release-manifest.json"), help="Output manifest file")
    parser.add_argument("--key-file", type=Path, default=None, help="Ed25519 private key for signing")
    parser.add_argument("--key-id", default=None, help="Signing key ID")

    args = parser.parse_args(argv)

    channel = ReleaseChannel(args.channel)
    builder = ManifestBuilder(
        product_version=args.version,
        channel=channel,
        packaging_revision=args.revision,
        published_at=args.published_at,
        expires_at=args.expires_at,
    )

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
        if not args.key_id:
            raise ValueError("--key-id is required when --key-file is provided.")
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
