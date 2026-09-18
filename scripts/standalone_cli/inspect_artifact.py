"""Run standalone artifact evidence generation from explicit build paths."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from scripts.standalone_cli.artifact_types import (
    ArtifactDescriptor,
    ArtifactEvidenceError,
)
from scripts.standalone_cli.inspect import inspect_artifact
from scripts.standalone_cli.model import load_target_spec

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_TARGET_POLICY = _PROJECT_ROOT / "packaging" / "standalone_cli" / "target-policy.json"


def main(argv: Sequence[str] | None = None) -> int:
    """Generate evidence for one raw standalone payload."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--payload-root", required=True, type=Path)
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--warning-file", required=True, type=Path)
    parser.add_argument("--build-metadata", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--target-policy", type=Path, default=_TARGET_POLICY)
    args = parser.parse_args(argv)
    try:
        artifact = ArtifactDescriptor(
            payload_root=args.payload_root,
            executable=args.executable,
            archive=None,
            target=load_target_spec(args.target_policy, args.target),
            wheel=args.wheel,
            pyinstaller_warning_file=args.warning_file,
            build_metadata_dir=args.build_metadata,
        )
        inspect_artifact(artifact, args.evidence_dir)
    except ArtifactEvidenceError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
