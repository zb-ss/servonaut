"""Unit tests for build_manifest CLI script."""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.distribution.build_manifest import load_private_key, main, parse_artifact_spec
from servonaut.distribution.manifest import ReleaseManifest
from servonaut.distribution.trust import TrustPolicy, verify_manifest


class TestBuildManifestCLI:
    def test_parse_artifact_spec(self) -> None:
        spec = "file=foo.tar.gz,kind=standalone_cli,distribution=frozen_cli,platform=linux,arch=x86_64,url=https://example.com/foo.tar.gz"
        parsed = parse_artifact_spec(spec)
        assert parsed["file"] == "foo.tar.gz"
        assert parsed["kind"] == "standalone_cli"
        assert parsed["distribution"] == "frozen_cli"
        assert parsed["platform"] == "linux"
        assert parsed["arch"] == "x86_64"
        assert parsed["url"] == "https://example.com/foo.tar.gz"

    def test_main_unsigned_build(self, tmp_path: Path) -> None:
        dummy_file = tmp_path / "servonaut-linux-x64.tar.gz"
        dummy_file.write_bytes(b"PAYLOAD_1")
        output_manifest = tmp_path / "manifest.json"

        argv = [
            "--version",
            "2.27.0",
            "--channel",
            "stable",
            "--artifact",
            f"file={dummy_file},kind=standalone_cli,distribution=frozen_cli,platform=linux,arch=x86_64,url=https://releases.servonaut.dev/servonaut-linux-x64.tar.gz",
            "--output",
            str(output_manifest),
        ]
        ret = main(argv)
        assert ret == 0
        assert output_manifest.is_file()

        manifest = ReleaseManifest.from_json(output_manifest.read_bytes())
        assert manifest.product_version == "2.27.0"
        assert len(manifest.artifacts) == 1
        assert manifest.artifacts[0].filename == "servonaut-linux-x64.tar.gz"

    def test_main_signed_build(self, tmp_path: Path) -> None:
        priv_key = Ed25519PrivateKey.generate()
        key_file = tmp_path / "ed25519.pem"
        key_bytes = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_file.write_bytes(key_bytes)

        dummy_file = tmp_path / "servonaut-linux-x64.tar.gz"
        dummy_file.write_bytes(b"PAYLOAD_2")
        output_manifest = tmp_path / "manifest.json"

        argv = [
            "--version",
            "2.27.0",
            "--channel",
            "stable",
            "--key-file",
            str(key_file),
            "--key-id",
            "signing-key-1",
            "--artifact",
            f"file={dummy_file},kind=standalone_cli,distribution=frozen_cli,platform=linux,arch=x86_64,url=https://releases.servonaut.dev/servonaut-linux-x64.tar.gz",
            "--output",
            str(output_manifest),
        ]
        ret = main(argv)
        assert ret == 0

        manifest = ReleaseManifest.from_json(output_manifest.read_bytes())
        assert len(manifest.signatures) == 1
        assert manifest.signatures[0].key_id == "signing-key-1"

        policy = TrustPolicy(
            trusted_public_keys={"signing-key-1": priv_key.public_key()},
            minimum_signatures=1,
            allowed_origin_prefixes=("https://releases.servonaut.dev/",),
        )
        # Verify manifest does not raise
        verify_manifest(manifest, policy)
