"""Unit tests for build_manifest CLI script."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.distribution import build_manifest
from scripts.distribution.build_manifest import load_private_key, main, parse_artifact_spec
from servonaut.distribution.manifest import ReleaseManifest
from servonaut.distribution.trust import TrustPolicy, verify_manifest

_EXPIRES_AT = "2099-01-01T00:00:00Z"


def _argv(tmp_path: Path, *extra: str, revision: str | None = "1") -> list[str]:
    artifact = tmp_path / "servonaut-linux-x64.tar.gz"
    artifact.write_bytes(b"PAYLOAD")
    return [
        "--version",
        "2.27.0",
        *(("--revision", revision) if revision is not None else ()),
        "--artifact",
        f"file={artifact},kind=standalone_cli,distribution=frozen_cli,platform=linux,arch=x86_64,"
        "url=https://releases.servonaut.dev/servonaut-linux-x64.tar.gz",
        "--output",
        str(tmp_path / "manifest.json"),
        *extra,
    ]


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
            "--revision",
            "1",
            "--expires-at",
            _EXPIRES_AT,
            "--unsigned",
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
        assert manifest.packaging_revision == 1
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
            "--revision",
            "1",
            "--expires-at",
            _EXPIRES_AT,
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
        assert manifest.expires_at == _EXPIRES_AT

    def test_main_requires_a_revision_for_packaged_builds(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit) as exit_info:
            main(_argv(tmp_path, "--unsigned", "--expires-at", _EXPIRES_AT, revision=None))
        assert exit_info.value.code == 2
        assert "--revision is required" in capsys.readouterr().err
        assert not (tmp_path / "manifest.json").exists()

    @pytest.mark.parametrize("revision", ["0", "65536", "-1"])
    def test_main_rejects_a_revision_outside_the_shared_range(
        self, tmp_path: Path, revision: str
    ) -> None:
        argv = _argv(tmp_path, "--unsigned", "--expires-at", _EXPIRES_AT, revision=revision)
        with pytest.raises(SystemExit) as exit_info:
            main(argv)
        assert exit_info.value.code == 2
        assert not (tmp_path / "manifest.json").exists()

    def test_main_requires_expires_at(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit) as exit_info:
            main(_argv(tmp_path, "--unsigned"))
        assert exit_info.value.code == 2
        assert not (tmp_path / "manifest.json").exists()

    @pytest.mark.parametrize(
        "expires_at",
        ["next tuesday", "2026-01-01T00:00:00Z"],
        ids=["unparseable", "not-after-published"],
    )
    def test_main_rejects_invalid_expires_at(self, tmp_path: Path, expires_at: str) -> None:
        argv = _argv(
            tmp_path,
            "--unsigned",
            "--published-at",
            "2026-06-01T00:00:00Z",
            "--expires-at",
            expires_at,
        )
        with pytest.raises(SystemExit) as exit_info:
            main(argv)
        assert exit_info.value.code == 2
        assert not (tmp_path / "manifest.json").exists()

    def test_main_refuses_to_write_unsigned_without_explicit_flag(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit) as exit_info:
            main(_argv(tmp_path, "--expires-at", _EXPIRES_AT))
        assert exit_info.value.code == 2
        assert not (tmp_path / "manifest.json").exists()

    def test_main_rejects_key_file_together_with_unsigned(self, tmp_path: Path) -> None:
        key_file = tmp_path / "seed.bin"
        key_file.write_bytes(bytes(32))
        argv = _argv(
            tmp_path, "--expires-at", _EXPIRES_AT, "--unsigned", "--key-file", str(key_file), "--key-id", "k"
        )
        with pytest.raises(SystemExit) as exit_info:
            main(argv)
        assert exit_info.value.code == 2

    def test_load_private_key_accepts_a_raw_seed(self, tmp_path: Path) -> None:
        key_file = tmp_path / "seed.bin"
        key_file.write_bytes(bytes(range(32)))
        assert load_private_key(key_file).private_bytes_raw() == bytes(range(32))

    def test_load_private_key_rejects_unrecognised_material(self, tmp_path: Path) -> None:
        key_file = tmp_path / "junk.pem"
        key_file.write_bytes(b"not a key at all")
        with pytest.raises(ValueError, match="Could not load Ed25519 private key"):
            load_private_key(key_file)

    def test_load_private_key_does_not_mask_unexpected_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken_loader(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("loader defect")

        monkeypatch.setattr(build_manifest.serialization, "load_pem_private_key", broken_loader)
        key_file = tmp_path / "key.pem"
        key_file.write_bytes(b"-----BEGIN PRIVATE KEY-----")
        with pytest.raises(RuntimeError, match="loader defect"):
            load_private_key(key_file)


def test_main_with_a_revision_writes_it_into_the_manifest(tmp_path: Path) -> None:
    assert main(_argv(tmp_path, "--unsigned", "--expires-at", _EXPIRES_AT, revision="3")) == 0

    manifest = ReleaseManifest.from_json((tmp_path / "manifest.json").read_bytes())
    assert manifest.packaging_revision == 3
